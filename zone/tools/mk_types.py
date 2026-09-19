"""Generate zonehook's C++ type and function headers from Zone.pdb.

    python zone/tools/mk_types.py --pdb Z:/ServerSource/Zone00/Zone.pdb --exe Z:/ServerSource/Zone00/Zone.exe \
                             --out include

Writes include/zone_types.h (enums, structs, unions) and include/zone_functions.h (a typed pointer to
every one of the zone's own functions). Both are generated: never edit them, re-run this.

WHY A FILTER, and what it drops. Zone.pdb describes 84,854 types, and most of them are the Windows SDK,
the STL and the compiler's own bookkeeping. Emitting those would not just be large - it would be WRONG:
a plugin includes <windows.h> and its own <string>, and a second, PDB-derived definition of tagRECT or
std::basic_string is a redefinition error at best and a silently different layout at worst. So this emits
the GAME's types and leaves everything the toolchain already provides to the toolchain. What was dropped
is counted and printed, so the filter can be argued with rather than trusted.

TYPE FIDELITY. A member whose type this cannot spell exactly is emitted as raw bytes of the right size
(`unsigned char name[N]; // <original type>`), never guessed and never silently omitted - every struct
here must keep its true sizeof and its true field offsets, because that is the whole point. Each emitted
struct is followed by a static_assert on sizeof, so a wrong layout fails the BUILD rather than corrupting
the zone's memory at runtime.
"""
import argparse
import collections
import hashlib
import os
import re
import subprocess
import sys

# ---- the dump -------------------------------------------------------------------------------------

REC = re.compile(r'^\s*0x([0-9A-F]+) \| (LF_\w+) \[size = \d+\](?: `(.*)`)?\s*$')
SYM = re.compile(r'^\s*\d+ \| (S_[GL]PROC32) \[size = \d+\] `(.*)`\s*$')
# llvm-pdbutil prints `addr = SSSS:OOOOO` with the SECTION in hex and the OFFSET in DECIMAL.
# Reading the offset as hex put sp_NC_ITEM_RELOC_REQ at 0x01671128 instead of its real 0x00537170
# - an address outside .text entirely. Cross-checked against zone_symbols.h, which is built from the
# S_PUB32 records by a different path and whose addresses are live-verified.
SYM_ADDR = re.compile(r'addr = ([0-9A-F]{4}):(\d+)')
SYM_TYPE = re.compile(r"type = `0x([0-9A-F]+)")

BUILTIN = {
    0x0003: 'void', 0x0010: 'char', 0x0011: 'short', 0x0012: 'long', 0x0013: 'long long',
    0x0020: 'unsigned char', 0x0021: 'unsigned short', 0x0022: 'unsigned long',
    0x0023: 'unsigned long long', 0x0030: 'bool', 0x0040: 'float', 0x0041: 'double',
    0x0068: 'signed char', 0x0069: 'unsigned char',
    0x0070: 'char', 0x0071: 'wchar_t', 0x0072: 'signed char', 0x0073: 'unsigned char',
    0x0074: 'int', 0x0075: 'unsigned int', 0x0076: 'long long', 0x0077: 'unsigned long long',
}
# pointer forms of the builtins: 0x04xx / 0x06xx
for _k, _v in list(BUILTIN.items()):
    BUILTIN.setdefault(0x0400 | _k, _v + '*')
    BUILTIN.setdefault(0x0600 | _k, _v + '*')


def parse_types(path):
    """index -> record dict. One pass; the dump is ~24MB and ordered."""
    recs = {}
    cur = None
    with open(path, encoding='latin-1') as fh:
        for line in fh:
            m = REC.match(line)
            if m:
                cur = dict(kind=m.group(2), name=m.group(3), body=[], items=[])
                recs[int(m.group(1), 16)] = cur
                continue
            if cur is None:
                continue
            s = line.strip()
            if not s:
                continue
            if s.startswith('- LF_'):
                cur['items'].append([s])
            elif cur['items'] and not s.startswith('0x'):
                cur['items'][-1].append(s)
            else:
                cur['body'].append(s)
    return recs


DSYM = re.compile(r'^\s*\d+ \| S_([GL])DATA32 \[size = \d+\] `(.*)`\s*$')
DSYM_AT = re.compile(r'type = 0x([0-9A-F]+)[^,]*, addr = ([0-9A-F]{4}):(\d+)')


def parse_data_symbols(path):
    """[(name, seg, off, type index)] for every global/static OBJECT.

    This is how a plugin reaches the tables the zone has ALREADY LOADED - itemdatabox, mobhat, the field
    container - rather than re-reading a file off disk and hoping it matches what the server is running."""
    out = []
    pending = None
    with open(path, encoding='latin-1') as fh:
        for line in fh:
            m = DSYM.match(line)
            if m:
                pending = m.group(2)
                continue
            if pending is None:
                continue
            a = DSYM_AT.search(line)
            if a:
                out.append((pending, int(a.group(2), 16), int(a.group(3)), int(a.group(1), 16)))
            pending = None
    return out


def emit_globals(dsyms, recs, namer, secs, image_base, notes):
    out, used = [], set()
    for name, seg, off, tidx in dsyms:
        if '<' in name or '$' in name or not is_game_type(name.split('::')[0]):
            continue
        if not (1 <= seg <= len(secs)):
            continue
        ident = cxx_ident(name)
        if ident in used:
            # Statics of the same name in different translation units. Which one a plugin meant is not
            # decidable from here, so emit the first and skip the rest rather than pick wrongly.
            notes['global_ambiguous'] += 1
            continue
        used.add(ident)
        va = image_base + secs[seg - 1][0] + off
        spelled = namer.name(tidx)
        sz = namer.sizeof(tidx)
        if spelled and '&' not in spelled and '[' not in spelled:
            out.append('// %s %s;   (%s bytes)' % (spelled, name, sz if sz else '?'))
            out.append('static const unsigned int kVa_%s = 0x%08Xu;' % (ident, va))
            out.append('inline %s* %s() { return (%s*)::zone::rebase(kVa_%s); }'
                       % (spelled, ident, spelled, ident))
        else:
            # Unspellable type: still give the address, as void*. Knowing WHERE the object is is most of
            # the value; the plugin can cast it to whatever zone_types.h calls it.
            out.append('// %s;   type not spelled here - cast it yourself' % name)
            out.append('static const unsigned int kVa_%s = 0x%08Xu;' % (ident, va))
            out.append('inline void* %s() { return ::zone::rebase(kVa_%s); }' % (ident, ident))
            notes['global_untyped'] += 1
        out.append('')
        notes['global'] += 1
    return out


def parse_symbols(path):
    """[(demangled name, seg, off, type index)] for every procedure."""
    out = []
    pending = None
    with open(path, encoding='latin-1') as fh:
        for line in fh:
            m = SYM.match(line)
            if m:
                pending = [m.group(2), None, None, None]
                continue
            if pending is None:
                continue
            a = SYM_ADDR.search(line)
            if a:
                pending[1], pending[2] = int(a.group(1), 16), int(a.group(2))
            t = SYM_TYPE.search(line)
            if t:
                pending[3] = int(t.group(1), 16)
                out.append(tuple(pending))
                pending = None
    return out


# ---- what counts as the game ------------------------------------------------------------------------
#
# Anything the toolchain already defines, anything the compiler invented, and anything whose name cannot
# be a C++ identifier. Checked against the name a type was given in the PDB.
DROP_SUBSTR = (
    'std::', '<lambda', '`', '$', 'std ::', '__vc_attributes', 'ATL::', 'ATL:', '_com_',
    'CAtl', 'IUri', '__MIDL', 'Concurrency::', 'Microsoft::', 'stdext::', '_Iterator',
)
DROP_PREFIX = (
    'tag', '_', '$', 'I', 'Uri_', 'CComp', 'CCom', 'IID', 'GUID', 'HW', 'LP',
)
# ... except these, which are the game's and merely start with an unlucky letter.
KEEP_ANYWAY = re.compile(
    r'^(Item|Inven|Shine|Mob|NPC|Npc|Quest|Skill|Char|Party|Guild|Map|Zone|Trade|Booth|Bank|'
    r'Cash|Craft|Pet|Ride|House|KQ|Achievement|Title|Collect|Use|Damage|Param|Stat|Effect|'
    r'Abstate|AbState|Regen|Gather|Produce|Enchant|Upgrade|Socket|Storage|Auction|Drop|Loot|'
    r'PROTO_|NC_|T[A-Z])'
)


def is_game_type(name):
    if not name:
        return False
    if any(d in name for d in DROP_SUBSTR):
        return False
    base = name.split('::')[0]
    if KEEP_ANYWAY.match(base):
        return True
    if base.startswith(DROP_PREFIX):
        return False
    return bool(re.match(r'^[A-Za-z][A-Za-z0-9_]*$', base))


def cxx_ident(name):
    """A PDB name -> a legal C++ identifier (Foo::Bar -> Foo_Bar)."""
    return re.sub(r'[^A-Za-z0-9_]', '_', name)


# ---- type naming ------------------------------------------------------------------------------------

class Namer:
    """Spell a type index as C++, or say it cannot."""

    def __init__(self, recs, canonical):
        self.recs = recs
        self.canonical = canonical      # C++ identifier -> the index of its REAL definition
        self.emitted = set(canonical)
        self.size_cache = {}

    def resolve(self, idx):
        """A record index -> the index that actually defines that type.

        The TPI holds a FORWARD REF for every type a translation unit only pointed at, and a forward ref
        reports `sizeof 0`. Taking that at face value is how ItemInventory came out as one opaque 22272-byte
        blob instead of 192 ItemInventoryCell: the cell's size read as 0, so the array length did not
        divide and the member fell back to raw bytes. Always resolve to the definition by name."""
        r = self.recs.get(idx)
        if not r or r['kind'] not in ('LF_STRUCTURE', 'LF_CLASS', 'LF_UNION', 'LF_ENUM'):
            return idx
        if 'forward ref' not in ' '.join(r['body']):
            return idx
        return self.canonical.get(cxx_ident(r['name'] or ''), idx)

    def value_dep(self, idx, depth=0):
        """The identifier this member embeds BY VALUE, or None.

        A pointer is deliberately not a dependency: 4 bytes need only a forward declaration, and treating
        pointers as edges would make the graph cyclic for every doubly-linked structure in the build."""
        if depth > 8 or idx in BUILTIN:
            return None
        idx = self.resolve(idx)
        r = self.recs.get(idx)
        if not r:
            return None
        k = r['kind']
        if k in ('LF_STRUCTURE', 'LF_CLASS', 'LF_UNION'):
            ident = cxx_ident(r['name'] or '')
            return ident if ident in self.emitted else None
        if k == 'LF_MODIFIER':
            m = re.search(r'referent = 0x([0-9A-F]+)', ' '.join(r['body']))
            return self.value_dep(int(m.group(1), 16), depth + 1) if m else None
        if k == 'LF_ARRAY':
            m = re.search(r'element type: 0x([0-9A-F]+)', ' '.join(r['body']))
            return self.value_dep(int(m.group(1), 16), depth + 1) if m else None
        return None

    def name(self, idx, depth=0):
        """A C++ spelling, or None when it cannot be spelled exactly."""
        if depth > 8:
            return None
        if idx in BUILTIN:
            return BUILTIN[idx]
        idx = self.resolve(idx)
        r = self.recs.get(idx)
        if not r:
            return None
        k = r['kind']
        if k in ('LF_STRUCTURE', 'LF_CLASS', 'LF_UNION', 'LF_ENUM'):
            n = r['name']
            return cxx_ident(n) if n and cxx_ident(n) in self.emitted else None
        if k == 'LF_MODIFIER':
            m = re.search(r'referent = 0x([0-9A-F]+)', ' '.join(r['body']))
            return self.name(int(m.group(1), 16), depth + 1) if m else None
        if k == 'LF_POINTER':
            b = ' '.join(r['body'])
            m = re.search(r'referent = 0x([0-9A-F]+)', b)
            if not m:
                return None
            # A pointer to something we cannot spell is still exactly 4 bytes, so void* keeps the layout
            # honest. A REFERENCE is also a pointer on the wire but must not be spelled as one in a field.
            inner = self.name(int(m.group(1), 16), depth + 1)
            if 'mode = ref' in b:
                return (inner + '&') if inner else None
            return (inner + '*') if inner else 'void*'
        if k == 'LF_ARRAY':
            b = ' '.join(r['body'])
            m = re.search(r'size: (\d+), index type: \S+ \([^)]*\), element type: 0x([0-9A-F]+)', b)
            if not m:
                m = re.search(r'size: (\d+),.*element type: 0x([0-9A-F]+)', b)
            if not m:
                return None
            total, elem_idx = int(m.group(1)), int(m.group(2), 16)
            elem = self.name(elem_idx, depth + 1)
            esz = self.sizeof(elem_idx)
            if not elem or not esz or total % esz:
                return None
            return '%s[%d]' % (elem, total // esz)
        return None

    def sizeof(self, idx, depth=0):
        if depth > 8:
            return None
        if idx in self.size_cache:
            return self.size_cache[idx]
        v = self._sizeof(idx, depth)
        self.size_cache[idx] = v
        return v

    def _sizeof(self, idx, depth):
        if idx in BUILTIN:
            n = BUILTIN[idx]
            if n.endswith('*'):
                return 4
            return {'void': 0, 'bool': 1, 'char': 1, 'signed char': 1, 'unsigned char': 1,
                    'short': 2, 'unsigned short': 2, 'wchar_t': 2, 'int': 4, 'unsigned int': 4,
                    'long': 4, 'unsigned long': 4, 'float': 4, 'double': 8,
                    'long long': 8, 'unsigned long long': 8}.get(n)
        idx = self.resolve(idx)
        r = self.recs.get(idx)
        if not r:
            return None
        k = r['kind']
        if k == 'LF_POINTER':
            return 4
        if k in ('LF_STRUCTURE', 'LF_CLASS', 'LF_UNION'):
            m = re.search(r'sizeof (\d+)', ' '.join(r['body']))
            # 0 means "this record is only a declaration" - unknown, not empty. Saying None makes the
            # caller fall back to the gap to the next member instead of silently consuming no space.
            return (int(m.group(1)) or None) if m else None
        if k == 'LF_ENUM':
            return 4
        if k == 'LF_ARRAY':
            m = re.search(r'size: (\d+)', ' '.join(r['body']))
            return int(m.group(1)) if m else None
        if k == 'LF_MODIFIER':
            m = re.search(r'referent = 0x([0-9A-F]+)', ' '.join(r['body']))
            return self.sizeof(int(m.group(1), 16), depth + 1) if m else None
        return None


# ---- members ----------------------------------------------------------------------------------------

MEMBER = re.compile(r'- LF_MEMBER \[name = `(.*?)`, Type = 0x([0-9A-F]+)(?: \([^)]*\))?, '
                    r'offset = (\d+)')
BCLASS_T = re.compile(r'type = 0x([0-9A-F]+), offset = (\d+)')
ENUMER = re.compile(r'- LF_ENUMERATE \[(.*?) = (-?\d+)\]')


def fieldlist_of(rec):
    m = re.search(r'field list: 0x([0-9A-F]+)', ' '.join(rec['body']))
    return int(m.group(1), 16) if m else None


def members_of(recs, fl_idx):
    """[(name, type index, offset)] plus base classes flattened in as fields."""
    out = []
    fl = recs.get(fl_idx)
    if not fl:
        return out
    for item in fl['items']:
        head = item[0]
        m = MEMBER.match(head)
        if m:
            out.append((m.group(1), int(m.group(2), 16), int(m.group(3))))
            continue
        if head.startswith('- LF_BCLASS'):
            b = BCLASS_T.search(' '.join(item[1:]))
            if b:
                out.append(('__base_%s' % b.group(1), int(b.group(1), 16), int(b.group(2))))
    out.sort(key=lambda x: x[2])
    return out


# ---- emitting structs -------------------------------------------------------------------------------

def emit_struct(name, rec, recs, namer, notes):
    """C++ source for one struct, or None if it cannot be emitted with a true layout."""
    body = ' '.join(rec['body'])
    size = re.search(r'sizeof (\d+)', body)
    if not size:
        return None
    size = int(size.group(1))
    if size == 0 or 'forward ref' in body:
        return None
    fl = fieldlist_of(rec)
    members = members_of(recs, fl) if fl else []

    lines = ['struct %s {          // sizeof %d' % (name, size)]
    pos = 0
    has_vtable = 'vtable: 0x' in body
    if has_vtable:
        # Every polymorphic object stores its vptr first. Naming it beats a nameless 4-byte pad, because
        # a hook that swaps a vtable slot needs to reach it.
        lines.append('    void** __vftable;')
        pos = 4

    used = set()
    for i, (mname, midx, moff) in enumerate(members):
        if moff < pos:
            continue                      # overlapping (a union member or a base we already covered)
        if moff > pos:
            lines.append('    unsigned char _pad_%d[%d];' % (pos, moff - pos))
            pos = moff
        # How many bytes this member occupies: its own type's size, bounded by where the next one starts.
        msize = namer.sizeof(midx)
        limit = members[i + 1][2] - moff if i + 1 < len(members) else size - moff
        if limit <= 0:
            continue
        if msize is None or msize > limit:
            msize = limit
        ident = cxx_ident(mname)
        if not ident or ident[0].isdigit():
            ident = 'f_%d' % moff
        while ident in used:
            ident += '_'
        used.add(ident)

        spelled = namer.name(midx)
        if spelled and namer.sizeof(midx) == msize and '&' not in spelled:
            # A MEMBER name hides a type of the same name for the rest of the struct - DiceTaiSaiDividind
            # has `unsigned short DividendRate[15]` and then a later member of type DividendRate. Qualify
            # the type when any member name in this struct, including this one, shadows it.
            base_name = spelled.rstrip('*[0123456789] ')
            if base_name == ident or base_name in used:
                spelled = '::zone::types::' + spelled
            if '[' in spelled:            # arrays: the brackets belong after the name
                base, _, dims = spelled.partition('[')
                lines.append('    %s %s[%s;' % (base, ident, dims))
            else:
                lines.append('    %s %s;' % (spelled, ident))
        else:
            # Never guess. Raw bytes of exactly the right width keep sizeof and every later offset true,
            # and the comment says what it really was so it can be spelled properly later.
            orig = spelled or ('type 0x%X' % midx)
            lines.append('    unsigned char %s[%d];   // %s' % (ident, msize, orig))
            notes['raw'] += 1
        pos += msize

    if pos < size:
        lines.append('    unsigned char _pad_%d[%d];' % (pos, size - pos))
    lines.append('};')
    # The build, not the zone, is where a wrong layout should fail.
    lines.append('ZONE_CHECK_SIZE(%s, %d);' % (name, size))
    return '\n'.join(lines)


def emit_union(name, rec, recs, namer):
    body = ' '.join(rec['body'])
    size = re.search(r'sizeof (\d+)', body)
    if not size or 'forward ref' in body:
        return None
    size = int(size.group(1))
    if size == 0:
        return None
    fl = fieldlist_of(rec)
    lines = ['union %s {          // sizeof %d' % (name, size)]
    used = set()
    for mname, midx, moff in (members_of(recs, fl) if fl else []):
        if moff != 0:
            continue                      # a union member not at 0 is not something to guess about
        spelled = namer.name(midx)
        if not spelled or '[' in spelled or '&' in spelled:
            continue
        ident = cxx_ident(mname)
        if ident in used or not ident:
            continue
        used.add(ident)
        lines.append('    %s %s;' % (spelled, ident))
    lines.append('    unsigned char _raw[%d];' % size)   # forces the true size whatever else landed
    lines.append('};')
    lines.append('ZONE_CHECK_SIZE(%s, %d);' % (name, size))
    return '\n'.join(lines)


def emit_enum(name, rec, recs, taken):
    fl = fieldlist_of(rec)
    if fl is None:
        return None
    flr = recs.get(fl)
    if not flr:
        return None
    values = []
    for item in flr['items']:
        m = ENUMER.match(item[0])
        if m:
            values.append((m.group(1), int(m.group(2))))
    if not values:
        return None
    lines = ['enum %s {' % name]
    for vname, val in values:
        ident = cxx_ident(vname)
        # Unscoped enumerators share one scope, and this build has enums that reuse a name. Keeping the
        # enum and qualifying the clash beats dropping either one.
        if ident in taken:
            ident = '%s_%s' % (name, ident)
            if ident in taken:
                continue
        taken.add(ident)
        lines.append('    %s = %d,' % (ident, val))
    lines.append('};')
    return '\n'.join(lines)


# ---- emitting functions -----------------------------------------------------------------------------
#
# A __thiscall member is declared as __fastcall with two leading parameters: ECX (the object) and a dead
# EDX. That is exactly what __thiscall is on x86, and it is the only way to spell it in a free function -
# the same trick ZONE_HOOK_PACKET uses for the packet handlers.

RESERVED = {'WinMain', 'DllMain', 'main', 'wWinMain', 'wmain'}

CONV = {'cdecl': '__cdecl', 'stdcall': '__stdcall', 'thiscall': '__fastcall',
        'fastcall': '__fastcall', 'near C': '__cdecl', 'near stdcall': '__stdcall',
        'near fastcall': '__fastcall', 'near thiscall': '__fastcall'}


def signature(idx, recs, namer):
    """(return type, calling convention, [arg types], is_thiscall) or None."""
    r = recs.get(idx)
    if not r or r['kind'] not in ('LF_MFUNCTION', 'LF_PROCEDURE'):
        return None
    body = ' '.join(r['body'])
    rt = re.search(r'return type = 0x([0-9A-F]+)', body)
    pl = re.search(r'param list = 0x([0-9A-F]+)', body)
    cc = re.search(r'calling conv = ([a-zA-Z ]+?),', body)
    if not (rt and pl and cc):
        return None
    conv_raw = cc.group(1).strip()
    conv = CONV.get(conv_raw)
    if not conv:
        return None
    ret = namer.name(int(rt.group(1), 16))
    if ret is None or '&' in ret or '[' in ret:
        return None

    args = []
    al = recs.get(int(pl.group(1), 16))
    if al and al['kind'] == 'LF_ARGLIST':
        for line in al['body']:
            m = re.match(r'^0x([0-9A-F]+)', line)
            if not m:
                continue
            ai = int(m.group(1), 16)
            a = namer.name(ai)
            if a is None or '&' in a or '[' in a:
                # A parameter we cannot spell is still one 4-byte stack slot for every type this build
                # passes by value here; anything wider would change the frame, so refuse the whole
                # signature rather than emit one that calls the function wrongly.
                if namer.sizeof(ai) != 4:
                    return None
                a = 'void*'
            args.append(a)
    return ret, conv, args, (r['kind'] == 'LF_MFUNCTION' and conv_raw.endswith('thiscall'))


def emit_functions(syms, recs, namer, secs, image_base, notes):
    out, used = [], {}
    for name, seg, off, tidx in syms:
        if '<' in name or not is_game_type(name.split('::')[0]):
            continue
        if seg is None or not (1 <= seg <= len(secs)):
            continue
        sig = signature(tidx, recs, namer)
        if not sig:
            notes['fn_unspellable'] += 1
            continue
        ret, conv, args, thiscall = sig
        va = image_base + secs[seg - 1][0] + off

        ident = cxx_ident(name)
        if ident in RESERVED:
            # WinMain/DllMain/main mean something specific to the compiler, and declaring one of them with
            # the wrong calling convention is a warning at best.
            ident += '_fn'
        n = used.get(ident, 0) + 1          # overloads: _2, _3, ... in the order the PDB lists them
        used[ident] = n
        if n > 1:
            ident = '%s_%d' % (ident, n)

        params = (['void* self', 'void* edx'] if thiscall else []) + \
                 ['%s a%d' % (a, i + 1) for i, a in enumerate(args)]
        out.append('// %s %s %s(%s)' % (ret, conv, name, ', '.join(args) or 'void'))
        out.append('typedef %s (%s* %s_t)(%s);' % (ret, conv, ident, ', '.join(params) or 'void'))
        out.append('static const unsigned int kVa_%s = 0x%08Xu;' % (ident, va))
        out.append('inline %s_t %s() { return (%s_t)::zone::rebase(kVa_%s); }'
                   % (ident, ident, ident, ident))
        out.append('')
        notes['fn'] += 1
    return out


# ---- functions the procedure list does not name: templates and COMDAT folds -------------------------
#
# emit_functions() works from the module procedures, which name each function ONCE. Two kinds are missed:
# template members (their names hold '<', which the spelling rules there refuse) and COMDAT folds - the
# linker keeps ONE body for identical instantiations, so SocketBundle<GameDBSession>::sb_GetSocket,
# <WorldManagerSession> and <GameLogSession> share 0x4199B0 and the procedure list carries one of the three.
# Every one of them is still a PUBLIC, and a public's mangled name encodes its whole signature, which MSVC's
# undname spells out: "public: class GameDBSession * __thiscall SocketBundle<class GameDBSession>::
# sb_GetSocket(void)". So each function public not already emitted is demangled, and emitted when every type
# in its signature is one zone_types.h defines (or a primitive) - never guessed.

PRIMITIVE = {
    'void', 'bool', 'char', 'signed char', 'unsigned char', 'short', 'unsigned short', 'int', 'unsigned int',
    'long', 'unsigned long', 'float', 'double', 'wchar_t', '__int64', 'unsigned __int64',
}
UNDNAME = r'C:/Program Files/Microsoft Visual Studio/18/Community/VC/Tools/MSVC/14.50.35717/bin/Hostx64/x86/undname.exe'
PUB = re.compile(r'^\s*\d+ \| S_PUB32 \[size = \d+\] `(.*)`\s*$')
PUB_AT = re.compile(r'flags = ([a-z |]+), addr = ([0-9A-F]{4}):(\d+)')
UND = re.compile(r'^(?:(?:public|private|protected): )?(?:(?:static|virtual) )*(.+?) '
                 r'(__thiscall|__cdecl|__stdcall|__fastcall) (.+?)\((.*)\)(?: const)?$')


def parse_publics(path):
    out, pending = [], None
    with open(path, encoding='latin-1') as fh:
        for line in fh:
            m = PUB.match(line)
            if m:
                pending = m.group(1)
                continue
            if pending is None:
                continue
            a = PUB_AT.search(line)
            if a and pending.startswith('?'):
                out.append((pending, int(a.group(2), 16), int(a.group(3)), 'function' in a.group(1)))
            pending = None
    return out


VTABLE = re.compile(r'^\?\?_7(.+?)@@6B@$')


def emit_vtables(pub_path, known, secs, image_base, notes):
    """zone::vtable::<Class>() for every class zone_types.h defines: the address of its vtable, as void**.

    A vtable is a public (`??_7<Class>@@6B@`), not a global, so neither the module nor the global stream has
    it. What needs one: a new subclass of a zone class borrows its RTTI locator ([-1]) - the void bag does
    this with ItemInventory's - and a vtable hook needs the table to patch."""
    out = []
    for mangled, seg, off, _fn in parse_publics(pub_path):
        m = VTABLE.match(mangled)
        if not m or not (1 <= seg <= len(secs)):
            continue
        # ItemInventory@@ -> ItemInventory ; ShinePlayer@ShineObjectClass -> ShineObjectClass::ShinePlayer
        name = '::'.join(reversed(m.group(1).split('@')))
        ident = cxx_ident(name)
        if ident not in known:
            continue
        va = image_base + secs[seg - 1][0] + off
        out.append("static const unsigned int kVa_%s = 0x%08Xu;   // %s::`vftable'" % (ident, va, name))
        out.append('inline void** %s() { return (void**)::zone::rebase(kVa_%s); }' % (ident, ident))
        notes['vtable'] += 1
    return out


def undecorate(names, exe):
    out = {}
    for i in range(0, len(names), 100):
        r = subprocess.run([exe] + names[i:i + 100], capture_output=True, text=True, errors='replace')
        for m in re.finditer(r'Undecoration of :- "(.*?)"\s*\nis :- "(.*?)"', r.stdout):
            out[m.group(1)] = m.group(2)
    return out


def spell(t, known):
    """An undname type -> the C++ zone_types.h spells, or None. References become pointers (same ABI)."""
    t = t.replace('const ', '').replace(' const', '').replace('volatile ', '').strip()
    t = re.sub(r'\b(class|struct|union|enum) ', '', t)
    stars = ''
    while t.endswith('*') or t.endswith('&'):
        stars += '*'
        t = t[:-1].rstrip()
    if '__ptr64' in t or '(' in t or '[' in t:
        return None
    if t in PRIMITIVE:
        base = {'__int64': 'long long', 'unsigned __int64': 'unsigned long long'}.get(t, t)
    else:
        base = cxx_ident(t)
        if base not in known:
            return None
    return base + stars


def emit_public_functions(pub_path, taken, known, secs, image_base, notes, undname=UNDNAME):
    if not os.path.exists(undname):
        print('  (no undname at %s - templated/folded functions skipped)' % undname)
        return []
    pubs = [p[:3] for p in parse_publics(pub_path) if p[3] and 1 <= p[1] <= len(secs)]
    und = undecorate([p[0] for p in pubs], undname)
    out, used = [], set(taken)
    for mangled, seg, off in pubs:
        m = UND.match(und.get(mangled, ''))
        if not m:
            continue
        ret, conv, qual, args = m.groups()
        qual = re.sub(r'\b(class|struct|union|enum) ', '', qual)
        if not is_game_type(qual.split('::')[0].split('<')[0]) or '`' in qual or 'operator' in qual:
            continue
        ident = cxx_ident(qual)
        if ident in used or ident in RESERVED:
            continue
        r = spell(ret, known)
        a = [] if args in ('void', '') else [spell(x, known) for x in re.split(r',(?![^<]*>)', args)]
        if r is None or any(x is None for x in a) or args.endswith('...'):
            notes['fn_public_unspellable'] += 1
            continue
        used.add(ident)
        va = image_base + secs[seg - 1][0] + off
        thiscall = conv == '__thiscall'
        params = (['void* self', 'void* edx'] if thiscall else []) + ['%s a%d' % (x, i + 1) for i, x in enumerate(a)]
        out.append('// %s   (from its public name: %s)' % (und[mangled], 'a template member or a COMDAT fold'))
        out.append('typedef %s (%s* %s_t)(%s);' % (r, '__fastcall' if thiscall else conv, ident, ', '.join(params) or 'void'))
        out.append('static const unsigned int kVa_%s = 0x%08Xu;' % (ident, va))
        out.append('inline %s_t %s() { return (%s_t)::zone::rebase(kVa_%s); }' % (ident, ident, ident, ident))
        out.append('')
        notes['fn_public'] += 1
    return out


# ---- main -------------------------------------------------------------------------------------------

BANNER = """// GENERATED by zone/tools/mk_types.py - do not edit, re-run the tool.
//   pdb %s
//   exe %s  sha256 %s
//
%s
#pragma once
"""

WHY_TYPES = """// The zone's own enums, structs and unions, as the compiler that built it laid them out.
//
// Only the GAME's types are here. The Windows SDK, the STL and the compiler's bookkeeping are left to the
// toolchain that already defines them - a second definition of tagRECT or std::basic_string would be a
// redefinition error at best and a differently-laid-out duplicate at worst.
//
// A member whose type could not be spelled exactly is raw bytes of the right width, with the original
// type in a comment, so every offset after it is still true. Every struct carries a sizeof assertion: if
// this header ever disagrees with the binary, the BUILD fails instead of the zone."""

WHY_FNS = """// A typed pointer to every one of the zone's own functions.
//
// OPT-IN: include <zone_functions.h> yourself. It is large, and a plugin that only hooks packets does not
// need it.
//
//     auto get = zone::fn::ShineObjectClass_ShinePlayer_sp_GetItemBag();
//     void* bag = get(player, 0);
//
// A __thiscall member is declared __fastcall with a leading `self` and a dead `edx` - that IS __thiscall
// on x86, and the only way to spell it in a free function.
//
// THESE ADDRESSES SURVIVE THE BINARY PATCHES. apply.py resolves each edit to a file offset and overwrites
// in place, and any new section is appended past SizeOfImage, so no existing RVA moves. The one exception
// is a recipe whose `new_section` RELOCATES a static object: the code's immediates then point into the new
// section and the PDB's address for THAT OBJECT is stale. Functions are never affected."""


PACK_NOTE = """
// PACKED, with every gap written out explicitly.
//
// The offsets below are the PDB's, so they are what the compiler that built the zone actually chose -
// its padding included. Letting THIS compiler add its own padding on top of that produced 102 structs
// whose size no longer matched the binary. Under pack(1) it adds none, and the _pad_ members reproduce
// the original layout byte for byte. The sizeof assertions are what prove it, at build time.
#pragma pack(push, 1)

"""


WHY_GLOBALS = """// The zone's global and static OBJECTS - among them the tables it has already loaded.
//
// This is the right way to read game data from a hook. The alternative, re-reading a .shn or .txt off
// disk, answers a different question: what is ON DISK, not what this server is RUNNING. Those differ
// whenever a table was patched, overridden or reloaded, and the difference is invisible until something
// behaves oddly. Read the loaded object.
//
// A static defined in more than one translation unit under the same name is emitted once and the rest
// counted, because which one a plugin meant is not decidable from the symbol alone."""


def human(n):
    return '%.1f MB' % (n / 1048576.0) if n > 1048576 else '%.0f KB' % (n / 1024.0)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--pdb', required=True)
    ap.add_argument('--exe', required=True)
    ap.add_argument('--out', required=True, help='directory to write the headers into')
    ap.add_argument('--types-dump', help='an existing llvm-pdbutil -types dump (else one is made)')
    ap.add_argument('--symbols-dump', help='an existing llvm-pdbutil -symbols dump')
    ap.add_argument('--pdbutil', default=r'C:/Program Files/LLVM/bin/llvm-pdbutil.exe')
    a = ap.parse_args()

    tmp = os.environ.get('TEMP', '.')
    tdump = a.types_dump or os.path.join(tmp, 'zone-types.txt')
    sdump = a.symbols_dump or os.path.join(tmp, 'zone-syms.txt')
    gdump = os.path.join(tmp, 'zone-globals.txt')
    pdump = os.path.join(tmp, 'zone-publics.txt')
    for flag, path in (('-types', tdump), ('-symbols', sdump), ('-globals', gdump), ('-publics', pdump)):
        if not os.path.exists(path):
            print('dumping %s -> %s' % (flag, path))
            with open(path, 'wb') as fh:
                subprocess.check_call([a.pdbutil, 'dump', flag, a.pdb], stdout=fh)

    import pefile
    pe = pefile.PE(a.exe, fast_load=True)
    secs = [(s.VirtualAddress, s.Misc_VirtualSize) for s in pe.sections]
    image_base = pe.OPTIONAL_HEADER.ImageBase
    exe_sha = hashlib.sha256(open(a.exe, 'rb').read()).hexdigest()

    print('parsing types  ...', end=' ')
    sys.stdout.flush()
    recs = parse_types(tdump)
    print('%d records' % len(recs))
    print('parsing symbols...', end=' ')
    sys.stdout.flush()
    syms = parse_symbols(sdump)
    print('%d procedures' % len(syms))

    notes = collections.Counter()

    # Pass 1: decide the names we will define, so Namer can refer to them while spelling members.
    candidates = {}
    for idx, r in recs.items():
        if r['kind'] not in ('LF_STRUCTURE', 'LF_CLASS', 'LF_UNION', 'LF_ENUM'):
            continue
        name = r['name']
        if not name or not is_game_type(name):
            notes['type_dropped'] += 1
            continue
        if 'forward ref' in ' '.join(r['body']):
            continue
        ident = cxx_ident(name)
        # The same type appears once per translation unit that used it; keep the richest definition.
        prev = candidates.get(ident)
        if prev is None or len(r['items']) > len(recs[prev]['items']):
            candidates[ident] = idx
    namer = Namer(recs, candidates)

    # ---- zone_types.h
    enums = []
    taken_enumerators = set()
    for ident, idx in sorted(candidates.items()):
        if recs[idx]['kind'] == 'LF_ENUM':
            s = emit_enum(ident, recs[idx], recs, taken_enumerators)
            if s:
                enums.append(s)

    # A struct that embeds another BY VALUE needs it already defined, so alphabetical order does not work -
    # it produced 1,900 "uses undefined struct" errors. Order by dependency instead. Pointers are not
    # edges (4 bytes, a forward declaration is enough), which also keeps the graph acyclic: a by-value
    # cycle cannot exist in a real C++ program, so one here would mean the extraction is wrong, and it is
    # reported rather than quietly broken.
    aggregates = {i: x for i, x in candidates.items() if recs[x]['kind'] != 'LF_ENUM'}
    deps = {}
    for ident, idx in aggregates.items():
        fl = fieldlist_of(recs[idx])
        d = set()
        for _mn, midx, _mo in (members_of(recs, fl) if fl is not None else []):
            dep = namer.value_dep(midx)
            if dep and dep != ident and dep in aggregates:
                d.add(dep)
        deps[ident] = d

    order, state = [], {}
    def visit(n, stack):
        st = state.get(n)
        if st == 2:
            return
        if st == 1:
            notes['cycle'] += 1
            print('  WARNING: by-value cycle through %s (%s) - emitting in discovery order'
                  % (n, ' -> '.join(stack[-4:])))
            return
        state[n] = 1
        for m in sorted(deps.get(n, ())):
            visit(m, stack + [n])
        state[n] = 2
        order.append(n)

    sys.setrecursionlimit(20000)
    for ident in sorted(aggregates):
        visit(ident, [])

    structs, unions, aggregate_text = [], [], []
    for ident in order:
        idx = aggregates[ident]
        r = recs[idx]
        if r['kind'] == 'LF_UNION':
            s = emit_union(ident, r, recs, namer)
            if s:
                unions.append(s)
                aggregate_text.append(s)
        else:
            s = emit_struct(ident, r, recs, namer, notes)
            if s:
                structs.append(s)
                aggregate_text.append(s)

    os.makedirs(a.out, exist_ok=True)
    types_h = os.path.join(a.out, 'zone_types.h')
    with open(types_h, 'w', newline='\n') as fh:
        fh.write(BANNER % (os.path.basename(a.pdb), os.path.basename(a.exe), exe_sha, WHY_TYPES))
        fh.write('\n// A sizeof check that works with and without a CRT, and names the type in the error.\n')
        fh.write('#define ZONE_CHECK_SIZE(T, N) '
                 'static_assert(sizeof(T) == (N), "zone_types.h: wrong sizeof for " #T)\n\n')
        fh.write('namespace zone {\nnamespace types {\n\n')
        fh.write('// ---- enums ------------------------------------------------------------------------\n\n')
        fh.write('\n\n'.join(enums))
        fh.write('\n\n// ---- forward declarations ---------------------------------------------------------\n\n')
        for ident, idx in sorted(candidates.items()):
            k = recs[idx]['kind']
            if k in ('LF_STRUCTURE', 'LF_CLASS'):
                fh.write('struct %s;\n' % ident)
            elif k == 'LF_UNION':
                fh.write('union %s;\n' % ident)
        fh.write('\n// ---- structs and unions, in dependency order --------------------------------------\n')
        fh.write(PACK_NOTE)
        fh.write('\n\n'.join(aggregate_text))
        fh.write('\n\n#pragma pack(pop)\n')
        fh.write('\n}  // namespace types\n}  // namespace zone\n')

    fn_lines = emit_functions(syms, recs, namer, secs, image_base, notes)
    taken = {l.split('kVa_')[1].split(' ')[0] for l in fn_lines if l.startswith('static const unsigned int kVa_')}
    fn_lines += emit_public_functions(pdump, taken, set(candidates), secs, image_base, notes)
    fns_h = os.path.join(a.out, 'zone_functions.h')
    with open(fns_h, 'w', newline='\n') as fh:
        fh.write(BANNER % (os.path.basename(a.pdb), os.path.basename(a.exe), exe_sha, WHY_FNS))
        fh.write('#include "zonehook.h"\n#include "zone_types.h"\n\n')
        fh.write('namespace zone {\nnamespace fn {\n\nusing namespace ::zone::types;\n\n')
        fh.write('\n'.join(fn_lines))
        fh.write('\n}  // namespace fn\n}  // namespace zone\n')

    # Module symbols carry the statics; the TRUE globals (gpp, sock2gameDB, chargedbuffdatabox, ...) are
    # only in the PDB's global symbol stream - which is why they used to be hand-listed ANCHORS in
    # mk_symbols.py. Read both, one entry per address, module first.
    dsyms, seen = [], set()
    for src in (sdump, gdump):
        for d in parse_data_symbols(src):
            if (d[1], d[2]) not in seen:
                seen.add((d[1], d[2]))
                dsyms.append(d)
    glob_lines = emit_globals(dsyms, recs, namer, secs, image_base, notes)
    globals_h = os.path.join(a.out, 'zone_globals.h')
    with open(globals_h, 'w', newline='\n') as fh:
        fh.write(BANNER % (os.path.basename(a.pdb), os.path.basename(a.exe), exe_sha, WHY_GLOBALS))
        fh.write('#include "zonehook.h"\n#include "zone_types.h"\n\n')
        fh.write('namespace zone {\nnamespace global {\n\nusing namespace ::zone::types;\n\n')
        fh.write('\n'.join(glob_lines))
        fh.write('\n}  // namespace global\n\n')
        fh.write("// Every zone class's vtable, by its class name (see emit_vtables in the tool).\n")
        fh.write('namespace vtable {\n\n')
        fh.write('\n'.join(emit_vtables(pdump, set(candidates), secs, image_base, notes)))
        fh.write('\n\n}  // namespace vtable\n}  // namespace zone\n')

    print()
    print('  %s  %d globals, %d vtables  (%s)' % (globals_h, notes['global'], notes['vtable'],
                                                    human(os.path.getsize(globals_h))))
    print('  %s   %d enums, %d structs, %d unions  (%s)'
          % (types_h, len(enums), len(structs), len(unions), human(os.path.getsize(types_h))))
    print('  %s  %d functions  (%s)' % (fns_h, notes['fn'], human(os.path.getsize(fns_h))))
    print()
    print('  members emitted as raw bytes                     : %d' % notes['raw'])
    print('  functions with an unspellable signature, skipped : %d' % notes['fn_unspellable'])
    print('  type records dropped as not-the-game             : %d' % notes['type_dropped'])
    print('  globals emitted untyped (address only)           : %d' % notes['global_untyped'])
    print('  functions from public names (templates, folds)   : %d  (unspellable: %d)' % (notes['fn_public'], notes['fn_public_unspellable']))
    print('  globals skipped as an ambiguous duplicate name   : %d' % notes['global_ambiguous'])


if __name__ == '__main__':
    main()
