#!/usr/bin/env python
"""Port binary-patch recipes from an original server exe to one REBUILT from source (fiesta-decomp's ProjectF2).

    # port one target's recipes, build the patched rebuilt exe, prove it against the patched original
    python tools/recipe_port.py port --target worldmanager \\
        --orig-exe Z:/ServerSource/WorldManager/WorldManager.exe --orig-pdb Z:/ServerSource/WorldManager/WorldManager.pdb \\
        --new-exe <ProjectF2>/build/WorldManager/WorldManager.exe --new-pdb <ProjectF2>/build/WorldManager/WorldManager.pdb \\
        --out-dir build/ported/WorldManager --build build/rebuilt/WorldManager.hooked.exe [--experimental]

    # one address of the original, explained
    python tools/recipe_port.py where 0x4288C4 --orig-exe ... --orig-pdb ... --new-exe ... --new-pdb ...

    # the original addresses hook plugins pass to hook::site(): a table for HOOK_SITES_HEADER (see hook_core.h)
    python tools/recipe_port.py sites --out build/rebuilt/zone_sites.h --orig-exe ... --new-pdb ... <plugin sources>

A recipe's addresses (`at`, cave jump targets, data it repoints) were read out of ONE binary. A rebuilt exe holds the
same source, laid out differently. This tool moves every address with its symbol, never by a guess:

  * An address is (the original PDB symbol that contains it, offset). The symbol is found in OUR PDB by its mangled
    public name (or, for a static with no public, its name + module). Missing, ambiguous, or an ICF fold that the two
    links resolved differently: REFUSED.
  * DATA (.data / .rdata / .bss): symbol + offset, the offset inside our symbol's extent.
  * CODE: if the function is identical in our build (every instruction, every address operand naming the same symbol +
    offset, every internal branch landing at the same offset), symbol + offset. Otherwise the two instruction streams
    are ALIGNED (difflib over symbol-normalised instructions) and an address maps only when every instruction a patch
    touches is aligned with an identical one, consecutively. Recipes with code caves need identical functions for every
    function a cave jumps into or out of - a cave depends on the frame and registers of the code around it.
  * Every recipe value that is an address of the original (a const, an inline literal) is classified by WHERE it is
    used (an `at`, a cave rel32/abs32, an expect that covers an address operand); an in-image value it cannot classify
    is refused, not translated on a hunch. `expect` is re-checked against our bytes after the port.
  * After the port the patched original and the patched rebuild are compared function by function (every patched
    function, every cave), with addresses normalised to symbols and arena regions to their labels: the patch must not
    introduce a single difference the unpatched pair did not already have.

Anything that cannot be mapped exactly stops the whole target: no partial output.

A recipe whose expects describe code BEFORE a patch the shipped exe already carries (wm-shipped-hotfixes: the stock
WorldManager has those fixes in its .custom section; our source does not) declares "reference": "unpatched". The
reference image for it is the original with the recipe's own expects written back at its sites - the shipped exe's
patch undone - and the port then proves those sites against our build like any other.

Needs llvm-pdbutil (--pdbutil) and capstone (pip install capstone). apply.py itself stays stdlib only.
"""
import argparse
import bisect
import copy
import difflib
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

import capstone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import apply as AP  # noqa: E402
import build as BUILD  # noqa: E402

PDBUTIL = r'C:/Program Files/LLVM/bin/llvm-pdbutil.exe'
NEWBASE_SENTINEL = 0x7E000000          # @newbase while classifying: outside every image this tool will see

_md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
_md.detail = True


class Refuse(Exception):
    pass


# ---- images --------------------------------------------------------------------------------------

class Image:
    """A PE32 image, read-only: VA reads, its base relocations (an exact list of address operands, when it has them)
    and the arena directory apply.py writes into a patched image."""

    def __init__(self, path=None, data=None, label=None):
        self.path = path
        self.data = bytes(data if data is not None else open(path, 'rb').read())
        self.pe = AP.Pe(bytearray(self.data))
        self.base = self.pe.image_base
        self.size = self.pe.size_of_image
        self.label = label or (os.path.basename(path) if path else '?')
        try:
            self.relocs = {self.base + r for r in self.pe.relocations()}
        except Exception:
            self.relocs = set()              # the stock exes' directory points at a section that was replaced
        self.lo = self.base + min(s['va'] for s in self.pe.sections)

    @property
    def sha256(self):
        return hashlib.sha256(self.data).hexdigest()

    def in_image(self, v):
        return self.lo <= v < self.base + self.size

    def read(self, va, n):
        """n bytes at va; zero-fill (bss) reads as zeros; None when va is in no section"""
        out = bytearray()
        for i in range(n):
            off = self.pe.offset_of(va + i)
            if off is None:
                rva = va + i - self.base
                if not any(s['va'] <= rva < s['va'] + max(s['vsize'], s['rawsize']) for s in self.pe.sections):
                    return None
                out.append(0)
            else:
                out.append(self.data[off])
        return bytes(out)

    def u32(self, va):
        b = self.read(va, 4)
        return struct.unpack('<I', b)[0] if b and len(b) == 4 else None

    def section(self, va):
        rva = va - self.base
        for s in self.pe.sections:
            if s['va'] <= rva < s['va'] + max(s['vsize'], s['rawsize']):
                return s
        return None

    def arena_regions(self):
        """[(label, va, size, exec)] from the arena directory (apply.py), or [] for an unpatched image"""
        try:
            sec = next(s for s in self.pe.sections if s['name'] == AP.ARENA_DATA)
        except StopIteration:
            return []
        out = []
        base = sec['rawptr'] + AP.ARENA_DIR_AT
        for i in range(AP.ARENA_DIR_MAX):
            at = base + i * AP.ARENA_DIR_ENTRY
            name = self.data[at:at + 20].rstrip(b'\0')
            if not name:
                continue
            off, size, flags = struct.unpack_from('<III', self.data, at + 20)
            which = AP.ARENA_EXEC if flags & AP.ARENA_FLAG_EXEC else AP.ARENA_DATA
            s = next(x for x in self.pe.sections if x['name'] == which)
            out.append((name.decode('latin-1'), self.base + s['va'] + off, size, bool(flags & AP.ARENA_FLAG_EXEC)))
        return out


# ---- the PDB -------------------------------------------------------------------------------------

def pdbutil(tool, *args):
    """llvm-pdbutil's text output, cached per (args, file size + mtime) - the dumps are re-read on every run"""
    stamp = [(a, os.path.getsize(a), os.path.getmtime(a)) for a in args if os.path.isfile(a)]
    key = hashlib.sha1(repr((tool, args, stamp)).encode()).hexdigest()
    cdir = os.path.join(tempfile.gettempdir(), 'recipe_port_pdbcache')
    path = os.path.join(cdir, key + '.txt')
    if os.path.exists(path):
        return open(path, encoding='utf-8').read()
    r = subprocess.run([tool, *args], capture_output=True, text=True, encoding='utf-8', errors='replace')
    if r.returncode != 0 or not r.stdout:
        raise SystemExit('llvm-pdbutil %s failed: %s' % (' '.join(args), r.stderr.strip()[:300]))
    os.makedirs(cdir, exist_ok=True)
    with open(path + '.tmp', 'w', encoding='utf-8') as f:
        f.write(r.stdout)
    os.replace(path + '.tmp', path)
    return r.stdout


class Sym:
    __slots__ = ('va', 'names', 'code', 'size', 'extent', 'label')

    def __init__(self, va):
        self.va, self.names, self.code, self.size, self.extent, self.label = va, set(), False, None, 0, None

    def __repr__(self):
        return '%s@0x%08X' % (self.label, self.va)


_PUB = re.compile(r'\| S_PUB32 \[size = \d+\] `(.*)`')
_PUB_ADDR = re.compile(r'flags = ([a-z, ]+), addr = ([0-9A-F]{4}):(\d+)')
_PROC = re.compile(r'\| (S_[GL]PROC32) \[size = \d+\] `(.*)`')
_PROC_ADDR = re.compile(r'addr = ([0-9A-F]{4}):(\d+), code size = (\d+)')
_DATA = re.compile(r'\| (S_[GL]DATA32|S_[GL]THREAD32) \[size = \d+\] `(.*)`')
_DATA_ADDR = re.compile(r'addr = ([0-9A-F]{4}):(\d+)')
_MOD = re.compile(r'^\s*Mod (\d+) \| `(.*)`:?\s*$')


class Symbols:
    """Every symbol the PDB places in the image: publics (mangled), procedures (with their exact code size), data.
    Names are keys: ('pub', mangled) | ('proc', name[, module]) | ('data', name[, module]) | ('arena', label)."""

    def __init__(self, img, pdb, tool=PDBUTIL):
        self.img = img
        secs = [img.base + s['va'] for s in img.pe.sections]
        by = {}

        def at(sec, off):
            sec = int(sec, 16)
            if not 1 <= sec <= len(secs):
                return None
            va = secs[sec - 1] + int(off)
            return by.setdefault(va, Sym(va))

        name = None
        for line in pdbutil(tool, 'dump', '-publics', pdb).splitlines():
            m = _PUB.search(line)
            if m:
                name = m.group(1)
                continue
            m = _PUB_ADDR.search(line)
            if m and name is not None:
                s = at(m.group(2), m.group(3))
                if s is not None:
                    s.names.add(('pub', name))
                    s.label = s.label or name
                    if 'function' in m.group(1) or 'code' in m.group(1):
                        s.code = True
            name = None
        for args in (('dump', '-symbols', pdb), ('dump', '-globals', pdb)):
            mod, pend = '', None
            for line in pdbutil(tool, *args).splitlines():
                m = _MOD.match(line)
                if m:
                    mod = os.path.basename(m.group(2).replace('\\', '/')).lower()
                    continue
                m = _PROC.search(line)
                if m:
                    pend = ('proc', m.group(1), m.group(2))
                    continue
                m = _DATA.search(line)
                if m:
                    pend = ('data', m.group(1), m.group(2))
                    continue
                if pend is None:
                    continue
                if pend[0] == 'proc':
                    m = _PROC_ADDR.search(line)
                    if m:
                        s = at(m.group(1), m.group(2))
                        if s is not None:
                            s.code = True
                            s.size = max(s.size or 0, int(m.group(3)))
                            s.names.add(('proc', pend[2]) if pend[1] == 'S_GPROC32' else ('proc', pend[2], mod))
                            s.label = s.label or pend[2]
                        pend = None
                else:
                    m = _DATA_ADDR.search(line)
                    if m:
                        s = at(m.group(1), m.group(2))
                        if s is not None:
                            glob = pend[1].startswith('S_G') or args[1] == '-globals'
                            if pend[2]:                  # an unnamed record (a switch table) is no identity
                                s.names.add(('data', pend[2]) if glob else ('data', pend[2], mod))
                            s.label = s.label or pend[2] or '(unnamed data)'
                        pend = None
        self._contribs(img, tool, pdb, secs)
        self._finish(by)

    def _contribs(self, img, tool, pdb, secs):
        """the section contributions: every piece each object put into the image. A module's own (non-COMDAT) data
        piece holds its statics, which our rebuild's PDB has no symbols for (its objects carry no CodeView) - the
        piece, paired with the original's by (object, section, attributes), locates them exactly."""
        mods, cur = {}, None
        for line in pdbutil(tool, 'dump', '-modules', pdb).splitlines():
            m = re.match(r'\s*Mod (\d+) \| `(.*)`', line)
            if m:
                cur = int(m.group(1))
                mods[cur] = [m.group(2), '']
                continue
            m = re.match(r'\s*Obj: `(.*)`', line)
            if m and cur is not None:
                mods[cur][1] = m.group(1)
        def key(i):
            name, obj = mods.get(i, ('?', ''))
            b = re.sub(r'(\.(c|cpp|cxx))?\.obj$', '', name.replace(chr(92), '/').rsplit('/', 1)[-1].lower())
            lib = obj.replace(chr(92), '/').rsplit('/', 1)[-1].lower() if obj.lower().endswith('.lib') else ''
            return (b, lib)
        self.sc = []
        pend = None
        for line in pdbutil(tool, 'dump', '-section-contribs', pdb).splitlines():
            m = re.search(r'SC\[(\S*)\]\s+\| mod = (\d+), ([0-9A-F]{4}):(\d+), size = (\d+), data crc = (\d+)', line)
            if m:
                sec = int(m.group(3), 16)
                if 1 <= sec <= len(secs):
                    pend = [secs[sec - 1] + int(m.group(4)), int(m.group(5)), key(int(m.group(2))), m.group(1), False,
                            int(m.group(6))]
                    self.sc.append(pend)
                else:
                    pend = None
                continue
            if pend is not None and 'IMAGE_SCN_LNK_COMDAT' in line:
                pend[4] = True
        self.sc.sort(key=lambda c: c[0])
        self.sc_starts = [c[0] for c in self.sc]

    def piece(self, va):
        """the section contribution containing va, or None"""
        i = bisect.bisect_right(self.sc_starts, va) - 1
        if i >= 0 and va < self.sc[i][0] + self.sc[i][1]:
            return self.sc[i]
        return None

    def _finish(self, by):
        self.syms = sorted(by.values(), key=lambda s: s.va)
        self.starts = [s.va for s in self.syms]
        for i, s in enumerate(self.syms):
            sec = self.img.section(s.va)
            end = self.img.base + sec['va'] + max(sec['vsize'], sec['rawsize']) if sec else s.va + 1
            nxt = self.syms[i + 1].va if i + 1 < len(self.syms) else end
            gap = min(nxt, end) - s.va
            s.extent = min(s.size, gap) if s.size is not None and s.size > 0 else gap
        self.by_name = {}
        for s in self.syms:
            for n in s.names:
                self.by_name.setdefault(n, []).append(s)

    def with_arena(self, img):
        """the same symbols over a PATCHED image, plus one symbol per arena region (by its label)"""
        c = copy.copy(self)
        c.img = img
        by = {s.va: s for s in self.syms}
        for label, va, size, ex in img.arena_regions():
            s = Sym(va)
            s.names.add(('arena', label))
            s.code, s.size, s.label = ex, size, '[arena %s]' % label
            by[va] = s
        c._finish(by)
        return c

    def containing(self, va):
        i = bisect.bisect_right(self.starts, va) - 1
        if i >= 0 and va < self.syms[i].va + self.syms[i].extent:
            return self.syms[i]
        return None

    def next_after(self, va):
        i = bisect.bisect_right(self.starts, va)
        return self.syms[i] if i < len(self.syms) else None


def _primary(names):
    """match by mangled publics when the symbol has any; a static without a public by its (name, module) key"""
    pubs = {n for n in names if n[0] in ('pub', 'arena')}
    local = {n for n in names if len(n) == 3}          # a static named with its module beats the bare name
    return pubs or local or set(names)


def match(src, dst, s):
    """the symbol of `dst` that is `s` of `src`: (sym, None) or (None, why)"""
    cands = {}
    for n in _primary(s.names):
        for t in dst.by_name.get(n, ()):
            cands[t.va] = t
    if not cands:
        return None, 'no symbol named %s in %s' % (s.label, dst.img.label)
    if len(cands) > 1:
        return None, ('%s of %s is %d different symbols in %s (an identical-code fold the two links resolved '
                      'differently): %s' % (s.label, src.img.label, len(cands), dst.img.label,
                                            ', '.join('0x%08X' % v for v in sorted(cands))))
    return next(iter(cands.values())), None


# ---- instructions --------------------------------------------------------------------------------

class Ins:
    __slots__ = ('addr', 'size', 'raw', 'mn', 'fields')

    def __repr__(self):
        return '0x%08X %s' % (self.addr, self.mn)


def decode(img, start, end):
    """[Ins] over [start, end): fields = [(offset, width, 'abs'|'rel', value)] - every operand that is an address:
    a rel8/rel32 branch target, a 4-byte displacement / immediate pointing into the image, and every base-relocated
    field (exact, where the image has a relocation directory)"""
    code = img.read(start, end - start) or b''
    out, pos = [], 0
    while pos < len(code):
        got = False
        for ins in _md.disasm(code[pos:], start + pos):
            got = True
            i = Ins()
            i.addr, i.size, i.raw, i.mn = ins.address, ins.size, bytes(ins.bytes), ins.mnemonic
            f = {}
            is_branch = ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL)
            if is_branch and ins.operands and ins.operands[0].type == capstone.x86.X86_OP_IMM and ins.imm_size:
                f[ins.imm_offset] = (ins.imm_offset, ins.imm_size, 'rel', ins.operands[0].imm & 0xFFFFFFFF)
            if ins.disp_size == 4 and img.in_image(ins.disp & 0xFFFFFFFF):
                f[ins.disp_offset] = (ins.disp_offset, 4, 'abs', ins.disp & 0xFFFFFFFF)
            if not is_branch and getattr(ins, 'imm_size', 0) == 4:
                for op in ins.operands:
                    if op.type == capstone.x86.X86_OP_IMM and img.in_image(op.imm & 0xFFFFFFFF):
                        f[ins.imm_offset] = (ins.imm_offset, 4, 'abs', op.imm & 0xFFFFFFFF)
            for r in range(ins.address, ins.address + ins.size - 3):
                if r in img.relocs and (r - ins.address) not in f:
                    o = r - ins.address
                    f[o] = (o, 4, 'abs', struct.unpack_from('<I', i.raw, o)[0])
            i.fields = sorted(f.values())
            out.append(i)
            pos = ins.address + ins.size - start
        if not got:                                         # undecodable byte (data in code): one byte, as raw
            i = Ins()
            i.addr, i.size, i.raw, i.mn, i.fields = start + pos, 1, code[pos:pos + 1], 'db', []
            out.append(i)
            pos += 1
    return out


def trim(ins):
    """the function's instructions only. A PDB without procedure records (our rebuild's has them only for the CRT)
    gives a function the extent up to the next symbol: the switch tables the compiler puts after the code (found as
    the function's own `jmp [table + r*4]` / `movzx r, byte [table + r]` operands) and the int3 / nop padding are
    cut off."""
    if ins:
        lo, hi = ins[0].addr, ins[-1].addr + ins[-1].size
        tables = [f[3] for i in ins for f in i.fields
                  if f[2] == 'abs' and lo < f[3] < hi and i.mn in ('jmp', 'movzx', 'mov')]
        if tables:
            end = min(tables)
            ins = [i for i in ins if i.addr < end]
    while ins and ins[-1].mn in ('int3', 'nop'):
        ins.pop()
    return ins


def masked(i):
    b = bytearray(i.raw)
    for o, w, _k, _v in i.fields:
        b[o:o + w] = bytes(w)
    return bytes(b)


# ---- the mapper ----------------------------------------------------------------------------------

class FnDiff:
    def __init__(self, o, n, identical, ins_map, oins, nins, why=''):
        self.o, self.n, self.identical, self.map, self.oins, self.nins, self.why = o, n, identical, ins_map, oins, nins, why
        self.ostarts = [i.addr for i in oins]

    def ins_at(self, va):
        k = bisect.bisect_right(self.ostarts, va) - 1
        if k >= 0 and va < self.oins[k].addr + self.oins[k].size:
            return self.oins[k]
        return None

    def unmatched(self):
        return {i.addr for i in self.oins if i.addr not in self.map}


class Mapper:
    """original (image, symbols) -> ours"""

    def __init__(self, osyms, nsyms):
        self.o, self.n = osyms, nsyms
        self._fn = {}
        self._pair_pieces()

    def _pair_pieces(self):
        """original data piece va -> ours. Each object's data comes in pieces (one per variable when the compiler
        made it a COMDAT); our rebuild's PDB names none of its statics, so a piece is located by its object and
        place: within one (object, section, COMDAT?, zero-fill?) group the pieces pair one to one IN ORDER when the
        two groups hold the same number of pieces with the same sizes (and, for initialised data, the same bytes by
        CRC). A group that differs pairs nothing; its pieces are then located only through their symbols.
        Code pieces are never paired this way: a function is located by its symbol."""
        def groups(sy):
            g = {}
            for c in sy.sc:
                if not c[1] or c[3].startswith('.text'):
                    continue
                sec = sy.img.section(c[0])
                if sec is None or sec['vsize'] and struct.unpack_from('<I', sy.img.data, sec['off'] + 36)[0]                         & AP.IMAGE_SCN_MEM_EXECUTE:
                    continue
                bss = sy.img.pe.offset_of(c[0]) is None
                g.setdefault((c[2], c[3], c[4], bss), []).append(c)
            return g
        go, gn = groups(self.o), groups(self.n)
        self.pieces, self.pieces_back = {}, {}
        for k, a in go.items():
            b = gn.get(k)
            if not b:
                continue
            ident = lambda c: (c[1], c[5] if not k[3] else 0)
            if len(a) == len(b) and all(ident(x) == ident(y) for x, y in zip(a, b)):
                pairs = list(zip(a, b))
            else:
                # the groups differ (a variable added, removed or moved to another section): pair only the pieces
                # whose (size, content) is unique in both groups, in order - an equal-size zero-fill piece next to
                # an insertion cannot be told from its neighbour, so it stays unpaired
                ca = {}
                for c in a + b:
                    ca[ident(c)] = ca.get(ident(c), 0) + 1
                ua = [c for c in a if ca[ident(c)] == 2 and sum(ident(x) == ident(c) for x in a) == 1]
                ub = [c for c in b if ca[ident(c)] == 2 and sum(ident(x) == ident(c) for x in b) == 1]
                sm = difflib.SequenceMatcher(None, [ident(c) for c in ua], [ident(c) for c in ub], autojunk=False)
                pairs = [(ua[blk.a + i], ub[blk.b + i]) for blk in sm.get_matching_blocks() for i in range(blk.size)]
            for x, y in pairs:
                self.pieces[x[0]] = y
                self.pieces_back[y[0]] = x

    def loc_piece(self, side, va):
        """(original piece va, offset) for an address in a paired non-COMDAT piece, else None"""
        sy = self.o if side == 'o' else self.n
        c = sy.piece(va)
        if c is None:
            return None
        if side == 'o':
            return (c[0], va - c[0]) if c[0] in self.pieces else None
        oc = self.pieces_back.get(c[0])
        return (oc[0], va - c[0]) if oc else None

    def counterpart(self, s, back=False):
        return match(self.n, self.o, s) if back else match(self.o, self.n, s)

    def addr_eq(self, v, w, depth=3):
        """original address operand v and ours w name the same thing: the same symbol + offset, for the symbol that
        contains v or the one right after it (a strength-reduced `base - 0xA` points just before its object); or, for
        the compiler's symbol-less exception-handling pieces, the same thing by structure (anon_eq)"""
        for c in (self.o.containing(v), self.o.next_after(v)):
            if c is None:
                continue
            t, _ = self.counterpart(c)
            if t is not None and w - t.va == v - c.va:
                return True
        po = self.loc_piece('o', v)
        if po is not None and po == self.loc_piece('n', w):
            return True                              # a static: located by its object's data piece
        return depth > 0 and self.anon_eq(v, w, depth - 1)

    # The compiler's exception-handling pieces have no symbol in either PDB: a function with a C++ EH frame pushes
    # `__ehhandler$<fn>` (a stub in .text$x: cookie check, `mov eax, offset __ehfuncinfo$<fn>`, jmp
    # ___CxxFrameHandler3), whose FuncInfo (.rdata, no symbol either) points at the unwind map and its funclets
    # (`lea ecx, [ebp-x]; jmp <dtor>`). They are equal when they are equal piece by piece: the stub's code, the
    # FuncInfo's counts, every unwind action and catch handler - each address in them again equal by symbol or by
    # this same structure. Nothing is assumed: a piece this cannot read as one of those is not equal.
    _FUNCINFO = 0x19930520

    def anon_eq(self, v, w, depth):
        cache = self.__dict__.setdefault('_anon', {})
        if (v, w) in cache:
            return cache[(v, w)]
        cache[(v, w)] = False                        # a cycle is not a proof
        so, sn = self.o.img.section(v), self.n.img.section(w)
        if so is None or sn is None:
            return False
        xo = bool(struct.unpack_from('<I', self.o.img.data, so['off'] + 36)[0] & AP.IMAGE_SCN_MEM_EXECUTE)
        xn = bool(struct.unpack_from('<I', self.n.img.data, sn['off'] + 36)[0] & AP.IMAGE_SCN_MEM_EXECUTE)
        if xo != xn:
            ok = False
        elif xo:
            ok = self._table_eq(v, w, depth) or self._stub_eq(v, w, depth)
        else:
            ok = self._funcinfo_eq(v, w, depth)
        cache[(v, w)] = ok
        return ok

    def _table_eq(self, v, w, depth):
        """a switch's jump table (dwords, each a case label inside one function) or its byte index table"""
        fo, fn_ = self.o.containing(self.o.img.u32(v) or 0), self.n.containing(self.n.img.u32(w) or 0)
        if fo is not None and fo.code and fn_ is not None and fn_.code:
            k = 0
            while True:
                a, b = self.o.img.u32(v + 4 * k), self.n.img.u32(w + 4 * k)
                ina = a is not None and fo.va <= a < fo.va + fo.extent
                inb = b is not None and fn_.va <= b < fn_.va + fn_.extent
                if ina != inb:
                    return False
                if not ina:
                    return k > 0
                if a - fo.va != b - fn_.va and not self._case_eq(fo, a, b):
                    return False
                k += 1
        # a byte index table: in the original it is a symbol of its own (the PDB has an unnamed data record for it)
        s = self.o.containing(v)
        if s is None or s.names:
            return False
        n = s.va + s.extent - v                       # to the end of the unnamed record (after a dword table)
        a, b = self.o.img.read(v, n), self.n.img.read(w, n)
        return a is not None and a == b and n > 0

    def _case_eq(self, fo, a, b):
        """a case label of a function that is not byte-identical: equal when it is the aligned instruction"""
        d = self._fn.get(fo.va)
        if d is None:
            return False
        x = d.map.get(a)
        return x is not None and x.addr == b

    def _stub(self, img, va):
        out = []
        for i in decode(img, va, va + 0x60):
            out.append(i)
            if i.mn in ('jmp', 'ret') or len(out) >= 24:
                break
        return out

    def _stub_eq(self, v, w, depth):
        a, b = self._stub(self.o.img, v), self._stub(self.n.img, w)
        if not a or len(a) != len(b) or a[-1].mn not in ('jmp', 'ret'):
            return False
        for x, y in zip(a, b):
            if x.size != y.size or masked(x) != masked(y) or [f[:3] for f in x.fields] != [f[:3] for f in y.fields]:
                return False
            for (o, _w, k, p), (_o, _w2, _k, q) in zip(x.fields, y.fields):
                if k == 'abs' and self.n.img.relocs and (y.addr + o) not in self.n.img.relocs:
                    if p != q:
                        return False
                elif not self.addr_eq(p, q, depth):
                    return False
        return True

    def _funcinfo_eq(self, v, w, depth):
        ro, rn = self.o.img, self.n.img
        a = [ro.u32(v + 4 * k) for k in range(9)]
        b = [rn.u32(w + 4 * k) for k in range(9)]
        if None in a or None in b or a[0] != b[0] or a[0] & ~0xF != self._FUNCINFO:
            return False
        magic, maxstate, unwind, ntry, trymap, nip, ipmap, estypes, flags = a
        if (maxstate, ntry, nip) != (b[1], b[3], b[5]) or (magic >= 0x19930522 and flags != b[8]):
            return False
        if (magic >= 0x19930521) and (estypes == 0) != (b[7] == 0):
            return False
        if (ipmap == 0) != (b[6] == 0) or nip:
            return False                              # x86 VC: no IP-to-state map; anything else is not understood
        def ptr_eq(p, q):
            return (p == 0 and q == 0) or (p != 0 and q != 0 and self.addr_eq(p, q, depth))
        for k in range(maxstate):
            to, act = ro.u32(unwind + 8 * k), ro.u32(unwind + 8 * k + 4)
            tn, an = rn.u32(b[2] + 8 * k), rn.u32(b[2] + 8 * k + 4)
            if None in (to, act, tn, an) or to != tn or not ptr_eq(act, an):
                return False
        for k in range(ntry):
            t = [ro.u32(trymap + 20 * k + 4 * j) for j in range(5)]
            u = [rn.u32(b[4] + 20 * k + 4 * j) for j in range(5)]
            if None in t or None in u or t[:4] != u[:4]:
                return False
            for c in range(t[3]):
                h = [ro.u32(t[4] + 16 * c + 4 * j) for j in range(4)]
                g = [rn.u32(u[4] + 16 * c + 4 * j) for j in range(4)]
                if None in h or None in g or h[0] != g[0] or h[2] != g[2]:
                    return False
                if not ptr_eq(h[1], g[1]) or not ptr_eq(h[3], g[3]):
                    return False
        return True

    def ins_eq(self, a, b, ofn, nfn, internal):
        """a (ours: b) equal, address operands by meaning. internal: 'offset' (same offset from the function start)
        or 'defer' (checked after alignment)"""
        if a.size != b.size or masked(a) != masked(b) or [f[:3] for f in a.fields] != [f[:3] for f in b.fields]:
            # one side saw an address operand the other did not: compare raw where ours says it is a constant
            if a.size != b.size or a.raw != b.raw:
                if not (a.size == b.size and self._fields_compatible(a, b)):
                    return False
            else:
                return True
        for (o, w, k, v), (_o2, _w2, _k2, x) in zip(a.fields, b.fields):
            if k == 'rel':
                oin = ofn is not None and ofn.va <= v < ofn.va + ofn.extent
                nin = nfn is not None and nfn.va <= x < nfn.va + nfn.extent
                if oin != nin:
                    return False
                if oin:
                    if internal == 'offset' and v - ofn.va != x - nfn.va:
                        return False
                    continue
            if k == 'abs' and self.n.img.relocs and (b.addr + o) not in self.n.img.relocs:
                if v != x:                                   # ours has no relocation here: a constant
                    return False
                continue
            if not self.addr_eq(v, x):
                return False
        return True

    def _fields_compatible(self, a, b):
        """the same instruction where only one side's heuristics flagged an address field: fine if every byte outside
        both sides' fields is equal (the flagged values are then compared in ins_eq's loop on the common fields)"""
        mask = bytearray(a.raw)
        mb = bytearray(b.raw)
        for o, w, _k, _v in a.fields + b.fields:
            mask[o:o + w] = bytes(w)
            mb[o:o + w] = bytes(w)
        if mask != mb:
            return False
        common = {f[0] for f in a.fields} & {f[0] for f in b.fields}
        only = [f for f in a.fields + b.fields if f[0] not in common]
        # a field only one side flagged must hold an address that maps (or the same constant on both sides)
        for o, w, k, v in only:
            av = struct.unpack_from('<I', a.raw, o)[0] if w == 4 else None
            bv = struct.unpack_from('<I', b.raw, o)[0] if w == 4 else None
            if av is None or bv is None or not (av == bv or self.addr_eq(av, bv)):
                return False
        a.fields = [f for f in a.fields if f[0] in common]
        b.fields = [f for f in b.fields if f[0] in common]
        return True

    def token(self, side, i, f, fn):
        o, w, k, v = f
        syms = self.o if side == 'o' else self.n
        if k == 'rel' and fn is not None and fn.va <= v < fn.va + fn.extent:
            return 'L'
        if side == 'n' and k == 'abs' and self.n.img.relocs and (i.addr + o) not in self.n.img.relocs:
            return ('const', v)
        c = syms.containing(v)
        p = self.loc_piece(side, v)
        if c is None:
            return ('piece',) + p if p else ('raw', v)
        t, _ = self.counterpart(c, back=(side == 'n'))
        if p is not None and (t is None or syms.piece(v)[0] > c.va):
            return ('piece',) + p                    # no symbol of its own (a static): its data piece
        if t is None:
            return (side, c.va, v - c.va)
        return (t.va if side == 'n' else c.va, v - c.va)

    def fn(self, osym):
        if osym.va in self._fn:
            return self._fn[osym.va]
        nsym, why = self.counterpart(osym)
        if nsym is None:
            raise Refuse(why)
        oins = trim(decode(self.o.img, osym.va, osym.va + osym.extent))
        nins = trim(decode(self.n.img, nsym.va, nsym.va + nsym.extent))
        if len(oins) == len(nins) and all(self.ins_eq(a, b, osym, nsym, 'offset') for a, b in zip(oins, nins)):
            d = FnDiff(osym, nsym, True, {a.addr: b for a, b in zip(oins, nins)}, oins, nins)
        else:
            d = self._align(osym, nsym, oins, nins)
        self._fn[osym.va] = d
        return d

    def _align(self, osym, nsym, oins, nins):
        def key(side, i, fn):
            # address fields in the key as symbol tokens; a constant (no relocation on our side) as itself
            return (i.mn, masked(i), tuple(self.token(side, i, f, fn) for f in i.fields))
        ok = [key('o', i, osym) for i in oins]
        nk = [key('n', i, nsym) for i in nins]
        sm = difflib.SequenceMatcher(None, ok, nk, autojunk=False)
        m = {}
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == 'equal' or (tag == 'replace' and i2 - i1 == j2 - j1):
                for a, b in zip(oins[i1:i2], nins[j1:j2]):
                    if tag == 'equal' or self.ins_eq(a, b, osym, nsym, 'defer'):
                        m[a.addr] = b
        # an aligned branch inside the function must land on the aligned counterpart of its target
        changed = True
        while changed:
            changed = False
            for a in oins:
                b = m.get(a.addr)
                if b is None:
                    continue
                for (o, w, k, v), (_o, _w, _k, x) in zip(a.fields, b.fields):
                    if k == 'rel' and osym.va <= v < osym.va + osym.extent:
                        t = m.get(v)
                        if t is None or t.addr != x:
                            del m[a.addr]
                            changed = True
                            break
        why = '%d of %d instructions aligned (ours %d)' % (len(m), len(oins), len(nins))
        return FnDiff(osym, nsym, False, m, oins, nins, why)

    def T(self, va, boundary=False, identical=False, what=''):
        """our address for the original's `va`, or Refuse: (va, how)"""
        s = self.o.containing(va)
        if s is None:
            raise Refuse('%s0x%08X is in no symbol of the original PDB' % (what, va))
        if s.code:
            d = self.fn(s)
            if d.identical:
                return d.n.va + (va - s.va), 'identical %s+0x%X' % (s.label, va - s.va)
            if identical:
                raise Refuse('%s0x%08X: %s+0x%X - a cave jumps into or out of this function, and it is not identical '
                             'in our build (%s)' % (what, va, s.label, va - s.va, d.why))
            i = d.ins_at(va)
            b = d.map.get(i.addr) if i else None
            if b is None:
                raise Refuse('%s0x%08X: %s+0x%X - the instruction there is not aligned with an identical one in our '
                             'build (%s)' % (what, va, s.label, va - s.va, d.why))
            if boundary and va != i.addr:
                raise Refuse('%s0x%08X is not an instruction boundary' % (what, va))
            return b.addr + (va - i.addr), 'aligned %s+0x%X' % (s.label, va - s.va)
        p = self.loc_piece('o', va)
        t, why = self.counterpart(s)
        if not s.names:
            return self._unnamed(s, va, what)
        if t is None and p is not None:
            return self.pieces[p[0]][0] + p[1], 'data %s+0x%X (its object\'s data piece)' % (s.label, va - s.va)
        if t is None:
            raise Refuse(what + why)
        if va - s.va >= t.extent:
            raise Refuse('%s0x%08X: %s+0x%X lies past our %s (extent 0x%X)' % (what, va, s.label, va - s.va,
                                                                                t.label, t.extent))
        return t.va + (va - s.va), 'data %s+0x%X' % (s.label, va - s.va)

    def _unnamed(self, s, va, what):
        """an unnamed record (a switch's jump / index table, emitted right after its function): the function's
        counterpart + the same offset, accepted only when the function is identical in our build and the table there
        is the same table (every case label the counterpart of the original's)"""
        k = bisect.bisect_right(self.o.starts, s.va) - 1
        while k >= 0 and not (self.o.syms[k].code and self.o.syms[k].names):
            k -= 1
        if k < 0:
            raise Refuse('%s0x%08X: an unnamed record with no function before it' % (what, va))
        f = self.o.syms[k]
        d = self.fn(f)
        if not d.identical:
            raise Refuse('%s0x%08X: a table of %s, which is not identical in our build (%s)' % (what, va, f.label,
                                                                                          d.why))
        w = d.n.va + (s.va - f.va)
        if not self._table_eq(s.va, w, 2):
            raise Refuse('%s0x%08X: the table after %s is not the same table in our build' % (what, va, f.label))
        return w + (va - s.va), 'table of %s+0x%X' % (f.label, va - f.va)

    def T_range(self, va, n, identical=False, what=''):
        first, how = self.T(va, identical=identical, what=what)
        for k in range(1, n):
            got, _ = self.T(va + k, identical=identical, what=what)
            if got != first + k:
                raise Refuse('%s0x%08X..+%d: the bytes do not stay together in our build (byte %d -> 0x%08X, '
                             'expected 0x%08X)' % (what, va, n, k, got, first + k))
        return first, how

    def site_fields(self, va, n):
        """the address fields of the original that overlap [va, va+n): [(field va, width, kind, value)]"""
        s = self.o.containing(va)
        if s is None:
            return []
        out = []
        if s.code:
            d = self.fn(s)
            for i in d.oins:
                if i.addr + i.size <= va or i.addr >= va + n:
                    continue
                for o, w, k, v in i.fields:
                    if i.addr + o < va + n and i.addr + o + w > va:
                        out.append((i.addr + o, w, k, v))
        else:
            for a in range((va & ~3) - 0, va + n, 4):
                v = self.o.img.u32(a)
                if v is not None and self.o.img.in_image(v) and self.o.containing(v) is not None \
                        and a + 4 > va and a < va + n:
                    out.append((a, 4, 'abs', v))
        return out


# ---- recipe expressions --------------------------------------------------------------------------

_NUM = re.compile(r'0x[0-9A-Fa-f]+|\d+')
_TOK = AP._TOKEN


def tokens(expr):
    if isinstance(expr, int):
        return [str(expr)]
    out, pos = [], 0
    while pos < len(expr):
        m = _TOK.match(expr, pos)
        if not m:
            raise Refuse('bad expression %r' % expr)
        out.append(m.group(1))
        pos = m.end()
    return out


class Recipe:
    def __init__(self, path):
        self.path = path
        self.name = os.path.splitext(os.path.basename(path))[0]
        self.r = json.load(open(path, encoding='utf-8'))
        self.consts = dict(self.r.get('consts', {}))
        self.params = dict(self.r.get('params', {}))
        self.env = {'@newbase': NEWBASE_SENTINEL}
        for k, v in list(self.consts.items()) + list(self.params.items()):
            self.env[k] = AP.evaluate(v, self.env) if isinstance(v, str) else v

    def ev(self, e, env=None):
        return AP.evaluate(e, env or self.env) & 0xFFFFFFFF if not isinstance(e, int) else e

    def leaves(self, expr, seen=()):
        """the literal leaves an expression rests on: ('const', name) for a const defined by one literal (recursing
        through consts defined by expressions), ('lit', text) for a number written inline. Params are knobs, never
        addresses: left out."""
        out = set()
        for t in tokens(expr):
            if _NUM.fullmatch(t):
                out.add(('lit', t))
            elif t in self.consts and t not in seen:
                d = self.consts[t]
                if isinstance(d, int) or (isinstance(d, str) and _NUM.fullmatch(d.strip())):
                    out.add(('const', t))
                else:
                    out |= self.leaves(d, seen + (t,))
        return out

    def leaf_value(self, leaf):
        return self.env[leaf[1]] if leaf[0] == 'const' else int(leaf[1], 0)


def rd(img, over, va, n):
    """n bytes at va with the chain's earlier writes laid over them"""
    b = img.read(va, n)
    if b is None or not over:
        return b
    return bytes(over.get(va + k, b[k]) for k in range(n))


def _with_bytes(img, va, b):
    d = bytearray(img.data)
    off = img.pe.offset_of(va)
    d[off:off + len(b)] = b
    return d


# ---- porting one recipe --------------------------------------------------------------------------

def port_recipe(rec, mp, new_img, notes, o_over=None, n_over=None):
    """the ported recipe dict, or Refuse. mp: the mapper whose original side is this recipe's reference image.
    o_over / n_over: {va: byte} the recipes before this one in the chain wrote (original / ours) - a recipe's expect
    may be an earlier recipe's write. Updated with this recipe's writes on success."""
    o_over = {} if o_over is None else o_over
    n_over = {} if n_over is None else n_over
    r = copy.deepcopy(rec.r)
    oimg = mp.o.img
    has_caves = bool(r.get('code'))
    in_img = lambda v: oimg.in_image(v)

    # 1. classify every in-image leaf by where it is used. An address of the original is an address because the
    #    bytes it lands in ARE an address operand: of the instruction the recipe edits (its expect), of the
    #    instruction the patched bytes form (a write; decoded from the original with this recipe's edits applied),
    #    of a cave instruction (a u32), or a pointer the original data held. A number that lands in opcode / string
    #    bytes is a number, whatever it looks like.
    role = {}

    def mark(leaf, what):
        role.setdefault(leaf, set()).add(what)

    edits0 = [(rec.ev(e['at']), int(e.get('width', 4)), rec.ev(e['write'])) for e in r.get('edits', [])]

    def patched_fields(at, w):
        """address fields of the ORIGINAL function containing `at` once this recipe's edits are in"""
        s = mp.o.containing(at)
        if s is None or not s.code:
            return []
        lo, hi = s.va, s.va + s.extent
        b = bytearray(rd(oimg, o_over, lo, hi - lo) or b'')
        for a2, w2, v2 in edits0:
            if lo <= a2 and a2 + w2 <= hi:
                b[a2 - lo:a2 - lo + w2] = struct.pack({1: '<B', 2: '<H', 4: '<I'}[w2], v2 & ((1 << 8 * w2) - 1))
        tmp = Image(data=_with_bytes(oimg, lo, bytes(b)), label='patched')
        out = []
        for i in decode(tmp, lo, hi):
            if i.addr + i.size <= at or i.addr >= at + w:
                continue
            out += [(i.addr + o, fw, k, v) for o, fw, k, v in i.fields if i.addr + o < at + w and i.addr + o + fw > at]
        return out

    for e in r.get('edits', []):
        at = rec.ev(e['at'])
        w = int(e.get('width', 4))
        site = mp.o.containing(at)
        fields = mp.site_fields(at, w)
        for leaf in rec.leaves(e['at']):
            if in_img(rec.leaf_value(leaf)):
                mark(leaf, 'addr')
        for leaf in rec.leaves(e['expect']):
            if in_img(rec.leaf_value(leaf)):
                mark(leaf, 'addr' if fields else 'scalar')
        wl = [x for x in rec.leaves(e['write']) if in_img(rec.leaf_value(x))]
        if not wl:
            continue
        if site is not None and site.code:
            pf = patched_fields(at, w)
            for leaf in wl:
                mark(leaf, 'addr' if pf else 'scalar')
        elif fields:
            for leaf in wl:
                mark(leaf, 'addr')
        else:
            cur = rd(oimg, o_over, at, w)
            for leaf in wl:
                mark(leaf, 'scalar' if cur and any(cur) else 'unknown')
    for c in r.get('code', []):
        for leaf in rec.leaves(c['at']):
            if in_img(rec.leaf_value(leaf)):
                mark(leaf, 'addr')
        blob, u32s = bytearray(), []
        for piece in c['emit']:
            if isinstance(piece, str):
                blob += bytes.fromhex(piece.replace(' ', ''))
                continue
            k, ex = next(iter(piece.items()))
            if k == 'u32':
                u32s.append((len(blob), ex))
            blob += struct.pack('<I', rec.ev(ex) & 0xFFFFFFFF) if k != 'rel32' else bytes(4)
            for leaf in rec.leaves(ex):
                if in_img(rec.leaf_value(leaf)) and k in ('rel32', 'abs32'):
                    mark(leaf, 'addr')
        fields_at = set()
        for ins in _md.disasm(bytes(blob), 0):
            if ins.disp_size == 4:
                fields_at.add(ins.address + ins.disp_offset)
            if getattr(ins, 'imm_size', 0) == 4:
                fields_at.add(ins.address + ins.imm_offset)
        for off, ex in u32s:
            for leaf in rec.leaves(ex):
                v = rec.leaf_value(leaf)
                if not in_img(v):
                    continue
                c2 = mp.o.containing(v)
                mark(leaf, 'addr' if off in fields_at or (c2 is not None and c2.code) else 'unknown')
    for leaf, roles in role.items():
        if 'unknown' in roles and 'addr' not in roles:
            raise Refuse('%s: %s = 0x%08X lies in the original image, but where it is used nothing says whether it is '
                         'an address (a u32 outside any instruction operand, or a write into data that held zero) - '
                         'write it as abs32 if it is one' % (rec.name, leaf[1], rec.leaf_value(leaf)))
        if 'addr' in roles and 'scalar' in roles:
            raise Refuse('%s: %s = 0x%08X is used both as an address and over bytes that hold no address operand' %
                         (rec.name, leaf[1], rec.leaf_value(leaf)))

    # 2. translate the address leaves
    cave_targets = set()
    for c in r.get('code', []):
        for piece in c['emit']:
            if isinstance(piece, dict) and 'rel32' in piece:
                v = rec.ev(piece['rel32'])
                if in_img(v):
                    cave_targets.add(v)
    new = {}
    for leaf, roles in sorted(role.items()):
        if 'addr' not in roles:
            continue
        v = rec.leaf_value(leaf)
        boundary = v in cave_targets
        nv, how = mp.T(v, boundary=boundary, identical=has_caves, what='%s: %s ' % (rec.name, leaf[1]))
        new[leaf] = nv
        notes.append('  %-22s 0x%08X -> 0x%08X  %s' % (leaf[1], v, nv, how))
    for k in list(r.get('consts', {})):
        if ('const', k) in new:
            r['consts'][k] = '0x%08X' % new[('const', k)]

    def rewrite(expr):
        if isinstance(expr, int):
            return '0x%08X' % new[('lit', str(expr))] if ('lit', str(expr)) in new else expr
        return re.sub(r'0x[0-9A-Fa-f]+|\b\d+\b',
                      lambda m: '0x%08X' % new[('lit', m.group(0))] if ('lit', m.group(0)) in new else m.group(0), expr)

    # leaves classified per use: an inline literal is only rewritten where it was classified an address. A literal
    # that is an address in one expression and raw bytes in another would be ambiguous - refused above.
    for e in r.get('edits', []):
        for k in ('at', 'expect', 'write'):
            e[k] = rewrite(e[k])
    for c in r.get('code', []):
        c['at'] = rewrite(c['at'])
        c['emit'] = [p if isinstance(p, str) else {k: rewrite(v) for k, v in p.items()} for p in c['emit']]

    # 3. cave raw bytes must not hide an address of the original
    for c in rec.r.get('code', []):
        blob = bytearray()
        for piece in c['emit']:
            if isinstance(piece, str):
                blob += bytes.fromhex(piece.replace(' ', ''))
            else:
                k, ex = next(iter(piece.items()))
                blob += b'\0\0\0\0'
        for ins in _md.disasm(bytes(blob), 0):
            for op in ins.operands:
                v = (op.imm if op.type == capstone.x86.X86_OP_IMM else
                     op.mem.disp if op.type == capstone.x86.X86_OP_MEM else 0) & 0xFFFFFFFF
                if in_img(v) and not (ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL)):
                    raise Refuse('%s: a cave hard-codes 0x%08X (an address of the original) in raw hex - write it '
                                 'as abs32' % (rec.name, v))

    # 4. verify every edit independently against our image
    penv = {'@newbase': NEWBASE_SENTINEL}
    for k, v in list(r.get('consts', {}).items()) + list(r.get('params', {}).items()):
        penv[k] = AP.evaluate(v, penv) if isinstance(v, str) else v
    for e0, e in zip(rec.r.get('edits', []), r.get('edits', [])):
        w = int(e.get('width', 4))
        fmt = {1: '<B', 2: '<H', 4: '<I'}[w]
        oat = rec.ev(e0['at'])
        obytes = rd(oimg, o_over, oat, w)
        oexp = rec.ev(e0['expect']) & ((1 << 8 * w) - 1)
        if obytes is None or struct.unpack(fmt, obytes)[0] != oexp:
            raise Refuse('%s: 0x%08X does not hold the recipe\'s expect 0x%X in the reference image (it holds %s)' %
                         (rec.name, oat, oexp, obytes.hex() if obytes else 'nothing'))
        want, how = mp.T_range(oat, w, identical=has_caves, what='%s: edit ' % rec.name)
        got = AP.evaluate(e['at'], penv)
        if got != want:
            raise Refuse('%s: edit at 0x%08X ports to 0x%08X by its expression but to 0x%08X by its instruction '
                         '(%s) - the expression mixes an address with an offset that did not move with it' %
                         (rec.name, oat, got, want, how))
        # our exe is DYNAMICBASE with a relocation directory: a write over a relocated field must replace that
        # whole address with an address (the loader adds the base delta to it), never with code or a constant
        for rv in sorted(new_img.relocs):
            if rv < want + w and rv + 4 > want:
                if not (rv >= want and rv + 4 <= want + w and
                        any(f[0] == oat + (rv - want) and f[2] == 'abs' for f in mp.site_fields(oat, w))):
                    raise Refuse('%s: edit at 0x%08X (ours 0x%08X) overwrites part of a base-relocated address at '
                                 '0x%08X with something that is not that whole address - the loader would corrupt '
                                 'it on a rebase' % (rec.name, oat, want, rv))
        nb = rd(new_img, n_over, want, w)
        nval = struct.unpack(fmt, nb)[0]
        pexp = AP.evaluate(e['expect'], penv) & ((1 << 8 * w) - 1)
        if pexp != nval:
            # the instructions there were proven equal with address operands by meaning, so a raw expect literal
            # that covers part of an address operand is re-read from our image; anything else is a refusal
            if not mp.site_fields(oat, w):
                raise Refuse('%s: edit at 0x%08X (ours 0x%08X): expect ported to 0x%X, our image holds 0x%X' %
                             (rec.name, oat, want, pexp, nval))
            e['expect_original'] = e0['expect']
            e['expect'] = '0x%0*X' % (2 * w, nval)
            notes.append('  expect at 0x%08X re-read from our image: 0x%X (an address operand)' % (want, nval))
        e['ported_from'] = '0x%08X %s' % (oat, how)
    for c0, c in zip(rec.r.get('code', []), r.get('code', [])):
        for p0, p in zip(c0['emit'], c['emit']):
            if isinstance(p0, dict) and 'rel32' in p0:
                ov = rec.ev(p0['rel32'])
                if in_img(ov):
                    want, _ = mp.T(ov, boundary=True, identical=True, what='%s: cave target ' % rec.name)
                    if AP.evaluate(p['rel32'], penv) != want:
                        raise Refuse('%s: cave jump target 0x%08X ports to 0x%08X, its instruction to 0x%08X' %
                                     (rec.name, ov, AP.evaluate(p['rel32'], penv), want))
    for e0, e in zip(rec.r.get('edits', []), r.get('edits', [])):
        w = int(e.get('width', 4))
        fmt = {1: '<B', 2: '<H', 4: '<I'}[w]
        for over, at, val in ((o_over, rec.ev(e0['at']), rec.ev(e0['write'])),
                              (n_over, AP.evaluate(e['at'], penv), AP.evaluate(e['write'], penv))):
            for k, b in enumerate(struct.pack(fmt, val & ((1 << 8 * w) - 1))):
                over[at + k] = b
    r['target'] = {'file': rec.r.get('target', {}).get('file'), 'sha256': new_img.sha256, 'size': len(new_img.data)}
    r['ported'] = {'from_sha256': rec.r.get('target', {}).get('sha256'), 'by': 'tools/recipe_port.py'}
    return r


# ---- comparing the two patched images ------------------------------------------------------------

def compare_patched(mp, mp_patched, ported, recipes):
    """every function a recipe touches, and every arena region, in the patched original vs the patched rebuild: the
    patch must add no difference the unpatched pair did not already have. -> [problem lines]"""
    problems, lines = [], []
    o_regions = {l: (va, size, ex) for l, va, size, ex in mp_patched.o.img.arena_regions()}
    n_regions = {l: (va, size, ex) for l, va, size, ex in mp_patched.n.img.arena_regions()}
    if set(o_regions) != set(n_regions):
        problems.append('arena regions differ: %s vs %s' % (sorted(o_regions), sorted(n_regions)))
    fns = {}
    for rec in recipes:
        for e in rec.r.get('edits', []):
            at = rec.ev(e['at'])
            s = mp.o.containing(at)
            if s is not None and s.code:
                fns.setdefault(s.va, (s, set()))[1].update(range(at, at + int(e.get('width', 4))))
            elif s is not None:
                # data: the patched values themselves
                w = int(e.get('width', 4))
                ov = mp_patched.o.img.read(at, w)
                nat, _ = mp.T(at)
                nv = mp_patched.n.img.read(nat, w)
                if w == 4:
                    a, b = struct.unpack('<I', ov)[0], struct.unpack('<I', nv)[0]
                    ok = a == b or mp_patched.addr_eq(a, b)
                else:
                    ok = ov == nv
                lines.append('  data %-40s 0x%08X/0x%08X %s' % (s.label[:40], at, nat, 'same' if ok else 'DIFFERS'))
                if not ok:
                    problems.append('data at 0x%08X: %s vs %s' % (at, ov.hex(), nv.hex()))
        for c in rec.r.get('code', []):
            for p in c['emit']:
                if isinstance(p, dict) and 'rel32' in p:
                    v = rec.ev(p['rel32'])
                    s = mp.o.containing(v)
                    if s is not None and s.code:
                        fns.setdefault(s.va, (s, set()))
    for va, (s, sites) in sorted(fns.items()):
        before = mp.fn(s)
        ps = mp_patched.o.containing(s.va)
        mp_patched._fn.pop(s.va, None)
        after = mp_patched.fn(ps)
        new_diff = after.unmatched() - before.unmatched()
        bad_sites = [a for a in sites if (after.ins_at(a) is None or after.ins_at(a).addr not in after.map)]
        state = 'identical' if after.identical else after.why
        lines.append('  fn   %-40s %s' % (s.label[:40], state))
        if new_diff or bad_sites:
            problems.append('%s: the patch adds %d differing instruction(s) (%s)%s' % (
                s.label, len(new_diff), ', '.join('0x%08X' % a for a in sorted(new_diff)[:6]),
                ' at the patched sites' if bad_sites else ''))
    io, inn = imports(mp_patched.o.img), imports(mp_patched.n.img)
    lines.append('  imports: %d / %d' % (len(io), len(inn)))
    if io != inn:
        problems.append('imports differ: only in the original %s, only in ours %s' % (sorted(io - inn)[:6],
                                                                                    sorted(inn - io)[:6]))
    for label, (va, size, ex) in sorted(o_regions.items()):
        if label not in n_regions:
            continue
        nva, nsize, nex = n_regions[label]
        if size != nsize or ex != nex:
            problems.append('region %s: 0x%X%s vs 0x%X%s' % (label, size, ' exec' if ex else '', nsize,
                                                             ' exec' if nex else ''))
            continue
        if not ex:
            continue
        a = decode(mp_patched.o.img, va, va + size)
        b = decode(mp_patched.n.img, nva, nva + size)
        osym, nsym = mp_patched.o.containing(va), mp_patched.n.containing(nva)
        ok = len(a) == len(b) and all(mp_patched.ins_eq(x, y, osym, nsym, 'offset') for x, y in zip(a, b))
        lines.append('  cave %-40s %s' % (label, 'equivalent' if ok else 'DIFFERS'))
        if not ok:
            problems.append('cave %s differs' % label)
    return lines, problems


def imports(img):
    """{(dll, function)} of an image's import directory, by name (ordinal imports as '#n')"""
    out = set()
    rva, size, _ = img.pe.data_directory(1)
    k = 0
    while True:
        d = img.read(img.base + rva + 20 * k, 20)
        if d is None:
            break
        ilt, _t, _f, name, iat = struct.unpack('<IIIII', d)
        if not (ilt or name or iat):
            break
        dll = (img.read(img.base + name, 64) or b'').split(b'\0')[0].decode('latin-1').lower()
        j = 0
        while True:
            e = img.u32(img.base + (ilt or iat) + 4 * j)
            if not e:
                break
            fn = '#%d' % (e & 0xFFFF) if e & 0x80000000 else                 (img.read(img.base + e + 2, 128) or b'').split(b'\0')[0].decode('latin-1')
            out.add((dll, fn))
            j += 1
        k += 1
    return out


# ---- driver --------------------------------------------------------------------------------------

def chain_for(target, experimental, rebuilt=True):
    chain = list(BUILD.chain_for(target, experimental=experimental))
    if rebuilt:
        chain += BUILD.REBUILT_ONLY.get(target, [])
    return chain


def reference_image(img, recipes):
    """the original with the expects of every "reference": "unpatched" recipe written back (the shipped exe's own
    post-link patch undone), or the original itself"""
    d = None
    for rec in recipes:
        if rec.r.get('reference') != 'unpatched':
            continue
        d = d or bytearray(img.data)
        pe = AP.Pe(d)
        for e in rec.r.get('edits', []):
            w = int(e.get('width', 4))
            at = rec.ev(e['at'])
            off = pe.offset_of(at)
            cur = d[off:off + w]
            exp = struct.pack({1: '<B', 2: '<H', 4: '<I'}[w], rec.ev(e['expect']) & ((1 << 8 * w) - 1))
            if bytes(cur) == exp:
                raise Refuse('%s says the original is already patched at 0x%08X, but it holds the unpatched bytes' %
                             (rec.name, at))
            d[off:off + w] = exp
    if d is None:
        return img
    return Image(data=d, label=img.label + ' (shipped patches undone)')


def run_build(target, exe, out, rdir, experimental, sets_chain, allow_mismatch=False):
    cmd = [sys.executable, os.path.join(HERE, 'build.py'), '--target', target, '--exe', exe, '--out', out,
           '--recipes-dir', rdir, '--rebuilt']
    if experimental:
        cmd.append('--experimental')
    if allow_mismatch:
        cmd.append('--allow-hash-mismatch')
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        raise Refuse('build.py failed for %s:\n%s%s' % (exe, r.stdout, r.stderr))
    return r.stdout


def cmd_port(a):
    oimg, nimg = Image(a.orig_exe), Image(a.new_exe)
    osyms = Symbols(oimg, a.orig_pdb, a.pdbutil)
    nsyms = Symbols(nimg, a.new_pdb, a.pdbutil)
    chain = chain_for(a.target, a.experimental)
    rdir = os.path.join(HERE, a.target, 'recipes')
    recipes = [Recipe(os.path.join(rdir, name + '.json')) for name, _sets in chain]
    for rec, (name, sets) in zip(recipes, chain):
        for kv in sets:
            k, _, v = kv.partition('=')
            rec.params[k.strip()] = int(v, 0)
            rec.env[k.strip()] = int(v, 0)
    print('target %s: %d recipe(s); original %s (%s...), ours %s (%s...)' % (
        a.target, len(recipes), a.orig_exe, oimg.sha256[:12], a.new_exe, nimg.sha256[:12]))
    ref = reference_image(oimg, recipes)
    if ref is not oimg:
        print('reference: %s' % ref.label)
    rsyms = copy.copy(osyms)
    rsyms.img = ref
    mp = Mapper(rsyms, nsyms)
    ported, refused = {}, {}
    o_over, n_over = {}, {}
    for rec in recipes:
        notes = []
        m = mp
        try:
            ported[rec.name] = port_recipe(rec, m, nimg, notes, o_over, n_over)
            kinds = {}
            for e in ported[rec.name].get('edits', []):
                k = e['ported_from'].split()[1]
                kinds[k] = kinds.get(k, 0) + 1
            print('  PORTED   %-28s %3d edit(s) %s, %d cave(s)%s' % (
                rec.name, len(rec.r.get('edits', [])), ' '.join('%s:%d' % kv for kv in sorted(kinds.items())),
                len(rec.r.get('code', [])), ', import' if rec.r.get('add_import') else ''))
            if a.verbose:
                print('\n'.join(notes))
        except Refuse as x:
            refused[rec.name] = str(x)
            print('  REFUSED  %-28s %s' % (rec.name, x))
    if refused:
        print('\n%d recipe(s) refused - nothing written.' % len(refused))
        return 1
    out = os.path.abspath(a.out_dir)
    os.makedirs(out, exist_ok=True)
    for name, r in ported.items():
        with open(os.path.join(out, name + '.json'), 'w', encoding='utf-8', newline='\n') as f:
            json.dump(r, f, indent=2, ensure_ascii=False)
            f.write('\n')
    print('wrote %d ported recipe(s) to %s' % (len(ported), out))
    if not a.build:
        return 0

    # build both sides and compare them
    work = tempfile.mkdtemp(prefix='recipe_port-')
    try:
        print(run_build(a.target, a.new_exe, a.build, out, a.experimental, chain).rstrip())
        ref_path = a.orig_exe
        if ref is not oimg:
            ref_path = os.path.join(work, 'reference.exe')
            open(ref_path, 'wb').write(ref.data)
        opatched = os.path.join(work, 'orig.patched.exe')
        run_build(a.target, ref_path, opatched, rdir, a.experimental, chain, allow_mismatch=True)
        po, pn = Image(opatched, label='original patched'), Image(a.build, label='ours patched')
        mp_patched = Mapper(osyms.with_arena(po), nsyms.with_arena(pn))
        lines, problems = compare_patched(mp, mp_patched, ported, recipes)
        print('patched original vs patched rebuild:')
        print('\n'.join(lines))
        if problems:
            print('COMPARE FAILED:\n  ' + '\n  '.join(problems))
            os.remove(a.build)
            print('removed %s' % a.build)
            return 1
        print('COMPARE OK: every patched function and cave is equivalent; %s' % a.build)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 0


def cmd_where(a):
    oimg, nimg = Image(a.orig_exe), Image(a.new_exe)
    mp = Mapper(Symbols(oimg, a.orig_pdb, a.pdbutil), Symbols(nimg, a.new_pdb, a.pdbutil))
    rc = 0
    for x in a.va:
        va = int(x, 16)
        try:
            nv, how = mp.T(va)
            s = mp.o.containing(va)
            extra = ''
            if s.code:
                d = mp.fn(s)
                extra = '' if d.identical else ' (function: %s)' % d.why
            print('0x%08X -> 0x%08X  %s%s' % (va, nv, how, extra))
        except Refuse as e:
            print('0x%08X    REFUSED: %s' % (va, e))
            rc = 1
    return rc


def map_symbol_address(mp, va):
    """a generated header's address (a function entry, a global, a vtable) -> ours: a function by its symbol (the
    mangled name carries the signature), anything else as T() maps it. (our va, how) or Refuse"""
    s = mp.o.containing(va)
    if s is not None and s.va == va and s.code:
        t, why = mp.counterpart(s)
        if t is None:
            raise Refuse(why)
        return t.va, 'function %s' % s.label
    return mp.T(va)


_HDR_VA = re.compile(r'^(\s*static const unsigned int (kVa\w*) = )0x([0-9A-Fa-f]{8})u;(.*)$')
_HDR_ENTRY = re.compile(r'^(\s*\{ "([^"]*)", )0x([0-9A-Fa-f]{8})u( \},.*)$')


def cmd_headers(a):
    """rewrite generated headers (mk_types.py / mk_symbols.py output, written from the ORIGINAL PDB) for our exe:
    every address through its symbol. Types and names stay the original PDB's - our rebuild's PDB carries neither
    (its objects are compiled without CodeView), and the source, so every layout, is the same. An address that does
    not map is REMOVED with its accessor, so a plugin that uses it fails to compile instead of calling into the
    wrong place."""
    oimg, nimg = Image(a.orig_exe), Image(a.new_exe)
    mp = Mapper(Symbols(oimg, a.orig_pdb, a.pdbutil), Symbols(nimg, a.new_pdb, a.pdbutil))
    os.makedirs(a.out_dir, exist_ok=True)
    if a.base_include:
        # the target's hand-written headers beside the remapped generated ones: a quoted #include searches the
        # including header's own folder first, so the two must sit in ONE folder or the stock ones win
        for f in os.listdir(a.base_include):
            if f.endswith('.h') and os.path.basename(f) not in {os.path.basename(h) for h in a.headers}:
                shutil.copyfile(os.path.join(a.base_include, f), os.path.join(a.out_dir, f))
    total_bad = 0
    for path in a.headers:
        lines = open(path, encoding='utf-8').read().split('\n')
        out, dropped, mapped, dead = [], [], 0, set()
        for ln in lines:
            m = _HDR_VA.match(ln)
            e = None if m else _HDR_ENTRY.match(ln)
            if m or e:
                g = m or e
                va = int(g.group(3), 16)
                name = g.group(2)
                try:
                    nv, _how = map_symbol_address(mp, va)
                    out.append('%s0x%08Xu%s%s' % (g.group(1), nv, ';' if m else '', g.group(4)))
                    mapped += 1
                except Refuse as x:
                    dropped.append('%s 0x%08X: %s' % (name, va, x))
                    if m:
                        dead.add(name)
                continue
            if dead and any(('%s)' % d) in ln or ('%s,' % d) in ln for d in dead if d in ln):
                continue                                   # the accessor of a dropped address
            ln = ln.replace(oimg.sha256, nimg.sha256)
            out.append(ln)
        # entry tables carry a count
        text = '\n'.join(out)
        for arr, cnt in (('kHandlers', 'kHandlerCount'), ('kVtables', 'kVtableCount')):
            mm = re.search(r'%s\[\] = \{\n(.*?)\n\};' % arr, text, re.S)
            if mm:
                n = len([x for x in mm.group(1).split('\n') if x.strip().startswith('{')])
                text = re.sub(r'(static const int %s = )\d+;' % cnt, r'\g<1>%d;' % n, text)
        head = ('// REMAPPED by tools/recipe_port.py headers for %s (sha256 %s): every address moved with its symbol '
                'from %s;\n// %d mapped, %d removed (no exact counterpart in our build%s).\n' %
                (os.path.basename(a.new_exe), nimg.sha256, os.path.basename(a.orig_exe), mapped, len(dropped),
                 ': ' + '; '.join(d.split(':')[0] for d in dropped[:40]) + (' ...' if len(dropped) > 40 else '')
                 if dropped else ''))
        dest = os.path.join(a.out_dir, os.path.basename(path))
        with open(dest, 'w', encoding='utf-8', newline='\n') as f:
            f.write(head + text)
        print('  %-24s %5d mapped, %4d removed -> %s' % (os.path.basename(path), mapped, len(dropped), dest))
        if a.verbose:
            for d in dropped:
                print('      removed ' + d[:200])
        total_bad += len(dropped)
    return 0


_SITE = re.compile(r'\bsite\(\s*(0x[0-9A-Fa-f]+)u?\s*\)')


def plugin_sources(path):
    return [path] if os.path.isfile(path) else sorted(os.path.join(dp, f) for dp, _d, fs in os.walk(path)
                                                     for f in fs if f.endswith(('.cpp', '.h')))


def write_sites(mp, oimg, nimg, sources, out):
    """every hook::site(0x...) in the sources -> a table of (original, ours) for HOOK_SITES_HEADER. False (and no
    table) when any one does not map exactly."""
    found = {}
    for path in sources:
        for f in plugin_sources(path):
            for m in _SITE.finditer(open(f, encoding='utf-8', errors='replace').read()):
                found.setdefault(int(m.group(1), 16), set()).add(os.path.relpath(f, HERE))
    rows, bad = [], 0
    for va in sorted(found):
        try:
            nv, how = mp.T(va)
            rows.append((va, nv, how))
            print('  site 0x%08X -> 0x%08X  %s   (%s)' % (va, nv, how[:90], ', '.join(sorted(found[va]))))
        except Refuse as e:
            bad += 1
            print('  site 0x%08X  REFUSED: %s   (%s)' % (va, e, ', '.join(sorted(found[va]))))
    if bad:
        print('%d site(s) refused - no site table written' % bad)
        return False
    with open(out, 'w', encoding='utf-8', newline='\n') as f:
        f.write('// GENERATED by tools/recipe_port.py - do not edit.\n')
        f.write('//   original %s  sha256 %s\n//   ours     %s  sha256 %s\n' % (
            oimg.label, oimg.sha256, nimg.label, nimg.sha256))
        f.write('// Every hook::site(original VA) the plugins use, moved with its function (identical in our build, or '
                'the aligned instruction) or its data symbol.\n#pragma once\nnamespace hook_sites {\n'
                'struct Site { unsigned orig, ours; };\nstatic const Site kSites[] = {\n')
        for va, nv, how in rows:
            f.write('    {0x%08Xu, 0x%08Xu},   // %s\n' % (va, nv, how.replace('*/', '')))
        if not rows:
            f.write('    {0u, 0u},   // (no sites)\n')
        f.write('};\nstatic const unsigned kCount = %d;\n}  // namespace hook_sites\n' % len(rows))
    return True


def cmd_sites(a):
    oimg, nimg = Image(a.orig_exe), Image(a.new_exe)
    mp = Mapper(Symbols(oimg, a.orig_pdb, a.pdbutil), Symbols(nimg, a.new_pdb, a.pdbutil))
    return 0 if write_sites(mp, oimg, nimg, a.sources, a.out) else 1


# an address literal of the original image written into plugin code (not in a comment): what `plugins` reports
_HARD = re.compile(r'0x0*([4-9A-Fa-f][0-9A-Fa-f]{5}|[1-9A-Fa-f][0-9A-Fa-f]{6,7})u?\b')

GENERATED = {'zone': ['zone_types.h', 'zone_functions.h', 'zone_globals.h', 'zone_symbols.h'],
             'worldmanager': ['wm_types.h', 'wm_functions.h', 'wm_globals.h'],
             'login': ['login_types.h', 'login_functions.h', 'login_globals.h']}


def hardcoded(img, sources):
    """[(file, line, text)]: original-image addresses a plugin writes as numbers instead of using a generated symbol
    (hook::site() is the declared way for an address inside a function; struct offsets and opcodes are not addresses)"""
    out = []
    for path in sources:
        for f in plugin_sources(path):
            if os.path.basename(f) in sum(GENERATED.values(), []):
                continue
            for n, line in enumerate(open(f, encoding='utf-8', errors='replace'), 1):
                code = line.split('//', 1)[0]
                for m in _HARD.finditer(code):
                    v = int(m.group(0).rstrip('uU'), 16)
                    if not img.in_image(v) or v < img.base + 0x1000:
                        continue
                    if re.search(r'\bsite\(\s*' + re.escape(m.group(0)), code):
                        continue
                    out.append((os.path.relpath(f, HERE), n, line.strip()[:140]))
    return out


def cmd_plugins(a):
    """the plugins of one target for our exe: remapped generated headers + the site table + every plugin built into
    a folder of its own. A plugin that still hard-codes an address is reported and NOT built."""
    oimg, nimg = Image(a.orig_exe), Image(a.new_exe)
    mp = Mapper(Symbols(oimg, a.orig_pdb, a.pdbutil), Symbols(nimg, a.new_pdb, a.pdbutil))
    tinc = os.path.join(HERE, a.target, 'include')
    gen = [os.path.join(tinc, h) for h in GENERATED.get(a.target, [])]
    missing = [g for g in gen if not os.path.exists(g)]
    if missing:
        raise Refuse('the generated headers are missing (%s) - generate them from the ORIGINAL exe + PDB first: '
                     'python zone/tools/mk_types.py --ns %s --pdb <orig pdb> --exe <orig exe> --out %s/include' %
                     (', '.join(os.path.basename(m) for m in missing), {'worldmanager': 'wm'}.get(a.target, a.target),
                      a.target))
    for g in gen:
        if oimg.sha256 not in open(g, encoding='utf-8', errors='replace').read(4096):
            raise Refuse('%s was not generated from %s (its sha256 is not in the header)' % (g, a.orig_exe))
    out_inc = os.path.abspath(os.path.join(a.out_dir, 'include', a.target))
    out_dll = os.path.abspath(os.path.join(a.out_dir, 'plugins', a.target))
    os.makedirs(out_inc, exist_ok=True)
    if gen:
        print('headers:')
        cmd_headers(argparse.Namespace(orig_exe=a.orig_exe, orig_pdb=a.orig_pdb, new_exe=a.new_exe,
                                       new_pdb=a.new_pdb, pdbutil=a.pdbutil, out_dir=out_inc, base_include=tinc,
                                       verbose=a.verbose, headers=gen))
    elif os.path.isdir(tinc):
        for f in os.listdir(tinc):
            shutil.copyfile(os.path.join(tinc, f), os.path.join(out_inc, f))
    pdir = os.path.join(HERE, a.target, 'plugins')
    names = sorted(d for d in os.listdir(pdir) if os.path.isfile(os.path.join(pdir, d, d + '.cpp'))) \
        if os.path.isdir(pdir) else []
    if a.only:
        names = [n for n in names if n in a.only]
    srcs = [os.path.join(pdir, n) for n in names] + ([tinc] if os.path.isdir(tinc) else [])
    sites_h = os.path.join(out_inc, '%s_sites.h' % a.target)
    print('sites:')
    if not write_sites(mp, oimg, nimg, srcs, sites_h):
        return 1
    hard = hardcoded(oimg, srcs)
    print('hard-coded addresses left (use a generated symbol, or hook::site() for an address no header names):')
    for f, n, t in hard:
        print('  %s:%d  %s' % (f, n, t))
    if not hard:
        print('  none')
    blocked = {f.replace('\\', '/').split('/')[2] for f, _n, _t in hard
               if f.replace('\\', '/').startswith(a.target + '/plugins/')}
    shared = [f for f, _n, _t in hard if not f.replace('\\', '/').startswith(a.target + '/plugins/')]
    env = dict(os.environ, HOOK_TARGET_INCLUDE=out_inc, HOOK_SITES=sites_h, PLUGIN_OUT=out_dll)
    env.pop('HOOK_RELOC', None)
    built, failed = [], []
    for n in names:
        if n in blocked or shared:
            failed.append((n, 'hard-codes an address (listed above) - not built for the rebuilt exe'))
            continue
        r = subprocess.run(['cmd', '/c', os.path.join(HERE, 'common', 'build_plugin.bat'), a.target, n],
                           capture_output=True, text=True, env=env, cwd=HERE)
        if r.returncode or not os.path.exists(os.path.join(out_dll, n + '.dll')):
            failed.append((n, [l for l in (r.stdout + r.stderr).splitlines() if 'error' in l.lower()][:12]))
        else:
            built.append(n)
    print('built %d plugin(s) into %s: %s' % (len(built), out_dll, ' '.join(built)))
    for n, why in failed:
        print('  NOT BUILT %s: %s' % (n, why if isinstance(why, str) else '\n      ' + '\n      '.join(why)))
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    def common(p):
        p.add_argument('--orig-exe', required=True)
        p.add_argument('--orig-pdb', required=True)
        p.add_argument('--new-exe', required=True)
        p.add_argument('--new-pdb', required=True)
        p.add_argument('--pdbutil', default=PDBUTIL)
    p = sub.add_parser('port', help='port a target\'s recipe chain')
    common(p)
    p.add_argument('--target', required=True, choices=sorted(BUILD.TARGETS))
    p.add_argument('--out-dir', required=True, help='where the ported recipes go (e.g. build/ported/<Exe>)')
    p.add_argument('--build', metavar='EXE', help='also build the patched rebuild there, and compare it with the '
                                                  'patched original')
    p.add_argument('--experimental', action='store_true')
    p.add_argument('-v', '--verbose', action='store_true')
    p = sub.add_parser('where', help='map original addresses')
    common(p)
    p.add_argument('va', nargs='+')
    p = sub.add_parser('sites', help='the hook::site() table for plugins')
    common(p)
    p.add_argument('--out', required=True)
    p.add_argument('sources', nargs='+')
    p = sub.add_parser('headers', help='remap generated plugin headers onto our exe')
    common(p)
    p.add_argument('--out-dir', required=True)
    p.add_argument('--base-include', help="copy the target's other headers (its include/ folder) beside them")
    p.add_argument('-v', '--verbose', action='store_true')
    p.add_argument('headers', nargs='+')
    p = sub.add_parser('plugins', help="build a target's hook plugins for our exe")
    common(p)
    p.add_argument('--target', required=True, choices=sorted(BUILD.TARGETS))
    p.add_argument('--out-dir', required=True, help='e.g. build/rebuilt: include/<target>/ and plugins/<target>/ go there')
    p.add_argument('--only', nargs='*', help='just these plugins')
    p.add_argument('-v', '--verbose', action='store_true')
    a = ap.parse_args()
    try:
        return {'port': cmd_port, 'where': cmd_where, 'sites': cmd_sites, 'headers': cmd_headers,
                'plugins': cmd_plugins}[a.cmd](a)
    except Refuse as e:
        print('REFUSED: %s' % e)
        return 1


if __name__ == '__main__':
    sys.exit(main())
