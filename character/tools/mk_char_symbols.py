"""Name Character.exe's functions WITHOUT a PDB.

    python character/tools/mk_char_symbols.py [--exe Z:/ServerSource/Character/Character.exe] [--out character/include/character_symbols.h]

There is no Character.pdb in the server folders. Two things make one unnecessary:

1. HANDLER NAMES FROM THE LOG STRINGS. Every CPFsCharacter::fc_NC_* handler writes its own name into its
   error log, so the name is a string in .rdata and the handler is the function whose code pushes that
   string's address. Find each string, find the `push imm32` of its address, walk back to the prologue.

2. FRAMEWORK FUNCTIONS FROM Account.pdb. Account, AccountLog and Character are built on one DB-bridge
   framework - 81 of Character's 113 RTTI classes are also in Account.exe, among them Database, DBRecord,
   CParser, CSession, CSessionWorker and WinService. Identical source compiles to identical bytes except
   where an address is embedded, so a framework function is found in Character.exe by its Account.exe
   bytes with every absolute address and rel32 masked out. A match must be UNIQUE to be kept.

Everything this cannot establish is left out rather than guessed.
"""
import argparse
import hashlib
import os
import re
import struct
import sys

import capstone
import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, 'C:/Projects/Fiesta2026on2016/tools')
import disasm_at as D  # noqa: E402

ACCOUNT_EXE = 'Z:/ServerSource/Account/Account.exe'
ACCOUNT_PDB = 'Z:/ServerSource/Account/Account.pdb'

# The framework functions a plugin needs, by Account.pdb mangled name -> the name we export.
FRAMEWORK = {
    # Real mangled names, read from Account.pdb - an earlier version typed four of these from memory and
    # got them wrong (query takes `const char*`, and bindColumns / openDB are virtual: UAE, not QAE).
    '?openDB@Database@@UAE_NPAD@Z': 'Database_openDB',
    '?InitEnv@Database@@IAE_NXZ': 'Database_InitEnv',
    '?CommitTran@Database@@QAE_NXZ': 'Database_CommitTran',
    '?close@Database@@QAEXXZ': 'Database_close',
    '?openDB@DBRecord@@UAE_NPAD@Z': 'DBRecord_openDB',
    '?query@DBRecord@@QAA_NPBDZZ': 'DBRecord_query',
    '?bindColumns@DBRecord@@UAE_NXZ': 'DBRecord_bindColumns',
    '?fetch@DBRecord@@QAE_NXZ': 'DBRecord_fetch',
    '?endFetch@DBRecord@@QAEXXZ': 'DBRecord_endFetch',
    '?close@DBRecord@@QAEXXZ': 'DBRecord_close',
    '?getStatement@DBRecord@@QAEPAXXZ': 'DBRecord_getStatement',
    # The only two column readers the framework has. Anything wider (blobs, strings) is read with ODBC
    # directly on getStatement()'s HSTMT - see dbhook.h.
    '??5DBRecord@@QAEAAV0@AAH@Z': 'DBRecord_readInt',
    '??5DBRecord@@QAEAAV0@AAK@Z': 'DBRecord_readULong',
    '?CheckConnectionValidation@CPFs@@QAEHPAUNETPACKET@@@Z': 'CPFs_CheckConnectionValidation',
}

# Functions found by READING THE DISASSEMBLY - no log string, no Account.pdb twin. Each is kept only if the
# exe has the bytes it was found with at that address (checked here, and emitted so a plugin can check the
# exe it is actually loaded into: chr::verify_known()). The signature is what the call sites show.
#   (name, va, head bytes, typedef'd signature as (return, params), how it was found)
KNOWN = [
    ('ItemListReader', 0x469F70, '558BEC8B451056',
     ('int', 'void* ecx, void* edx, void* dbf, unsigned long owner, int type, int limit, int* count, void* records'),
     'reads bag `type` of `owner` (p_Item_GetListType) into 40-byte records, at most `limit`; __thiscall on '
     'dbf+0x24, ret 0x18. Every per-bag wrapper (0x46A290 bag 9 limit 0x90, 0x46A2C0 bag 8 ...) calls it; '
     'refuses type >= 0x11 unless char-itemlist-void widened it.'),
    ('ItemListPack', 0x402E50, '558BEC81EC88000000',
     ('int', 'void* cpfs, void* edx, void* list, unsigned char* out, int* len'),
     'packs a reader list {int count; int pad; records} into the zone wire form {.., u8 count, items}; '
     '__thiscall on the handler\'s CPFs, ret 0xC.'),
    ('InventoryPacker', 0x402F80, '558BECB88C160000',
     ('int', 'void* cpfs, void* edx, unsigned long owner, unsigned char* out, int* len'),
     'bag 9 end to end: reader (limit 144, a stack buffer sized for exactly that) + ItemListPack. Called by '
     'fc_NC_CHAR_CHARDATA_REQ (login) and GET_ITEMLIST_BY_TYPE case 9. char_void replaces it (192).'),
]

UNDNAME = r'C:/Program Files/Microsoft Visual Studio/18/Community/VC/Tools/MSVC/14.50.35717/bin/Hostx64/x86/undname.exe'
PRIMITIVE = {'void', 'bool', 'char', 'signed char', 'unsigned char', 'short', 'unsigned short', 'int',
             'unsigned int', 'long', 'unsigned long', 'float', 'double', 'wchar_t', '__int64', 'unsigned __int64'}


def framework_signatures(mangled_names):
    """{mangled: (ret, conv, [params])} from undname. There are no Character types to spell, so a class is
    void* - the ABI is the same, and the framework is used through its functions, not its fields."""
    import subprocess
    if not os.path.exists(UNDNAME):
        return {}
    r = subprocess.run([UNDNAME] + list(mangled_names), capture_output=True, text=True, errors='replace')
    und = dict(re.findall(r'Undecoration of :- "(.*?)"\s*\nis :- "(.*?)"', r.stdout))

    def spell(t):
        t = re.sub(r'\b(const|volatile) ', '', t).replace(' const', '').strip()
        stars = ''
        while t.endswith('*') or t.endswith('&'):
            stars += '*'
            t = t[:-1].rstrip()
        if re.match(r'(class|struct|union|enum) ', t):
            return 'void' + (stars or '*') if stars else None     # a class by VALUE cannot be spelled
        if t == '__int64':
            t = 'long long'
        return (t + stars) if t in PRIMITIVE or t == 'long long' else None

    out = {}
    for m, text in und.items():
        g = re.match(r'^(?:(?:public|private|protected): )?(?:(?:static|virtual) )*(.+?) '
                     r'(__thiscall|__cdecl|__stdcall|__fastcall) (.+?)\((.*)\)(?: const)?$', text)
        if not g:
            continue
        ret, conv, qual, args = g.groups()
        # a NON-static member that is __cdecl (DBRecord::query is variadic, so it has to be) takes `this` as a
        # hidden FIRST STACK argument - undname does not show it
        cdecl_member = conv == '__cdecl' and '::' in qual and 'static ' not in text
        variadic = args.endswith('...')
        plist = [] if args in ('void', '', '...') else [a for a in re.split(r',', args.replace(',...', '')) if a]
        sp = [spell(ret)] + [spell(a) for a in plist]
        if any(x is None for x in sp):
            continue
        params = [('%s a%d' % (x, i + 1)) for i, x in enumerate(sp[1:])]
        if conv == '__thiscall':
            params = ['void* self', 'void* edx'] + params
            conv = '__fastcall'
        elif cdecl_member:
            params = ['void* self'] + params
        if variadic:
            if conv != '__cdecl':
                continue
            params.append('...')
        out[m] = (sp[0], conv, params, text)
    return out


class Image:
    def __init__(self, path):
        self.path = path
        self.pe = pefile.PE(path, fast_load=True)
        self.data = open(path, 'rb').read()
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.text = next(s for s in self.pe.sections if s.Name.startswith(b'.text'))
        self.tdata = self.text.get_data()
        self.tva = self.base + self.text.VirtualAddress
        self.lo, self.hi = self.base, self.base + self.pe.OPTIONAL_HEADER.SizeOfImage

    def va_of_file(self, off):
        return self.base + self.pe.get_rva_from_offset(off)

    def func_start(self, va):
        p = va - self.tva
        for s in range(p, max(0, p - 0x6000), -1):
            if self.tdata[s:s + 3] == b'\x55\x8B\xEC' and (s == 0 or self.tdata[s - 1] in (0xCC, 0xC3, 0x90)
                                                          or self.tdata[s - 3] == 0xC2):
                return self.tva + s
        return None


# ---- 1. handlers by their log string ----------------------------------------------------------------

def handlers(img):
    # The name is followed by whatever the message says next (" - FAILED CharNo=%d", " : DB_ERROR ..."), NOT
    # by a NUL - requiring one matched 5 of the ~137 handlers. A handler usually logs several such strings;
    # all of them must lead back to the same function, so the functions are collected per NAME.
    per_name = {}
    for m in re.finditer(rb'([A-Za-z_]+)::((?:fc|gds|usp)_[A-Za-z0-9_]+)(?![A-Za-z0-9_])', img.data):
        cls, fn = m.group(1).decode(), m.group(2).decode()
        # The name is often INSIDE a longer log string ("ERROR - CPFsCharacter::fc_NC_..."), and code refers
        # to a string by its START, so walk back to the string's first byte before searching for references.
        start = m.start()
        while start > 0 and img.data[start - 1] not in (0,):
            start -= 1
        try:
            sva = img.va_of_file(start)
        except Exception:
            continue
        # the handler pushes (or movs) the string's address; the string is referenced by its absolute VA
        pat = struct.pack('<I', sva)
        starts = set()
        for r in re.finditer(re.escape(pat), img.tdata):
            st = img.func_start(img.tva + r.start())
            if st:
                starts.add(st)
        per_name.setdefault('%s::%s' % (cls, fn), set()).update(starts)
    out = {}
    for name, starts in per_name.items():
        if len(starts) == 1:
            out[name] = next(iter(starts))
        elif starts:
            out[name] = None                     # ambiguous: its strings live in more than one function
    return out


def handlers_by_reply(img, named, enums_path, check_va):
    """Handlers that log NO name of their own, named by the one reply they build instead.

    A REQ handler answers with its _ACK: `push <ack opcode>` into the packet-header setter. When exactly one
    unnamed function pushes an _ACK opcode, and a _REQ of the same name exists, that function is the _REQ's
    handler. Found this way first: NC_CHAR_GET_ITEMLIST_BY_TYPE_REQ (0x1076) at 0x417460, which pushes 0x1077
    three times and writes no log line with its name. Opcodes = (department << 10) | command, from the
    PDB-extracted enum list."""
    import json
    if not os.path.exists(enums_path):
        print('  (no enum list at %s - handlers named by reply skipped)' % enums_path)
        return {}
    op = {}
    for dept in json.load(open(enums_path, encoding='utf-8')).values():
        for name, cmd in dept['opcodes'].items():
            op[name] = (dept['id'] << 10) | cmd
    taken = {v for v in named.values() if v}

    def handler_shaped(st):
        # the shape every log-named handler has: CPFs::CheckConnectionValidation called near the top, and a
        # `ret 8` (two stack arguments, NETPACKET* and int) before the function's trailing padding
        p = st - img.tva
        body = img.tdata[p:p + 0x6000]
        end = body.find(b'\xCC\xCC')
        body = body[:end if end > 0 else len(body)]
        early = any(body[i] == 0xE8 and st + i + 5 + struct.unpack_from('<i', body, i + 1)[0] == check_va
                    for i in range(min(0x80, len(body) - 5)))
        return early and b'\xC2\x08\x00' in body

    claims = {}
    for ack, code in op.items():
        if not ack.endswith('_ACK') or ack[:-4] + '_REQ' not in op:
            continue
        starts = set()
        for r in re.finditer(re.escape(b'h' + struct.pack('<I', code)), img.tdata):
            st = img.func_start(img.tva + r.start())
            if st:
                starts.add(st)
        if len(starts) == 1:
            claims.setdefault(next(iter(starts)), []).append(ack[:-4] + '_REQ')
    out = {}
    for st, reqs in claims.items():
        # one function claimed by two _ACKs is not named: which request it serves is not decidable here
        if len(reqs) == 1 and st not in taken and check_va and handler_shaped(st):
            out['CPFsCharacter::fc_%s' % reqs[0]] = st
    return out


# ---- 2. framework functions by masked bytes ----------------------------------------------------------

def masked(img, va, n=None):
    """The function's bytes with every embedded absolute address and relative target replaced by None."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    p = va - img.tva
    out = []
    for i in md.disasm(img.tdata[p:p + 0x800], va):
        raw = list(i.bytes)
        if i.mnemonic.startswith(('call', 'j')) and i.operands and i.operands[0].type == capstone.x86.X86_OP_IMM \
                and i.size >= 5:
            raw[-4:] = [None] * 4                       # rel32 target: depends on layout
        else:
            for k in range(0, len(raw) - 3):            # any imm/disp that looks like an address in the image
                v = struct.unpack('<I', bytes(b if b is not None else 0 for b in raw[k:k + 4]))[0]
                if img.lo <= v < img.hi:
                    raw[k:k + 4] = [None] * 4
        out += raw
        if i.mnemonic in ('ret', 'retn') or (i.mnemonic == 'jmp' and i.op_str.startswith('dword')):
            break
    return out


def find_unique(img, sig):
    """VA of the only place in img's .text where sig matches, or None."""
    anchor_at = next((k for k in range(len(sig) - 7) if all(b is not None for b in sig[k:k + 8])), None)
    if anchor_at is None:
        return None
    anchor = bytes(sig[anchor_at:anchor_at + 8])
    hits = []
    for m in re.finditer(re.escape(anchor), img.tdata):
        s = m.start() - anchor_at
        if s < 0 or s + len(sig) > len(img.tdata):
            continue
        if all(b is None or img.tdata[s + k] == b for k, b in enumerate(sig)):
            hits.append(img.tva + s)
            if len(hits) > 1:
                return None
    return hits[0] if hits else None


def framework(char):
    acct = Image(ACCOUNT_EXE)
    secs = D.sections(ACCOUNT_EXE)[0]
    pubs = {n: 0x400000 + secs[s - 1][0] + o for n, s, o in D.publics(open(ACCOUNT_PDB, 'rb').read())
            if 1 <= s <= len(secs)}
    out, how, acct_va = {}, {}, {}
    for mangled, name in FRAMEWORK.items():
        va = pubs.get(mangled)
        if va is None:
            print('  not in Account.pdb: %s' % mangled)
            continue
        acct_va[name] = va
        out[name] = find_unique(char, masked(acct, va))
        how[name] = 'unique byte match' if out[name] else None

    # A tiny function (getStatement is little more than `mov eax, [ecx+0xC]; ret`) byte-matches dozens of
    # others, so a search cannot place it. But functions from one source file are laid out together: if two
    # uniquely-matched functions of the same class sit the same distance apart in both exes, the block is
    # laid out identically, and the rest of it can be LOCATED by offset and then VERIFIED byte-for-byte at
    # exactly that address. Verified, not assumed - a candidate that does not match is dropped.
    for name in list(out):
        if out[name]:
            continue
        cls = name.split('_')[0]
        anchors = [n for n in out if out[n] and n.split('_')[0] == cls]
        for a in anchors:
            cand = out[a] + (acct_va[name] - acct_va[a])
            sig = masked(acct, acct_va[name])
            p = cand - char.tva
            if 0 <= p and p + len(sig) <= len(char.tdata) and                     all(b is None or char.tdata[p + k] == b for k, b in enumerate(sig)):
                out[name] = cand
                how[name] = 'same layout as %s, bytes verified at the address' % a
                break
    framework.how = how
    return out


# ---- 3. where each worker keeps its DB object -------------------------------------------------------

def worker_db_offset(img, named):
    """CSessionWorker::m_DBF, read off every call to a stored-procedure wrapper.

    Each handler that runs a query does `mov eax, [this]` (the worker), `add eax, <m_DBF>`, pushes that as
    the DBRecord* and calls a CSQLP*::usp_*. Collect the immediate at every such call site; they must ALL
    agree, or nothing is emitted. (Account.exe's is 0x124C per its PDB - the same framework.)"""
    usp = {va for name, va in named.items() if va and '::usp_' in name}
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    seen = {}
    for m in re.finditer(re.escape(bytes([0xE8])), img.tdata):     # every call rel32
        p = m.start()
        if p < 40 or p + 5 > len(img.tdata):
            continue
        tgt = (img.tva + p + 5 + struct.unpack_from('<i', img.tdata, p + 1)[0]) & 0xFFFFFFFF
        if tgt not in usp:
            continue
        ins = list(md.disasm(img.tdata[p - 40:p + 5], img.tva + p - 40))
        if not ins or ins[-1].address != img.tva + p:
            continue
        for i in ins:
            mm = re.match(r'add e[a-d]x, (0x[0-9a-f]+)$', '%s %s' % (i.mnemonic, i.op_str))
            if mm and int(mm.group(1), 16) > 0x400:
                v = int(mm.group(1), 16)
                seen[v] = seen.get(v, 0) + 1
    if len(seen) != 1:
        return None, seen
    v = next(iter(seen))
    return v, seen


# ---- output -----------------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--exe', default='Z:/ServerSource/Character/Character.exe')
    ap.add_argument('--out', default=os.path.join(HERE, '..', 'include', 'character_symbols.h'))
    ap.add_argument('--enums', default='C:/Projects/fiesta-proxy/lib/FiestaLib-Reloaded/docs/extracted/merged/all-enums.json',
                    help='FiestaLib-Reloaded all-enums.json: names handlers that log no name by the reply they build')
    a = ap.parse_args()
    img = Image(a.exe)
    sha = hashlib.sha256(img.data).hexdigest()

    hs = handlers(img)
    fw = framework(img)
    by_reply = {k: v for k, v in handlers_by_reply(img, hs, a.enums, fw.get('CPFs_CheckConnectionValidation')).items()
                if k not in hs}
    hs.update(by_reply)

    ok_h = {k: v for k, v in hs.items() if v}
    amb = sorted(k for k, v in hs.items() if not v)
    lines = [
        '// GENERATED by character/tools/mk_char_symbols.py - do not edit, re-run the tool.',
        '//   exe %s  sha256 %s' % (os.path.basename(a.exe), sha),
        '//',
        '// There is no Character.pdb. Handler names come from the log strings each handler writes; framework',
        '// functions are Account.pdb\'s, found in this exe by their masked bytes. See the tool for both.',
        '// Addresses are VAs at the default base 0x00400000 - rebase at runtime.',
        '#pragma once',
        '',
        'namespace chr {',
        '',
        'static const unsigned int kImageBase = 0x%08Xu;' % img.base,
        'static const char kExeSha256[] = "%s";' % sha,
        '',
        '// Handlers: int __thiscall CPFs*::fc_NC_*(NETPACKET*, int). Found by their own log string.',
        'struct Handler { const char* name; unsigned int va; };',
        'static const Handler kHandlers[] = {',
    ]
    for k in sorted(ok_h):
        lines.append('    { "%s", 0x%08Xu },' % (k, ok_h[k]))
    lines += ['};', 'static const int kHandlerCount = %d;' % len(ok_h), '']
    if by_reply:
        lines.append('// Of these, named by the one _ACK they build (they log no name of their own): %d' % len(by_reply))
        for k in sorted(by_reply):
            lines.append('//   %s' % k)
        lines.append('')
    if amb:
        lines.append('// Named in a log string but used by more than one function, so not assigned: %d' % len(amb))
        for k in amb:
            lines.append('//   %s' % k)
        lines.append('')
    lines.append('// Framework functions (Account.pdb names, matched by bytes). 0 = no UNIQUE match - not guessed.')
    for name in sorted(fw):
        lines.append('static const unsigned int kVa_%s = 0x%08Xu;   // %s'
                     % (name, fw[name] or 0, framework.how.get(name) or 'NOT FOUND'))

    # Typed accessors: chr::fn::X() is the live, callable pointer - no kVa, no rebase, no cast at the call
    # site. A framework function the byte match did not find yields NULL rather than a wrong address.
    sigs = framework_signatures(FRAMEWORK)
    fn_lines = ['', '// Typed accessors. __thiscall is spelled __fastcall with a dead edx (same ABI, callee-clean).',
                'namespace fn {', '']
    for mangled, name in sorted(FRAMEWORK.items(), key=lambda kv: kv[1]):
        if not fw.get(name) or mangled not in sigs:
            fn_lines.append('// %s: %s' % (name, 'not found in this exe' if not fw.get(name) else 'signature not spellable'))
            continue
        ret, conv, params, text = sigs[mangled]
        fn_lines.append('// %s' % text)
        fn_lines.append('typedef %s (%s* %s_t)(%s);' % (ret, conv, name, ', '.join(params) or 'void'))
        fn_lines.append('inline %s_t %s() { return (%s_t)::hook::rebase(kVa_%s, kImageBase); }' % (name, name, name, name))
        fn_lines.append('')
    known_ok = []
    for name, va, head, (ret, params), why in KNOWN:
        want = bytes.fromhex(head)
        got = img.data[img.pe.get_offset_from_rva(va - img.base):][:len(want)]
        if got != want:
            fn_lines.append('// %s: NOT at 0x%08X in this exe (bytes differ) - left out' % (name, va))
            print('  KNOWN %-16s bytes DIFFER at 0x%08X - left out' % (name, va))
            continue
        known_ok.append((name, va, want))
        fn_lines.append('// %s - found by reading the disassembly: %s' % (name, why))
        fn_lines.append('typedef %s (__fastcall* %s_t)(%s);' % (ret, name, params))
        fn_lines.append('static const unsigned int kVa_%s = 0x%08Xu;' % (name, va))
        fn_lines.append('inline %s_t %s() { return (%s_t)::hook::rebase(kVa_%s, kImageBase); }' % (name, name, name, name))
        fn_lines.append('')
    fn_lines.append('}  // namespace fn')
    fn_lines += ['', '// The bytes each disassembly-found function starts with, for chr::verify_known() (charhook.h):',
                 '// the header was generated from one exe; a plugin runs in whichever one is deployed.',
                 'struct KnownHead { const char* name; unsigned int va; unsigned char head[16]; unsigned int n; };',
                 'static const KnownHead kKnownHeads[] = {']
    for name, va, want in known_ok:
        fn_lines.append('    { "%s", 0x%08Xu, { %s }, %d },' % (name, va, ', '.join('0x%02X' % b for b in want), len(want)))
    fn_lines += ['};', 'static const int kKnownCount = %d;' % len(known_ok)]
    lines += fn_lines
    dbf, votes = worker_db_offset(img, hs)
    lines.append('')
    if dbf is not None:
        lines.append("// CSessionWorker::m_DBF - each worker thread's own, already-connected DBRecord. Read off every call to a")
        lines.append('// stored-procedure wrapper (add reg, <this> before the call): %d call sites, all agreeing.' % votes[dbf])
        lines.append('static const unsigned int kWorkerDbfOffset = 0x%X;' % dbf)
    else:
        lines.append('// CSessionWorker::m_DBF: call sites DISAGREE (%s) - not emitted.' % votes)
    lines += ['', '}  // namespace chr', '']

    dest = os.path.abspath(a.out)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    open(dest, 'w', encoding='utf-8', newline='\n').write('\n'.join(lines))
    print('%s' % dest)
    print('  handlers named   : %d  (ambiguous, left out: %d)' % (len(ok_h), len(amb)))
    for name in sorted(fw):
        print('  %-32s %s' % (name, ('0x%08X' % fw[name]) if fw[name] else 'NO UNIQUE MATCH'))


if __name__ == '__main__':
    main()
