"""Find the 2026 client plugins' addresses in a new Fiesta.exe - so an official client update is mostly automatic.

    python client_sigs.py make                       # (re)build signatures.json from symbols.json + the reference exe
    python client_sigs.py resolve <Fiesta.exe>       # find every symbol in a new exe -> builds/<stamp>.json + report
    python client_sigs.py header                     # regenerate ../include/client_addrs.h from builds/*.json

HOW A SYMBOL IS FOUND
  code  A signature taken AT the address in the reference exe: the instruction bytes from there on, with every byte
        that moves between builds wildcarded - the 4-byte absolute operands the exe's own .reloc table lists, and the
        rel32 displacements of call / jmp / jcc. The signature grows until it is unique in the reference exe (plus a
        margin); resolve searches the new exe for it and requires exactly one hit. A second signature ENDING at the
        address (the code before it) is the fallback when the code at the address itself changed.
        A function whose start is too generic for either (a stock SEH prologue) is anchored on a unique CALL to it:
        resolve finds that call site and follows its rel32.
  data  Through code that references it: every relocated operand in .text that holds the address is a candidate; the
        first whose signature is unique becomes the anchor. resolve finds the anchor and reads the operand there.
A symbol that is not found, or found more than once, is reported and left out of the build - the plugins that need it
refuse to hook on that build (they ask client_addrs.h and get 0), so a client update never runs a plugin on a wrong
address. Fix such a symbol by hand (look at the report), add its new address to builds/<stamp>.json, rerun header.
"""
import json
import os
import re
import struct
import sys
import time

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = os.path.dirname(os.path.abspath(__file__))
SYMBOLS = os.path.join(HERE, 'symbols.json')
SIGS = os.path.join(HERE, 'signatures.json')
BUILDS = os.path.join(HERE, 'builds')
HEADER = os.path.join(os.path.dirname(HERE), 'include', 'client_addrs.h')
MIN_LEN, MAX_LEN, MARGIN = 12, 160, 8


class Exe:
    def __init__(self, path):
        self.path = path
        self.pe = pefile.PE(path, fast_load=True)
        self.pe.parse_data_directories([pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']])
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.img = self.pe.get_memory_mapped_image()
        self.stamp = self.pe.FILE_HEADER.TimeDateStamp
        text = self.pe.sections[0]
        self.t0, self.t1 = self.base + text.VirtualAddress, self.base + text.VirtualAddress + text.Misc_VirtualSize
        self.relocs = set()
        for blk in getattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC', []):
            for e in blk.entries:
                if e.type == 3:                       # HIGHLOW: a 4-byte absolute address
                    self.relocs.add(self.base + e.rva)
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.skipdata = True

    def b(self, va, n):
        return self.img[va - self.base:va - self.base + n]

    def u32(self, va):
        return struct.unpack_from('<I', self.img, va - self.base)[0]

    def call_sites(self, target):
        out = []
        for o in range(self.t0 - self.base, self.t1 - self.base - 5):
            if self.img[o] == 0xE8 and self.base + o + 5 + struct.unpack_from('<i', self.img, o + 1)[0] == target:
                out.append(self.base + o)
        return out

    def mask(self, start, n):
        """wildcard mask for [start, start+n): relocated dwords + relative branch displacements"""
        m = [True] * n
        for r in self.relocs:
            if start - 3 <= r < start + n:
                for k in range(4):
                    if 0 <= r + k - start < n:
                        m[r + k - start] = False
        for ins in self.md.disasm(self.b(start, n + 16), start):
            if ins.address >= start + n:
                break
            by = ins.bytes
            rel = None
            if by[0] in (0xE8, 0xE9) and len(by) == 5:
                rel = 1
            elif by[0] == 0x0F and len(by) == 6 and 0x80 <= by[1] <= 0x8F:
                rel = 2
            if rel is not None:
                for k in range(rel, rel + 4):
                    if 0 <= ins.address + k - start < n:
                        m[ins.address + k - start] = False
        return m


def to_pattern(data, m):
    return ''.join('%02X' % x if keep else '??' for x, keep in zip(data, m))


def to_regex(pat):
    parts = [pat[i:i + 2] for i in range(0, len(pat), 2)]
    return re.compile(b''.join(b'.' if p == '??' else re.escape(bytes([int(p, 16)])) for p in parts), re.S)


def hits(exe, pat, lo=None, hi=None, limit=3):
    rx = to_regex(pat)
    lo = (lo or exe.t0) - exe.base
    hi = (hi or exe.t1) - exe.base
    out = []
    for mo in rx.finditer(exe.img, lo, hi):
        out.append(exe.base + mo.start())
        if len(out) >= limit:
            break
    return out


def grow(exe, start, back=False):
    """the shortest unique masked signature from `start` forward (or ending at `start` when back), + MARGIN bytes"""
    for n in range(MIN_LEN, MAX_LEN + 1, 4):
        s = start - n if back else start
        pat = to_pattern(exe.b(s, n), exe.mask(s, n))
        if pat.count('??') * 2 > len(pat) * 0.6:
            continue
        if len(hits(exe, pat, limit=2)) == 1:
            n2 = min(n + MARGIN, MAX_LEN)
            s = start - n2 if back else start
            return to_pattern(exe.b(s, n2), exe.mask(s, n2))
    return None


def make():
    syms = json.load(open(SYMBOLS, encoding='utf-8'))
    exe = Exe(syms['reference']['exe'])
    out = {'reference': syms['reference'], 'stamp': exe.stamp, 'symbols': {}}
    for s in syms['symbols']:
        va = int(s['va'], 16)
        e = {'va': s['va'], 'kind': s['kind']}
        if s['kind'] == 'code':
            e['fwd'] = grow(exe, va)
            e['back'] = grow(exe, va, back=True)
            if not e['fwd']:                         # a generic prologue: anchor on a unique CALL to it as well
                for c in exe.call_sites(va):
                    pat = grow(exe, c)
                    if pat:
                        e['call'] = pat
                        e['anchor'] = '0x%08X' % c
                        break
        else:
            refs = sorted(r for r in exe.relocs if exe.t0 <= r < exe.t1 and exe.u32(r) == va)
            for r in refs:                         # the anchor: an instruction holding the address, signature at it
                ins_start = next((i.address for i in exe.md.disasm(exe.b(r - 8, 24), r - 8)
                                  if i.address <= r < i.address + i.size), None)
                if ins_start is None:
                    continue
                pat = grow(exe, ins_start)
                if pat:
                    e.update(anchor='0x%08X' % ins_start, operand=r - ins_start, fwd=pat)
                    break
            e['refs'] = len(refs)
        status = 'ok' if e.get('fwd') or e.get('back') else ('ok (via call %s)' % e['anchor']) if e.get('call') else 'NO SIGNATURE'
        print('%-24s %s %-5s %s' % (s['name'], s['va'], s['kind'], status))
        out['symbols'][s['name']] = e
    json.dump(out, open(SIGS, 'w', encoding='utf-8'), indent=1)
    print('-> %s (reference stamp %08X)' % (SIGS, exe.stamp))


def resolve(path):
    sigs = json.load(open(SIGS, encoding='utf-8'))
    exe = Exe(path)
    found, report = {}, []
    for name, e in sigs['symbols'].items():
        old = int(e['va'], 16)
        va, how = None, ''
        if e['kind'] == 'code':
            for key, off in (('fwd', 0), ('back', None)):
                pat = e.get(key)
                if not pat:
                    continue
                h = hits(exe, pat)
                if len(h) == 1:
                    va = h[0] + (off if off is not None else len(pat) // 2)
                    how = key
                    break
                how += '%s:%d hits ' % (key, len(h))
            if not va and e.get('call'):
                h = hits(exe, e['call'])
                if len(h) == 1:
                    va, how = h[0] + 5 + struct.unpack_from('<i', exe.img, h[0] + 1 - exe.base)[0], 'call'
                else:
                    how += 'call:%d hits' % len(h)
        elif e.get('fwd'):
            h = hits(exe, e['fwd'])
            if len(h) == 1:
                va, how = exe.u32(h[0] + e['operand']), 'anchor'
            else:
                how = 'anchor:%d hits' % len(h)
        if va:
            found[name] = '0x%08X' % va
        report.append('%-24s %s -> %s  %s' % (name, e['va'], ('0x%08X (%+#x)' % (va, va - old)) if va else 'NOT FOUND', how))
    os.makedirs(BUILDS, exist_ok=True)
    ver = ''
    mf = os.path.join(os.path.dirname(path), 'manifest.txt')
    if os.path.exists(mf):
        ver = open(mf, encoding='utf-8', errors='replace').readline().strip().replace('version ', '')
    rec = {'exe': path, 'version': ver, 'stamp': '%08X' % exe.stamp,
           'date': time.strftime('%Y-%m-%d', time.gmtime(exe.stamp)), 'symbols': found}
    dst = os.path.join(BUILDS, '%08X.json' % exe.stamp)
    json.dump(rec, open(dst, 'w', encoding='utf-8'), indent=1)
    print('\n'.join(report))
    miss = len(sigs['symbols']) - len(found)
    print('-> %s: %d/%d found%s' % (dst, len(found), len(sigs['symbols']), (', %d MISSING - fix by hand' % miss) if miss else ''))


def header():
    syms = [s['name'] for s in json.load(open(SYMBOLS, encoding='utf-8'))['symbols']]
    builds = [json.load(open(os.path.join(BUILDS, f), encoding='utf-8')) for f in sorted(os.listdir(BUILDS)) if f.endswith('.json')]
    L = ['// GENERATED by client/addresses/client_sigs.py header - do not edit; edit symbols.json / builds/*.json and rerun.',
         '// The 2026 client plugins\' addresses per Fiesta.exe build (PE TimeDateStamp). caddr::va(caddr::kX) returns the',
         '// address at the default image base (pass it to hook::rebase), or 0 when the running build is unknown or the',
         '// symbol was not found in it - a plugin then logs and does not hook.',
         '#pragma once', '#include <windows.h>', '#include <initializer_list>', '', 'namespace caddr {', '', 'enum Sym {']
    L += ['    k%s,' % n for n in syms] + ['    kCount', '};', '']
    L += ['inline const char* const kNames[kCount] = {'] + ['    "%s",' % n for n in syms] + ['};', '']
    L += ['struct Build {', '    unsigned stamp;', '    const char* version;', '    unsigned va[kCount];', '};', '']
    L.append('inline const Build kBuilds[] = {')
    for b in builds:
        vals = ', '.join(b['symbols'].get(n, '0') for n in syms)
        L.append('    {0x%su, "%s", {%s}},' % (b['stamp'], b['version'], vals))
    L += ['};', '',
          'inline const Build* current() {',
          '    static const Build* cur = nullptr;',
          '    static bool done = false;',
          '    if (!done) {',
          '        done = true;',
          '        const unsigned char* m = (const unsigned char*)GetModuleHandleA(nullptr);',
          '        const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(m + ((const IMAGE_DOS_HEADER*)m)->e_lfanew);',
          '        for (const Build& b : kBuilds)',
          '            if (b.stamp == nt->FileHeader.TimeDateStamp) cur = &b;',
          '    }',
          '    return cur;',
          '}', '',
          'inline unsigned va(Sym s) {',
          '    const Build* b = current();',
          '    return b ? b->va[s] : 0;',
          '}', '',
          '// the first of `need` this build lacks (its name), or nullptr when the plugin can hook - "unknown build" when the',
          '// running Fiesta.exe is none of kBuilds',
          'inline const char* missing(std::initializer_list<Sym> need) {',
          '    if (!current()) return "unknown Fiesta.exe build (run client/addresses/client_sigs.py resolve)";',
          '    for (Sym s : need)',
          '        if (!va(s)) return kNames[s];',
          '    return nullptr;',
          '}', '',
          '}  // namespace caddr', '']
    open(HEADER, 'w', encoding='utf-8', newline='\r\n').write('\n'.join(L))
    print('-> %s: %d symbols x %d build(s) %s' % (HEADER, len(syms), len(builds), [b['version'] for b in builds]))


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'make':
        make()
    elif cmd == 'resolve' and len(sys.argv) > 2:
        resolve(sys.argv[2])
    elif cmd == 'header':
        header()
    else:
        print(__doc__)
