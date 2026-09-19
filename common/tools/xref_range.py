#!/usr/bin/env python
"""Every instruction in Zone.exe whose imm32 / disp32 falls inside an address RANGE (or a set of
register-relative offsets), grouped by the containing function.

    python common/tools/xref_range.py --range 0x8B7018-0x8B7418            # absolute references into a static object
    python common/tools/xref_range.py --disp 0x28068-0x28098                # [reg + disp32] member offsets (mid-object array)
    python common/tools/xref_range.py --range ... --exe Z:/ServerSource/Zone00/Zone.exe --pdb Z:/ServerSource/Zone00/Zone.pdb

WHY: relocating or growing a static object means rewriting every instruction that carries part of it. An
exact-value search finds the references to its FIRST byte; the members after it are reached as base+8,
base+0x10, base+N (the two sites mob-spawn-group-cap missed on its first attempt were exactly that). So
the search is over a range, and it reports both absolute operands (imm32 and disp32 without a base
register) and, with --disp, register-relative displacements - the form a member access takes when `this`
is in a register. Every hit prints the containing symbol, the VA, the raw bytes and the operand, so a
recipe can cite each edit.
"""
import argparse
import bisect
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
S_PUB32 = 0x110E
IMAGE = 0x400000


def publics(pdb_path, secs):
    """{va: name} from S_PUB32 records (the same raw scan ik-fiesta-bots/tools/pdb_disasm.py uses)."""
    data = open(pdb_path, 'rb').read()
    out = {}
    for m in re.finditer(rb'[?_][ -~]{4,220}', data):
        i = m.start()
        if i < 12:
            continue
        rectyp, flags, off, seg = struct.unpack_from('<HIIH', data, i - 12)
        if rectyp != S_PUB32 or seg < 1 or seg > len(secs):
            continue
        va = IMAGE + secs[seg - 1][0] + off
        out.setdefault(va, m.group(0).decode('latin-1'))
    return out


def parse_range(s):
    a, b = s.split('-')
    return int(a, 16), int(b, 16)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', default='Z:/ServerSource/Zone00/Zone.exe')
    ap.add_argument('--pdb', default='Z:/ServerSource/Zone00/Zone.pdb')
    ap.add_argument('--range', action='append', default=[], help='absolute VA range lo-hi (hex), repeatable')
    ap.add_argument('--disp', action='append', default=[], help='register-relative disp32 range lo-hi (hex), repeatable')
    a = ap.parse_args()
    import pefile
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86 import X86_OP_MEM, X86_OP_IMM
    pe = pefile.PE(a.exe, fast_load=True)
    secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData, s.Name.rstrip(b'\0').decode()) for s in pe.sections]
    syms = publics(a.pdb, secs)
    sym_vas = sorted(syms)
    raw = open(a.exe, 'rb').read()
    ranges = [parse_range(r) for r in a.range]
    disps = [parse_range(r) for r in a.disp]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    text = secs[0]
    code = raw[text[2]:text[2] + text[3]]
    base = IMAGE + text[0]
    hits = []
    # linear sweep; on a decode gap skip one byte (padding / data in .text)
    off = 0
    while off < len(code):
        got = False
        for ins in md.disasm(code[off:off + 16], base + off, count=1):
            got = True
            for op in ins.operands:
                v = None
                kind = ''
                if op.type == X86_OP_IMM:
                    v, kind = op.imm & 0xFFFFFFFF, 'imm'
                elif op.type == X86_OP_MEM:
                    if op.mem.base == 0 and op.mem.index == 0:
                        v, kind = op.mem.disp & 0xFFFFFFFF, 'abs'
                    elif op.mem.base == 0 and op.mem.index != 0:
                        v, kind = op.mem.disp & 0xFFFFFFFF, 'abs+idx'
                    else:
                        d = op.mem.disp & 0xFFFFFFFF
                        if any(lo <= d < hi for lo, hi in disps):
                            hits.append((ins.address, ins.bytes.hex(), ins.mnemonic + ' ' + ins.op_str, 'disp', d))
                        continue
                if v is not None and any(lo <= v < hi for lo, hi in ranges):
                    hits.append((ins.address, ins.bytes.hex(), ins.mnemonic + ' ' + ins.op_str, kind, v))
            off += ins.size
        if not got:
            off += 1
    for va, hexb, txt, kind, v in hits:
        i = bisect.bisect_right(sym_vas, va) - 1
        fn = syms[sym_vas[i]] if i >= 0 else '?'
        print('%08X  %-24s %-48s %-7s 0x%X   in %s+0x%X' % (va, hexb, txt, kind, v, fn[:90], va - sym_vas[i]))
    print('%d hits' % len(hits))


if __name__ == '__main__':
    main()
