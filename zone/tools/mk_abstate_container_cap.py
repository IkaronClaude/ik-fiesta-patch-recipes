"""Generate zone/recipes/abstate-container-cap.json: the per-AbStataIndex arrays of AbnormalStateContainer for
`slots` indexes (the other half of abstate-index-cap, which lifted only the dictionary).

    python zone/tools/mk_abstate_container_cap.py --exe Z:/ServerSource/Zone00/Zone.exe

WHY (found 2026-09-24 from a zone01 crash dump, docs in the recipe): with the 2026 AbState table switched in (1096
rows, AbStataIndex up to 1093), two unchecked writes indexed by AbStataIndex ran past 792-slot storage:

  1. ?abstateidentarray (0x875228) = AbnormalStateIdentifier[792], 12 bytes each, BSS. AbstateElementInObject::aeo_Set
     writes identarray[idx] (0x40A47F) BEFORE it checks idx against abstatetemplate's count (0x40A48D); every
     reader goes through it too. Index 1093 (Gold Dragon's Grace) lands on 0x878564 - inside ?abstatetemplate,
     over the handler objects of AbStataIndex 228/229 - and the next Shield Increase T1 (229) called a null vtable
     slot (aeo_Set+0x176, EIP 0). Fix: the array moves to a new section sized for `slots`; every reference is an
     indexed [reg*4 + disp32] with disp = base + 0 / 4 / 8 / 0xA, rewritten to the same field of the new array.
  2. ShineObject::so_AbnormalState_BitSet / BitReset (0x401A00 / 0x401A40) set bit idx of the object's
     ABNORMAL_STATE_BIT (99 bytes = 792 bits, vtable+0x4A0) with no bound: index 1093 writes 37 bytes past it, into
     the object. That array is part of the object and of the 2016 wire (99 bytes), so it cannot grow here: both
     get a bound check (idx >= 792 -> return), i.e. a state past 792 is not in the view bitset others receive. The
     2026 wire carries 136 bytes; widening the object + wire is the open part of feature A1.

abstatetemplate (the per-index handler objects) is NOT touched: all 9 readers compare idx against its count (792)
first, so an index past it simply has no special handler - the stock behaviour for any state without one.
"""
import argparse
import json
import os
import struct

import capstone
import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
ARR = 0x00875228            # ?abstateidentarray@@3PAUAbnormalStateIdentifier@AbnormalStateContainer@@A
ENTRY = 12
OLD_SLOTS = 792
ARR_END = ARR + OLD_SLOTS * ENTRY
NEXT_GLOBAL = 0x00877748    # ?actorcluster - the array cannot grow in place
FIELDS = {0: 'actor', 4: 'argument', 8: 'word +8', 0xA: 'word +0xA'}
BITFN = ((0x401A00, 'so_AbnormalState_BitSet'), (0x401A40, 'so_AbnormalState_BitReset'))
PROLOGUE = bytes.fromhex('558BEC8B01')                 # push ebp / mov ebp, esp / mov eax, [ecx]
CODE = 0x40                                           # the array starts after the two 0x14-byte stubs


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--exe', required=True)
    ap.add_argument('--slots', type=int, default=2048)
    a = ap.parse_args()
    assert ARR_END == NEXT_GLOBAL, 'array size vs the next global'
    pe = pefile.PE(a.exe, fast_load=True)
    sec = next(s for s in pe.sections if s.Name.startswith(b'.text'))
    d, va0 = sec.get_data(), pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    X = capstone.x86

    edits, per_field, stray = [], {k: 0 for k in FIELDS}, []
    off = 0
    while off < len(d):                                   # one linear sweep: the instruction that holds the bytes
        ins = next(md.disasm(d[off:off + 15], va0 + off, 1), None)
        if ins is None:
            off += 1
            continue
        for o in ins.operands:
            v = None
            if o.type == X.X86_OP_MEM and o.mem.base == 0:
                v = o.mem.disp & 0xFFFFFFFF
            elif o.type == X.X86_OP_IMM:
                v = o.imm & 0xFFFFFFFF
            if v is None or not (ARR <= v < ARR_END):
                continue
            field = v - ARR
            if o.type != X.X86_OP_MEM or o.mem.index == 0 or o.mem.scale != 4 or field not in FIELDS:
                stray.append('0x%08X %s %s' % (ins.address, ins.mnemonic, ins.op_str))
                continue
            raw = ins.bytes
            pos = raw.find(struct.pack('<I', v))
            assert pos >= 0 and raw.find(struct.pack('<I', v), pos + 1) < 0, hex(ins.address)
            edits.append({'why': 'identarray[i].%s  (%s %s at 0x%08X)' % (FIELDS[field], ins.mnemonic, ins.op_str, ins.address),
                          'at': '0x%08X' % (ins.address + pos), 'expect': '0x%X' % v,
                          'write': '@newbase + 0x%X' % (CODE + field) if CODE + field else '@newbase'})
            per_field[field] += 1
        off += ins.size
    assert not stray, 'references into the array that are not [idx*4 + field]: %s' % stray
    for s2 in pe.sections:                               # no pointer into the array outside code
        if s2 is sec:
            continue
        blob = s2.get_data()
        for pos in range(0, len(blob) - 4, 4):
            v = struct.unpack_from('<I', blob, pos)[0]
            assert not (ARR <= v < ARR_END), 'identarray address in %s at +0x%X' % (s2.Name, pos)

    code = []
    for k, (fn, name) in enumerate(BITFN):
        at = fn - va0
        assert d[at:at + 5] == PROLOGUE, '%s prologue changed' % name
        stub = '@newbase + 0x%X' % (k * 0x20)
        code.append({'why': '%s: return when idx >= %d (the object bitset is %d bits)' % (name, OLD_SLOTS, OLD_SLOTS),
                     'at': stub,
                     'emit': ['817C2404', {'u32': '0x%X' % OLD_SLOTS},  # cmp dword [esp+4], 792
                              '730A',                                   # jae -> ret 4
                              PROLOGUE.hex().upper(),                   # the 5 bytes the jmp replaced
                              'E9', {'rel32': '0x%X' % (fn + 5)},      # back into the function
                              'C20400']})                               # ret 4
        edits.append({'why': '%s: jmp to the bound check (E9)' % name, 'at': '0x%08X' % fn, 'width': 1,
                      'expect': '0x55', 'write': '0xE9'})
        edits.append({'why': '%s: jmp rel32' % name, 'at': '0x%08X' % (fn + 1), 'expect': '0x018BEC8B',
                      'write': '%s - 0x%X' % (stub, fn + 5)})

    edits.sort(key=lambda e: int(e['at'], 16))
    seen = set()
    for e in edits:
        assert e['at'] not in seen, 'two edits at %s' % e['at']
        seen.add(e['at'])
    recipe = {
        'name': 'abstate-container-cap',
        'summary': 'AbnormalStateContainer for `slots` AbStataIndexes: abstateidentarray moves to a section sized for '
                   'them, and the object state bitset (792 bits) is bounds-checked. Without it a 2026 state past 792 '
                   'corrupts the handler table (zone01 crash 2026-09-24).',
        'status': 'GENERATED 2026-09-24; BOOTED on zone03 the same day and live-tested there: a bot used Gold Dragon Grace '
                  'Grace (AbStataIndex 1093 -> the relocated identarray entry filled, abstatetemplate 228-230 intact) and '
                  'then Shield Increase T1 (229, applied, zone up) - the sequence that crashed zone01 on the old exe. '
                  'Then rolled out to every zone of the stack in build/Zone.hooked.exe.',
        'target': {'file': 'Zone00/Zone.exe', 'sha256': '7ef3532da08194a377558322ca2bd06d1ce5bdb2813796e033173b72d9ff883d', 'size': 4673536},
        'params': {'slots': a.slots},
        'consts': {},
        'why': [line for line in __doc__.split('WHY', 1)[1].splitlines()[1:]] + [
            '',
            'Sites (all found by decoding the stock exe): %d indexed references (actor %d, argument %d, word+8 %d, '
            'word+0xA %d) and the two bitset prologues.' % (sum(per_field.values()), per_field[0], per_field[4],
                                                           per_field[8], per_field[0xA]),
        ],
        'new_section': {'name': '.absc', 'size': '0x%X + slots * %d' % (CODE, ENTRY), 'materialise': True, 'execute': True,
                        'note': 'Two 0x14-byte bound-check stubs at +0x00 / +0x20, then the zero-filled identarray at +0x40 '
                                '(materialised because the stubs are code).'},
        'code': code,
        'edits': edits,
    }
    out = os.path.join(os.path.dirname(HERE), 'recipes', 'abstate-container-cap.json')
    json.dump(recipe, open(out, 'w', encoding='utf-8', newline='\n'), indent=2)
    print('%d edits -> %s (fields %s)' % (len(edits), out, per_field))


if __name__ == '__main__':
    main()
