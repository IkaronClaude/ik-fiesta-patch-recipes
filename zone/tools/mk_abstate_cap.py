"""Generate zone/recipes/abstate-index-cap.json: lift the 792-slot AbStataIndex list of the abstate dictionary.

    python zone/tools/mk_abstate_cap.py --exe Z:/ServerSource/Zone00/Zone.exe

AbnormalStateDictionary::AbState (global ?dic_abstate, 0x1620 bytes, in the zero-fill tail of .data) keeps
`as_StateIndexList[792]` - the AbStataIndex -> AbStateStr* lookup every abstate set / check goes through - inside
the object, with the two BTrees (by id, by index) BEHIND it. as_Load refuses an index >= 792 and as_FromIndex
asserts `Invalid skill idx[N]` on one, which is the 1032 / 1040 assert burst the 2026 abstates produce (AbState
2026 needs 1083 slots), and why AbState / SubAbState / AbStateView stay 2016 with 129 skill references blanked.

The list cannot grow in place (g_AbstateNeverShelter follows the object), so the whole object moves to a new
zero-filled section sized for `slots`, and three kinds of site move with it, every one FOUND by decoding the stock
exe (rerun this to reproduce the committed file byte for byte):

  - every absolute reference into the object (imm32 `offset dic_abstate...`, or a [disp32] without a base): the
    same offset in the new section - plus the growth for the two BTrees that sit behind the list;
  - every [this + 0xE18] / [this + 0x121C] (the BTrees) inside the AbState methods: + the growth;
  - every `0x318` the AbState methods compare an index against: `slots`.
"""
import argparse
import json
import os
import re
import struct

import capstone
import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
OBJ = 0x0087AEA8            # ?dic_abstate@@3VAbState@AbnormalStateDictionary@@A
OBJ_SIZE = 0x1620
LIST_OFF = 0x1B8            # as_StateIndexList[792] (after as_BinData, as_SaveTypeBinData, three dwords)
OLD_SLOTS = 0x318
TAIL_OFF = 0xE18            # as_BTreeID, then as_BTreeIndex at 0x121C: both move by the growth
TAIL = {0xE18: 'as_BTreeID', 0x121C: 'as_BTreeIndex'}
NEXT_GLOBAL = 0x0087C4C8    # ?g_AbstateNeverShelter - the object cannot grow in place
# the AbState methods (Zone.pdb): a [reg + 0xE18] outside these is some other class's field
METHODS = ((0x416D30, 0xB0, 'AbState::AbState'), (0x416DE0, 0xA0, 'AbState::~AbState'), (0x416E80, 1200, 'as_Load'),
           (0x4013E0, 64, 'as_FromID'), (0x401420, 64, 'as_FromIndex'), (0x418F80, 96, 'as_FromName'))
GROWTH = '(slots - 792) * 4'


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--exe', required=True)
    ap.add_argument('--slots', type=int, default=2048)
    a = ap.parse_args()
    assert OBJ + OBJ_SIZE == NEXT_GLOBAL, 'object size vs the next global'
    pe = pefile.PE(a.exe, fast_load=True)
    sec = next(s for s in pe.sections if s.Name.startswith(b'.text'))
    d, va0 = sec.get_data(), pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    X = capstone.x86

    def method_of(va):
        return next((n for s, size, n in METHODS if s <= va < s + size), None)

    # one linear sweep of .text: every site is the instruction that actually CONTAINS its four bytes (backing up
    # 1..7 bytes and taking the first decode that fits mislabels `mov esi, [0x87b4f4]` as `xor eax, 0x87b4f4` - the
    # same four bytes, but a heuristic that can also accept a coincidence)
    at_pos = {}
    off = 0
    while off < len(d):
        ins = next(md.disasm(d[off:off + 15], va0 + off, 1), None)
        if ins is None:
            off += 1
            continue
        for k in range(off, off + ins.size):
            at_pos[k] = ins
        off += ins.size

    def decode_at(pos, want):
        ins = at_pos.get(pos)
        return ins if ins is not None and ins.address - va0 + ins.size >= pos + 4 and want(ins) else None

    edits, strays = [], []
    # 1 ---- absolute references into the object: imm32, or a memory operand with no base register
    abs_refs = 0
    for pos in range(0, len(d) - 4):
        v = struct.unpack_from('<I', d, pos)[0]
        if not (OBJ <= v < OBJ + OBJ_SIZE):
            continue
        off = v - OBJ
        ins = decode_at(pos, lambda i: any((o.type == X.X86_OP_IMM and (o.imm & 0xFFFFFFFF) == v) or
                                           (o.type == X.X86_OP_MEM and o.mem.base == 0 and o.mem.index == 0 and (o.mem.disp & 0xFFFFFFFF) == v) or
                                           (o.type == X.X86_OP_MEM and o.mem.base == 0 and o.mem.index != 0 and (o.mem.disp & 0xFFFFFFFF) == v)
                                           for o in i.operands))
        if ins is None:
            continue   # four bytes that happen to look like the address inside some other instruction
        if off >= TAIL_OFF:
            what = '%s+0x%X' % (TAIL[max(t for t in TAIL if t <= off)], off - max(t for t in TAIL if t <= off))
            write = '@newbase + 0x%X + %s' % (off, GROWTH)
        elif off >= LIST_OFF:
            what = 'as_StateIndexList[%d]' % ((off - LIST_OFF) // 4)
            write = '@newbase + 0x%X' % off
        else:
            what = {0: 'dic_abstate', 0x1AC: 'as_AbstateArray', 0x1B0: 'as_Number', 0x1B4: 'as_maxhandle'}.get(off, 'dic_abstate+0x%X' % off)
            write = '@newbase + 0x%X' % off if off else '@newbase'
        edits.append({'why': '&%s  (%s %s at 0x%08X)' % (what, ins.mnemonic, ins.op_str, ins.address), 'at': '0x%08X' % (va0 + pos),
                      'expect': '0x%X' % v, 'write': write})
        abs_refs += 1
    # 2 ---- [this + tail member] inside the AbState methods
    tail_refs = 0
    for old, name in TAIL.items():
        for m in re.finditer(re.escape(struct.pack('<I', old)), d):
            ins = decode_at(m.start(), lambda i: any(o.type == X.X86_OP_MEM and o.mem.base != 0 and o.mem.disp == old for o in i.operands))
            if ins is None:
                continue
            meth = method_of(ins.address)
            if meth is None:
                strays.append('0x%08X %s %s' % (ins.address, ins.mnemonic, ins.op_str))
                continue
            edits.append({'why': '%s: %s  (%s %s)' % (meth, name, ins.mnemonic, ins.op_str), 'at': '0x%08X' % (va0 + m.start()),
                          'expect': '0x%X' % old, 'write': '0x%X + %s' % (old, GROWTH)})
            tail_refs += 1
    # 3 ---- the bound: cmp/mov ..., 0x318 inside the methods
    bounds = 0
    for s, size, name in METHODS:
        off = s - va0
        while off < s + size - va0:
            ins = next(md.disasm(d[off:off + 15], va0 + off, 1), None)
            if ins is None:
                off += 1
                continue
            for o in ins.operands:
                if o.type == X.X86_OP_IMM and (o.imm & 0xFFFFFFFF) == OLD_SLOTS and ins.mnemonic in ('cmp', 'mov'):
                    pos = off + ins.size - 4
                    assert struct.unpack_from('<I', d, pos)[0] == OLD_SLOTS, hex(ins.address)
                    edits.append({'why': '%s: the slot bound  (%s %s)' % (name, ins.mnemonic, ins.op_str), 'at': '0x%08X' % (va0 + pos),
                                  'expect': '0x%X' % OLD_SLOTS, 'write': 'slots'})
                    bounds += 1
            off += ins.size
    # no other section may hold an address into the object (a vtable, a pointer table)
    for s2 in pe.sections:
        if s2 is sec:
            continue
        blob = s2.get_data()
        for pos in range(0, len(blob) - 4, 4):
            v = struct.unpack_from('<I', blob, pos)[0]
            assert not (OBJ <= v < OBJ + OBJ_SIZE), 'dic_abstate address in %s at +0x%X' % (s2.Name, pos)

    edits.sort(key=lambda e: e['at'])
    seen = set()
    for e in edits:
        assert e['at'] not in seen, 'two edits at %s' % e['at']
        seen.add(e['at'])
    recipe = {
        'name': 'abstate-index-cap',
        'summary': 'Lift the 792-slot AbStataIndex list of the abstate dictionary (2026 AbState needs 1083): the whole dic_abstate object moves to a new section sized for `slots`.',
        'status': 'GENERATED 2026-09-22; BOOTED the same day on zone03 (2016 abstate data), then on every zone of the stack as part of build/Zone.hooked.exe. The 2026 AbState / SubAbState / AbStateView tables are not switched in yet.',
        'target': {'file': 'Zone00/Zone.exe', 'sha256': '7ef3532da08194a377558322ca2bd06d1ce5bdb2813796e033173b72d9ff883d', 'size': 4673536},
        'params': {'slots': a.slots},
        'consts': {},
        'why': [
            'AbnormalStateDictionary::AbState (global ?dic_abstate at 0x%08X, 0x%X bytes, zero-fill tail of .data) is laid out as' % (OBJ, OBJ_SIZE),
            '',
            '    +0x0000  as_BinData[356], as_SaveTypeBinData[72]',
            '    +0x01AC  AbStateStr* as_AbstateArray; u32 as_Number; u32 as_maxhandle',
            '    +0x01B8  AbStateStr* as_StateIndexList[792]   the AbStataIndex -> row lookup',
            '    +0x0E18  BTree as_BTreeID                      by AbState ID',
            '    +0x121C  BTree as_BTreeIndex                   by AbStataIndex',
            '',
            'as_Load (0x416E80) fills the list from AbState.shn and refuses an AbStataIndex >= 792 (cmp ..., 0x318);',
            'as_FromIndex (0x401420) asserts `AbState::as_FromIndex : Invalid skill idx[N]` on one. The 2026 AbState',
            'table needs 1083 slots, which is the 1032 / 1040 assert burst seen on zone04 whenever a player is on a',
            '2026 map, and why AbState / SubAbState / AbStateView are kept at 2016 with 129 skill status references',
            'blanked (Fiesta2026on2016 invented.json skills_clamped).',
            '',
            'The list cannot grow in place (?g_AbstateNeverShelter follows at 0x%08X), so the whole object moves to a' % NEXT_GLOBAL,
            'new zero-filled section of 0x%X + (slots - 792) * 4 bytes, and three kinds of site move with it, all found' % OBJ_SIZE,
            'by decoding the stock exe (zone/tools/mk_abstate_cap.py - rerun it to reproduce this file):',
            '',
            '  - every absolute reference into the object (%d): the same offset in the new section; the two BTrees' % abs_refs,
            '    behind the list (as_BTreeID +0xE18, as_BTreeIndex +0x121C, reached as `mov ecx, offset` for every',
            '    lookup by id or index) also move by the growth',
            '  - every [this + 0xE18] / [this + 0x121C] inside the six AbState methods (%d)      -> + the growth' % tail_refs,
            '  - every `0x318` the methods compare an index against (%d)                          -> slots' % bounds,
            '',
            'The old 0x1620 bytes of .data are simply no longer referenced. No other section holds an address into the',
            'object (checked). The list is indexed by AbStataIndex, the id the client sends and receives, so it cannot',
            'be renumbered instead.',
            '',
            'This lifts the INDEX cap only. AbStateStr::subabstate[40] (sub-actions per state) is a separate, per-row',
            'limit; the 2026 SubAbState table must be checked against it before the data switches to 2026.',
        ],
        'new_section': {'name': '.abst', 'size': '0x%X + %s' % (OBJ_SIZE, GROWTH), 'materialise': False,
                        'note': 'Zero-filled data, exactly as the original lives in the BSS tail of .data. The BTree constructors run at start-up through the rewritten absolute references.'},
        'edits': edits,
    }
    out = os.path.join(os.path.dirname(HERE), 'recipes', 'abstate-index-cap.json')
    json.dump(recipe, open(out, 'w', encoding='utf-8', newline='\n'), indent=2)
    print('%d edits -> %s' % (len(edits), out))
    print('  absolute refs %d, tail-member sites %d, bounds %d' % (abs_refs, tail_refs, bounds))
    print('  left alone (not AbState code):')
    for s in strays:
        print('    ' + s)


if __name__ == '__main__':
    main()
