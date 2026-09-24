"""Generate zone/recipes/npcitemlist-cap.json: lift the 100-merchant cap of the NPC shop-list table.

    python zone/tools/mk_npcitemlist_cap.py --exe Z:/ServerSource/Zone00/Zone.exe [--slots 1024]

NPCItemList::NPCItemListTable (global ?npcitemlist, 0x598 bytes) keeps one prebuilt shop packet per merchant shop
list it has read:

    +0x000  PROTO_NC_MENU_SHOPOPENTABLE_CMD* nilt_Packet[100]
    +0x190  int   nilt_TableNumber                  how many are in use
    +0x194  BTree nilt_Index2Handle                 list name -> slot

nilt_ReadTable (0x4C5130) runs once per NPC.txt PLACEMENT of a Merchant with a list (a merchant standing on 12 maps
reads its list 12 times) and asserts `Too many merchants[100]` (cmp nilt_TableNumber, 0x64) - a ShineExit at
zone start. Fiesta2026on2016 hits it with the Rebalanced merchants (the enchant / buff merchants stand beside every
smith) and will hit it with captured maps too.

The array cannot grow in place (?merchantcity follows at 0x%08X), so the whole object moves to a new zero-filled
section sized for `slots`, the same technique as abstate-index-cap. Sites, all FOUND by decoding the stock exe:
  - every absolute reference into the object (imm32 / [disp32]): the same offset in the new section, plus the
    growth for the two members behind the array (the BTree is reached as `mov ecx, offset` by its constructor,
    destructor and the lookup in nilt_MenuPacket);
  - every [this + 0x190] / [this + 0x194] inside the two NPCItemListTable methods: + the growth;
  - the `cmp ..., 0x64` bound in those methods: slots.
"""
import argparse
import json
import os
import re
import struct

import capstone
import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
OBJ = 0x0DA29450            # ?npcitemlist@@3VNPCItemListTable@NPCItemList@@A
OBJ_SIZE = 0x598
OLD_SLOTS = 100
TAIL = {0x190: 'nilt_TableNumber', 0x194: 'nilt_Index2Handle'}   # both move by the growth
TAIL_OFF = min(TAIL)
NEXT_GLOBAL = 0x0DA29A18    # ?merchantcity - the object cannot grow in place
METHODS = ((0x4C5050, 0xE0, 'nilt_MenuPacket'), (0x4C5130, 0x1A0, 'nilt_ReadTable'))
GROWTH = '(slots - 100) * 4'


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--exe', required=True)
    ap.add_argument('--slots', type=int, default=1024)
    a = ap.parse_args()
    assert OBJ + OBJ_SIZE <= NEXT_GLOBAL
    pe = pefile.PE(a.exe, fast_load=True)
    sec = next(s for s in pe.sections if s.Name.startswith(b'.text'))
    d, va0 = sec.get_data(), pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    X = capstone.x86

    def method_of(va):
        return next((n for s, size, n in METHODS if s <= va < s + size), None)

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
    # 1 ---- absolute references into the object
    abs_refs = 0
    for pos in range(0, len(d) - 4):
        v = struct.unpack_from('<I', d, pos)[0]
        if not (OBJ <= v < OBJ + OBJ_SIZE):
            continue
        o = v - OBJ
        ins = decode_at(pos, lambda i: any((op.type == X.X86_OP_IMM and (op.imm & 0xFFFFFFFF) == v) or
                                           (op.type == X.X86_OP_MEM and op.mem.base == 0 and (op.mem.disp & 0xFFFFFFFF) == v)
                                           for op in i.operands))
        if ins is None:
            continue
        if o >= TAIL_OFF:
            base = max(t for t in TAIL if t <= o)
            what, write = '%s+0x%X' % (TAIL[base], o - base), '@newbase + 0x%X + %s' % (o, GROWTH)
        else:
            what = 'npcitemlist' if not o else 'nilt_Packet[%d]' % (o // 4)
            write = '@newbase + 0x%X' % o if o else '@newbase'
        edits.append({'why': '&%s  (%s %s at 0x%08X)' % (what, ins.mnemonic, ins.op_str, ins.address),
                      'at': '0x%08X' % (va0 + pos), 'expect': '0x%X' % v, 'write': write})
        abs_refs += 1
    # 2 ---- [this + tail member] inside the two methods
    tail_refs = 0
    for old, name in TAIL.items():
        for m in re.finditer(re.escape(struct.pack('<I', old)), d):
            ins = decode_at(m.start(), lambda i: any(op.type == X.X86_OP_MEM and op.mem.base != 0 and op.mem.disp == old
                                                     for op in i.operands))
            if ins is None:
                continue
            meth = method_of(ins.address)
            if meth is None:
                continue          # [reg+0x190] in other classes: not ours
            edits.append({'why': '%s: %s  (%s %s)' % (meth, name, ins.mnemonic, ins.op_str), 'at': '0x%08X' % (va0 + m.start()),
                          'expect': '0x%X' % old, 'write': '0x%X + %s' % (old, GROWTH)})
            tail_refs += 1
    # 3 ---- the bound: cmp ..., 0x64 inside the methods (imm8 or imm32)
    bounds = 0
    for s, size, name in METHODS:
        off = s - va0
        while off < s + size - va0:
            ins = next(md.disasm(d[off:off + 15], va0 + off, 1), None)
            if ins is None:
                off += 1
                continue
            if ins.mnemonic == 'cmp':
                for op in ins.operands:
                    if op.type == X.X86_OP_IMM and (op.imm & 0xFFFFFFFF) == OLD_SLOTS:
                        raw = d[off:off + ins.size]
                        if raw[:2] == b'\x83\xF8' and ins.size == 3:
                            # `cmp eax, 0x64` (imm8) in nilt_MenuPacket: the slot index the BTree hands back. It is
                            # a value nilt_ReadTable stored (0 <= index < 65536), so for a cap that is a multiple
                            # of 256, eax < slots <=> ah < slots / 256: `cmp ah, imm8` is the same 3 bytes, and the
                            # jae that follows keeps its meaning.
                            if a.slots % 256 or a.slots // 256 > 0xFF:
                                raise SystemExit('slots must be a multiple of 256 below 65536 (imm8 cmp at 0x%08X)' % ins.address)
                            edits.append({'why': '%s: the slot bound, cmp eax,0x64 -> cmp ah,slots/256  (opcode + modrm)' % name,
                                          'at': '0x%08X' % ins.address, 'width': 2, 'expect': '0xF883', 'write': '0xFC80'})
                            edits.append({'why': '%s: the slot bound, imm8 0x64 -> slots/256 = 0x%02X' % (name, a.slots // 256),
                                          'at': '0x%08X' % (ins.address + 2), 'width': 1, 'expect': '0x64',
                                          'write': '0x%02X' % (a.slots // 256)})
                            bounds += 1
                            continue
                        pos = off + ins.size - 4
                        assert struct.unpack_from('<I', d, pos)[0] == OLD_SLOTS, hex(ins.address)
                        edits.append({'why': '%s: the merchant cap  (%s %s)' % (name, ins.mnemonic, ins.op_str),
                                      'at': '0x%08X' % (va0 + pos), 'expect': '0x%X' % OLD_SLOTS, 'write': 'slots'})
                        bounds += 1
            off += ins.size
    for s2 in pe.sections:
        if s2 is sec:
            continue
        blob = s2.get_data()
        for pos in range(0, len(blob) - 4, 4):
            v = struct.unpack_from('<I', blob, pos)[0]
            assert not (OBJ <= v < OBJ + OBJ_SIZE), 'npcitemlist address in %s at +0x%X' % (s2.Name, pos)
    assert bounds == 2, 'expected the cap compare and the slot bound, found %d' % bounds

    edits.sort(key=lambda e: e['at'])
    assert len({e['at'] for e in edits}) == len(edits)
    recipe = {
        'name': 'npcitemlist-cap',
        'summary': 'Lift the 100 shop-list cap of NPCItemListTable ("Too many merchants[100]", counted per merchant PLACEMENT): the whole ?npcitemlist object moves to a new section sized for `slots`.',
        'status': 'GENERATED 2026-09-24 by zone/tools/mk_npcitemlist_cap.py.',
        'target': {'file': 'Zone00/Zone.exe', 'sha256': '7ef3532da08194a377558322ca2bd06d1ce5bdb2813796e033173b72d9ff883d', 'size': 4673536},
        'params': {'slots': a.slots},
        'consts': {},
        'why': [line for line in __doc__.strip().splitlines()[2:]] + [
            '',
            'Found: %d absolute references, %d tail-member sites, %d bound. No other section holds an address into' % (abs_refs, tail_refs, bounds),
            'the object (checked). The old 0x598 bytes are simply no longer referenced.'],
        'new_section': {'name': '.nilt', 'size': '0x%X + %s' % (OBJ_SIZE, GROWTH), 'materialise': False,
                        'note': 'Zero-filled, as the original in the BSS tail of .data; the BTree constructor runs at start-up through the rewritten absolute reference.'},
        'edits': edits,
    }
    recipe['why'][recipe['why'].index('The array cannot grow in place (?merchantcity follows at 0x%08X), so the whole object moves to a new zero-filled')] = \
        'The array cannot grow in place (?merchantcity follows at 0x%08X), so the whole object moves to a new zero-filled' % NEXT_GLOBAL
    out = os.path.join(os.path.dirname(HERE), 'recipes', 'npcitemlist-cap.json')
    json.dump(recipe, open(out, 'w', encoding='utf-8', newline='\n'), indent=2)
    print('%d edits -> %s  (absolute %d, tail %d, bound %d)' % (len(edits), out, abs_refs, tail_refs, bounds))
    for e in edits:
        print('  %s  %s' % (e['at'], e['why']))


if __name__ == '__main__':
    main()
