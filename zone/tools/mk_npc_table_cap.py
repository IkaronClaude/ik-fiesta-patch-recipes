"""Generate zone/recipes/npc-table-cap.json: lift NPCManager's fixed 1024-row table.

    python zone/tools/mk_npc_table_cap.py --exe Z:/ServerSource/Zone00/Zone.exe

The recipe is ~110 mechanical edits, so it is generated - and every site is FOUND by decoding the stock exe, not typed
in, then checked against the expected operand before it is written down. Run it again after any doubt; it must
reproduce the committed file byte for byte.
"""
import argparse
import json
import os
import re
import struct

import capstone
import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
MGR = 0x0DA29A60            # ?npcmanager@@3VNPCManager@@A
OLD_ROWS = 0x400
OLD_COUNT = OLD_ROWS * 12   # 0x3000: the row count, right behind the array
OLD_READER = OLD_COUNT + 4  # 0x3004: the OptionReader member
MGR_END = 0x0DA3D2B8        # ?optoollist - the next global: NPCManager is 0x13858 bytes
READER_SIZE = MGR_END - MGR - OLD_READER
# every NPCManager method (Zone.pdb) - a [reg + 0x3000] outside these is some other class's field
METHODS = ((0x418F10, 0x70, 'nm_FindNPCFunc'), (0x4C52E0, 0x10, 'operator OptionReader*'), (0x4C5310, 0x60, 'nm_DynamicReleaseNPC'),
           (0x4C58C0, 0xCA0, 'nm_Load'), (0x4C6560, 0x310, 'nm_SetNPC'), (0x4C6870, 0x260, 'nm_MarkingNPC'),
           (0x4C6AD0, 0x200, 'nm_UnmarkNPC'), (0x4C6CD0, 0x380, 'nm_DynamicRegenerateNPC'), (0x4C7CC0, 0x50, '~NPCManager'),
           (0x5600F0, 0x40, 'nm_FindNPCInfo'))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--exe', required=True)
    a = ap.parse_args()
    pe = pefile.PE(a.exe, fast_load=True)
    sec = next(s for s in pe.sections if s.Name.startswith(b'.text'))
    d, va0 = sec.get_data(), pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    X = capstone.x86

    def method_of(va):
        return next((n for s, size, n in METHODS if s <= va < s + size), None)

    def decode_at(pos, want):
        """The instruction that holds the 4 bytes at file offset pos as `want` (an operand kind), or None."""
        for back in range(1, 8):
            ins = next(md.disasm(d[pos - back:pos - back + 15], va0 + pos - back, 1), None)
            if ins is not None and pos - back + ins.size >= pos + 4 and want(ins):
                return ins
        return None

    edits, strays = [], []
    # 1 ---- [reg + 0x3000] / [reg + 0x3004]: the count and the reader, addressed off `this`
    for old, new, what in ((OLD_COUNT, 'rows * 12', 'row count'), (OLD_READER, 'rows * 12 + 4', 'OptionReader member')):
        for m in re.finditer(re.escape(struct.pack('<I', old)), d):
            ins = decode_at(m.start(), lambda i: any(o.type == X.X86_OP_MEM and o.mem.base != 0 and o.mem.disp == old for o in i.operands))
            if ins is None:
                continue
            name = method_of(ins.address)
            if name is None:
                strays.append('0x%08X %s %s' % (ins.address, ins.mnemonic, ins.op_str))
                continue
            edits.append({'why': '%s: %s  (%s %s)' % (name, what, ins.mnemonic, ins.op_str), 'at': '0x%08X' % (va0 + m.start()),
                          'expect': '0x%X' % old, 'write': new})
    # 2 ---- the bound itself: cmp/mov ..., 0x400 inside the methods
    for s, size, name in METHODS:
        off = s - va0
        while off < s + size - va0:
            ins = next(md.disasm(d[off:off + 15], va0 + off, 1), None)
            if ins is None:
                off += 1
                continue
            for o in ins.operands:
                if o.type == X.X86_OP_IMM and (o.imm & 0xFFFFFFFF) == OLD_ROWS and ins.mnemonic in ('cmp', 'mov'):
                    pos = off + ins.size - 4
                    assert struct.unpack_from('<I', d, pos)[0] == OLD_ROWS, hex(ins.address)
                    edits.append({'why': '%s: the row bound  (%s %s)' % (name, ins.mnemonic, ins.op_str), 'at': '0x%08X' % (va0 + pos),
                                  'expect': '0x%X' % OLD_ROWS, 'write': 'rows'})
            off += ins.size
    # 3 ---- the global itself: every `mov ecx, offset npcmanager` and `mov ecx, offset npcmanager.reader`
    for old, new, what in ((MGR, '@newbase', 'npcmanager'), (MGR + OLD_READER, '@newbase + rows * 12 + 4', 'npcmanager.reader')):
        for m in re.finditer(re.escape(struct.pack('<I', old)), d):
            ins = decode_at(m.start(), lambda i: any(o.type == X.X86_OP_IMM and (o.imm & 0xFFFFFFFF) == old for o in i.operands))
            assert ins is not None, 'undecoded reference at 0x%X' % (va0 + m.start())
            edits.append({'why': '&%s  (%s %s at 0x%08X)' % (what, ins.mnemonic, ins.op_str, ins.address), 'at': '0x%08X' % (va0 + m.start()),
                          'expect': '0x%X' % old, 'write': new})
    # .rdata / .data must not hold the address either (a vtable, a pointer table)
    for s2 in pe.sections:
        if s2 is sec:
            continue
        blob = s2.get_data()
        for old in (MGR, MGR + OLD_READER):
            assert struct.pack('<I', old) not in blob, 'npcmanager address in %s' % s2.Name

    edits.sort(key=lambda e: e['at'])
    recipe = {
        'name': 'npc-table-cap',
        'summary': 'Lift the 1024-row limit of NPC.txt: NPCManager keeps the whole table in a fixed array inside a global, and row 1025 overwrites its own row count.',
        'status': 'GENERATED 2026-09-18 and verified to apply on the stock exe and on top of the full chain. NOT yet booted - see the README entry.',
        'target': {'file': 'Zone00/Zone.exe', 'sha256': '7ef3532da08194a377558322ca2bd06d1ce5bdb2813796e033173b72d9ff883d', 'size': 4673536},
        'params': {'rows': 4096},
        'consts': {},
        'why': [
            'NPCManager (global ?npcmanager at 0x%08X, 0x%X bytes) is laid out as' % (MGR, MGR_END - MGR),
            '',
            '    +0x0000  NPCIndexArray rows[1024]   12 bytes each: NPCInformTemplete*, NPCRole*, u16 handle (0xFFFF = none)',
            '    +0x3000  u32 row count',
            '    +0x3004  OptionReader reader        0x%X bytes (the parsed NPC.txt)' % READER_SIZE,
            '',
            'nm_Load appends one row per ShineNPC record of NPC.txt - the WHOLE file, whatever maps the zone hosts - and',
            'never tests the count. Row 1025 lands on +0x3000, i.e. on the count itself: the loader then sees zero NPCs,',
            'asserts "NPCManager::nm_Load : Empty NPC inform" and ShineExits. Every zone of the cluster goes down at',
            'startup. Found 2026-09-18 when the first full capture harvest took NPC.txt from 895 rows to 1043.',
            '',
            'The array cannot grow in place (the next global follows at 0x%08X), so the whole object moves to a new' % MGR_END,
            'zero-filled section sized for `rows` rows, and three kinds of site move with it, all found by decoding the',
            'stock exe (zone/tools/mk_npc_table_cap.py - rerun it to reproduce this file):',
            '',
            '  - every [this + 0x3000] and [this + 0x3004] inside the ten NPCManager methods  -> rows*12, rows*12 + 4',
            '  - every `0x400` the methods compare the count or a loop index against           -> rows',
            '    (nm_Load clears the array with it, nm_DynamicRegenerateNPC / nm_DynamicReleaseNPC scan it for a free',
            '    or matching handle, the destructor walks it)',
            '  - every `mov ecx, offset npcmanager` (22) and `offset npcmanager.reader` (3)     -> the new section',
            '',
            'The old 80 KB of .data are simply no longer referenced. No other section holds the address (checked).',
            '`[esi + 0x3000]` also occurs in one unrelated class (0x004152D6, a run of consecutive fields); sites',
            'outside the ten methods are left alone and listed by the generator.',
            '',
            'This is the TABLE cap. The per-zone NPC OBJECT pool and handle range are npc-object-pool-cap (1024 per zone,',
            '0x525C..0x565C with handle-layout-2026): a zone still cannot host more than 1024 NPCs, but NPC.txt as a',
            'whole - every map of every zone - can now hold `rows`.',
            'After deploying it, raise NPC_ROW_CAP in Fiesta2026on2016 tools/merge_harvest.py to match.',
        ],
        'new_section': {'name': '.npct', 'size': 'rows * 12 + 4 + 0x%X' % READER_SIZE, 'materialise': False,
                        'note': 'Zero-filled data, exactly as the original lives in the BSS tail of .data.'},
        'edits': edits,
    }
    out = os.path.join(os.path.dirname(HERE), 'recipes', 'npc-table-cap.json')
    json.dump(recipe, open(out, 'w', encoding='utf-8', newline='\n'), indent=2)
    kinds = [sum(1 for e in edits if k in e['why']) for k in ('row count', 'OptionReader member', 'row bound', '&npcmanager ', '&npcmanager.reader')]
    print('%d edits -> %s' % (len(edits), out))
    print('  count sites %d, reader-member sites %d, bounds %d, &npcmanager %d, &npcmanager.reader %d' % tuple(kinds))
    print('  left alone (not NPCManager code):')
    for s in strays:
        print('    ' + s)


if __name__ == '__main__':
    main()
