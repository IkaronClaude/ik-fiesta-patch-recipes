"""Generate zone/recipes/roumen-is-rou.json: the zone's hard-coded fallback town is Rou, not RouN.

    python zone/tools/mk_roumen_is_rou.py --exe Z:/ServerSource/Zone00/Zone.exe

The 2016 Zone.exe sends a player to "RouN" (6445, 8630) wherever it needs a default town, with no table behind it:
ShinePlayer::sp_2Roumen, so_SaveLocation (3 fallbacks - e.g. logging out in the Lucky House, GBHouse, saved the
character in RouN although Field.txt says RegenCity Rou), so_ply_ToNormalLoc, so_Prison_End and
WorldManagerSession::wms_NC_KQ_LINK_TO_FORCE_BY_BAN_CMD, plus a static town-name list (sp_NC_MISC_HIDE_EXCEPT_ME_ON_CMD)
and a global default. In the 2026 world RouN is retired and Rou (the rebuilt Roumen) is the town (Fiesta2026on2016
rule: nothing a player reaches may lead to RouN).

  - the literal "RouN\\0" at its one .rdata address becomes "Rou\\0": every one of its 11 users (all `push offset`)
    copies it as the town name, so one 4-byte edit moves them all;
  - every (6445, 8630) pair written by those functions (`mov dword [reg+x], 0x192D` / `0x21B6`) becomes the Rou town
    point (params town_x / town_y). The same numbers elsewhere (MobBreederGroup) are unrelated and left alone.
"""
import argparse
import json
import os
import struct

import capstone
import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
LITERAL = 0x006AC7F4                    # ??_C@_04CEILLLCM@RouN?$AA@
OLD_X, OLD_Y = 6445, 8630
# the functions that place a player in the fallback town (Zone.pdb publics: start VA, size to scan)
FUNCS = ((0x0043CF80, 0x200, 'ShinePlayer::sp_2Roumen'),
         (0x004542F0, 0x600, 'ShinePlayer::so_SaveLocation'),
         (0x00497120, 0x180, 'WorldManagerSession::wms_NC_KQ_LINK_TO_FORCE_BY_BAN_CMD'),
         (0x00552350, 0x400, 'ShinePlayer::so_ply_ToNormalLoc'))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--exe', required=True)
    a = ap.parse_args()
    pe = pefile.PE(a.exe, fast_load=True)
    image = pe.OPTIONAL_HEADER.ImageBase
    raw = open(a.exe, 'rb').read()
    assert raw[pe.get_offset_from_rva(LITERAL - image):][:5] == b'RouN\0', 'the RouN literal moved'
    sec = next(s for s in pe.sections if s.Name.startswith(b'.text'))
    d, va0 = sec.get_data(), image + sec.VirtualAddress
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    edits = [{'why': '"RouN" -> "Rou": the fallback town name of every user of the literal', 'at': '0x%08X' % LITERAL,
              'expect': '0x4E756F52', 'write': '0x00756F52'}]
    found = {OLD_X: 0, OLD_Y: 0}
    for start, size, name in FUNCS:
        off = start - va0
        for ins in md.disasm(d[off:off + size], start):
            if ins.mnemonic != 'mov' or len(ins.operands) != 2 or ins.operands[1].type != capstone.x86.X86_OP_IMM:
                continue
            v = ins.operands[1].imm & 0xFFFFFFFF
            if v not in found or ins.operands[0].type != capstone.x86.X86_OP_MEM:
                continue
            pos = ins.address + ins.size - 4
            assert struct.unpack_from('<I', d, pos - va0)[0] == v
            edits.append({'why': '%s: fallback %s %d -> Rou  (%s %s at 0x%08X)' % (name, 'x' if v == OLD_X else 'y', v,
                                                                                   ins.mnemonic, ins.op_str, ins.address),
                          'at': '0x%08X' % pos, 'expect': '0x%X' % v, 'write': 'town_x' if v == OLD_X else 'town_y'})
            found[v] += 1
    assert found[OLD_X] == found[OLD_Y] == 6, 'expected 6 coordinate pairs, found %s' % found
    edits.sort(key=lambda e: int(e['at'], 16))
    recipe = {
        'name': 'roumen-is-rou',
        'summary': 'The hard-coded fallback town (RouN 6445, 8630) becomes Rou and its town point.',
        'status': 'GENERATED 2026-09-24; tested on zone03 (a Lucky House logout now saves Rou 4199,4769, was RouN 6445,8630), then on every zone in build/Zone.hooked.exe.',
        'target': {'file': 'Zone00/Zone.exe', 'sha256': '7ef3532da08194a377558322ca2bd06d1ce5bdb2813796e033173b72d9ff883d', 'size': 4673536},
        'params': {'town_x': 4199, 'town_y': 4769},
        'consts': {},
        'why': [l for l in __doc__.splitlines()[4:]],
        'edits': edits,
    }
    out = os.path.join(os.path.dirname(HERE), 'recipes', 'roumen-is-rou.json')
    json.dump(recipe, open(out, 'w', encoding='utf-8', newline='\n'), indent=2)
    print('%d edits -> %s' % (len(edits), out))


if __name__ == '__main__':
    main()
