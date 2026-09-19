"""Generate zone/recipes/void-bag-reloc.json - the 17 original jump-table entries are READ from the exe."""
import os
import json
import struct

import pefile

EXE = 'Z:/ServerSource/Zone00/Zone.exe'
pe = pefile.PE(EXE, fast_load=True)
d = open(EXE, 'rb').read()


def u32(va):
    return struct.unpack_from('<I', d, pe.get_offset_from_rva(va - 0x400000))[0]


SRC_TBL, DST_TBL = 0x5370E4, 0x537128
src = [u32(SRC_TBL + 4 * i) for i in range(17)]
dst = [u32(DST_TBL + 4 * i) for i in range(17)]
SRC_DEFAULT, DST_DEFAULT = 0x5370A9, 0x536A85
assert src[1] == SRC_DEFAULT and dst[1] == DST_DEFAULT, 'bag 1 is unsupported in both: its entry IS the default'

H = lambda v: '0x%08X' % v

recipe = {
    "name": "void-bag-reloc",
    "summary": "Let item moves resolve bag 18 (the 2026 Void Inventory) to a bag the void_bag plugin provides.",
    "status": "BUILT AND STATICALLY VERIFIED. Not yet booted.",
    "target": {"file": "Zone00/Zone.exe",
               "sha256": "7ef3532da08194a377558322ca2bd06d1ce5bdb2813796e033173b72d9ff883d",
               "size": 4673536},
    "params": {},
    "consts": {
        "src_cmp_imm8": "0x005367BD", "src_tbl_disp": "0x005367C7", "src_tbl_old": H(SRC_TBL),
        "dst_cmp_imm8": "0x00536A06", "dst_tbl_disp": "0x00536A0C", "dst_tbl_old": H(DST_TBL),
        "src_default": H(SRC_DEFAULT), "dst_default": H(DST_DEFAULT),
        "src_resolved": "0x005369EE", "dst_resolved": "0x00536B78",
        "old_max_bag": "0x10", "new_max_bag": "0x12",
        "slot": "0x00", "src_tbl": "0x04", "dst_tbl": "0x50", "src_cave": "0xA0", "dst_cave": "0xE0",
    },
    "new_section": {
        "name": ".voidreloc",
        "size": "0x140",
        "materialise": True,
        "execute": True,
        "note": "One arena region, labelled .voidreloc in the arena directory: the plugin slot (+0), both "
                "widened jump tables (+0x04, +0x50) and the two caves (+0xA0, +0xE0). Executable and "
                "materialised - code cannot live in zero-fill - and writable, because the plugin fills the "
                "slot at start-up.",
    },
    "why": [
        "ShinePlayer::sp_ItemReloc resolves both ends of a move with a switch on the bag id -",
        "",
        "    0x5367B8  shr eax, 0xA ; cmp eax, 0x10 ; ja default ; jmp [eax*4 + 0x5370E4]    source",
        "    0x536A01  shr eax, 0xA ; cmp eax, 0x10 ; ja default ; jmp [eax*4 + 0x537128]    destination",
        "",
        "so bag 18 falls to the default and the move is refused with 0x0243 (observed 2026-09-19: a",
        "deposit 9:24 -> 18:0 answered 0x300C 0x0243). Each case only sets the ItemBag* and the bag's OWNER,",
        "e.g. the inventory's source case:",
        "",
        "    0x5367CB  [ebp-0x14] = esi + 0x8E2C                    ; the ItemBag*",
        "              [ebp-0x48] = player->so_GetCharRegistNumber() ; vtable 0x344: the owner - a character",
        "              jmp 0x5369EE                                  ; (shared storages put the account/guild)",
        "",
        "and EVERYTHING after works on that ItemBag* through its four virtuals - cell lookup, sizes, the",
        "belonging check, irm_Move / irm_Exchange, the 0x3001 / 0x300C replies. It is the only place in the",
        "zone that switches on a bag id like this (a scan for `shr 0xA ... cmp 0x10` finds exactly these two).",
        "",
        "This widens both switches to 0..18: entry 17 is the default, entry 18 jumps to a cave that asks",
        "the plugin for the player's void bag through the slot at +0 (ItemBag* __cdecl f(ShinePlayer*)).",
        "The cave then does exactly what the inventory's case does, with that bag instead. A null slot or a",
        "null bag takes the default, so without the plugin the zone behaves exactly as unpatched.",
    ],
    "code": [
        {"why": "source jump table, widened to 0..18",
         "at": "@newbase + src_tbl",
         "emit": [{"u32": H(e)} for e in src] + [{"u32": "src_default"}, {"u32": "@newbase + src_cave"}]},
        {"why": "destination jump table, widened to 0..18",
         "at": "@newbase + dst_tbl",
         "emit": [{"u32": H(e)} for e in dst] + [{"u32": "dst_default"}, {"u32": "@newbase + dst_cave"}]},
        {"why": "source case 18: the plugin's void bag, else the default",
         "at": "@newbase + src_cave",
         "emit": [
             "A1", {"u32": "@newbase + slot"},        # mov eax, [slot]
             "85C0", "0F84", {"rel32": "src_default"},  # test eax, eax ; jz default
             "56", "FFD0", "83C404",                  # push esi ; call eax ; add esp, 4
             "85C0", "0F84", {"rel32": "src_default"},  # test eax, eax ; jz default
             "8945EC",                                # mov [ebp-0x14], eax      the source ItemBag*
             "8B16", "8BCE", "8B8244030000", "FFD0",  # owner = so_GetCharRegistNumber(): per character, as bag 9
             "8945B8",                                # mov [ebp-0x48], eax
             "E9", {"rel32": "src_resolved"},
         ]},
        {"why": "destination case 18: the plugin's void bag, else the default",
         "at": "@newbase + dst_cave",
         "emit": [
             "A1", {"u32": "@newbase + slot"},
             "85C0", "0F84", {"rel32": "dst_default"},
             "56", "FFD0", "83C404",
             "85C0", "0F84", {"rel32": "dst_default"},
             "8945F0",                                # mov [ebp-0x10], eax      the destination ItemBag*
             "8B16", "8BCE", "8B8244030000", "FFD0",
             "8945C8",                                # mov [ebp-0x38], eax
             "E9", {"rel32": "dst_resolved"},
         ]},
    ],
    "edits": [
        {"why": "sp_ItemReloc source switch: bound 16 -> 18", "at": "src_cmp_imm8", "width": 1,
         "expect": "old_max_bag", "write": "new_max_bag"},
        {"why": "sp_ItemReloc source switch: the widened table", "at": "src_tbl_disp",
         "expect": "src_tbl_old", "write": "@newbase + src_tbl"},
        {"why": "sp_ItemReloc destination switch: bound 16 -> 18", "at": "dst_cmp_imm8", "width": 1,
         "expect": "old_max_bag", "write": "new_max_bag"},
        {"why": "sp_ItemReloc destination switch: the widened table", "at": "dst_tbl_disp",
         "expect": "dst_tbl_old", "write": "@newbase + dst_tbl"},
    ],
}
json.dump(recipe, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'recipes', 'void-bag-reloc.json'), 'w',
                         newline='\n'),
          indent=2)
print('written; source table', [hex(e) for e in src[:4]], '... dest', [hex(e) for e in dst[:4]], '...')
