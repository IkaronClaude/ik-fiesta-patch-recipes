"""Generate character/recipes/char-itemlist-void.json - the 17 original jump-table entries are READ from the exe."""
import hashlib
import json
import os
import struct

import pefile

EXE = 'Z:/ServerSource/Character/Character.exe'
pe = pefile.PE(EXE, fast_load=True)
d = open(EXE, 'rb').read()


def u32(va):
    return struct.unpack_from('<I', d, pe.get_offset_from_rva(va - 0x400000))[0]


def at(va, n):
    o = pe.get_offset_from_rva(va - 0x400000)
    return d[o:o + n]


TABLE = 0x41781C
table = [u32(TABLE + 4 * i) for i in range(17)]
DEFAULT, RESOLVED = 0x4176B6, 0x41752B
# the switch and the two type gates, checked here so a different build fails at generation, not at apply
assert at(0x417505, 3) == b'\x83\xF9\x10', 'cmp ecx, 0x10'
assert at(0x417508, 2) == b'\x0F\x87', 'ja default'
assert at(0x41750E, 3) == b'\xFF\x24\x8D' and u32(0x417511) == TABLE, 'jmp [ecx*4 + table]'
assert at(0x469F80, 2) == b'\x3C\x11' and at(0x46A06A, 2) == b'\x3C\x11', 'cmp al, 0x11 in both list readers'
assert table[9] == 0x4175F9, 'case 9 is the inventory (calls 0x402F80)'

H = lambda v: '0x%08X' % v

recipe = {
    "name": "char-itemlist-void",
    "summary": "Let NC_CHAR_GET_ITEMLIST_BY_TYPE_REQ answer bag 18 (the 2026 Void Inventory) through a packer the "
               "char_void plugin provides.",
    "status": "BUILT AND STATICALLY VERIFIED. Not yet booted.",
    "target": {"file": "Character/Character.exe",
               "sha256": hashlib.sha256(d).hexdigest(),
               "size": len(d)},
    "params": {},
    "consts": {
        "switch_cmp_imm8": "0x00417507", "switch_tbl_disp": "0x00417511", "switch_tbl_old": H(TABLE),
        "default": H(DEFAULT), "resolved": H(RESOLVED),
        "gate1_imm8": "0x00469F81", "gate2_imm8": "0x0046A06B",
        "old_max_type": "0x10", "new_max_type": "0x12",
        "old_type_limit": "0x11", "new_type_limit": "0x13",
        "slot": "0x00", "tbl": "0x04", "cave": "0x50",
    },
    "new_section": {
        "name": ".charvoid",
        "size": "0x80",
        "materialise": True,
        "execute": True,
        "note": "One arena region, labelled .charvoid: the plugin slot (+0), the widened jump table (+0x04) and the "
                "case-18 cave (+0x50). Executable and materialised, and writable because the plugin fills the slot.",
    },
    "why": [
        "The zone asks Character for one bag's items with NC_CHAR_GET_ITEMLIST_BY_TYPE_REQ (0x1076, {header, u8",
        "type, u32 owner}); Character's handler (0x417460 - it logs no name of its own, it is found by the 0x1077",
        "reply it builds) switches on the type and calls that bag's packer:",
        "",
        "    0x417505  cmp ecx, 0x10 ; ja 0x4176B6 (error 0x1202) ; jmp [ecx*4 + 0x41781C]",
        "    case 9:   lea edx,[ebp-0x1E828] ; push edx ; lea ecx,[ebp-0x1C813] ; push ecx ; push eax ; mov ecx,esi",
        "              call 0x402F80 ; jmp 0x41752B",
        "",
        "and everything after 0x41752B is bag-agnostic: it splits the packed list into 0x1077 replies of at most",
        "0x1FFB bytes, first/last flagged. So bag 18 needs a case and a packer, nothing else. The packer is the",
        "plugin's (__thiscall(CPFs*, owner, out, int* len), as 0x402F80); a null slot takes the default, so without",
        "the plugin Character answers 18 with the 0x1202 it always did.",
        "",
        "The two list readers the packers end in (0x469F70, 0x46A040) refuse any type >= 0x11 before querying;",
        "p_Item_GetListType itself is `WHERE nOwner = @nCharNo AND nStorageType = @nStorageType`, generic. Their",
        "bound goes to 0x13. Every existing caller passes a constant type below 0x11, so none of them changes.",
    ],
    "code": [
        {"why": "the handler's jump table, widened to 0..18",
         "at": "@newbase + tbl",
         "emit": [{"u32": H(e)} for e in table] + [{"u32": "default"}, {"u32": "@newbase + cave"}]},
        {"why": "case 18: the plugin's packer, called exactly as case 9 calls 0x402F80, else the default",
         "at": "@newbase + cave",
         "emit": [
             "8B15", {"u32": "@newbase + slot"},       # mov edx, [slot]
             "85D2", "0F84", {"rel32": "default"},     # test edx, edx ; jz default
             "8D8DD817FEFF", "51",                     # lea ecx, [ebp-0x1E828] ; push ecx      int* len
             "8D8DED37FEFF", "51",                     # lea ecx, [ebp-0x1C813] ; push ecx      out
             "50",                                     # push eax                                owner
             "8BCE", "FFD2",                           # mov ecx, esi ; call edx                 __thiscall
             "E9", {"rel32": "resolved"},
         ]},
    ],
    "edits": [
        {"why": "GET_ITEMLIST_BY_TYPE switch: bound 16 -> 18", "at": "switch_cmp_imm8", "width": 1,
         "expect": "old_max_type", "write": "new_max_type"},
        {"why": "GET_ITEMLIST_BY_TYPE switch: the widened table", "at": "switch_tbl_disp",
         "expect": "switch_tbl_old", "write": "@newbase + tbl"},
        {"why": "list reader 0x469F70: accept type 18", "at": "gate1_imm8", "width": 1,
         "expect": "old_type_limit", "write": "new_type_limit"},
        {"why": "list reader 0x46A040: accept type 18", "at": "gate2_imm8", "width": 1,
         "expect": "old_type_limit", "write": "new_type_limit"},
    ],
}
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'recipes', 'char-itemlist-void.json')
json.dump(recipe, open(out, 'w', newline='\n'), indent=2)
print('written; table', [hex(e) for e in table])
