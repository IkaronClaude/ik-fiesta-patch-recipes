# grade_colours - where the client colours an item by its grade

Spec for a future colour-change hook. Nothing is hooked yet: this records every place the 2026 US `Fiesta.exe`
turns `ItemInfo.ItemGradeType` into a colour, with the stock values, so a plugin can repoint them.
Read 2026-10-08 from `Z:/Client2026patched_10_6_6/Fiesta.exe` (image base 0x400000).

## The grade enum

`ItemInfo.ItemGradeType` (ItemInfo record +0x76, a dword) is the client enum `GT_*`, named in the 2016 PDB
(`Z:/ClientSource/Fiesta.pdb`):

| value | enum | stock colour |
|---|---|---|
| 0 | GT_NORMAL | white |
| 1 | GT_NAMED | green |
| 2 | GT_RARE | blue |
| 3 | GT_UNIQUE | yellow |
| 4 | GT_CHARGE | pink (cash shop) |
| 5 | GT_SET | blue (shares GT_RARE's case at every site but one) |
| 6 | GT_LEGENDARY | orange |
| 7 | GT_MYTHIC | magenta / violet |
| 8 | (none) | yellow - only the float list switch has a 9th case |

## Text colours: 13 switches

Every site is `mov eax, [reg+0x76]; cmp eax, 7 (or 8); ja default; jmp [eax*4 + table]`. The table is the
cheapest patch point: repoint an entry at another case, or at a stub that loads a new colour.

### RGB as push/byte immediates (r, g, b, a)

| site | table | form |
|---|---|---|
| 0x483D11 | 0x48762C | `push a; push b; push g; push r` -> SetTextColor(r,g,b,a) |
| 0x49341C | 0x4934D8 | same |
| 0x4964F9 | 0x4970C4 | same |
| 0x6357F1 | 0x63910C | same |
| 0x491170 | 0x4912D0 | `mov byte [ebp-0x2C/-0x30/-0x34], ...` (r/g/b bytes) |

Values: 0 (255,255,255) 1 (0,255,0) 2 (13,194,254) 3 (255,228,0) 4 (253,32,239) 5 (13,194,254) 6 (255,128,0)
7 (255,0,255). Default (grade > 7) is white.

In 2016 these are `ItemInfoWin::InsertNameContents` (the tooltip name), `MarketSearchWin::SetListItem` and
`ChatDisplayWin2::AddChatLinkItemInfo`. The 2026 exe has no symbols, so which 2026 site is which window is still
open: test one by changing it.

### COLORREF immediates (0x00BBGGRR)

| site | table | form |
|---|---|---|
| 0x744B80 | 0x744C7C | `mov eax, imm32` (2016 `NameBD::UpdateDropItem`, the ground name) |
| 0x744F2C | 0x744F7C | `pop edi; mov eax, imm32; pop esi; ret` (2016 `CharScreenBoardDropItem::GetNameColor`) |
| 0x7478DD | 0x747A98 | `mov dword [esi+0x64], imm32` |

Same RGB values as above. No item -> (255,243,50).

### Rich-text tags

| site | table | strings |
|---|---|---|
| 0x5C4E73 | 0x5C5024 | `{color,#FFFFFF,` `{color,green,` `{color,lightblue,` `{color,yellow,` `{color,pink,` `{color,lightblue,` `{color,orange,` `{color,violet,` |
| 0x718DF7 | 0x718FB8 | same |

A plugin can point a case at its own `{color,#RRGGBB,` string.

### D3DXCOLOR pointers (floats 0..1)

| site | table | entries |
|---|---|---|
| 0x6E695A | 0x6E6EAC | `mov eax, &color` |

Per grade: 0 (255,255,255) 1 (102,255,51) 2 (135,207,250) 3 (255,255,0) 4 (255,0,255) 5 (135,207,250) 6 (146,255,67)
7 (128,0,128). The pointees are SHARED named colour constants (0xC164F8 white, 0xC16528, 0xC184C8, ...): never write
them; point a case at a new constant instead.

### Float RGB (0..255), 9 cases

| site | table |
|---|---|
| 0x65B2DF | (read from the `jmp [eax*4+...]` two instructions on) |

R/G/B stored to [ebp-8]/[ebp-4]/[ebp+8], then pushed into a list row with the item name: 0 (255,255,255)
1 (0,255,0) 2 (13,194,254) 3 (255,228,0) 4 (253,32,239) 5 (120,120,255) 6 (225,128,0) 7 (225,0,255) 8 (255,255,0).
The only site where set is not rare's blue.

## Icon border and slot background

Not found. No 2026 (or 2016) code reads the grade to draw a slot. The icons are transparent art with nothing painted
in, and two items of different grades share one icon (`F100Sword_LD` grade 6 and `Arena_F100Sword` grade 2, ItemEqu005
#60). `resmenu/Icon/ItemGrade*.dds` are badge sprites (L/M/H, numbered gems, crowns), not frames.
`ItemViewInfo` `Undefined0..2` / `SUB_R/G/B` are a per-item tint that does not follow the grade.

Many `cmp dword [reg+0x76], 4` sites (GT_CHARGE checks, e.g. 0x7CA... in Fiesta.bin) are the cash-item tests; one of
them may draw a cash frame.

## Method

Scan `.text` for `[reg+0x76]` reads followed by a `cmp 7/8` + jump table; decode each case. The 2016 counterparts were
named through the PDB (`pdb_disasm.py --sym`).
