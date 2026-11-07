# The 2026 item shop ("PurchaseNet") protocol - traced from the 2026 US client 10.6.6 (Fiesta.exe 6AB41A55)

Status: IN PROGRESS (2026-11-07). Next: the record layouts (window functions 0x495580 / 0x4954E0 / 0x495970 /
0x495B30 / 0x495940 / 0x4A8B30 / 0x4A8FC0), E823 / E827 bodies, E819 / E820 / E826 / E82A / E82C (0x4AE810 / 0x4AE5D0 /
0x4AEAC0 / 0x4AECF0 / 0x4AEF10), then the server side (the stack's cash = Account tCash? delivery = the charged items). The server side will be this WorldManager plugin (operator: "If WM address is reused,
then please write it as a WM plugin instead").

## The connection
- `PurchaseNetFrameWork` (registered with the client's frameworks at 0x446BC5; init 0x4ACF10) opens a SECOND connection
  (net object `[0xC331A8]`, kept at net `+0x990`; zone `+0x984`, WM `+0x988`) to `[0xC3253C]` (IP, 16 B) / `[0xC3254C]`
  (port) - written by `LoginWorldNetFrameWork` (0x5583DB / 0x5586F0) from the world-select answer's IP (+4) and port
  (+0x14): **the WM's own address**. Same framing / cipher object as the zone and WM sockets.
- Receive dispatch (0x4AD050): dept 2 cmd 7 (the seed, NC_MISC_SEED_ACK) -> the socket's seed; dept 0x3A (0xE8xx) cmd
  1..0x2E through the table 0x4AD92C / 0x4AD97C.
- Client data: ressystem ItemShop.shn / ItemShopView.shn; window ItemShopSys (Game\ItemShopSys.nif, GameUI +0x14EC),
  a second window at GameUI +0x310 (E817 / E81A / E81B ...).

## Sends (client -> server)
| op | body | sender | when |
|---|---|---|---|
| E810 | 2 B | 0x5C25E0(0) | after E805's last part |
| E812 | 2 B | 0x5C25E0(1) | after E811 |
| E814 | 2 B | 0x5C25E0(2) | after E813's last part |
| E80E | 2 B | 0x5C25E0(3) | after E815's last part |
| E800 | 6 B | 0x5C25E0(4) | after E80F's last part (then the shop refreshed, 0x5867E0(0)) |
| E818 | 4 B | 0x5C2710 | |
| E825 | 1 B (01) | 0x497620 via 0x818A10 (the purchase socket's send) | the shop window |
| E82B | 33 B | 0x497650 via 0x818A10 | built from our name (0x794E80) - a gift / target name? |
| E823 / E827 | ? | 0x497D40 / 0x494650 | the shop window (E823 builds a request through 0x4985E0 / 0x498770 - likely the BUY) |

## Receives (server -> client)
| op | handler | layout (offsets in the body) | effect |
|---|---|---|---|
| E805 | 0x4AD08B | ? u16 @0, u32 @2 -> global [0xC1CC30], part u8 @6 (2 = last), count u32 @7, records 0x5D (93) B @0xB | first part clears the 5 lists (+0x30..+0x60); records -> list +0x30; last part -> window 0x495580(list), send E810 |
| E811 | 0x4AD246 | ? u16 @0, 5 x 16 B records @2 | list +0x3C; window 0x4954E0; send E812 |
| E813 | 0x4AD2C3 | ? u16 @0, part u8 @2, count u32 @3, records 12 B @7 | list +0x48; last -> window 0x495970, send E814 |
| E815 | 0x4AD374 | ? u16 @0, part u8 @2, count u32 @3, records 13 B @7 | list +0x54; last -> window 0x495B30, send E80E |
| E80F | 0x4AD416 | ? u16 @0, part u8 @2, count u32 @3, records 16 B @7 | list +0x60; last -> window 0x495940, send E800, shop refresh 0x5867E0(0) |
| E809 | 0x4AD1BD | ? | the window refilled from all lists (0x497720(1), 0x4954E0, 0x495580), 0x5867E0(2) |
| E801 | 0x4AD1A8 -> 0x4AD9F0 | ... coins u32 @0x203 (-> global [0xC1CC2C]), err u16 @0x20B (0 = ok) | only while [0xC329C4] == 1 (the shop up): the balance formatted (a stringstream, thousands) into the shop (0x495C80) |
| E817 | 0x4AD4B1 | count u32 @0x618, records 0x4E (78) B @4 | window +0x310 (0x4A8B30 per record, 0x4A91F0, 0x4A9080); +0x158 == 2 selects 0x4A8F80 else 0x4A8D00 first |
| E81A | 0x4AD53B | count u32 @0x41A, u32 @0x41E, records 0x15 (21) B @0xC | window +0x310 0x4A8FC0 per record |
| E81B | 0x4AD59F | u32 @0, u32 @4, u32 @8 | window +0x310 0x4A9400(@8, @0, @4) |
| E81C | 0x4AD5D2 | u32 @0, u32 @4, u32 @8, u32 @0xC | window +0x310 0x4A9480(@0xC, @0, @4, @8), shown (0x884870) |
| E81E | 0x4AD615 | item u16 @0, u32 @2, err u16 @6 | +0x310 +0x159 = 0; err 0 -> 0x4A93D0(item), 0x4A93F0(@2), the ItemInfo row (0x22 = its name, table [0xCE2E98]) -> 0x4A95B0; else ItemShopSys line "Could not complete the pull. Please try again." (0x128C95AB, 0x497850) - a gacha "pull" |
| E820 | 0x4AD6F9 | | 0x4AE5D0 |
| E819 | 0x4AD70E | | 0x4AE810 |
| E824 | 0x4AD723 | item u16 @6, count u32 @8, code u16 @0xC | the PURCHASE result: code 0 and count > 0 -> 0x497620(item, count); the shop unlocked ([0xC329E5] = 0, 0x4976E0(1)); code 1 "The conditions for purchasing this item are not met." (0x916C6A33, %d item), 2 "You currently don't have enough coins for this." (0x217DC7B3), 5 "ItemShop purchases currenty not possible. Please try again later.", 0x22B "Purchase is still being processed.. please wait", other (3, 4, ...) "Invalid Value" (0x855640D3) - lines in ItemShopSys (0x497850) |
| E826 | 0x4AD84C | | 0x4AEAC0 |
| E82A | 0x4AD861 | | 0x4AECF0 |
| E82C | 0x4AD876 | | 0x4AEF10 |
| E82E | 0x4AD88B | ? @0, part u8 @2, count u32 @3, records 16 B @7 | list +0x6C |

The record layouts (93 / 16 / 12 / 13 / 16 / 78 / 21 B) are still to be read from the window functions.
