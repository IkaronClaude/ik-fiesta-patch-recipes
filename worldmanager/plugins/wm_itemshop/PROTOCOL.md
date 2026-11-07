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
| E823 | 8 B: goods u16 @6 (+0..5 left as the stack had them) | 0x4981CE / 0x49E0B5 (the shop window, selected goods +0x45D; only with +0x4AC set and no purchase pending) | the BUY: sets "purchase pending" [0xC329E5] = 1 (cleared by E824) |
| E827 | 28 B: u32 0, u16 0 @4, u32 @6 = [0xC32550] (a byte from a login-stage packet @0x53, set at 0x55537A - the world no?), goods u16 @0xA, name[16] @0xC | 0x4948A3 / 0x49E1BC | the GIFT buy (to that name); sets the pending flag too |

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
| E820 | 0x4AD6F9 -> 0x4AE5D0 | item u16 @0, @0xA u16, ... + a balance | a pull result into window +0x310 (0x4A93D0 / 0x4A93F0 / 0x4A95B0, the item's ItemInfo 0x48F070); the balance re-shown (0x495C80); failures "sorry!!nothings!! try again" / "ItemShop purchases currenty not possible. Please try again later." in ItemShopSys |
| E819 | 0x4AD70E -> 0x4AE810 | a purchase result for window +0x310 + a balance | ok -> the balance re-shown, the item into the premium bag (0x497620), the shop unlocked; "You currently don't have enough coins for this." (0x5BFA3C71) as a system line; the same codes / texts as E824 |
| E824 | 0x4AD723 | item u16 @6, count u32 @8, code u16 @0xC | the PURCHASE result: code 0 and count > 0 -> 0x497620(item, count); the shop unlocked ([0xC329E5] = 0, 0x4976E0(1)); code 1 "The conditions for purchasing this item are not met." (0x916C6A33, %d item), 2 "You currently don't have enough coins for this." (0x217DC7B3), 5 "ItemShop purchases currenty not possible. Please try again later.", 0x22B "Purchase is still being processed.. please wait", other (3, 4, ...) "Invalid Value" (0x855640D3) - lines in ItemShopSys (0x497850) |
| E826 | 0x4AD84C -> 0x4AEAC0 | a purchase result + a balance | ok -> "Your purchase was successful! Your item was added to your premium inventory." (0x95ADE9CC); failures "You currently don't have enough coins for this." (0xBCB44906), "The item you're trying to purchase is out of stock." (0xF2DB4634), "An internal error occurred." (0x253574FC / 0x02F10FE5), not possible / still processing / "Invalid Value" |
| E82A | 0x4AD861 -> 0x4AECF0 | item u16 @6, code u16 @8 | the GIFT result (E827's answer): 0 -> 0x497650(item), "The item has been sent out as gift. Purchase complete." (0x8526D94A); else conditions (0x916C6A33) / coins (0x217DC7B3) / not possible / "The character you entered could not be found." (0x8092A916) / "The user could not be found." (0xA176D8EA) / "Invalid Value"; the shop unlocked |
| E82C | 0x4AD876 -> 0x4AEF10 | a gift result + a balance | ok -> "The item has been sent out as gift. Purchase complete." (0xA3FE6DDF); failures as E826 |
| E82E | 0x4AD88B | ? @0, part u8 @2, count u32 @3, records 16 B @7 | list +0x6C |

The record layouts (93 / 16 / 12 / 13 / 16 / 78 / 21 B) are still to be read from the window functions. Known: the 93-byte
catalogue record has a type at +8 (0 / 1: 0x495580 splits the list into two by it).

## The client's own catalogue data (ressystem, 10.6.6)
- ItemShop.shn (9737 rows): goodsNo u32, InxName[32] (the ItemInfo item), Lot u32, PremiumReturn u8, Visibility u32.
- ItemShopView.shn (307 rows): goodNo u32, Name[256], IconIndex / IconFile, SubIconIndex / SubIconFile, PeriodIconIndex /
  PeriodIconFile, Undefined0..2 u32, Descript[256].
So the server sends WHICH goods are on sale (and prices / categories) by goodsNo; names, icons and items are client data.

## The stack's backend (2016 item mall, Account DB) - what the plugin will use
- `tCash` {userNo int, cashtype tinyint, cash int, status bit} + `usp_Cash_getCash` / `usp_Cash_useCash` / `usp_Cash_setCash`:
  the coin balance (E801 @0x203, the balances in E819 / E820 / E826 / E82C).
- `tChargeItem` {rowNo, userNo, orderNo, goodsNo, amount, registerDate, isDraw, drawDate} + `usp_Charge_ItemInsert` /
  `usp_Charge_ItemSelectList` / `usp_Charge_ItemDraw` / `usp_Charge_ItemDel`: the PREMIUM inventory by goodsNo - the
  2016 zone's charged-item window already delivers from it. A buy = useCash + ItemInsert ("Your item was added to your
  premium inventory.").
- No price / category table anywhere (server data has ItemShop / ItemShopView only = the client's own catalogue): the
  official prices came with the 93-byte E805 records. GUESS until a capture: a new table (e.g. Account.tItemShopGoods
  {goodsNo, price, category, ...}) feeding E805.
- OPEN: the record layouts (93 / 16 / 12 / 13 / 16 / 78 / 21 B) - static reading goes through STL containers in the window
  code; ONE capture of the official US client opening the item shop (and a buy) would give them all.
