// char_void - Character.exe's half of the void inventory (bag 18), and the inventory's own load limit.
//
// Loaded by fiestahook.dll into Character.exe, from Character\hooks\ (a zone plugin must never go there).
// Needs the Character chain: build_zone.py --target character (dll-loader-character, char-itemlist-void).
//
// ---- 1. the inventory loses items past 144 on relog ------------------------------------------------
//
// Every bag has a packer that reads the bag from the DB and packs it for the zone. They all go through one
// reader with a FIXED capacity per bag, into a buffer on the packer's own stack sized for exactly that:
//
//     0x402F80  inventory packer: sub esp 0x168C (= 8 + 144*40 + 4) ; call 0x46A290
//     0x46A290  push 0x90 ; push 9 ; ... ; call 0x469F70      reader(dbf, owner, type 9, limit 144, &n, recs)
//
// The zone holds 192 inventory cells (ItemInventory::ii_Array, Zone.pdb), the client shows 8 pages, but
// the reader stops at 144 rows - in whatever order p_Item_GetListType returns them. Observed 2026-09-19:
// more than 144 items made in-game, relog, "random items disappear and only 144 show". The rows are still
// in tItem; they are simply never loaded, so they come back once the limit is right.
//
// The fix replaces the inventory packer with one that reads up to 192 into a heap buffer and hands the
// result to the SAME packing function (0x402E50). The packed list fits both places it goes:
//   login (fc_NC_CHAR_CHARDATA_REQ): 33,248 bytes of buffer; 192 items x 114 bytes max = 21,888
//   GET_ITEMLIST_BY_TYPE (0x417460): ~116 KB, split into 0x1077 replies of <= 0x1FFB bytes
// and the packed count is a byte (0x402E6B), so 192 fits.
//
// NOT CHANGED: 0x4180B0 (the style-change path, fc_NC_CHAR_SET_STYLE_DB_REQ) reads the inventory through
// the same 144-limited wrapper into its own 144-sized stack buffer. With more than 144 items it can miss
// the style item; it cannot overflow.
//
// ---- 2. bag 18 ---------------------------------------------------------------------------------------
//
// The zone asks for one bag with NC_CHAR_GET_ITEMLIST_BY_TYPE_REQ (0x1076). The char-itemlist-void recipe
// widens that handler's switch to 18 and calls the function in its .charvoid slot, exactly as case 9 calls
// the inventory packer. This plugin puts pack_void there: the same reader and packer, type 18, 288 rows
// (2 pages of 144 - see zonehook/hooks/void_bag/void_bag.cpp for where 144 comes from).
//
// Everything here READS. Saving a move is p_Item_SetStorage / p_Item_ExchangeStorage, which are generic
// over the bag id and already store bag 18 (tItem.nStorageType = 18).
#include <charhook.h>

#include <vector>

namespace {

// ---- the list the reader fills --------------------------------------------------------------------
//
// {int count; int pad; Rec rec[limit]} - the wrapper passes &count and count+8. A record is 40 bytes
// (the reader indexes eax*5*8): item key @0 (u64), storage slot @8 (u16), type @0xA (u8), item id @0xC,
// flags @0x10, date @0x14.
const int kRecordSize = 40;

const unsigned char kInventoryBag = 9;
const int kInventoryCells = 192;          // ItemInventory::ii_Array in Zone.pdb; the stock reader stops at 144
const unsigned char kVoidBag = 18;
const int kVoidCells = 2 * 144;           // two pages of 144 (void_bag.cpp)

// Read bag `type` of character `owner` and pack it into `out` - what every stock bag packer does, with
// the capacity a parameter instead of a constant.
int load_and_pack(void* self, unsigned owner, void* out, int* len, unsigned char type, int limit) {
    if (!self || !out || !len) return 0;
    char* dbf = *(char**)self + chr::kWorkerDbfOffset;       // this worker's own, already-connected DBRecord
    std::vector<unsigned char> list(8 + (size_t)limit * kRecordSize, 0);
    if (!chr::fn::ItemListReader()(dbf + 0x24, 0, dbf, owner, type, limit, (int*)list.data(), list.data() + 8)) {
        chr::log("bag %u of char %u: the DB read FAILED", (unsigned)type, owner);
        return 0;
    }
    int n = *(int*)list.data();
    int r = chr::fn::ItemListPack()(self, 0, list.data(), (unsigned char*)out, len);
    chr::log("bag %u of char %u: %d item(s) read (limit %d), packed %d bytes -> %s", (unsigned)type, owner, n,
             limit, *len, r ? "ok" : "PACK FAILED");
    if (n >= limit) chr::log("bag %u of char %u: AT the limit - rows past %d stay in tItem, unloaded",
                             (unsigned)type, owner, limit);
    return r;
}

// Both are __thiscall(CPFs*, owner, out, len) and clean their 12 bytes, as the stock packer does.
int __fastcall pack_inventory(void* self, void* /*edx*/, unsigned owner, void* out, int* len) {
    return load_and_pack(self, owner, out, len, kInventoryBag, kInventoryCells);
}

int __fastcall pack_void(void* self, void* /*edx*/, unsigned owner, void* out, int* len) {
    return load_and_pack(self, owner, out, len, kVoidBag, kVoidCells);
}

chr::Detour g_inven_detour;

}  // namespace

HOOK_PLUGIN("char_void") {
    // ItemListReader / ItemListPack / InventoryPacker were found by reading the disassembly (none logs a name);
    // character_symbols.h carries the bytes each starts with. A different Character.exe: a log line, no hooks.
    if (!chr::verify_known()) return;

    // 1. the inventory, 144 -> 192. Replaced whole: the trampoline is never called, because the stock body
    //    IS the 144 limit (its stack frame is sized for it).
    chr::hook_function("inventory packer (144 -> 192)", (void*)chr::fn::InventoryPacker(), (void*)pack_inventory,
                       &g_inven_detour);

    // 2. bag 18. The slot is filled last: the recipe's cave treats null as "no plugin" and answers 0x1202.
    chr::ArenaRegion slot = chr::arena_region(".charvoid");
    if (slot.base && slot.size >= 4) {
        *(void**)slot.base = (void*)pack_void;
        chr::log("bag %u (%d cells) answers NC_CHAR_GET_ITEMLIST_BY_TYPE_REQ through the .charvoid slot at %x",
                 (unsigned)kVoidBag, kVoidCells, slot.base);
    } else {
        chr::log("NO .charvoid slot: this Character.exe lacks char-itemlist-void, so bag 18 is still refused");
    }
}
