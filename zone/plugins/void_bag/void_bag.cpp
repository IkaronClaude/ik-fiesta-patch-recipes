// void_bag - the extra inventory (bag 18), as a hook DLL.
//
// STATUS (proven live 2026-09-19): bag 18 is a real ItemBag in the zone; items move in and out of it
// (void-bag-reloc recipe), moves are saved to tItem by the zone's own generic storage calls, and at login
// the zone asks Character for bag 18 (NC_CHAR_GET_ITEMLIST_BY_TYPE_REQ - needs the Character chain and the
// char_void plugin there, see "loading" below). The unlock is the item's permanent charged effect.
//
// ---- THE SPEC (operator) ---------------------------------------------------------------------------
//   2 pages of 144 slots = 288 cells total.
//   Each page is unlocked by USING a void-inventory item, once, on that character.
//   The unlock is permanent, the way the existing bag expansions are.
//
// ---- WHAT THE WIRE SHOWS (live-20260918-112257, character Keans, annotated by self-whisper) ---------
//
// The operator whispered themselves while moving items, so the capture reads as a narrative:
//
//   22.95  "opening void bag"
//   39.01  "top left item strong bone (ingredient), moving to inv"
//   47.93  "Returning back to void bag"
//   68.41  "2 pages but page 2 is closed. bottom right slot:"
//
// and each annotation sits next to the packets it caused:
//
//   C-> 0x300B  RELOC_REQ  {u16 from, u16 to}         00 48 bb 24   bag 18 slot   0 -> bag 9 slot 187
//   S<- 0x3001  CELLCHANGE                            the source cell set to item 0xFFFF (emptied)
//   S<- 0x3001  CELLCHANGE                            the destination cell set to item 3040 x100
//   S<- 0x300C  RELOC_ACK  0x0241                     same code on every successful move
//
//   C-> 0x300B  RELOC_REQ                             8f 48 bb 24   bag 18 slot 143 -> bag 9 slot 187
//
// An ITEM_INVEN is (inven << 10) | slot, so bag 18 is 0x4800..0x4BFF and those two moves are the FIRST
// and LAST slot of page 1. **Slot 143 is the last slot of a 144-slot page** - the wire confirms the page
// size independently of the spec. Page 2 is therefore slots 144..287, and was closed at capture time.
//
// The server also sends a 0x1047 CLIENT_ITEM for box 18 at login (106 items, one capture), which is how
// the contents arrive. Box 15 appears in every capture with a count of ZERO - consistent with the
// operator's reading that 15 is something else, not more inventory.
//
// ---- WHAT THAT MEANS FOR THE IMPLEMENTATION --------------------------------------------------------
//
// A BAG IS A CLASS, NOT A RANGE. An earlier note here said a new bag was "a question of which indices
// are addressable, not of allocating anything". That was wrong. ItemBag is an abstract base (sizeof 4,
// just a vptr) and each storage kind is a SUBCLASS owning its own cell array, with its own
// ib_GetInvenType / ib_GetInventoryCell / ib_BagSizeInput / ib_BagSizeOutput. Disassembling the nine
// ib_GetInvenType bodies (each is `mov al, N; ret`) gives the id -> class map exactly:
//
//     id  class                           cells   (sizeof - 4) / sizeof(ItemInventoryCell)
//      0  ItemGuildAcademyRewardStorage      72
//      1  ItemRewardStorage                  24
//      3  ItemFurnicherBox                   98
//      4  ItemGuildStorage                   36
//      6  ItemAccountStorage                576      <- precedent: far bigger than the inventory
//      7  ItemQuestItemBox                    5
//      8  ItemEquipment                      31.6    <- not a whole cell array; equipment differs
//      9  ItemInventory                     192      <- the player inventory, and ONLY that
//     12  ItemMiniHouseBox                   35
//
// This reproduces the {0,1,3,4,6,7,8,9,12} set found earlier by disassembling ib_GetInvenType, by a
// completely different route. 18 is absent, which is why bag 18 goes nowhere on this build.
//
// So the void inventory is a TENTH ItemBag subclass with 288 cells. It does not fit inside
// ItemInventory's 192 and was never meant to - ItemAccountStorage already carries 576, so a bag larger
// than the inventory is ordinary here.
//
// ---- OPEN ------------------------------------------------------------------------------------------
//   - Which bags the void bag may trade with. It is judged as the inventory for now (see IA_CanInvenReloc
//     below); the operator suspects official is stricter (e.g. no trading straight out of it).
//
// UNVERIFIED: whether 0x300B/0x3001/0x300C keep these numbers on the 2026 wire (the opcode table this
// repo has is the 2016 one, and the names printed for them were UNKNOWN_xxxx). The FIELD layout above is
// read straight from the bytes and does not depend on the name being right.
#include <zonehook.h>
#include <zonehook_lua.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cstddef>         // offsetof
#include <cstdio>          // proving the full CRT is available in a plugin
#include <string>
#include <unordered_map>
#include <unordered_set>

using zone::types::ItemInventory;
using zone::types::ItemInventoryCell;

namespace {

// How many cells the one flat inventory really has. Derived, never typed in: if the struct changes, this
// changes with it, and the static_assert in zone_types.h has already checked it against the binary.
const int kInventoryCells = sizeof(ItemInventory::ii_Array) / sizeof(ItemInventoryCell);

long long g_reloc_count = 0;

}  // namespace

// ---- every inventory move --------------------------------------------------------------------------
//
// Logs the bag/slot on both sides. Bags outside the set this build accepts are called out, because those
// are the interesting ones: a 2026 client asking for bag 18 or 15 is the evidence the feature needs.

static bool known_bag(unsigned b) {
    switch (b) {
        case 0: case 1: case 3: case 4: case 6: case 7: case 8: case 9: case 12: return true;
        case 18: return true;                          // ours, via void-bag-reloc
        default: return false;
    }
}

ZONE_HOOK_PACKET(NC_ITEM_RELOC_REQ, {
    const unsigned char* p = (const unsigned char*)cmd;
    if (p) {
        unsigned short from = *(const unsigned short*)(p + 2);   // past the 2-byte opcode
        unsigned short to   = *(const unsigned short*)(p + 4);
        unsigned fb = from >> 10, fs = from & 0x3FF;
        unsigned tb = to   >> 10, ts = to   & 0x3FF;
        g_reloc_count++;
        zone::log("reloc #%d  player=%x  %u:%u -> %u:%u%s",
                  (int)g_reloc_count, self, fb, fs, tb, ts,
                  (known_bag(fb) && known_bag(tb)) ? "" : "   <-- BAG THIS BUILD DOES NOT ACCEPT");
    }
    ZONE_CALL_ORIGINAL_OF(NC_ITEM_RELOC_REQ);
});

// ---- the time-limit item list: where an Iron Case, and a Void Inventory item, take effect ------------
//
// A permanent bag expansion is not a stored flag. It is a CHARGED EFFECT: using the item adds an entry
// {record*, end date} to the character's ChargedItemEffectList, and ChargedItemEffectElement::ciee_Activ
// applies it by switching on the record's EffectEnum. For the Iron Case (AddInventory02_4, EffectEnum 2,
// EffectValue 2, KeepTime_Hour 0 = permanent) the whole effect is, at 0x4505E2:
//
//     state.ci_Effect.cec_MoreInven += EffectValue;  if (> 6) = 6;
//
// The 2026 Void Inventory item (VoidInvent, id 37144) is EffectEnum 45, EffectValue 1, KeepTime_Hour 0 -
// one page per use, permanent. This zone's switch stops at 38 (`cmp ecx, 0x26; ja default`), so 45 lands
// in the default and does NOTHING. It is bounds-checked: 45 is ignored, not used as an index.
//
// This hook watches every activation, so using a Void Inventory item shows whether 45 reaches here at all -
// which decides whether the existing charged-item persistence carries the unlock for free.
//
// ciee_Activ is __thiscall(ChargedItemEffectElement* this, ChargedItem* state, unsigned short).
// Prologue: push ebp / mov ebp,esp / push ebx / push esi - 5 bytes, all decodable.

namespace {

const int kEffectVoidInventory = 45;     // from the 2026 ChargedEffect table (VoidInvent)
const int kEffectMoreInventory = 2;      // EE_MOREINVENTORY in the zone's own EffectEnumerate

zone::Detour g_activ_detour;

void __fastcall activ_impl(void* self, void* /*edx*/, void* state, unsigned short a2) {
    using zone::types::ChargedItemEffect;
    using zone::types::ChargedItemEffectList__ChargedItemEffectElement;
    auto* el = (ChargedItemEffectList__ChargedItemEffectElement*)self;
    const ChargedItemEffect* rec = el ? el->ciee_Index : nullptr;
    if (rec) {
        int e = (int)rec->EffectEnum;
        const char* what = e == kEffectVoidInventory ? "   <-- VOID INVENTORY (this zone has no case for it)"
                         : e == kEffectMoreInventory ? "   <-- inventory expansion (Iron Case family)"
                         : e > 38                    ? "   <-- above this zone's switch: ignored"
                         : "";
        zone::log("charged effect %.32s  enum %d  value %u  keep %uh  until %u-%u-%u %u:%02u%s",
                  rec->ItemID, e, (unsigned)rec->EffectValue, (unsigned)rec->KeepTime_Hour,
                  2000u + el->ciee_Year, (unsigned)el->ciee_Month, (unsigned)el->ciee_Date,
                  (unsigned)el->ciee_Hour, (unsigned)el->ciee_Minute, what);
    }
    typedef void(__fastcall* Orig)(void*, void*, void*, unsigned short);
    ((Orig)g_activ_detour.trampoline)(self, 0, state, a2);
}

void __declspec(naked) activ_thunk() {
    __asm { jmp activ_impl }
}

}  // namespace

// ---- letting the Void Inventory item be used ---------------------------------------------------------
//
// UseEffect::UseItemChargedBuff::uib_CanUseItem(ShinePlayer*, ItemTotalInformation*) decides whether a
// charged item may be used: 0x700 yes, 0x713 "The selected item does not have any effect when used". It
// finds the item's ChargedItemEffect in chargedbuffdatabox and switches on EffectEnum - `cmp eax, 0x26;
// ja -> 0x713` - so every enum past 38, the void inventory's 45 among them, is refused. Observed
// 2026-09-19: C->S 0x3015 for VoidInvent (37144), answer 0x3016 result 0x0713.
//
// Everything AFTER this check is enum-agnostic, which is what makes letting 45 through safe: uib_Effect
// calls ShinePlayer::so_ply_ChargedBuff, and that consumes the item, sets the end date (KeepTime 0 is its
// hard-coded 2255-12-31 23:59), adds the list element, saves it (p_Char_SetChargedBuffer) and sends 0x9003 -
// the only EffectEnum it looks at is one abstate special case. So the zone's own code records and persists a
// void page, and the login-time list (0x104A) carries it back after a relog. This hook only answers the
// question the switch cannot.
//
// The rule is the one the patch notes and the spec give: one page per item, two pages at most.

namespace {

const int kMaxVoidPages = 2;
const unsigned short kUseOk = 0x700;         // uib_CanUseItem's own two answers, read off its two exits
const unsigned short kUseNoEffect = 0x713;

// chargedbuffdatabox's array is {u16 item id, u16 pad, ChargedItemEffect*} per entry - uib_CanUseItem reads
// `word [array + i*8]` and `[array + i*8 + 4]`.
struct ChargedBuffEntry {
    unsigned short item;
    unsigned short pad;
    const zone::types::ChargedItemEffect* effect;
};
static_assert(sizeof(ChargedBuffEntry) == 8, "the zone walks this table in 8-byte steps");

const zone::types::ChargedItemEffect* charged_effect_of(unsigned short item_id) {
    const auto* box = zone::global::chargedbuffdatabox();
    auto* arr = (const ChargedBuffEntry*)box->cideb_Array;
    for (int i = 0; arr && i < box->cideb_Total; i++)
        if (arr[i].item == item_id) return arr[i].effect;
    return nullptr;
}

// Pages the player already has: the sum of EffectValue over its active enum-45 effects. The list is
// ChargedItem::ci_List, which sits immediately before the container so_ply_ChargedEffectContainer returns.
// ASSUMES a freed slot is never a void page: ciee_Free does not visibly clear the slot's pointer, but a void
// page is permanent and is never freed, so no stale enum-45 record can be left behind.
int void_pages_in(const void* container) {
    using ChargedItem = zone::types::ChargedItemEffectList__ChargedItem;
    if (!container) return 0;
    auto* item = (const ChargedItem*)((const char*)container - offsetof(ChargedItem, ci_Effect));
    int pages = 0;
    for (const auto& el : item->ci_List.cel_Effect)
        if (el.ciee_Index && (int)el.ciee_Index->EffectEnum == kEffectVoidInventory)
            pages += el.ciee_Index->EffectValue;
    return pages > kMaxVoidPages ? kMaxVoidPages : pages;
}

int void_pages(void* player) {
    auto get = zone::fn::ShineObjectClass__ShinePlayer__so_ply_ChargedEffectContainer();
    return player ? void_pages_in(get(player, 0)) : 0;
}

zone::Detour g_canuse_detour;

unsigned short __fastcall canuse_impl(void* self, void* /*edx*/, void* player, void* itemp) {
    auto* item = (const zone::types::ItemTotalInformation*)itemp;
    const zone::types::ChargedItemEffect* eff = item ? charged_effect_of(item->iti_itemstruct.itemid) : nullptr;
    if (eff && (int)eff->EffectEnum == kEffectVoidInventory) {
        int have = void_pages(player);
        unsigned short r = (have + eff->EffectValue <= kMaxVoidPages) ? kUseOk : kUseNoEffect;
        zone::log("void inventory item %u: player %x has %d page(s), +%u -> %s",
                  (unsigned)item->iti_itemstruct.itemid, player, have, (unsigned)eff->EffectValue,
                  r == kUseOk ? "ALLOWED" : "refused, already at the maximum");
        return r;
    }
    typedef unsigned short(__fastcall* Orig)(void*, void*, void*, void*);
    return ((Orig)g_canuse_detour.trampoline)(self, 0, player, itemp);
}

void __declspec(naked) canuse_thunk() {
    __asm { jmp canuse_impl }
}

}  // namespace

// ---- the void inventory itself: bag 18, a real ItemBag -----------------------------------------------
//
// An ItemBag is { vptr; ItemInventoryCell cells[N]; } behind four virtuals (read off every bag's vtable -
// the table stops at 4 and the next class's RTTI follows):
//
//   [0] ItemInventoryCell* ib_GetInventoryCell(int slot)   ONE implementation for every bag (0x643000):
//                                                          slot < ib_BagSizeOutput() ? this + 4 + slot*116
//   [1] int ib_BagSizeInput(const ChargedEffectContainer*) USABLE cells, from the charged effects - the
//                                                          inventory's is (2 + cec_MoreInven) * 24, max 192
//   [2] int ib_BagSizeOutput()                             CAPACITY - the inventory's is 192
//   [3] unsigned char ib_GetInvenType()                    `mov al, N; ret` - 9 for the inventory
//
// The void bag is the same shape: 288 cells (2 pages of 144), usable = 144 x void pages, pages being the
// enum-45 charged effects - counted from the list, not kept in a counter of our own, so it cannot drift
// from what the zone itself holds. Slot 0 reuses the zone's own generic cell lookup, so the bag behaves
// exactly as the zone expects a bag to.
//
// One per character. ShinePlayer objects are pooled and reused for other characters, so a bag is keyed by
// the player object and CLEARED every time a character is loaded into it (so_StoreInventoryFromServer):
// one character's void items can never show up for the next.
//
// sp_ItemReloc reaches it through the void-bag-reloc recipe, which widens that function's two bag-id
// switches to 18 and asks void_bag_of() through a slot it labels ".voidreloc" in the arena directory.

namespace {

const unsigned char kVoidBagId = 18;
const unsigned char kInventoryBagId = 9;                    // ItemInventory::ib_GetInvenType: mov al, 9
const int kCellsPerVoidPage = 144;                          // wire: page 1 is slots 0..143 (see the top)
const int kVoidCapacity = kMaxVoidPages * kCellsPerVoidPage;

struct VoidBag {
    void** vptr;
    ItemInventoryCell cells[kVoidCapacity];
    // ours, after everything the zone reads (the vptr and 288 cells)
    bool loaded;            // the character's bag-18 rows have arrived from Character (see "loading" below)
    unsigned owner;         // the character they belong to (so_GetCharRegistNumber)
};
static_assert(offsetof(VoidBag, cells) == 4, "ib_GetInventoryCell addresses this + 4 + slot * 116");
static_assert(sizeof(ItemInventoryCell) == 116, "and 116 is the cell size it multiplies by");

// The virtuals are __thiscall; __fastcall with a dead edx is the same thing, and callee-cleans its stack
// arguments exactly as __thiscall does.
int __fastcall vb_size_input(VoidBag*, void*, const void* container) {
    return void_pages_in(container) * kCellsPerVoidPage;
}
int __fastcall vb_size_output(VoidBag*, void*) { return kVoidCapacity; }
unsigned char __fastcall vb_inven_type(VoidBag*, void*) { return kVoidBagId; }

// [-1] is the RTTI Complete Object Locator every MSVC vtable carries, and the zone has 41 __RTDynamicCast
// call sites: one reading a NULL locator off a bag would take the zone down. So it is borrowed from
// ItemInventory. A dynamic_cast would then take the void bag for an inventory - which is memory-safe,
// because the cell layout is identical and 192 cells is fewer than our 288.
void* g_vtable[5];

void build_vtable() {
    void** inv_vt = zone::vtable::ItemInventory();
    g_vtable[0] = inv_vt[-1];
    g_vtable[1] = (void*)zone::fn::ItemRewardStorage__ib_GetInventoryCell();  // the shared one
    g_vtable[2] = (void*)vb_size_input;
    g_vtable[3] = (void*)vb_size_output;
    g_vtable[4] = (void*)vb_inven_type;
}

CRITICAL_SECTION g_bags_lock;
std::unordered_map<void*, VoidBag*> g_bags;

void clear_bag(VoidBag* bag) {
    // The zone's own ItemBag::ib_clear copies its empty-cell template (registration number all FF, item id
    // 0xFFFF, the null attribute object) into every cell up to ib_BagSizeOutput - so the bag starts as
    // empty as any real bag, by the zone's definition of empty.
    zone::fn::ItemBag__ib_clear()(bag, 0);
}

VoidBag* bag_for(void* player, bool create) {
    EnterCriticalSection(&g_bags_lock);
    VoidBag* bag = nullptr;
    auto it = g_bags.find(player);
    if (it != g_bags.end()) {
        bag = it->second;
    } else if (create) {
        bag = new VoidBag;
        bag->vptr = &g_vtable[1];
        bag->loaded = false;
        bag->owner = 0;
        clear_bag(bag);
        g_bags[player] = bag;
    }
    LeaveCriticalSection(&g_bags_lock);
    return bag;
}

// What the recipe's cave calls: ItemBag* __cdecl (ShinePlayer*). Null makes the move take the zone's
// default - refused, exactly as without the recipe.
//
// NOT UNTIL THE BAG IS LOADED. Its contents arrive from Character a moment after login (see "loading"
// below). A move made before that would work on an empty in-memory bag while tItem still holds the real
// rows: a deposit could take a slot a stored item already occupies, and two items would then share one
// (nStorageType, nStorage). Refusing costs the player one click; the other way costs an item.
extern "C" void* __cdecl void_bag_of(void* player) {
    VoidBag* bag = player ? bag_for(player, false) : nullptr;
    if (bag && bag->loaded) return bag;
    zone::log("void bag of player %x: %s - move refused", player,
              bag ? "contents not loaded from Character yet" : "never loaded (no inventory login seen)");
    return nullptr;
}

// Which bags an item may move between. Every move is checked by CItemAuthorityBase::IA_CanInvenReloc(
// belong, puton, from, to, *err), which REFUSES any bag id >= 17 outright and otherwise reads one of three
// 17x17 permission matrices kept in the object (char-bound +0x125, account-bound +0x246, the rest +0x4),
// indexed [from * 17 + to]. Bag 18 is outside all of them, so every deposit came back 0x024A - which the
// client words as "you cannot transfer an item that has been bound to yourself", whatever the item.
//
// The void bag answers AS THE INVENTORY DOES: 18 is asked as 9 on either side. That invents no rule - an
// inventory<->void move is judged as an inventory<->inventory one (always allowed), void->account storage as
// inventory->account storage (a character-bound item refused, exactly where the inventory refuses it).
// OPEN: official may restrict what the void bag accepts; this mirrors the inventory until that is known.
zone::Detour g_ia_detour;

int __fastcall ia_impl(void* self, void* /*edx*/, int belong, int puton, unsigned from, unsigned to, int* err) {
    unsigned short f = (unsigned short)from, t = (unsigned short)to;
    if (f == kVoidBagId) f = kInventoryBagId;
    if (t == kVoidBagId) t = kInventoryBagId;
    typedef int(__fastcall* Orig)(void*, void*, int, int, unsigned, unsigned, int*);
    int r = ((Orig)g_ia_detour.trampoline)(self, 0, belong, puton, f, t, err);
    if (f != (unsigned short)from || t != (unsigned short)to)
        zone::log("void bag move %u -> %u judged as %u -> %u: %s", (unsigned)(unsigned short)from,
                  (unsigned)(unsigned short)to, (unsigned)f, (unsigned)t, r ? "allowed" : "refused");
    return r;
}

void __declspec(naked) ia_thunk() {
    __asm { jmp ia_impl }
}

// ---- loading: bag 18 from Character at login ----------------------------------------------------------
//
// Character sends the login bags as PROTO_NC_CHAR_ITEM_CMDs, one per bag, and so_StoreInventoryFromServer
// picks the bag by nPartMark (byte 1): 0x04 inventory, 0x08 equipment, 0x10 mini-house, 0x20 action items.
// There is no bit for bag 18. But there is a request for ANY bag, already in both exes:
//
//   zone -> Character  NC_CHAR_GET_ITEMLIST_BY_TYPE_REQ 0x1076  {u16 op, u16 handle, u32 charno, u8 type, u32 owner}
//   Character -> zone  NC_CHAR_GET_ITEMLIST_BY_TYPE_ACK 0x1077  ... +8 type, +9 owner, +0xD u16 error (0x1200 ok),
//                      +0x10 flags (bit 0 first reply, bit 1 last), +0x11 u8 count, +0x12 the items
//
// The zone sends it itself for the mini-house bags (0x5722A4) and its reply handler loads types 3, 13, 14 and
// 16 (0x518E20). Character answers 18 through the char_void plugin (char-itemlist-void widens its switch).
//
// So: when the inventory part arrives - once per login into this zone - the bag is reset and 18 is asked for.
// The replies are loaded with the zone's own ItemBag::ib_Initializetotal (the function the login bags go
// through: it files each item at its own slot and asserts on a slot past the bag), and after the last one
// the client gets box 18 as a 0x1047, built by the zone's own ci_FillBufferInventoryItem. Until then the bag
// is not "loaded" and every move into or out of it is refused (void_bag_of).

const unsigned short kOpItemListByTypeReq = 0x1076;   // NC_CHAR_GET_ITEMLIST_BY_TYPE_REQ: CHAR (4) << 10 | 118
const unsigned short kOpClientItemCmd = 0x1047;       // NC_CHAR_CLIENT_ITEM_CMD, as so_StoreInventoryFromServer sends it
const unsigned short kItemListOk = 0x1200;
const unsigned char kPartInventory = 0x04;            // so_StoreInventoryFromServer: test al, 4 -> the inventory
const int kClientChunkBytes = 0x1F40;                 // what so_StoreInventoryFromServer asks per 0x1047

using zone::types::ShineObjectClass__ShinePlayer;
static_assert(offsetof(ShineObjectClass__ShinePlayer, sp_Item.itembag) == 0x7FD8,
              "the CharacterInventory so_StoreInventoryFromServer passes to ci_FillBufferInventoryItem (0x44E01A)");

unsigned char_number(void* player) {
    return (unsigned)zone::fn::ShineObjectClass__ShinePlayer__so_GetCharRegistNumber()(player, 0);
}

unsigned short handle_of(void* player) {
    return *(const unsigned short*)((const char*)player + offsetof(zone::types::ShineObjectClass__ShineObject, so_handle));
}

// The global packet every zone sender fills: its first member points at the buffer, which starts with the opcode.
void* global_packet() { return zone::global::gpp(); }
unsigned char* global_buffer() { return *(unsigned char**)global_packet(); }

bool set_packet_len(int len) {
    return zone::fn::ProtocolPacket__pp_SetPacketLen()(global_packet(), 0, len) != 0;
}

void request_void_list(void* player, unsigned charno) {
    void* session = zone::fn::SocketBundle_GameDBSession___sb_GetSocket()(zone::global::sock2gameDB(), 0);
    unsigned char* b = global_buffer();
    if (!session || !b) {
        zone::log("void bag of char %u: NOT requested - %s", charno, session ? "no packet buffer" : "no Character session");
        return;
    }
    *(unsigned short*)(b + 0) = kOpItemListByTypeReq;
    *(unsigned short*)(b + 2) = handle_of(player);
    *(unsigned*)(b + 4) = charno;
    b[8] = kVoidBagId;
    *(unsigned*)(b + 9) = charno;
    if (!set_packet_len(13)) {
        zone::log("void bag of char %u: NOT requested - pp_SetPacketLen refused 13 bytes", charno);
        return;
    }
    zone::fn::ProtocolPacket__pp_SendPacket()(global_packet(), 0, (zone::types::ZoneBaseSession*)session);
    zone::log("void bag of char %u (player %x): asked Character for bag %u", charno, player, (unsigned)kVoidBagId);
}

// Box 18 to the client, exactly as so_StoreInventoryFromServer sends a login bag (0x44DF57..0x44E0AB): the
// global buffer as {u16 0x1047, u8 count, u8 box, u8 flags (bit 0: first), items}, filled 0x1F40 bytes at a
// time by ci_FillBufferInventoryItem, which walks the bag it is GIVEN - ours - and returns the bytes it wrote.
int send_void_list(void* player, VoidBag* bag) {
    unsigned char* b = global_buffer();
    if (!b) return 0;
    *(unsigned short*)b = kOpClientItemCmd;
    unsigned char* p = b + 2;
    p[1] = kVoidBagId;
    void* ci = (char*)player + offsetof(ShineObjectClass__ShinePlayer, sp_Item.itembag);
    auto fill = zone::fn::CharacterInventory__ci_FillBufferInventoryItem();
    int cursor = 0, packets = 0;
    unsigned char first = 1;
    for (;;) {
        int n = fill(ci, 0, p, (zone::types::PROTO_ITEMPACKET_INFORM*)(p + 3), kVoidBagId, &cursor,
                     kClientChunkBytes, (zone::types::ItemBag*)bag);
        if (n <= 0) break;
        p[2] = (unsigned char)((p[2] & ~1) | first);
        first = 0;
        if (!set_packet_len(n + 5)) { zone::log("box 18 list: pp_SetPacketLen refused %d bytes", n + 5); break; }
        // ShinePlayer::so_GetDataSocketStream()->[+0xC](player, packet): the client send the zone uses here
        typedef void(__fastcall* Send)(void* stream, void* edx, void* player, void* packet);
        void* stream = zone::fn::ShineObjectClass__ShinePlayer__so_GetDataSocketStream()(player, 0);
        if (!stream) break;
        ((Send)(*(void***)stream)[0xC / 4])(stream, 0, player, global_packet());
        packets++;
    }
    return packets;
}

VoidBag* bag_of_char(unsigned owner, void** player_out) {
    VoidBag* found = nullptr;
    EnterCriticalSection(&g_bags_lock);
    for (auto& kv : g_bags)
        if (kv.second->owner == owner) { found = kv.second; *player_out = kv.first; break; }
    LeaveCriticalSection(&g_bags_lock);
    // the object may have been handed to another character since the request went out
    if (found && char_number(*player_out) != owner) return nullptr;
    return found;
}

void on_void_list(const unsigned char* pkt) {
    unsigned owner = *(const unsigned*)(pkt + 9);
    unsigned short err = *(const unsigned short*)(pkt + 0xD);
    unsigned char flags = pkt[0x10];
    unsigned char n = pkt[0x11];
    void* player = nullptr;
    VoidBag* bag = bag_of_char(owner, &player);
    if (!bag) {
        zone::log("bag 18 reply for char %u: no such player here any more - dropped", owner);
        return;
    }
    if (err != kItemListOk) {
        // 0x1202 is what a Character WITHOUT char_void answers. The bag stays unloaded: moves stay refused.
        zone::log("bag 18 reply for char %u: error 0x%04X - bag left unloaded, void moves stay refused", owner, (unsigned)err);
        return;
    }
    if (flags & 1) { clear_bag(bag); bag->loaded = false; }
    if (n) {
        unsigned char count = n;
        zone::fn::ItemBag__ib_Initializetotal()(bag, 0, &count,
            (zone::types::PROTO_ITEMPACKET_TOTAL*)(pkt + 0x12), kVoidBagId);
    }
    zone::log("bag 18 reply for char %u: %u item(s)%s%s", owner, (unsigned)n, (flags & 1) ? ", first" : "",
              (flags & 2) ? ", last" : "");
    if (flags & 2) {
        int items = 0;
        for (const auto& c : bag->cells)
            if (c.iic_Item.iti_itemstruct.itemid != 0xFFFF) items++;
        bag->loaded = true;
        int packets = send_void_list(player, bag);
        zone::log("void bag of char %u LOADED: %d item(s) in %d cells; box 18 sent to the client in %d packet(s)",
                  owner, items, kVoidCapacity, packets);
    }
}

// GameDBSession::gds_NC_CHAR_GET_ITEMLIST_BY_TYPE_ACK(NETCOMMAND*, int): type 18 is ours, the rest go on.
zone::Detour g_list_detour;

void __fastcall list_ack_impl(void* self, void* /*edx*/, unsigned char* pkt, int a2) {
    if (pkt && pkt[8] == kVoidBagId) {
        on_void_list(pkt);
        return;
    }
    typedef void(__fastcall* Orig)(void*, void*, unsigned char*, int);
    ((Orig)g_list_detour.trampoline)(self, 0, pkt, a2);
}

void __declspec(naked) list_ack_thunk() {
    __asm { jmp list_ack_impl }
}

// A login bag arrived. Only the INVENTORY part marks a (re)load of the character: it resets the void bag and
// asks for bag 18. The other parts (equipment, mini-house, action items) leave it alone - clearing on every
// part, as this used to, wiped the bag three more times per login.
zone::Detour g_store_detour;

void __fastcall store_impl(void* self, void* /*edx*/, void* itemcmd) {
    typedef void(__fastcall* Orig)(void*, void*, void*);
    ((Orig)g_store_detour.trampoline)(self, 0, itemcmd);
    const unsigned char* cmd = (const unsigned char*)itemcmd;
    if (!cmd || !(cmd[1] & kPartInventory)) return;
    unsigned charno = char_number(self);
    VoidBag* bag = bag_for(self, true);
    clear_bag(bag);
    bag->loaded = false;
    bag->owner = charno;
    // A character is in the zone once. Any OTHER bag still carrying this character belongs to a player object
    // from an earlier login (bags are kept per object and objects are pooled), and must stop answering to it:
    // the reply is matched by character number, and matching the stale bag loaded the items into it and sent
    // box 18 down the old, closed connection - the new login got nothing (2026-09-19, 13:17 then 14:21).
    EnterCriticalSection(&g_bags_lock);
    for (auto& kv : g_bags)
        if (kv.second != bag && kv.second->owner == charno) {
            zone::log("void bag of player %x let go of char %u (an earlier login of it)", kv.first, charno);
            kv.second->owner = 0;
            kv.second->loaded = false;
        }
    LeaveCriticalSection(&g_bags_lock);
    request_void_list(self, charno);
}

void __declspec(naked) store_thunk() {
    __asm { jmp store_impl }
}

}  // namespace

// ---- a script-visible view -------------------------------------------------------------------------
//
// Registered on every map's Lua state as VoidBagInfo(). Returns the cell count and how many relocations
// have been seen, so the state of this hook can be checked from a quest script or the GM console without
// reading the log file.

static int __cdecl l_void_bag_info(zone::types::lua_State* L) {
    zone::lua::push_int(L, kInventoryCells);
    zone::lua::push_int(L, (int)g_reloc_count);
    return 2;                                   // two return values
}

// ---- watching the script engine ---------------------------------------------------------------------
//
// NPC DIALOGUE IS ALREADY A SCRIPT CALLBACK - there is nothing to build for it. The engine passes
// LuaScriptArgument::LuaArgumentNPCMenu{ NPC, Player, SelectMenu } into script when a player answers a
// dialogue, and LuaArgumentNPCClick{ NPC, Player, String } when one is clicked. So "run a function when a
// given response is sent to a given dialogue" is a script that switches on SelectMenu, not a C++ hook.
//
// This observer exists for the case where you want to see the calls from C++ too - it names every script
// entry point as it happens, which is the fastest way to find out what a map's script is actually called.

// Each script entry point is logged ONCE, the first time it is seen.
//
// It used to log every call, and every log line is written and flushed on the zone's main thread. Measured
// 2026-09-19: zone04 (Elderine, Psiken - script-heavy maps) made 180 script calls a second, the log grew by
// 100,000 lines in 15 minutes, and the main loop spent most of each second waiting on it. Zone logins then
// came out ~1 s per packet and the client gave up at 9 s ("stuck at 0%, then kicked"). zone00 (Bera, a third
// of the load) still coped, which is why it looked like a zone04-only fault. The names are the useful part.
static CRITICAL_SECTION g_seen_lock;
static std::unordered_set<std::string>* g_seen_scripts = nullptr;

static bool on_script_call(zone::types::LuaScript* script, const char* name, void* /*args*/) {
    if (!name) return true;
    bool fresh;
    EnterCriticalSection(&g_seen_lock);
    fresh = g_seen_scripts->insert(name).second;
    LeaveCriticalSection(&g_seen_lock);
    if (fresh) zone::log("script -> %s (state %x) - first call", name, zone::lua::state_of(script));
    return true;                                // true = let it run; false would swallow the call
}

// ---- entry ------------------------------------------------------------------------------------------

ZONEHOOK_PLUGIN("void_bag") {
    // Proof the full CRT really is usable here, which the loader itself cannot do (see build_hook.bat).
    char line[128];
    std::snprintf(line, sizeof(line), "CRT ok - inventory is %d cells of %d bytes",
                  kInventoryCells, (int)sizeof(ItemInventoryCell));
    zone::log("%s", line);

    if (!ZONE_INSTALL_PACKET(NC_ITEM_RELOC_REQ)) {
        zone::log("NC_ITEM_RELOC_REQ hook FAILED - no reloc trace will be produced");
    }
    InitializeCriticalSection(&g_seen_lock);
    g_seen_scripts = new std::unordered_set<std::string>();
    zone::lua::on_function_call(on_script_call);
    zone::hook_function("ChargedItemEffectElement::ciee_Activ",
                        (void*)zone::fn::ChargedItemEffectList__ChargedItemEffectElement__ciee_Activ(),
                        (void*)activ_thunk, &g_activ_detour);
    zone::hook_function("UseItemChargedBuff::uib_CanUseItem",
                        (void*)zone::fn::UseEffect__UseItemChargedBuff__uib_CanUseItem(),
                        (void*)canuse_thunk, &g_canuse_detour);

    // The bag itself. The slot is filled LAST, once everything the cave will reach is ready: the
    // recipe's cave treats a null slot as "no plugin" and takes the zone's default.
    InitializeCriticalSection(&g_bags_lock);
    build_vtable();
    zone::hook_function("ShinePlayer::so_StoreInventoryFromServer",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__so_StoreInventoryFromServer(),
                        (void*)store_thunk, &g_store_detour);
    zone::hook_function("GameDBSession::gds_NC_CHAR_GET_ITEMLIST_BY_TYPE_ACK",
                        (void*)zone::fn::GameDBSession__gds_NC_CHAR_GET_ITEMLIST_BY_TYPE_ACK(),
                        (void*)list_ack_thunk, &g_list_detour);
    zone::hook_function("CItemAuthorityBase::IA_CanInvenReloc",
                        (void*)zone::fn::CItemAuthorityBase__IA_CanInvenReloc(),
                        (void*)ia_thunk, &g_ia_detour);
    zone::ArenaRegion slot = zone::arena_region(".voidreloc");
    if (slot.base && slot.size >= 4) {
        *(void**)slot.base = (void*)void_bag_of;
        zone::log("void bag (id %u, %d cells) registered in the .voidreloc slot at %x",
                  (unsigned)kVoidBagId, kVoidCapacity, slot.base);
    } else {
        zone::log("NO .voidreloc slot: this Zone.exe lacks the void-bag-reloc recipe, so bag 18 stays refused");
    }

    // The Lua function is registered per map, and no map is loaded yet at this point - the zone has not
    // started. Registration therefore has to happen when a state first appears, which is what the script
    // observer above is the hook for. Left explicit rather than pretending it worked here.
    (void)&l_void_bag_info;
    zone::log("up; VoidBagInfo() is not registered yet - see the note in void_bag.cpp");
}
