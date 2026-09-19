// void_bag - the extra inventory (bag 18), as a hook DLL.
//
// STATUS: bag 18 exists in the zone and items move in and out of it within a session (with the
// void-bag-reloc recipe). NOT YET PERSISTED: the Character side - saving the move and loading bag 18
// at login - is the next piece.
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
// ---- NEXT, in order --------------------------------------------------------------------------------
//   1. Find how an existing bag expansion persists its unlock, and mirror it. The spec says "like the
//      bags do", and the server's own mechanism is the one to copy - do not invent a flag.
//   2. Add the subclass. Its cell array and the id 18 are a RECIPE (a constant and a vtable), not a
//      runtime patch: reviewable and verifiable in a way a DLL rewriting bytes is not.
//   3. Persistence is S2S - see docs/HOOK-TARGETS.md. A bag that does not survive a relog is not a bag.
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
    using Box = zone::types::ChargedItemEffectDataBox_ChargedItemEffect_;
    auto* box = (const Box*)zone::rebase(zone::kVaChargedBuffDataBox);
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
    void** inv_vt = (void**)zone::rebase(zone::kVaItemInventoryVtable);
    g_vtable[0] = inv_vt[-1];
    g_vtable[1] = zone::rebase(zone::fn::kVa_ItemRewardStorage__ib_GetInventoryCell);  // the shared one
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
        clear_bag(bag);
        g_bags[player] = bag;
    }
    LeaveCriticalSection(&g_bags_lock);
    return bag;
}

// What the recipe's cave calls: ItemBag* __cdecl (ShinePlayer*). Null would make the move take the
// zone's default - refused, exactly as without the recipe.
extern "C" void* __cdecl void_bag_of(void* player) {
    return player ? bag_for(player, true) : nullptr;
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

// A character is being loaded into this player object: whatever the bag held belonged to someone else.
zone::Detour g_store_detour;

void __fastcall store_impl(void* self, void* /*edx*/, void* itemcmd) {
    typedef void(__fastcall* Orig)(void*, void*, void*);
    ((Orig)g_store_detour.trampoline)(self, 0, itemcmd);
    if (VoidBag* bag = bag_for(self, false)) {
        clear_bag(bag);
        zone::log("void bag of player %x cleared for a newly loaded character", self);
    }
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
                        zone::rebase(zone::fn::kVa_ChargedItemEffectList__ChargedItemEffectElement__ciee_Activ),
                        (void*)activ_thunk, &g_activ_detour);
    zone::hook_function("UseItemChargedBuff::uib_CanUseItem",
                        zone::rebase(zone::fn::kVa_UseEffect__UseItemChargedBuff__uib_CanUseItem),
                        (void*)canuse_thunk, &g_canuse_detour);

    // The bag itself. The slot is filled LAST, once everything the cave will reach is ready: the
    // recipe's cave treats a null slot as "no plugin" and takes the zone's default.
    InitializeCriticalSection(&g_bags_lock);
    build_vtable();
    zone::hook_function("ShinePlayer::so_StoreInventoryFromServer",
                        zone::rebase(zone::fn::kVa_ShineObjectClass__ShinePlayer__so_StoreInventoryFromServer),
                        (void*)store_thunk, &g_store_detour);
    zone::hook_function("CItemAuthorityBase::IA_CanInvenReloc",
                        zone::rebase(zone::fn::kVa_CItemAuthorityBase__IA_CanInvenReloc),
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
