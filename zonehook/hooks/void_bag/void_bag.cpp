// void_bag - the extra inventory (bag 18), as a hook DLL.
//
// STATUS: instrumentation, not the feature. It watches and reports; it does not yet grant a bag.
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

#include <cstdio>          // proving the full CRT is available in a plugin

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

static bool on_script_call(zone::types::LuaScript* script, const char* name, void* /*args*/) {
    zone::log("script -> %s (state %x)", name ? name : "?", zone::lua::state_of(script));
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
    zone::lua::on_function_call(on_script_call);
    zone::hook_function("ChargedItemEffectElement::ciee_Activ",
                        zone::rebase(zone::fn::kVa_ChargedItemEffectList__ChargedItemEffectElement__ciee_Activ),
                        (void*)activ_thunk, &g_activ_detour);

    // The Lua function is registered per map, and no map is loaded yet at this point - the zone has not
    // started. Registration therefore has to happen when a state first appears, which is what the script
    // observer above is the hook for. Left explicit rather than pretending it worked here.
    (void)&l_void_bag_info;
    zone::log("up; VoidBagInfo() is not registered yet - see the note in void_bag.cpp");
}
