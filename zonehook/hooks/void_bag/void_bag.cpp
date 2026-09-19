// void_bag - the extra inventory, as a hook DLL.
//
// STATUS: this is the INSTRUMENTATION stage, not the feature. It watches and reports; it does not yet
// grant a bag. Everything below that says "observed" was read off the wire or out of the zone at runtime;
// everything under NEXT is still a plan. Read the log before believing any of it.
//
// WHAT THE FEATURE NEEDS, and what is already known:
//
//   the inventory exists      ItemInventory is a flat ItemInventoryCell[192] (verified: zone_types.h
//                             asserts sizeof 22276 = 4 + 192*116 against the binary). "Bags" are ranges
//                             inside that one array, not separate objects - so a new bag is a question of
//                             which indices are addressable, not of allocating anything.
//   the bag ids the zone
//   accepts                   ib_GetInvenType returns 0, 1, 3, 4, 6, 7, 8, 9, 12 in this build
//                             (disassembled earlier). 18 is NOT among them, which is why the 2026 client's
//                             bag 18 goes nowhere: the server rejects the id before any slot maths runs.
//   moving items              NC_ITEM_RELOC_REQ carries two ITEM_INVEN u16 of (inven << 10) | slot. That is
//                             the packet a bag is used through, and the one hooked below.
//
// NEXT, in order:
//   1. Confirm from the log which (inven, slot) pairs a real 2026 client actually sends for bag 18 and
//      bag 15 - the reloc trace below is there to answer exactly that.
//   2. Widen ib_GetInvenType to accept the new id. That is a binpatch (a recipe), not a hook: it is a
//      switch in the middle of a function, and patching a jump table from a DLL is worse than declaring
//      the change in a recipe where it is reviewable.
//   3. Only then decide whether anything here needs to stay.
//
// Bag 15 is deliberately NOT assumed to be "more slots". The operator's reading is that 18 is the extra
// space and 15 is something else, and nothing observed so far contradicts or confirms that.
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

    // The Lua function is registered per map, and no map is loaded yet at this point - the zone has not
    // started. Registration therefore has to happen when a state first appears, which is what the script
    // observer above is the hook for. Left explicit rather than pretending it worked here.
    (void)&l_void_bag_info;
    zone::log("up; VoidBagInfo() is not registered yet - see the note in void_bag.cpp");
}
