// minimon_sort - sorting the inventory no longer switches the mini pet's auto-buff off (operator 2026-09-27: "Sorting
// inventory deactivates auto buff").
//
// ---- THE STOCK BEHAVIOUR (read from Zone.exe + the bridge log of the operator's sort, 2026-09-27 11:55:57) ----------
//   NC_ITEM_AUTO_ARRANGE_INVEN_REQ (0x304A) starts an asynchronous sort: so_ply_SetArrangeInven(1) (0x560DC0) loads a
//   counter at player+0x2AB18 with 0xC0, one per inventory cell, and the sort then swaps cells over several
//   round trips (a stream of NC_ITEM_CELLCHANGE pairs); so_ply_IsArrangeInven (0x560DB0) = counter != 0.
//   Every time an item leaves its cell, ShinePlayer::so_ply_UseItemMinimon_SlotItemCheck(itemid) (0x564C90, virtual)
//   checks the auto-use slots: mid-swap the item is momentarily in no cell, so the check sees it "used up", sends
//   NC_CHAR_USEITEM_MINIMON_NOTICE_CMD (0x112D, 0x3648) and clears that slot. After the last slotted item the list is
//   empty and the server switches auto-buff off (NC_CHAR_USEITEM_MINIMON_NORMAL_ITEM_OFF_ACK 0x1127).
//
// ---- THIS PLUGIN ---------------------------------------------------------------------------------------------------
// While a sort is in progress the check is skipped. A sort only moves items - every slotted item is still in the bag
// when it ends - so nothing needs re-checking afterwards; an item really used up is checked on its next move as
// before. Parity-neutral (a sort never meant to turn auto-buff off), so not flag-gated.
#include <zonehook.h>
#include <zone_functions.h>

namespace {

zone::Detour g_check;

void __fastcall slot_item_check(void* player, void*, unsigned short item) {
    typedef int(__fastcall * IsArrangeInven)(void*, void*);
    if (((IsArrangeInven)zone::rebase(0x00560DB0u))(player, nullptr)) return;   // mid-sort: the item is only moving
    ((void(__fastcall*)(void*, void*, unsigned short))g_check.trampoline)(player, nullptr, item);
}

}  // namespace

ZONEHOOK_PLUGIN("minimon_sort") {
    zone::hook_function("ShinePlayer::so_ply_UseItemMinimon_SlotItemCheck 0x564C90 (skipped while the inventory sorts)",
                        zone::rebase(0x00564C90u), (void*)slot_item_check, &g_check);
}
