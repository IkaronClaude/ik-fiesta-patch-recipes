// minimon_keep - an auto-use mini pet keeps a slot whose scroll / potion ran out, and uses it again once the player has
// that item again (operator 2026-09-27 P3 [QoL]: "remember the item of an emptied slot and re-bind it to the next stack").
//
// ---- THE STOCK CODE (read from Zone.exe + Zone.pdb) --------------------------------------------------------------------
//   The pet's 12 normal + 12 charged slots hold ITEM IDS. A slot is cleared - and the client told, and after the last one
//   auto-use switched off - by sp_UseItemMinimon_NormalSlotClear (0x563F60) / ChargedSlotClear (0x564150), called from
//   exactly two "used up" paths and nowhere else (checked: every call site in the exe):
//     so_ply_UseItemMinimon_SlotItemCheck 0x564C90   an item left its cell and ib_GetItemLot(id) == 0
//     sp_UseItemMinimon_Normal/ChargedRoutine        the periodic use: sp_FindItemFromInventory(id) found nothing
//   The routine skips a slot whose item it cannot find (and would only call the clear again), so a kept slot is safe:
//   the pet passes over it until a stack of that id is back, then uses it. The slots already persist (DB) as ids.
//
// ---- THIS PLUGIN -------------------------------------------------------------------------------------------------------
//   Both clears return without clearing - but only when 9Data/Shine/MinimonKeepSlots.flag exists (the QoL layer ships
//   it; parity keeps the stock clearing). The player's own slot edits (NC_CHAR_USEITEM_MINIMON_*_ON_REQ) are untouched.
#include <zonehook.h>

namespace {

const unsigned kVaNormalClear = 0x00563F60u;     // ShinePlayer::sp_UseItemMinimon_NormalSlotClear(u8 slot), thiscall
const unsigned kVaChargedClear = 0x00564150u;    // ShinePlayer::sp_UseItemMinimon_ChargedSlotClear(u8 slot)
const char* kFlag = "../9Data/Shine/MinimonKeepSlots.flag";

zone::Detour g_normal, g_charged;
unsigned g_kept = 0;

void __fastcall normal_clear(void* player, void*, unsigned char slot) {
    ++g_kept;                                    // kept: the item comes back into use when the player has it again
    zone::log("minimon_keep: normal slot %u of player %p used up - kept (stock would clear it) [%u kept]", slot, player, g_kept);
}

void __fastcall charged_clear(void* player, void*, unsigned char slot) {
    ++g_kept;
    zone::log("minimon_keep: charged slot %u of player %p used up - kept (stock would clear it) [%u kept]", slot, player, g_kept);
}

}  // namespace

ZONEHOOK_PLUGIN("minimon_keep") {
    if (GetFileAttributesA(kFlag) == INVALID_FILE_ATTRIBUTES) {
        zone::log("minimon_keep: no %s - an emptied auto-use slot is cleared (stock)", kFlag);
        return;
    }
    zone::hook_function("ShinePlayer::sp_UseItemMinimon_NormalSlotClear 0x563F60 (emptied slots are kept)",
                        zone::rebase(kVaNormalClear), (void*)normal_clear, &g_normal);
    zone::hook_function("ShinePlayer::sp_UseItemMinimon_ChargedSlotClear 0x564150 (emptied slots are kept)",
                        zone::rebase(kVaChargedClear), (void*)charged_clear, &g_charged);
    zone::log("minimon_keep: %s - an auto-use pet keeps the slot of a used-up item and uses it again once restocked", kFlag);
}
