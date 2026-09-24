// vault_jobs - Mystery Vault rows for a specific JOB, not just a class line (Fiesta2026on2016 ticket Q22).
//
// ---- THE STOCK GATE (read from Zone.exe) ----------------------------------------------------------------------
//
//   ShinePlayer::sp_MysteryVaultMakeItem(ItemTotalInformation* vault, unsigned short* err)   0x5658F0
//       walks the vault's MysteryVaultServer rows (a multimap by vault item id); for each one that passes the rate
//       roll it calls, at 0x565AAD,
//   MysteryVaultTable::IsCheckClassType(ChrClassType row, unsigned char base)                 0x5C82E0
//       base = the player's BASE class (vtable+0x4DC: 1/6/11/16/21/26); row 0..5 = that base class, 6 = everyone,
//       anything else logs an error and fails. The rows that pass go into a vector; then
//         empty vector                                   -> *err = 0x724, fail
//         sp_GetEmptyItemInventoryCount() < rows (0x565B6F) -> *err = 0x723 "Inventory full", fail
//       and otherwise every item is made.
//
// A row can only name a class LINE, so a level-100 weapon (Gladiator vs Knight, ...) cannot go to the right job.
//
// ---- THIS PLUGIN ------------------------------------------------------------------------------------------------
//
//   * a row whose ChrClass is kJobBase + class id (101..127, the ClassName ids) passes only when the player's
//     CURRENT class (ShinePlayer::so_GetClass 0x5598C0) is that class;
//   * a vault that has such rows but none for the player's current class is REFUSED as a whole (the operator's
//     rule: a vault with job items opens only once the character has the job) - the free-slot check reports 0 for
//     this one call, so the zone takes its own "fail" path and nothing is made or consumed, and the error becomes
//     0x709, which the 2026 client shows as "Cannot use due to the Class Requirement." (its GetErrMsg 0x4BDBB0).
// Every other row goes through the stock gate unchanged.
#include <zonehook.h>
#include <zone_functions.h>

namespace {

const int kJobBase = 100;                         // ChrClass kJobBase + class id = that one job
const int kJobLast = kJobBase + 127;
const unsigned short kErrClass = 0x709;            // "Cannot use due to the Class Requirement." (2026 client)

struct Open {                                      // the vault being opened on this thread
    void* player = nullptr;
    bool job_rows = false;                         // it has rows for a specific job
    bool job_match = false;                        // one of them is the player's job
    bool refused = false;
};
thread_local Open t_open;

zone::Detour g_make, g_check, g_empty;

unsigned char player_class(void* player) {
    auto get = zone::fn::ShineObjectClass__ShinePlayer__so_GetClass();
    return player ? get(player, 0) : 0;
}

bool __cdecl check_impl(int row, unsigned char base) {
    if (t_open.player && row > kJobBase && row <= kJobLast) {
        const unsigned char cls = player_class(t_open.player);
        t_open.job_rows = true;
        if (cls == row - kJobBase) {
            t_open.job_match = true;
            return true;
        }
        return false;
    }
    typedef bool(__cdecl * Orig)(int, unsigned char);
    return ((Orig)g_check.trampoline)(row, base);
}

int __fastcall empty_impl(void* player, void*) {
    typedef int(__fastcall * Orig)(void*, void*);
    if (t_open.player == player && t_open.job_rows && !t_open.job_match) {
        t_open.refused = true;
        return 0;                                  // the zone's own "not enough room" fail: nothing is made
    }
    return ((Orig)g_empty.trampoline)(player, 0);
}

unsigned char __fastcall make_impl(void* player, void*, void* vault, unsigned short* err) {
    typedef unsigned char(__fastcall * Orig)(void*, void*, void*, unsigned short*);
    const Open saved = t_open;
    t_open = Open();
    t_open.player = player;
    unsigned char ok = ((Orig)g_make.trampoline)(player, 0, vault, err);
    if (t_open.refused) {
        if (err) *err = kErrClass;
        zone::log("vault refused: class %u has no job among the vault's job rows", player_class(player));
    } else if (t_open.job_rows) {
        zone::log("vault opened by class %u (job rows: matched)", player_class(player));
    }
    t_open = saved;
    return ok;
}

void __declspec(naked) make_thunk() { __asm { jmp make_impl } }
void __declspec(naked) empty_thunk() { __asm { jmp empty_impl } }

}  // namespace

ZONEHOOK_PLUGIN("vault_jobs") {
    zone::hook_function("ShinePlayer::sp_MysteryVaultMakeItem",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__sp_MysteryVaultMakeItem(),
                        (void*)make_thunk, &g_make);
    zone::hook_function("MysteryVaultTable::IsCheckClassType",
                        (void*)zone::fn::MysteryVaultTable__IsCheckClassType(), (void*)check_impl, &g_check);
    zone::hook_function("ShinePlayer::sp_GetEmptyItemInventoryCount",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__sp_GetEmptyItemInventoryCount(),
                        (void*)empty_thunk, &g_empty);
}
