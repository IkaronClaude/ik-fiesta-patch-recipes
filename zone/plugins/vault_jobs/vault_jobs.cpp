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
//   * a vault that has such rows is REFUSED as a whole to a character who has none of the HIGH JOBS (the operator's
//     rule: a vault with job items opens only once the character has a job; 2026-10-03: "if there are ANY high-class
//     requirements for any class, we allow opening if we are ANY high class, even if our class does not have an item
//     for it in it"). The high jobs are listed in ../9Data/Shine/VaultJobs.txt (written by Fiesta2026on2016
//     migrations-rebalance/0009: every job that has job rows in some vault); without that file only a character
//     whose own job has rows in THIS vault may open it (the rule before). A refusal: the free-slot check reports 0
//     for this one call, so the zone takes its own "fail" path and nothing is made or consumed, and the error becomes
//     0x709, which the 2026 client shows as "Cannot use due to the Class Requirement." (its GetErrMsg 0x4BDBB0).
// Every other row goes through the stock gate unchanged.
#include <zonehook.h>
#include <zone_functions.h>

#include <cstdio>

namespace {

const int kJobBase = 100;                         // ChrClass kJobBase + class id = that one job
const int kJobLast = kJobBase + 127;
const unsigned short kErrClass = 0x709;            // "Cannot use due to the Class Requirement." (2026 client)
const char* kHighJobs = "../9Data/Shine/VaultJobs.txt";
bool g_high[256] = {};                             // class id -> a high job
bool g_have_high = false;                          // the list was read

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
    if (t_open.player == player && t_open.job_rows && !t_open.job_match &&
        !(g_have_high && g_high[player_class(player)])) {
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
        zone::log("vault refused: class %u is not a high job", player_class(player));
    } else if (t_open.job_rows) {
        zone::log("vault opened by class %u (job rows: %s)", player_class(player),
                  t_open.job_match ? "its own" : "none for it - a high job, common rows only");
    }
    t_open = saved;
    return ok;
}

void __declspec(naked) make_thunk() { __asm { jmp make_impl } }
void __declspec(naked) empty_thunk() { __asm { jmp empty_impl } }

}  // namespace

void load_high_jobs() {
    FILE* f = std::fopen(kHighJobs, "r");
    if (!f) {
        zone::log("no %s - only a job with rows in the vault may open it", kHighJobs);
        return;
    }
    char line[128];
    int n = 0;
    while (std::fgets(line, sizeof line, f)) {
        unsigned id = 0;
        if (line[0] != '#' && std::sscanf(line, "%u", &id) == 1 && id < 256) {
            g_high[id] = true;
            n++;
        }
    }
    std::fclose(f);
    g_have_high = n > 0;
    zone::log("high jobs: %d (any of them opens a vault with job rows)", n);
}

ZONEHOOK_PLUGIN("vault_jobs") {
    load_high_jobs();
    zone::hook_function("ShinePlayer::sp_MysteryVaultMakeItem",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__sp_MysteryVaultMakeItem(),
                        (void*)make_thunk, &g_make);
    zone::hook_function("MysteryVaultTable::IsCheckClassType",
                        (void*)zone::fn::MysteryVaultTable__IsCheckClassType(), (void*)check_impl, &g_check);
    zone::hook_function("ShinePlayer::sp_GetEmptyItemInventoryCount",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__sp_GetEmptyItemInventoryCount(),
                        (void*)empty_thunk, &g_empty);
}
