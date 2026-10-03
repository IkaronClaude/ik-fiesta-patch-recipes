// minimon_pickup_keep - equipping a mini pet no longer switches auto-pickup back on (operator 2026-09-29: "equipping auto
// minimon reenables auto PICKUP even if previously disabled").
//
// ---- THE STOCK CODE (2026 Fiesta.exe, read 2026-09-29) -------------------------------------------------------------------
//   Wire: C 0x300F equip -> S 0x3011 0x0281 -> 26 ms later the client sends 0x10BC 01 (auto-pick ON) on its own; the zone
//   only acks. The 0x10BC comes from the UI message 0xFD: the window dispatcher at 0x5790C8 (case = msg - 9, table
//   0x57BB8C, entry 244 -> 0x57B874) sends 0x10BC with value (wParam == 1). The manual toggle posts 0xFD with its
//   checkbox state (0x62D175 / 0x62FBA2); the pet refresh after an equip change posts it with a hard-coded 1:
//     0x586646..  for each equipped mini pet, MinimonInfo role ([rec+0x24]): 1 pickup -> bl = 1, 2 auto-use -> flag
//     0x586678    test bl, bl / je 0x58668E
//     0x58667C    push 0 / push 1 / push 0xFD / mov ecx, esi / call 0x874AE0 (post) / jmp 0x5866A7
//     0x5866A7    [[esi+0x304] + 0x699] = bl                      "a pickup pet is equipped", kept by the window
//   So ANY mini-pet change while a pickup pet is worn forces auto-pickup on, whatever the player chose.
//
// ---- THIS PLUGIN ---------------------------------------------------------------------------------------------------------
//   The post at 0x58667C is made only when [[esi+0x304]+0x699] is still 0, i.e. a pickup pet has just appeared (the stock
//   convenience: equipping your first pickup pet turns pickup on). With one already worn, the player's own setting stays.
#include <hook_core.h>
#include <client_addrs.h>

#include <cstring>

namespace {

const unsigned kVaSite = caddr::va(caddr::kMinimonPickupSite);           // test bl,bl; je; push 0; push 1; push 0xFD; mov ecx,esi; call; jmp
const unsigned kVaPost = caddr::va(caddr::kWindowPostMessage);           // the window's post-message call (thiscall, 3 args)
const unsigned kVaAfter = caddr::va(caddr::kMinimonPickupAfter);          // mov eax,[esi+0x304] - where the stock post path continues
const unsigned char kSite[] = {0x84, 0xDB, 0x74, 0x12, 0x6A, 0x00, 0x6A, 0x01, 0x68, 0xFD, 0x00, 0x00, 0x00,
                               0x8B, 0xCE, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x19};   // call rel32 (16..19): to WindowPostMessage
const int kSiteCallRel = 16;
const unsigned kOffWin = 0x304;
const unsigned kOffHasPickup = 0x699;

void* g_post = nullptr;
void* g_after = nullptr;
unsigned g_kept = 0;

__declspec(naked) void post_if_new() {
    __asm {
        mov eax, [esi + kOffWin]
        test eax, eax
        je post
        cmp byte ptr [eax + kOffHasPickup], 0
        jne kept
    post:
        push 0
        push 1
        push 0xFD
        mov ecx, esi
        call g_post
        jmp g_after
    kept:
        inc g_kept
        jmp g_after
    }
}

}  // namespace

HOOK_PLUGIN("minimon_pickup_keep") {
    if (const char* m = caddr::missing({caddr::kMinimonPickupSite, caddr::kWindowPostMessage, caddr::kMinimonPickupAfter})) {
        hook::log("minimon_pickup_keep: %s - not hooked", m);
        return;
    }
    unsigned char* site = (unsigned char*)hook::rebase(kVaSite);
    const int call_end = kSiteCallRel + 4;
    if (std::memcmp(site, kSite, kSiteCallRel) || std::memcmp(site + call_end, kSite + call_end, sizeof kSite - call_end) ||
        site + call_end + *(const int*)(site + kSiteCallRel) != (unsigned char*)hook::rebase(kVaPost)) {
        hook::log("minimon_pickup_keep: the pet refresh is not the expected code - stock behaviour");
        return;
    }
    g_post = hook::rebase(kVaPost);
    g_after = hook::rebase(kVaAfter);
    unsigned char* at = site + 4;                 // the post: push 0 (2) + push 1 (2) + push 0xFD (5) ...
    unsigned char jmp[5] = {0xE9, 0, 0, 0, 0};
    int rel = (int)((unsigned char*)&post_if_new - (at + 5));
    std::memcpy(jmp + 1, &rel, 4);
    if (hook::write_code(at, jmp, sizeof jmp))
        hook::log("minimon_pickup_keep: equipping a mini pet keeps the auto-pickup setting (post at %p)", at);
}
