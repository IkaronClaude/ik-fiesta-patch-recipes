// quest_drop_max - a quest drop can give its CountMax: a server bug fix for every product (Fiesta2026on2016, operator
// 2026-10-01: "Can you just fix the zone instead?" / "this should be in base 2026 ... We are just fixing a bug in the server").
//
// The quest drop roll (CQuestZone::QuestActionMobKill, Zone.exe 0x5BD23F..0x5BD271), esi = the QUEST_ACTION:
//
//     005BD249  call well512_GetRandom(1000000)          ; eax = r, 0 <= r < 1,000,000
//     005BD24E  8B 8E D8 00 00 00  mov  ecx, [esi+0xD8]  ; CountMin
//     005BD254  8B 96 DC 00 00 00  mov  edx, [esi+0xDC]  ; CountMax
//     005BD25A  2B D1              sub  edx, ecx         ; Max - Min
//     005BD25C  0F AF D0           imul edx, eax
//     005BD25F  B8 E9 E2 1B 43     mov  eax, 0x431BE2E9  ; ... >> 18 = / 1,000,000
//     ...       add esi, ecx                             ; Min + floor((Max - Min) * r / 1e6), then clamped to what is still needed
//
// r < 1e6, so the floor never reaches Max - Min: a 1-2 drop always gave 1 (the operator never saw a 2). The 5 bytes at
// 0x5BD25A become a jmp to a thunk doing sub / inc / imul: Min + floor((Max - Min + 1) * r / 1e6) - uniform over Min..Max.
// Min == Max still gives Min (floor(r / 1e6) = 0).
#include <zonehook.h>

#include <windows.h>

namespace {

const unsigned kVaSite = 0x005BD25Au;
const unsigned kVaBack = 0x005BD25Fu;
const unsigned char kStock[5] = {0x2B, 0xD1, 0x0F, 0xAF, 0xD0};     // sub edx, ecx ; imul edx, eax

unsigned char* g_thunk = nullptr;

}  // namespace

ZONEHOOK_PLUGIN("quest_drop_max") {
    unsigned char* site = (unsigned char*)zone::rebase(kVaSite);
    if (memcmp(site, kStock, sizeof kStock) != 0) {
        zone::log("quest_drop_max: unexpected bytes %02X %02X %02X %02X %02X at 0x5BD25A - NOT patched",
                  site[0], site[1], site[2], site[3], site[4]);
        return;
    }
    // thunk: sub edx, ecx ; inc edx ; imul edx, eax ; jmp back
    g_thunk = (unsigned char*)VirtualAlloc(nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_thunk) {
        zone::log("quest_drop_max: VirtualAlloc failed - NOT patched");
        return;
    }
    unsigned char* t = g_thunk;
    *t++ = 0x2B; *t++ = 0xD1;                 // sub  edx, ecx
    *t++ = 0x42;                              // inc  edx
    *t++ = 0x0F; *t++ = 0xAF; *t++ = 0xD0;    // imul edx, eax
    unsigned char* back = (unsigned char*)zone::rebase(kVaBack);
    *t = 0xE9;                                // jmp  back
    *(int*)(t + 1) = (int)(back - (t + 5));
    FlushInstructionCache(GetCurrentProcess(), g_thunk, 32);

    DWORD old;
    VirtualProtect(site, 5, PAGE_EXECUTE_READWRITE, &old);
    site[0] = 0xE9;                           // jmp thunk (exactly the 5 replaced bytes)
    *(int*)(site + 1) = (int)(g_thunk - (site + 5));
    VirtualProtect(site, 5, old, &old);
    FlushInstructionCache(GetCurrentProcess(), site, 5);
    zone::log("quest_drop_max: quest drops roll Min..Max inclusive (thunk at %p)", g_thunk);
}
