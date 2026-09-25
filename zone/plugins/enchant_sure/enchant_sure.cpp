// enchant_sure - enhancing never fails when the server data asks for it (Fiesta2026on2016 Rebalanced, ticket Q46).
//
// The roll (Item_Upgrade, Zone.exe 0x53CD2C..0x53D024): threshold = CriFail + DownFail + NormalFail - (nCon x stones
// + bonuses) from the ItemUpgrade / AccUpgrade record, clamped at 0 for item type 38 and for grade >= 6 records that
// use NormalFail alone (the jns at 0x53CFF8 / the mov edi, ebx at 0x53D020); then
//
//     0053D022  3B C7              cmp eax, edi         ; eax = random(1000), edi = threshold
//     0053D024  0F 8F FD 00 00 00  jg  0x53D127         ; success
//
// Rebalanced zeroes every fail weight, so the threshold is <= 0 - but where it is clamped to 0 a roll of exactly 0
// still fails (1 in 1000, the harmless "no change" kind). jg -> jge closes that. The exe is shared by all three
// products (the parity port keeps official odds), so the byte is only patched when the server data carries the flag
// file the Rebalanced layer ships (migrations-rebalance/0015-enchant-flag.py -> 9Data/Shine/EnchantAlwaysSucceeds.flag).
// With every weight 0 no other roll changes: jge differs from jg only when roll == threshold, i.e. threshold 0.
#include <zonehook.h>

#include <windows.h>

namespace {

const char* kFlag = "../9Data/Shine/EnchantAlwaysSucceeds.flag";
const unsigned kVaJcc = 0x0053D025u;        // second byte of 0F 8F (jg rel32)
const unsigned char kJg = 0x8F, kJge = 0x8D;

}  // namespace

ZONEHOOK_PLUGIN("enchant_sure") {
    if (GetFileAttributesA(kFlag) == INVALID_FILE_ATTRIBUTES) {
        zone::log("enchant_sure: no %s - enchant odds unchanged", kFlag);
        return;
    }
    unsigned char* p = (unsigned char*)zone::rebase(kVaJcc);
    if (*p != kJg || p[-1] != 0x0F) {
        zone::log("enchant_sure: unexpected bytes %02X %02X at 0x53D024 - NOT patched", p[-1], *p);
        return;
    }
    DWORD old;
    VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &old);
    *p = kJge;
    VirtualProtect(p, 1, old, &old);
    FlushInstructionCache(GetCurrentProcess(), p, 1);
    zone::log("enchant_sure: %s present - the enchant roll succeeds on a clamped 0 threshold (jg -> jge)", kFlag);
}
