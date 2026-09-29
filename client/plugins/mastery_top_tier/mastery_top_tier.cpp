// mastery_top_tier - the production window shows "( 150000 )" at the top mastery tier instead of "( 150000/1907359904 )"
// (operator 2026-09-29 P5).
//
// ---- THE STOCK CODE (2026 Fiesta.exe, ProductionWin, read 2026-09-29) -------------------------------------------------------
//   0x690CDF  mastery = 0x692750(type)                               -> [ebp-0xC]
//   0x690CE9  tier    = 0x6928F0(type, mastery); edi = tier + 1
//   0x690D05  rec     = 0x48F560(type)          (the ProduceView row: tiers MasteryExp, Undefined0..3 = 5 dwords at +0x86)
//   0x690D16  [ebp-8] = rec[+0x86 + edi*4]     THE NEXT TIER - at the top tier (index 4) edi = 5 reads past the row
//   0x690D52  push [ebp-8]; push [ebp-0xC]; ...; push "( %d/%d )"; sprintf
//
// ---- THIS PLUGIN --------------------------------------------------------------------------------------------------------
//   At 0x690D16: an index past the last tier stores NO_NEXT instead of reading. At the format push 0x690D5A: NO_NEXT picks
//   "( %d )" (the extra pushed argument is ignored; the caller cleans the stack as before).
#include <hook_core.h>

#include <cstring>

namespace {

const unsigned kVaRead = 0x00690D16u;        // mov eax,[eax+edi*4+0x86]; mov [ebp-8],eax   (10 bytes)
const unsigned kVaReadBack = 0x00690D20u;
const unsigned kVaFormat = 0x00690D5Au;      // push 0xB31E68 "( %d/%d )"                   (5 bytes)
const unsigned kVaFormatBack = 0x00690D5Fu;
const unsigned char kRead[] = {0x8B, 0x84, 0xB8, 0x86, 0x00, 0x00, 0x00, 0x89, 0x45, 0xF8};
const unsigned char kFormat[] = {0x68, 0x68, 0x1E, 0xB3, 0x00};
const unsigned kTiers = 5;                   // ProduceView's tier columns (MasteryExp + Undefined0..3)
const unsigned kNoNext = 0xFFFFFFFFu;

void* g_read_back = nullptr;
void* g_format_back = nullptr;
void* g_stock_format = nullptr;
const char kSingle[] = "( %d )";
const char* g_single = kSingle;

__declspec(naked) void read_next() {
    __asm {
        cmp  edi, 5                           // kTiers
        jae  top
        mov  eax, [eax + edi * 4 + 0x86]
        mov  [ebp - 8], eax
        jmp  g_read_back
    top:
        mov  dword ptr [ebp - 8], -1          // kNoNext
        jmp  g_read_back
    }
}

__declspec(naked) void pick_format() {
    __asm {
        cmp  dword ptr [ebp - 8], -1          // kNoNext
        je   single
        push dword ptr [g_stock_format]
        jmp  g_format_back
    single:
        push dword ptr [g_single]
        jmp  g_format_back
    }
}

bool jump(unsigned va, void* to, int len) {
    unsigned char code[16];
    unsigned char* at = (unsigned char*)hook::rebase(va);
    code[0] = 0xE9;
    int rel = (int)((unsigned char*)to - (at + 5));
    std::memcpy(code + 1, &rel, 4);
    for (int i = 5; i < len; ++i) code[i] = 0x90;
    return hook::write_code(at, code, len);
}

}  // namespace

HOOK_PLUGIN("mastery_top_tier") {
    if (std::memcmp(hook::rebase(kVaRead), kRead, sizeof kRead) || std::memcmp(hook::rebase(kVaFormat), kFormat, sizeof kFormat)) {
        hook::log("mastery_top_tier: the production window code is not the expected one - stock display");
        return;
    }
    g_read_back = hook::rebase(kVaReadBack);
    g_format_back = hook::rebase(kVaFormatBack);
    g_stock_format = hook::rebase(0x00B31E68u);
    if (jump(kVaRead, (void*)read_next, sizeof kRead) && jump(kVaFormat, (void*)pick_format, sizeof kFormat))
        hook::log("mastery_top_tier: the top production tier shows the mastery alone");
}
