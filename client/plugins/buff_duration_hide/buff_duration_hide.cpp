// buff_duration_hide - a buff whose remaining time is absurd (more than 10,000 hours: the permanent-style premium
// abstates) shows its name alone in the buff icon tooltip, without "Duration Time: 99999 Hours ..." (Fiesta2026on2016
// ticket P5, operator 2026-10-05: "hide the 'Duration Time:' line in the buff tooltip for premium buffs whose runtime
// exceeds 10,000 hours").
//
// ---- THE STOCK CODE (2026 Fiesta.exe, 10.6.4 reference addresses, read 2026-10-06) -----------------------------------------
//   Three sites build a buff icon's tooltip the same way:
//     time  = BuffDurationText(this, buf, entry)       0x5DC0B0, thiscall, ret 8: remaining time as text into buf
//               (end = BuffEndTime(entry + 0xA) 0x5DE580 -> __int64; minus the server clock as mktime)
//     label = TextData 0xF5F0D2B5 "Duration Time"
//     text  = <va-format helper>("%s\n\n%s: %s", entry + 0x46 (name), label, time)    call at BuffTipFormat1/2/3
//     tooltip control SetText(text)
//
// ---- THIS PLUGIN ---------------------------------------------------------------------------------------------------------
//   BuffDurationText is wrapped: after it ran, an entry ending more than kHideHours from now marks its buffer. The three
//   format calls are pointed at fmt_wrap, which formats the name alone for a marked buffer and calls the stock helper
//   unchanged otherwise. The clock is this PC's (the stock text uses the server's) - irrelevant at a 10,000-hour threshold.
#include <hook_core.h>
#include <client_addrs.h>

#include <windows.h>

#include <cstring>
#include <ctime>

namespace {

const long long kHideHours = 10000;
const unsigned kEntryEndOff = 0xA;
const unsigned char kStockText[5] = {0x55, 0x8B, 0xEC, 0x81, 0xEC};   // push ebp ; mov ebp, esp ; sub esp, imm32

hook::Detour g_text;
typedef const char*(__cdecl* FormatFn)(const char*, ...);
FormatFn g_format = nullptr;                 // the stock va-format helper the three sites call
const char* g_hidden = nullptr;              // the time buffer of the entry being built, when it is "permanent"

typedef char*(__fastcall* TextFn)(void* self, void* edx, char* buf, void* entry);
typedef long long(__fastcall* EndFn)(void* end_field, void* edx);

char* __fastcall text_impl(void* self, void* /*edx*/, char* buf, void* entry) {
    char* out = ((TextFn)g_text.trampoline)(self, 0, buf, entry);
    g_hidden = nullptr;
    __try {
        if (entry) {
            long long end = ((EndFn)hook::rebase(caddr::va(caddr::kBuffEndTime)))((char*)entry + kEntryEndOff, 0);
            long long left = end - (long long)_time64(nullptr);
            if (left > kHideHours * 3600) g_hidden = out;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_hidden = nullptr;
    }
    return out;
}

const char* __cdecl fmt_wrap(const char* fmt, const char* name, const char* label, const char* time) {
    if (g_hidden && time == g_hidden) {
        g_hidden = nullptr;
        return g_format("%s", name);
    }
    return g_format(fmt, name, label, time);
}

// the call at `va` must be E8 rel32 to the same helper as the others (learned into g_format)
bool check_site(unsigned va) {
    unsigned char* at = (unsigned char*)hook::rebase(va);
    if (at[0] != 0xE8) return false;
    FormatFn target = (FormatFn)(at + 5 + *(int*)(at + 1));
    if (g_format && target != g_format) return false;
    g_format = target;
    return true;
}

bool patch(unsigned va) {
    unsigned char* at = (unsigned char*)hook::rebase(va);
    unsigned char code[5] = {0xE8};
    int rel = (int)((unsigned char*)fmt_wrap - (at + 5));
    std::memcpy(code + 1, &rel, 4);
    return hook::write_code(at, code, 5);
}

}  // namespace

HOOK_PLUGIN("buff_duration_hide") {
    if (const char* m = caddr::missing({caddr::kBuffDurationText, caddr::kBuffEndTime, caddr::kBuffTipFormat1,
                                        caddr::kBuffTipFormat2, caddr::kBuffTipFormat3})) {
        hook::log("buff_duration_hide: %s - not hooked", m);
        return;
    }
    const unsigned sites[3] = {caddr::va(caddr::kBuffTipFormat1), caddr::va(caddr::kBuffTipFormat2),
                               caddr::va(caddr::kBuffTipFormat3)};
    for (unsigned va : sites) {
        if (!check_site(va)) {
            hook::log("buff_duration_hide: the tooltip format call at 0x%X is not the expected one - stock tooltips", va);
            return;
        }
    }
    unsigned char* text = (unsigned char*)hook::rebase(caddr::va(caddr::kBuffDurationText));
    if (std::memcmp(text, kStockText, sizeof kStockText) != 0) {
        hook::log("buff_duration_hide: unexpected bytes at BuffDurationText - stock tooltips");
        return;
    }
    if (!hook::hook_function("BuffDurationText", text, (void*)text_impl, &g_text)) return;
    int n = 0;
    for (unsigned va : sites) n += patch(va) ? 1 : 0;
    hook::log("buff_duration_hide: %d of 3 buff tooltip sites show only the name past %lld hours", n, kHideHours);
}
