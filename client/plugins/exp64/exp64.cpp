// exp64 - the 2026 client takes EXP gains as 64 bits (ticket Q32). Pairs with the zone recipe exp-gain-u64.
//
// The zone (exp-gain-u64) sends NC_BAT_EXPGAIN 0x240B as {u32 low, u16 handle, u32 high} for every gain, so a
// quest reward past 2^32 arrives in one packet. The stock 2026 client (Fiesta.exe) reads the first 6 bytes:
//
//   case 0x58F6A7    new(0x18); ctor 0x73F050(this, a1, payload): payload u32 -> +0x10, u16 handle -> +0x14 / +8
//   handler 0x73F0E0 (vtable 0xB4B5B4 slot 0, the queued object):
//       push [ebx+0x10]; mov ecx, 0xC1BB08; call 0x7949E0     ; EXP total +0x192/+0x196 (already u64): add low
//       ... 0x796200(buf, [ebx+0x10], 0)                       ; localised number of a SIGNED 64-bit value
//       ... "Obtained %s Exp." (TextData3 0xD6551652) to chat
//
// Everything past the packet read is already 64-bit - the total and the formatter; only the high dword is
// dropped. This plugin carries it through without touching the exe's bytes (a byte-patch version crashed the
// live client on 2026-09-25: its cave held an unrelocated absolute address and the 2026 exe is ASLR-loaded):
//   * after the ctor, the payload's high dword (+6) is remembered for that object when it is non-zero;
//   * around the handler, the high dword is added to the EXP total first (the stock add then adds the low one
//     with its carry), and while the handler runs, its FIRST call of the formatter gets the high dword instead
//     of the 0 the stock code pushes - so the chat line shows the full amount.
// A packet with high == 0 (every kill, every stock-sized reward) passes through untouched.
#include <hook_core.h>

#include <mutex>
#include <unordered_map>

namespace {

const unsigned kVaCtor = 0x0073F050u;       // EXPGAIN object ctor, thiscall(this, a1, payload), ret 8
const unsigned kVaHandler = 0x0073F0E0u;    // its handler, thiscall(this), ret
const unsigned kVaFormat = 0x00796200u;     // cdecl (std::string* out, u32 low, u32 high)
const unsigned kVaExpTotal = 0x00C1BB08u;   // the object 0x7949E0 adds into: u64 total at +0x192
const unsigned kTotalHigh = 0x196;
const unsigned kPayloadHigh = 6;            // {u32 low, u16 handle, u32 high}

hook::Detour g_ctor, g_handler, g_format;
std::mutex g_lock;
std::unordered_map<void*, unsigned> g_high;   // queued EXPGAIN object -> high dword
thread_local unsigned t_pending = 0;          // the high dword the next formatter call inside the handler gets

void* __fastcall ctor_impl(void* self, void*, void* a1, const unsigned char* payload) {
    typedef void*(__fastcall * Orig)(void*, void*, void*, const unsigned char*);
    void* r = ((Orig)g_ctor.trampoline)(self, 0, a1, payload);
    unsigned high = payload ? *(const unsigned*)(payload + kPayloadHigh) : 0;
    if (high) {
        std::lock_guard<std::mutex> g(g_lock);
        g_high[self] = high;
    }
    return r;
}

void __fastcall handler_impl(void* self, void*) {
    typedef void(__fastcall * Orig)(void*, void*);
    unsigned high = 0;
    {
        std::lock_guard<std::mutex> g(g_lock);
        auto it = g_high.find(self);
        if (it != g_high.end()) { high = it->second; g_high.erase(it); }
    }
    if (high) {
        *(unsigned*)((char*)hook::rebase(kVaExpTotal) + kTotalHigh) += high;
        t_pending = high;
    }
    ((Orig)g_handler.trampoline)(self, 0);
    t_pending = 0;
}

void* __cdecl format_impl(void* out, unsigned low, unsigned high) {
    typedef void*(__cdecl * Orig)(void*, unsigned, unsigned);
    if (t_pending && high == 0) {
        high = t_pending;
        t_pending = 0;                               // the handler's first number only
    }
    return ((Orig)g_format.trampoline)(out, low, high);
}

void __declspec(naked) ctor_thunk() { __asm { jmp ctor_impl } }
void __declspec(naked) handler_thunk() { __asm { jmp handler_impl } }

}  // namespace

HOOK_PLUGIN("exp64") {
    hook::hook_function("EXPGAIN ctor 0x73F050 (keep the high dword)", hook::rebase(kVaCtor), (void*)ctor_thunk, &g_ctor);
    hook::hook_function("EXPGAIN handler 0x73F0E0 (add the high dword)", hook::rebase(kVaHandler), (void*)handler_thunk, &g_handler);
    hook::hook_function("number formatter 0x796200 (64-bit EXP line)", hook::rebase(kVaFormat), (void*)format_impl, &g_format);
}
