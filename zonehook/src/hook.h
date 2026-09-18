// zonehook - hooking primitives for Zone.exe (x86, MSVC, 32-bit).
//
// Three tools, because the zone needs three different kinds of interception:
//
//   detour()      a trampoline hook on a function that is called directly. This is what the packet
//                 handlers need: ShinePlayer::sp_NC_* are NOT virtual (their mangling is QAE, public
//                 __thiscall, not UAE), so no vtable holds their address and the call sites are direct.
//   vtable_set()  swap one slot of a C++ vtable. Right for genuinely virtual methods, and cheaper and
//                 safer than a trampoline because nothing is rewritten in .text.
//   rebase()      turn a PDB address into a live one. Zone.exe sets DYNAMIC_BASE, so the image can and
//                 does load somewhere other than 0x00400000, and a hardcoded VA would land in nothing.
//
// EVERYTHING HERE IS x86-SPECIFIC and single-threaded-install. Install hooks from ZoneHookInit, before
// the zone's own threads exist; installing into code another thread is executing is how you get a crash
// that reproduces once a week.
#pragma once
#include <stdint.h>
#include <windows.h>

namespace zone {

// ---- addresses ------------------------------------------------------------------------------------

// The module's actual base, resolved once. GetModuleHandle(NULL) is the exe no matter how we got loaded.
inline uintptr_t module_base() {
    static uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    return b;
}

// A PDB VA (based at kImageBase) -> the live address in this process.
inline void* rebase(uint32_t va_at_default_base, uint32_t default_base = 0x00400000u) {
    return (void*)(module_base() + (va_at_default_base - default_base));
}

// ---- writing to code ------------------------------------------------------------------------------

class Unprotect {  // RAII: .text is not writable, and leaving it writable is a liability
public:
    Unprotect(void* at, size_t n) : at_(at), n_(n), old_(0) {
        ok_ = VirtualProtect(at, n, PAGE_EXECUTE_READWRITE, &old_) != 0;
    }
    ~Unprotect() {
        if (ok_) {
            DWORD ignored;
            VirtualProtect(at_, n_, old_, &ignored);
            FlushInstructionCache(GetCurrentProcess(), at_, n_);
        }
    }
    bool ok() const { return ok_; }
private:
    void* at_; size_t n_; DWORD old_; bool ok_;
};

// ---- instruction length, enough of it -------------------------------------------------------------
//
// A trampoline has to copy whole instructions: cut one in half and the relocated bytes are garbage. A
// full x86 length decoder is a large thing to carry, so this covers the prologue shapes MSVC actually
// emits for these functions and REFUSES anything else. Refusing is the point - a wrong length here
// corrupts the function silently, and there is no way to notice until it runs.
size_t insn_len(const uint8_t* p);

// ---- the hooks ------------------------------------------------------------------------------------

struct Detour {
    void* target;        // the function that was hooked
    void* trampoline;    // call this to reach the original behaviour
    uint8_t saved[32];   // the bytes we displaced, for uninstall
    size_t  saved_len;
    bool    installed;
};

// Install a JMP at `target` to `replacement`, relocating the displaced instructions into a trampoline.
// Returns false and touches nothing when the prologue cannot be decoded or protection cannot be changed.
bool detour(void* target, void* replacement, Detour* out);
bool undetour(Detour* d);

// Replace one entry of a vtable. `vtable` is the table itself (what the object's first field points at).
void* vtable_set(void** vtable, int index, void* replacement);

// ---- logging --------------------------------------------------------------------------------------
// The zone is a service with no console, so everything goes to a file beside the exe and to the
// debugger. A hook that fails silently is worse than no hook.
void log(const char* fmt, ...);
void log_init(const wchar_t* filename);

}  // namespace zone
