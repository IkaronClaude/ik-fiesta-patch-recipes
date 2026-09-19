// zonehook - header-only hooking library for the Fiesta server exes (x86, MSVC, 32-bit).
//
// Include this and nothing else. It is header-only on purpose: a hook DLL in hooks/ is built on its own,
// with its own CRT, and linking it against a static library would make the two builds agree about things
// they do not need to agree about. Everything here is inline, and each DLL gets its own copy of its own
// hook state - which is what you want, because a plugin owns the hooks it installs.
//
//     #include <zonehook.h>
//
//     ZONE_HOOK_PACKET(NC_ITEM_RELOC_REQ, {
//         zone::log("reloc from %u to %u", ...);
//         ZONE_CALL_ORIGINAL_OF(NC_ITEM_RELOC_REQ);     // omit to swallow the packet
//     });
//
//     ZONEHOOK_PLUGIN("void_bag") {
//         ZONE_INSTALL_PACKET(NC_ITEM_RELOC_REQ);
//     }
//
// FOUR WAYS IN, because the zone needs four different kinds of interception:
//
//   detour()      trampoline a function that is called directly. This is what the packet handlers need:
//                 ShinePlayer::sp_NC_* are NOT virtual (mangling QAE, public __thiscall), so no vtable
//                 holds their address and every call site is direct.
//   vtable_set()  swap one slot of a C++ vtable. Right for genuinely virtual methods, and cheaper and
//                 safer than a trampoline because nothing in .text is rewritten.
//   iat_hook()    swap an imported function. The safest of the three when it applies - no code is
//                 rewritten and no instruction has to be decoded. This is how the loader gets in front of
//                 the service routine.
//   rebase()      turn a PDB address into a live one. These exes set DYNAMIC_BASE, so the image can load
//                 somewhere other than 0x00400000 and a hardcoded VA would land in nothing.
//
// EVERYTHING HERE IS x86-SPECIFIC. Install hooks from your plugin entry point, which the loader calls on
// the service thread before the zone has started any of its own threads. Installing into code that
// another thread is executing is how you get a crash that reproduces once a week.
#pragma once

#ifndef _WIN32
#error zonehook targets Win32 (the server exes are PE32)
#endif
#ifdef _WIN64
#error zonehook is 32-bit only - the server exes are PE32 and a 64-bit DLL will not load into them
#endif

#include <windows.h>
#include <stdarg.h>

#include "zone_symbols.h"

namespace zone {

typedef unsigned char u8;
typedef signed int i32;
typedef unsigned int u32;
typedef unsigned int uptr;

// ---- small string helpers -------------------------------------------------------------------------
//
// Spelled out rather than taken from <string.h> so this header also works in the LOADER, which is built
// with no CRT at all. That is a choice, not a necessity: measured 2026-09-19, a STATIC CRT (/MT) in a DLL
// statically imported by Zone.exe overflows the main thread's stack during its start-up, before DllMain is
// reached, while the DYNAMIC CRT (/MD) was verified working in exactly that position. The loader stays
// CRT-free so it has no redistributable dependency at all; plugins are free to use the full CRT.
namespace detail {

inline void* mem_copy(void* dst, const void* src, size_t n) {
    u8* d = (u8*)dst; const u8* s = (const u8*)src;
    while (n--) *d++ = *s++;
    return dst;
}

inline void* mem_set(void* dst, int v, size_t n) {
    u8* d = (u8*)dst;
    while (n--) *d++ = (u8)v;
    return dst;
}

inline size_t str_len(const char* s) { size_t n = 0; while (s[n]) n++; return n; }

inline int str_cmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

inline int str_icmp(const char* a, const char* b) {
    for (;; a++, b++) {
        char ca = (*a >= 'A' && *a <= 'Z') ? (char)(*a + 32) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (char)(*b + 32) : *b;
        if (ca != cb) return (int)(unsigned char)ca - (int)(unsigned char)cb;
        if (!ca) return 0;
    }
}

inline void str_copy(char* dst, size_t cap, const char* src) {
    size_t i = 0;
    for (; src[i] && i + 1 < cap; i++) dst[i] = src[i];
    if (cap) dst[i] = 0;
}

inline size_t wstr_len(const wchar_t* s) { size_t n = 0; while (s[n]) n++; return n; }

inline void wstr_append(wchar_t* dst, size_t cap, const wchar_t* src) {
    size_t i = wstr_len(dst), j = 0;
    while (src[j] && i + 1 < cap) dst[i++] = src[j++];
    if (cap) dst[i] = 0;
}

}  // namespace detail

// ---- logging --------------------------------------------------------------------------------------
//
// The zone is a service with no console, so everything goes to one file beside the exe. Every module -
// the loader and each plugin - appends to the SAME file with its own name as a prefix, because the thing
// you actually need when a hook misbehaves is one chronological narrative, not five separate logs.
//
// A hook that fails silently is worse than no hook, so log() is deliberately hard to break: it takes no
// allocation, holds a lock, and flushes every line.
namespace detail {

// C++17 inline variables: one copy per DLL, which is the right granularity here.
inline HANDLE g_log = INVALID_HANDLE_VALUE;
inline CRITICAL_SECTION g_log_lock;
inline bool g_log_ready = false;
inline char g_log_tag[64] = "zonehook";

// STACK AT LOADER TIME IS TIGHT. Measured 2026-09-19 under Wine: a MAX_PATH wide buffer plus a 1 KB
// format buffer on the stack overflowed the main thread by 824 bytes before the exe's entry point had
// run, and the DLL died writing nothing. These are static for that reason; the lock makes that safe.
inline wchar_t g_log_path[MAX_PATH];
inline char g_log_buf[1024];

}  // namespace detail

// Open the log. `tag` prefixes every line from this module; pass the plugin's name.
inline void log_init(const char* tag, const wchar_t* filename = L"zonehook.log") {
    if (detail::g_log_ready) return;
    InitializeCriticalSection(&detail::g_log_lock);
    detail::g_log_ready = true;
    if (tag) detail::str_copy(detail::g_log_tag, sizeof(detail::g_log_tag), tag);

    wchar_t* path = detail::g_log_path;
    DWORD n = GetModuleFileNameW(GetModuleHandleW(NULL), path, MAX_PATH);
    if (n && n < MAX_PATH) {
        wchar_t* slash = 0;
        for (wchar_t* q = path; *q; q++) if (*q == L'\\') slash = q;
        if (slash) *(slash + 1) = 0;
        detail::wstr_append(path, MAX_PATH, filename);
        detail::g_log = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    // Fall back to the working directory. Measured 2026-09-19: a probe DLL writing a RELATIVE name landed
    // in the server folder while the absolute path built from GetModuleFileNameW produced nothing, so do
    // not let the log depend on that call succeeding - it is the one thing that has to work before
    // anything else can be diagnosed.
    if (detail::g_log == INVALID_HANDLE_VALUE) {
        detail::g_log = CreateFileW(filename, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    }
}

// wvsprintfA is USER32, not the CRT, so this works in the no-CRT loader too. It understands
// %s %d %u %x %c %% and width/precision. It does NOT do %p or floating point - use %x for pointers.
inline void log(const char* fmt, ...) {
    if (detail::g_log_ready) EnterCriticalSection(&detail::g_log_lock);

    char* buf = detail::g_log_buf;
    size_t head = 0;
    buf[head++] = '[';
    for (const char* t = detail::g_log_tag; *t && head < 40; t++) buf[head++] = *t;
    buf[head++] = ']';
    buf[head++] = ' ';

    va_list ap;
    va_start(ap, fmt);
    int n = wvsprintfA(buf + head, fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;

    size_t total = head + (size_t)n;
    buf[total] = '\n';
    buf[total + 1] = 0;

    if (detail::g_log != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(detail::g_log, buf, (DWORD)(total + 1), &written, NULL);
        FlushFileBuffers(detail::g_log);
    }
#ifndef ZH_NO_ODS
    // Wine implements OutputDebugString by RAISING AN EXCEPTION (DBG_PRINTEXCEPTION_C). Setting one up
    // costs a CONTEXT record on the stack, and at loader time - before the exe's entry point, with the
    // main thread's stack barely committed - that was enough to overflow it: measured 2026-09-19, the
    // zone died with "virtual_setup_exception stack overflow 824 bytes" inside zonehook's .text and wrote
    // nothing. The loader builds with ZH_NO_ODS; a plugin loaded later is on a normal stack and need not.
    OutputDebugStringA(buf);
#endif

    if (detail::g_log_ready) LeaveCriticalSection(&detail::g_log_lock);
}

// ---- addresses ------------------------------------------------------------------------------------

// The exe's actual base. GetModuleHandle(NULL) is the exe no matter which module asks.
// NOT a function-local static: that needs the CRT's __Init_thread_header/footer, which do not exist in
// the no-CRT loader. GetModuleHandleW(NULL) is a cheap PEB read, so resolving every time costs nothing.
inline uptr module_base() { return (uptr)GetModuleHandleW(NULL); }

// A PDB VA (based at kImageBase) -> the live address in this process.
inline void* rebase(u32 va_at_default_base, u32 default_base = kImageBase) {
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

// Write bytes over code, restoring protection afterwards. For the small patches a feature needs
// (a JE to a JMP, a constant bumped) where a whole detour would be overkill.
inline bool write_code(void* at, const void* bytes, size_t n) {
    Unprotect up(at, n);
    if (!up.ok()) { log("[hook] cannot unprotect %x (%u)", at, GetLastError()); return false; }
    detail::mem_copy(at, bytes, n);
    return true;
}

// ---- instruction length, enough of it -------------------------------------------------------------
//
// A trampoline has to copy WHOLE instructions: cut one in half and the relocated bytes are garbage. A
// full x86 length decoder is a large thing to carry, so this covers the prologue shapes MSVC actually
// emits for these functions and REFUSES anything else by returning 0. Refusing is the point - a wrong
// length here corrupts the function silently, and there is no way to notice until it runs.
inline size_t insn_len(const u8* p) {
    size_t i = 0;
    while (p[i] == 0x66 || p[i] == 0x67 || p[i] == 0xF2 || p[i] == 0xF3) i++;
    const bool opsize = i > 0 && p[i - 1] == 0x66;
    const u8 op = p[i];

    if ((op >= 0x50 && op <= 0x5F) ||                 // push/pop reg
        op == 0x90 || op == 0xC3 || op == 0xC9 || op == 0xCC) return i + 1;
    if (op == 0xC2) return i + 3;                     // ret imm16
    if (op == 0x68) return i + 5;                     // push imm32
    if (op == 0x6A) return i + 2;                     // push imm8
    // mov eax,[moffs32] and friends (A0-A3). MSVC emits A1 right after the frame set-up whenever the
    // function reads a global, which is most of them - found by test_hook, where `triple` began
    // 55 8B EC A1 ... and the decoder refused (correctly) rather than cutting the A1 in half.
    if (op >= 0xA0 && op <= 0xA3) return i + 1 + 4;
    if (op >= 0xB8 && op <= 0xBF) return i + 1 + (opsize ? 2 : 4);   // mov r32, imm32
    if (op >= 0xB0 && op <= 0xB7) return i + 2;                      // mov r8, imm8
    if (op == 0xE8 || op == 0xE9) return i + 5;                      // call/jmp rel32 (relocated below)
    if (op == 0xEB) return i + 2;                                    // jmp rel8

    const bool has_modrm =
        (op <= 0x3F && (op & 7) <= 3) || op == 0x84 || op == 0x85 || op == 0x63 ||
        (op >= 0x88 && op <= 0x8B) || op == 0x8D || op == 0x8F ||
        op == 0xC6 || op == 0xC7 || op == 0xF6 || op == 0xF7 || op == 0xFF ||
        (op >= 0x80 && op <= 0x83);
    if (!has_modrm) return 0;

    size_t j = i + 1;
    const u8 modrm = p[j++];
    const u8 mod = modrm >> 6, rm = modrm & 7;
    if (mod != 3 && rm == 4) j++;                     // SIB
    if (mod == 1) j += 1;                             // disp8
    else if (mod == 2) j += 4;                        // disp32
    else if (mod == 0 && rm == 5) j += 4;             // disp32, no base
    if (op == 0xC6 || op == 0x80 || (op >= 0x81 && op <= 0x83 && op != 0x82)) {
        j += (op == 0xC6 || op == 0x80 || op == 0x83) ? 1 : (opsize ? 2 : 4);
    } else if (op == 0xC7) {
        j += opsize ? 2 : 4;
    } else if (op == 0xF6) {
        if (((modrm >> 3) & 7) <= 1) j += 1;
    } else if (op == 0xF7) {
        if (((modrm >> 3) & 7) <= 1) j += opsize ? 2 : 4;
    }
    return j;
}

// ---- detour ---------------------------------------------------------------------------------------

struct Detour {
    void*  target;        // the function that was hooked
    void*  trampoline;    // call this to reach the original behaviour
    u8     saved[32];     // the bytes we displaced, for uninstall
    size_t saved_len;
    bool   installed;
};

// Install a JMP at `target` to `replacement`, relocating the displaced instructions into a trampoline.
// Returns false and touches NOTHING when the prologue cannot be decoded or protection cannot be changed.
inline bool detour(void* target, void* replacement, Detour* out) {
    const size_t kJmpLen = 5;
    if (!target || !replacement || !out) return false;
    detail::mem_set(out, 0, sizeof(*out));
    u8* t = (u8*)target;

    size_t len = 0;
    while (len < kJmpLen) {
        size_t n = insn_len(t + len);
        if (!n || len + n > sizeof(out->saved)) {
            log("[hook] REFUSED %x: cannot decode the prologue at +%u (byte %02X)",
                target, (unsigned)len, t[len]);
            return false;
        }
        len += n;
    }

    // A trampoline reached by a rel32 JMP has to be within +-2GB; on 32-bit everything is.
    u8* tramp = (u8*)VirtualAlloc(NULL, len + kJmpLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) { log("[hook] REFUSED %x: no memory for a trampoline", target); return false; }

    detail::mem_copy(tramp, t, len);
    // A displaced rel32 call/jmp would point at the wrong place from its new home: fix the one case that
    // can appear this early, and refuse the rest rather than relocate blind.
    for (size_t k = 0; k < len; ) {
        size_t n = insn_len(t + k);
        if ((t[k] == 0xE8 || t[k] == 0xE9) && n == 5) {
            i32 rel = *(i32*)(t + k + 1);
            i32 adj = (i32)((t + k) - (tramp + k));
            *(i32*)(tramp + k + 1) = rel + adj;
        } else if (t[k] == 0xEB) {
            log("[hook] REFUSED %x: a short jump in the first %u bytes", target, (unsigned)len);
            VirtualFree(tramp, 0, MEM_RELEASE);
            return false;
        }
        k += n;
    }
    tramp[len] = 0xE9;
    *(i32*)(tramp + len + 1) = (i32)((t + len) - (tramp + len + kJmpLen));

    Unprotect up(t, len);
    if (!up.ok()) {
        log("[hook] REFUSED %x: VirtualProtect failed (%u)", target, GetLastError());
        VirtualFree(tramp, 0, MEM_RELEASE);
        return false;
    }
    detail::mem_copy(out->saved, t, len);
    out->saved_len = len;
    t[0] = 0xE9;
    *(i32*)(t + 1) = (i32)((u8*)replacement - (t + kJmpLen));
    for (size_t k = kJmpLen; k < len; k++) t[k] = 0x90;   // pad so a disassembler stays sane

    out->target = target;
    out->trampoline = tramp;
    out->installed = true;
    return true;
}

inline bool undetour(Detour* d) {
    if (!d || !d->installed) return false;
    Unprotect up(d->target, d->saved_len);
    if (!up.ok()) return false;
    detail::mem_copy(d->target, d->saved, d->saved_len);
    d->installed = false;
    VirtualFree(d->trampoline, 0, MEM_RELEASE);
    d->trampoline = NULL;
    return true;
}

// ---- vtable ---------------------------------------------------------------------------------------

// Replace one entry of a vtable. `vtable` is the table itself - what the object's first field points at,
// or kVtables[] rebased for a table you found in the PDB.
inline void* vtable_set(void** vtable, int index, void* replacement) {
    if (!vtable) return NULL;
    Unprotect up(&vtable[index], sizeof(void*));   // vtables live in .rdata: read-only until asked
    if (!up.ok()) return NULL;
    void* old = vtable[index];
    vtable[index] = replacement;
    return old;
}

// The vtable of a live object: every polymorphic C++ object stores it as its first field.
inline void** vtable_of(void* object) { return object ? *(void***)object : NULL; }

// A named vtable from the PDB (see kVtables in zone_symbols.h), rebased.
inline void** vtable_by_name(const char* name) {
    for (int i = 0; i < kVtableCount; i++) {
        if (detail::str_cmp(kVtables[i].name, name) == 0) return (void**)rebase(kVtables[i].va);
    }
    log("[hook] no vtable called '%s' in the symbol table", name);
    return NULL;
}

// ---- imports --------------------------------------------------------------------------------------
//
// Swap the IAT slot a module uses for an imported function. Nothing in .text is rewritten and no
// instruction has to be decoded, so this is the safest option whenever the target is an import.
//
// It is also how the loader gets in front of a Windows SERVICE: these exes have NO EXPORTS AT ALL and
// ServiceMain is a plain callback handed to StartServiceCtrlDispatcherA inside a SERVICE_TABLE_ENTRY, so
// there is no symbol to detour - but hooking that one import hands you the table before the SCM sees it.
// Returns the previous value, or null if the import is not there.
inline void* iat_hook(HMODULE module, const char* dll, const char* function, void* replacement) {
    u8* base = (u8*)(module ? module : GetModuleHandleW(NULL));
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return 0;

    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);
    for (; imp->Name; imp++) {
        // case-insensitive: the descriptor spells it however the linker felt that day
        if (detail::str_icmp((const char*)(base + imp->Name), dll) != 0) continue;

        // Walk the ORIGINAL thunks for the names, and patch the matching slot of the LIVE IAT. The
        // original list is read-only and still holds the names after binding; FirstThunk is what the
        // code actually calls through.
        IMAGE_THUNK_DATA* orig = imp->OriginalFirstThunk
                               ? (IMAGE_THUNK_DATA*)(base + imp->OriginalFirstThunk)
                               : (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
        IMAGE_THUNK_DATA* live = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
        for (; orig->u1.AddressOfData; orig++, live++) {
            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;     // imported by ordinal: no name
            IMAGE_IMPORT_BY_NAME* byname = (IMAGE_IMPORT_BY_NAME*)(base + orig->u1.AddressOfData);
            if (detail::str_cmp((const char*)byname->Name, function) != 0) continue;
            Unprotect up(&live->u1.Function, sizeof(void*));
            if (!up.ok()) return 0;
            void* old = (void*)live->u1.Function;
            live->u1.Function = (uptr)replacement;
            return old;
        }
    }
    return 0;
}

// ---- the zone's own functions ---------------------------------------------------------------------
//
// zone_symbols.h carries every address this build knows about, generated from Zone.pdb. Look them up by
// name rather than typing an address: the name survives a rebuild of the symbol table, an address does
// not, and a typo'd address is a jump into the middle of an unrelated function.

// A packet handler by name, accepting either spelling ("sp_NC_ITEM_RELOC_REQ" or "NC_ITEM_RELOC_REQ").
inline void* handler_address(const char* name) {
    for (int i = 0; i < kHandlerCount; i++) {
        const char* h = kHandlers[i].name;
        if (detail::str_cmp(h, name) == 0) return rebase(kHandlers[i].va);
        if (detail::str_cmp(h + 3, name) == 0) return rebase(kHandlers[i].va);   // skip "sp_"
    }
    return NULL;
}

// Every other function the zone has is in <zone_functions.h>, generated from the same PDB and TYPED -
// 10,261 of them, each with its calling convention, arguments and address. Use that rather than a
// stringly-typed lookup: a signature the compiler checks beats one you remembered.

// ---- installed hooks ------------------------------------------------------------------------------
//
// Per-module, so a plugin can roll its own hooks back without touching anybody else's.
namespace detail {
enum { kMaxHooks = 64 };
inline Detour* g_hooks[kMaxHooks];
inline int g_hook_count = 0;
}  // namespace detail

inline int installed_count() { return detail::g_hook_count; }

// Detour a named packet handler. `replacement` must be a naked thunk of the shape ZONE_HOOK_PACKET emits.
inline bool hook_packet(const char* name, void* replacement, Detour* out) {
    void* target = handler_address(name);
    if (!target) { log("[hook] NO SUCH HANDLER: %s", name); return false; }
    if (!detour(target, replacement, out)) return false;
    if (detail::g_hook_count < detail::kMaxHooks) detail::g_hooks[detail::g_hook_count++] = out;
    log("[hook] %s at %x -> %x (trampoline %x, %u bytes displaced)",
        name, target, replacement, out->trampoline, (unsigned)out->saved_len);
    return true;
}

// Detour any function, tracked alongside the packet hooks so uninstall_all() covers it.
inline bool hook_function(const char* what, void* target, void* replacement, Detour* out) {
    if (!target) { log("[hook] NO ADDRESS for %s", what); return false; }
    if (!detour(target, replacement, out)) return false;
    if (detail::g_hook_count < detail::kMaxHooks) detail::g_hooks[detail::g_hook_count++] = out;
    log("[hook] %s at %x -> %x (trampoline %x)", what, target, replacement, out->trampoline);
    return true;
}

inline void uninstall_all() {
    for (int i = detail::g_hook_count - 1; i >= 0; i--) undetour(detail::g_hooks[i]);
    detail::g_hook_count = 0;
}

}  // namespace zone

// ---- hooking a packet handler ----------------------------------------------------------------------
//
// The zone dispatches a client packet to ShinePlayer::sp_NC_<NAME>(TNETCOMMAND*, int, unsigned short).
// There are 246 of them in this build and NONE is virtual - the mangling is QAE (public __thiscall), so
// there is no vtable slot to swap and every call site is direct. Each hook is therefore a trampoline on
// the function itself, at an address taken from zone_symbols.h rather than typed in.
//
// __thiscall is why this needs a macro rather than a plain function pointer: the ShinePlayer* arrives in
// ECX, which MSVC will not let a free function declare portably. The macro emits a naked thunk that turns
// it into __fastcall - ECX then EDX, which is __thiscall plus one dead register - so the body you write
// is ordinary C++ with `self` as a normal parameter.
//
// Inside the body you have:  self (ShinePlayer*), cmd (the packet), a2, a3.
//
// VARIADIC on purpose. The preprocessor protects commas inside PARENTHESES, not braces, so a body that
// declares `unsigned a = x, b = y;` would otherwise split into two macro arguments and fail with a
// "too many arguments" pointing at a line that looks fine. __VA_ARGS__ takes the body whole.
#define ZONE_HOOK_PACKET(NAME, ...)                                                                    \
    static zone::Detour zone_detour_##NAME;                                                            \
    static void __fastcall zone_impl_##NAME(void* self, void* /*edx*/,                                 \
                                            void* cmd, int a2, unsigned short a3);                     \
    static void __declspec(naked) zone_thunk_##NAME() {                                                \
        __asm { jmp zone_impl_##NAME }                                                                 \
    }                                                                                                  \
    static void __fastcall zone_impl_##NAME(void* self, void* /*edx*/,                                 \
                                            void* cmd, int a2, unsigned short a3) __VA_ARGS__

// Call the original handler from inside a body. Restores __thiscall: ECX = self.
// Omit it to swallow the packet entirely.
#define ZONE_CALL_ORIGINAL_OF(NAME)                                                                    \
    do {                                                                                               \
        typedef void(__fastcall * ZoneOrig)(void*, void*, void*, int, unsigned short);                 \
        ((ZoneOrig)zone_detour_##NAME.trampoline)(self, 0, cmd, a2, a3);                               \
    } while (0)

#define ZONE_INSTALL_PACKET(NAME)                                                                      \
    zone::hook_packet(#NAME, (void*)zone_thunk_##NAME, &zone_detour_##NAME)

// ---- a plugin -------------------------------------------------------------------------------------
//
// Defines the DllMain a hooks/*.dll needs. The loader loads plugins from the SERVICE thread, not during
// loader init. By the time this body runs the process is fully initialised, you are on a normal 1 MB
// stack, no loader lock is held, and the full CRT - static or dynamic, your choice - is available. The
// zone itself has not started yet, which is exactly the window where installing hooks is safe.
//
//     ZONEHOOK_PLUGIN("void_bag") {
//         ZONE_INSTALL_PACKET(NC_ITEM_RELOC_REQ);
//     }
#define ZONEHOOK_PLUGIN(NAME)                                                                          \
    static void zonehook_plugin_main();                                                                \
    extern "C" BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {                           \
        if (reason == DLL_PROCESS_ATTACH) {                                                            \
            DisableThreadLibraryCalls(module);                                                         \
            zone::log_init(NAME);                                                                      \
            zone::log("loaded");                                                                       \
            zonehook_plugin_main();                                                                    \
        } else if (reason == DLL_PROCESS_DETACH) {                                                     \
            zone::uninstall_all();                                                                     \
        }                                                                                              \
        return TRUE;                                                                                   \
    }                                                                                                  \
    static void zonehook_plugin_main()
