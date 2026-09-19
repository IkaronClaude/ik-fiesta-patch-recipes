// zonehook.h - hooking Zone.exe. The core (detour, vtable, IAT, logging, plugins) is hook_core.h;
// this adds the zone's own symbols and the ShinePlayer packet-handler macros.
//
//     #include <zonehook.h>
//
//     ZONE_HOOK_PACKET(NC_ITEM_RELOC_REQ, {
//         zone::log("reloc from %x", self);
//         ZONE_CALL_ORIGINAL_OF(NC_ITEM_RELOC_REQ);     // omit to swallow the packet
//     });
//
//     HOOK_PLUGIN("void_bag") {
//         ZONE_INSTALL_PACKET(NC_ITEM_RELOC_REQ);
//     }
#pragma once
#include "hook_core.h"
#include "zone_symbols.h"

namespace zone {

// Everything in the core is reachable as zone::... too - zone::log, zone::detour, zone::rebase.
using namespace ::hook;

// A named vtable from the PDB (see kVtables in zone_symbols.h), rebased.
inline void** vtable_by_name(const char* name) {
    for (int i = 0; i < kVtableCount; i++) {
        if (detail::str_cmp(kVtables[i].name, name) == 0) return (void**)rebase(kVtables[i].va);
    }
    log("[hook] no vtable called '%s' in the symbol table", name);
    return NULL;
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

