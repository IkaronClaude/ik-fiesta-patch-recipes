// Hooking zone packet handlers by name.
//
// The zone dispatches a client packet to ShinePlayer::sp_NC_<NAME>(TNETCOMMAND*, int, unsigned short).
// There are 246 of them in this build and NONE is virtual - the mangling is QAE (public __thiscall), so
// there is no vtable slot to swap and the call sites are direct. Each hook is therefore a trampoline on
// the function itself, with the address taken from zone_symbols.h (generated from Zone.pdb) rather than
// typed in.
//
//   ZONE_HOOK_PACKET(NC_ITEM_RELOC_REQ, {
//       zone::log("reloc: from %04X to %04X", cmd->u.reloc.from, cmd->u.reloc.to);
//       ZONE_CALL_ORIGINAL();                 // omit this to swallow the packet entirely
//   });
//
// __thiscall is the reason this needs a macro rather than a plain function pointer: the ShinePlayer*
// arrives in ECX, which MSVC will not let a free function declare portably. The macro emits a naked
// thunk that moves ECX into an explicit first argument, so the body is ordinary C++.
#pragma once
#include "hook.h"
#include "zone_symbols.h"

namespace zone {

// Opaque to us for now: the zone's own TNETCOMMAND. Packet bodies are reached by casting past the
// 2-byte opcode, exactly as harvest.py does on the wire.
struct TNetCommand;

// Look a handler up by name ("sp_NC_ITEM_RELOC_REQ" or "NC_ITEM_RELOC_REQ") and return its live address.
void* handler_address(const char* name);

// Install a detour on a named handler. `replacement` must be a naked thunk of the shape the macro emits.
bool hook_packet(const char* name, void* replacement, Detour* out);

// Every hook installed, so a failure at startup can be reported and rolled back as a unit.
int installed_count();
void uninstall_all();

}  // namespace zone

// ---- the macro ------------------------------------------------------------------------------------
//
// Emits, for NAME:
//   zone_detour_NAME      the Detour record (trampoline lives here)
//   zone_impl_NAME        your body, as __fastcall(ShinePlayer* self, void* unused, TNetCommand*, int, unsigned short)
//   zone_thunk_NAME       a naked function that is what actually replaces the handler
// __fastcall takes ECX then EDX, which is exactly __thiscall plus one dead register, so the thunk is a
// straight jump and no register juggling is needed.
#define ZONE_HOOK_PACKET(NAME, BODY)                                                                   \
    static zone::Detour zone_detour_##NAME;                                                            \
    static void __fastcall zone_impl_##NAME(void* self, void* /*edx*/,                                 \
                                            zone::TNetCommand* cmd, int a2, unsigned short a3);        \
    static void __declspec(naked) zone_thunk_##NAME() {                                                \
        __asm { jmp zone_impl_##NAME }                                                                 \
    }                                                                                                  \
    static void __fastcall zone_impl_##NAME(void* self, void* /*edx*/,                                 \
                                            zone::TNetCommand* cmd, int a2, unsigned short a3) BODY

// Call the original handler from inside a body. Restores __thiscall: ECX = self.
#define ZONE_CALL_ORIGINAL_OF(NAME)                                                                    \
    do {                                                                                               \
        typedef void(__fastcall * Orig)(void*, void*, zone::TNetCommand*, int, unsigned short);        \
        ((Orig)zone_detour_##NAME.trampoline)(self, 0, cmd, a2, a3);                                    \
    } while (0)

#define ZONE_INSTALL_PACKET(NAME)                                                                      \
    zone::hook_packet(#NAME, (void*)zone_thunk_##NAME, &zone_detour_##NAME)
