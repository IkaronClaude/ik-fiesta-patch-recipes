// zonehook.dll - loaded by Zone.exe through an injected import (recipes/dll-loader.json).
//
// DllMain runs before the exe's entry point, which is early: the CRT has not initialised, no zone thread
// exists, and none of the game's globals are constructed. That is the right moment to REWRITE CODE (no
// other thread is executing it) and the wrong moment to CALL any of it. So DllMain only installs hooks;
// anything that needs the zone to be alive belongs in a hook body that fires later.
#include "packet_hook.h"

// ---- an example hook, and the smoke test that the plumbing works ----------------------------------
//
// NC_ITEM_RELOC_REQ is the packet the void bag will need (moving an item between inventories is exactly
// what inven 18 does on the 2026 wire: two ITEM_INVEN u16 of (inven << 10) | slot). Logging it first
// proves the detour fires with the right `this` before anything is changed.
ZONE_HOOK_PACKET(NC_ITEM_RELOC_REQ, {
    const unsigned char* p = (const unsigned char*)cmd;
    if (p) {
        unsigned short from = *(const unsigned short*)(p + 2);   // past the opcode
        unsigned short to = *(const unsigned short*)(p + 4);
        zone::log("[reloc] self=%p  %u:%u -> %u:%u", self,
                  from >> 10, from & 0x3FF, to >> 10, to & 0x3FF);
    }
    ZONE_CALL_ORIGINAL_OF(NC_ITEM_RELOC_REQ);
});

extern "C" __declspec(dllexport) void ZoneHookInit() {
    // Imported by name from Zone.exe so a missing DLL fails loudly at load. Nothing calls it; the import
    // exists to make the loader map us. Keep it exported and harmless.
}

static void install() {
    zone::log_init(L"zonehook.log");
    zone::log("[zonehook] loaded; exe base %p, %d known handlers",
              (void*)zone::module_base(), zone::kHandlerCount);
    if (!ZONE_INSTALL_PACKET(NC_ITEM_RELOC_REQ)) {
        zone::log("[zonehook] NOTHING INSTALLED - the zone runs unchanged");
        return;
    }
    zone::log("[zonehook] %d hook(s) installed", zone::installed_count());
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        install();
    } else if (reason == DLL_PROCESS_DETACH) {
        zone::uninstall_all();
    }
    return TRUE;
}
