// zonehook.dll - loaded by Zone.exe through an injected import (recipes/dll-loader.json).
//
// TWO-STAGE START-UP, and the reason for it:
//
//   stage 1, DllMain      Runs during loader init, BEFORE the exe's entry point and its CRT, on a stack
//                         with very little committed. Measured 2026-09-19 under Wine: a DLL carrying the
//                         static CRT dies right here ("stack overflow 824 bytes") before DllMain is even
//                         reached. So stage 1 does the minimum that is safe - install ONE hook - and
//                         nothing else. No allocation, no file I/O, no zone code.
//
//   stage 2, the service  These exes are Windows SERVICES. WinMain runs, calls StartServiceCtrlDispatcher,
//   thread                and that BLOCKS; the SCM then calls the service routine on another thread, and
//                         that is where the zone actually starts. ZoneServer::zs_ServiceThreadFunction is
//                         that thread. By the time it runs the process is fully initialised and we are on
//                         a normal 1 MB stack, so everything real happens here.
//
// Run by hand, the exe only registers a service and exits - stage 2 never fires, and that is expected.
// Stage 1 still logs, which is how you tell the DLL loaded at all.
#include "packet_hook.h"

// ---- stage 2 ---------------------------------------------------------------------------------------

// NC_ITEM_RELOC_REQ is the packet the void bag needs: moving an item between inventories is exactly what
// inven 18 does on the 2026 wire, two ITEM_INVEN u16 of (inven << 10) | slot. Logging it first proves the
// detour fires with the right `this` before anything is changed.
ZONE_HOOK_PACKET(NC_ITEM_RELOC_REQ, {
    const unsigned char* p = (const unsigned char*)cmd;
    if (p) {
        unsigned short from = *(const unsigned short*)(p + 2);   // past the opcode
        unsigned short to = *(const unsigned short*)(p + 4);
        zone::log("[reloc] self=%x  %u:%u -> %u:%u", self,
                  from >> 10, from & 0x3FF, to >> 10, to & 0x3FF);
    }
    ZONE_CALL_ORIGINAL_OF(NC_ITEM_RELOC_REQ);
});

static void install_features() {
    zone::log("[zonehook] service thread up; installing features");
    if (!ZONE_INSTALL_PACKET(NC_ITEM_RELOC_REQ)) {
        zone::log("[zonehook] NO FEATURE HOOKS INSTALLED - the zone runs unchanged");
        return;
    }
    zone::log("[zonehook] %d feature hook(s) installed", zone::installed_count());
}

// ---- stage 1 ---------------------------------------------------------------------------------------

static zone::Detour g_service_detour;
typedef DWORD(WINAPI* ServiceThreadFn)(void*);

static DWORD WINAPI service_thread_hook(void* arg) {
    install_features();                                   // stage 2, on a real thread with a real stack
    return ((ServiceThreadFn)g_service_detour.trampoline)(arg);
}

extern "C" __declspec(dllexport) void ZoneHookInit() {
    // Imported by name from Zone.exe so a missing or mismatched DLL fails loudly at load. Nothing calls
    // it; the import exists to make the loader map us.
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        zone::log_init(L"zonehook.log");
        zone::log("[zonehook] loaded; exe base %x, %d known handlers",
                  zone::module_base(), zone::kHandlerCount);
        void* svc = zone::rebase(zone::kVaZoneServiceThread);
        if (zone::detour(svc, (void*)service_thread_hook, &g_service_detour)) {
            zone::log("[zonehook] waiting for the service thread at %x", svc);
        } else {
            zone::log("[zonehook] COULD NOT HOOK the service thread at %x - nothing will install", svc);
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        zone::uninstall_all();
    }
    return TRUE;
}
