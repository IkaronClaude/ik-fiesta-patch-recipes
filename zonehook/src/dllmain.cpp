// zonehook.dll - the LOADER. Zone.exe is patched to import it (recipes/dll-loader.json), and everything
// else lives in hooks/*.dll, which this loads.
//
// TWO STAGES, and the reason for it:
//
//   stage 1, DllMain        Runs during loader init, before the exe's entry point and its CRT, on a stack
//                           with very little committed. Measured 2026-09-19 under Wine, a DLL carrying the
//                           STATIC CRT dies right here ("stack overflow 824 bytes") before DllMain is even
//                           reached; the dynamic CRT was fine in the same position. Stage 1 therefore does
//                           exactly one thing - rewrite one IAT slot - and nothing else.
//
//   stage 2, ServiceMain    These exes are Windows SERVICES. The zone starts when the SCM calls the
//                           service routine, which we get in front of by hooking the
//                           StartServiceCtrlDispatcherA import and rewriting the SERVICE_TABLE_ENTRY it is
//                           handed (see service_hook.h). Here the process is fully initialised, the stack
//                           is a normal 1 MB, no loader lock is held, and the zone has not started - so
//                           this is where the plugins are loaded and where hooks are installed.
//
// Run by hand, the exe only registers a service and exits: stage 2 never fires, and that is expected.
// Stage 1 still logs, which is how you tell the DLL loaded at all.
#include "../include/zonehook.h"
#include "plugins.h"
#include "service_hook.h"

// Plugins may register a callback instead of doing their work in DllMain. Both run at the same moment;
// the callback exists so a plugin can keep its DllMain trivial. The list is fixed-size on purpose - no
// allocation anywhere in the start-up path.
namespace {
enum { kMaxCallbacks = 32 };
zone::ServiceInitFn g_callbacks[kMaxCallbacks];
int g_callback_count = 0;
}  // namespace

extern "C" __declspec(dllexport) int ZoneHookRegister(zone::ServiceInitFn fn) {
    if (!fn || g_callback_count >= kMaxCallbacks) return 0;
    g_callbacks[g_callback_count++] = fn;
    return 1;
}

// ---- stage 2: on the service thread, before the zone's own ServiceMain ------------------------------

static void start_plugins() {
    zone::log("service starting - loading plugins before the zone's ServiceMain");

    int loaded = zone::load_plugins();
    for (int i = 0; i < g_callback_count; i++) {
        zone::log("plugin callback %d of %d", i + 1, g_callback_count);
        g_callbacks[i]();
    }

    if (!loaded) {
        // Not an error: a stock server has no plugins. Say so plainly rather than leaving the log silent,
        // because "no hooks ran" and "no hooks exist" look identical otherwise.
        zone::log("no plugins in hooks/ - the zone runs exactly as it would unpatched");
    } else {
        zone::log("%d plugin(s) up, %d callback(s) run", loaded, g_callback_count);
    }
}

// ---- stage 1: loader init ---------------------------------------------------------------------------

extern "C" __declspec(dllexport) void ZoneHookInit() {
    // Imported by name from Zone.exe so a missing or mismatched DLL fails loudly at load. Nothing calls
    // it; the import exists to make the loader map us.
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        zone::log_init("loader");
        zone::log("loaded; exe base %x, %d known packet handlers",
                  zone::module_base(), zone::kHandlerCount);

        if (zone::hook_service_main(start_plugins)) {
            zone::log("waiting for ServiceMain");
        } else {
            zone::log("NOT A SERVICE (no StartServiceCtrlDispatcherA import) - nothing will be loaded");
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        zone::uninstall_all();
    }
    return TRUE;
}
