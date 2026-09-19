// fiestahook.dll - the LOADER. A server exe is patched to import it (recipes/dll-loader*.json), and everything
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
#include "../include/hook_core.h"
#include "plugins.h"
#include "service_hook.h"

// Plugins may register a callback instead of doing their work in DllMain. Both run at the same moment;
// the callback exists so a plugin can keep its DllMain trivial. The list is fixed-size on purpose - no
// allocation anywhere in the start-up path.
namespace {
enum { kMaxCallbacks = 32 };
hook::ServiceInitFn g_callbacks[kMaxCallbacks];
int g_callback_count = 0;
}  // namespace

extern "C" __declspec(dllexport) int ZoneHookRegister(hook::ServiceInitFn fn) {
    if (!fn || g_callback_count >= kMaxCallbacks) return 0;
    g_callbacks[g_callback_count++] = fn;
    return 1;
}

// ---- stage 2: on the service thread, before the server's own ServiceMain ------------------------------

static void start_plugins() {
    hook::log("service starting - loading plugins before the server's ServiceMain");

    int loaded = hook::load_plugins();
    for (int i = 0; i < g_callback_count; i++) {
        hook::log("plugin callback %d of %d", i + 1, g_callback_count);
        g_callbacks[i]();
    }

    if (!loaded) {
        // Not an error: a stock server has no plugins. Say so plainly rather than leaving the log silent,
        // because "no hooks ran" and "no hooks exist" look identical otherwise.
        hook::log("no plugins in hooks/ - the server runs exactly as it would unpatched");
    } else {
        hook::log("%d plugin(s) up, %d callback(s) run", loaded, g_callback_count);
    }
}

// ---- stage 1: loader init ---------------------------------------------------------------------------

extern "C" __declspec(dllexport) void ZoneHookInit() {
    // Imported by name from the patched exe so a missing or mismatched DLL fails loudly at load. Nothing calls
    // it; the import exists to make the loader map us.
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        hook::log_init("loader");
        // Which exe: the same loader goes into Zone.exe and Character.exe, so say which one this is.
        // STATIC, not on the stack: DllMain runs on the loader's barely-committed stack, where a MAX_PATH
        // buffer plus the log's own was exactly what overflowed it by 824 bytes (2026-09-19).
        static char exe[MAX_PATH];
        DWORD n = GetModuleFileNameA(NULL, exe, MAX_PATH);
        const char* name = exe;
        for (DWORD i = 0; i < n; i++) if (exe[i] == '\\' || exe[i] == '/') name = exe + i + 1;
        hook::log("loaded into %s; exe base %x", n ? name : "?", hook::module_base());

        if (hook::hook_service_main(start_plugins)) {
            hook::log("waiting for ServiceMain");
        } else {
            hook::log("NOT A SERVICE (no StartServiceCtrlDispatcherA import) - nothing will be loaded");
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        hook::uninstall_all();
    }
    return TRUE;
}
