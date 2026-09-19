#include "service_hook.h"

#define detail_str_cmp  ::zone::detail::str_cmp
#define detail_str_copy ::zone::detail::str_copy

namespace zone {
namespace {

enum { kMaxServices = 8, kMaxName = 64 };

struct Saved {
    char name[kMaxName];
    LPSERVICE_MAIN_FUNCTIONA proc;
};

Saved g_saved[kMaxServices];
int g_saved_count = 0;

// Our table, kept alive for the life of the process: StartServiceCtrlDispatcher does not copy it, and the
// SCM reads it after we have returned. A local would be a dangling pointer the moment the hook returns.
SERVICE_TABLE_ENTRYA g_table[kMaxServices + 1];
char g_names[kMaxServices][kMaxName];

ServiceInitFn g_init = 0;
bool g_started = false;
bool g_init_done = false;

// One wrapper serves every entry. A service routine is called with argv[0] = the service name, so the
// name is enough to find the original we replaced - no per-entry thunk needed.
void WINAPI service_main_hook(DWORD argc, LPSTR* argv) {
    const char* who = (argc && argv && argv[0]) ? argv[0] : "";
    LPSERVICE_MAIN_FUNCTIONA original = g_saved_count ? g_saved[0].proc : 0;
    for (int i = 0; i < g_saved_count; i++) {
        if (detail_str_cmp(g_saved[i].name, who) == 0) { original = g_saved[i].proc; break; }
    }

    g_started = true;
    log("[service] '%s' starting; running set-up before its ServiceMain at %x", who, original);

    // Ours first, and only once - the SCM can start a service routine more than once in a process.
    if (!g_init_done) {
        g_init_done = true;
        if (g_init) g_init();
    }

    if (original) {
        original(argc, argv);
    } else {
        // Never expected: it would mean we replaced a proc we never saved. Do not silently return, or the
        // SCM sees the service exit immediately and the zone "starts and stops" with no explanation.
        log("[service] NO ORIGINAL for '%s' - the service will not run", who);
    }
}

typedef BOOL(WINAPI* StartDispatcherAFn)(const SERVICE_TABLE_ENTRYA*);
StartDispatcherAFn g_original_dispatch = 0;

BOOL WINAPI start_dispatcher_hook(const SERVICE_TABLE_ENTRYA* table) {
    if (!table) return g_original_dispatch ? g_original_dispatch(table) : FALSE;

    int n = 0;
    for (; table[n].lpServiceProc && n < kMaxServices; n++) {
        const char* name = table[n].lpServiceName ? table[n].lpServiceName : "";
        detail_str_copy(g_saved[n].name, kMaxName, name);
        g_saved[n].proc = table[n].lpServiceProc;
        detail_str_copy(g_names[n], kMaxName, name);
        g_table[n].lpServiceName = g_names[n];
        g_table[n].lpServiceProc = service_main_hook;
        log("[service] table entry %d: '%s' ServiceMain %x -> %x",
            n, g_names[n], table[n].lpServiceProc, service_main_hook);
    }
    g_table[n].lpServiceName = 0;     // the terminator the dispatcher looks for
    g_table[n].lpServiceProc = 0;
    g_saved_count = n;

    if (!n) log("[service] dispatcher called with an EMPTY table - nothing to wrap");
    return g_original_dispatch(g_table);
}

}  // namespace

bool hook_service_main(ServiceInitFn fn) {
    g_init = fn;
    void* previous = iat_hook(0, "advapi32.dll", "StartServiceCtrlDispatcherA",
                              (void*)start_dispatcher_hook);
    if (!previous) return false;
    g_original_dispatch = (StartDispatcherAFn)previous;
    return true;
}

bool service_started() { return g_started; }

}  // namespace zone
