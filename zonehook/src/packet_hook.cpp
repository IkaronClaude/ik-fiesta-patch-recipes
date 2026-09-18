#include "packet_hook.h"
#include <string.h>
#include <stdio.h>

namespace zone {

static Detour* g_installed[64];
static int g_count = 0;

void* handler_address(const char* name) {
    if (!name) return NULL;
    const char* want = name;
    if (strncmp(want, "sp_", 3) != 0) {
        // allow the bare packet name: "NC_ITEM_RELOC_REQ" -> "sp_NC_ITEM_RELOC_REQ"
        static char buf[128];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "sp_%s", name);
        want = buf;
    }
    for (int i = 0; i < kHandlerCount; i++) {
        if (strcmp(kHandlers[i].name, want) == 0) return rebase(kHandlers[i].va);
    }
    return NULL;
}

bool hook_packet(const char* name, void* replacement, Detour* out) {
    void* at = handler_address(name);
    if (!at) {
        log("[hook] no handler named %s in this build", name);
        return false;
    }
    if (!detour(at, replacement, out)) {
        log("[hook] %s at %p: detour refused", name, at);
        return false;
    }
    if (g_count < (int)(sizeof(g_installed) / sizeof(g_installed[0]))) g_installed[g_count++] = out;
    log("[hook] %s at %p -> %p (trampoline %p, %u bytes displaced)", name, at, replacement,
        out->trampoline, (unsigned)out->saved_len);
    return true;
}

int installed_count() { return g_count; }

void uninstall_all() {
    for (int i = g_count - 1; i >= 0; i--) undetour(g_installed[i]);
    g_count = 0;
}

}  // namespace zone
