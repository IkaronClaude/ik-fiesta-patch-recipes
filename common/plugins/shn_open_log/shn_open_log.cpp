// shn_open_log - logs every .shn file the exe opens (diagnostic, any service: WorldManager, Character, Account...).
// P1 "one set of tables": which server programs besides the zones read the client tables (ItemInfo, MobInfo, ...), so
// the zone-side on-the-fly conversion knows whether a table's server file may become the 2026 client's own.
// Swaps the exe's CreateFileA / CreateFileW imports; logs "shn_open_log: <file>" once per file. Active only with
// ../9Data/Shine/ShnOpenLog.flag.
#include <hook_core.h>

#include <cstring>
#include <cwchar>
#include <set>
#include <string>

namespace {

typedef HANDLE(WINAPI* CreateFileAFn)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(WINAPI* CreateFileWFn)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
CreateFileAFn g_a = nullptr;
CreateFileWFn g_w = nullptr;
std::set<std::string> g_seen;
CRITICAL_SECTION g_lock;

void note(const std::string& f) {
    if (f.size() < 4 || _stricmp(f.c_str() + f.size() - 4, ".shn") != 0) return;
    EnterCriticalSection(&g_lock);
    bool fresh = g_seen.insert(f).second;
    LeaveCriticalSection(&g_lock);
    if (fresh) hook::log("shn_open_log: %s", f.c_str());
}

HANDLE WINAPI my_a(LPCSTR n, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa, DWORD c, DWORD f, HANDLE t) {
    if (n) note(n);
    return g_a(n, a, s, sa, c, f, t);
}

HANDLE WINAPI my_w(LPCWSTR n, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa, DWORD c, DWORD f, HANDLE t) {
    if (n) {
        char buf[MAX_PATH * 2];
        WideCharToMultiByte(CP_ACP, 0, n, -1, buf, sizeof buf, nullptr, nullptr);
        note(buf);
    }
    return g_w(n, a, s, sa, c, f, t);
}

}  // namespace

HOOK_PLUGIN("shn_open_log") {
    if (GetFileAttributesA("../9Data/Shine/ShnOpenLog.flag") == INVALID_FILE_ATTRIBUTES) return;
    InitializeCriticalSection(&g_lock);
    HMODULE exe = GetModuleHandleA(nullptr);
    g_a = (CreateFileAFn)hook::iat_hook(exe, "kernel32.dll", "CreateFileA", (void*)my_a);
    g_w = (CreateFileWFn)hook::iat_hook(exe, "kernel32.dll", "CreateFileW", (void*)my_w);
    hook::log("shn_open_log: logging .shn opens (CreateFileA %s, CreateFileW %s)", g_a ? "hooked" : "not imported",
              g_w ? "hooked" : "not imported");
}
