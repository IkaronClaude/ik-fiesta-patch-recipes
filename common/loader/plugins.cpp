#include "plugins.h"

namespace hook {
namespace {

size_t wlen(const wchar_t* s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

void wappend(wchar_t* dst, size_t cap, const wchar_t* src) {
    size_t i = wlen(dst), j = 0;
    while (src[j] && i + 1 < cap) dst[i++] = src[j++];
    if (cap) dst[i] = 0;
}

// The log takes ANSI; plugin names are ASCII in practice, and a name that is not degrades to '?' rather
// than losing the line.
void log_w(const char* fmt, const wchar_t* w) {
    char narrow[MAX_PATH * 2];
    int n = WideCharToMultiByte(CP_ACP, 0, w, -1, narrow, sizeof(narrow) - 1, 0, 0);
    if (n <= 0) { narrow[0] = '?'; narrow[1] = 0; }
    log(fmt, narrow);
}

void log_w2(const char* fmt, const wchar_t* w, unsigned a) {
    char narrow[MAX_PATH * 2];
    int n = WideCharToMultiByte(CP_ACP, 0, w, -1, narrow, sizeof(narrow) - 1, 0, 0);
    if (n <= 0) { narrow[0] = '?'; narrow[1] = 0; }
    log(fmt, narrow, a);
}

}  // namespace

// ---- hooks\<name>.ini beside hooks\<name>.dll (operator 2026-09-27) -----------------------------------------------
//   [plugin]
//   enabled=0          skip this DLL (default 1: no .ini = load it, as before)
//   after=a, b         load after these plugins (their DLL names without .dll); missing ones and cycles are logged
//                      and the plugin still loads, last
//   [config]           the plugin's own settings: hook::config_int / hook::config_str (hook_core.h) read this section
// Order otherwise = the folder listing (alphabetical on NTFS). Plain Win32 (GetPrivateProfile*): the loader has no CRT.
namespace {
enum { kMaxPlugins = 64, kMaxDeps = 8, kName = 64 };

struct Plugin {
    wchar_t name[kName];            // file name without .dll
    wchar_t dll[MAX_PATH];
    bool enabled;
    int ndeps;
    int deps[kMaxDeps];             // indices into the plugin table, -1 = named plugin not present
    wchar_t depname[kMaxDeps][kName];
    int state;                      // 0 = not yet, 1 = visiting, 2 = loaded / given up
};

bool wieq(const wchar_t* a, const wchar_t* b) {
    for (;; a++, b++) {
        wchar_t ca = (*a >= L'A' && *a <= L'Z') ? (wchar_t)(*a + 32) : *a;
        wchar_t cb = (*b >= L'A' && *b <= L'Z') ? (wchar_t)(*b + 32) : *b;
        if (ca != cb) return false;
        if (!ca) return true;
    }
}

Plugin g_plugins[kMaxPlugins];
int g_count = 0;
int g_loaded = 0;

void load_one(int i) {
    Plugin& p = g_plugins[i];
    if (p.state == 2) return;
    if (p.state == 1) {
        log_w("plugin %s: dependency CYCLE - loading it without waiting for the rest of the cycle", p.name);
        return;
    }
    p.state = 1;
    for (int d = 0; d < p.ndeps; d++) {
        if (p.deps[d] < 0) {
            char me[kName * 2], dn[kName * 2];
            if (WideCharToMultiByte(CP_ACP, 0, p.name, -1, me, sizeof(me) - 1, 0, 0) <= 0) { me[0] = '?'; me[1] = 0; }
            if (WideCharToMultiByte(CP_ACP, 0, p.depname[d], -1, dn, sizeof(dn) - 1, 0, 0) <= 0) { dn[0] = '?'; dn[1] = 0; }
            log("plugin %s: after= names %s, which is not in the folder (or is disabled) - ignored", me, dn);
            continue;
        }
        load_one(p.deps[d]);
    }
    if (p.state == 2) return;          // loaded by a cycle through itself
    p.state = 2;
    HMODULE m = LoadLibraryW(p.dll);
    if (m) {
        g_loaded++;
        log_w2("loaded %s at %x", p.name, (unsigned)(uintptr_t)m);
    } else {
        log_w2("FAILED to load %s (error %u)", p.name, GetLastError());
    }
}
}  // namespace

int load_plugins(const wchar_t* folder) {
    // Beside the EXE, not beside this DLL: the hook folder belongs to the server install, and the working
    // directory of a service is not the install directory.
    wchar_t dir[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, dir, MAX_PATH);
    if (!len || len >= MAX_PATH) { log("cannot resolve the exe path"); return 0; }
    while (len && dir[len - 1] != L'\\' && dir[len - 1] != L'/') len--;
    dir[len] = 0;
    wappend(dir, MAX_PATH, folder);

    wchar_t pattern[MAX_PATH];
    pattern[0] = 0;
    wappend(pattern, MAX_PATH, dir);
    wappend(pattern, MAX_PATH, L"\\*.dll");

    WIN32_FIND_DATAW found;
    HANDLE h = FindFirstFileW(pattern, &found);
    if (h == INVALID_HANDLE_VALUE) {
        log_w("no hooks folder at %s", dir);
        return 0;
    }
    // 1. the table: every DLL + its .ini
    g_count = g_loaded = 0;
    int skipped = 0;
    do {
        if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (g_count >= kMaxPlugins) { log("more than %d plugins - the rest are not loaded", (int)kMaxPlugins); break; }
        Plugin& p = g_plugins[g_count];
        p.dll[0] = 0;
        wappend(p.dll, MAX_PATH, dir);
        wappend(p.dll, MAX_PATH, L"\\");
        wappend(p.dll, MAX_PATH, found.cFileName);
        size_t n = wlen(found.cFileName);
        size_t k = 0;
        for (; k + 4 < n && k < kName - 1; k++) p.name[k] = found.cFileName[k];      // minus ".dll"
        p.name[k] = 0;
        wchar_t ini[MAX_PATH];
        ini[0] = 0;
        wappend(ini, MAX_PATH, dir);
        wappend(ini, MAX_PATH, L"\\");
        wappend(ini, MAX_PATH, p.name);
        wappend(ini, MAX_PATH, L".ini");
        p.enabled = GetPrivateProfileIntW(L"plugin", L"enabled", 1, ini) != 0;
        p.ndeps = 0;
        p.state = 0;
        wchar_t after[512];
        GetPrivateProfileStringW(L"plugin", L"after", L"", after, 512, ini);
        for (wchar_t* c = after; *c && p.ndeps < kMaxDeps;) {       // "a, b,c" -> names
            while (*c == L' ' || *c == L',' || *c == L'\t') c++;
            if (!*c) break;
            int j = 0;
            while (*c && *c != L',' && *c != L' ' && *c != L'\t' && j < kName - 1) p.depname[p.ndeps][j++] = *c++;
            p.depname[p.ndeps][j] = 0;
            if (j) p.ndeps++;
        }
        if (!p.enabled) {
            log_w("plugin %s: enabled=0 in its .ini - not loaded", p.name);
            skipped++;
            continue;
        }
        g_count++;
    } while (FindNextFileW(h, &found));
    FindClose(h);

    // 2. resolve the dependency names, then 3. load depth-first so every plugin comes after what it names
    for (int i = 0; i < g_count; i++)
        for (int d = 0; d < g_plugins[i].ndeps; d++) {
            g_plugins[i].deps[d] = -1;
            for (int j = 0; j < g_count; j++)
                if (wieq(g_plugins[j].name, g_plugins[i].depname[d])) g_plugins[i].deps[d] = j;
        }
    for (int i = 0; i < g_count; i++) load_one(i);

    log_w2("%s: %u loaded", dir, (unsigned)g_loaded);
    if (skipped) log("%d plugin(s) disabled by their .ini", skipped);
    return g_loaded;
}

}  // namespace hook
