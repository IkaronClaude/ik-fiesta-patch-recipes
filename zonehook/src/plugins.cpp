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

    int loaded = 0;
    do {
        if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        wchar_t path[MAX_PATH];
        path[0] = 0;
        wappend(path, MAX_PATH, dir);
        wappend(path, MAX_PATH, L"\\");
        wappend(path, MAX_PATH, found.cFileName);

        // The plugin's DllMain runs to completion inside this call, before the exe's entry point. See the
        // loader-lock caveat in plugins.h - a plugin that blocks here hangs the process with no log line.
        HMODULE m = LoadLibraryW(path);
        if (m) {
            loaded++;
            log_w2("loaded %s at %x", found.cFileName, (unsigned)(uintptr_t)m);
        } else {
            log_w2("FAILED to load %s (error %u)", found.cFileName, GetLastError());
        }
    } while (FindNextFileW(h, &found));
    FindClose(h);

    log_w2("%s: %u loaded", dir, (unsigned)loaded);
    return loaded;
}

}  // namespace hook
