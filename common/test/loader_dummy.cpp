// A plugin stand-in for test_loader: on load it appends "<own name>=<[config] n>" to order.txt beside the exe, so the
// test sees the load order the loader chose and what hook::config_int read from this DLL's own .ini.
#include "../include/hook_core.h"

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    char self[MAX_PATH], line[MAX_PATH + 32];
    DWORD n = GetModuleFileNameA((HMODULE)&__ImageBase, self, MAX_PATH);
    const char* name = self;
    for (DWORD i = 0; i < n; i++) if (self[i] == '\\' || self[i] == '/') name = self + i + 1;
    wsprintfA(line, "%s=%d\r\n", name, hook::config_int("n", -1));
    HANDLE f = CreateFileA("order.txt", FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, 0, 0);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(f, line, lstrlenA(line), &w, 0);
        CloseHandle(f);
    }
    return TRUE;
}
