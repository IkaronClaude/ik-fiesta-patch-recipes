// crash_keep - every crash report of the 2026 client is SAVED to <client>\crash_reports\ instead of shown in BugTrap's
// dialog, whose "don't send" deletes the zip (operator 2026-10-23: "stops error report cleanup ... the file stays").
//
// ---- THE CLIENT CODE --------------------------------------------------------------------------------------------------
//   Fiesta.exe imports BugTrap.dll and sets only its app name / version, flags, support server and log (BT_SetAppName,
//   BT_SetFlags, BT_SetSupportServer, BT_InstallSehFilter ...) - never the activity, so BugTrap runs its default
//   BTA_SHOWUI: the report zip is built in %TEMP% and removed when the dialog closes without sending.
//
// ---- THIS PLUGIN ------------------------------------------------------------------------------------------------------
//   At load: BT_SetActivityType(BTA_SAVEREPORT = 2) and BT_SetReportFilePath(<client>\crash_reports\) - BugTrap then
//   writes the report there (crashdump.dmp + errorlog.xml zipped) and the client exits, no dialog. Both read back and
//   logged. hooks\crash_keep.ini [plugin] enabled=0 turns it off (on by default: a report is never worth losing).
#include <hook_core.h>

#include <windows.h>

namespace {

typedef void(__stdcall* BtSetActivity)(int);
typedef int(__stdcall* BtGetActivity)();
typedef void(__stdcall* BtSetPath)(const char*);
typedef const char*(__stdcall* BtGetPath)();
const int kSaveReport = 2;      // BUGTRAP_ACTIVITY: 1 show UI, 2 save report, 3 mail, 4 send

}  // namespace

HOOK_PLUGIN("crash_keep") {
    if (hook::config_int("enabled", 1, "plugin") == 0) {
        hook::log("crash_keep.ini says enabled=0 - BugTrap keeps its dialog (stock)");
        return;
    }
    HMODULE bt = GetModuleHandleA("BugTrap.dll");
    if (!bt) bt = LoadLibraryA("BugTrap.dll");
    BtSetActivity set_act = bt ? (BtSetActivity)GetProcAddress(bt, "BT_SetActivityType") : nullptr;
    BtGetActivity get_act = bt ? (BtGetActivity)GetProcAddress(bt, "BT_GetActivityType") : nullptr;
    BtSetPath set_path = bt ? (BtSetPath)GetProcAddress(bt, "BT_SetReportFilePath") : nullptr;
    BtGetPath get_path = bt ? (BtGetPath)GetProcAddress(bt, "BT_GetReportFilePath") : nullptr;
    if (!set_act || !set_path) {
        hook::log("crash_keep: BugTrap.dll / its exports not found - reports stay stock");
        return;
    }
    char dir[MAX_PATH];
    DWORD n = GetModuleFileNameA(nullptr, dir, MAX_PATH);
    while (n > 0 && dir[n - 1] != 0x5C && dir[n - 1] != '/') n--;   // 0x5C = backslash
    dir[n] = 0;
    lstrcatA(dir, "crash_reports\\");
    CreateDirectoryA(dir, nullptr);
    set_path(dir);
    set_act(kSaveReport);
    hook::log("crash_keep: BugTrap saves every report to %s (activity %d, path read back %s)", dir,
              get_act ? get_act() : -1, get_path && get_path() ? get_path() : "?");
}
