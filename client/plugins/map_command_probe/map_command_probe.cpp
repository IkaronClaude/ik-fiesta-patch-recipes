// map_command_probe - DIAGNOSTIC: logs every FullMapWin::OnCommand(cmd, lParam) of the 2026 client, to find which command
// a click on the full map's quest legend sends (map_legend_focus hooked UpdateArea, the 2016 route for command 9, and saw
// no call when the operator clicked quests on 2026-09-27). Remove once the route is known.
//
// 2026 FullMapWin::OnCommand = 0x60F8B0 (FullMapWin vtable 0xB20334 slot 97), thiscall(this, unsigned cmd, long lParam),
// ret 8; a 12-way switch on cmd - 1 (table 0x60FDB0).
#include <hook_core.h>

namespace {

const unsigned kVaOnCommand = 0x0060F8B0u;

hook::Detour g_cmd;

void __fastcall on_command(void* map, void*, unsigned cmd, long lparam) {
    hook::log("FullMapWin::OnCommand cmd %u lParam %ld (0x%lX) this %p", cmd, lparam, (unsigned long)lparam, map);
    ((void(__fastcall*)(void*, void*, unsigned, long))g_cmd.trampoline)(map, 0, cmd, lparam);
}

}  // namespace

HOOK_PLUGIN("map_command_probe") {
    hook::hook_function("FullMapWin::OnCommand 0x60F8B0 (log every map window command)", hook::rebase(kVaOnCommand),
                        (void*)on_command, &g_cmd);
}
