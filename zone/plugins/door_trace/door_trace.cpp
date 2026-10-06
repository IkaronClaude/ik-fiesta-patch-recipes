// door_trace - DIAGNOSTIC (2026-10-06): every door the zone builds, every state change, and every door appear-packet sent,
// to prove whether a player entering a map is told about a door that is already closed (operator goal: "100% full proof
// for how a 2026 client handles a door that was already closed when a map is entered, AND why the 2016 client fails").
//
// Static facts (Zone.exe, read 2026-10-06): a door's appear packet is BUILDDOOR 0x1C0F (BriefInformationDoor ctor 0x549260:
// dept 7, cmd 0xF), its record at door+0x1EEB -> record (+0 handle, +2 mobid, +4 coord, +0xD doorstate, +0xE Name8 block).
// ShineDoor::so_door_DoorAction (0x550770) writes the new state into that record, calls mbi_DoorAction (collision) and
// sends SCENARIO_DOORSTATE 0x6C09; ShineDoor::so_SendMyBriefInfo (0x555B60) sends the record to a player in view.
// Remove after the proof (the P4 diagnostic-plugin rule).
#include <zonehook.h>
#include <zone_functions.h>

#include <windows.h>

#include <cstdio>
#include <cstring>

namespace {

zone::Detour g_cbuild, g_caction, g_mbi, g_closeall, g_build, g_action, g_send;
const unsigned kRecPtr = 0x1EEB;

void name8(const void* p, char out[33]) {
    memset(out, 0, 33);
    __try {
        if (p) memcpy(out, p, 32);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        strcpy_s(out, 33, "?");
    }
    for (int i = 0; i < 32 && out[i]; i++)
        if (out[i] < 32 || out[i] > 126) out[i] = '?';
}

void rec_text(void* door, char* buf, size_t n) {
    __try {
        const unsigned char* r = *(const unsigned char**)((char*)door + kRecPtr);
        char nm[33];
        name8(r + 0xE, nm);
        sprintf_s(buf, n, "handle %u mob %u state %u block '%s'", *(unsigned short*)r, *(unsigned short*)(r + 2), r[0xD], nm);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        sprintf_s(buf, n, "record unreadable");
    }
}

typedef int(__cdecl* LuaFn)(void*);
int __cdecl cbuild_impl(void* L) {
    int r = ((LuaFn)g_cbuild.trampoline)(L);
    zone::log("door_trace: Lua cDoorBuild -> %d", r);
    return r;
}
int __cdecl caction_impl(void* L) {
    int r = ((LuaFn)g_caction.trampoline)(L);
    zone::log("door_trace: Lua cDoorAction -> %d", r);
    return r;
}

typedef unsigned char(__fastcall* MbiFn)(void*, void*, void*, int);
unsigned char __fastcall mbi_impl(void* self, void*, void* name, int action) {
    char nm[33];
    name8(name, nm);
    unsigned char r = ((MbiFn)g_mbi.trampoline)(self, 0, name, action);
    zone::log("door_trace: map collision mbi_DoorAction('%s', action %d) -> %u (map block %p)", nm, action, r, self);
    return r;
}

typedef void(__fastcall* CloseAllFn)(void*, void*, void*);
void __fastcall closeall_impl(void* self, void*, void* mbi) {
    ((CloseAllFn)g_closeall.trampoline)(self, 0, mbi);
    zone::log("door_trace: map collision mda_CloseAllDoor (doors %p, map block %p)", self, mbi);
}

typedef int(__fastcall* BuildFn)(void*, void*, void*, int, int, int, unsigned short, unsigned short, int, unsigned long long);
int __fastcall build_impl(void* self, void*, void* map, int a2, int a3, int a4, unsigned short a5, unsigned short a6, int a7,
                          unsigned long long a8) {
    int r = ((BuildFn)g_build.trampoline)(self, 0, map, a2, a3, a4, a5, a6, a7, a8);
    char m[13] = {0}, rec[128];
    __try {
        if (map) memcpy(m, map, 12);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    rec_text(self, rec, sizeof rec);
    zone::log("door_trace: ShineDoor %p built on map '%s' -> %d: %s", self, m, r, rec);
    return r;
}

typedef unsigned char(__fastcall* ActionFn)(void*, void*, char*, int);
unsigned char __fastcall action_impl(void* self, void*, char* name, int action) {
    char nm[33], rec[128];
    name8(name, nm);
    unsigned char r = ((ActionFn)g_action.trampoline)(self, 0, name, action);
    rec_text(self, rec, sizeof rec);
    zone::log("door_trace: ShineDoor %p DoorAction('%s', %d) -> %u: now %s (SCENARIO_DOORSTATE 0x6C09 sent)", self, nm, action, r, rec);
    return r;
}

typedef void(__fastcall* SendFn)(void*, void*, void*);
void __fastcall send_impl(void* self, void*, void* target) {
    char rec[128];
    rec_text(self, rec, sizeof rec);
    zone::log("door_trace: ShineDoor %p appear BUILDDOOR 0x1C0F -> object %p: %s", self, target, rec);
    ((SendFn)g_send.trampoline)(self, 0, target);
}

}  // namespace

ZONEHOOK_PLUGIN("door_trace") {
    zone::hook_function("cDoorBuild", (void*)zone::fn::cDoorBuild(), (void*)cbuild_impl, &g_cbuild);
    zone::hook_function("cDoorAction", (void*)zone::fn::cDoorAction(), (void*)caction_impl, &g_caction);
    zone::hook_function("MapBlockInformation::mbi_DoorAction", (void*)zone::fn::MapBlock__MapBlockInformation__mbi_DoorAction(),
                        (void*)mbi_impl, &g_mbi);
    zone::hook_function("MapDoorArray::mda_CloseAllDoor", (void*)zone::fn::MapBlock__MapDoorArray__mda_CloseAllDoor(),
                        (void*)closeall_impl, &g_closeall);
    zone::hook_function("ShineDoor::so_door_Build", (void*)zone::fn::ShineObjectClass__ShineDoor__so_door_Build(),
                        (void*)build_impl, &g_build);
    zone::hook_function("ShineDoor::so_door_DoorAction", (void*)zone::fn::ShineObjectClass__ShineDoor__so_door_DoorAction(),
                        (void*)action_impl, &g_action);
    zone::hook_function("ShineDoor::so_SendMyBriefInfo", (void*)zone::fn::ShineObjectClass__ShineDoor__so_SendMyBriefInfo(),
                        (void*)send_impl, &g_send);
    zone::log("door_trace: up - door builds, state changes, collision changes and appear-sends are logged");
}
