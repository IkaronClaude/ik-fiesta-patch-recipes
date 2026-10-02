// mob_census - counts every mob spawn per map, to find what fills a zone's mob object pool (operator 2026-10-02: zone01
// lost its last ~1,540 spawns on every boot, "MobBreeder::mb_regen : Too many mob", although its regen tables ask for
// the same ~13,600 mobs as the day before - "you can deploy a hook to log etc. to try to trace it down"). DIAGNOSTIC:
// remove once found.
//
// Every mob spawn - regen tables (MobBreeder::mb_regen), scripted cMobRegen_XY, family members - ends in
// ShineMob::so_mob_Regenerate (0x4B41B0, thiscall, 13 stack args, ret 0x38); its first argument is the MAP name
// (Name3 = 12 chars, the Field.txt MapIDClient width). The detour is a naked thunk that counts [esp+4] and jumps on.
// Every 30 s (and on the first 2000 spawns in a burst) it logs the maps by spawns so far:
//     mob_census: 13612 spawns, 127 maps: Egma 1201, RouCos01 842, ...
#include <zonehook.h>

#include <windows.h>

#include <cstring>

namespace {

const unsigned kVaRegenerate = 0x004B41B0u;     // ShineMob::so_mob_Regenerate (2016 Zone.pdb)
const int kMaxMaps = 512;
const int kTop = 40;

struct MapCount {
    char name[13];
    unsigned n;
};

zone::Detour g_detour;
void* g_tramp = nullptr;
MapCount g_maps[kMaxMaps];
int g_nmaps = 0;
unsigned g_total = 0;
DWORD g_last_log = 0;
CRITICAL_SECTION g_cs;

// every map, biggest first, in log lines of ~30 maps; the name shown in hex too when it is not printable (a spawn whose
// map argument is not a map name)
void dump(const char* why) {
    static int order[kMaxMaps];
    for (int i = 0; i < g_nmaps; i++) order[i] = i;
    for (int i = 1; i < g_nmaps; i++)
        for (int k = i; k > 0 && g_maps[order[k]].n > g_maps[order[k - 1]].n; k--) {
            int t = order[k];
            order[k] = order[k - 1];
            order[k - 1] = t;
        }
    zone::log("mob_census (%s): %u spawns, %d maps", why, g_total, g_nmaps);
    char line[1536];
    int len = 0;
    for (int r = 0; r < g_nmaps; r++) {
        const MapCount& m = g_maps[order[r]];
        bool printable = m.name[0] != 0;
        for (int c = 0; m.name[c]; c++) printable &= m.name[c] >= 0x20 && m.name[c] < 0x7F;
        if (printable)
            len += wsprintfA(line + len, " %s %u,", m.name, m.n);
        else
            len += wsprintfA(line + len, " <%02x%02x%02x%02x> %u,", (unsigned char)m.name[0], (unsigned char)m.name[1],
                             (unsigned char)m.name[2], (unsigned char)m.name[3], m.n);
        if (len > 1400 || r == g_nmaps - 1) {
            zone::log("mob_census  %s", line);
            len = 0;
        }
    }
}

unsigned g_watch_logged = 0;
const char kWatch[] = "E_Olympic";      // the map whose spawns are logged one by one (the first kWatchMax of them)
const unsigned kWatchMax = 300;

void __stdcall count(const char* map, unsigned* args, void* self) {
    __try {
        if (g_watch_logged < kWatchMax && std::strncmp(map, kWatch, sizeof kWatch) == 0) {
            g_watch_logged++;
            zone::log("mob_census %s spawn #%u: this %p args x %d y %d a3 %d w4 %u w5 %u p6 %p k7 %u obj8 %p brd9 %p i10 %d",
                      kWatch, g_watch_logged, self, args[1], args[2], args[3], args[4] & 0xFFFF, args[5] & 0xFFFF,
                      (void*)args[6], args[7], (void*)args[8], (void*)args[9], args[10]);
        }
        EnterCriticalSection(&g_cs);
        char name[13];
        std::memcpy(name, map, 12);
        name[12] = 0;
        int i = 0;
        while (i < g_nmaps && std::strcmp(g_maps[i].name, name) != 0) i++;
        if (i == g_nmaps && g_nmaps < kMaxMaps) {
            std::memcpy(g_maps[i].name, name, 13);
            g_maps[i].n = 0;
            g_nmaps++;
        }
        if (i < g_nmaps) g_maps[i].n++;
        g_total++;
        DWORD now = GetTickCount();
        if (now - g_last_log > 30000) {
            g_last_log = now;
            dump("periodic");
        }
        LeaveCriticalSection(&g_cs);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

// thiscall: ecx = this, [esp] = return address, [esp+4] = the map name. Everything is preserved for the original.
__declspec(naked) void regenerate_thunk() {
    __asm {
        pushad
        pushfd
        push ecx                            // this (the ShineMob)
        lea eax, [esp + 4 + 36 + 4]         // the argument block: 4 (this) + 32 (pushad) + 4 (pushfd) + 4 (return address)
        push eax
        push dword ptr [esp + 8 + 36 + 4]   // the first argument (the map name)
        call count
        popfd
        popad
        jmp g_tramp
    }
}

}  // namespace

ZONEHOOK_PLUGIN("mob_census") {
    InitializeCriticalSection(&g_cs);
    g_last_log = GetTickCount();
    if (zone::hook_function("ShineMob::so_mob_Regenerate 0x4B41B0 (spawn census per map)", zone::rebase(kVaRegenerate),
                            (void*)regenerate_thunk, &g_detour)) {
        g_tramp = g_detour.trampoline;
        zone::log("mob_census: counting every mob spawn per map, top %d logged every 30 s", kTop);
    }
}
