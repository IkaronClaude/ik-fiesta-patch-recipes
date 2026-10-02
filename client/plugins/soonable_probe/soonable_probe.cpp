// soonable_probe - DIAGNOSTIC: why does the 2026 client leave a quest out of its "Available" list?
//
// Operator 2026-10-02: Kiera's Tears (60211) never shows under "Available" although the Shiny Elemental Stone (its start
// item) is in the bag - not after the hand-in that gives it, not after a relog. Static reading of the client says every
// condition passes, so this probe logs what the client ACTUALLY computes:
//
//   CQuest::IsSoonableQuest(row)  Fiesta.exe 0x900260 (thiscall, ret 4): level+5 >= LvlStart (+0x15) and level <= LvlEnd
//     (+0x16) when LvlStart != 0; if Type (+0x14) & 0x20: vtable+0x68(ItemID +0x1A) >= ItemLot (+0x1C); PrevQuestID (+0x3A)
//     done (status 2 / 4); race +0x3C, class +0x3E, gender +0x40, Type & 0x40, DateMode +0x48.
//   the per-quest state 0x8FF5C0 (thiscall, ret 4): the player's own entry first (this+0xC, 0x25 B each), else the above
//     -> 5 / 3 / ...
// For every quest id in kWatch it logs the inputs (level via vtable+0x64, item count via vtable+0x68) and both results
// whenever any of them changes - so the log stays small while the quest window refreshes every frame.

#include <hook_core.h>

#include <windows.h>

#include <cstdio>
#include <map>

namespace {

const unsigned kVaIsSoonable = 0x00900260u;
const unsigned kVaQuestState = 0x008FF5C0u;
const unsigned short kWatch[] = {60211, 60212, 60207};

hook::Detour g_soonable, g_state;

struct Seen {
    int level = -1, count = -1, soon = -1, state = -1;
};
std::map<unsigned short, Seen>* g_seen = nullptr;

bool watched(unsigned short id) {
    for (unsigned short w : kWatch)
        if (w == id) return true;
    return false;
}

void report(void* self, const unsigned char* row, int soon, int state) {
    const unsigned short id = *(const unsigned short*)row;
    const unsigned char type = row[0x14];
    const unsigned short item = *(const unsigned short*)(row + 0x1A), lot = *(const unsigned short*)(row + 0x1C);
    void** vt = *(void***)self;
    const int level = ((unsigned char (__thiscall*)(void*))vt[0x64 / 4])(self);
    const int count = (type & 0x20) ? ((unsigned short (__thiscall*)(void*, unsigned short))vt[0x68 / 4])(self, item) : -2;
    Seen& s = (*g_seen)[id];
    const int st = state >= 0 ? state : s.state, so = soon >= 0 ? soon : s.soon;
    if (s.level == level && s.count == count && s.soon == so && s.state == st) return;
    s.level = level, s.count = count, s.soon = so, s.state = st;
    hook::log("soonable_probe: quest %u type 0x%02X lv %u-%u item %u x%u | player lv %d, item count %d | IsSoonable %d, "
              "state %d, prev %u", id, type, row[0x15], row[0x16], item, lot, level, count, so, st,
              *(const unsigned short*)(row + 0x3A));
}

int __fastcall is_soonable(void* self, void*, const unsigned char* row) {
    const int r = ((int (__fastcall*)(void*, void*, const unsigned char*))g_soonable.trampoline)(self, nullptr, row);
    __try {
        if (row && watched(*(const unsigned short*)row)) report(self, row, r, -1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return r;
}

int __fastcall quest_state(void* self, void*, const unsigned char* row) {
    const int r = ((int (__fastcall*)(void*, void*, const unsigned char*))g_state.trampoline)(self, nullptr, row);
    __try {
        if (row && watched(*(const unsigned short*)row)) report(self, row, -1, r);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return r;
}

}  // namespace

HOOK_PLUGIN("soonable_probe") {
    g_seen = new std::map<unsigned short, Seen>();
    hook::hook_function("CQuest::IsSoonableQuest 0x900260 (probe)", hook::rebase(kVaIsSoonable), (void*)is_soonable,
                        &g_soonable);
    hook::hook_function("CQuest quest state 0x8FF5C0 (probe)", hook::rebase(kVaQuestState), (void*)quest_state, &g_state);
}
