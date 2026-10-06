// quest_name_probe - DIAGNOSTIC: log what the 2026 client resolves as the monster name of a quest kill line (Fiesta2026on2016
// ticket "QUEST KILL POPUP EMPTY FOR BATS", operator 2026-09-25 / 2026-10-03: "A sign of crisis" and "Don't Be Fooled by
// the Looks" show "- 2/10" with no monster name).
//
// ---- THE CLIENT CODE (2026 Fiesta.exe, 10.6.6 addresses, read 2026-10-06) ----------------------------------------------
//   The objective rows are the client's QuestEndNpc (+0 quest, +2 IsEnabled, +3 MobID, +5 Group, +6 NpcMobActionType,
//   +0xA Count). Two builders format a kill line, each right after looking the mob up in MobInfo (eax = the row or 0):
//     KillLineWindow 0x7EE074  cmp byte [esi+5],0 ; jne   (quest window: "- %d/%d %s")
//     KillLinePopup  0x7346A3  cmp byte [edi+5],0 ; jne   (objective popup: "%s %d/%d")
//   Group 0 prints MobLoca[MobInfo+0x22] (MobLocaName 0x8FB6B0, cdecl); Group 1..4 the MobViewInfo Group1/2/3/S text.
//   The data is right in the played client (checked 2026-10-06), so the empty name is runtime - this logs it.
//
// ---- THIS PLUGIN ------------------------------------------------------------------------------------------------------
//   Both sites jump to a stub that logs {site, quest, mob, group, type, count, MobInfo row, name id, resolved name} ONCE
//   per distinct (site, quest, mob, group, name) and then runs the two stock instructions. Remove once the cause is known.
#include <hook_core.h>
#include <client_addrs.h>

#include <windows.h>

#include <cstring>

namespace {

const unsigned kMobName = 0x22;            // MobInfo row: u32 MobLoca name id
const unsigned char kStockWindow[4] = {0x80, 0x7E, 0x05, 0x00};   // cmp byte ptr [esi+5], 0 ; then 75 rel8 (jne)
const unsigned char kStockPopup[4] = {0x80, 0x7F, 0x05, 0x00};    // cmp byte ptr [edi+5], 0 ; then 75 rel8

typedef const char*(__cdecl* NameFn)(unsigned);
NameFn g_name = nullptr;
void* g_backW = nullptr;
void* g_takenW = nullptr;
void* g_backP = nullptr;
void* g_takenP = nullptr;

unsigned g_seen[512];
int g_nseen = 0;

bool seen(unsigned key) {
    for (int i = 0; i < g_nseen; i++)
        if (g_seen[i] == key) return true;
    if (g_nseen < 512) g_seen[g_nseen++] = key;
    return false;
}

const char* name_of(unsigned id) {
    __try {
        const char* s = g_name(id);
        return s ? s : "(null)";
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return "(fault)";
    }
}

void __cdecl probe(int site, const unsigned char* obj, const unsigned char* mob) {
    __try {
        unsigned quest = *(const unsigned short*)obj, mobid = *(const unsigned short*)(obj + 3), group = obj[5];
        unsigned type = *(const unsigned*)(obj + 6), count = *(const unsigned*)(obj + 0xA);
        unsigned nid = mob ? *(const unsigned*)(mob + kMobName) : 0;
        const char* nm = mob ? name_of(nid) : "(no MobInfo row)";
        unsigned key = (unsigned)site * 2654435761u ^ quest * 40503u ^ mobid * 97u ^ group ^ nid;
        if (seen(key)) return;
        char nbuf[48];
        int k = 0;
        for (; nm[k] && k < 40; k++) nbuf[k] = (nm[k] >= 32 && nm[k] < 127) ? nm[k] : '?';
        nbuf[k] = 0;
        hook::log("quest_name_probe: %s quest %u mob %u group %u type %u count %u MobInfo %p name id %u -> \"%s\" (len %d)",
                  site ? "popup" : "window", quest, mobid, group, type, count, mob, nid, nbuf, (int)std::strlen(nm));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook::log("quest_name_probe: fault reading site %d obj %p mob %p", site, obj, mob);
    }
}

__declspec(naked) void stub_window() {
    __asm {
        pushad
        push eax
        push esi
        push 0
        call probe
        add esp, 12
        popad
        cmp byte ptr [esi + 5], 0
        jne taken
        jmp g_backW
    taken:
        jmp g_takenW
    }
}

__declspec(naked) void stub_popup() {
    __asm {
        pushad
        push eax
        push edi
        push 1
        call probe
        add esp, 12
        popad
        cmp byte ptr [edi + 5], 0
        jne taken
        jmp g_backP
    taken:
        jmp g_takenP
    }
}

bool divert(unsigned char* at, const unsigned char* stock, void* to, void** back, void** taken) {
    if (std::memcmp(at, stock, 4) != 0 || at[4] != 0x75) return false;
    *back = at + 6;
    *taken = at + 6 + (signed char)at[5];
    unsigned char b[6] = {0xE9, 0, 0, 0, 0, 0x90};
    int rel = (int)((unsigned char*)to - (at + 5));
    std::memcpy(b + 1, &rel, 4);
    return hook::write_code(at, b, sizeof b);
}

}  // namespace

HOOK_PLUGIN("quest_name_probe") {
    if (const char* m = caddr::missing({caddr::kKillLineWindow, caddr::kKillLinePopup, caddr::kMobLocaName})) {
        hook::log("quest_name_probe: %s - not hooked", m);
        return;
    }
    g_name = (NameFn)hook::rebase(caddr::va(caddr::kMobLocaName));
    bool w = divert((unsigned char*)hook::rebase(caddr::va(caddr::kKillLineWindow)), kStockWindow, (void*)stub_window,
                    &g_backW, &g_takenW);
    bool p = divert((unsigned char*)hook::rebase(caddr::va(caddr::kKillLinePopup)), kStockPopup, (void*)stub_popup,
                    &g_backP, &g_takenP);
    hook::log("quest_name_probe: window site %s, popup site %s - kill one quest monster and read the lines below",
              w ? "hooked" : "NOT hooked (unexpected bytes)", p ? "hooked" : "NOT hooked (unexpected bytes)");
}
