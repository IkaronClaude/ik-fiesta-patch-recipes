// mob_ai_log - logs the mob AI's state changes, to find why a mob stops chasing (operator 2026-10-01: "mobs ... aggro you,
// do a single attack and you walk out of attack range and then they just stand there"; "a persistent 2016 server bug I
// want to fix"; "you'll need to write a logging hook to figure it out"). A DIAGNOSTIC plugin: remove it once fixed.
//
// The mob AI is a state machine of MobTacticElement::MobAction* objects; each tick the mob's current action's
// mab_Think(MobActionArgument*) (vtable slot 0, thiscall, ret 4) returns the next action. The argument holds the mob at +4
// (MobActionSwingDamage::mab_Think 0x4BAAC0 reads [arg+4]). ShineObject handle = u16 at +4 (so_GetZoneHandle 0x428390),
// a mob's current target = u16 at +0x24AE (ShineMob::so_mob_CurrentTarget 0x5D2790). The built-in hook for exactly this,
// ShineMob::sm_TacticDebugging (vtable +0x10), is an empty stub with no callers left in the release build.
//
// Every mab_Think is detoured; a line is written when a mob's action CLASS changes while it has a target, or when it
// leaves a combat state (Attack / SwingDamage / WaitSkillEnd / Chase / InChase / Turning):
//     mob 5123 tgt 12000: MobActionSwingDamage -> MobActionWaitSkillEnd
// A mob that freezes shows as its last line with no follow-up. Classes from the 2016 Zone.pdb.
#include <zonehook.h>

#include <windows.h>

#include <cstring>

namespace {

struct ThinkSite {
    unsigned va;
    const char* name;
    bool combat;
};

const ThinkSite kSites[] = {
    {0x004B8C50, "MobActionNoBrain", false},     {0x004B8EC0, "MobActionBase", false},
    {0x004B8F10, "MobActionInMove", false},      {0x004B9010, "DuringReturn2Regen", false},
    {0x004B9140, "MobActionWaitSkillEnd", true}, {0x004B9760, "MobActionInChase", true},
    {0x004B99E0, "MobActionTargetting", false},  {0x004B9EA0, "MobActionTurning", true},
    {0x004BA1D0, "MobAction2Region", false},     {0x004BA390, "MobActionBackStep", false},
    {0x004BA750, "MobActionAvoidOverlap", false}, {0x004BAAC0, "MobActionSwingDamage", true},
    {0x004BB790, "MobActionWander", false},      {0x004BBA00, "MobActionAttack", true},
    {0x004BC3A0, "MobActionRoaming", false},     {0x004BC950, "MobActionChase", true},
};
const int kNumSites = sizeof kSites / sizeof kSites[0];

const unsigned kOffArgMob = 4, kOffHandle = 4, kOffTarget = 0x24AE, kOffDataBox = 0x1F90;
const unsigned kOnlyMob = 519;                          // MobInfo "Miner" (Burning Rock), the mob under investigation
const unsigned kMaxHandle = 0x5000;

zone::Detour g_detours[kNumSites];
unsigned char g_last[kMaxHandle];                       // last action site + 1 per mob handle (0 = none)

typedef void*(__fastcall* ThinkFn)(void* action, void* edx, void* arg);

// the class of a returned action object, by its vtable's RTTI (MSVC: vtable[-1] -> COL, +0xC -> TypeDescriptor, +8 name)
const char* class_of(void* obj) {
    __try {
        if (!obj) return "null";
        char* col = (char*)(*(void***)obj)[-1];
        const char* n = *(char**)(col + 0xC) + 8;        // ".?AVMobActionChase@MobTacticElement@@"
        return n;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return "?";
    }
}

int site_of_class(const char* rtti) {
    for (int i = 0; i < kNumSites; i++) {
        size_t n = std::strlen(kSites[i].name);
        if (std::strncmp(rtti + 4, kSites[i].name, n) == 0 && rtti[4 + n] == '@') return i;
    }
    return -1;
}

void* think(int site, void* action, void* arg) {
    void* next = ((ThinkFn)g_detours[site].trampoline)(action, 0, arg);
    __try {
        char* mob = arg ? *(char**)((char*)arg + kOffArgMob) : nullptr;
        if (!mob) return next;
        // only the one mob being investigated - every other mob returns here, before any RTTI / logging (operator
        // 2026-10-01: "The zone is lagging wayyyy too hard ... restrict to only 'Miner' enemy in Burning Rock" / "519").
        // MobInfo ID = [[mob + 0x1F90]] u16 (ShineMob::so_mob_MobID 0x556AB0)
        char* box = *(char**)(mob + kOffDataBox);
        if (!box || *(unsigned short*)(*(char**)box) != kOnlyMob) return next;
        unsigned h = *(unsigned short*)(mob + kOffHandle);
        unsigned tgt = *(unsigned short*)(mob + kOffTarget);
        int to = next ? site_of_class(class_of(next)) : -1;
        if (h >= kMaxHandle) return next;
        int from = site;
        if (to == from && g_last[h] == from + 1) return next;   // no change
        bool interesting = tgt != 0 || kSites[from].combat;
        g_last[h] = (unsigned char)(to + 1);
        if (interesting)
            zone::log("mob %u tgt %u: %s -> %s", h, tgt, kSites[from].name,
                      to >= 0 ? kSites[to].name : (next ? class_of(next) : "null"));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return next;
}

#define THINK_IMPL(N) \
    void* __fastcall think_##N(void* action, void* /*edx*/, void* arg) { return think(N, action, arg); }
THINK_IMPL(0) THINK_IMPL(1) THINK_IMPL(2) THINK_IMPL(3) THINK_IMPL(4) THINK_IMPL(5) THINK_IMPL(6) THINK_IMPL(7)
THINK_IMPL(8) THINK_IMPL(9) THINK_IMPL(10) THINK_IMPL(11) THINK_IMPL(12) THINK_IMPL(13) THINK_IMPL(14) THINK_IMPL(15)
void* const kImpls[] = {(void*)think_0,  (void*)think_1,  (void*)think_2,  (void*)think_3,  (void*)think_4,  (void*)think_5,
                        (void*)think_6,  (void*)think_7,  (void*)think_8,  (void*)think_9,  (void*)think_10, (void*)think_11,
                        (void*)think_12, (void*)think_13, (void*)think_14, (void*)think_15};
static_assert(sizeof kImpls / sizeof kImpls[0] == kNumSites, "one impl per site");

}  // namespace

ZONEHOOK_PLUGIN("mob_ai_log") {
    int n = 0;
    for (int i = 0; i < kNumSites; i++) {
        char what[96];
        wsprintfA(what, "%s::mab_Think 0x%X", kSites[i].name, kSites[i].va);
        if (zone::hook_function(what, zone::rebase(kSites[i].va), kImpls[i], &g_detours[i])) n++;
    }
    zone::log("mob_ai_log: %d of %d mab_Think detoured - logging mob AI state changes", n, kNumSites);
}
