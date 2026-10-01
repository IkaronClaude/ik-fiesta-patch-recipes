// mob_chase_after_swing - a mob keeps chasing its target after a melee swing (a 2016 server bug, fixed for every product;
// operator 2026-10-01: "mobs (e.g. miner moles) will aggro you, do a single attack and you walk out of attack range and
// then they just stand there instead of following you"; "a persistent 2016 server bug I want to fix").
//
// FOUND with the diagnostic plugin mob_ai_log on Burning Rock's Miners (MobInfo 519), the mob AI state machine
// (MobTacticElement::MobAction*, each tick current->mab_Think(arg) returns the next action):
//     Targetting -> Attack -> WaitSkillEnd -> SwingDamage -> WaitSkillEnd -> Targetting -> Wander   (target dropped)
// while a Miner that had not swung yet chased fine (Attack -> Chase -> InChase ...). After every swing
// MobActionWaitSkillEnd hands the mob back to MobActionTargetting, which re-picks the target from the aggro selector
// (MobTargetSelector::mts_TargetObject) with a can-see check - and a player who stepped away during the swing is outside
// its pick-up range though well inside the chase range, so the target is cleared (sm_CurrentTarget -> 0xFFFF) and the
// mob wanders: "stands there". Whether it happens depends only on where the player is when the swing ends - "random".
//
// THE FIX: when MobActionWaitSkillEnd::mab_Think (Zone.exe 0x4B9140) returns the Targetting action while the mob still
// has a target, the mob's own Attack action is returned instead - what Targetting itself returns when it keeps a target:
// the Attack action is EMBEDDED in the argument at +0x2B8 (MobActionTargetting::mab_Think 0x4B99E0 returns
// `lea eax, [arg+0x2B8]` after storing the kept target through the pointer at [arg+0x2BC] - Attack's target slot, which
// still holds the target it just swung at). (First try read [arg+0x2BC] as the Attack object: wrong, the RTTI check
// refused it and the fix never fired - operator 2026-10-01: "Not fixed, same issue just happened again".) Attack then chases an out-of-reach target (Attack -> Chase) or
// lets it go by its own checks (can-see, dead, leash). Only that one post-swing step changes; first contact, losing a
// target out of sight, the return to regen are untouched. arg+4 = the mob (MobActionSwingDamage::mab_Think 0x4BAAC0),
// mob+0x24AE = its current target handle (ShineMob::so_mob_CurrentTarget 0x5D2790; 0xFFFF = none).
#include <zonehook.h>

#include <windows.h>

#include <cstring>

namespace {

const unsigned kVaWaitSkillEndThink = 0x004B9140u;
const unsigned kOffArgMob = 4, kOffArgAttack = 0x2B8, kOffTarget = 0x24AE;
const unsigned short kNoTarget = 0xFFFF;

zone::Detour g_think;
unsigned g_kept = 0;

typedef void*(__fastcall* ThinkFn)(void* action, void* edx, void* arg);

// exact class name of an action object by RTTI (".?AVMobActionAttack@MobTacticElement@@")
bool is_class(void* obj, const char* cls) {
    __try {
        if (!obj) return false;
        char* col = (char*)(*(void***)obj)[-1];
        const char* n = *(char**)(col + 0xC) + 8;
        size_t k = std::strlen(cls);
        return std::strncmp(n, ".?AV", 4) == 0 && std::strncmp(n + 4, cls, k) == 0 && n[4 + k] == '@';
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void* __fastcall think_impl(void* action, void* /*edx*/, void* arg) {
    void* next = ((ThinkFn)g_think.trampoline)(action, 0, arg);
    __try {
        if (!arg || !is_class(next, "MobActionTargetting")) return next;
        char* mob = *(char**)((char*)arg + kOffArgMob);
        if (!mob || *(unsigned short*)(mob + kOffTarget) == kNoTarget) return next;
        void* attack = (char*)arg + kOffArgAttack;         // the embedded MobActionAttack
        if (!is_class(attack, "MobActionAttack")) return next;
        if (++g_kept <= 20 || g_kept % 1000 == 0)
            zone::log("mob_chase_after_swing: mob %u keeps target %u after its swing (Attack instead of Targetting; %u so far)",
                      *(unsigned short*)(mob + 4), *(unsigned short*)(mob + kOffTarget), g_kept);
        return attack;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return next;
    }
}

}  // namespace

ZONEHOOK_PLUGIN("mob_chase_after_swing") {
    if (zone::hook_function("MobActionWaitSkillEnd::mab_Think 0x4B9140 (keep the target after a swing)",
                            zone::rebase(kVaWaitSkillEndThink), (void*)think_impl, &g_think))
        zone::log("mob_chase_after_swing: installed - a mob goes back to Attack, not Targetting, after its swing");
}
