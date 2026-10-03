// miss_keeps_cast - an enemy attack that MISSES no longer cancels a cast in progress (mount summon, item cast bars,
// skill casts) (Fiesta2026on2016 QoL, operator 2026-10-03: "make it so an enemy attack that misses doesn't cancel mounting").
//
// Gameplay, not parity: active only when 9Data/Shine/MissKeepsCast.flag exists (migrations-qol writes it).
//
// ---- THE STOCK PATH (read from Zone.exe) --------------------------------------------------------------------------------
//   ShineMobileObject::smo_AttackedDamage(victim, damage, EngageArgument*) (0x42AEB0), run on the ATTACKER after a swing:
//   its normal path (0x42AFD1) calls victim->so_DamagedBy(attacker, damage, 1000, 1) (vtable 0x5BC / 0x5C0) with the last
//   argument 1 whatever the result - a miss arrives with damage 0 and EngageArgument.ismiss (+0x11) set.
//   ShinePlayer::so_DamagedBy(by, damage, ?, cancel) (0x431500): subtracts the damage, then `if (cancel)`
//   so_ply_AllCastCancel (vtable 0x8D0) - every cast in progress, the mount summon's cast bar included.
//
// ---- THIS PLUGIN --------------------------------------------------------------------------------------------------------
//   smo_AttackedDamage is detoured: when the engagement is a miss, the call runs with a "miss" mark set; ShinePlayer::
//   so_DamagedBy is detoured: while the mark is set it passes cancel = 0. A hit (any damage, even 0 from a block or an
//   immunity) is untouched - only EngageArgument.ismiss changes anything.

#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cstdio>

namespace {

const char* kFlag = "../9Data/Shine/MissKeepsCast.flag";
zone::Detour g_attacked, g_damaged;
int g_miss_depth = 0;                        // zone game logic runs on one thread
unsigned g_kept = 0;

void __fastcall attacked_damage(void* self, void*, zone::types::ShineObjectClass__ShineObject* victim, int damage,
                                zone::types::EngageArgument* eng) {
    const bool miss = eng && eng->ismiss;
    if (miss) ++g_miss_depth;
    ((void (__fastcall*)(void*, void*, zone::types::ShineObjectClass__ShineObject*, int, zone::types::EngageArgument*))
         g_attacked.trampoline)(self, nullptr, victim, damage, eng);
    if (miss) --g_miss_depth;
}

void __fastcall damaged_by(void* self, void*, zone::types::ShineObjectClass__ShineObject* by, int damage, int a3,
                           unsigned char cancel) {
    if (cancel && g_miss_depth > 0) {
        cancel = 0;
        if (g_kept++ < 50 || g_kept % 1000 == 0) zone::log("miss_keeps_cast: a missed attack did not cancel a cast (#%u)", g_kept);
    }
    ((void (__fastcall*)(void*, void*, zone::types::ShineObjectClass__ShineObject*, int, int, unsigned char))g_damaged.trampoline)(
        self, nullptr, by, damage, a3, cancel);
}

}  // namespace

HOOK_PLUGIN("miss_keeps_cast") {
    if (FILE* f = std::fopen(kFlag, "rb")) {
        std::fclose(f);
    } else {
        zone::log("no %s - misses cancel casts as stock", kFlag);
        return;
    }
    zone::hook_function("ShineMobileObject::smo_AttackedDamage (mark misses)",
                        (void*)zone::fn::ShineObjectClass__ShineMobileObject__smo_AttackedDamage(), (void*)attacked_damage, &g_attacked);
    zone::hook_function("ShinePlayer::so_DamagedBy (a miss keeps the cast)",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__so_DamagedBy(), (void*)damaged_by, &g_damaged);
}
