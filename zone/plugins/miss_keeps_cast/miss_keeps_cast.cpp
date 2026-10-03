// miss_keeps_cast - only an attack that actually deals damage cancels a cast in progress (mount summon, item cast bars,
// skill casts); a miss, a block or an absorbed hit no longer does (Fiesta2026on2016 QoL, operator 2026-10-03: "make it so an
// enemy attack that misses doesn't cancel mounting" - "0 damage blocks/immunities e.g. through the priest skill that blocks
// damage should also not cancel it. Only when a hit breaks that shield and actually connects and deals > 0 damage should it
// cancel").
//
// Gameplay, not parity: active only when 9Data/Shine/MissKeepsCast.flag exists (migrations-qol writes it).
//
// ---- THE STOCK PATH (read from Zone.exe) --------------------------------------------------------------------------------
//   ShinePlayer::so_DamagedBy(by, damage, ?, cancel) (0x431500, vtable 0x5C0): subtracts the damage from HP, then
//   `if (cancel)` so_ply_AllCastCancel (vtable 0x8D0) - every cast in progress, the mount summon's cast bar included.
//   Its callers pass cancel = 1 whatever the result: ShineMobileObject::smo_AttackedDamage (0x42AEB0) after a swing - a miss
//   with damage 0 (EngageArgument.ismiss), the damage-absorbing states (abstates 0xC9 / 0xCA branches: damage 0) - and the
//   skill / damage-over-time paths. The damage it gets is what the hit really takes from HP.
//
// ---- THIS PLUGIN --------------------------------------------------------------------------------------------------------
//   ShinePlayer::so_DamagedBy is detoured: cancel is passed on only when damage > 0. A hit that breaks a shield and lands
//   (damage > 0) cancels as before.

#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cstdio>

namespace {

const char* kFlag = "../9Data/Shine/MissKeepsCast.flag";
zone::Detour g_damaged;
unsigned g_kept = 0;

void __fastcall damaged_by(void* self, void*, zone::types::ShineObjectClass__ShineObject* by, int damage, int a3,
                           unsigned char cancel) {
    if (cancel && damage <= 0) {
        cancel = 0;
        if (g_kept++ < 50 || g_kept % 1000 == 0)
            zone::log("miss_keeps_cast: an attack that dealt no damage did not cancel a cast (#%u)", g_kept);
    }
    ((void (__fastcall*)(void*, void*, zone::types::ShineObjectClass__ShineObject*, int, int, unsigned char))g_damaged.trampoline)(
        self, nullptr, by, damage, a3, cancel);
}

}  // namespace

HOOK_PLUGIN("miss_keeps_cast") {
    if (FILE* f = std::fopen(kFlag, "rb")) {
        std::fclose(f);
    } else {
        zone::log("no %s - every hit result cancels casts as stock", kFlag);
        return;
    }
    zone::hook_function("ShinePlayer::so_DamagedBy (only damage > 0 cancels a cast)",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__so_DamagedBy(), (void*)damaged_by, &g_damaged);
}
