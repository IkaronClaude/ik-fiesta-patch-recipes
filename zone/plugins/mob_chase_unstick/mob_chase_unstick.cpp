// mob_chase_unstick - a mob that has aggroed you but stands just out of reach walks the rest of the way (operator
// 2026-10-03: "They frequently aggro and just stand around for 30+ seconds unable to attack, just sitting there, but if I
// move a few mm, then they all hit"; the Cursed Mandragora "stand ~1 attack range away and do nothing").
//
// FOUND with the diagnostic plugin mob_ai_log on Island of Eya (Void Muru Muru, 13,543 state changes): no swing at all,
//     MobActionAttack -> MobActionChase  3,511x
//     MobActionChase  -> MobActionAttack 3,452x
// The two actions disagree about the distance and neither moves the mob:
//   * MobActionAttack::mab_Think (Zone.exe 0x4BBA00) swings only while target.so_DistanceSquar(mob) <= R*R with
//     R = ShineMob::so_AttackRange(target) (0x5566C0: the current MobWeapon row's Range + the target's body radius,
//     target vtable +0x6CC); otherwise -> Chase.
//   * MobActionChase::mab_Think (0x4BC950) issues a new run (mab_RunTo 0x4B9590 + InChase) only on one branch; when the
//     TARGET's own move destination (target vtable +0x60C, so_mobile_Move2Where) lies on the far side of the target as
//     seen from the mob - a target standing still, its destination = where it stands - it takes the predictive branch
//     (0x4BCB8F), which can return to Attack without moving the mob at all. The mob stalls one step short; any step the
//     player takes changes the destination and the loop breaks - "move a few mm and they all hit".
//
// THE FIX: after MobActionChase::mab_Think returns an Attack action (by RTTI class) while its
// target (Attack's target slot, the pointer at [arg+0x2BC]) is still out of attack range AND the mob has not moved for
// kStuckTicks thinks, the mob is sent to the target's position with the zone's own MobActionBase::mab_RunTo(mob, &pos) -
// the call Chase itself makes on its normal branch. Everything else is untouched; a mob that is moving or in range is
// left to the stock code. Logged (first 20 and every 500th) with the distances.
#include <zonehook.h>

#include <windows.h>

#include <cstring>

namespace {

const unsigned kVaChaseThink = 0x004BC950u;     // MobActionChase::mab_Think
const unsigned kVaRunTo = 0x004B9590u;          // MobActionBase::mab_RunTo(ShineMobileObject*, SHINE_XY_TYPE*), thiscall
const unsigned kVaDistanceSquar = 0x004028F0u;  // ShineObject::so_DistanceSquar(ShineObject*) -> u32, thiscall
const unsigned kOffArgMob = 4, kOffArgAttackTarget = 0x2BC;   // the embedded Attack action is at arg+0x2B8
const unsigned kOffPos = 0x66;                  // ShineObject -> SHINE_XY_TYPE* {x, y}
const unsigned kOffHandle = 4;
const int kSlotAttackRange = 0x510 / 4;         // ShineObject vtable: so_AttackRange(ShineObject* target) -> u32
const unsigned kMaxHandle = 0x10000;
const int kStuckTicks = 3;

struct Last {
    int x, y;
    unsigned char ticks;
};
Last g_last[kMaxHandle];
unsigned g_runs = 0;

zone::Detour g_think;

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

typedef void*(__fastcall* ThinkFn)(void* action, void* edx, void* arg);
typedef unsigned(__fastcall* RangeFn)(void* self, void* edx, void* target);
typedef unsigned(__fastcall* DistFn)(void* self, void* edx, void* other);
typedef void(__fastcall* RunToFn)(void* action, void* edx, void* mob, int* xy);

void* __fastcall think_impl(void* action, void* /*edx*/, void* arg) {
    void* next = ((ThinkFn)g_think.trampoline)(action, 0, arg);
    __try {
        if (!arg || !is_class(next, "MobActionAttack")) return next;
        char* mob = *(char**)((char*)arg + kOffArgMob);
        void** slot = *(void***)((char*)arg + kOffArgAttackTarget);
        char* target = slot ? (char*)*slot : nullptr;
        if (!mob || !target) return next;
        unsigned h = *(unsigned short*)(mob + kOffHandle);
        int* pos = *(int**)(mob + kOffPos);
        int* tpos = *(int**)(target + kOffPos);
        if (!pos || !tpos || h >= kMaxHandle) return next;
        unsigned d2 = ((DistFn)zone::rebase(kVaDistanceSquar))(target, 0, mob);
        unsigned r = ((RangeFn)(*(void***)mob)[kSlotAttackRange])(mob, 0, target);
        Last& l = g_last[h];
        if (d2 <= r * r) {                       // in reach: Attack swings, nothing to do
            l.ticks = 0;
            return next;
        }
        if (l.x == pos[0] && l.y == pos[1]) {
            if (l.ticks < 255) l.ticks++;
        } else {
            l.x = pos[0], l.y = pos[1], l.ticks = 0;
        }
        if (l.ticks < kStuckTicks) return next;
        l.ticks = 0;
        int dest[2] = {tpos[0], tpos[1]};
        ((RunToFn)zone::rebase(kVaRunTo))(action, 0, mob, dest);
        if (++g_runs <= 20 || g_runs % 500 == 0)
            zone::log("mob_chase_unstick: mob %u stood out of reach of its target (distance^2 %u > range %u^2) - sent to (%d, %d); "
                      "%u so far", h, d2, r, dest[0], dest[1], g_runs);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return next;
}

}  // namespace

ZONEHOOK_PLUGIN("mob_chase_unstick") {
    if (zone::hook_function("MobActionChase::mab_Think 0x4BC950 (run the rest of the way when stalled out of reach)",
                            zone::rebase(kVaChaseThink), (void*)think_impl, &g_think))
        zone::log("mob_chase_unstick: installed - a mob stalled out of reach is sent to its target");
}
