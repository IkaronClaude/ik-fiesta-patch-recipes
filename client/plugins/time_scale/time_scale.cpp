// time_scale - the official client's VISUAL time slowed / sped for frame-by-frame captures, matching fiesta-godot's
// FiestaClock.set_visual_scale (test option --slow-after N S): both clients' animations then line up (operator
// 2026-10-23). Cooldowns and movement stay REAL time (operator: "the 2 truly time-based elements").
//
// ---- THE CLIENT CODE (Gamebryo inside the 2026 Fiesta.exe; 2016 PDB names) -------------------------------------------
//   Every NIF animation runs on the app time handed to three entry points, which use it ONLY for controllers:
//     NiAVObject::Update(float fTime, bool)   2016 0x821490 / 10.6.6 0x984070 (thiscall, ret 8)
//     NiAVObject::UpdateSelected(float fTime) 2016 0x8214D0 / 10.6.6 0x984350 (thiscall, ret 4)
//     NiActorManager::Update(float fTime)     2016 0x7C91F0 / 10.6.6 0x926E90 (thiscall, ret 4) - characters' KF
//   Positions are written by game code (Char movement) and cooldowns are game timers: neither passes through these.
//
// ---- THIS PLUGIN ----------------------------------------------------------------------------------------------------
//   The time argument becomes t0 + (t - t0) * scale (t0 = the first time seen, so the clock stays continuous).
//   hooks\time_scale.ini:  [plugin] enabled=1   [config] scale=0.1   (no file / scale 1 = stock).
//   KNOWN GAP: the game's own Effect lifetimes run on real time - a slowed effect can end before its animation does.
#include <hook_core.h>
#include <client_addrs.h>

#include <cstdlib>

namespace {

hook::Detour g_upd, g_sel, g_act;
double g_scale = 1.0;
bool g_have = false;
float g_t0 = 0.0f;

float virt(float t) {
    if (!g_have) {
        g_have = true;
        g_t0 = t;
    }
    return g_t0 + (float)((double)(t - g_t0) * g_scale);
}

void __fastcall upd_impl(void* self, void*, float t, bool controllers) {
    typedef void(__fastcall * Orig)(void*, void*, float, bool);
    ((Orig)g_upd.trampoline)(self, nullptr, virt(t), controllers);
}

void __fastcall sel_impl(void* self, void*, float t) {
    typedef void(__fastcall * Orig)(void*, void*, float);
    ((Orig)g_sel.trampoline)(self, nullptr, virt(t));
}

void __fastcall act_impl(void* self, void*, float t) {
    typedef void(__fastcall * Orig)(void*, void*, float);
    ((Orig)g_act.trampoline)(self, nullptr, virt(t));
}

}  // namespace

HOOK_PLUGIN("time_scale") {
    if (const char* m = caddr::missing({caddr::kNiAVObjectUpdate, caddr::kNiAVObjectUpdateSelected, caddr::kNiActorManagerUpdate})) {
        hook::log("time_scale: %s - not hooked", m);
        return;
    }
    if (!hook::ini_opted_in()) {
        hook::log("time_scale.ini does not say enabled=1 - real time (stock)");
        return;
    }
    char buf[32];
    hook::config_str("scale", "1", buf, sizeof buf);
    g_scale = std::atof(buf);
    if (!(g_scale > 0.0) || g_scale == 1.0) {
        hook::log("time_scale: scale %s - real time (stock)", buf);
        return;
    }
    // logged BEFORE hooking, and without %f: hook::log is a small formatter (a %.3f here faulted inside DllMain after the
    // hooks were in -> the loader unloaded the DLL with live detours -> the client crashed on the next scene update)
    hook::log("time_scale: visual time x %s (movement / cooldowns stay real time)", buf);
    bool ok = hook::hook_function("NiAVObject::Update", hook::rebase(caddr::va(caddr::kNiAVObjectUpdate)), (void*)upd_impl, &g_upd)
           && hook::hook_function("NiAVObject::UpdateSelected", hook::rebase(caddr::va(caddr::kNiAVObjectUpdateSelected)), (void*)sel_impl, &g_sel)
           && hook::hook_function("NiActorManager::Update", hook::rebase(caddr::va(caddr::kNiActorManagerUpdate)), (void*)act_impl, &g_act);
    hook::log("time_scale: %s", ok ? "hooked" : "a hook FAILED");
}
