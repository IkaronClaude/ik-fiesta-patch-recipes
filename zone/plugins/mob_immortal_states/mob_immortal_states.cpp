// mob_immortal_states - more than one "can't be hurt" state for mobs, each with its own name (Fiesta2026on2016
// Rebalanced, operator 2026-10-07: the instance eggs are invulnerable under "Euryale's Protection", "Malephar's
// Protection" ... - ideally named per egg).
//
// ---- the stock zone ------------------------------------------------------------------------------------------------------
// ShineMob::so_mobile_IsImmortal (0x42B010) is ONE question: is abstate 198 set (this->vtable[0x3E4](0xC6) - AbState
// StaMobImmortal, view "Unattackable Status")? The answer is code, not data: a copy of that AbState under another
// AbStataIndex shows its own name but protects nothing.
// ---- this plugin ---------------------------------------------------------------------------------------------------------
// so_mobile_IsImmortal also answers yes for every AbState named StaMobImmortal_<n> (n = 1, 2, ... up to the first name
// the dictionary does not have) - the server's own AbState table names them, each its own index and view text
// (the Rebalanced step 0038 makes them). Looked up once, by name, in the zone's own dictionary (read where the zone takes
// it - the abstate-index-cap recipe MOVES dic_abstate, see indun_party_scale), under a fault guard.
#include <zonehook.h>
#include <zone_functions.h>

#include <windows.h>

#include <cstdio>
#include <cstring>

namespace {

const unsigned kVaMapBuffDicMov = 0x00464620;   // MapBuffDataBox::mbdb_SetAbstate: mov ecx, &dic_abstate; call as_FromName
const unsigned kIsSetSlot = 0x3E4;              // the vtable slot so_mobile_IsImmortal asks (abstate index -> set?)
const int kMax = 32;
int g_index[kMax];
int g_count = -1;                               // -1: not looked up yet
zone::Detour g_immortal;

typedef void*(__fastcall* FromNameFn)(void*, void*, char*);
typedef unsigned char(__fastcall* IsSetFn)(void*, void*, int);
typedef unsigned char(__fastcall* ImmortalFn)(void*, void*);

void* dictionary() {
    const unsigned char* at = (const unsigned char*)zone::rebase(kVaMapBuffDicMov);
    if (at[0] != 0xB9 || at[5] != 0xE8) return nullptr;
    return *(void**)(at + 1);
}

void look_up() {
    g_count = 0;
    void* dic = dictionary();
    if (!dic) {
        zone::log("mob_immortal_states: no `mov ecx, &dic_abstate; call` at 0x%08X - only StaMobImmortal protects", kVaMapBuffDicMov);
        return;
    }
    for (int n = 1; n <= kMax; ++n) {
        static char name[48];
        std::snprintf(name, sizeof name, "StaMobImmortal_%d", n);
        void* str = nullptr;
        __try {
            str = ((FromNameFn)zone::fn::AbnormalStateDictionary__AbState__as_FromName())(dic, 0, name);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            zone::log("mob_immortal_states: FAULT looking up %s (code %08x)", name, GetExceptionCode());
            return;
        }
        if (!str) break;
        auto* info = ((zone::types::AbnormalStateDictionary__AbState__AbStateStr*)str)->index;
        if (!info) break;
        g_index[g_count++] = (int)info->AbStataIndex;
        zone::log("mob_immortal_states: %s (index %d) makes a mob unattackable", name, (int)info->AbStataIndex);
    }
}

unsigned char __fastcall immortal(void* self, void* edx) {
    unsigned char yes = ((ImmortalFn)g_immortal.trampoline)(self, edx);
    if (yes || !self) return yes;
    if (g_count < 0) look_up();
    IsSetFn is_set = (IsSetFn)(*(void***)self)[kIsSetSlot / 4];
    for (int i = 0; i < g_count; ++i)
        if (is_set(self, 0, g_index[i])) return 1;
    return 0;
}

}  // namespace

ZONEHOOK_PLUGIN("mob_immortal_states") {
    zone::hook_function("ShineMob::so_mobile_IsImmortal (+ StaMobImmortal_<n>)",
                        (void*)zone::fn::ShineObjectClass__ShineMob__so_mobile_IsImmortal(), (void*)immortal, &g_immortal);
}
