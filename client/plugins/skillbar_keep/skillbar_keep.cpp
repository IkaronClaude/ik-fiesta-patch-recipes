// skillbar_keep - learning a skill level only upgrades the bar slots that held the level you had (ticket Q59).
//
// Operator 2026-09-25: "If a skill bar slot contains a skill of level X, but the char already has Y (Y > X), then when
// you learn skill Y+1, do NOT update the slot to Y+1, keep at X ... so I can purposefully keep a skill at level 1 in my
// skill bar, even if I buy higher level versions of it. Check per slot".
//
// ---- the stock 2026 client (Fiesta.exe, read 2026-09-25) ------------------------------------------------------
//
//   NC_SKILL_SKILL_LEARNSUC_CMD 0x4804 {u16 skill, u8 flag} -> 0x5AD110 (thiscall(this, a1, payload), ret 8). With
//   flag 0 it walks the 100 shortcut slots (array 0xC1750C, a slot object: vtable+4 = type, 1 = skill; +8 = skill id):
//   for a skill slot whose skill's InxName minus its 2-character level suffix equals the learned skill's
//   ("PowerStrike01" / "PowerStrike02"), it parses that suffix as the slot's level and keeps the slots at the HIGHEST
//   level found on the bar; after the loop those get the new skill id and are saved one by one (0x742130 -> 0x7037 to
//   the WorldManager). An empty slot (null) is skipped. So a lone level-1 slot is "the highest" and was upgraded.
//
// ---- this plugin --------------------------------------------------------------------------------------------------
//
//   Around 0x5AD110, every matching slot whose level is below the level the character just had (new level - 1) is
//   hidden (its array entry nulled) for that one call and put back right after; the stock loop then only sees - and
//   upgrades - the slots at the level being replaced. The handler redraws the bars (0x57E2D0) during that call, so
//   the plugin redraws them once more after putting the slots back. Nothing else about the bar changes.
#include <hook_core.h>

#include <cstdlib>
#include <cstring>

namespace {

const unsigned kVaLearn = 0x005AD110u;     // LEARNSUC handler, thiscall(this, a1, payload), ret 8
const unsigned kVaSkill = 0x007DCCC0u;     // cdecl skill record lookup (u16 id) -> record*, InxName at +2
const unsigned kVaSlots = 0x00C1750Cu;     // void* slot[100]
const unsigned kVaRedraw = 0x0057E2D0u;    // thiscall(same this as the handler): redraw the visible quick bars
const int kSlots = 100, kSkillType = 1;
const unsigned kSlotSkillId = 8, kRecordName = 2;

hook::Detour g_learn;

const char* skill_name(unsigned short id) {
    typedef const unsigned char*(__cdecl * Lookup)(unsigned short);
    const unsigned char* rec = ((Lookup)hook::rebase(kVaSkill))(id);
    return rec ? (const char*)(rec + kRecordName) : nullptr;
}

// "PowerStrike05" -> base length 11, level 5 (the client's own rule: the last two characters are the level)
bool split(const char* name, size_t* base, int* level) {
    size_t n = name ? std::strlen(name) : 0;
    if (n < 3) return false;
    *base = n - 2;
    *level = std::atoi(name + n - 2);
    return true;
}

int slot_type(void* slot) {
    typedef int(__fastcall * Type)(void*, void*);
    return ((Type)(*(void***)slot)[1])(slot, 0);
}

void __fastcall learn_impl(void* self, void*, void* a1, const unsigned char* payload) {
    typedef void(__fastcall * Orig)(void*, void*, void*, const unsigned char*);
    void** slots = (void**)hook::rebase(kVaSlots);
    void* hidden[kSlots] = {};
    int n_hidden = 0;
    const char* learned = payload && payload[2] == 0 ? skill_name(*(const unsigned short*)payload) : nullptr;
    size_t base = 0;
    int level = 0;
    if (learned && split(learned, &base, &level)) {
        for (int i = 0; i < kSlots; i++) {
            void* s = slots[i];
            if (!s || slot_type(s) != kSkillType) continue;
            const char* name = skill_name(*(unsigned short*)((char*)s + kSlotSkillId));
            size_t b;
            int lv;
            if (!name || !split(name, &b, &lv) || b != base || std::strncmp(name, learned, base) != 0) continue;
            if (lv < level - 1) {                  // a level below the one being replaced: kept on purpose
                hidden[i] = s;
                slots[i] = nullptr;
                n_hidden++;
            }
        }
    }
    ((Orig)g_learn.trampoline)(self, 0, a1, payload);
    for (int i = 0; i < kSlots; i++)
        if (hidden[i]) slots[i] = hidden[i];
    if (n_hidden) {
        // the handler redrew the bars while those slots were hidden: draw them again with the slots back
        typedef void(__fastcall * Redraw)(void*, void*);
        ((Redraw)hook::rebase(kVaRedraw))(self, 0);
        hook::log("learned %s: %d bar slot(s) below level %d kept as they were", learned, n_hidden, level - 1);
    }
}

void __declspec(naked) learn_thunk() { __asm { jmp learn_impl } }

}  // namespace

HOOK_PLUGIN("skillbar_keep") {
    hook::hook_function("skill learn 0x5AD110 (bar keeps deliberately lower levels)", hook::rebase(kVaLearn),
                        (void*)learn_thunk, &g_learn);
}
