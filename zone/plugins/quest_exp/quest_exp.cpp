// quest_exp - quest EXP past 2^31 (and past 2^32), the 2026 Quest EXP Booster, and permanent charged AbStates.
//
// ---- 1. QUEST EXP: THE STOCK PATH (read from Zone.exe) -------------------------------------------------------
//
//   CQuestZone::QuestTakeReward, reward type 0 (0x5BC053): mov edx,[Value] -> the reward packet +0x33, a u32
//   InventoryCellLockList::icl_QuestReward(quest, int exp, int fame, b, b)  0x489800: parks it in a LockedCell
//       lc_Index = quest id, lc_Argument +0x10 = exp (dword), +0x14 = fame, +0x18/+0x19 = title flags
//   ShinePlayer::so_ply_InvenCellReleaser_QuestReward(LockedCell*)          0x52D980: when the DB answers,
//       sp_GainExp(player, int [cell+0x10], 0xFFFF, 0xFFFF), then fame, then the title
//   ShinePlayer::sp_GainExp(int exp, ...)                                   0x42D830: `mov eax,edi; cdq;
//       add [esi+0x7F57],eax; adc [esi+0x7F5B],edx` - the u64 player EXP += the SIGN-EXTENDED int.
//
// So a quest reward above 2,147,483,647 is SUBTRACTED from the player's EXP. The 2026 tables have 42 of them
// (QuestReward.Flag stored negative, levels 110-150): a parity bug on the stock zone.
//
// This plugin replaces the releaser's EXP grant: the amount is read UNSIGNED, widened to the full 8-byte reward
// value when the quest's EXP slot carries a high dword (QUEST_DATA Reward[k].Value is 8 bytes; the stock zone only
// ever reads the low 4, and the high dword is 0 in every parity record - Fiesta2026on2016 variants may fill it),
// scaled by an active Quest EXP Booster, and granted through sp_GainExp in chunks of at most 2^31-1 (so level-ups,
// the EXP freeze and the level cap stay the zone's own). The stock releaser then runs with EXP 0 for fame + title.
// A quest whose reward is <= 2^31-1 with no booster goes through untouched.
//
// ---- 2. THE QUEST EXP BOOSTER (charged EffectEnum 40) -------------------------------------------------------
//
// A 2026 charged type the 2016 zone does not know: uib_CanUseItem refuses every enum past 38 (0x713, "no effect")
// and ciee_Activ ignores it. Here: uib_CanUseItem lets 40 through (everything after that check is enum-agnostic -
// see void_bag), and the quest grant above adds EffectValue per mille of the quest EXP (QExpBoost 10% = 100) for
// the strongest active booster.
//
// ---- 3. PERMANENT CHARGED ABSTATES (charged EffectEnum 31) --------------------------------------------------
//
// Type 31 applies an AbState: EffectValue = the AbState id, StaStrength = its strength (Red Dragon's Grace =
// StaACRedDragon). The duration handed to ShinePlayer::so_AbnormalState_Set (8th argument, a signed int of ms,
// EnchantFrom 0x0B) comes from
//   - first use, so_ply_ChargedBuff 0x5973AE: KeepTime_Hour * 3,600,000 -> 0 for a permanent (KeepTime 0) item;
//   - every login, ciee_AfterLoginComplete 0x417A08: difftime(end, now) * 1000 -> _ftol -> the LOW 32 BITS of a
//     64-bit value -> garbage for a permanent item (its end date is 2255-12-31).
// While either of those runs for a type-31 record with KeepTime 0, the duration is forced to 2^31-1 ms (24.8
// days); the next login re-applies it, so the state never runs out for anyone who logs in within three weeks.
// Timed type-31 items are left exactly as they were.
#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cstddef>

namespace {

using zone::types::ChargedItemEffect;
using zone::types::QUEST_DATA;

const int kEffectChargedAbState = 31;
const int kEffectQuestExpBooster = 40;
const unsigned short kUseOk = 0x700;             // uib_CanUseItem's "yes"
const int kEnchantFromCharged = 0x0B;            // so_AbnormalState_Set's EnchantFrom at both type-31 call sites
const int kIntMax = 0x7FFFFFFF;
const unsigned kRewardExp = 0;                   // QUEST_DATA Reward[k].Type for EXP
const unsigned kCellExp = 0x10;                  // LockedCell lc_Argument offsets (icl_QuestReward 0x4898DE..)

// ---- the player's active charged effects ----------------------------------------------------------------------
// ChargedItem = so_ply_ChargedEffectContainer() - offsetof(ci_Effect) (player + 0x2A330). The ACTIVE set is not
// cel_Effect[50] itself (a freed slot keeps its record pointer) but the list whose header sits in ChargedEffectList's
// padding: +4 u16 capacity, +8 node array, +0xE u16 head; a node is {element*, u16 next @4, u8 used @8}, 12 bytes.
// Walked exactly as the zone walks it at 0x418080.
struct Node {
    const zone::types::ChargedItemEffectList__ChargedItemEffectElement* element;
    unsigned short next;
    unsigned char _pad[2];
    unsigned char used;
    unsigned char _pad2[3];
};
static_assert(sizeof(Node) == 12, "the zone steps the node array by 12");

template <class F>
void for_each_active(void* player, F f) {
    using ChargedItem = zone::types::ChargedItemEffectList__ChargedItem;
    auto get = zone::fn::ShineObjectClass__ShinePlayer__so_ply_ChargedEffectContainer();
    void* container = player ? get(player, 0) : nullptr;
    if (!container) return;
    const char* list = (const char*)container - offsetof(ChargedItem, ci_Effect);
    unsigned short cap = *(const unsigned short*)(list + 4);
    const Node* nodes = *(const Node* const*)(list + 8);
    unsigned short head = *(const unsigned short*)(list + 0xE);
    if (!nodes || head >= cap) return;
    for (unsigned short i = nodes[head].next, guard = 0; i < cap && guard < cap; i = nodes[i].next, ++guard) {
        if (!nodes[i].used || !nodes[i].element) break;
        const ChargedItemEffect* e = nodes[i].element->ciee_Index;
        if (e) f(*e);
    }
}

unsigned booster_permille(void* player) {
    unsigned best = 0;
    for_each_active(player, [&](const ChargedItemEffect& e) {
        if ((int)e.EffectEnum == kEffectQuestExpBooster && e.EffectValue > best) best = e.EffectValue;
    });
    return best;
}

// ---- 1 + 2: the quest EXP grant --------------------------------------------------------------------------------
zone::Detour g_release;

unsigned long long full_exp(unsigned short quest, unsigned low) {
    auto get = zone::fn::CQuestData__GetQuestData();
    const QUEST_DATA* q = get(zone::global::gQuestData(), 0, quest);
    if (!q) return low;
    for (const auto& r : q->Reward) {
        if (!r.Use || r.Type != kRewardExp) continue;
        const unsigned* v = (const unsigned*)&r.Value;
        if (v[0] == low) return ((unsigned long long)v[1] << 32) | v[0];   // the slot QuestTakeReward used
    }
    return low;
}

void __fastcall release_impl(void* player, void*, zone::types::InventoryLocking__LockedCell* cell) {
    typedef void(__fastcall * Orig)(void*, void*, zone::types::InventoryLocking__LockedCell*);
    unsigned* exp_arg = cell ? (unsigned*)((char*)cell + kCellExp) : nullptr;
    if (!exp_arg || !*exp_arg) return ((Orig)g_release.trampoline)(player, 0, cell);
    const unsigned low = *exp_arg;
    const unsigned long long base = full_exp(cell->lc_Index, low);
    const unsigned boost = booster_permille(player);
    const unsigned long long total = base + base * boost / 1000;
    if (total == low && low <= (unsigned)kIntMax) return ((Orig)g_release.trampoline)(player, 0, cell);

    auto gain = zone::fn::ShineObjectClass__ShinePlayer__sp_GainExp();
    for (unsigned long long left = total; left; ) {
        int chunk = left > (unsigned long long)kIntMax ? kIntMax : (int)left;
        gain(player, 0, chunk, 0xFFFF, 0xFFFF);
        left -= (unsigned long long)chunk;
    }
    zone::log("quest %u: EXP %llu (reward %llu%s, booster +%u.%u%%) granted in %s",
              (unsigned)cell->lc_Index, total, base, base != low ? " from the 8-byte slot" : "",
              boost / 10, boost % 10, total > (unsigned long long)kIntMax ? "chunks" : "one call");
    *exp_arg = 0;                                   // the stock releaser still does fame + title
    ((Orig)g_release.trampoline)(player, 0, cell);
    *exp_arg = low;
}

void __declspec(naked) release_thunk() { __asm { jmp release_impl } }

// ---- 2: letting the booster be used ----------------------------------------------------------------------------
zone::Detour g_canuse;

struct ChargedBuffEntry {                           // chargedbuffdatabox: {u16 item, u16 pad, ChargedItemEffect*}
    unsigned short item;
    unsigned short pad;
    const ChargedItemEffect* effect;
};
static_assert(sizeof(ChargedBuffEntry) == 8, "uib_CanUseItem walks this table in 8-byte steps");

const ChargedItemEffect* charged_effect_of(unsigned short item_id) {
    const auto* box = zone::global::chargedbuffdatabox();
    auto* arr = (const ChargedBuffEntry*)box->cideb_Array;
    for (int i = 0; arr && i < box->cideb_Total; i++)
        if (arr[i].item == item_id) return arr[i].effect;
    return nullptr;
}

unsigned short __fastcall canuse_impl(void* self, void*, void* player, zone::types::ItemTotalInformation* item) {
    const ChargedItemEffect* e = item ? charged_effect_of(item->iti_itemstruct.itemid) : nullptr;
    if (e && (int)e->EffectEnum == kEffectQuestExpBooster) return kUseOk;
    typedef unsigned short(__fastcall * Orig)(void*, void*, void*, void*);
    return ((Orig)g_canuse.trampoline)(self, 0, player, item);
}

void __declspec(naked) canuse_thunk() { __asm { jmp canuse_impl } }

// ---- 3: permanent type-31 AbStates -----------------------------------------------------------------------------
thread_local bool t_permanent = false;               // set while a permanent type-31 record is being applied
zone::Detour g_login, g_buff, g_abstate;

bool permanent_abstate(const ChargedItemEffect* e) {
    return e && (int)e->EffectEnum == kEffectChargedAbState && e->KeepTime_Hour == 0;
}

void __fastcall login_impl(zone::types::ChargedItemEffectList__ChargedItemEffectElement* el, void*,
                           unsigned short a1, void* player) {
    typedef void(__fastcall * Orig)(void*, void*, unsigned short, void*);
    const bool was = t_permanent;
    t_permanent = el && permanent_abstate(el->ciee_Index);
    ((Orig)g_login.trampoline)(el, 0, a1, player);
    t_permanent = was;
}

void __fastcall buff_impl(void* player, void*, zone::types::ItemTotalInformation* item) {
    typedef void(__fastcall * Orig)(void*, void*, void*);
    const bool was = t_permanent;
    t_permanent = item && permanent_abstate(charged_effect_of(item->iti_itemstruct.itemid));
    ((Orig)g_buff.trampoline)(player, 0, item);
    t_permanent = was;
}

unsigned char __fastcall abstate_impl(void* player, void*, void* from, int idx, int strength, void* str,
                                      unsigned long tick, int a6, int a7, int duration, int from_kind, void* data) {
    if (t_permanent && from_kind == kEnchantFromCharged && duration != kIntMax) {
        zone::log("permanent charged abstate %d (strength %d): duration %d ms -> %d", idx, strength, duration, kIntMax);
        duration = kIntMax;
    }
    typedef unsigned char(__fastcall * Orig)(void*, void*, void*, int, int, void*, unsigned long, int, int, int, int, void*);
    return ((Orig)g_abstate.trampoline)(player, 0, from, idx, strength, str, tick, a6, a7, duration, from_kind, data);
}

void __declspec(naked) login_thunk() { __asm { jmp login_impl } }
void __declspec(naked) buff_thunk() { __asm { jmp buff_impl } }
void __declspec(naked) abstate_thunk() { __asm { jmp abstate_impl } }

}  // namespace

ZONEHOOK_PLUGIN("quest_exp") {
    zone::hook_function("ShinePlayer::so_ply_InvenCellReleaser_QuestReward",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__so_ply_InvenCellReleaser_QuestReward(),
                        (void*)release_thunk, &g_release);
    zone::hook_function("UseItemChargedBuff::uib_CanUseItem (quest EXP booster)",
                        (void*)zone::fn::UseEffect__UseItemChargedBuff__uib_CanUseItem(),
                        (void*)canuse_thunk, &g_canuse);
    zone::hook_function("ChargedItemEffectElement::ciee_AfterLoginComplete",
                        (void*)zone::fn::ChargedItemEffectList__ChargedItemEffectElement__ciee_AfterLoginComplete(),
                        (void*)login_thunk, &g_login);
    zone::hook_function("ShinePlayer::so_ply_ChargedBuff",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__so_ply_ChargedBuff(),
                        (void*)buff_thunk, &g_buff);
    zone::hook_function("ShinePlayer::so_AbnormalState_Set",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__so_AbnormalState_Set(),
                        (void*)abstate_thunk, &g_abstate);
}
