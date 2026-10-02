// quest_item_enough - a quest item on the ground cannot be picked up once the quest has all it asks for.
//
// Operator, 2026-10-01: "Quests ban you from picking up quest items if you no longer have the quest. They should also
// ban you when you already have >= target number".
//
// ---- THE STOCK CHECK (read from Zone.exe) ------------------------------------------------------------
//
//   ShinePlayer::so_ply_QuestItemCheck(item)          0x561790 (virtual): the player's CQuestZone (this+0x173E8,
//                                                     through a one-line getter) -> IsQuestDropItem(item) != 0
//   CQuestZone::IsQuestDropItem(item)                 0x5BC900, its ONLY caller is the function above:
//     for each quest the player holds (count this+8, CQuest::GetQuestInfoByIndex) with Status 6 (doing):
//       QUEST_DATA = CQuestData::GetQuestData(this+4, id)
//       for j < NumOfAction: Action[j].ThenType == 1 (drop) && ThenTarget == item -> return 1
//     return 0
// So the zone refuses a quest item no quest in progress drops - but never asks how many the player has.
//
// ---- THE CHANGE ---------------------------------------------------------------------------------------
//
// The stock function still decides first; a 0 stays 0. When it says 1, this plugin walks the same quests and lets
// the item through only if at least one of them still needs it:
//   need = CQuestZone::GetSuccessItemCount(q, item)   0x5BA800: the sum of End.ItemList lots for that item
//   have = CQuestZone::GetQuestPlayerItemLot(item)    0x5BA4E0: what the player's inventory holds of it
//   need == 0 (dropped, but not an end requirement - a script uses it) or have < need -> allowed, as stock.
// These are the same two numbers the zone's own quest drop uses to stop rolling at the target
// (CQuestZone::QuestActionMobKill 0x5BD000: have < need, capped at need - have), so pick-ups now agree with drops.
// Several quests wanting the same item: the item is allowed while ANY of them is short.

#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

namespace {

using zone::types::PLAYER_QUEST_INFO;
using zone::types::QUEST_DATA;

const unsigned char kStatusDoing = 6;       // PLAYER_QUEST_STATUS: in progress
const unsigned char kThenDrop = 1;          // QUEST_ACTION ThenType: drop an item

zone::Detour g_drop_item;
unsigned g_refused = 0;

int __fastcall is_quest_drop_item(void* self, void*, unsigned short item) {
    const int stock = ((int (__fastcall*)(void*, void*, unsigned short))g_drop_item.trampoline)(self, nullptr, item);
    if (!stock) return 0;
    void* quest_data = *(void**)((char*)self + 4);
    const int count = *(int*)((char*)self + 8);
    int have = -1;                                   // asked once, only when a quest needs a count
    unsigned short full_quest = 0;
    int full_need = 0;
    for (int i = 0; i < count; ++i) {
        PLAYER_QUEST_INFO* qi = zone::fn::CQuest__GetQuestInfoByIndex()(self, nullptr, i);
        if (!qi || qi->Status != kStatusDoing) continue;
        QUEST_DATA* q = zone::fn::CQuestData__GetQuestData()(quest_data, nullptr, qi->ID);
        if (!q) continue;
        bool drops = false;
        for (int j = 0; j < q->NumOfAction && j < 10; ++j)
            if (q->Action[j].ThenType == kThenDrop && (unsigned short)q->Action[j].ThenTarget == item) drops = true;
        if (!drops) continue;
        const int need = zone::fn::CQuestZone__GetSuccessItemCount()(self, nullptr, q, item);
        if (need <= 0) return 1;                     // not an end requirement: the stock answer stands
        if (have < 0) have = zone::fn::CQuestZone__GetQuestPlayerItemLot()(self, nullptr, item);
        if (have < need) return 1;
        full_quest = qi->ID, full_need = need;
    }
    if (full_quest) {
        if (g_refused++ < 200 || g_refused % 1000 == 0)
            zone::log("refused pick-up of quest item %u: holds %d, quest %u needs %d (refusal #%u)", item, have, full_quest,
                      full_need, g_refused);
        return 0;
    }
    return stock;                                    // a quest_ext row the record does not hold: leave it to stock
}

}  // namespace

HOOK_PLUGIN("quest_item_enough") {
    zone::hook_function("CQuestZone::IsQuestDropItem (no pick-up once the quest has enough)",
                        (void*)zone::fn::CQuestZone__IsQuestDropItem(), (void*)is_quest_drop_item, &g_drop_item);
}
