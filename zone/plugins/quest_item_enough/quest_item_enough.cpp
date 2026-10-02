// quest_item_enough - a quest item on the ground cannot be picked up once the quest has all it asks for, and a stack
// bigger than what the quest still needs is picked up only partly.
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
//
// ---- PARTIAL PICK-UP (operator 2026-10-02: "a stack of 2 quest items on the ground, you're at 9/10, pick up, the stack
// stays on the ground but now as 1 instead of 2 and you're at 10/10") -------------------------------------------------
//
// Ground stacks of quest items exist (ItemDropGroup Q_GoblinMushroom / Herb / Fruit / Q_SandHerb: 1-3 per drop). The
// pick-up path read 2026-10-02 is all-or-nothing: ShinePlayer::so_ply_PickupItem 0x52FAF0 merges the WHOLE stack into one
// inventory cell (ii_PickMerge 0x52F440, only when cell + stack <= MaxLot) or stores it in an empty cell (ii_PickAll
// 0x52F1B0, else error 0x346), then calls the drop's so_itempicked (slot 0x54C, 0x555340), which blanks the item inside it
// (key -1, id 0xFFFF); the blanked object is then deleted from everyone's view (BRIEFINFO delete 0x1805). There is no
// "reduce a ground stack" packet - a ground stack is a drop object whose lot only lives in the server's ItemTotalInformation
// (drop+0x18D), which the client never displays. So the partial pick-up is the stock pick with one call held back:
//   1. a copy of the ground item with lot k (iac_SetLot, slot 0x20) and a fresh item key (iti_mkregnum - it only matters
//      when the k land in a NEW cell; a merge keeps the cell's own key) goes through the stock so_ply_PickupItem: bag, DB
//      and the picker's pick result exactly as stock;
//   2. while that call runs, ShineDropItem::so_itempicked is a no-op for this drop - the ground object keeps its item, its
//      cell, its handle and its loot rights, and nobody is told it went away;
//   3. its lot then becomes L - k (iac_SetLot on drop+0x18D in place).
// And once every quest that asks for it has enough (k == 0), a quest item is refused here too - stacks from normal drop
// groups never pass so_ply_QuestItemCheck (CanLooting asks it only for quest-flagged drops) - with the zone's own loot
// refusal: so_ply_itempickresult (player slot 0x6C0)(0x345, 0xFFFF), as sp_NC_ITEM_PICK_REQ sends when CanLooting fails.
// Items no quest counts, and stacks that fit whole, take the stock path untouched.

#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cstring>

namespace {

using zone::types::ItemTotalInformation;
using zone::types::PLAYER_QUEST_INFO;
using zone::types::QUEST_DATA;

const unsigned char kStatusDoing = 6;       // PLAYER_QUEST_STATUS: in progress
const unsigned char kThenDrop = 1;          // QUEST_ACTION ThenType: drop an item
const int kQuestZoneInPlayer = 0x173E8;     // ShinePlayer -> its CQuestZone (the getter at 0x450350 is "mov eax, ecx")
// ItemAttributeClass slots
const int kAttrIsLot = 0x18;                //   stackable test (what so_ply_PickupItem asks before merging)
const int kAttrGetLot = 0x1C;
const int kAttrSetLot = 0x20;
const unsigned short kObjectTypeDrop = 1;
const int kItemTypeQuest = 3;
const int kPlyPickResult = 0x6C0;           // ShinePlayer::so_ply_itempickresult(err, handle)
const unsigned short kPickRefused = 0x345;  // what sp_NC_ITEM_PICK_REQ sends when CanLooting fails               // ItemInfo.Type of quest items (Q_..., the 2026 event items)   // som_AllocObject type, as sp_QuestItemGet allocates

zone::Detour g_drop_item, g_pickup, g_picked;
unsigned g_refused = 0;

template <typename F> F slot(void* obj, int off) { return (F)(*(void***)obj)[off / 4]; }

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

// what the quests in progress still need of this item - every quest whose End.ItemList asks for it, with or without a
// drop row (the quest items that lie on the ground in STACKS come from normal drop groups, e.g. Goblin Mushroom 1-3 from
// its nodes, never from a quest drop row: QuestActionMobKill drops lot 1 per sp_QuestItemGet). -1 = no quest asks for
// it, else the largest shortfall (0 = all have enough).
int still_needed(void* qz, unsigned short item) {
    void* quest_data = *(void**)((char*)qz + 4);
    const int count = *(int*)((char*)qz + 8);
    int best = -1, have = -1;
    for (int i = 0; i < count; ++i) {
        PLAYER_QUEST_INFO* qi = zone::fn::CQuest__GetQuestInfoByIndex()(qz, nullptr, i);
        if (!qi || qi->Status != kStatusDoing) continue;
        QUEST_DATA* q = zone::fn::CQuestData__GetQuestData()(quest_data, nullptr, qi->ID);
        if (!q) continue;
        const int need = zone::fn::CQuestZone__GetSuccessItemCount()(qz, nullptr, q, item);
        if (need <= 0) continue;                     // this quest does not ask for it
        if (have < 0) have = zone::fn::CQuestZone__GetQuestPlayerItemLot()(qz, nullptr, item);
        if (need - have > best) best = need - have;
    }
    return best < 0 ? -1 : best;
}

void* g_hold_drop = nullptr;                 // the drop whose so_itempicked is held back during a partial pick-up

void __fastcall item_picked(void* self, void*) {
    if (self == g_hold_drop) return;
    ((void (__fastcall*)(void*, void*))g_picked.trampoline)(self, nullptr);
}

unsigned char __fastcall pickup(void* self, void*, void* drop, ItemTotalInformation* info, unsigned short a3) {
    auto stock = (unsigned char (__fastcall*)(void*, void*, void*, ItemTotalInformation*, unsigned short))g_pickup.trampoline;
    if (!info || !drop) return stock(self, nullptr, drop, info, a3);
    const unsigned short item = info->iti_itemstruct.itemid;
    void* attr = zone::fn::ItemAttributeClassContainer__operator__()(zone::global::itmattcontainer(), nullptr, item);
    if (!attr || !slot<unsigned char (__thiscall*)(void*)>(attr, kAttrIsLot)(attr)) return stock(self, nullptr, drop, info, a3);
    // quest items only (ItemInfo.Type 3): an ore / dust a quest also asks for may be picked up whole
    auto* idx = zone::fn::ItemDataBox__operator__()(zone::global::itemdatabox(), nullptr, item);
    if (!idx || !idx->data || (int)idx->data->Type != kItemTypeQuest) return stock(self, nullptr, drop, info, a3);
    const int k = still_needed((char*)self + kQuestZoneInPlayer, item);
    if (k < 0) return stock(self, nullptr, drop, info, a3);                // no quest asks for it
    if (k == 0) {                                                           // every quest asking for it has enough
        slot<void (__thiscall*)(void*, unsigned short, unsigned short)>(self, kPlyPickResult)(self, kPickRefused, 0xFFFF);
        if (g_refused++ < 200 || g_refused % 1000 == 0)
            zone::log("refused pick-up of quest item %u (normal drop): the quests asking for it have enough (refusal #%u)",
                      item, g_refused);
        return 0;
    }
    const unsigned long lot = slot<unsigned long (__thiscall*)(void*, void*)>(attr, kAttrGetLot)(attr, &info->iti_itemstruct);
    if (lot <= (unsigned long)k) return stock(self, nullptr, drop, info, a3);
    ItemTotalInformation part = *info;
    slot<void (__thiscall*)(void*, void*, unsigned long)>(attr, kAttrSetLot)(attr, &part.iti_itemstruct, (unsigned long)k);
    const auto* wd = zone::fn::ZoneServer__zs_worlddata()(zone::global::zoneserver(), nullptr);
    zone::fn::ItemTotalInformation__iti_mkregnum()(&part, nullptr, item, 2, wd->nZoneNo, wd->nWorldNo);
    g_hold_drop = drop;
    const unsigned char r = stock(self, nullptr, drop, &part, a3);
    g_hold_drop = nullptr;
    if (r != 1) return r;                                                   // nothing taken: the stack stays as it was
    slot<void (__thiscall*)(void*, void*, unsigned long)>(attr, kAttrSetLot)(attr, &info->iti_itemstruct, lot - k);
    zone::log("partial pick-up of quest item %u: took %d of %lu, the original stack keeps %lu", item, k, lot, lot - k);
    return r;
}

}  // namespace

HOOK_PLUGIN("quest_item_enough") {
    zone::hook_function("CQuestZone::IsQuestDropItem (no pick-up once the quest has enough)",
                        (void*)zone::fn::CQuestZone__IsQuestDropItem(), (void*)is_quest_drop_item, &g_drop_item);
    zone::hook_function("ShinePlayer::so_ply_PickupItem (partial pick-up of a quest item stack)",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__so_ply_PickupItem(), (void*)pickup, &g_pickup);
    zone::hook_function("ShineDropItem::so_itempicked (held back during a partial pick-up)",
                        (void*)zone::fn::ShineObjectClass__ShineDropItem__so_itempicked(), (void*)item_picked, &g_picked);
}
