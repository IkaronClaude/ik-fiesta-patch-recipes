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
// 0x52F1B0, else error 0x346), then removes the ground object. So this plugin detours so_ply_PickupItem: when a quest in
// progress drops the item and still needs k < the stack's lot L of it, it
//   1. lets the stock function pick up a COPY of the ground item with lot k (attr slot 0x20 iac_SetLot) - the original item
//      key goes into the bag through the normal DB path and the ground object goes away as usual;
//   2. on success drops a NEW stack of L - k at the picker's feet, owned by the picker - exactly the way the zone drops a
//      quest item (ShinePlayer::sp_QuestItemGet 0x528240): ItemAttributeClassContainer[item], iti_mkregnum(item, 2, zone,
//      world) = a fresh item key, iac_itemcreate (slot 0x14), iac_SetLot (slot 0x20), som_AllocObject(&handle, 1),
//      ShineMultiTypeHandle::SetShineObject(player), drop->so_ItemDrop (slot 0x544)(handle, player, info, 1, &owner, 1)
//      == 0x301. No item key is ever on the ground and in a bag at once.
// Items no quest counts, and stacks that fit whole, take the stock path untouched.

#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cstring>

namespace {

using zone::types::ItemTotalInformation;
using zone::types::PLAYER_QUEST_INFO;
using zone::types::QUEST_DATA;
using zone::types::ShineMultiTypeHandle;

const unsigned char kStatusDoing = 6;       // PLAYER_QUEST_STATUS: in progress
const unsigned char kThenDrop = 1;          // QUEST_ACTION ThenType: drop an item
const int kQuestZoneInPlayer = 0x173E8;     // ShinePlayer -> its CQuestZone (the getter at 0x450350 is "mov eax, ecx")
const int kAttrItemCreate = 0x14;           // ItemAttributeClass slots
const int kAttrIsLot = 0x18;                //   stackable test (what so_ply_PickupItem asks before merging)
const int kAttrGetLot = 0x1C;
const int kAttrSetLot = 0x20;
const int kDropItemDrop = 0x544;            // ShineDropItem::so_ItemDrop
const unsigned short kDropOk = 0x301;
const unsigned short kObjectTypeDrop = 1;   // som_AllocObject type, as sp_QuestItemGet allocates

zone::Detour g_drop_item, g_pickup;
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

// what the quests in progress that DROP this item still need of it: -1 = none counts it (no limit), else the largest
// shortfall among them (0 = all have enough)
int still_needed(void* qz, unsigned short item) {
    void* quest_data = *(void**)((char*)qz + 4);
    const int count = *(int*)((char*)qz + 8);
    int best = -1, have = -1;
    for (int i = 0; i < count; ++i) {
        PLAYER_QUEST_INFO* qi = zone::fn::CQuest__GetQuestInfoByIndex()(qz, nullptr, i);
        if (!qi || qi->Status != kStatusDoing) continue;
        QUEST_DATA* q = zone::fn::CQuestData__GetQuestData()(quest_data, nullptr, qi->ID);
        if (!q) continue;
        bool drops = false;
        for (int j = 0; j < q->NumOfAction && j < 10; ++j)
            if (q->Action[j].ThenType == kThenDrop && (unsigned short)q->Action[j].ThenTarget == item) drops = true;
        if (!drops) continue;
        const int need = zone::fn::CQuestZone__GetSuccessItemCount()(qz, nullptr, q, item);
        if (need <= 0) return -1;                    // a script item: no count to respect
        if (have < 0) have = zone::fn::CQuestZone__GetQuestPlayerItemLot()(qz, nullptr, item);
        if (need - have > best) best = need - have;
    }
    return best < 0 ? -1 : best;
}

bool drop_remainder(void* player, unsigned short item, unsigned long lot) {
    void* attr = zone::fn::ItemAttributeClassContainer__operator__()(zone::global::itmattcontainer(), nullptr, item);
    if (!attr) return false;
    ItemTotalInformation info;
    std::memset(&info, 0, sizeof info);
    const auto* wd = zone::fn::ZoneServer__zs_worlddata()(zone::global::zoneserver(), nullptr);
    zone::fn::ItemTotalInformation__iti_mkregnum()(&info, nullptr, item, 2, wd->nZoneNo, wd->nWorldNo);
    info.iti_itemstruct.itemid = item;
    static char reason[] = "quest_item_enough remainder";
    slot<void (__thiscall*)(void*, unsigned short, ItemTotalInformation*, char*)>(attr, kAttrItemCreate)(attr, item, &info,
                                                                                                         reason);
    slot<void (__thiscall*)(void*, void*, unsigned long)>(attr, kAttrSetLot)(attr, &info.iti_itemstruct, lot);
    unsigned short handle = 0;
    void* drop = zone::fn::ShineObjectManager__som_AllocObject()(zone::global::shineobjmanager(), nullptr, &handle, kObjectTypeDrop);
    if (!drop) return false;
    ShineMultiTypeHandle owner;
    zone::fn::ShineMultiTypeHandle__ShineMultiTypeHandle()(&owner, nullptr);
    zone::fn::ShineMultiTypeHandle__SetShineObject()(&owner, nullptr, (zone::types::ShineObjectClass__ShineObject*)player);
    const unsigned short r =
        slot<unsigned short (__thiscall*)(void*, unsigned short, void*, ItemTotalInformation*, unsigned long, void*,
                                          unsigned char)>(drop, kDropItemDrop)(drop, handle, player, &info, 1, &owner, 1);
    return r == kDropOk;
}

unsigned char __fastcall pickup(void* self, void*, void* drop, ItemTotalInformation* info, unsigned short a3) {
    auto stock = (unsigned char (__fastcall*)(void*, void*, void*, ItemTotalInformation*, unsigned short))g_pickup.trampoline;
    if (!info) return stock(self, nullptr, drop, info, a3);
    const unsigned short item = info->iti_itemstruct.itemid;
    void* attr = zone::fn::ItemAttributeClassContainer__operator__()(zone::global::itmattcontainer(), nullptr, item);
    if (!attr || !slot<unsigned char (__thiscall*)(void*)>(attr, kAttrIsLot)(attr)) return stock(self, nullptr, drop, info, a3);
    const int k = still_needed((char*)self + kQuestZoneInPlayer, item);
    if (k <= 0) return stock(self, nullptr, drop, info, a3);
    const unsigned long lot = slot<unsigned long (__thiscall*)(void*, void*)>(attr, kAttrGetLot)(attr, &info->iti_itemstruct);
    if (lot <= (unsigned long)k) return stock(self, nullptr, drop, info, a3);
    ItemTotalInformation part = *info;
    slot<void (__thiscall*)(void*, void*, unsigned long)>(attr, kAttrSetLot)(attr, &part.iti_itemstruct, (unsigned long)k);
    const unsigned char r = stock(self, nullptr, drop, &part, a3);
    if (r != 1) return r;
    const bool left = drop_remainder(self, item, lot - k);
    zone::log("partial pick-up of quest item %u: took %d of %lu, %lu left on the ground%s", item, k, lot, lot - k,
              left ? "" : " - REMAINDER DROP FAILED");
    return r;
}

}  // namespace

HOOK_PLUGIN("quest_item_enough") {
    zone::hook_function("CQuestZone::IsQuestDropItem (no pick-up once the quest has enough)",
                        (void*)zone::fn::CQuestZone__IsQuestDropItem(), (void*)is_quest_drop_item, &g_drop_item);
    zone::hook_function("ShinePlayer::so_ply_PickupItem (partial pick-up of a quest item stack)",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__so_ply_PickupItem(), (void*)pickup, &g_pickup);
}
