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
#include <vector>

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
const unsigned short kPickRefused = 0x345;
const unsigned short kPickBagFull = 0x346;  // ii_PickAll's refusal: no free cell
const int kPlayerBag = 0x8E2C;              // ShinePlayer: its bag (ItemBag), what so_ply_PickupItem iterates
const int kPlayerCharged = 0x2A5A0;         //   its ChargedEffectContainer (bag expansions)
const int kPlyLockList = 0x7D4;             //   slot: the inventory lock list for UnlockedInventoryIterator
const int kInvenBag = 9;                    //   inventory type of the bag  // what sp_NC_ITEM_PICK_REQ sends when CanLooting fails               // ItemInfo.Type of quest items (Q_..., the 2026 event items)   // som_AllocObject type, as sp_QuestItemGet allocates

zone::Detour g_drop_item, g_pickup, g_picked, g_result;
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

// ---- holding back two stock calls for one pick-up -------------------------------------------------------------------
void* g_hold_drop = nullptr;                 // this drop's so_itempicked is a no-op while set
bool g_capture_result = false;               // so_ply_itempickresult is captured instead of sent while set
unsigned short g_result_err = 0, g_result_handle = 0;
bool g_result_seen = false;

void __fastcall item_picked(void* self, void*) {
    if (self == g_hold_drop) return;
    ((void (__fastcall*)(void*, void*))g_picked.trampoline)(self, nullptr);
}

void __fastcall pick_result(void* self, void*, unsigned short err, unsigned short handle) {
    if (g_capture_result) {
        g_result_err = err, g_result_handle = handle, g_result_seen = true;
        return;
    }
    ((void (__fastcall*)(void*, void*, unsigned short, unsigned short))g_result.trampoline)(self, nullptr, err, handle);
}

void send_result(void* player, unsigned short err, unsigned short handle) {
    ((void (__fastcall*)(void*, void*, unsigned short, unsigned short))g_result.trampoline)(player, nullptr, err, handle);
}

// the free room of every bag cell holding this item (MaxLot - lot), the way so_ply_PickupItem walks them (0x52FCE1..):
// ItemBoxIterIdent(bag = player+0x8E2C, item, charged effects = player+0x2A5A0), UnlockedInventoryIterator {iter, player
// slot 0x7D4 (the lock list), 9}, uii_Home / uii_Next; cell = bag->slot0(iter index), lot = cell+0x70 attr -> GetLot(cell+8)
std::vector<unsigned long> cell_rooms(void* player, unsigned short item, unsigned long max_lot) {
    std::vector<unsigned long> rooms;
    alignas(8) unsigned char ident[0x20] = {};
    zone::fn::ItemBoxIterIdent__ItemBoxIterIdent()(ident, nullptr, (zone::types::ItemBag*)((char*)player + kPlayerBag), item,
                                                   (zone::types::ChargedEffectContainer*)((char*)player + kPlayerCharged));
    void* locks = slot<void* (__thiscall*)(void*)>(player, kPlyLockList)(player);
    struct {
        void* iter;
        void* locks;
        int inven_type;
    } it = {ident, locks, kInvenBag};
    if (zone::fn::InventoryLocking__UnlockedInventoryIterator__uii_Home()(&it, nullptr)) {
        do {
            void* bag = *(void**)(ident + 4);
            const int index = *(int*)(ident + 8);
            void* cell = slot<void* (__thiscall*)(void*, int)>(bag, 0)(bag, index);
            if (!cell) continue;
            void* attr = *(void**)((char*)cell + 0x70);
            if (!attr || !slot<unsigned char (__thiscall*)(void*)>(attr, kAttrIsLot)(attr)) continue;
            const unsigned long lot = slot<unsigned long (__thiscall*)(void*, void*)>(attr, kAttrGetLot)(attr, (char*)cell + 8);
            if (lot < max_lot) rooms.push_back(max_lot - lot);
        } while (zone::fn::InventoryLocking__UnlockedInventoryIterator__uii_Next()(&it, nullptr));
    }
    return rooms;
}

// one stock pick of `n` from the ground stack, the drop's so_itempicked held back; the result reaches the client as stock
unsigned char pick_part(void* self, void* drop, const ItemTotalInformation* info, void* attr, unsigned long n,
                        unsigned short a3, bool capture) {
    auto stock = (unsigned char (__fastcall*)(void*, void*, void*, ItemTotalInformation*, unsigned short))g_pickup.trampoline;
    ItemTotalInformation part = *info;
    slot<void (__thiscall*)(void*, void*, unsigned long)>(attr, kAttrSetLot)(attr, &part.iti_itemstruct, n);
    const auto* wd = zone::fn::ZoneServer__zs_worlddata()(zone::global::zoneserver(), nullptr);
    zone::fn::ItemTotalInformation__iti_mkregnum()(&part, nullptr, info->iti_itemstruct.itemid, 2, wd->nZoneNo, wd->nWorldNo);
    g_hold_drop = drop;
    g_capture_result = capture, g_result_seen = false;
    const unsigned char r = stock(self, nullptr, drop, &part, a3);
    g_capture_result = false;
    g_hold_drop = nullptr;
    return r;
}

unsigned char __fastcall pickup(void* self, void*, void* drop, ItemTotalInformation* info, unsigned short a3) {
    auto stock = (unsigned char (__fastcall*)(void*, void*, void*, ItemTotalInformation*, unsigned short))g_pickup.trampoline;
    if (!info || !drop) return stock(self, nullptr, drop, info, a3);
    const unsigned short item = info->iti_itemstruct.itemid;
    void* attr = zone::fn::ItemAttributeClassContainer__operator__()(zone::global::itmattcontainer(), nullptr, item);
    auto* idx = zone::fn::ItemDataBox__operator__()(zone::global::itemdatabox(), nullptr, item);
    if (!attr || !idx || !idx->data || !slot<unsigned char (__thiscall*)(void*)>(attr, kAttrIsLot)(attr))
        return stock(self, nullptr, drop, info, a3);                         // not a stack: stock
    const unsigned long lot = slot<unsigned long (__thiscall*)(void*, void*)>(attr, kAttrGetLot)(attr, &info->iti_itemstruct);
    unsigned long want = lot;
    if ((int)idx->data->Type == kItemTypeQuest) {
        const int k = still_needed((char*)self + kQuestZoneInPlayer, item);
        if (k == 0) {                                                       // every quest asking for it has enough
            send_result(self, kPickRefused, 0xFFFF);
            if (g_refused++ < 200 || g_refused % 1000 == 0)
                zone::log("refused pick-up of quest item %u: the quests asking for it have enough (refusal #%u)", item, g_refused);
            return 0;
        }
        if (k > 0 && (unsigned long)k < want) want = (unsigned long)k;
    }
    // 1. the stock pick of what is wanted, its result held back: a success (whole stack, or the quest's share into one
    //    cell / an empty cell) is the stock path; only "bag full" (0x346) goes on to the per-cell split
    unsigned long remaining = want;
    if (want == lot) {
        g_capture_result = true, g_result_seen = false;
        const unsigned char r = stock(self, nullptr, drop, info, a3);
        g_capture_result = false;
        if (g_result_seen && !(r != 1 && g_result_err == kPickBagFull)) send_result(self, g_result_err, g_result_handle);
        if (r == 1 || !g_result_seen || g_result_err != kPickBagFull) return r;
    } else {
        const unsigned char r = pick_part(self, drop, info, attr, want, a3, true);
        if (g_result_seen && !(r != 1 && g_result_err == kPickBagFull)) send_result(self, g_result_err, g_result_handle);
        if (r == 1) {
            slot<void (__thiscall*)(void*, void*, unsigned long)>(attr, kAttrSetLot)(attr, &info->iti_itemstruct, lot - want);
            zone::log("partial pick-up of %u: took %lu of %lu (the quest's share), %lu stay on the ground", item, want, lot,
                      lot - want);
            return r;
        }
        if (!g_result_seen || g_result_err != kPickBagFull) return r;
    }
    // 2. the bag is full for the whole amount: fill every cell of this item that has room, one stock pick each
    const unsigned short bag_full_handle = g_result_handle;
    unsigned char last = 0;
    int chunks = 0;
    for (unsigned long room : cell_rooms(self, item, idx->data->MaxLot)) {
        if (!remaining) break;
        const unsigned long n = room < remaining ? room : remaining;
        if (pick_part(self, drop, info, attr, n, a3, false) == 1) remaining -= n, last = 1, ++chunks;
    }
    const unsigned long taken = want - remaining;
    if (!taken) {
        send_result(self, kPickBagFull, bag_full_handle);                   // nothing fits: the stock refusal
        return 0;
    }
    if (taken == lot) {
        item_picked(drop, nullptr);                                         // used up: picked as stock does
    } else {
        slot<void (__thiscall*)(void*, void*, unsigned long)>(attr, kAttrSetLot)(attr, &info->iti_itemstruct, lot - taken);
    }
    zone::log("partial pick-up of %u: took %lu of %lu into %d cell(s) (bag full), %lu stay on the ground", item, taken, lot,
              chunks, lot - taken);
    return last;
}

}  // namespace

HOOK_PLUGIN("quest_item_enough") {
    zone::hook_function("CQuestZone::IsQuestDropItem (no pick-up once the quest has enough)",
                        (void*)zone::fn::CQuestZone__IsQuestDropItem(), (void*)is_quest_drop_item, &g_drop_item);
    zone::hook_function("ShinePlayer::so_ply_PickupItem (partial pick-up of a quest item stack)",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__so_ply_PickupItem(), (void*)pickup, &g_pickup);
    zone::hook_function("ShineDropItem::so_itempicked (held back during a partial pick-up)",
                        (void*)zone::fn::ShineObjectClass__ShineDropItem__so_itempicked(), (void*)item_picked, &g_picked);
    zone::hook_function("ShinePlayer::so_ply_itempickresult (held back while a pick-up is tried whole)",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__so_ply_itempickresult(), (void*)pick_result, &g_result);
}
