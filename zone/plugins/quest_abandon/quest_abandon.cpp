// quest_abandon - giving up a quest takes the quest items it was dropping.
//
// Operator 2026-09-26: abandoning a quest should remove its quest items - "read the list of quest items of the created
// type, and delete just those. Those are the ones the active quest adds to drop tables".
//
// ---- THE STOCK GIVE-UP (read from Zone.exe) ------------------------------------------------------------------------
//   ShinePlayer::sp_NC_QUEST_GIVE_UP_REQ 0x578910 (the delay check, recipe quest-giveup-delay)
//     -> CQuestZone::Recv_NC_QUEST_GIVE_UP_REQ(PROTO_NC_QUEST_GIVE_UP_REQ*) 0x5BD960:
//        GetQuestInfo / GetQuestData / IsDoingQuest, SetQuestInfoClearRepeat, Send_NC_QUEST_DB_SET_INFO_REQ,
//        Send_NC_QUEST_DB_GIVE_UP_REQ, Send_NC_QUEST_GIVE_UP_ACK. Nothing touches the inventory.
//
// ---- WHICH ITEMS -------------------------------------------------------------------------------------------------------
// The quest's drop rules: QUEST_DATA.Action[i] with ThenType 1, ThenTarget = the item a kill drops while the quest is
// in progress (CQuestZone::QuestActionMobKill 0x5BD000). Fiesta2026on2016 keeps one source per quest item among the 10
// actions (migration 0341), so these name every item a quest drops; quest_ext only rolls extra sources of the same
// items. In the merged data 811 items are such drops, 800 of them ItemInfoServer.ItemSort_Index IS_QUEST; the other 11
// are ordinary things a player also gets elsewhere (RoyalWood, CrystalOre, BestToadStool, a recipe scroll, event
// items), so only IS_QUEST items are taken. 151 drop items are shared by several quests: an item another quest in
// progress also drops or asks for (End.ItemList) is kept.
//
// ---- HOW -------------------------------------------------------------------------------------------------------------
// The hand-in path's own call: the END script's `DELETE_ITEM <item> ALL` (CQuestZone::QuestNext 0x5BE253) is
// ShinePlayer::sp_DestroyItem(handle, item, count, 0) 0x527B60; count <= 0 destroys every unlocked inventory copy and
// saves through the zone's item-DB destroy (0x3459). One log line per item (quest_abandon: ...).
#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cstring>
#include <vector>

namespace {

using zone::types::PLAYER_QUEST_INFO;
using zone::types::QUEST_DATA;

const char* kQuestSort = "IS_QUEST";
const unsigned char kThenDropItem = 1;       // QUEST_DATA.Action ThenType: drop ThenTarget
const int kActions = 10;
const unsigned kQuestZonePlayer = 0xB4;      // CQuestZone::m_pPlayer
const unsigned kQuestZoneData = 0x4;         // CQuest -> CQuestData*
const unsigned kQuestCount = 0x8;            // CQuest: number of quest records
const unsigned kPlayerHandle = 0x4;          // what DELETE_ITEM passes: movzx edx, word [player+4]
const unsigned char kStatusDoing = 6, kStatusReady = 8;   // 6 doing, 7 failed, 8 reward pending

zone::Detour g_give_up;

bool in_progress(const PLAYER_QUEST_INFO* qi) { return qi && qi->Status >= kStatusDoing && qi->Status <= kStatusReady; }

QUEST_DATA* quest_data(void* quests, unsigned short id) {
    return zone::fn::CQuestData__GetQuestData()(*(void**)((char*)quests + kQuestZoneData), nullptr, id);
}

std::vector<unsigned short> drop_items(const QUEST_DATA* q) {
    std::vector<unsigned short> v;
    for (int i = 0; q && i < q->NumOfAction && i < kActions; ++i) {
        const auto& a = q->Action[i];
        if (a.ThenType != kThenDropItem) continue;
        const unsigned short item = (unsigned short)a.ThenTarget;
        bool seen = false;
        for (unsigned short x : v) seen |= x == item;
        if (!seen) v.push_back(item);
    }
    return v;
}

bool uses_item(const QUEST_DATA* q, unsigned short item) {
    if (!q) return false;
    for (const auto& e : q->End.ItemList)
        if (e.bItem && e.ItemID == item) return true;
    for (unsigned short x : drop_items(q))
        if (x == item) return true;
    return false;
}

// the in-progress quest (other than `skip`) that also drops or asks for the item, or 0
unsigned short other_user(void* quests, unsigned short skip, unsigned short item) {
    const int count = *(int*)((char*)quests + kQuestCount);
    for (int i = 0; i < count; ++i) {
        PLAYER_QUEST_INFO* qi = zone::fn::CQuest__GetQuestInfoByIndex()(quests, nullptr, i);
        if (in_progress(qi) && qi->ID != skip && uses_item(quest_data(quests, qi->ID), item)) return qi->ID;
    }
    return 0;
}

void take_items(void* quests, void* player, unsigned short quest) {
    const unsigned char_no = (unsigned)zone::fn::ShineObjectClass__ShinePlayer__so_GetCharRegistNumber()(player, 0);
    const unsigned short handle = *(unsigned short*)((char*)player + kPlayerHandle);
    for (unsigned short item : drop_items(quest_data(quests, quest))) {
        auto* idx = zone::fn::ItemDataBox__operator__()(zone::global::itemdatabox(), nullptr, item);
        const char* name = idx && idx->data ? idx->data->InxName : "?";
        const char* sort = idx && idx->dataserv ? idx->dataserv->ItemSort_Index : "?";
        const int have = zone::fn::ShineObjectClass__ShinePlayer__sp_GetItemInvenLot()(player, nullptr, item);
        if (have <= 0) continue;
        if (std::strcmp(sort, kQuestSort)) {
            zone::log("quest_abandon: char %u quest %u item %u %s x%d kept (%s, not a quest item)",
                      char_no, quest, item, name, have, sort);
            continue;
        }
        if (unsigned short other = other_user(quests, quest, item)) {
            zone::log("quest_abandon: char %u quest %u item %u %s x%d kept (quest %u in progress uses it)",
                      char_no, quest, item, name, have, other);
            continue;
        }
        const bool ok = zone::fn::ShineObjectClass__ShinePlayer__sp_DestroyItem_4()(player, nullptr, handle, item, 0, nullptr) != 0;
        zone::log("quest_abandon: char %u quest %u item %u %s x%d %s", char_no, quest, item, name, have,
                  ok ? "taken" : "NOT taken (sp_DestroyItem failed - locked in a trade or booth?)");
    }
}

void __fastcall give_up(void* quests, void*, const unsigned short* req) {
    const unsigned short id = req ? *req : 0;
    const bool was = in_progress(zone::fn::CQuest__GetQuestInfo()(quests, nullptr, id));
    ((void(__fastcall*)(void*, void*, const unsigned short*))g_give_up.trampoline)(quests, nullptr, req);
    void* player = quests ? *(void**)((char*)quests + kQuestZonePlayer) : nullptr;
    if (!was || !player || in_progress(zone::fn::CQuest__GetQuestInfo()(quests, nullptr, id))) return;   // refused
    take_items(quests, player, id);
}

}  // namespace

ZONEHOOK_PLUGIN("quest_abandon") {
    zone::hook_function("CQuestZone::Recv_NC_QUEST_GIVE_UP_REQ 0x5BD960 (a given-up quest's drop items are taken)",
                        (void*)zone::fn::CQuestZone__Recv_NC_QUEST_GIVE_UP_REQ(), (void*)give_up, &g_give_up);
}
