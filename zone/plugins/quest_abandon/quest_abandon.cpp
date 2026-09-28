// quest_abandon - giving up a quest takes the quest items it was dropping.
//
// Operator 2026-09-26: abandoning a quest should remove its quest items - "read the list of quest items of the created
// type, and delete just those. Those are the ones the active quest adds to drop tables".
//
// ---- THE STOCK GIVE-UP (read from Zone.exe) ------------------------------------------------------------------------
//   ShinePlayer::sp_NC_QUEST_GIVE_UP_REQ 0x578910 (the delay check, recipe quest-giveup-delay)
//     -> CQuestZone::Recv_NC_QUEST_GIVE_UP_REQ(PROTO_NC_QUEST_GIVE_UP_REQ*) 0x5BD960:
//        GetQuestInfo / GetQuestData / IsDoingQuest, then by QUEST_DATA +0x12 (repeatable):
//          repeatable     -> SetQuestInfoClearRepeat + Send_NC_QUEST_DB_SET_INFO_REQ: the quest ends HERE;
//          not repeatable -> Send_NC_QUEST_DB_GIVE_UP_REQ only: the quest is still in progress when this returns. It ends
//            in CQuestZone::Recv_NC_QUEST_DB_GIVE_UP_ACK 0x5BAFC0 when the Character DB answers ErrorType 0xB41 (ok):
//            AddQuestInfo(status 0x14) then Send_NC_QUEST_GIVE_UP_ACK.
//        Nothing touches the inventory. So the items are taken in both places: after the REQ when the quest ended there,
//        after an ok DB ACK otherwise (found 2026-09-27: "Green Maria 2" kept its Rock Dust - v1 hooked only the REQ).
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
#include <unordered_map>
#include <vector>

namespace {

using zone::types::CDataReader;
using zone::types::CDataReader__FIELD;
using zone::types::CDataReader__HEAD;
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
const unsigned short kDbGiveUpOk = 0xB41;   // PROTO_NC_QUEST_DB_GIVE_UP_ACK.ErrorType on success

zone::Detour g_give_up, g_db_ack;

bool in_progress(const PLAYER_QUEST_INFO* qi) { return qi && qi->Status >= kStatusDoing && qi->Status <= kStatusReady; }

QUEST_DATA* quest_data(void* quests, unsigned short id) {
    return zone::fn::CQuestData__GetQuestData()(*(void**)((char*)quests + kQuestZoneData), nullptr, id);
}

// A column of any width the reader declares, by name.
struct Col { int off = -1, size = 0; };
unsigned long field(const unsigned char* rec, const Col& c) {
    if (c.off < 0) return 0;
    if (c.size == 1) return rec[c.off];
    if (c.size == 2) return *(const unsigned short*)(rec + c.off);
    return *(const unsigned long*)(rec + c.off);
}

// Reads a 9Data table with the zone's own CDataReader and calls per_row(record, cols) for each record; cols[k] is
// the column named names[k]. False (logged) when the file or a column is missing.
template <class F>
bool read_table(const char* path, const char* const* names, int n, F per_row) {
    void* reader = ::operator new(sizeof(CDataReader));
    zone::fn::CDataReader__CDataReader()(reader, nullptr);
    bool ok = zone::fn::CDataReader__Read()(reader, nullptr, (char*)path) != 0;
    std::vector<Col> c(n);
    if (!ok) {
        zone::log("cannot read %s", path);
    } else {
        CDataReader* r = (CDataReader*)reader;
        const CDataReader__FIELD* f = (const CDataReader__FIELD*)((const unsigned char*)r->m_pHead + sizeof(CDataReader__HEAD));
        int off = 0;
        for (unsigned i = 0; i < r->m_pHead->nNumOfField; ++i) {
            for (int k = 0; k < n; ++k)
                if (!std::strcmp(f[i].Name, names[k])) { c[k].off = off; c[k].size = (int)f[i].Size; }
            off += (int)f[i].Size;
        }
        for (int k = 0; k < n && ok; ++k)
            if (c[k].off < 0) { zone::log("%s has no %s column", path, names[k]); ok = false; }
    }
    if (ok) {
        unsigned long rows = zone::fn::CDataReader__GetNumOfRecord()(reader, nullptr);
        for (unsigned long i = 0; i < rows; ++i) {
            const unsigned char* rec = (const unsigned char*)zone::fn::CDataReader__GetRecord()(reader, nullptr, i);
            if (rec) per_row(rec, c.data());
        }
    }
    zone::fn::CDataReader___CDataReader()(reader, nullptr);
    ::operator delete(reader);
    return ok;
}

// 2026's QuestAction table: the kill -> drop rows past a quest's 10 QUEST_DATA actions, which quest_ext rolls (found
// 2026-09-28: quest 100's Goblin Captain's Helmet, Q_GoblinCap, drops ONLY from its QuestAction row, so a give-up
// kept it). Result 1 = drop ResultTarget. Read once at load with the zone's own reader, like quest_ext.
std::unordered_map<unsigned short, std::vector<unsigned short>> g_extra;   // quest id -> items its extra rows drop

void load_extra() {
    const char* names[] = {"ID", "Result", "ResultTarget"};
    unsigned long rows = 0;
    if (!read_table("../9Data/Shine/QuestAction.shn", names, 3, [&](const unsigned char* rec, const Col* c) {
            if (field(rec, c[1]) != kThenDropItem) return;
            g_extra[(unsigned short)field(rec, c[0])].push_back((unsigned short)field(rec, c[2]));
            ++rows;
        })) {
        zone::log("quest_abandon: no QuestAction.shn - only the QUEST_DATA drop items are taken");
        return;
    }
    zone::log("quest_abandon: %lu QuestAction drop rows for %u quests (taken on give-up too)", rows, (unsigned)g_extra.size());
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
    if (q) {
        auto it = g_extra.find(q->ID);
        if (it != g_extra.end())
            for (unsigned short item : it->second) {
                bool seen = false;
                for (unsigned short x : v) seen |= x == item;
                if (!seen) v.push_back(item);
            }
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
    if (!was || !player) return;
    if (in_progress(zone::fn::CQuest__GetQuestInfo()(quests, nullptr, id))) {
        zone::log("quest_abandon: quest %u give-up sent to the Character DB, items are taken on its ACK", id);
        return;
    }
    take_items(quests, player, id);
}

void __fastcall db_ack(void* quests, void*, const zone::types::PROTO_NC_QUEST_DB_GIVE_UP_ACK* ack) {
    ((void(__fastcall*)(void*, void*, const void*))g_db_ack.trampoline)(quests, nullptr, ack);
    void* player = quests ? *(void**)((char*)quests + kQuestZonePlayer) : nullptr;
    if (!ack || !player) return;
    if (ack->ErrorType != kDbGiveUpOk) {
        zone::log("quest_abandon: quest %u give-up refused by the Character DB (0x%X), items kept", ack->nQuestID, ack->ErrorType);
        return;
    }
    take_items(quests, player, ack->nQuestID);
}

}  // namespace

ZONEHOOK_PLUGIN("quest_abandon") {
    load_extra();
    zone::hook_function("CQuestZone::Recv_NC_QUEST_GIVE_UP_REQ 0x5BD960 (a given-up quest's drop items are taken)",
                        (void*)zone::fn::CQuestZone__Recv_NC_QUEST_GIVE_UP_REQ(), (void*)give_up, &g_give_up);
    zone::hook_function("CQuestZone::Recv_NC_QUEST_DB_GIVE_UP_ACK 0x5BAFC0 (a non-repeatable quest ends here)",
                        (void*)zone::fn::CQuestZone__Recv_NC_QUEST_DB_GIVE_UP_ACK(), (void*)db_ack, &g_db_ack);
}
