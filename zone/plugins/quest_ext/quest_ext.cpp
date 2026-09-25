// quest_ext - 2026 quest item-drop rules past the 10 QUEST_DATA holds.
//
// ---- THE LIMIT --------------------------------------------------------------------------------------
//
// QUEST_DATA (Zone.pdb, 680 bytes) has Action[10]: {IfType, IfTarget, ThenType, ThenTarget, ThenPersent,
// ThenCountMin, ThenCountMax, TargetGroup}. 2026's QuestAction table gives 8 quests more (11..23 unique rows;
// 65484 / 65485 gather 5 herbs / clams from 23 nodes). Fiesta2026on2016 migration 0341 keeps the best 10 (one
// source per quest item); the 44 rows that do not fit are all IfType 1 (mob kill) -> ThenType 1 (drop an item).
//
// ---- THE STOCK PATH (read from Zone.exe) --------------------------------------------------------------
//
//   CQuestZone::QuestPlayer_NPCMobKill(mob)                                   0x5C08D0
//     for each quest the player holds (count this+8, CQuest::GetQuestInfoByIndex) with Status 6 (doing):
//       QUEST_DATA = CQuestData::GetQuestData(this+4, id)
//       ... kill counters (End.NPCMobList, 5 slots) ...
//       for j < NumOfAction: IsConnectionAction(q, j, mobid)  0x5B9B60 -> QuestActionMobKill(info, q, j, mob)  0x5BD000
//       if anything changed: DoingQuestUpdateStatus(i); 6 -> 8 calls vtable+0x50, -> 7 vtable+0x54
//   IsConnectionAction: player vtable+0xA84 must agree with (q.Type == 8); IfType == 1;
//                       MobDataBox::mdb_IsSpeciesDistanceByQuest(IfTarget, mobid, TargetGroup)
//   QuestActionMobKill, the drop:  need = GetSuccessItemCount(q, item); have = sp_GetItemInvenLot(item);
//                       have < need and well512(1e6) < ThenPersent -> n = min + well512(1e6)*(max-min)/1e6,
//                       capped at need - have; sp_QuestItemGet(item, mob) n times.
//
// This plugin runs the stock function, then does exactly that for the quest's 2026 rows that are NOT among its
// QUEST_DATA actions - so a row the merge kept is never rolled twice. The rows come from the 2026 QuestAction
// table, shipped to 9Data/Shine by the merge (overrides/server/Shine/QuestAction.shn), read with the zone's own
// CDataReader.
//
// ---- THE HAND-IN NPC OF QUESTS WITH MORE THAN 5 END ROWS ----------------------------------------------
//
// 6 quests are the hand-in NPC (NpcMobActionType 0) + 5..7 kills; End.NPCMobList has 5 slots. The merge
// (Fiesta2026on2016 merge_quests END_OVERFLOW / migration 0351) gives the slots to the kills, so the record has no
// action-0 slot, which is where the zone reads the hand-in NPC:
//   CQuest::GetRewardNPC(QUEST_DATA*)        0x62FBF0: the first used slot with action 0 -> its MobID, else 0xFFFF
//   CQuest::IsQuestNPCMob(QUEST_DATA*, npc)  0x62FB50: the start NPC, or a used slot with action 0 or 3
// (GetRewardNPC(u16 quest) 0x62FC40 looks the quest up and calls the first.) When the stock answer finds no action-0
// slot, both answer from the 2026 QuestEndNpc (shipped to 9Data/Shine/QuestEndNpc.shn like QuestAction.shn). A
// quest whose record still has its action-0 slot is answered by the stock code alone. The quest's counters stay the
// zone's 5 bytes; Bridge2026 shifts them one slot up for the 2026 client, whose rows keep the talk row first.
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

const char* kTablePath = "../9Data/Shine/QuestAction.shn";
const char* kEndNpcPath = "../9Data/Shine/QuestEndNpc.shn";
const unsigned short kNoNpc = 0xFFFF;             // GetRewardNPC's "none"
const unsigned char kStatusDoing = 6;       // PLAYER_QUEST_STATUS as the stock loop tests it
const unsigned char kStatusReady = 8;
const unsigned char kStatusFailed = 7;
const unsigned char kQuestTypeParty = 8;    // IsConnectionAction's Type test
const unsigned int kVaRandom = 0x150BA418u; // cWell512Random the stock drop rolls with (0x5BD22B)
const unsigned int kRoll = 1000000;         // ThenPersent is out of 1,000,000

struct Rule { unsigned char if_type, then_type, group; unsigned long if_target, then_target, pct, cmin, cmax; };
std::unordered_map<unsigned short, std::vector<Rule>>* g_rules = nullptr;   // quest id -> every 2026 row
zone::Detour g_kill, g_reward_npc, g_is_npc;
std::unordered_map<unsigned short, unsigned short>* g_end_npc = nullptr;   // quest id -> 2026 hand-in NPC

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

bool load_table() {
    const char* names[] = {"ID", "Condition", "ConditionTarget", "Group", "Result", "ResultTarget", "Percent", "CountMin", "CountMax"};
    unsigned long kept = 0;
    bool ok = read_table(kTablePath, names, 9, [&](const unsigned char* rec, const Col* c) {
        Rule x = {(unsigned char)field(rec, c[1]), (unsigned char)field(rec, c[4]), (unsigned char)field(rec, c[3]),
                  field(rec, c[2]), field(rec, c[5]), field(rec, c[6]), field(rec, c[7]), field(rec, c[8])};
        if (x.if_type != 1 || x.then_type != 1) return;       // only kill -> drop rows exist past the 10
        (*g_rules)[(unsigned short)field(rec, c[0])].push_back(x);
        ++kept;
    });
    if (!ok) { zone::log("quests keep their 10 QUEST_DATA actions"); return false; }
    zone::log("%lu kill->drop rows for %u quests from %s", kept, (unsigned)g_rules->size(), kTablePath);
    return !g_rules->empty();
}

bool in_quest_data(const QUEST_DATA* q, const Rule& x) {
    for (int j = 0; j < q->NumOfAction && j < 10; ++j) {
        const auto& a = q->Action[j];
        if (a.IfType == x.if_type && a.IfTarget == x.if_target && a.ThenType == x.then_type &&
            a.ThenTarget == x.then_target && a.TargetGroup == x.group)
            return true;
    }
    return false;
}

unsigned roll() {
    return zone::fn::cWell512Random__well512_GetRandom_3()(zone::rebase(kVaRandom), nullptr, kRoll);
}

// The stock drop (QuestActionMobKill's item branch) for one row. Returns whether it gave anything.
bool drop(void* self, void* player, QUEST_DATA* q, const Rule& x, void* mob) {
    const unsigned short item = (unsigned short)x.then_target;
    int need = zone::fn::CQuestZone__GetSuccessItemCount()(self, nullptr, q, item);
    int have = zone::fn::ShineObjectClass__ShinePlayer__sp_GetItemInvenLot()(player, nullptr, item);
    if (have >= need || roll() >= x.pct) return false;
    unsigned n = x.cmin + (unsigned)(((unsigned long long)roll() * (x.cmax - x.cmin)) / kRoll);
    if (n > (unsigned)(need - have)) n = (unsigned)(need - have);
    for (unsigned k = 0; k < n; ++k)
        zone::fn::ShineObjectClass__ShinePlayer__sp_QuestItemGet()(player, nullptr, item, (zone::types::ShineObjectClass__ShineObject*)mob);
    return n > 0;
}

int __fastcall npc_mob_kill(void* self, void*, void* mob) {
    int r = ((int (__fastcall*)(void*, void*, void*))g_kill.trampoline)(self, nullptr, mob);
    void* player = *(void**)((char*)self + 0xB4);
    if (!player || !mob) return r;
    // the mob id, as the stock loop reads it (0x5C097D): mob vtable+0x710 called WITH the player, -> a pointer to
    // its MobInfo row, whose first word is the id
    void* info = ((void* (__thiscall*)(void*, void*))(*(void***)mob)[0x710 / 4])(mob, player);
    if (!info) return r;
    const unsigned short mobid = **(unsigned short**)info;
    const bool party = ((int (__thiscall*)(void*))(*(void***)player)[0xA84 / 4])(player) != 0;
    const int count = *(int*)((char*)self + 8);
    for (int i = 0; i < count; ++i) {
        PLAYER_QUEST_INFO* qi = zone::fn::CQuest__GetQuestInfoByIndex()(self, nullptr, i);
        if (!qi || qi->Status != kStatusDoing) continue;
        auto it = g_rules->find(qi->ID);
        if (it == g_rules->end()) continue;
        QUEST_DATA* q = zone::fn::CQuestData__GetQuestData()(*(void**)((char*)self + 4), nullptr, qi->ID);
        if (!q || party != (q->Type == kQuestTypeParty)) continue;
        bool gave = false;
        for (const Rule& x : it->second) {
            if (in_quest_data(q, x)) continue;                  // the stock loop already rolled it
            if (!zone::fn::MobDataBox__mdb_IsSpeciesDistanceByQuest()(zone::global::mobdatabox(), nullptr,
                                                                    (unsigned short)x.if_target, mobid, x.group))
                continue;
            gave |= drop(self, player, q, x, mob);
        }
        if (!gave) continue;
        const unsigned char was = qi->Status;
        const int now = zone::fn::CQuest__DoingQuestUpdateStatus()(self, nullptr, i);
        if (was == kStatusDoing && (now == kStatusReady || now == kStatusFailed)) {
            void* fn = (*(void***)self)[(now == kStatusReady ? 0x50 : 0x54) / 4];
            ((void (__thiscall*)(void*, PLAYER_QUEST_INFO*, QUEST_DATA*))fn)(self, qi, q);
        }
        r = 1;
    }
    return r;
}

// ---- the hand-in NPC ----------------------------------------------------------------------------------------------
bool load_end_npcs() {
    const char* names[] = {"ID", "IsEnabled", "MobID", "NpcMobActionType"};
    bool ok = read_table(kEndNpcPath, names, 4, [&](const unsigned char* rec, const Col* c) {
        if (!field(rec, c[1]) || field(rec, c[3]) != 0) return;              // enabled hand-in rows only
        g_end_npc->emplace((unsigned short)field(rec, c[0]), (unsigned short)field(rec, c[2]));   // the first one
    });
    if (ok) zone::log("%u hand-in NPCs from %s", (unsigned)g_end_npc->size(), kEndNpcPath);
    return ok && !g_end_npc->empty();
}

unsigned short end_npc_of(const QUEST_DATA* q) {
    auto it = q ? g_end_npc->find(q->ID) : g_end_npc->end();
    return it == g_end_npc->end() ? kNoNpc : it->second;
}

unsigned short __fastcall reward_npc(void* self, void*, QUEST_DATA* q) {
    unsigned short r = ((unsigned short (__fastcall*)(void*, void*, QUEST_DATA*))g_reward_npc.trampoline)(self, nullptr, q);
    return r != kNoNpc ? r : end_npc_of(q);
}

int __fastcall is_quest_npc(void* self, void*, QUEST_DATA* q, unsigned short npc) {
    if (((int (__fastcall*)(void*, void*, QUEST_DATA*, unsigned short))g_is_npc.trampoline)(self, nullptr, q, npc)) return 1;
    // only for a record with no action-0 slot of its own (stock GetRewardNPC says none)
    if (!q || ((unsigned short (__fastcall*)(void*, void*, QUEST_DATA*))g_reward_npc.trampoline)(self, nullptr, q) != kNoNpc)
        return 0;
    return npc != kNoNpc && end_npc_of(q) == npc;
}

}  // namespace

HOOK_PLUGIN("quest_ext") {
    g_rules = new std::unordered_map<unsigned short, std::vector<Rule>>();
    g_end_npc = new std::unordered_map<unsigned short, unsigned short>();
    if (load_table()) {
        void* target = zone::rebase(zone::fn::kVa_CQuestZone__QuestPlayer_NPCMobKill);
        if (!zone::detour(target, (void*)npc_mob_kill, &g_kill)) zone::log("QuestPlayer_NPCMobKill: NOT hooked");
        else zone::log("CQuestZone::QuestPlayer_NPCMobKill at %x -> %x: 2026 kill->drop rows past QUEST_DATA's 10 are rolled",
                       target, (void*)npc_mob_kill);
    }
    if (load_end_npcs()) {
        zone::hook_function("CQuest::GetRewardNPC (hand-in NPC past End.NPCMobList)",
                            (void*)zone::fn::CQuest__GetRewardNPC(), (void*)reward_npc, &g_reward_npc);
        zone::hook_function("CQuest::IsQuestNPCMob (hand-in NPC past End.NPCMobList)",
                            (void*)zone::fn::CQuest__IsQuestNPCMob(), (void*)is_quest_npc, &g_is_npc);
    } else {
        zone::log("no hand-in NPC table - quests keep the hand-in NPC their QUEST_DATA holds");
    }
}
