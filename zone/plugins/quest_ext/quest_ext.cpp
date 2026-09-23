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
// NOT HERE: kill targets past End.NPCMobList[5] (6 quests) - those counters live in PLAYER_QUEST_INFO and the
// character DB; a different change.
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
const unsigned char kStatusDoing = 6;       // PLAYER_QUEST_STATUS as the stock loop tests it
const unsigned char kStatusReady = 8;
const unsigned char kStatusFailed = 7;
const unsigned char kQuestTypeParty = 8;    // IsConnectionAction's Type test
const unsigned int kVaRandom = 0x150BA418u; // cWell512Random the stock drop rolls with (0x5BD22B)
const unsigned int kRoll = 1000000;         // ThenPersent is out of 1,000,000

struct Rule { unsigned char if_type, then_type, group; unsigned long if_target, then_target, pct, cmin, cmax; };
std::unordered_map<unsigned short, std::vector<Rule>>* g_rules = nullptr;   // quest id -> every 2026 row
zone::Detour g_kill;

// A column of any width the reader declares, by name.
struct Col { int off = -1, size = 0; };
unsigned long field(const unsigned char* rec, const Col& c) {
    if (c.off < 0) return 0;
    if (c.size == 1) return rec[c.off];
    if (c.size == 2) return *(const unsigned short*)(rec + c.off);
    return *(const unsigned long*)(rec + c.off);
}

bool load_table() {
    void* reader = ::operator new(sizeof(CDataReader));
    zone::fn::CDataReader__CDataReader()(reader, nullptr);
    if (!zone::fn::CDataReader__Read()(reader, nullptr, (char*)kTablePath)) {
        zone::log("cannot read %s - quests keep their 10 QUEST_DATA actions", kTablePath);
        zone::fn::CDataReader___CDataReader()(reader, nullptr);
        ::operator delete(reader);
        return false;
    }
    CDataReader* r = (CDataReader*)reader;
    const CDataReader__FIELD* f = (const CDataReader__FIELD*)((const unsigned char*)r->m_pHead + sizeof(CDataReader__HEAD));
    const char* names[] = {"ID", "Condition", "ConditionTarget", "Group", "Result", "ResultTarget", "Percent", "CountMin", "CountMax"};
    Col c[9];
    int off = 0;
    for (unsigned i = 0; i < r->m_pHead->nNumOfField; ++i) {
        for (int k = 0; k < 9; ++k)
            if (!std::strcmp(f[i].Name, names[k])) { c[k].off = off; c[k].size = (int)f[i].Size; }
        off += (int)f[i].Size;
    }
    for (int k = 0; k < 9; ++k)
        if (c[k].off < 0) {
            zone::log("%s has no %s column - quests keep their 10 QUEST_DATA actions", kTablePath, names[k]);
            zone::fn::CDataReader___CDataReader()(reader, nullptr);
            ::operator delete(reader);
            return false;
        }
    unsigned long n = zone::fn::CDataReader__GetNumOfRecord()(reader, nullptr), kept = 0;
    for (unsigned long i = 0; i < n; ++i) {
        const unsigned char* rec = (const unsigned char*)zone::fn::CDataReader__GetRecord()(reader, nullptr, i);
        if (!rec) continue;
        Rule x = {(unsigned char)field(rec, c[1]), (unsigned char)field(rec, c[4]), (unsigned char)field(rec, c[3]),
                  field(rec, c[2]), field(rec, c[5]), field(rec, c[6]), field(rec, c[7]), field(rec, c[8])};
        if (x.if_type != 1 || x.then_type != 1) continue;     // only kill -> drop rows exist past the 10
        (*g_rules)[(unsigned short)field(rec, c[0])].push_back(x);
        ++kept;
    }
    zone::fn::CDataReader___CDataReader()(reader, nullptr);
    ::operator delete(reader);
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

}  // namespace

HOOK_PLUGIN("quest_ext") {
    g_rules = new std::unordered_map<unsigned short, std::vector<Rule>>();
    if (!load_table()) return;
    void* target = zone::rebase(zone::fn::kVa_CQuestZone__QuestPlayer_NPCMobKill);
    if (!zone::detour(target, (void*)npc_mob_kill, &g_kill)) { zone::log("QuestPlayer_NPCMobKill: NOT hooked"); return; }
    zone::log("CQuestZone::QuestPlayer_NPCMobKill at %x -> %x: 2026 kill->drop rows past QUEST_DATA's 10 are rolled",
              target, (void*)npc_mob_kill);
}
