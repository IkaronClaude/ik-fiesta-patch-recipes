// bridge26 - the 2026 client's wire shapes, translated INSIDE the zone (operator 2026-10-04: "move the 2026 packet
// translation layer into zone/world/login hook ... so no proxy is required, and disabling it is just a change in the
// ini ... can accept either shape always regardless of settings, setting just changes which version is sent").
//
// Moved over from the proxy's Bridge2026 plugin (fiesta-proxy plugins/Bridge2026) in BATCHES: each batch moves a few
// packets here and removes them from the proxy in the same change, so nothing is translated twice. MOVED SO FAR:
//   batch 1 (S->C, combat): 0x2448 SWING_DAMAGE, 0x2449 SOMEONESWING_DAMAGE, 0x243C DOTDAMAGE, 0x2452 SKILLBASH_HIT_DAMAGE,
//                           0x2402 TARGETINFO
//   batch 2 (S->C): the four SKILLBASH *_START frames 0x244E / 0x2450 / 0x244F / 0x2451 (+u32)
//           (C->S): 0x4811 SKILL_EMPOWALLOC_REQ 14 -> 6 B; 0x4411 QUEST_REWARD_SELECT client index -> zone slot;
//                   0x441F / 0x4421 tracker requests that are not 2 B dropped; 0x182E (2026 map-status request) answered
//                   0x182F {0} here, as official does
//   batch 3 (quest dialog + lists, send=2026 only): 0x4401 script DONE -> relayed + 0x442E, END -> 0x442E (and this zone
//                   is then known to announce ENDs: the per-ack 0x442E stops); C->S 0x4402 ack -> 0x442E to the client;
//                   the client's 0x200B ENDOFTRADE echo of that close (within 1.5 s) swallowed; 0x103A quest DOING and
//                   0x10D7 REPEAT lists 32 -> 37 B per entry (+ counter rows moved per quest-counter-rows.txt), the
//                   TRACKED bit (quest_track) stripped and sent as 0x110F after the DOING list
//   batch 4 (S->C, stateless): 0x1038 CHAR_CLIENT_BASE 105 -> the US 362, 0x104A CHARGEDBUFF list, 0x9003 / 0x9004
//                   BUFFSTART / BUFFTERMINATE, the six SHOPOPEN tables 0x3C03/04/06/09/0A/0B (slot u8 -> u32)
//   batch 5 (S->C, briefinfo records, US width - ini build=us|de): 0x1C08 REGENMOB, 0x1C09 MOB, 0x1C1A REGENMOVER,
//                   0x1C06 LOGINCHARACTER, 0x1C07 CHARACTER; abstates >= 792 learnt from 0x2427/0x2428/0x1C18/0x1C19
//                   and set into the LOGINCHARACTER records' 36 extra bitset bytes
//
// hooks\bridge26.ini:
//   [config]
//   send=2026          shape of the packets this plugin owns, sent to every client (default 2016 = untouched)
//   verify=1           also build the 2026 shape while sending 2016, and log (2016, 2026) pairs to bridge26-verify.log
//                      (tools/bridge26_verify replays them through the proxy's C# translators: they must match)
//   verify_max=200     pairs logged per opcode
//   close_dialog=1     the 0x442E dance for an unmodified 2026 client (0 for a client carrying the self-close recipe)
//   [plugin] after=quest_track   - its 0x441F / 0x4421 handlers must be registered before ours wrap them
//
// C->S: the zone dispatches a client packet through its client protocol table (shineprotofunc); hook::proto swaps the
// slots (no code patch). The table is filled by protocolstore 0x4D4510 at server start, AFTER plugins load, so the slots
// are hooked right after it runs. A handler gets (cmd = opcode + payload, len = opcode + payload, u16). Both shapes are
// accepted whatever `send` says (the 2026 empower is 14 B, the 2016 one 6 B); a translation that changes MEANING but not
// shape (the reward index) is applied when send=2026 (a 2026 client).
//
// ---- WHERE ---------------------------------------------------------------------------------------------------------
// S->C: every game packet to a client is appended by PacketContainer::pcb_Append(ShineObject*, ProtocolPacket*)
// 0x4C8B20 (__thiscall, ret 8), one unframed packet per call {u8* pp_Buffer (opcode + payload), int pp_BufferSize,
// int pp_PacketLength}; the container copies it straight away, so a translated packet can live in a per-thread buffer.
// Server-to-server traffic never passes here (ProtocolPacket::pp_SendPacket), and S->C is plain (pe_FromServerToClient
// is the identity). Read 2026-10-04 (Zone.exe, the RE notes in the commit).
#include <zonehook.h>
#include <zone_types.h>
#include <zone_shn.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <algorithm>
#include <cstddef>
#include <map>
#include <vector>

#include <cstdio>
#include <cstring>

#include "bridge26_translate.h"
#include "bridge26_items.h"
#include "bridge26_tables.h"

namespace {

const unsigned kVaPcbAppend = 0x004C8B20u;
const unsigned kVaProtocolStore = 0x004D4510u;   // protocolstore(PROTOCOLFUNCTIONTEMPLETE<ShinePlayer>*), cdecl

using zone::types::ShineObjectClass__ShinePlayer;
using zone::types::ShineObjectClass__ShinePlayer__SocketStream;
const size_t kGameStreamAt = offsetof(ShineObjectClass__ShinePlayer, sp_SocketContainer) +
                             offsetof(ShineObjectClass__ShinePlayer__SocketStream, gamestream);
static_assert(kGameStreamAt == 0x7E28, "ShinePlayer::gamestream - the client stream senders append to (RE 2026-10-04)");

struct ProtocolPacket {
    unsigned char* buffer;   // opcode + payload
    int size;
    int length;
};

// send=auto (default): each player gets the shapes of ITS client, told apart at map login (the 2026 MAP_LOGIN_REQ carries
// 53 checksums, 1718 B; the 2016 one 49, 1590 B) - 2016 and 2026 clients share the zone. send=2026 / 2016 force one.
enum SendMode { kSendAuto, kSend2016, kSend2026 };
SendMode g_send = kSendAuto;
bool g_verify = false;
int g_verify_max = 200;

zone::Detour g_append;
typedef void(__fastcall* AppendFn)(void* self, void* edx, void* object, ProtocolPacket* pkt);

using namespace bridge26;

// ---- verify log -----------------------------------------------------------------------------------------------------
CRITICAL_SECTION g_vlock;
FILE* g_vlog = 0;
int g_vcount[kOwnedCount];
int g_unknown_shape[kOwnedCount];

void hex(FILE* f, const unsigned char* p, int n) { for (int i = 0; i < n; i++) fprintf(f, "%02X", p[i]); }

void verify_log(const Owned* o, const unsigned char* in, int n, const unsigned char* out, int m) {
    int idx = (int)(o - kOwned);
    EnterCriticalSection(&g_vlock);
    if (g_vlog && g_vcount[idx] < g_verify_max) {
        g_vcount[idx]++;
        fprintf(g_vlog, "%04X ", o->op);
        hex(g_vlog, in, n);
        fputc(' ', g_vlog);
        if (m) hex(g_vlog, out, m); else fputc('-', g_vlog);
        fputc('\n', g_vlog);
        fflush(g_vlog);
    }
    LeaveCriticalSection(&g_vlock);
}

std::map<unsigned, int> g_vcount_op;
void verify_log_op(unsigned op, const unsigned char* in, int n, const unsigned char* out, int m) {
    EnterCriticalSection(&g_vlock);
    if (g_vlog && g_vcount_op[op] < g_verify_max) {
        g_vcount_op[op]++;
        fprintf(g_vlog, "%04X ", op);
        hex(g_vlog, in, n);
        fputc(' ', g_vlog);
        if (m) hex(g_vlog, out, m); else fputc('-', g_vlog);
        fputc('\n', g_vlog);
        fflush(g_vlog);
    }
    LeaveCriticalSection(&g_vlock);
}

// ---- sending to a client ---------------------------------------------------------------------------------------------
// The player's own stream (gamestream: the real container once logged in, a do-nothing one before), vtable slot 3 =
// pcb_Append - the same call every zone sender makes, so it passes through on_append too.
void send_to_client(void* player, unsigned short op, const unsigned char* payload, int n) {
    if (!player || n < 0 || n > 0x1000) return;
    void* stream = *(void**)((unsigned char*)player + kGameStreamAt);
    if (!stream) return;
    unsigned char buf[0x1002];
    buf[0] = (unsigned char)op; buf[1] = (unsigned char)(op >> 8);
    memcpy(buf + 2, payload, n);
    ProtocolPacket pkt = { buf, (int)sizeof buf, n + 2 };
    typedef void(__fastcall * AppendVt)(void*, void*, void*, ProtocolPacket*);
    ((AppendVt)(*(void***)stream)[3])(stream, 0, player, &pkt);
}

// ---- per-player state (keyed by the ShinePlayer the packet is for; several map threads send, so under a lock) ----------
struct PlayerState {
    int client = 0;                        // 2016 / 2026 as its map login said; 0 = not seen (send=auto: 2016 shapes)
    std::vector<unsigned short> tracked;   // the quest tracker set built from this login's DOING list(s)
    std::vector<int> folded_empty;         // 2026 equip slots this client already has empty (items, batch 6)
    DWORD close_sent_at = 0;               // when we last told the client to close its dialog (0x442E); 0 = not pending
    bool close_pending = false;
};
CRITICAL_SECTION g_plock;
std::map<void*, PlayerState> g_players;

// does this player get the 2026 shapes?
bool to2026(void* player) {
    if (g_send != kSendAuto) return g_send == kSend2026;
    EnterCriticalSection(&g_plock);
    std::map<void*, PlayerState>::const_iterator it = g_players.find(player);
    bool r = it != g_players.end() && it->second.client == 2026;
    LeaveCriticalSection(&g_plock);
    return r;
}
bool g_close_dialog = true;
volatile LONG g_zone_announces_end = 0;     // learned: this zone's exe sends QSC_END itself (quest-script-end-notify)
const unsigned char kCloseDialog[2] = { 0xFF, 0xFF };
const DWORD kCloseEchoMs = 1500;

// ---- the 2026 quest tables, read with the zone's own CDataReader (quest_ext's pattern) ---------------------------------
// No side files (operator 2026-10-04: "NO AUXILIARY FILES ... if you need an shn, load it via the server native funcs"):
// the 2026 client's QuestEndNpc / QuestReward come from 9Data/Shine (shipped by the build), the 2016 side is the zone's
// own QUEST_DATA (gQuestData), and the two mappings tools/bridge_data.py used to precompute are derived here, per quest,
// on first use.
struct Col { int off = -1; int size = 0; };
unsigned long field(const unsigned char* rec, const Col& c) {
    if (c.size == 1) return rec[c.off];
    if (c.size == 2) return *(const unsigned short*)(rec + c.off);
    return *(const unsigned long*)(rec + c.off);                  // 4, and the low half of an 8-byte column
}

template <class F>
bool read_table(const char* path, const char* const* names, int n, F per_row) {
    using zone::types::CDataReader;
    using zone::types::CDataReader__FIELD;
    using zone::types::CDataReader__HEAD;
    void* reader = ::operator new(sizeof(CDataReader));
    zone::fn::CDataReader__CDataReader()(reader, nullptr);
    bool ok = zone::fn::CDataReader__Read()(reader, nullptr, (char*)path) != 0;
    std::vector<Col> c(n);
    if (!ok) {
        zone::log("[bridge26] cannot read %s", path);
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
            if (c[k].off < 0) { zone::log("[bridge26] %s has no %s column", path, names[k]); ok = false; }
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

struct EndRow { unsigned short mob; unsigned char action; bool kill; };
struct RewRow { unsigned char type; unsigned long low; };
std::map<unsigned, std::vector<EndRow> > g_end26;   // quest -> its 2026 QuestEndNpc rows, file order (= the client's rows)
std::map<unsigned, std::vector<RewRow> > g_rew26;   // quest -> its 2026 QuestReward rows (file order = the client's index),
                                                   // only quests with a choice (a Selectable 2 row)
CRITICAL_SECTION g_qlock;
std::map<unsigned, std::vector<int> > g_counter_rows;   // quest -> the 2026 client row of each zone counter slot (cached)
std::map<unsigned, bool> g_counter_done;
std::map<unsigned, std::vector<int> > g_reward_slots;   // quest -> zone reward slot per client index (-1 = none), cached

void load_quest_tables() {
    const char* end_cols[] = { "ID", "MobID", "NpcMobActionType", "IsEnabled", "Count" };
    read_table("../9Data/Shine/QuestEndNpc.shn", end_cols, 5, [&](const unsigned char* r, const Col* c) {
        EndRow e = { (unsigned short)field(r, c[1]), (unsigned char)field(r, c[2]),
                     field(r, c[3]) && field(r, c[2]) == 1 && field(r, c[4]) };
        g_end26[(unsigned)field(r, c[0])].push_back(e);
    });
    std::map<unsigned, bool> choice;
    const char* rew_cols[] = { "ID", "RewardType", "Flag", "Selectable" };
    read_table("../9Data/Shine/QuestReward.shn", rew_cols, 4, [&](const unsigned char* r, const Col* c) {
        unsigned q = (unsigned)field(r, c[0]);
        RewRow x = { (unsigned char)field(r, c[1]), field(r, c[2]) };
        g_rew26[q].push_back(x);
        if (field(r, c[3]) == 2) choice[q] = true;
    });
    for (std::map<unsigned, std::vector<RewRow> >::iterator it = g_rew26.begin(); it != g_rew26.end();) {
        if (choice.count(it->first)) ++it;
        else it = g_rew26.erase(it);
    }
    zone::log("[bridge26] 2026 quest tables: QuestEndNpc rows for %u quests, reward choices for %u quests",
              (unsigned)g_end26.size(), (unsigned)g_rew26.size());
}

const zone::types::QUEST_DATA* quest_data(unsigned quest) {
    return zone::fn::CQuestData__GetQuestData()(zone::global::gQuestData(), nullptr, (unsigned short)quest);
}

// tools/bridge_data.py counter_rows, here: each zone counter slot k is the client's row of the same (mob, action) as the
// zone's End.NPCMobList[k]; an untimed quest's kill rows past the 5 that quest_ext counts (at most 2) follow
const std::vector<int>* counter_rows(unsigned quest) {
    EnterCriticalSection(&g_qlock);
    if (!g_counter_done[quest]) {
        g_counter_done[quest] = true;
        const zone::types::QUEST_DATA* q = quest_data(quest);
        const std::vector<EndRow>& client = g_end26[quest];
        std::vector<int> want, used;
        for (int k = 0; q && k < 5; k++) {
            const zone::types::QUEST_DATA__QUEST_END_CONDITION___NPCMobList& m = q->End.NPCMobList[k];
            if (!m.bNPCMob) { want.push_back(k); continue; }
            int hit = k;
            for (int i = 0; i < (int)client.size(); i++)
                if (std::find(used.begin(), used.end(), i) == used.end() && client[i].mob == m.NPCMobID
                    && client[i].action == m.NPCMobAction) { hit = i; break; }
            used.push_back(hit);
            want.push_back(hit);
        }
        if (q && !q->End.bTimeLimit) {
            std::vector<int> kills;
            for (int i = 0; i < (int)client.size(); i++) if (client[i].kill) kills.push_back(i);
            if (kills.size() > 5)
                for (int i = 0, added = 0; i < (int)kills.size() && added < 2; i++)
                    if (std::find(used.begin(), used.end(), kills[i]) == used.end()) { want.push_back(kills[i]); added++; }
        }
        bool same = want.size() == 5;
        for (int k = 0; same && k < 5; k++) same = want[k] == k;
        if (q && !same) g_counter_rows[quest] = want;
    }
    std::map<unsigned, std::vector<int> >::const_iterator it = g_counter_rows.find(quest);
    const std::vector<int>* r = it == g_counter_rows.end() ? 0 : &it->second;
    LeaveCriticalSection(&g_qlock);
    return r;
}

// ---- items (batch 6): the 2026 item classes + equip slots ------------------------------------------------------------
// The 2026 client sizes an inventory record from the item's 2026 CLASS, and draws an equipped item at its 2026 EQUIP slot.
// The table half converts ItemInfo for the zone (class 39 -> 0, slots 30-44 folded into 2016 ones) and records each
// item's 2026 Class / Equip from the raw rows on the way (tables::item26); the 2016 slot of each item is the zone's own
// loaded row (build_folds) - the fold is the pair. One read of the file, the zone's.
std::map<int, std::vector<int> > g_folded_into;   // 2016 equip slot -> the 2026 slots folded into it
std::map<int, int> g_equip26;                      // item id -> its 2026 slot, only where that slot is folded
bool g_folds_built = false;

int item_class(int item) {                         // -1 until the zone has loaded (and tables:: converted) ItemInfo
    std::map<int, std::pair<int, int> >::const_iterator it = tables::item26.find(item);
    return it == tables::item26.end() ? -1 : it->second.first;
}

// the raw 2026 ItemInfo: {ID, Class, Equip} per row, through the zone's decrypt

// the fold, against the zone's OWN item table (ItemDataBox, loaded by the zone through client_tables): every item whose
// 2016 Equip differs from its 2026 one. Built on the first equip change, once the zone has loaded its tables.
// Never a second CDataReader read of ItemInfo: CShnDataFileCheckSum::InitDataFileCheckSum (0x6311A0) counts every
// registration of a checksummed table, duplicates included, and refuses past 49 - a second ItemInfo read spent one and
// the zone's last checksummed table (BRAccUpgradeInfo) then failed to load ("Fail to read SHN Data File", 2026-10-04).
void build_folds() {
    EnterCriticalSection(&g_qlock);
    if (!g_folds_built) {
        g_folds_built = true;
        int folds = 0;
        for (std::map<int, std::pair<int, int> >::const_iterator it = tables::item26.begin(); it != tables::item26.end(); ++it) {
            zone::types::ItemDataBox__ItemDataBoxIndex* idx =
                zone::fn::ItemDataBox__operator__()(zone::global::itemdatabox(), nullptr, (unsigned short)it->first);
            if (!idx || !idx->data) continue;
            int slot16 = (int)idx->data->Equip, slot26 = it->second.second;
            if (slot16 == slot26) continue;
            g_equip26[it->first] = slot26;
            std::vector<int>& v = g_folded_into[slot16];
            if (std::find(v.begin(), v.end(), slot26) == v.end()) { v.push_back(slot26); folds++; }
        }
        zone::log("[bridge26] equip fold (zone ItemDataBox vs 2026 ItemInfo): %d folded slot(s), %u items drawn at one",
                  folds, (unsigned)g_equip26.size());
    }
    LeaveCriticalSection(&g_qlock);
}

// verify mode: derive every quest's mappings once and log them, so they can be compared with what the old precomputed
// files held (an offline check; the plugin itself reads no such file)
void log_all_mappings();
volatile LONG g_mappings_logged = 0;

// tools/bridge_data.py reward_index, here: the client's reward rows (items first) matched in order to the zone's used
// QUEST_DATA.Reward slots of the same type and value; -1 = not offered by the zone
int reward_slot(unsigned quest, unsigned index) {
    EnterCriticalSection(&g_qlock);
    std::map<unsigned, std::vector<int> >::iterator it = g_reward_slots.find(quest);
    if (it == g_reward_slots.end()) {
        std::vector<int> slots;
        std::map<unsigned, std::vector<RewRow> >::const_iterator rows = g_rew26.find(quest);
        const zone::types::QUEST_DATA* q = rows == g_rew26.end() ? 0 : quest_data(quest);
        if (q) {
            bool used[12] = {};
            for (const RewRow& r : rows->second) {
                int hit = -1;
                for (int k = 0; k < 12 && hit < 0; k++) {
                    const zone::types::QUEST_DATA__QUEST_REWARD& x = q->Reward[k];
                    if (!x.Use || used[k] || x.Type != r.type) continue;
                    const unsigned char* v = (const unsigned char*)&x.Value;
                    unsigned long val = r.type == 2 ? (unsigned long)(v[0] | (v[1] << 8))
                                                    : (unsigned long)(v[0] | (v[1] << 8) | (v[2] << 16) | ((unsigned long)v[3] << 24));
                    if (val == r.low) hit = k;
                }
                if (hit >= 0) used[hit] = true;
                slots.push_back(hit);
            }
        }
        it = g_reward_slots.insert(std::make_pair(quest, slots)).first;
    }
    int slot = index < it->second.size() ? it->second[index] : -1;
    LeaveCriticalSection(&g_qlock);
    return slot;
}

void log_all_mappings() {
    if (!g_verify || InterlockedExchange(&g_mappings_logged, 1)) return;
    int moved = 0, choices = 0;
    for (std::map<unsigned, std::vector<EndRow> >::const_iterator it = g_end26.begin(); it != g_end26.end(); ++it) {
        const std::vector<int>* r = counter_rows(it->first);
        if (!r) continue;
        char line[128]; int k = 0;
        for (int v : *r) k += sprintf_s(line + k, sizeof line - k, " %d", v);
        zone::log("[bridge26] derived counter rows %u%s", it->first, line);
        moved++;
    }
    for (std::map<unsigned, std::vector<RewRow> >::const_iterator it = g_rew26.begin(); it != g_rew26.end(); ++it)
        for (unsigned i = 0; i < it->second.size(); i++) {
            int slot = reward_slot(it->first, i);
            if (slot >= 0) { zone::log("[bridge26] derived reward %u %u %d", it->first, i, slot); choices++; }
        }
    zone::log("[bridge26] derived: %d quests with moved counter rows, %d reward choices", moved, choices);
}

// PLAYER_QUEST_INFO 32 B -> 37 B (T.QuestEntry2016To2026): the same 32 bytes, 5 zero; a quest whose 2016 record could not
// hold every end row has its counters moved to the 2026 client's rows (10-byte counter array at 24)
void quest_entry(const unsigned char* src, unsigned char* dst) {
    memcpy(dst, src, 32);
    memset(dst + 32, 0, 5);
    log_all_mappings();
    const std::vector<int>* moved = counter_rows(src[0] | (src[1] << 8));
    if (!moved) return;
    memset(dst + 24, 0, 10);
    const std::vector<int>& rows = *moved;
    for (int k = 0; k < (int)rows.size() && k < 7; k++)
        if (rows[k] >= 0 && rows[k] < 10) dst[24 + rows[k]] = src[k < 5 ? 24 + k : 30 + k - 5];
}

// the DOING {chrregnum u32, needClear u8, count u8} / REPEAT {chrregnum u32, count u16} lists: head 6, then the entries
int quest_list(const unsigned char* p, int n, int count, unsigned char* o) {
    if (n != 6 + 32 * count || 6 + 37 * count > 0x1FF0) return 0;
    memcpy(o, p, 6);
    for (int i = 0; i < count; i++) quest_entry(p + 6 + 32 * i, o + 6 + 37 * i);
    return 6 + 37 * count;
}

// ---- client -> server --------------------------------------------------------------------------------------------------
int g_track_dropped = 0;


// substituted requests live in a per-thread ring: the zone keeps the last command pointer for a while (sp_LastProtocol)
thread_local unsigned char t_cmd[8][0x400];
thread_local int t_cmd_next = 0;
unsigned char* cmd_buffer() { return t_cmd[t_cmd_next++ & 7]; }
thread_local unsigned char t_maplogin[2][0x800];      // MAP_LOGIN_REQ is 1590 B in 2016 form - too big for the ring
thread_local int t_maplogin_next = 0;

void* g_client_table = 0;

// MAP_LOGIN_REQ, 2026 form: 22 B head + the 2026 client's 53 checksums (its list at Fiesta.exe 0xB6F504) -> 22 + the
// zone's 49: zone slots 0..23 = client 0..23; 24, 25 (MapLinkPoint, MapWayPoint - the 2026 client neither has nor checks
// them) = 32 '0's, which is what the table half registers for those two; zone 26..48 = client 24..46; the client's last
// six (DeprecatedFiles + 5 quest tables the 2016 zone has no slot for) are dropped. The 2016 form passes as it is.
const int kMapLoginHead = 22, kSum = 32, kSums2026 = 53, kSums2016 = 49;
int maplogin_2026_to_2016(const unsigned char* p, int n, unsigned char* o) {
    if (n != kMapLoginHead + kSums2026 * kSum) return 0;
    memcpy(o, p, kMapLoginHead + 24 * kSum);
    memset(o + kMapLoginHead + 24 * kSum, '0', 2 * kSum);
    memcpy(o + kMapLoginHead + 26 * kSum, p + kMapLoginHead + 24 * kSum, 23 * kSum);
    return kMapLoginHead + kSums2016 * kSum;
}

// 2026 logout opcodes: 0x0C15 {LogoutType u8} is NC_USER_NORMALLOGOUT_CMD in 2026 but a SERVER->client opcode in 2016
// ("Invalid protocol[3/21]" + hang-up on return to character select); 2016 numbers the request 0x0C18. The 2026
// instant logout wraps it: 0x0C23 {inner opcode u16 = 0x0C15, LogoutType u8} (0x0C23 = REGISENUMBER_REQ in 2016).
const unsigned short kLogout2026 = 0x0C15, kLogout2016 = 0x0C18, kWrapped2026 = 0x0C23;
void logout_as_2016(hook::proto::Call& c, unsigned char type) {
    void* h = g_client_table ? hook::proto::get(g_client_table, kLogout2016) : 0;
    if (!h || !hook::proto::is_registered(g_client_table, kLogout2016)) {
        zone::log("[bridge26] 2026 logout (type %u): the zone has no 0x0C18 handler - dropped", type);
        return;
    }
    unsigned char* t = cmd_buffer();
    t[0] = (unsigned char)(kLogout2016 & 0xFF); t[1] = (unsigned char)(kLogout2016 >> 8); t[2] = type;
    typedef hook::u32(__fastcall * F3)(void*, void*, hook::u32, hook::u32, hook::u32);
    ((F3)h)(c.self, 0, (hook::u32)t, 3, c.args[2]);
}

// a 2026 client: an opcode the zone has no handler for is dropped (logged, a few per opcode) instead of dropping the CLIENT
// - it sends some the 2016 build never had (seen: 0x3085 and 0xC010 on every map login). A 2016 client: stock.
std::map<unsigned, int> g_unknown_seen;
CRITICAL_SECTION g_ulock;
void* g_unknown_handler = 0;                      // the zone's own: what a 2016 client still gets
hook::u32 __fastcall drop_unregistered(void* player, void*, hook::u32 cmd, hook::u32 len, hook::u32 a3) {
    if (!to2026(player) && g_unknown_handler) {
        typedef hook::u32(__fastcall * H)(void*, void*, hook::u32, hook::u32, hook::u32);
        return ((H)g_unknown_handler)(player, 0, cmd, len, a3);
    }
    const unsigned char* c = (const unsigned char*)cmd;
    unsigned op = c ? (unsigned)(c[0] | (c[1] << 8)) : 0xFFFF;
    EnterCriticalSection(&g_ulock);
    int k = ++g_unknown_seen[op];
    LeaveCriticalSection(&g_ulock);
    if (k <= 3) zone::log("[bridge26] dropped 0x%04x (%u B): no handler in the 2016 zone%s", op, len, k == 3 ? " (last report)" : "");
    return 0;
}

void on_client_packet(hook::proto::Call& c) {
    const unsigned char* cmd = (const unsigned char*)c.args[0];
    int n = (int)c.args[1] - 2;                      // the length covers the opcode
    const unsigned char* p = cmd + 2;
    switch (c.op) {
    case 0x4811: {                                   // SKILL_EMPOWALLOC_REQ: the 2026 14-byte form -> 6
        unsigned char* t = cmd_buffer();
        int m = empower_2026_to_2016(p, n, t + 2);
        if (m) {
            t[0] = cmd[0]; t[1] = cmd[1];
            zone::log("[bridge26] skill %u empower (2026, 14 B) -> plus %04x minus %04x", p[0] | (p[1] << 8),
                      t[4] | (t[5] << 8), t[6] | (t[7] << 8));
            c.args[0] = (hook::u32)t;
            c.args[1] = (hook::u32)(m + 2);
        }
        c.original();
        return;
    }
    case 0x4411: {                                   // QUEST_REWARD_SELECT {quest u16, index u32}
        if (n == 6 && to2026(c.self)) {
            unsigned quest = p[0] | (p[1] << 8);
            unsigned index = p[2] | (p[3] << 8) | (p[4] << 16) | ((unsigned)p[5] << 24);
            int slot = index < 256 ? reward_slot(quest, index) : -1;
            bool known = slot >= 0;
            if (known && (unsigned)slot != index) {
                unsigned char* t = cmd_buffer();
                memcpy(t, cmd, 8);
                put_u32(t + 4, (unsigned)slot);
                c.args[0] = (hook::u32)t;
            }
            zone::log("[bridge26] quest %u reward choice: client index %u -> slot %d%s", quest, index, slot,
                      known ? "" : " (no zone slot for it, as sent)");
        }
        c.original();
        return;
    }
    case 0x441F:
    case 0x4421:                                     // tracker: 2016 numbers these as zone-to-zone packets
        if (n != 2) {
            if (g_track_dropped++ < 5) zone::log("[bridge26] 0x%04x %d B dropped: not the 2-byte tracker request", c.op, n);
            return;
        }
        c.original();
        return;
    case 0x4402:                                     // QUEST_SCRIPT_CMD_ACK: a 2026 client waits to be told to close
        if (g_close_dialog && !g_zone_announces_end && to2026(c.self)) {
            send_to_client(c.self, 0x442E, kCloseDialog, 2);
            EnterCriticalSection(&g_plock);
            PlayerState& st = g_players[c.self];
            st.close_sent_at = GetTickCount();
            st.close_pending = true;
            LeaveCriticalSection(&g_plock);
        }
        c.original();
        return;
    case 0x200B: {                                   // ACT_ENDOFTRADE: the 2026 close path's echo of OUR 0x442E
        bool swallow = false;
        EnterCriticalSection(&g_plock);
        std::map<void*, PlayerState>::iterator it = g_players.find(c.self);
        if (it != g_players.end() && it->second.close_pending) {
            swallow = GetTickCount() - it->second.close_sent_at <= kCloseEchoMs;
            it->second.close_pending = false;
        }
        LeaveCriticalSection(&g_plock);
        if (!swallow) c.original();
        return;
    }
    case 0x1801: {                                   // MAP_LOGIN_REQ: the 2026 form -> the 2016 one (any send mode)
        {
            int client = n == kMapLoginHead + kSums2026 * kSum ? 2026 : n == kMapLoginHead + kSums2016 * kSum ? 2016 : 0;
            EnterCriticalSection(&g_plock);
            PlayerState& st = g_players[c.self];
            st = PlayerState();                      // a new login on this player object: nothing carries over
            st.client = client;
            LeaveCriticalSection(&g_plock);
            zone::log("[bridge26] map login: %s client (%d B)%s", client == 2026 ? "2026" : client == 2016 ? "2016" : "unknown",
                      n, g_send == kSendAuto ? "" : g_send == kSend2026 ? " - send=2026 forces 2026 shapes" : " - send=2016 forces 2016 shapes");
        }
        unsigned char* t = t_maplogin[t_maplogin_next++ & 1];
        int m = maplogin_2026_to_2016(p, n, t + 2);
        if (m) {
            t[0] = cmd[0]; t[1] = cmd[1];
            c.args[0] = (hook::u32)t;
            c.args[1] = (hook::u32)(m + 2);
            zone::log("[bridge26] MAP_LOGIN_REQ 2026 form (%d B, 53 checksums) -> 2016 (%d B, 49)", n, m);
        }
        c.original();
        return;
    }
    case kLogout2026:                                // never a request in 2016: always the 2026 client's logout
        if (n == 1) logout_as_2016(c, p[0]);
        else zone::log("[bridge26] 0x0C15 of %d B dropped: not the 1-byte 2026 logout", n);
        return;
    case kWrapped2026:
        if (n == 3 && (p[0] | (p[1] << 8)) == kLogout2026) { logout_as_2016(c, p[2]); return; }
        if (c.orig != hook::proto::unknown_handler(g_client_table)) c.original();   // the zone's own 0x0C23
        else zone::log("[bridge26] 0x0C23 of %d B dropped: not a wrapped logout, and the zone has no handler", n);
        return;
    case 0x182E: {                                   // 2026 map-status request after a map login: official answers 00
        unsigned char zero = 0;
        send_to_client(c.self, 0x182F, &zero, 1);
        return;                                      // no 2016 handler: never c.original() (the unknown handler drops the client)
    }
    }
    c.original();
}

const unsigned short kClientOps[] = { 0x4811, 0x4411, 0x441F, 0x4421, 0x182E, 0x4402, 0x200B, 0x1801, kLogout2026, kWrapped2026 };

zone::Detour g_store;
typedef void(__cdecl* StoreFn)(void* table);

void __cdecl on_protocolstore(void* table) {
    ((StoreFn)g_store.trampoline)(table);
    if (table != zone::client_protocol_table()) return;
    g_client_table = table;
    bool wrapped_registered = hook::proto::is_registered(table, kWrapped2026);
    int ok = 0;
    for (unsigned short op : kClientOps)
        ok += hook::proto::hook_opcode<0>(table, op, on_client_packet, hook::proto::kPacketArg1) ? 1 : 0;
    zone::log("[bridge26] client table: %d of %d request handler(s) hooked (0x0C18 logout %s, 0x0C23 %s)", ok,
              (int)(sizeof kClientOps / sizeof kClientOps[0]),
              hook::proto::is_registered(table, kLogout2016) ? "registered" : "MISSING",
              wrapped_registered ? "registered" : "not registered");
    if (g_send != kSend2016) {                       // LAST: is_registered() reports everything as registered after this
        g_unknown_handler = hook::proto::unknown_handler(table);
        int n = hook::proto::cover_unregistered(table, (void*)&drop_unregistered);
        zone::log("[bridge26] %d unregistered opcode slot(s): a 2026 client's packet is dropped there, a 2016 client gets the "
                  "zone's own handling", n);
    }
}

// ---- the S->C hook ---------------------------------------------------------------------------------------------------
thread_local unsigned char t_out[0x2000];

// the quest packets of batch 3 (send=2026 only); true = handled (sent, or sent with extras / instead)
bool on_quest_packet(void* self, void* edx, void* object, ProtocolPacket* pkt) {
    AppendFn original = (AppendFn)g_append.trampoline;
    unsigned op = get_u16(pkt->buffer);
    const unsigned char* p = pkt->buffer + 2;
    int n = pkt->length - 2;
    if (op == 0x4401 && n >= 6) {                    // QUEST_SCRIPT_CMD_REQ {quest u16, STRUCT_QSC.Command u32, ...}
        unsigned cmdno = p[2] | (p[3] << 8) | (p[4] << 16) | ((unsigned)p[5] << 24);
        if (cmdno == 1 /* QSC_END */) {
            if (!InterlockedExchange(&g_zone_announces_end, 1))
                zone::log("[bridge26] this zone announces quest script END: the per-ack 0x442E is off");
            if (!g_close_dialog) return false;
            ProtocolPacket t = { (unsigned char*)0, 0, 0 };
            unsigned char buf[4] = { 0x2E, 0x44, 0xFF, 0xFF };     // END -> 0x442E (it also restores the HUD the dialog hid)
            t.buffer = buf; t.size = 4; t.length = 4;
            original(self, edx, object, &t);
        } else if (cmdno == 10 /* QSC_DONE */ && g_close_dialog) {
            original(self, edx, object, pkt);         // the reward ... then the close the 2026 client waits for
            unsigned char buf[4] = { 0x2E, 0x44, 0xFF, 0xFF };
            ProtocolPacket t = { buf, 4, 4 };
            original(self, edx, object, &t);
        } else {
            return false;
        }
        EnterCriticalSection(&g_plock);
        PlayerState& st = g_players[object];
        st.close_sent_at = GetTickCount();
        st.close_pending = true;
        LeaveCriticalSection(&g_plock);
        return true;
    }
    if ((op == 0x103A || op == 0x10D7) && n >= 6) {  // quest DOING / REPEAT lists
        unsigned char in[0x2000];
        if (n > (int)sizeof in) return false;
        memcpy(in, p, n);
        std::vector<unsigned short> tracked;
        int count;
        if (op == 0x103A) {
            count = in[5];
            EnterCriticalSection(&g_plock);
            PlayerState& st = g_players[object];
            if (in[4]) st.tracked.clear();           // needClear: a new list
            for (int i = 0; i < count && 6 + 32 * (i + 1) <= n; i++) {   // QuestTracker.TakeTracked
                unsigned char* rec = in + 6 + 32 * i;
                if (!(rec[0x1D] & 0x80)) continue;
                rec[0x1D] &= 0x7F;
                unsigned short q = (unsigned short)(rec[0] | (rec[1] << 8));
                bool have = false;
                for (unsigned short x : st.tracked) have = have || x == q;
                if (rec[2] >= 6 && rec[2] <= 8 && !have && st.tracked.size() < 5) st.tracked.push_back(q);
            }
            tracked = st.tracked;
            LeaveCriticalSection(&g_plock);
        } else {
            count = in[4] | (in[5] << 8);
        }
        int m = quest_list(in, n, count, t_out + 2);
        if (!m) return false;
        if (g_verify) verify_log_op(op, p, n, t_out + 2, m);
        t_out[0] = pkt->buffer[0]; t_out[1] = pkt->buffer[1];
        ProtocolPacket t = { t_out, (int)sizeof t_out, m + 2 };
        original(self, edx, object, &t);
        if (op == 0x103A) {                          // 0x110F: the tracked set, 0xFFFF = empty slot
            unsigned char list[12] = { 0x0F, 0x11 };
            for (int i = 0; i < 5; i++) {
                unsigned short q = i < (int)tracked.size() ? tracked[i] : 0xFFFF;
                list[2 + 2 * i] = (unsigned char)q; list[3 + 2 * i] = (unsigned char)(q >> 8);
            }
            ProtocolPacket t2 = { list, 12, 12 };
            original(self, edx, object, &t2);
        }
        return true;
    }
    return false;
}

// ---- abnormal states past the 2016 bitset (ExtraAbStates.cs): indexes 792..1079 per object handle ----------------------
// The 2016 zone's 99-byte bitset stops at 792, so its LOGINCHARACTER records carry no bit for the newer states; the 2026
// records have 36 more bytes. The zone announces these states BY INDEX (ABSTATESET / RESET, BRIEFINFO_ABSTATE_CHANGE and
// its LIST), so they are learnt from what the zone sends - one map for the whole zone (every client sees the same
// broadcasts) - and set into the translated records. A handle that goes out of view keeps its states.
const int kExtraFirst = 792, kExtraBytes = 36, kExtraLast = kExtraFirst + kExtraBytes * 8 - 1;
CRITICAL_SECTION g_slock;
std::map<unsigned short, std::vector<int> > g_extra;

void extra_set(unsigned short h, int index, bool on) {
    if (index < kExtraFirst || index > kExtraLast) return;
    std::vector<int>& v = g_extra[h];
    std::vector<int>::iterator it = std::find(v.begin(), v.end(), index);
    if (on && it == v.end()) v.push_back(index);
    else if (!on && it != v.end()) v.erase(it);
    if (v.empty()) g_extra.erase(h);
}

void extra_observe(unsigned op, const unsigned char* p, int n) {
    if (op != 0x2427 && op != 0x2428 && op != 0x1C18 && op != 0x1C19) return;
    EnterCriticalSection(&g_slock);
    unsigned short h = n >= 2 ? (unsigned short)get_u16(p) : 0;
    unsigned idx = n >= 6 ? (p[2] | (p[3] << 8) | (p[4] << 16) | ((unsigned)p[5] << 24)) : 0;
    if ((op == 0x2427 && n >= 6) || (op == 0x1C18 && n >= 14)) extra_set(h, (int)idx, true);
    else if (op == 0x2428 && n >= 6) extra_set(h, (int)idx, false);
    else if (op == 0x1C19 && n >= 3) {           // the handle's whole state: replaces what was tracked
        g_extra.erase(h);
        int k = p[2];
        for (int i = 0; i < k && 3 + 12 * i + 4 <= n; i++) {
            const unsigned char* q = p + 3 + 12 * i;
            extra_set(h, (int)(q[0] | (q[1] << 8) | (q[2] << 16) | ((unsigned)q[3] << 24)), true);
        }
    }
    LeaveCriticalSection(&g_slock);
}

// set the tracked bits of the record's handle (u16 at 0) into its 36 extra bitset bytes (ExtraAbStates.Fill)
void extra_fill(unsigned char* rec) {
    EnterCriticalSection(&g_slock);
    std::map<unsigned short, std::vector<int> >::const_iterator it = g_extra.find((unsigned short)get_u16(rec));
    if (it != g_extra.end())
        for (int index : it->second) {
            int bit = index - kExtraFirst;
            rec[kLoginCharacterExtraBitsAt + bit / 8] |= (unsigned char)(1 << (bit % 8));
        }
    LeaveCriticalSection(&g_slock);
}

// after the stateless translation (and after its verify log, which keeps the proxy's pure form): the record states
void post_translate(unsigned op, unsigned char* out, int m) {
    int row = 304 + g_us_extra;
    if (op == 0x1C06 && m == row) extra_fill(out);
    else if (op == 0x1C07 && m >= 1)
        for (int i = 0; i < out[0] && 1 + (i + 1) * row <= m; i++) extra_fill(out + 1 + i * row);
}

// the item packets of batch 6 (send=2026 and the 2026 item classes loaded); true = handled
bool on_item_packet(void* self, void* edx, void* object, ProtocolPacket* pkt) {
    if (!bridge26::g_class_of) return false;
    AppendFn original = (AppendFn)g_append.trampoline;
    unsigned op = get_u16(pkt->buffer);
    const unsigned char* p = pkt->buffer + 2;
    int n = pkt->length - 2, m = 0;
    bool us = g_us_extra == 1;
    switch (op) {
    case 0x3001: m = bridge26::trailing_item(p, n, 4, t_out + 2); if (m == n) m = 0; break;      // ITEM_CELLCHANGE
    case 0x3002: m = bridge26::trailing_item(p, n, 3, t_out + 2); if (m == n) m = 0; break;      // ITEM_EQUIPCHANGE
    case 0x1047:                                                                                  // CHAR_CLIENT_ITEM
        m = bridge26::client_item(p, n, t_out + 2);
        if (!m) {
            zone::log("[bridge26] inventory box %d not translated record by record: header only", n > 1 ? p[1] : -1);
            m = bridge26::client_item_head(p, n, t_out + 2);
        }
        break;
    case 0x305B: if (us) m = bridge26::record_list(p, n, 0, 3, t_out + 2); break;     // sell (buy-back) list
    case 0x7492: if (us) m = bridge26::record_list(p, n, 18, 3, t_out + 2); break;    // guild storage
    case 0x6814: if (us) m = bridge26::record_list(p, n, 2, 15, t_out + 2); break;    // booth search
    case 0x986E: if (us) m = bridge26::record_list(p, n, 10, 3, t_out + 2); break;    // academy reward storage
    case 0x302D: if (us) m = bridge26::record_list(p, n, 0, 3, t_out + 2); break;     // reward inventory
    case 0x3C08: if (us) m = bridge26::record_list(p, n, 11, 3, t_out + 2); break;    // storage
    case 0x305C: m = bridge26::leading_item(p, n, 2, t_out + 2); if (m == n && !memcmp(t_out + 2, p, n)) m = 0; break;
    case 0x4C10: m = bridge26::leading_item(p, n, 1, t_out + 2); if (m == n && !memcmp(t_out + 2, p, n)) m = 0; break;
    case 0xC407: m = bridge26::leading_item(p, n, 3, t_out + 2); if (m == n && !memcmp(t_out + 2, p, n)) m = 0; break;
    default: return false;
    }
    if (g_verify) verify_log_op(op, p, n, t_out + 2, m);
    if (m) {
        t_out[0] = pkt->buffer[0]; t_out[1] = pkt->buffer[1];
        ProtocolPacket t = { t_out, (int)sizeof t_out, m + 2 };
        original(self, edx, object, &t);
    } else {
        original(self, edx, object, pkt);
    }
    if (op == 0x3002 && n >= 5) {
        // STOPGAP for the equip fold (tickets.md "REAL 2026 EQUIP SLOTS 30-44 - then DELETE THE EQUIP FOLD"): remove this
        // block, g_folded_into / g_equip26 and PlayerState.folded_empty once the zone holds slots 30-44 itself.
        // the server names its 2016 slot; the 2026 client draws an item at its own 2026 slot - clear every 2026 slot
        // folded into the changed one (except where the new item is drawn), once until something is drawn there again
        build_folds();
        std::map<int, std::vector<int> >::const_iterator f = g_folded_into.find(p[2]);
        if (f != g_folded_into.end()) {
            int item = p[3] | (p[4] << 8);
            std::map<int, int>::const_iterator e = item == 0xFFFF ? g_equip26.end() : g_equip26.find(item);
            int drawn = e == g_equip26.end() ? -1 : e->second;
            std::vector<int> clear;
            EnterCriticalSection(&g_plock);
            std::vector<int>& empty = g_players[object].folded_empty;
            if (drawn >= 0) empty.erase(std::remove(empty.begin(), empty.end(), drawn), empty.end());
            for (int slot : f->second) {
                if (slot == drawn || std::find(empty.begin(), empty.end(), slot) != empty.end()) continue;
                empty.push_back(slot);
                clear.push_back(slot);
            }
            LeaveCriticalSection(&g_plock);
            for (int slot : clear) {
                unsigned char b[7] = { 0x02, 0x30, p[0], p[1], (unsigned char)slot, 0xFF, 0xFF };
                ProtocolPacket c = { b, 7, 7 };
                original(self, edx, object, &c);
                zone::log("[bridge26] 0x3002 slot %d: also cleared the folded 2026 slot %d", p[2], slot);
            }
        }
    }
    return true;
}

void __fastcall on_append(void* self, void* edx, void* object, ProtocolPacket* pkt) {
    AppendFn original = (AppendFn)g_append.trampoline;
    bool valid = pkt && pkt->buffer && pkt->length >= 2;
    if (valid && g_send != kSend2016)               // broadcast state a 2026 recipient's records need, whoever it went to
        extra_observe(get_u16(pkt->buffer), pkt->buffer + 2, pkt->length - 2);
    bool to26 = valid && to2026(object);
    if (to26 && on_quest_packet(self, edx, object, pkt)) return;
    if (to26 && on_item_packet(self, edx, object, pkt)) return;
    if ((to26 || g_verify) && valid) {
        unsigned op = get_u16(pkt->buffer);
        if (const Owned* o = owned(op)) {
            const unsigned char* payload = pkt->buffer + 2;
            int n = pkt->length - 2;
            int m = o->fn(payload, n, t_out + 2);
            if (!m) {
                int idx = (int)(o - kOwned);
                if (g_unknown_shape[idx]++ < 5)
                    zone::log("[bridge26] %s %d B is not the 2016 shape: sent as it is", o->name, n);
            }
            if (g_verify) verify_log(o, payload, n, t_out + 2, m);
            if (to26 && m) {
                post_translate(op, t_out + 2, m);
                t_out[0] = pkt->buffer[0];
                t_out[1] = pkt->buffer[1];
                ProtocolPacket t = { t_out, (int)sizeof t_out, m + 2 };
                original(self, edx, object, &t);
                return;
            }
        }
    }
    original(self, edx, object, pkt);
}

}  // namespace

HOOK_PLUGIN("bridge26") {
    // the TABLE half first, whatever `send` says: the zone runs on the 2026 client's own table files and must have them
    // converted (and its checksums stated) before it loads them (bridge26_tables.h, ex-client_tables)
    tables::init();
    char send[16];
    hook::config_str("send", "auto", send, sizeof send);
    g_send = strcmp(send, "2026") == 0 ? kSend2026 : strcmp(send, "2016") == 0 ? kSend2016 : kSendAuto;
    g_verify = hook::config_int("verify", 0) != 0;
    g_verify_max = hook::config_int("verify_max", 200);
    InitializeCriticalSection(&g_vlock);
    InitializeCriticalSection(&g_slock);
    char build[8];
    hook::config_str("build", "us", build, sizeof build);
    g_us_extra = strcmp(build, "de") == 0 ? 0 : 1;   // the 2026 client build: US records are one byte longer
    if (g_verify) {
        char path[MAX_PATH];
        DWORD k = GetModuleFileNameA(NULL, path, MAX_PATH);   // beside the zone exe, like fiestahook.log
        while (k && path[k - 1] != '\\' && path[k - 1] != '/') k--;
        strcpy_s(path + k, MAX_PATH - k, "bridge26-verify.log");
        if (fopen_s(&g_vlog, path, "a") != 0) g_vlog = 0;
        zone::log("[bridge26] verify log %s%s", path, g_vlog ? "" : " - COULD NOT OPEN");
    }
    InitializeCriticalSection(&g_qlock);
    load_quest_tables();
    bridge26::g_class_of = item_class;
    g_close_dialog = hook::config_int("close_dialog", 1) != 0;
    InitializeCriticalSection(&g_plock);
    InitializeCriticalSection(&g_ulock);
    zone::hook_function("PacketContainer::pcb_Append", zone::rebase(kVaPcbAppend), (void*)on_append, &g_append);
    zone::hook_function("protocolstore", zone::rebase(kVaProtocolStore), (void*)on_protocolstore, &g_store);
    zone::log("[bridge26] %s for %d packet(s)%s", g_send == kSendAuto ? "per client (send=auto: told apart at map login)"
              : g_send == kSend2026 ? "2026 shapes to every client (send=2026)" : "2016 shapes to every client (send=2016)",
              kOwnedCount, g_verify ? ", verify on" : "");
}
