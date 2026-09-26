// quest_track - the 2026 QUEST TRACKER (pinned quests, patch 10.5.0) kept ON THE CHARACTER, as a hook DLL.
//
// Operator 2026-09-25: the tracked set "will likely need to be retained in character => hook for both, cannot
// live in bridge". The first cut kept it in the bridge (fiesta-proxy ed73fdd, a JSON file); this moves the state
// into the character's own quest records, so it is saved and loaded by the zone and Character exactly like a kill
// counter.
//
// ---- THE WIRE (official live-20260919-201932 + our stack 2026-09-25) --------------------------------------------
//   C->S 0x441F {u16 quest}               track (every quest accept + the "start tracking" button)
//   S->C 0x4420 {u16 result, u16 quest}   0x30B0 tracked, 0x30B5 already tracked, 0x30B4 refused
//   C->S 0x4421 {u16 quest}               stop tracking (the button)
//   S->C 0x4422 {u16 0x30B8, u16 quest}   removed (official also sends it unasked after a tracked quest's reward)
//   S->C 0x110F 5 x u16                   the tracked set at zone login (0xFFFF = empty)
// 2016 numbers 0x441F / 0x4421 NC_QUEST_JOBDUNGEON_FIND_RNG / _LINK_FAIL_CMD, zone-to-zone packets: the client
// table (below) has no entry for either, so a client's request was dropped by the zone until now.
//
// ---- WHERE THE FLAG LIVES -----------------------------------------------------------------------------------------
// PLAYER_QUEST_INFO {u16 ID, u8 Status, PLAYER_QUEST_DATA Data} (32 bytes); Data+26 (record +0x1D) is a bitfield
// byte using bits 0-1 (End_Location, End_Scenario). Every zone access to that byte of a PLAYER record keeps the
// upper bits (read 2026-09-25 over the whole .text: SetQuestAccept / SetQuestCancel / SetQuestInfoClearRepeat
// `and 0xFC`, CheckLocation `or 1`, ScenarioDone read-modify-write, IsRewardAble `test 2`; every `cmp [x+0x1D], 0`
// is on the static QUEST_DATA, which also reads +0x1E). Bit 7 = TRACKED.
// It persists with no new code: the character save (CQuestZone::MakeStruct_NC_CHARSAVE_QUEST_DOING_REQ 0x5BB850)
// copies whole 32-byte records of every quest in status 6/7/8, Character's p_Quest_Set stores the Data as
// tQuest.sData unchanged, and the login list NC_CHAR_CLIENT_QUEST_DOING_CMD 0x103A carries the records back - which
// is where the bridge reads the bit for 0x110F (and clears it before the 2026 client sees the record).
//
// ---- HOW THE REQUESTS REACH US ------------------------------------------------------------------------------------
// ZoneServer_zs_start_black calls protocolstore(0x850E28) 0x4D4510, which fills the ShinePlayer client table through
// PROTOCOLFUNCTIONTEMPLETE::pft_Store(dept, cmd, handler) 0x4D36C0 (e.g. 0x4D4DD3: push sp_NC_QUEST_GIVE_UP_REQ;
// push 7; push 0x11). After it runs, this plugin stores two handlers of its own at 0x11/0x1F and 0x11/0x21. A
// handler is ShinePlayer::sp_X(NETCOMMAND*, int len, u16), thiscall, ret 0xC; the payload is at NETCOMMAND+2 and
// the player's quests at ShinePlayer::sp_QuestDiary (0x173E8, a CQuestZone whose base is CQuest).
//
// ---- A TRACKED QUEST THAT IS HANDED IN ---------------------------------------------------------------------------
// Official answers the reward with an unasked 0x4422 {0x30B8, quest} (six times in live-20260919-201932). Here:
// CQuest::SetQuestDone(PLAYER_QUEST_INFO*) 0x62F610 (the u16 overload 0x6302B0 finds the record and calls it) clears
// the bit and tells the player (CQuestZone::m_pPlayer, +0xB4). Without the clear a repeatable quest would come back
// tracked: SetQuestInfoClearRepeat keeps the upper bits.
#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cstddef>

namespace {

using zone::types::ShineObjectClass__ShinePlayer;
static_assert(offsetof(ShineObjectClass__ShinePlayer, sp_QuestDiary) == 0x173E8,
              "sp_NC_QUEST_GIVE_UP_REQ 0x578994 passes lea ecx, [esi + 0x173E8] as the quest object");

const unsigned kVaProtocolStore = 0x004D4510u;   // protocolstore(PROTOCOLFUNCTIONTEMPLETE<ShinePlayer>*), cdecl
const unsigned kVaPftStore = 0x004D36C0u;        // pft_Store(dept, cmd, handler), thiscall on the table, ret 0xC
const int kDeptQuest = 0x11;
const int kCmdTrack = 0x1F, kCmdUntrack = 0x21;
const unsigned short kOpTrackAck = 0x4420, kOpUntrackAck = 0x4422;
const unsigned short kTracked = 0x30B0, kRefused = 0x30B4, kAlreadyTracked = 0x30B5, kRemoved = 0x30B8;
const int kSlots = 5;
const int kRecordSize = 32, kRecordStatus = 2, kRecordFlags = 0x1D;
const unsigned char kTrackedBit = 0x80;

zone::Detour g_store, g_done;
const unsigned kQuestZonePlayer = 0xB4;           // CQuestZone::m_pPlayer

// status 6 in progress, 7 failed, 8 reward pending: the records the character save keeps (0x5BB910)
bool active(const unsigned char* rec) { return rec[kRecordStatus] >= 6 && rec[kRecordStatus] <= 8; }

void* quests_of(void* player) { return (char*)player + offsetof(ShineObjectClass__ShinePlayer, sp_QuestDiary); }

unsigned char* record(void* quests, unsigned short id) {
    return (unsigned char*)zone::fn::CQuest__GetQuestInfo()(quests, 0, id);
}

int tracked_count(void* quests) {
    const auto* q = (const zone::types::CQuest*)quests;
    const unsigned char* arr = (const unsigned char*)q->m_pQuestArray;
    int n = 0;
    for (int i = 0; arr && i < q->m_NumOfQuest; i++) {
        const unsigned char* rec = arr + i * kRecordSize;
        if (active(rec) && (rec[kRecordFlags] & kTrackedBit)) n++;
    }
    return n;
}

// Our OWN packet, never the zone's global one (zone::global::gpp): SetQuestDone runs while the zone is building its
// script packet in gpp, and writing 0x4422 there corrupted that packet (2026-09-26: a remote hand-in's QSC_DONE went out
// as command 0 + garbage, the client never closed the script and the player was stuck in a mode that refuses items -
// could not dismount).
void reply(void* player, unsigned short op, unsigned short result, unsigned short quest) {
    unsigned char buf[16] = {};
    zone::types::ProtocolPacket packet{buf, (int)sizeof buf, 0};
    *(unsigned short*)(buf + 0) = op;
    *(unsigned short*)(buf + 2) = result;
    *(unsigned short*)(buf + 4) = quest;
    if (!zone::fn::ProtocolPacket__pp_SetPacketLen()(&packet, 0, 6)) return;
    void* stream = zone::fn::ShineObjectClass__ShinePlayer__so_GetDataSocketStream()(player, 0);
    if (!stream) return;
    typedef void(__fastcall * Send)(void* stream, void* edx, void* player, void* packet);
    ((Send)(*(void***)stream)[0xC / 4])(stream, 0, player, &packet);
}

unsigned char_no(void* player) {
    return (unsigned)zone::fn::ShineObjectClass__ShinePlayer__so_GetCharRegistNumber()(player, 0);
}

void __fastcall on_track(void* player, void*, const unsigned char* nc, int len, unsigned short) {
    if (!player || !nc || len < 4) return;
    const unsigned short id = *(const unsigned short*)(nc + 2);
    void* quests = quests_of(player);
    unsigned char* rec = record(quests, id);
    unsigned short result;
    if (!rec || !active(rec)) result = kRefused;
    else if (rec[kRecordFlags] & kTrackedBit) result = kAlreadyTracked;
    else if (tracked_count(quests) >= kSlots) result = kRefused;
    else {
        rec[kRecordFlags] |= kTrackedBit;
        result = kTracked;
    }
    reply(player, kOpTrackAck, result, id);
    zone::log("quest_track: char %u track %u -> 0x%04X (%s)", char_no(player), id, result,
              result == kTracked ? "tracked" : result == kAlreadyTracked ? "already" :
              !rec ? "no such quest" : !active(rec) ? "not in progress" : "all 5 slots used");
}

void __fastcall on_untrack(void* player, void*, const unsigned char* nc, int len, unsigned short) {
    if (!player || !nc || len < 4) return;
    const unsigned short id = *(const unsigned short*)(nc + 2);
    unsigned char* rec = record(quests_of(player), id);
    const bool had = rec && (rec[kRecordFlags] & kTrackedBit);
    if (rec) rec[kRecordFlags] &= (unsigned char)~kTrackedBit;
    reply(player, kOpUntrackAck, kRemoved, id);
    zone::log("quest_track: char %u untrack %u (%s)", char_no(player), id, had ? "was tracked" : "was not tracked");
}

int __fastcall set_done(void* quests, void*, unsigned char* rec) {
    const bool tracked = rec && (rec[kRecordFlags] & kTrackedBit);
    if (tracked) rec[kRecordFlags] &= (unsigned char)~kTrackedBit;
    const unsigned short id = rec ? *(const unsigned short*)rec : 0;
    int r = ((int(__fastcall*)(void*, void*, unsigned char*))g_done.trampoline)(quests, 0, rec);
    void* player = quests ? *(void**)((char*)quests + kQuestZonePlayer) : nullptr;
    if (tracked && player) {
        reply(player, kOpUntrackAck, kRemoved, id);
        zone::log("quest_track: char %u quest %u done -> untracked", char_no(player), id);
    }
    return r;
}

void __cdecl store(void* table) {
    ((void(__cdecl*)(void*))g_store.trampoline)(table);
    typedef void(__fastcall * PftStore)(void* table, void* edx, int dept, int cmd, void* handler);
    auto pft = (PftStore)zone::rebase(kVaPftStore);
    pft(table, 0, kDeptQuest, kCmdTrack, (void*)on_track);
    pft(table, 0, kDeptQuest, kCmdUntrack, (void*)on_untrack);
    zone::log("quest_track: client handlers 0x%04X (track) and 0x%04X (untrack) stored",
              (kDeptQuest << 10) | kCmdTrack, (kDeptQuest << 10) | kCmdUntrack);
}

}  // namespace

ZONEHOOK_PLUGIN("quest_track") {
    zone::hook_function("protocolstore(ShinePlayer table) 0x4D4510 (+ quest tracker handlers)",
                        (void*)zone::rebase(kVaProtocolStore), (void*)store, &g_store);
    zone::hook_function("CQuest::SetQuestDone 0x62F610 (a tracked quest handed in leaves the tracker)",
                        (void*)zone::fn::CQuest__SetQuestDone(), (void*)set_done, &g_done);
}
