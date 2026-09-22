// quest_gate - quest-gated map entry (the 2026 rule), as a hook DLL.
//
// Operator, 2026-09-22: "adding quest requirements to the zone hook (same as 2026 rules, note, must also affect
// gates and town portals)" and "needs to include on instance gates AND show the appropriate 2026 error messages".
//
// ---- THE RULE (2026 data + the official server's behaviour) ----------------------------------------
//
// FieldQuestCondition.shn (2026 client only; 12 rows: MapIndex -> QuestId) names, per map, the quest a character
// must have COMPLETED before it may enter. All twelve quests are completed OUTSIDE the map they gate (an NPC on the
// previous map, or kills there), and the official server's refusal text says "complete" (captured on the DE server,
// NC_ACT_NOTICE_CMD: "Du musst eine Quest abschliessen, um dieses Tor passieren zu koennen") - so "done" is the test,
// not "in progress". The zone's own prerequisite test (CQuest::IsSoonableQuest, 0x62FC80) is the same shape:
// GetQuestInfo(id) exists and its Status is PQS_DONE (2) or PQS_REPEAT (4).
//
// ---- WHERE IT HOOKS ----------------------------------------------------------------------------------
//
// Every map transfer of a player ends in the virtual ShinePlayer::so_LinkTo(LinkInformTemplete*, int, int, int)
// (vtable slot 384): the gate menu (ServerMenuFuncter::smfm_Link), the town portal roles (NPCRole_Portal / ID_Portal /
// Mode_ID_Portal), the map-link scroll, the auto-way gate, the instance level-select menu, the ring summon, and the
// GM &linkto. Swapping that one slot covers gates, town portals, scrolls and instance gates in one place, beside the
// zone's own FieldLvCondition level-band test, which the callers run before they get here.
//
// LinkInformTemplete.linktoserver (+20, char[33]) is the destination map's server name - the MapIndex the table keys
// on. A refusal returns 0 (the value so_LinkTo's own failures return) after the notice was sent, so the caller
// takes its normal "link did not happen" path.
//
// ---- THE MESSAGES --------------------------------------------------------------------------------------
//
// The zone's notices are server-side text looked up by key in 9Data/Shine/Script/ETC.txt (ShineScript::ss_String:
// LevelLimit, NeedPartyOrQuest, NeedItem, ...). The 2026 ones are new keys, added to ETC.txt by the data pipeline:
//   NeedQuestGate     a field gate      "You must complete a quest to pass through this gate."
//   NeedQuestDungeon  an instance gate  "You are missing a quest or a required item to enter this dungeon."
// (English transcriptions of the DE server's text; the official US wording is not captured.) If the key is missing
// from the file the plugin sends its own fallback text, so a stale ETC.txt still refuses with a message.
//
// ---- THE DATA -------------------------------------------------------------------------------------------
//
// ../9Data/Shine/FieldQuestCondition.shn, read with the zone's own CDataReader (operator: use the exe's readers,
// never a second parser). The columns are located by NAME from the file's field list, so a reordered table still
// reads; a missing file or column logs and leaves every map open (nothing is gated by accident).
//
// GM bypass: a character with so_AdministratorLevel() > 0 is let through with a log line, so &linkto and the
// operator's map checks keep working.

#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>

namespace {

using zone::types::NPCManager__LinkInformTemplete;
using zone::types::PLAYER_QUEST_INFO;
using zone::types::CDataReader;
using zone::types::CDataReader__FIELD;
using zone::types::CDataReader__HEAD;
using zone::types::ShineObjectClass__ShinePlayer;

const int kLinkToSlot = 384;                 // ShinePlayer vtable: so_LinkTo (0x49AD30 in the stock exe)
const unsigned char kStatusDone = 2;         // PLAYER_QUEST_STATUS::PQS_DONE
const unsigned char kStatusRepeatDone = 4;   // PLAYER_QUEST_STATUS::PQS_REPEAT
const char* kTablePath = "../9Data/Shine/FieldQuestCondition.shn";
const char* kKeyGate = "NeedQuestGate";
const char* kKeyDungeon = "NeedQuestDungeon";
const char* kFallbackGate = "You must complete a quest to pass through this gate.";
const char* kFallbackDungeon = "You are missing a quest or a required item to enter this dungeon.";

std::unordered_map<std::string, unsigned short>* g_gates = nullptr;   // map server name -> quest id
zone::fn::ShineObjectClass__ShinePlayer__so_LinkTo_t g_orig_linkto = nullptr;

// ---- the table, through the zone's own reader ----------------------------------------------------------

bool load_table() {
    // CDataReader is 64 bytes; construct one on the heap the way the zone does, read, walk, destroy.
    void* reader = ::operator new(sizeof(CDataReader));
    zone::fn::CDataReader__CDataReader()(reader, nullptr);
    if (!zone::fn::CDataReader__Read()(reader, nullptr, (char*)kTablePath)) {
        zone::log("cannot read %s - NO map is quest-gated", kTablePath);
        zone::fn::CDataReader___CDataReader()(reader, nullptr);
        ::operator delete(reader);
        return false;
    }
    CDataReader* r = (CDataReader*)reader;
    const CDataReader__FIELD* fields = (const CDataReader__FIELD*)((const unsigned char*)r->m_pHead + sizeof(CDataReader__HEAD));
    unsigned nfields = r->m_pHead->nNumOfField;
    int off_map = -1, off_quest = -1, size_map = 0, off = 0;
    for (unsigned i = 0; i < nfields; ++i) {
        if (!std::strcmp(fields[i].Name, "MapIndex")) { off_map = off; size_map = (int)fields[i].Size; }
        if (!std::strcmp(fields[i].Name, "QuestId")) off_quest = off;
        off += (int)fields[i].Size;
    }
    if (off_map < 0 || off_quest < 0) {
        zone::log("%s has no MapIndex / QuestId column (%u fields) - NO map is quest-gated", kTablePath, nfields);
        zone::fn::CDataReader___CDataReader()(reader, nullptr);
        ::operator delete(reader);
        return false;
    }
    unsigned long n = zone::fn::CDataReader__GetNumOfRecord()(reader, nullptr);
    for (unsigned long i = 0; i < n; ++i) {
        const unsigned char* rec = (const unsigned char*)zone::fn::CDataReader__GetRecord()(reader, nullptr, i);
        if (!rec) continue;
        char name[64] = {0};
        int len = size_map < 63 ? size_map : 63;
        std::memcpy(name, rec + off_map, len);
        unsigned short qid = *(const unsigned short*)(rec + off_quest);
        if (name[0] && qid) {
            (*g_gates)[name] = qid;
            zone::log("gate: %s needs quest %u done", name, qid);
        }
    }
    zone::fn::CDataReader___CDataReader()(reader, nullptr);
    ::operator delete(reader);
    zone::log("%u quest-gated maps from %s", (unsigned)g_gates->size(), kTablePath);
    return !g_gates->empty();
}

// ---- the check ---------------------------------------------------------------------------------------------

bool quest_done(ShineObjectClass__ShinePlayer* player, unsigned short qid) {
    void* diary = &player->sp_QuestDiary;   // ShineQuestDiary wraps a CQuestZone, which derives from CQuest
    PLAYER_QUEST_INFO* info = zone::fn::CQuest__GetQuestInfo()(diary, nullptr, qid);
    return info && (info->Status == kStatusDone || info->Status == kStatusRepeatDone);
}

const char* message_for(const char* map) {
    zone::types::Name3 nm;
    std::memset(&nm, 0, sizeof(nm));
    std::strncpy((char*)&nm, map, sizeof(nm) - 1);
    bool dungeon = zone::fn::FieldContainer__fc_GetInstanceDungeonInfoByMapName()(zone::global::fieldlist(), nullptr, &nm, (void*)1) != nullptr;
    const char* key = dungeon ? kKeyDungeon : kKeyGate;
    char* text = zone::fn::ShineScript__ss_String()(zone::global::shinescriptetc(), nullptr, (char*)key);
    if (text && text[0]) return text;
    return dungeon ? kFallbackDungeon : kFallbackGate;
}

unsigned char __fastcall linkto_hook(void* self, void* edx, NPCManager__LinkInformTemplete* link, int a2, int a3, int a4) {
    if (link && g_gates) {
        char map[34] = {0};
        std::memcpy(map, link->linktoserver, 33);
        auto it = g_gates->find(map);
        if (it != g_gates->end()) {
            ShineObjectClass__ShinePlayer* player = (ShineObjectClass__ShinePlayer*)self;
            unsigned short qid = it->second;
            if (quest_done(player, qid)) {
                zone::log("-> %s: quest %u done, entering", map, qid);
            } else if (zone::fn::ShineObjectClass__ShinePlayer__so_AdministratorLevel()(self, nullptr) > 0) {
                zone::log("-> %s: quest %u NOT done, GM (admin level %u) let through", map, qid,
                          zone::fn::ShineObjectClass__ShinePlayer__so_AdministratorLevel()(self, nullptr));
            } else {
                const char* text = message_for(map);
                zone::log("-> %s REFUSED: quest %u not done - \"%s\"", map, qid, text);
                zone::fn::ShineObjectClass__ShinePlayer__so_ply_Notice()(self, nullptr, (char*)text);
                return 0;
            }
        }
    }
    return g_orig_linkto(self, edx, link, a2, a3, a4);
}

}  // namespace

ZONEHOOK_PLUGIN("quest_gate") {
    g_gates = new std::unordered_map<std::string, unsigned short>();
    if (!load_table()) return;     // nothing to enforce: leave the vtable alone
    void** vt = zone::vtable::ShineObjectClass__ShinePlayer();
    void* expected = (void*)zone::fn::ShineObjectClass__ShinePlayer__so_LinkTo();
    if (vt[kLinkToSlot] != expected) {
        zone::log("ShinePlayer vtable slot %d is %x, not so_LinkTo %x - NOT hooked (another plugin, or a different exe?)",
                  kLinkToSlot, vt[kLinkToSlot], expected);
        return;
    }
    g_orig_linkto = (zone::fn::ShineObjectClass__ShinePlayer__so_LinkTo_t)hook::vtable_set(vt, kLinkToSlot, (void*)linkto_hook);
    zone::log(g_orig_linkto ? "ShinePlayer::so_LinkTo hooked (vtable slot %d)" : "vtable_set FAILED on slot %d", kLinkToSlot);
}
