// wm_indun_solo - the WorldManager half of solo instance dungeons (Fiesta2026on2016 Q56; zone half = indun_solo).
//
// ---- THE STOCK CHAIN (read from Zone.exe + WorldManager.exe, 2026-09-25) --------------------------------------
//
//   zone  MapCluster::mc_Routine 0x486900 - per instance (key, type): nobody inside -> EMPTY_DUNGEON_CMD 0xA401
//         {type u8, key u32} to the WM; somebody back inside -> RESET_COUNTDOWN_CMD 0xA403 {type, key}.
//   WM    CParserZone::fc_NC_INSTANCE_DUNGEON_EMPTY_DUNGEON_CMD 0x42BA20: type 3 -> the raid's members, type 0 -> the
//         PARTY looked up by the key's low 16 bits: every member gets 0x0810 {1, 300} (the 5-minute notice), the
//         party leader's character number is the target; then DELETE_DUNGEON_CMD 0xA402 {type, key, target} to every
//         zone (CWMZoneSessionManager::BroadCast, 12 bytes). Returns 1.
//   WM    CParserZone::fc_NC_INSTANCE_DUNGEON_RESET_COUNTDOWN_CMD 0x42BC40: the same members get 0x0810 {1, 0}.
//   zone  wms_NC_INSTANCE_DUNGEON_DELETE_DUNGEON_CMD 0x484590: the target character gets the server menu "delete the
//         instance?"; Yes = ServerMenuFuncter::smfm_DeleteInstanceDungeon -> the instance is emptied (no party check).
//
// A solo instance (zone plugin indun_solo) has key 0x10000 + character number, type 0: the WM finds no party for it,
// so nobody got the notice or the prompt - and the low 16 bits (the character number) could name an unrelated party
// that got the notice instead. This plugin answers both commands for a solo key (>= 0x10000 - no party number is):
// the character itself gets the notices, and it is the DELETE target, so it gets the same prompt a party leader gets.
// Every other key goes to the stock handlers untouched. Addresses are WorldManager.exe's (PDB publics).
#include <hook_core.h>

#include <cstring>

namespace {

const unsigned kVaEmptyCmd = 0x42BA20;        // CParserZone::fc_NC_INSTANCE_DUNGEON_EMPTY_DUNGEON_CMD
const unsigned kVaResetCmd = 0x42BC40;        // CParserZone::fc_NC_INSTANCE_DUNGEON_RESET_COUNTDOWN_CMD
const unsigned kVaCheckValid = 0x428230;      // CParserZone::CheckConnectionValidation(session, packet, len)
const unsigned kVaGetSession = 0x437910;      // CWMClientSessionManager::GetSession(unsigned long charNo)
const unsigned kVaClientMgr = 0x556BB0;       // the CWMClientSessionManager
const unsigned kVaSend = 0x42FCA0;            // CWMBaseSession::Send(void*, int)
const unsigned kVaBroadCast = 0x4394B0;       // CWMZoneSessionManager::BroadCast(void*, int)
const unsigned kVaZoneMgr = 0x557CEC;         // the CWMZoneSessionManager
const unsigned kSessionChar = 0x560;          // CWMClientSession: its character (null = not in game)
const unsigned long kSoloKeyBase = 0x10000;   // indun_solo's key = this + character number; no party number reaches it
const unsigned char kTypeParty = 0;
const unsigned short kOpNotice = 0x0810;      // the instance countdown notice {u8 1, u16 seconds}
const unsigned short kOpDelete = 0xA402;      // NC_INSTANCE_DUNGEON_DELETE_DUNGEON_CMD
const unsigned short kCountdownSec = 300;     // what the stock handler tells a party (0x12C)

hook::Detour g_empty, g_reset;

typedef int(__fastcall* ParserFn)(void*, void*, void*, unsigned char*, int);

bool solo_key(const unsigned char* pkt, unsigned long* chr) {
    const unsigned long key = *(const unsigned long*)(pkt + 3);
    if (pkt[2] != kTypeParty || key < kSoloKeyBase || key == 0xFFFFFFFFul) return false;
    *chr = key - kSoloKeyBase;
    return true;
}

bool valid(void* self, void* session, unsigned char* pkt, int len) {
    typedef int(__fastcall * CheckFn)(void*, void*, void*, unsigned char*, int);
    return ((CheckFn)hook::rebase(kVaCheckValid))(self, nullptr, session, pkt, len) != 0;
}

// the stock notice to one character, if it is in game: {len 5, op 0x0810, u8 1, u16 seconds}
void notice(unsigned long chr, unsigned short seconds) {
    typedef void*(__fastcall * GetFn)(void*, void*, unsigned long);
    typedef int(__fastcall * SendFn)(void*, void*, void*, int);
    void* s = ((GetFn)hook::rebase(kVaGetSession))(hook::rebase(kVaClientMgr), nullptr, chr);
    if (!s || !*(void**)((char*)s + kSessionChar)) return;
    unsigned char buf[6] = {5, (unsigned char)(kOpNotice & 0xFF), (unsigned char)(kOpNotice >> 8), 1,
                            (unsigned char)(seconds & 0xFF), (unsigned char)(seconds >> 8)};
    ((SendFn)hook::rebase(kVaSend))(s, nullptr, buf, sizeof buf);
}

int __fastcall empty_cmd(void* self, void*, void* session, unsigned char* pkt, int len) {
    unsigned long chr;
    if (!pkt || !solo_key(pkt, &chr)) return ((ParserFn)g_empty.trampoline)(self, nullptr, session, pkt, len);
    if (!valid(self, session, pkt, len)) return 0;
    notice(chr, kCountdownSec);
    // DELETE_DUNGEON {len 11, op, type, key, target}: the zone that holds the character asks it "delete?"
    unsigned char buf[12] = {11, (unsigned char)(kOpDelete & 0xFF), (unsigned char)(kOpDelete >> 8), pkt[2]};
    std::memcpy(buf + 4, pkt + 3, 4);
    std::memcpy(buf + 8, &chr, 4);
    typedef int(__fastcall * BroadFn)(void*, void*, void*, int);
    ((BroadFn)hook::rebase(kVaBroadCast))(hook::rebase(kVaZoneMgr), nullptr, buf, sizeof buf);
    hook::log("wm_indun_solo: solo instance of character %lu is empty - 5-minute notice + delete prompt sent", chr);
    return 1;
}

int __fastcall reset_cmd(void* self, void*, void* session, unsigned char* pkt, int len) {
    unsigned long chr;
    if (!pkt || !solo_key(pkt, &chr)) return ((ParserFn)g_reset.trampoline)(self, nullptr, session, pkt, len);
    if (!valid(self, session, pkt, len)) return 0;
    notice(chr, 0);
    hook::log("wm_indun_solo: character %lu is back in its solo instance - countdown cancelled", chr);
    return 1;
}

}  // namespace

HOOK_PLUGIN("wm_indun_solo") {
    bool a = hook::detour(hook::rebase(kVaEmptyCmd), (void*)empty_cmd, &g_empty);
    bool b = hook::detour(hook::rebase(kVaResetCmd), (void*)reset_cmd, &g_reset);
    hook::log("wm_indun_solo: EMPTY_DUNGEON %s, RESET_COUNTDOWN %s - solo instance keys (>= 0x10000) answered for the "
              "character itself", a ? "hooked" : "NOT hooked", b ? "hooked" : "NOT hooked");
}
