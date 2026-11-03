// wm_tutorial_skip - a new character that SKIPS the tutorial was refused its first login (Fiesta2026on2016).
//
// ---- THE STOCK CHAIN (WorldManager.exe, PDB publics, read 2026-11-03) ------------------------------------------
//
//   CParserCharDB::fc_NC_USER_AVATARINFO_ACK 0x40EDE0 {u16 ?, u16 session, u8 count, 130-byte avatar records}: for a
//     record whose tutorial state (+0x7D) is 0 the login map (+0x1B, Name3) is OVERWRITTEN with "RouT" (0x486120,
//     0x40EEE9), then the record is copied into the session's slot (+0x23C + slot * 0x82).
//   CParserClient::fc_NC_CHAR_LOGIN_REQ: state 0 + flag 0 -> NC_CHAR_TUTORIAL_POPUP_REQ 0x1110.
//   CParserClient::fc_NC_CHAR_TUTORIAL_POPUP_ACK 0x418CB0 {bIsSkip} -> NC_CHAR_TUTORIAL_MAKE_ITEM_REQ 0x1112 to the
//     character server; CParserCharDB::fc_NC_CHAR_TUTORIAL_MAKE_ITEM_ACK 0x40E2D0: 0x31E8 + skip -> state = 2 ->
//   CWMClientSession::TutorialLoginProcess 0x4371A0: state 0 -> "RouT00" into the slot map (+0x257) - the tutorial;
//     otherwise the slot map as it is - "RouT" - and GetServiceMapZoneNo("RouT") = -1 -> "TutorialMap Search Fail" +
//     CHAR_LOGINFAIL 0x0145 ("The map is under maintenance"). The next login works (state 2 stored, no overwrite).
// Live 2026-11-03: every new character skipping (the 2026 client always does: its handler 0x55FD90 answers bIsSkip 1)
// was refused; the log here showed "slot 3 char 1017 state 2 map 'RouT'".
//
// FIX: before AVATARINFO_ACK runs, the login map of every state-0 record is kept by character number; when
// TutorialLoginProcess runs for a skipped character (state != 0) whose slot map is the exe's own "RouT" placeholder,
// the kept map goes back into the slot - the character logs in where the character server has it, as its next login
// would. The tutorial path (state 0) is untouched.
#include <hook_core.h>
#include <windows.h>

#include <cstring>
#include <map>
#include <string>

namespace {

const unsigned kVaAvatarInfoAck = 0x40EDE0;   // CParserCharDB::fc_NC_USER_AVATARINFO_ACK
const unsigned kVaTutorialLogin = 0x4371A0;   // CWMClientSession::TutorialLoginProcess
const unsigned kVaRouT = 0x486120;            // the exe's "RouT" placeholder string
const int kRecords = 5, kRecordSize = 0x82, kRecMap = 0x1B, kRecState = 0x7D, kMapLen = 12;
const unsigned kSlotField = 0x1ED2D;          // the tutorial-selected slot (SetTutorialSelectedSlot 0x433610)
const unsigned kSlotBase = 0x23C;             // the slot's copy of the avatar record (character number first)
const unsigned kMaxSlots = 6;                 // TutorialLoginProcess refuses slot >= 6 (0x4371BE)

hook::Detour g_avatars, g_login;
CRITICAL_SECTION g_lock;
std::map<unsigned long, std::string> g_maps;  // character number -> its login map before the "RouT" overwrite

typedef int(__fastcall* ParserFn)(void*, void*, void*, unsigned char*, int);
typedef int(__fastcall* LoginFn)(void*, void*);

int __fastcall avatar_info(void* self, void*, void* session, unsigned char* pkt, int len) {
    if (pkt && len >= kRecords && pkt[4] != 0xFF) {
        EnterCriticalSection(&g_lock);
        for (int i = 0; i < pkt[4] && kRecords + (i + 1) * kRecordSize <= len; i++) {
            const unsigned char* r = pkt + kRecords + i * kRecordSize;
            if (*(const int*)(r + kRecState) != 0) continue;
            g_maps[*(const unsigned long*)r] = std::string((const char*)r + kRecMap, strnlen((const char*)r + kRecMap, kMapLen));
        }
        LeaveCriticalSection(&g_lock);
    }
    return ((ParserFn)g_avatars.trampoline)(self, nullptr, session, pkt, len);
}

int __fastcall tutorial_login(void* self, void*) {
    unsigned char* s = (unsigned char*)self;
    unsigned slot = s[kSlotField];
    if (slot < kMaxSlots) {
        unsigned char* r = s + kSlotBase + slot * kRecordSize;
        const char* rout = (const char*)hook::rebase(kVaRouT);
        if (*(const int*)(r + kRecState) != 0 && strncmp((const char*)r + kRecMap, rout, kMapLen) == 0) {
            unsigned long chr = *(const unsigned long*)r;
            std::string map;
            EnterCriticalSection(&g_lock);
            auto it = g_maps.find(chr);
            if (it != g_maps.end()) map = it->second;
            LeaveCriticalSection(&g_lock);
            if (!map.empty()) {
                std::memset(r + kRecMap, 0, kMapLen);
                std::memcpy(r + kRecMap, map.data(), map.size() < (size_t)kMapLen ? map.size() : kMapLen - 1);
                hook::log("wm_tutorial_skip: character %lu skipped the tutorial - login map '%s' (not '%s')", chr,
                          map.c_str(), rout);
            } else {
                hook::log("wm_tutorial_skip: character %lu skipped the tutorial - no kept map, stock path", chr);
            }
        }
    }
    return ((LoginFn)g_login.trampoline)(self, nullptr);
}

}  // namespace

HOOK_PLUGIN("wm_tutorial_skip") {
    InitializeCriticalSection(&g_lock);
    bool a = hook::detour(hook::rebase(kVaAvatarInfoAck), (void*)avatar_info, &g_avatars);
    bool b = hook::detour(hook::rebase(kVaTutorialLogin), (void*)tutorial_login, &g_login);
    hook::log("wm_tutorial_skip: AVATARINFO_ACK %s, TutorialLoginProcess %s - a skipped tutorial logs in on the "
              "character's own map", a ? "hooked" : "NOT hooked", b ? "hooked" : "NOT hooked");
}
