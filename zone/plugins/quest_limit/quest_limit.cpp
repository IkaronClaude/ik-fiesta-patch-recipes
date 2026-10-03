// quest_limit - raise the number of quests a character may have in progress (Fiesta2026on2016 P1, operator 2026-10-03:
// "build a hook that lets us raise the in progress quests limit in both client and server and database etc.").
//
// Gameplay, not parity: active only when 9Data/Shine/QuestDoingLimit.txt exists (a variant writes it); its first number
// is the new limit (41..127). No file = the stock 40.
//
// ---- WHERE THE LIMIT IS (read 2026-10-03) ------------------------------------------------------------------------------
//   Zone.exe CQuestZone::QuestNext (the script step that runs ACCEPT), 0x5BE860:
//       call CQuest::GetNumOfDoingQuest (0x62FB10: quests in status 6..8)
//       cmp  eax, 0x28            ; 83 F8 28 at 0x5BE867 - the ONLY place the zone compares against it
//       jl   <accept>
//       push 0xC0F                ; "quest list full"
//   Nowhere else: CQuest keeps every quest behind a pointer (m_pQuestArray, m_NumOfQuest) - no 40-sized array; the
//   doing-list packets carry a u8 count (PROTO_NC_CHAR_QUEST_DOING_CMD / NC_CHARSAVE_QUEST_DOING_REQ / the WM copy) and
//   are split with bNeedClear; WorldManager / Character have no compare against 40; the DB procedures (p_Quest_Set /
//   p_Quest_GetAllDoing) store and load one row per quest; the 2016 client has no doing-quest counter (IsDoingQuest /
//   IsDoingableQuest only), and the bridge keeps growing lists. So the immediate is the limit - up to 127 (imm8, signed).

#include <zonehook.h>
#include <zone_functions.h>

#include <cstdio>
#include <cstring>

namespace {

const char* kFile = "../9Data/Shine/QuestDoingLimit.txt";
const unsigned kVaCmp = 0x005BE867u;
const unsigned char kStock[3] = {0x83, 0xF8, 0x28};       // cmp eax, 40

int read_limit() {
    FILE* f = std::fopen(kFile, "r");
    if (!f) return 0;
    char line[128];
    int v = 0;
    while (std::fgets(line, sizeof line, f)) {
        if (line[0] == '#' || line[0] == ';') continue;
        if (std::sscanf(line, "%d", &v) == 1) break;
    }
    std::fclose(f);
    return v;
}

}  // namespace

ZONEHOOK_PLUGIN("quest_limit") {
    const int limit = read_limit();
    if (limit == 0) {
        zone::log("no %s - the stock 40 quests in progress", kFile);
        return;
    }
    if (limit < 1 || limit > 127) {
        zone::log("%s says %d - must be 1..127 (an imm8 compare); left at 40", kFile, limit);
        return;
    }
    unsigned char* at = (unsigned char*)zone::rebase(kVaCmp);
    if (std::memcmp(at, kStock, sizeof kStock)) {
        zone::log("CQuestZone::QuestNext's limit compare is not the expected code (%02X %02X %02X) - left alone", at[0], at[1], at[2]);
        return;
    }
    const unsigned char neu[3] = {0x83, 0xF8, (unsigned char)limit};
    if (!zone::write_code(at, neu, sizeof neu)) {
        zone::log("could not write the limit compare - left at 40");
        return;
    }
    zone::log("quests in progress: up to %d (was 40)", limit);
}
