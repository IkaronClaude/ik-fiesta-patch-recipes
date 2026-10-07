// leave_command - "&leave": any player (admin level 0) leaves the instance dungeon they are in (Fiesta2026on2016 P4,
// operator 2026-10-07: "0-admin-level admin command &leave that everyone can use to leave an instance dungeon").
//
// ---- THE STOCK CODE (Zone.exe, read 2026-10-07) -------------------------------------------------------------------------
//   ShinePlayer::sp_NC_ACT_CHAT_REQ (0x45A506) hands every chat line to sp_AmpersandCommand (0x41A060): a line that starts
//   with '&' goes to so_ply_AdminCommand (player vtable +0x964, 0x427A40), which walks the global command list ampcmd
//   (0x87C770, AmpersandCommand: 256 x {name[20], admin level, member-function pointer[16]}) and calls the entry whose name
//   matches IF the player's so_AdministratorLevel (vtable +0x4D4) >= the entry's level (0x419C32); else "Invalid command".
//   Entries are added by AmpersandCommand::ac_Store(char* name, int level, pmf) (0x41A310, ret 0x18) - the constructor
//   (0x425B70) stores the stock ones that way ("&linkto" at level 10). A handler is
//   thiscall(AmpersandCommand*, u16 handle, ShinePlayer*, int argc, char (*args)[33]).
//   The return point: ShinePlayer::sp_LinktoCurMapSaveData (0x560170) links the player to the current map's save link
//   (FieldMap::fm_GetSaveLinktoData) - the spot a relog inside an instance sends you to (the stock GM command
//   &linktosavedata, ac_LinktoSaveData 0x4194F0, is exactly that call).
//
// ---- THIS PLUGIN --------------------------------------------------------------------------------------------------------
//   Stores "&leave" at level 0 through the zone's own ac_Store. The handler refuses outside an instance (Field.txt
//   InstanceDungeon rows; an instance runs on a numbered copy, so the copy's MapInfo base id is what is looked up - the
//   indun_party_scale test) and on a map with no save link, and otherwise calls sp_LinktoCurMapSaveData.
#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cstring>

namespace {

const unsigned kPlayerMap = 0x7A;            // ShinePlayer -> FieldMap*
const unsigned kMapMapInfo = 0x10;           // FieldMap -> MapInfo*
const unsigned kMapInfoName = 0x2;           // MapInfo: Name3 MapName
const unsigned kIndunMapIDClient = 0x16;     // FieldOption::InstanceDungeonInfo.MapIDClient
char kName[] = "&leave";
const int kLevel = 0;                        // everyone

typedef void(__fastcall* StoreFn)(void* self, void* edx, char* name, int level, void* fn, unsigned adj, unsigned vb,
                                  unsigned vi);
typedef void*(__fastcall* IndunInfoFn)(void*, void*, void*);

void base_id(void* map, char out[13]) {
    std::memset(out, 0, 13);
    if (!map) return;
    const char* src = (const char*)map;      // fm_MapID
    __try {
        void* info = *(void**)((char*)map + kMapMapInfo);
        if (info && ((const char*)info + kMapInfoName)[0]) src = (const char*)info + kMapInfoName;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    std::memcpy(out, src, 12);
}

// fc_GetFirstInstanceDungeonInfo returns the LAST row on a miss (indun_party_scale, 2026-10-06), so the row is compared
bool is_instance(void* map) {
    char want[13];
    base_id(map, want);
    if (!want[0]) return false;
    char name3[12];
    std::memcpy(name3, want, 12);
    auto info = (const char*)((IndunInfoFn)zone::fn::FieldContainer__fc_GetFirstInstanceDungeonInfo_2())(
        zone::global::fieldlist(), 0, name3);
    if (!info) return false;
    char have[13] = {0};
    std::memcpy(have, info + kIndunMapIDClient, 12);
    return std::strcmp(want, have) == 0;
}

void notice(void* player, const char* text) {
    char buf[128];
    std::strncpy(buf, text, sizeof buf - 1);
    buf[sizeof buf - 1] = 0;
    zone::fn::ShineObjectClass__ShinePlayer__so_ply_Notice()(player, nullptr, buf);
}

void __fastcall leave(void* self, void* edx, unsigned short handle, void* player, int argc, void* args) {
    (void)self, (void)edx, (void)argc, (void)args;
    void* map = player ? *(void**)((char*)player + kPlayerMap) : nullptr;
    char base[13];
    base_id(map, base);
    if (!map || !is_instance(map)) {
        notice(player, "&leave works only inside an instance dungeon.");
        zone::log("leave_command: player %u on '%s' - not an instance, refused", handle, base);
        return;
    }
    if (!zone::fn::FieldMap__fm_GetSaveLinktoData()(map, nullptr)) {
        notice(player, "This instance has no exit to send you to.");
        zone::log("leave_command: player %u on instance '%s' - the map has no save link, refused", handle, base);
        return;
    }
    zone::log("leave_command: player %u leaves instance '%s' (the map's save link)", handle, base);
    zone::fn::ShineObjectClass__ShinePlayer__sp_LinktoCurMapSaveData()(player, nullptr);
}

}  // namespace

ZONEHOOK_PLUGIN("leave_command") {
    ((StoreFn)zone::rebase(zone::fn::kVa_AmpersandCommand__ac_Store))(zone::global::ampcmd(), nullptr, kName, kLevel,
                                                                         (void*)leave, 0, 0, 0);
    zone::log("leave_command: %s registered at admin level %d - any player leaves an instance to the map's save link",
              kName, kLevel);
}
