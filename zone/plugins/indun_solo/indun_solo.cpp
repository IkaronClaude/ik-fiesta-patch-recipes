// indun_solo - enter party instance dungeons without a party (Fiesta2026on2016 Q56, operator 2026-09-25).
//
// ---- THE STOCK CHECK (read from Zone.exe) ----------------------------------------------------------------
//
//   FieldContainer::fc_CanEnterIndun(player, InstanceDungeonInfo*, u32* key, u32* keyType)   0x4624D0
//     level band, then a switch on info->EntranceType (+0x44; every instance is 2 or 4):
//       2 party:        party = player vtable+0x550 (u16, 0xFFFF = none); none, or in a raid (vtable+0xA84),
//                       -> ENTER_MAP_ERR_NEED_PARTY_OR_QUEST (4); else *key = party, *keyType = 0
//       3 raid, 4 raid-else-party: *key = raid id, *keyType = 3 / the party branch
//       0, 1:           no group check - *key is left as the caller set it (-1) and 0x462629 refuses a -1 key.
//     Then (0x462629..) the NeedQuest check (4 as well), the NeedItem count (6), else 0.
//   The key finds the instance: the zone ring FIND packet carries it as a u32 (IDRegisterNumber), and the cluster
//   lookup 0x484BE0 compares it as a DWORD with the key type - a party number never exceeds 0xFFFF.
//   The WorldManager's kicks (wms_KickPlayerFromInstanceDungeon 0x486C00) name an instance by (key, type) and only
//   remove a player who is IN that instance, so a party joined inside a solo instance never kicks anyone out of it.
//
// ---- THIS PLUGIN -----------------------------------------------------------------------------------------
//
// When the stock check refuses a character with NO party and NO raid at a party (2) or raid-else-party (4)
// instance, it runs the check again on a copy of the instance info with EntranceType 1 and the key already set to
// the character's own: 0x10000 + character number, key type 0 (party) - above every party number, so it can never
// open a party's instance. Every other check (level, NeedQuest, NeedItem) runs as before on that second pass.
// The gate's Yes then runs zrpb_Request, which re-derives the key type from the group and refused "no party" as
// "Instance Dungeon is currently full"; a 6-byte patch there lets a solo key through as type 0 (see below).
// Pure raid instances (3) are left alone.
//
// Gameplay, not parity: active only when the server data carries the flag the QoL layer ships
// (Fiesta2026on2016 migrations-qol/0013-indun-solo.py -> 9Data/Shine/IndunSolo.flag).
#include <zonehook.h>
#include <zone_functions.h>

#include <cstring>

namespace {

using zone::types::FieldOption__InstanceDungeonInfo;

const char* kFlag = "../9Data/Shine/IndunSolo.flag";
const int kErrNeedParty = 4;                     // ENTER_MAP_ERR_NEED_PARTY_OR_QUEST
const unsigned char kEntranceParty = 2, kEntranceRaidElseParty = 4, kEntranceNoGroup = 1;
const unsigned kVtPartyNumber = 0x550;           // player vtable: party registration number (u16, 0xFFFF = none)
const unsigned kVtRaid = 0xA84;                  // player vtable: the raid object, 0 = none
const unsigned short kNoParty = 0xFFFF;
const unsigned long kSoloKeyBase = 0x10000;      // above every party number (u16)
const unsigned long kKeyTypeParty = 0;

zone::Detour g_can_enter;

typedef int(__fastcall* CanEnterFn)(void*, void*, void*, FieldOption__InstanceDungeonInfo*, unsigned long*, unsigned long*);

int __fastcall can_enter(void* self, void*, void* player, FieldOption__InstanceDungeonInfo* info, unsigned long* key,
                         unsigned long* key_type) {
    auto orig = (CanEnterFn)g_can_enter.trampoline;
    int r = orig(self, nullptr, player, info, key, key_type);
    if (r != kErrNeedParty || !player || !info || !key || !key_type) return r;
    if (info->EntranceType != kEntranceParty && info->EntranceType != kEntranceRaidElseParty) return r;
    void** vt = *(void***)player;
    const unsigned short party = ((unsigned short(__thiscall*)(void*))vt[kVtPartyNumber / 4])(player);
    const void* raid = ((void*(__thiscall*)(void*))vt[kVtRaid / 4])(player);
    if (party != kNoParty || raid) return r;         // in a group: the stock answer stands
    FieldOption__InstanceDungeonInfo solo;
    std::memcpy(&solo, info, sizeof solo);
    solo.EntranceType = kEntranceNoGroup;
    const unsigned chr = (unsigned)zone::fn::ShineObjectClass__ShinePlayer__so_GetCharRegistNumber()(player, 0);
    *key = kSoloKeyBase + chr;
    *key_type = kKeyTypeParty;
    r = orig(self, nullptr, player, &solo, key, key_type);
    zone::log("indun_solo: character %u enters %.13s alone (key %lu): %s", chr, info->MapIDClient, *key,
              r == 0 ? "allowed" : "refused by the other checks (quest / item)");
    return r;
}

// ---- the gate answer: ZoneRingPacketFindInstanceDungeon::zrpb_Request 0x5A92E0 ----------------------------------
// After the Yes on the gate menu (ServerMenuFuncter::smfm_LinkToDungeon builds the command: +0xD = the key
// fc_CanEnterIndun gave, +9 = its type), zrpb_Request derives the key TYPE again from the player's group:
//   0x5A9388  raid (vtable+0xA84)          -> type 3
//   0x5A939D  party = vtable+0x550; 0x5A93B1 `je 0x5A9587` when it is 0xFFFF -> "CannotAddAnymore" ("You can not
//             enter because Instance Dungeon is currently full.", seen live 2026-09-25 with this plugin's first cut)
//   0x5A93B7  xor eax, eax                 -> type 0, then the instance is found / made by the command's key.
// The je (6 bytes, 0F 84 rel32) becomes a jmp to solo_type (+ nop): the flags of `cmp cx, ax` survive the jmp, so
// a party goes on as before; no party with a solo key (>= 0x10000 - no party number is) goes on as type 0; no
// party with any other key is refused as before.
const unsigned kVaNoPartyJe = 0x5A93B1;
const unsigned kVaTypeParty = 0x5A93B7;
const unsigned kVaRefuse = 0x5A9587;
const unsigned char kNoPartyJe[6] = {0x0F, 0x84, 0xD0, 0x01, 0x00, 0x00};   // je 0x5A9587
unsigned g_type_party = 0, g_refuse = 0;

void __declspec(naked) solo_type() {
    __asm {
        jne  party                              // cmp cx, ax: a real party number
        mov  edx, dword ptr [ebp - 0x84]        // the command (+2)
        cmp  dword ptr [edx + 0xB], 0x10000     // its key
        jb   refuse
    party:
        jmp  dword ptr [g_type_party]
    refuse:
        jmp  dword ptr [g_refuse]
    }
}

bool patch_gate_answer() {
    unsigned char* p = (unsigned char*)zone::rebase(kVaNoPartyJe);
    if (std::memcmp(p, kNoPartyJe, sizeof kNoPartyJe) != 0) {
        zone::log("indun_solo: unexpected bytes at 0x5A93B1 - the gate answer is NOT patched (solo entry refused there)");
        return false;
    }
    g_type_party = (unsigned)zone::rebase(kVaTypeParty);
    g_refuse = (unsigned)zone::rebase(kVaRefuse);
    unsigned char jmp[6] = {0xE9, 0, 0, 0, 0, 0x90};
    *(int*)(jmp + 1) = (int)((unsigned char*)solo_type - (p + 5));
    return hook::write_code(p, jmp, sizeof jmp);
}

}  // namespace

ZONEHOOK_PLUGIN("indun_solo") {
    if (GetFileAttributesA(kFlag) == INVALID_FILE_ATTRIBUTES) {
        zone::log("indun_solo: no %s - party instances need a party (stock)", kFlag);
        return;
    }
    zone::hook_function("FieldContainer::fc_CanEnterIndun (solo entry)",
                        (void*)zone::fn::FieldContainer__fc_CanEnterIndun(), (void*)can_enter, &g_can_enter);
    if (patch_gate_answer())
        zone::log("indun_solo: gate answer 0x5A93B1 -> solo key (>= 0x10000) with no party goes on as key type 0");
    zone::log("indun_solo: %s present - a character with no party / raid enters party instances on its own key",
              kFlag);
}
