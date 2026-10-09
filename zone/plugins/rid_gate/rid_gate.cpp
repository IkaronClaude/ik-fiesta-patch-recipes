// rid_gate - raid gates that also enter the raid's INSTANCE versions (Fiesta2026on2016, operator 2026-10-06: "Make RIDGate
// and RID4Gate - RID will be "Helga's Tomb" and "Helga's Tomb (Instance)", while the "4" version will have normal AND hard
// and normal instance and hard instance").
//
// ---- NPC.txt ----------------------------------------------------------------------------------------------------------
//   #record <gate mob> <map> <x> <y> <dir> 0 RIDGate  <X>      one open raid destination + its instance
//   #record <gate mob> <map> <x> <y> <dir> 0 RID4Gate <X>      normal + hard raid + both instances
// X is the gate's LinkTable argument, exactly as a stock Gate: its LinkTable row(s) are the open raid destinations (one, or
// two when normal and hard share the gate). The instance options are the Field.txt InstanceDungeon rows whose Argument is
// X_I1 (ModeIDLv 1) and X_I2 (ModeIDLv 2), each with its own LinkTable row (where the party appears inside). Both role
// names behave the same - the menu lists what the data has; the two names say what the gate is meant to offer.
//
// ---- THE ZONE (read from Zone.exe) -------------------------------------------------------------------------------------
// NPCManager::nm_Load compares each NPC's Role (NPCInformTemplete +0x40, an ORToken) with the stock names and builds the
// role object; an unknown one asserts "NPCManager::nm_Load : Invalid NPC Role" and exits (0x4C6456). Patched there: a
// RIDGate / RID4Gate continues into the stock Gate branch (0x4C5E5C: NPCRole_Portal, which loads the argument's links).
// NPCRole_Portal::nrb_Role (0x4C2EF0) is the click; for an RID gate this plugin opens ONE server menu instead:
//   - a button per link (NPCRole_Portal::nrb_linkinform(i)), the stock smfm_Link with the link as its argument;
//   - a button per instance mode found, which runs what the stock IDGate click runs (NPCRole_ID_Portal::nrb_Role
//     0x4C33F0): fc_CanEnterIndun (+ fc_EnterMapErrMsg for a refusal), an NC_INSTANCE_DUNGEON_FIND_RNG 0xA404 command
//     {+3 handle, +5 char no, +9 key type, +0xD key, +0x11 argument, +0x46 = 2} and ZoneRingPacketFindInstanceDungeon::
//     zrpb_Query - the stock "enter the instance?" flow from there;
//   - Cancel (smfm_Cancel).
// The globals that flow uses are read from the stock code's own immediates (cap recipes move some globals).
#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cstdio>
#include <cstring>

namespace {

using zone::types::FieldOption__InstanceDungeonInfo;

const unsigned kVaInvalidRole = 0x4C6456;      // push ebx ; push "Invalid NPC Role"
const unsigned kVaInvalidRoleNext = 0x4C645C;  // mov ecx, 0x871b00 (the assert continues)
const unsigned kVaGateBranch = 0x4C5E5C;       // the Gate branch: new NPCRole_Portal
const unsigned kVaInvalidRoleMsg = 0x6C5988;
const unsigned char kInvalidRoleBytes[6] = {0x53, 0x68, 0x88, 0x59, 0x6C, 0x00};
// immediates inside NPCRole_ID_Portal::nrb_Role
const unsigned kVaFieldContainerMov = 0x4C34E5;   // mov ecx, fieldcontainer
const unsigned kVaFieldLvMov = 0x4C3515;          // mov ecx, fieldleveldatabox
const unsigned kVaPacketMov = 0x4C354A;           // mov esi, [packet buffer pointer]
const unsigned kVaZrpbMov = 0x4C3593;             // mov ecx, the find-instance ring packet
const unsigned kVaMapDataBoxMov = 0x4C32A3;       // (unused - map box read below from NPCRole_Portal)
const unsigned kRoleOffset = 0x40, kArgOffset = 0x54;    // NPCInformTemplete: Role, RoleArg0 (ORToken)
const unsigned kVtCharNo = 0x344;                 // player vtable: character registration number
const unsigned short kMenuRange = 1000;

void* g_fieldcontainer = nullptr;
void* g_fieldlv = nullptr;
unsigned char** g_packet = nullptr;
void* g_zrpb = nullptr;
unsigned g_gate_branch = 0, g_invalid_next = 0;
zone::Detour g_role;

bool is_rid(const char* role) {
    return std::strncmp(role, "RIDGate", 20) == 0 || std::strncmp(role, "RID4Gate", 20) == 0;
}

// ---- boot: the invalid-role branch -------------------------------------------------------------------------------------
// eax/ebx/esi/edi as nm_Load has them; the role token was copied to [ebp-0xF4]
int __stdcall rid_role(const char* role) { return is_rid(role) ? 1 : 0; }

void __declspec(naked) invalid_role() {
    __asm {
        pushad
        lea  eax, [ebp - 0xF4]
        push eax
        call rid_role
        test eax, eax
        popad
        jz   stock
        jmp  dword ptr [g_gate_branch]
    stock:
        push ebx
        push kVaInvalidRoleMsg
        jmp  dword ptr [g_invalid_next]
    }
}

// ---- the menu --------------------------------------------------------------------------------------------------------
struct Option {          // one instance button: the argument + mode it enters, from which gate
    char arg[24];
    unsigned char mode;
    unsigned short npc;
};
Option g_options[64];
unsigned g_next_option = 0;

const char* map_name(const char* map_id, char* out, size_t n) {
    std::snprintf(out, n, "%s", map_id);
    auto* box = zone::global::mapdatabox();
    if (!box) return out;
    unsigned short id = zone::fn::MapDataBox__mdb_2mapid()(box, 0, (char*)map_id);
    auto* info = zone::fn::MapDataBox__operator__()(box, 0, id);
    if (info && info->Name[0]) std::snprintf(out, n, "%.31s", info->Name);
    return out;
}

FieldOption__InstanceDungeonInfo* instance(const char* arg, unsigned char mode) {
    unsigned char token[20];
    zone::fn::ORToken__ORToken()(token, 0, (char*)arg);
    auto* info = zone::fn::FieldContainer__fc_GetInstanceDungeonInfo()(g_fieldcontainer, 0, token, (void*)(unsigned)mode);
    if (!info || std::memcmp(info->Argument._raw, token, sizeof token) != 0 || info->ModeIDLv != mode) return nullptr;
    return info;
}

// HARD (mode 2) goes through the STOCK difficulty select. A mode-2 entry is not just a different row: the stock
// sp_NC_INSTANCE_DUNGEON_LEVEL_SELECT_MENU_ACK (0x485810, the client's answer to the level-select window) sends 0xA40E to
// the WorldManager with the level at +0x26, which registers it against the party's instance key; its answer comes back
// as wms_..._LEVEL_SELECT_JOIN_ACK (0x485B90), which enters. The FIND our normal button uses carries no level, so a
// mode-2 row was never matched and Hard did nothing (operator 2026-10-08). We call the stock handler with the gate's
// handle and level 2, exactly what the client sends ({+2 npc handle, +4 level}; the trailing args are unused). The three
// handlers it runs through demand an IDGate (role type 4) and look the instance up by the gate's own argument - see
// the role-check stubs and find_hook below, which let an RID gate through and map X -> X_I<mode>.
void enter_hard(zone::types::ShineObjectClass__ShinePlayer* player, const Option& o) {
    unsigned char cmd[8] = {0};
    *(unsigned short*)(cmd + 2) = o.npc;
    *(unsigned*)(cmd + 4) = o.mode;
    zone::fn::ShineObjectClass__ShinePlayer__sp_NC_INSTANCE_DUNGEON_LEVEL_SELECT_MENU_ACK()(
        player, 0, (zone::types::NETCOMMAND*)cmd, 6, 0);
    zone::log("rid_gate: hard - stock level select for %.20s mode %u (gate %u)", o.arg, o.mode, o.npc);
}

// the instance button: the stock IDGate click
void enter(zone::types::ShineObjectClass__ShinePlayer* player, const Option& o) {
    auto* info = instance(o.arg, o.mode);
    if (!info) return;
    if (o.mode >= 2) { enter_hard(player, o); return; }
    unsigned long key = 0xFFFFFFFF, type = 0xFFFFFFFF;
    auto err = zone::fn::FieldContainer__fc_CanEnterIndun()(g_fieldcontainer, 0, player, info, &key, &type);
    zone::types::FieldContainer__EnterFieldErrInfo lv = {1, 0};
    if (auto* c = zone::fn::FieldLevelDataBox__fldb_GetFieldLv()(g_fieldlv, 0, info->MapIDClient, info->ModeIDLv)) {
        lv.LevelFrom = *(unsigned short*)((char*)c + 0x22);
        lv.LevelTo = *(unsigned short*)((char*)c + 0x24);
    }
    if (!zone::fn::FieldContainer__fc_EnterMapErrMsg()(g_fieldcontainer, 0, player, err, &lv)) return;
    // straight in: the stock IDGate click hands its FIND command to zrpb_Query (0x5A6D10), which only builds a second
    // "Do you want to go to <map> field?" menu whose Yes is smfm_LinkToDungeon with this argument (+0 the key, +4 the
    // argument as a string, +24 sep 0, +28 the key type) - our menu already asked, so the Yes is called directly
    // (operator 2026-10-06: "it opens a new box ... bit redundant").
    zone::types::ServerMenuArgument a;
    std::memset(&a, 0, sizeof a);
    a.sma_linkDungeon.IDRegisterNumber = key;
    zone::fn::ORToken__ort_GetString()(info->Argument._raw, 0, (char*)a.sma_linkDungeon.argument);
    a.sma_linkDungeon.sep = 0;
    *(unsigned long*)a.sma_linkDungeon.category = type;
    zone::fn::ServerMenuFuncter__smfm_LinkToDungeon()(zone::global::ServerMenuActor__sma_Functer(), 0, player, &a);
    zone::log("rid_gate: enters instance %.20s mode %u (key %lu type %lu)", o.arg, o.mode, key, type);
}

// a ServerMenuFuncter member: __thiscall(functer, player, ServerMenuArgument*), callee pops 8
void __fastcall enter_functer(void* /*functer*/, void*, zone::types::ShineObjectClass__ShinePlayer* player,
                              zone::types::ServerMenuArgument* arg) {
    unsigned idx = *(unsigned*)arg->_raw;
    if (player && idx < sizeof g_options / sizeof g_options[0]) enter(player, g_options[idx]);
}

// ---- the menu entries ----------------------------------------------------------------------------------------------------
const int kShown = 3;                // ServerMenuWin (client) shows at most 3 buttons: SetServerMenu clamps the count
const int kMaxEntries = 8;
enum { kAll = 0, kLink = 1, kInstance = 2 };
struct Entry {
    int kind;
    char text[32];
    zone::types::ServerMenuArgument arg;
    void* functer;
};
struct Sub {                         // a group's own menu: which gate, which group
    void* self;
    unsigned short npc;
    int kind;
    char arg[24];
};
Sub g_subs[64];
unsigned g_next_sub = 0;

// the gate's entries of one kind (kAll: links, then the instance modes)
int collect(void* self, const char* x, int want, Entry* e, unsigned short npc) {
    int n = 0;
    if (want != kInstance) {
        // the open raid(s): the gate's own links. nrb_linkinform(i) is row i of the WHOLE LinkTable (0x4C5420:
        // or_SelectFromOrder("LinkTable", i)); the stock Portal keeps the rows whose index is its argument
        // (nrb_BriefInformSet 0x4C2360) - same filter here (2026-10-06: unfiltered, the Helga gate listed Forest of
        // Tides, Sand Beach, Sea of Greed = rows 0-2).
        unsigned char want_tok[20];
        zone::fn::ORToken__ORToken()(want_tok, 0, (char*)x);
        for (int i = 0; i < 4096 && n < 6; ++i) {
            auto* link = zone::fn::NPCRole_Portal__nrb_linkinform()(self, 0, i);
            if (!link) break;
            if (std::memcmp(link->index, want_tok, sizeof want_tok) != 0 || !link->linktoserver[0]) continue;
            Entry& en = e[n++];
            std::memset(&en, 0, sizeof en);
            en.kind = kLink;
            map_name(link->linktoserver, en.text, sizeof en.text);
            std::memcpy(&en.arg.sma_link.sml_lnkinf, link, sizeof *link);
            en.arg.sma_link.sml_LevelFrom = 1;
            en.arg.sma_link.sml_LevelTo = 0xFFFF;
            en.functer = (void*)zone::fn::ServerMenuFuncter__smfm_Link();
        }
    }
    if (want != kLink) {
        // ONE MODE ONLY = "Instance" (operator 2026-10-09: the Psiken gate said "Psiken Mansion" and "Normal"): a gate whose
        // raid has no hard instance shows its one instance beside the open raid, where "Normal" reads like the open map.
        // "Normal" / "Hard" are kept for a gate that has both (they sit in the Instance submenu there).
        int modes = 0;
        for (unsigned char slot = 1; slot <= 2; ++slot) {
            char a[24];
            std::snprintf(a, sizeof a, "%.17s_I%u", x, slot);
            if (instance(a, slot) || (slot == 2 && instance(a, 1))) ++modes;
        }
        // the instance versions: X_I1 = Normal (ModeIDLv 1), X_I2 = Hard (ModeIDLv 2 - entered through the stock level
        // select, see enter_hard; a hard row stored at mode 1 is accepted too and entered like a normal one)
        for (unsigned char slot = 1; slot <= 2 && n < kMaxEntries; ++slot) {
            Option o = {};
            std::snprintf(o.arg, sizeof o.arg, "%.17s_I%u", x, slot);
            auto* info = instance(o.arg, slot);
            if (!info && slot == 2) info = instance(o.arg, 1);
            if (!info) continue;
            o.mode = info->ModeIDLv;
            o.npc = npc;
            unsigned idx = g_next_option++ % (sizeof g_options / sizeof g_options[0]);
            g_options[idx] = o;
            Entry& en = e[n++];
            std::memset(&en, 0, sizeof en);
            en.kind = kInstance;
            // "Normal" / "Hard", not the instance map's name: the menu said [Instance] and then
            // [Malephar's Lair (Instance)] for both modes - too long, and it does not say which is which (operator 2026-10-08)
            std::snprintf(en.text, sizeof en.text, "%s", modes == 1 ? "Instance" : slot == 1 ? "Normal" : "Hard");
            *(unsigned*)en.arg._raw = idx;
            en.functer = (void*)enter_functer;
        }
    }
    return n;
}

// a menu of these entries (at most kShown - 1 of them) and Cancel
void open_menu(zone::types::ShineObjectClass__ShinePlayer* player, unsigned short npc, Entry* e, int n) {
    static char title[] = "Where do you want to go?";
    static char cancel[] = "Cancel";
    static Entry shown[kShown];
    static zone::types::ServerMenuArgument none;
    if (n > kShown - 1) {
        zone::log("rid_gate: %d entries for one menu - only the first %d shown", n, kShown - 1);
        n = kShown - 1;
    }
    void* m = zone::fn::ShineObjectClass__ShinePlayer__sp_ServerMenuTitle()(player, 0, title);
    for (int i = 0; i < n; ++i) {
        shown[i] = e[i];
        m = zone::fn::ShineObjectClass__ShinePlayer__sp_ServerMenuItem()(m, 0, shown[i].functer, shown[i].text, &shown[i].arg);
    }
    m = zone::fn::ShineObjectClass__ShinePlayer__sp_ServerMenuItem()(
        m, 0, (void*)zone::fn::ServerMenuFuncter__smfm_Cancel(), cancel, &none);
    zone::fn::ShineObjectClass__ShinePlayer__sp_ServerMenuOpen()(m, 0, 0, npc, nullptr, kMenuRange);
}

// a group's button: its own menu, the group's entries and Cancel
void __fastcall sub_functer(void* /*functer*/, void*, zone::types::ShineObjectClass__ShinePlayer* player,
                            zone::types::ServerMenuArgument* arg) {
    unsigned idx = *(unsigned*)arg->_raw;
    if (!player || idx >= sizeof g_subs / sizeof g_subs[0]) return;
    Sub sub = g_subs[idx];
    Entry e[kMaxEntries];
    int n = collect(sub.self, sub.arg, sub.kind, e, sub.npc);
    open_menu(player, sub.npc, e, n);
}

typedef void(__fastcall* RoleFn)(void*, void*, zone::types::ShineObjectClass__ShinePlayer*,
                                 zone::types::NPCManager__NPCIndexArray*, unsigned short);

void __fastcall role(void* self, void*, zone::types::ShineObjectClass__ShinePlayer* player,
                     zone::types::NPCManager__NPCIndexArray* npc, unsigned short a3) {
    const char* tpl = npc && npc->pnt ? (const char*)npc->pnt : nullptr;
    if (!player || !tpl || !is_rid(tpl + kRoleOffset)) {
        ((RoleFn)g_role.trampoline)(self, 0, player, npc, a3);
        return;
    }
    char x[24] = {0};
    std::memcpy(x, tpl + kArgOffset, 20);
    Entry e[kMaxEntries];
    int n = collect(self, x, kAll, e, npc->handle);
    if (n + 1 <= kShown) {                               // it fits: every entry and Cancel in one menu
        open_menu(player, npc->handle, e, n);
        return;
    }
    // more than the client shows (ServerMenuWin: 3 buttons, the rest are dropped - operator 2026-10-07, the gate's
    // Cancel never appeared): one button per GROUP - the raid link(s), the instance mode(s) - a group of one is its own
    // entry, a bigger one opens its own menu (submenu functer); Cancel last
    Entry top[kShown];
    int t = 0;
    for (int kind = kLink; kind <= kInstance; ++kind) {
        int first = -1, count = 0;
        for (int i = 0; i < n; ++i)
            if (e[i].kind == kind) { if (first < 0) first = i; ++count; }
        if (!count) continue;
        if (count == 1) { top[t++] = e[first]; continue; }
        Entry& g = top[t++];
        std::memset(&g, 0, sizeof g);
        g.kind = kind;
        std::snprintf(g.text, sizeof g.text, "%s", kind == kInstance ? "Instance" : e[first].text);
        Sub& sub = g_subs[g_next_sub++ % (sizeof g_subs / sizeof g_subs[0])];
        sub.self = self;
        sub.npc = npc->handle;
        sub.kind = kind;
        std::memcpy(sub.arg, x, sizeof sub.arg);
        *(unsigned*)g.arg._raw = (unsigned)(&sub - g_subs);
        g.functer = (void*)sub_functer;
    }
    open_menu(player, npc->handle, top, t);
}


// ---- the stock difficulty select, for an RID gate -----------------------------------------------------------------------
// MENU_ACK (0x485810), CHECK_ACK (0x485540) and JOIN_ACK (0x485B90) each refuse an NPC that is not an IDGate:
//   call <vfunc +0x4D0> ; cmp al, 4 ; je ok          ("Invalid NPC Handle3")
// Each site is detoured to a stub that runs the call, then also accepts an RID gate (the NPC record - NPCIndexArray, its
// template at +0 - is in ebx at MENU_ACK / CHECK_ACK and in edi at JOIN_ACK).
const unsigned kVaMenuCheck = 0x485973, kVaMenuOk = 0x485990, kVaMenuNo = 0x485979;
const unsigned kVaCheckCheck = 0x485643, kVaCheckOk = 0x485652, kVaCheckNo = 0x485649;
const unsigned kVaJoinCheck = 0x485C9C, kVaJoinOk = 0x485CAE, kVaJoinNo = 0x485CA2;
const unsigned char kMenuBytes[6] = {0xFF, 0xD0, 0x3C, 0x04, 0x74, 0x17};
const unsigned char kCheckBytes[6] = {0xFF, 0xD2, 0x3C, 0x04, 0x74, 0x09};
const unsigned char kJoinBytes[6] = {0xFF, 0xD0, 0x3C, 0x04, 0x74, 0x0C};
unsigned g_menu_ok = 0, g_menu_no = 0, g_check_ok = 0, g_check_no = 0, g_join_ok = 0, g_join_no = 0;

int __stdcall rid_npc(void* index_array) {
    auto* a = (zone::types::NPCManager__NPCIndexArray*)index_array;
    const char* tpl = a && a->pnt ? (const char*)a->pnt : nullptr;
    return tpl && is_rid(tpl + kRoleOffset) ? 1 : 0;
}

void __declspec(naked) menu_check() {
    __asm {
        call eax
        cmp  al, 4
        je   menu_yes
        pushad
        push ebx
        call rid_npc
        test eax, eax
        popad
        jnz  menu_yes
        jmp  dword ptr [g_menu_no]
    menu_yes:
        jmp  dword ptr [g_menu_ok]
    }
}
void __declspec(naked) check_check() {
    __asm {
        call edx
        cmp  al, 4
        je   check_yes
        pushad
        push ebx
        call rid_npc
        test eax, eax
        popad
        jnz  check_yes
        jmp  dword ptr [g_check_no]
    check_yes:
        jmp  dword ptr [g_check_ok]
    }
}
void __declspec(naked) join_check() {
    __asm {
        call eax
        cmp  al, 4
        je   join_yes
        pushad
        push edi
        call rid_npc
        test eax, eax
        popad
        jnz  join_yes
        jmp  dword ptr [g_join_no]
    join_yes:
        jmp  dword ptr [g_join_ok]
    }
}

bool patch_check(unsigned va, const unsigned char (&want)[6], void* stub, const char* what) {
    unsigned char* p = (unsigned char*)zone::rebase(va);
    if (std::memcmp(p, want, sizeof want) != 0) {
        zone::log("rid_gate: unexpected bytes at %s 0x%X - hard mode through an RID gate NOT enabled", what, va);
        return false;
    }
    unsigned char jmp[6] = {0xE9, 0, 0, 0, 0, 0x90};
    *(int*)(jmp + 1) = (int)((unsigned char*)stub - (p + 5));
    hook::write_code(p, jmp, sizeof jmp);
    return true;
}

// The handlers look the instance up by the GATE's argument X and a level; our rows are X_I<mode>. A lookup that misses
// is retried as X_I<mode> - only our rows have that shape, so a stock gate's miss stays a miss.
zone::Detour g_find;
typedef FieldOption__InstanceDungeonInfo*(__fastcall* FindFn)(void*, void*, void*, void*);
FieldOption__InstanceDungeonInfo* __fastcall find_hook(void* self, void* edx, void* token, void* mode) {
    auto* r = ((FindFn)g_find.trampoline)(self, edx, token, mode);
    if (!token || (r && std::memcmp(r->Argument._raw, token, 20) == 0)) return r;
    char x[24] = {0};
    zone::fn::ORToken__ort_GetString()(token, 0, x);
    if (!x[0] || std::strstr(x, "_I")) return r;
    char arg[24];
    std::snprintf(arg, sizeof arg, "%.17s_I%u", x, (unsigned)(unsigned long)mode);
    unsigned char tok[20];
    zone::fn::ORToken__ORToken()(tok, 0, arg);
    auto* r2 = ((FindFn)g_find.trampoline)(self, edx, tok, mode);
    if (r2 && std::memcmp(r2->Argument._raw, tok, sizeof tok) == 0 && r2->ModeIDLv == (unsigned)(unsigned long)mode) return r2;
    return r;
}

unsigned imm32(unsigned va, unsigned at) { return *(unsigned*)((unsigned char*)zone::rebase(va) + at); }

}  // namespace

ZONEHOOK_PLUGIN("rid_gate") {
    // the globals the IDGate flow uses, from the stock instructions (B9 imm32 = mov ecx; 8B 35 imm32 = mov esi,[imm])
    g_fieldcontainer = (void*)imm32(kVaFieldContainerMov, 1);
    g_fieldlv = (void*)imm32(kVaFieldLvMov, 1);
    g_packet = (unsigned char**)imm32(kVaPacketMov, 2);
    g_zrpb = (void*)imm32(kVaZrpbMov, 1);
    unsigned char* p = (unsigned char*)zone::rebase(kVaInvalidRole);
    if (std::memcmp(p, kInvalidRoleBytes, sizeof kInvalidRoleBytes) != 0) {
        zone::log("rid_gate: unexpected bytes at 0x4C6456 - RIDGate / RID4Gate NOT enabled (an NPC.txt row using them exits)");
        return;
    }
    g_gate_branch = (unsigned)zone::rebase(kVaGateBranch);
    g_invalid_next = (unsigned)zone::rebase(kVaInvalidRoleNext);
    unsigned char jmp[6] = {0xE9, 0, 0, 0, 0, 0x90};
    *(int*)(jmp + 1) = (int)((unsigned char*)invalid_role - (p + 5));
    hook::write_code(p, jmp, sizeof jmp);
    zone::hook_function("NPCRole_Portal::nrb_Role (RIDGate / RID4Gate menu)", (void*)zone::fn::NPCRole_Portal__nrb_Role(),
                        (void*)role, &g_role);
    zone::log("rid_gate: Role RIDGate / RID4Gate = a Gate whose menu adds the instance rows <arg>_I1 / <arg>_I2");
    // hard mode: the stock difficulty select accepts an RID gate (see enter_hard)
    g_menu_ok = (unsigned)zone::rebase(kVaMenuOk);   g_menu_no = (unsigned)zone::rebase(kVaMenuNo);
    g_check_ok = (unsigned)zone::rebase(kVaCheckOk); g_check_no = (unsigned)zone::rebase(kVaCheckNo);
    g_join_ok = (unsigned)zone::rebase(kVaJoinOk);   g_join_no = (unsigned)zone::rebase(kVaJoinNo);
    bool ok = patch_check(kVaMenuCheck, kMenuBytes, (void*)menu_check, "LEVEL_SELECT_MENU_ACK")
           && patch_check(kVaCheckCheck, kCheckBytes, (void*)check_check, "LEVEL_SELECT_CHECK_ACK")
           && patch_check(kVaJoinCheck, kJoinBytes, (void*)join_check, "LEVEL_SELECT_JOIN_ACK");
    zone::hook_function("FieldContainer::fc_GetInstanceDungeonInfo (an RID gate's X -> X_I<mode>)",
                        (void*)zone::fn::FieldContainer__fc_GetInstanceDungeonInfo(), (void*)find_hook, &g_find);
    zone::log("rid_gate: hard mode through the stock level select %s", ok ? "enabled" : "NOT enabled (see above)");
}
