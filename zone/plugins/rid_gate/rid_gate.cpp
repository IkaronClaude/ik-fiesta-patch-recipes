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
struct Option {          // one instance button: the argument + mode it enters
    char arg[24];
    unsigned char mode;
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

// the instance button: the stock IDGate click
void enter(zone::types::ShineObjectClass__ShinePlayer* player, const Option& o) {
    auto* info = instance(o.arg, o.mode);
    if (!info) return;
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
int collect(void* self, const char* x, int want, Entry* e) {
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
        // the instance versions: X_I1 (mode 1), X_I2 (mode 2)
        for (unsigned char mode = 1; mode <= 2 && n < kMaxEntries; ++mode) {
            Option o = {};
            std::snprintf(o.arg, sizeof o.arg, "%.17s_I%u", x, mode);
            o.mode = mode;
            auto* info = instance(o.arg, mode);
            if (!info) continue;
            unsigned idx = g_next_option++ % (sizeof g_options / sizeof g_options[0]);
            g_options[idx] = o;
            Entry& en = e[n++];
            std::memset(&en, 0, sizeof en);
            en.kind = kInstance;
            map_name(info->MapIDClient, en.text, sizeof en.text);
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
    int n = collect(sub.self, sub.arg, sub.kind, e);
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
    int n = collect(self, x, kAll, e);
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
}
