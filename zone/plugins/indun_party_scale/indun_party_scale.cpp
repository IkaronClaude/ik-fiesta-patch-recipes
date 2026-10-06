// indun_party_scale - instance difficulty follows the party members ON THE MAP (Fiesta2026on2016, operator 2026-10-06:
// "base it, roughly, around where this feature [MapBuff] hooks in, just with added active instance member counts (in map
// - change when someone from the party enters the instance or leaves. Notably only count party members ON THIS MAP)").
//
// ---- WHAT THE ZONE ALREADY DOES (MapBuff, read from Zone.exe) --------------------------------------------------------
//   ShinePlayer::sp_NC_MAP_LOGINCOMPLETE_CMD (0x443390) and sp_ReviveNow (0x57D290) call
//   MapBuffDataBox::mbdb_SetAbstate(mapId, mode, player) (0x4645C0): mode = the instance's difficulty
//   (FieldMap::fm_eLevelType, chosen at the gate's level-select menu; 0 easy, 1/3 normal, 2 hard), and every MapBuff row
//   of (map, mode) puts its AbState on the player:
//       holder = AbState::as_FromName(&dic_abstate, name)                         0x418F80
//       player->vtable[0x638](player, index, strength, holder, now, 0, -1, 0, 0, 0)   = ShinePlayer::so_AbnormalState_Set
//       so_AbnormalState_BitSet(index); vtable[0x3F0](index, arg, 1); so_AbnormalState_BroadcastSet(index, arg, 1)
//   index = holder->index->+0x22, the strength's entry = holder +0xC + strength * 0x24 (arg = entry->+0x2B).
//
// ---- THIS PLUGIN -----------------------------------------------------------------------------------------------------
//   The same application, with the AbState StaIDPartyScale at STRENGTH = the party members on this instance map (a
//   player without a party counts 1). No strength row for the count (a full party) = the state comes off. Re-counted for
//   the whole party on: a map login (the MapBuff hook), a revive, a party join / leave / handle update / break, and a
//   member leaving the zone or logging out. Members in another zone have no object here and so never count.
//   The state is looked up BY NAME in the zone's own AbState table: the Rebalanced layer ships it
//   (migrations-rebalance/0034-indun-party-scale.py, tiers there); without it this plugin does nothing.
#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <windows.h>

#include <cstring>

namespace {

const char* kState = "StaIDPartyScale";
const unsigned kPlayerMap = 0x7A;            // ShinePlayer -> FieldMap* (mov eax,[ebx+0x7A] in LOGINCOMPLETE)
const unsigned kVtPartyNumber = 0x550;       // player vtable: party number (u16, 0xFFFF = none) - indun_solo
const unsigned kVtAbstateSet = 0x638;        // player vtable: so_AbnormalState_Set
const unsigned kVtAbstateInform = 0x3F0;     // player vtable: so_AbnormalState_Inform
const unsigned short kNoParty = 0xFFFF;
const int kMaxMembers = 5;
const int kMaxStrength = 8;
const unsigned kVaNowOperand = 0x0041641A;   // so_AbnormalState_Set_Simple: mov ecx,[now] - the operand = &now

zone::Detour g_login, g_revive, g_leave, g_join, g_break, g_handle, g_zoneleave, g_logout;
void* g_vt_player = nullptr;                 // a real player's vtable, learned on the first map login
CRITICAL_SECTION g_lock;

typedef void* (__fastcall* FromNameFn)(void*, void*, char*);
typedef unsigned char(__fastcall* SetFn)(void*, void*, void*, unsigned, int, void*, unsigned long, int, int, int, int, int);
typedef void(__fastcall* IdxFn)(void*, void*, unsigned);
typedef void(__fastcall* Idx3Fn)(void*, void*, unsigned, int, int);
typedef unsigned char(__fastcall* StrengthFn)(void*, void*, unsigned);
typedef void*(__fastcall* IndunInfoFn)(void*, void*, void*);

void* vfn(void* obj, unsigned off) { return (*(void***)obj)[off / 4]; }

bool is_player(void* p) {
    __try {
        return p && g_vt_player && *(void**)p == g_vt_player;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

unsigned short party_of(void* player) {
    return ((unsigned short(__fastcall*)(void*, void*))vfn(player, kVtPartyNumber))(player, 0);
}

void* map_of(void* player) { return *(void**)((char*)player + kPlayerMap); }

bool is_instance(void* map) {
    if (!map) return false;
    auto info = (IndunInfoFn)zone::fn::FieldContainer__fc_GetFirstInstanceDungeonInfo_2();
    return info(zone::global::fieldlist(), 0, map) != nullptr;   // fm_MapID (Name3) is the FieldMap's first field
}

void* state_holder() {
    static char name[32];
    strcpy_s(name, sizeof name, kState);
    return ((FromNameFn)zone::fn::AbnormalStateDictionary__AbState__as_FromName())(zone::global::dic_abstate(), 0, name);
}

unsigned index_of(void* holder) { return *(unsigned*)((char*)(*(void**)holder) + 0x22); }
void* strength_entry(void* holder, int s) { return *(void**)((char*)holder + 0xC + s * 0x24); }

// the strength the player has now (0 = none)
int current(void* player, unsigned idx) {
    return ((StrengthFn)zone::fn::ShineObjectClass__ShineMobileObject__so_AbnormalState_Strength())(player, 0, idx);
}

// put the state on at `s`, or take it off (s == 0) - only when it changes
void apply(void* player, int s) {
    void* holder = state_holder();
    if (!holder) return;
    unsigned idx = index_of(holder);
    if (s > kMaxStrength || (s && !strength_entry(holder, s))) s = 0;   // no row for that count (a full party)
    int now_s = current(player, idx);
    if (now_s == s) return;
    if (now_s) ((IdxFn)zone::fn::ShineObjectClass__ShinePlayer__so_AbnormalState_Reset())(player, 0, idx);
    if (s) {
        void* entry = strength_entry(holder, s);
        unsigned long now = **(unsigned long**)zone::rebase(kVaNowOperand);
        unsigned char ok = ((SetFn)vfn(player, kVtAbstateSet))(player, 0, player, idx, s, holder, now, 0, -1, 0, 0, 0);
        if (ok == 1) {
            int arg = *(int*)((char*)entry + 0x2B);
            ((IdxFn)zone::fn::ShineObjectClass__ShineObject__so_AbnormalState_BitSet())(player, 0, idx);
            ((Idx3Fn)vfn(player, kVtAbstateInform))(player, 0, idx, arg, 1);
            ((Idx3Fn)zone::fn::ShineObjectClass__ShineObject__so_AbnormalState_BroadcastSet())(player, 0, idx, arg, 1);
        } else {
            zone::log("indun_party_scale: so_AbnormalState_Set refused strength %d on player %x", s, player);
            return;
        }
    }
    zone::log("indun_party_scale: player %x strength %d -> %d", player, now_s, s);
}

// every member of the party that is in this zone (or just `player` without a party), minus `gone`
int members(void* player, void* gone, void** out) {
    int n = 0;
    unsigned short party = party_of(player);
    if (party == kNoParty) {
        if (player != gone) out[n++] = player;
        return n;
    }
    auto* pc = zone::global::partycontainer();
    if (!pc || !pc->m_Array || party >= (unsigned)pc->m_NumOfParty) {
        if (player != gone) out[n++] = player;
        return n;
    }
    auto& slot = pc->m_Array[party];
    for (int i = 0; i < kMaxMembers && i < slot.NumOfMember + kMaxMembers; i++) {
        void* m = slot.Members[i].memberobj;
        if (!m || m == gone || !is_player(m)) continue;
        bool dup = false;
        for (int k = 0; k < n; k++) dup |= out[k] == m;
        if (!dup && party_of(m) == party) out[n++] = m;
    }
    bool self = false;
    for (int k = 0; k < n; k++) self |= out[k] == player;
    if (!self && player != gone && n < kMaxMembers + 1) out[n++] = player;
    return n;
}

// re-count the party of `player` (without `gone`, a member on the way out) and set every member's strength
void refresh(void* player, void* gone = nullptr) {
    if (!is_player(player) || !state_holder()) return;
    EnterCriticalSection(&g_lock);
    __try {
        void* list[kMaxMembers + 1];
        int n = members(player, gone, list);
        for (int i = 0; i < n; i++) {
            void* map = map_of(list[i]);
            int here = 0;
            if (is_instance(map))
                for (int k = 0; k < n; k++) here += map_of(list[k]) == map;
            apply(list[i], here);
        }
        if (gone && is_player(gone) && party_of(gone) == kNoParty) apply(gone, is_instance(map_of(gone)) ? 1 : 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        zone::log("indun_party_scale: fault re-counting the party of %x - left as it was", player);
    }
    LeaveCriticalSection(&g_lock);
}

void refresh_party(unsigned short party, void* gone = nullptr) {
    auto* pc = zone::global::partycontainer();
    if (!pc || !pc->m_Array || party >= (unsigned)pc->m_NumOfParty) return;
    for (int i = 0; i < kMaxMembers; i++) {
        void* m = pc->m_Array[party].Members[i].memberobj;
        if (m && m != gone && is_player(m)) {
            refresh(m, gone);
            return;
        }
    }
}

// ---- hooks ---------------------------------------------------------------------------------------------------------
typedef void(__fastcall* LoginFn)(void*, void*, void*, int, unsigned short);
void __fastcall login_impl(void* self, void*, void* cmd, int a2, unsigned short a3) {
    ((LoginFn)g_login.trampoline)(self, 0, cmd, a2, a3);
    if (!g_vt_player && self) g_vt_player = *(void**)self;
    refresh(self);
}

typedef void(__fastcall* ReviveFn)(void*, void*, unsigned short);
void __fastcall revive_impl(void* self, void*, unsigned short a1) {
    ((ReviveFn)g_revive.trampoline)(self, 0, a1);
    refresh(self);
}

typedef void(__fastcall* LeaveFn)(void*, void*, unsigned short, unsigned long);
void __fastcall leave_impl(void* self, void*, unsigned short party, unsigned long chrregnum) {
    void* leaver = nullptr;
    auto* pc = zone::global::partycontainer();
    __try {
        if (pc && pc->m_Array && party < (unsigned)pc->m_NumOfParty)
            for (int i = 0; i < kMaxMembers; i++)
                if (pc->m_Array[party].Members[i].MemberInform.Member.chrregnum == chrregnum) leaver = pc->m_Array[party].Members[i].memberobj;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    ((LeaveFn)g_leave.trampoline)(self, 0, party, chrregnum);
    refresh_party(party, leaver);
    if (leaver && is_player(leaver)) refresh(leaver);   // now without a party: counts as 1
}

typedef void(__fastcall* PartyFn)(void*, void*, unsigned short);
void __fastcall join_impl(void* self, void*, unsigned short party) {
    ((PartyFn)g_join.trampoline)(self, 0, party);
    refresh_party(party);
}

void __fastcall break_impl(void* self, void*, unsigned short party) {
    void* was[kMaxMembers] = {};
    auto* pc = zone::global::partycontainer();
    __try {
        if (pc && pc->m_Array && party < (unsigned)pc->m_NumOfParty)
            for (int i = 0; i < kMaxMembers; i++) was[i] = pc->m_Array[party].Members[i].memberobj;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    ((PartyFn)g_break.trampoline)(self, 0, party);
    for (int i = 0; i < kMaxMembers; i++)
        if (was[i] && is_player(was[i])) refresh(was[i]);   // each on their own now
}

typedef void(__fastcall* HandleFn)(void*, void*, unsigned short, void*);
void __fastcall handle_impl(void* self, void*, unsigned short party, void* member) {
    ((HandleFn)g_handle.trampoline)(self, 0, party, member);
    refresh_party(party);
}

typedef void(__fastcall* SelfFn)(void*, void*);
void __fastcall zoneleave_impl(void* self, void*) {
    unsigned short party = is_player(self) ? party_of(self) : kNoParty;
    ((SelfFn)g_zoneleave.trampoline)(self, 0);
    if (party != kNoParty) refresh_party(party, self);
}

void __fastcall logout_impl(void* self, void*) {
    unsigned short party = is_player(self) ? party_of(self) : kNoParty;
    ((SelfFn)g_logout.trampoline)(self, 0);
    if (party != kNoParty) refresh_party(party, self);
}

}  // namespace

ZONEHOOK_PLUGIN("indun_party_scale") {
    InitializeCriticalSection(&g_lock);
    zone::hook_function("ShinePlayer::sp_NC_MAP_LOGINCOMPLETE_CMD",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__sp_NC_MAP_LOGINCOMPLETE_CMD(), (void*)login_impl, &g_login);
    zone::hook_function("ShinePlayer::sp_ReviveNow", (void*)zone::fn::ShineObjectClass__ShinePlayer__sp_ReviveNow(),
                        (void*)revive_impl, &g_revive);
    zone::hook_function("PartyManufacture::pm_MemberLeave", (void*)zone::fn::PartyManufacture__pm_MemberLeave(),
                        (void*)leave_impl, &g_leave);
    zone::hook_function("PartyManufacture::pm_NewMemberJoin", (void*)zone::fn::PartyManufacture__pm_NewMemberJoin(),
                        (void*)join_impl, &g_join);
    zone::hook_function("PartyManufacture::pm_Break", (void*)zone::fn::PartyManufacture__pm_Break(), (void*)break_impl,
                        &g_break);
    zone::hook_function("PartyManufacture::pm_HandleSet", (void*)zone::fn::PartyManufacture__pm_HandleSet(),
                        (void*)handle_impl, &g_handle);
    zone::hook_function("ShinePlayer::so_ply_PartyZoneLeaveCmd",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__so_ply_PartyZoneLeaveCmd(), (void*)zoneleave_impl,
                        &g_zoneleave);
    zone::hook_function("ShinePlayer::sp_LogoutDuringParty",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__sp_LogoutDuringParty(), (void*)logout_impl, &g_logout);
    zone::log("indun_party_scale: up - %s is applied at the strength of the party members on each instance map "
              "(the state is looked up at use; without it in AbState this plugin does nothing)", kState);
}
