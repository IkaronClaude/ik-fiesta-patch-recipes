// bridge26 - the 2026 client's wire shapes, translated INSIDE the zone (operator 2026-10-04: "move the 2026 packet
// translation layer into zone/world/login hook ... so no proxy is required, and disabling it is just a change in the
// ini ... can accept either shape always regardless of settings, setting just changes which version is sent").
//
// Moved over from the proxy's Bridge2026 plugin (fiesta-proxy plugins/Bridge2026) in BATCHES: each batch moves a few
// packets here and removes them from the proxy in the same change, so nothing is translated twice. MOVED SO FAR:
//   batch 1 (S->C, combat): 0x2448 SWING_DAMAGE, 0x2449 SOMEONESWING_DAMAGE, 0x243C DOTDAMAGE, 0x2452 SKILLBASH_HIT_DAMAGE,
//                           0x2402 TARGETINFO
//   batch 2 (S->C): the four SKILLBASH *_START frames 0x244E / 0x2450 / 0x244F / 0x2451 (+u32)
//           (C->S): 0x4811 SKILL_EMPOWALLOC_REQ 14 -> 6 B; 0x4411 QUEST_REWARD_SELECT client index -> zone slot;
//                   0x441F / 0x4421 tracker requests that are not 2 B dropped; 0x182E (2026 map-status request) answered
//                   0x182F {0} here, as official does
//   batch 3 (quest dialog + lists, send=2026 only): 0x4401 script DONE -> relayed + 0x442E, END -> 0x442E (and this zone
//                   is then known to announce ENDs: the per-ack 0x442E stops); C->S 0x4402 ack -> 0x442E to the client;
//                   the client's 0x200B ENDOFTRADE echo of that close (within 1.5 s) swallowed; 0x103A quest DOING and
//                   0x10D7 REPEAT lists 32 -> 37 B per entry (+ counter rows moved per quest-counter-rows.txt), the
//                   TRACKED bit (quest_track) stripped and sent as 0x110F after the DOING list
//
// hooks\bridge26.ini:
//   [config]
//   send=2026          shape of the packets this plugin owns, sent to every client (default 2016 = untouched)
//   verify=1           also build the 2026 shape while sending 2016, and log (2016, 2026) pairs to bridge26-verify.log
//                      (tools/bridge26_verify replays them through the proxy's C# translators: they must match)
//   verify_max=200     pairs logged per opcode
//   quest_reward_index=../9Data/Shine/Bridge2026/quest-reward-index.txt   (tools/bridge_data.py: "quest index slot")
//   quest_counter_rows=../9Data/Shine/Bridge2026/quest-counter-rows.txt   ("quest r0..r4 [r5 r6]")
//   close_dialog=1     the 0x442E dance for an unmodified 2026 client (0 for a client carrying the self-close recipe)
//   [plugin] after=quest_track   - its 0x441F / 0x4421 handlers must be registered before ours wrap them
//
// C->S: the zone dispatches a client packet through its client protocol table (shineprotofunc); hook::proto swaps the
// slots (no code patch). The table is filled by protocolstore 0x4D4510 at server start, AFTER plugins load, so the slots
// are hooked right after it runs. A handler gets (cmd = opcode + payload, len = opcode + payload, u16). Both shapes are
// accepted whatever `send` says (the 2026 empower is 14 B, the 2016 one 6 B); a translation that changes MEANING but not
// shape (the reward index) is applied when send=2026 (a 2026 client).
//
// ---- WHERE ---------------------------------------------------------------------------------------------------------
// S->C: every game packet to a client is appended by PacketContainer::pcb_Append(ShineObject*, ProtocolPacket*)
// 0x4C8B20 (__thiscall, ret 8), one unframed packet per call {u8* pp_Buffer (opcode + payload), int pp_BufferSize,
// int pp_PacketLength}; the container copies it straight away, so a translated packet can live in a per-thread buffer.
// Server-to-server traffic never passes here (ProtocolPacket::pp_SendPacket), and S->C is plain (pe_FromServerToClient
// is the identity). Read 2026-10-04 (Zone.exe, the RE notes in the commit).
#include <zonehook.h>
#include <zone_types.h>

#include <cstddef>
#include <map>
#include <vector>

#include <cstdio>
#include <cstring>

#include "bridge26_translate.h"

namespace {

const unsigned kVaPcbAppend = 0x004C8B20u;
const unsigned kVaProtocolStore = 0x004D4510u;   // protocolstore(PROTOCOLFUNCTIONTEMPLETE<ShinePlayer>*), cdecl

using zone::types::ShineObjectClass__ShinePlayer;
using zone::types::ShineObjectClass__ShinePlayer__SocketStream;
const size_t kGameStreamAt = offsetof(ShineObjectClass__ShinePlayer, sp_SocketContainer) +
                             offsetof(ShineObjectClass__ShinePlayer__SocketStream, gamestream);
static_assert(kGameStreamAt == 0x7E28, "ShinePlayer::gamestream - the client stream senders append to (RE 2026-10-04)");

struct ProtocolPacket {
    unsigned char* buffer;   // opcode + payload
    int size;
    int length;
};

bool g_send2026 = false;
bool g_verify = false;
int g_verify_max = 200;

zone::Detour g_append;
typedef void(__fastcall* AppendFn)(void* self, void* edx, void* object, ProtocolPacket* pkt);

using namespace bridge26;

// ---- verify log -----------------------------------------------------------------------------------------------------
CRITICAL_SECTION g_vlock;
FILE* g_vlog = 0;
int g_vcount[kOwnedCount];
int g_unknown_shape[kOwnedCount];

void hex(FILE* f, const unsigned char* p, int n) { for (int i = 0; i < n; i++) fprintf(f, "%02X", p[i]); }

void verify_log(const Owned* o, const unsigned char* in, int n, const unsigned char* out, int m) {
    int idx = (int)(o - kOwned);
    EnterCriticalSection(&g_vlock);
    if (g_vlog && g_vcount[idx] < g_verify_max) {
        g_vcount[idx]++;
        fprintf(g_vlog, "%04X ", o->op);
        hex(g_vlog, in, n);
        fputc(' ', g_vlog);
        if (m) hex(g_vlog, out, m); else fputc('-', g_vlog);
        fputc('\n', g_vlog);
        fflush(g_vlog);
    }
    LeaveCriticalSection(&g_vlock);
}

std::map<unsigned, int> g_vcount_op;
void verify_log_op(unsigned op, const unsigned char* in, int n, const unsigned char* out, int m) {
    EnterCriticalSection(&g_vlock);
    if (g_vlog && g_vcount_op[op] < g_verify_max) {
        g_vcount_op[op]++;
        fprintf(g_vlog, "%04X ", op);
        hex(g_vlog, in, n);
        fputc(' ', g_vlog);
        if (m) hex(g_vlog, out, m); else fputc('-', g_vlog);
        fputc('\n', g_vlog);
        fflush(g_vlog);
    }
    LeaveCriticalSection(&g_vlock);
}

// ---- sending to a client ---------------------------------------------------------------------------------------------
// The player's own stream (gamestream: the real container once logged in, a do-nothing one before), vtable slot 3 =
// pcb_Append - the same call every zone sender makes, so it passes through on_append too.
void send_to_client(void* player, unsigned short op, const unsigned char* payload, int n) {
    if (!player || n < 0 || n > 0x1000) return;
    void* stream = *(void**)((unsigned char*)player + kGameStreamAt);
    if (!stream) return;
    unsigned char buf[0x1002];
    buf[0] = (unsigned char)op; buf[1] = (unsigned char)(op >> 8);
    memcpy(buf + 2, payload, n);
    ProtocolPacket pkt = { buf, (int)sizeof buf, n + 2 };
    typedef void(__fastcall * AppendVt)(void*, void*, void*, ProtocolPacket*);
    ((AppendVt)(*(void***)stream)[3])(stream, 0, player, &pkt);
}

// ---- per-player state (keyed by the ShinePlayer the packet is for; several map threads send, so under a lock) ----------
struct PlayerState {
    std::vector<unsigned short> tracked;   // the quest tracker set built from this login's DOING list(s)
    DWORD close_sent_at = 0;               // when we last told the client to close its dialog (0x442E); 0 = not pending
    bool close_pending = false;
};
CRITICAL_SECTION g_plock;
std::map<void*, PlayerState> g_players;
bool g_close_dialog = true;
volatile LONG g_zone_announces_end = 0;     // learned: this zone's exe sends QSC_END itself (quest-script-end-notify)
const unsigned char kCloseDialog[2] = { 0xFF, 0xFF };
const DWORD kCloseEchoMs = 1500;

std::map<unsigned, std::vector<int> > g_counter_rows;   // quest -> the 2026 client row of each zone counter slot

void load_counter_rows() {
    char path[MAX_PATH];
    hook::config_str("quest_counter_rows", "../9Data/Shine/Bridge2026/quest-counter-rows.txt", path, sizeof path);
    FILE* f = 0;
    if (fopen_s(&f, path, "r") != 0 || !f) {
        zone::log("[bridge26] no counter rows %s: quests with more than 5 end rows show their counts one row off", path);
        return;
    }
    char line[256];
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '#') continue;
        int v[9], k = 0;
        char* ctx = 0;
        for (char* t = strtok_s(line, " \t\r\n", &ctx); t && k < 9; t = strtok_s(0, " \t\r\n", &ctx)) v[k++] = atoi(t);
        if (k == 6 || k == 8) g_counter_rows[(unsigned)v[0]] = std::vector<int>(v + 1, v + k);
    }
    fclose(f);
    zone::log("[bridge26] %u quests with moved counter rows from %s", (unsigned)g_counter_rows.size(), path);
}

// PLAYER_QUEST_INFO 32 B -> 37 B (T.QuestEntry2016To2026): the same 32 bytes, 5 zero; a quest whose 2016 record could not
// hold every end row has its counters moved to the 2026 client's rows (10-byte counter array at 24)
void quest_entry(const unsigned char* src, unsigned char* dst) {
    memcpy(dst, src, 32);
    memset(dst + 32, 0, 5);
    std::map<unsigned, std::vector<int> >::const_iterator it = g_counter_rows.find(src[0] | (src[1] << 8));
    if (it == g_counter_rows.end()) return;
    memset(dst + 24, 0, 10);
    const std::vector<int>& rows = it->second;
    for (int k = 0; k < (int)rows.size() && k < 7; k++)
        if (rows[k] >= 0 && rows[k] < 10) dst[24 + rows[k]] = src[k < 5 ? 24 + k : 30 + k - 5];
}

// the DOING {chrregnum u32, needClear u8, count u8} / REPEAT {chrregnum u32, count u16} lists: head 6, then the entries
int quest_list(const unsigned char* p, int n, int count, unsigned char* o) {
    if (n != 6 + 32 * count || 6 + 37 * count > 0x1FF0) return 0;
    memcpy(o, p, 6);
    for (int i = 0; i < count; i++) quest_entry(p + 6 + 32 * i, o + 6 + 37 * i);
    return 6 + 37 * count;
}

// ---- client -> server --------------------------------------------------------------------------------------------------
std::map<unsigned, unsigned> g_reward_slot;      // (quest << 8 | client index) -> zone reward slot
int g_track_dropped = 0;

void load_reward_index() {
    char path[MAX_PATH];
    hook::config_str("quest_reward_index", "../9Data/Shine/Bridge2026/quest-reward-index.txt", path, sizeof path);
    FILE* f = 0;
    if (fopen_s(&f, path, "r") != 0 || !f) {
        zone::log("[bridge26] no reward index %s: a 2026 reward choice reaches the zone as the client's index", path);
        return;
    }
    unsigned q, i, slot;
    char line[128];
    while (fgets(line, sizeof line, f))
        if (line[0] != '#' && sscanf_s(line, "%u %u %u", &q, &i, &slot) == 3 && i < 256) g_reward_slot[(q << 8) | i] = slot;
    fclose(f);
    zone::log("[bridge26] %u quest reward choices from %s", (unsigned)g_reward_slot.size(), path);
}

// substituted requests live in a per-thread ring: the zone keeps the last command pointer for a while (sp_LastProtocol)
thread_local unsigned char t_cmd[8][0x400];
thread_local int t_cmd_next = 0;
unsigned char* cmd_buffer() { return t_cmd[t_cmd_next++ & 7]; }

void on_client_packet(hook::proto::Call& c) {
    const unsigned char* cmd = (const unsigned char*)c.args[0];
    int n = (int)c.args[1] - 2;                      // the length covers the opcode
    const unsigned char* p = cmd + 2;
    switch (c.op) {
    case 0x4811: {                                   // SKILL_EMPOWALLOC_REQ: the 2026 14-byte form -> 6
        unsigned char* t = cmd_buffer();
        int m = empower_2026_to_2016(p, n, t + 2);
        if (m) {
            t[0] = cmd[0]; t[1] = cmd[1];
            zone::log("[bridge26] skill %u empower (2026, 14 B) -> plus %04x minus %04x", p[0] | (p[1] << 8),
                      t[4] | (t[5] << 8), t[6] | (t[7] << 8));
            c.args[0] = (hook::u32)t;
            c.args[1] = (hook::u32)(m + 2);
        }
        c.original();
        return;
    }
    case 0x4411: {                                   // QUEST_REWARD_SELECT {quest u16, index u32}
        if (n == 6 && g_send2026) {
            unsigned quest = p[0] | (p[1] << 8);
            unsigned index = p[2] | (p[3] << 8) | (p[4] << 16) | ((unsigned)p[5] << 24);
            std::map<unsigned, unsigned>::const_iterator it =
                index < 256 ? g_reward_slot.find((quest << 8) | index) : g_reward_slot.end();
            bool known = it != g_reward_slot.end();
            if (known && it->second != index) {
                unsigned char* t = cmd_buffer();
                memcpy(t, cmd, 8);
                put_u32(t + 4, it->second);
                c.args[0] = (hook::u32)t;
            }
            zone::log("[bridge26] quest %u reward choice: client index %u -> slot %d%s", quest, index,
                      known ? (int)it->second : -1, known ? "" : " (not in the map, as sent)");
        }
        c.original();
        return;
    }
    case 0x441F:
    case 0x4421:                                     // tracker: 2016 numbers these as zone-to-zone packets
        if (n != 2) {
            if (g_track_dropped++ < 5) zone::log("[bridge26] 0x%04x %d B dropped: not the 2-byte tracker request", c.op, n);
            return;
        }
        c.original();
        return;
    case 0x4402:                                     // QUEST_SCRIPT_CMD_ACK: a 2026 client waits to be told to close
        if (g_send2026 && g_close_dialog && !g_zone_announces_end) {
            send_to_client(c.self, 0x442E, kCloseDialog, 2);
            EnterCriticalSection(&g_plock);
            PlayerState& st = g_players[c.self];
            st.close_sent_at = GetTickCount();
            st.close_pending = true;
            LeaveCriticalSection(&g_plock);
        }
        c.original();
        return;
    case 0x200B: {                                   // ACT_ENDOFTRADE: the 2026 close path's echo of OUR 0x442E
        bool swallow = false;
        EnterCriticalSection(&g_plock);
        std::map<void*, PlayerState>::iterator it = g_players.find(c.self);
        if (it != g_players.end() && it->second.close_pending) {
            swallow = GetTickCount() - it->second.close_sent_at <= kCloseEchoMs;
            it->second.close_pending = false;
        }
        LeaveCriticalSection(&g_plock);
        if (!swallow) c.original();
        return;
    }
    case 0x182E: {                                   // 2026 map-status request after a map login: official answers 00
        unsigned char zero = 0;
        send_to_client(c.self, 0x182F, &zero, 1);
        return;                                      // no 2016 handler: never c.original() (the unknown handler drops the client)
    }
    }
    c.original();
}

const unsigned short kClientOps[] = { 0x4811, 0x4411, 0x441F, 0x4421, 0x182E, 0x4402, 0x200B };

zone::Detour g_store;
typedef void(__cdecl* StoreFn)(void* table);

void __cdecl on_protocolstore(void* table) {
    ((StoreFn)g_store.trampoline)(table);
    if (table != zone::client_protocol_table()) return;
    int ok = 0;
    for (unsigned short op : kClientOps)
        ok += hook::proto::hook_opcode<0>(table, op, on_client_packet, hook::proto::kPacketArg1) ? 1 : 0;
    zone::log("[bridge26] client table: %d of %d request handler(s) hooked", ok, (int)(sizeof kClientOps / sizeof kClientOps[0]));
}

// ---- the S->C hook ---------------------------------------------------------------------------------------------------
thread_local unsigned char t_out[0x2000];

// the quest packets of batch 3 (send=2026 only); true = handled (sent, or sent with extras / instead)
bool on_quest_packet(void* self, void* edx, void* object, ProtocolPacket* pkt) {
    AppendFn original = (AppendFn)g_append.trampoline;
    unsigned op = get_u16(pkt->buffer);
    const unsigned char* p = pkt->buffer + 2;
    int n = pkt->length - 2;
    if (op == 0x4401 && n >= 6) {                    // QUEST_SCRIPT_CMD_REQ {quest u16, STRUCT_QSC.Command u32, ...}
        unsigned cmdno = p[2] | (p[3] << 8) | (p[4] << 16) | ((unsigned)p[5] << 24);
        if (cmdno == 1 /* QSC_END */) {
            if (!InterlockedExchange(&g_zone_announces_end, 1))
                zone::log("[bridge26] this zone announces quest script END: the per-ack 0x442E is off");
            if (!g_close_dialog) return false;
            ProtocolPacket t = { (unsigned char*)0, 0, 0 };
            unsigned char buf[4] = { 0x2E, 0x44, 0xFF, 0xFF };     // END -> 0x442E (it also restores the HUD the dialog hid)
            t.buffer = buf; t.size = 4; t.length = 4;
            original(self, edx, object, &t);
        } else if (cmdno == 10 /* QSC_DONE */ && g_close_dialog) {
            original(self, edx, object, pkt);         // the reward ... then the close the 2026 client waits for
            unsigned char buf[4] = { 0x2E, 0x44, 0xFF, 0xFF };
            ProtocolPacket t = { buf, 4, 4 };
            original(self, edx, object, &t);
        } else {
            return false;
        }
        EnterCriticalSection(&g_plock);
        PlayerState& st = g_players[object];
        st.close_sent_at = GetTickCount();
        st.close_pending = true;
        LeaveCriticalSection(&g_plock);
        return true;
    }
    if ((op == 0x103A || op == 0x10D7) && n >= 6) {  // quest DOING / REPEAT lists
        unsigned char in[0x2000];
        if (n > (int)sizeof in) return false;
        memcpy(in, p, n);
        std::vector<unsigned short> tracked;
        int count;
        if (op == 0x103A) {
            count = in[5];
            EnterCriticalSection(&g_plock);
            PlayerState& st = g_players[object];
            if (in[4]) st.tracked.clear();           // needClear: a new list
            for (int i = 0; i < count && 6 + 32 * (i + 1) <= n; i++) {   // QuestTracker.TakeTracked
                unsigned char* rec = in + 6 + 32 * i;
                if (!(rec[0x1D] & 0x80)) continue;
                rec[0x1D] &= 0x7F;
                unsigned short q = (unsigned short)(rec[0] | (rec[1] << 8));
                bool have = false;
                for (unsigned short x : st.tracked) have = have || x == q;
                if (rec[2] >= 6 && rec[2] <= 8 && !have && st.tracked.size() < 5) st.tracked.push_back(q);
            }
            tracked = st.tracked;
            LeaveCriticalSection(&g_plock);
        } else {
            count = in[4] | (in[5] << 8);
        }
        int m = quest_list(in, n, count, t_out + 2);
        if (!m) return false;
        if (g_verify) verify_log_op(op, p, n, t_out + 2, m);
        t_out[0] = pkt->buffer[0]; t_out[1] = pkt->buffer[1];
        ProtocolPacket t = { t_out, (int)sizeof t_out, m + 2 };
        original(self, edx, object, &t);
        if (op == 0x103A) {                          // 0x110F: the tracked set, 0xFFFF = empty slot
            unsigned char list[12] = { 0x0F, 0x11 };
            for (int i = 0; i < 5; i++) {
                unsigned short q = i < (int)tracked.size() ? tracked[i] : 0xFFFF;
                list[2 + 2 * i] = (unsigned char)q; list[3 + 2 * i] = (unsigned char)(q >> 8);
            }
            ProtocolPacket t2 = { list, 12, 12 };
            original(self, edx, object, &t2);
        }
        return true;
    }
    return false;
}

void __fastcall on_append(void* self, void* edx, void* object, ProtocolPacket* pkt) {
    AppendFn original = (AppendFn)g_append.trampoline;
    if (g_send2026 && pkt && pkt->buffer && pkt->length >= 2 && on_quest_packet(self, edx, object, pkt)) return;
    if ((g_send2026 || g_verify) && pkt && pkt->buffer && pkt->length >= 2) {
        unsigned op = get_u16(pkt->buffer);
        if (const Owned* o = owned(op)) {
            const unsigned char* payload = pkt->buffer + 2;
            int n = pkt->length - 2;
            int m = o->fn(payload, n, t_out + 2);
            if (!m) {
                int idx = (int)(o - kOwned);
                if (g_unknown_shape[idx]++ < 5)
                    zone::log("[bridge26] %s %d B is not the 2016 shape: sent as it is", o->name, n);
            }
            if (g_verify) verify_log(o, payload, n, t_out + 2, m);
            if (g_send2026 && m) {
                t_out[0] = pkt->buffer[0];
                t_out[1] = pkt->buffer[1];
                ProtocolPacket t = { t_out, (int)sizeof t_out, m + 2 };
                original(self, edx, object, &t);
                return;
            }
        }
    }
    original(self, edx, object, pkt);
}

}  // namespace

HOOK_PLUGIN("bridge26") {
    char send[16];
    hook::config_str("send", "2016", send, sizeof send);
    g_send2026 = strcmp(send, "2026") == 0;
    g_verify = hook::config_int("verify", 0) != 0;
    g_verify_max = hook::config_int("verify_max", 200);
    InitializeCriticalSection(&g_vlock);
    if (g_verify) {
        char path[MAX_PATH];
        DWORD k = GetModuleFileNameA(NULL, path, MAX_PATH);   // beside the zone exe, like fiestahook.log
        while (k && path[k - 1] != '\\' && path[k - 1] != '/') k--;
        strcpy_s(path + k, MAX_PATH - k, "bridge26-verify.log");
        if (fopen_s(&g_vlog, path, "a") != 0) g_vlog = 0;
        zone::log("[bridge26] verify log %s%s", path, g_vlog ? "" : " - COULD NOT OPEN");
    }
    load_reward_index();
    load_counter_rows();
    g_close_dialog = hook::config_int("close_dialog", 1) != 0;
    InitializeCriticalSection(&g_plock);
    zone::hook_function("PacketContainer::pcb_Append", zone::rebase(kVaPcbAppend), (void*)on_append, &g_append);
    zone::hook_function("protocolstore", zone::rebase(kVaProtocolStore), (void*)on_protocolstore, &g_store);
    zone::log("[bridge26] sending %s shapes for %d packet(s)%s", g_send2026 ? "2026" : "2016", kOwnedCount,
              g_verify ? ", verify on" : "");
}
