// bridge26 - the 2026 client's wire shapes, translated INSIDE the zone (operator 2026-10-04: "move the 2026 packet
// translation layer into zone/world/login hook ... so no proxy is required, and disabling it is just a change in the
// ini ... can accept either shape always regardless of settings, setting just changes which version is sent").
//
// Moved over from the proxy's Bridge2026 plugin (fiesta-proxy plugins/Bridge2026) in BATCHES: each batch moves a few
// packets here and removes them from the proxy in the same change, so nothing is translated twice. MOVED SO FAR:
//   batch 1 (S->C, combat): 0x2448 SWING_DAMAGE, 0x2449 SOMEONESWING_DAMAGE, 0x243C DOTDAMAGE, 0x2452 SKILLBASH_HIT_DAMAGE,
//                           0x2402 TARGETINFO
//
// hooks\bridge26.ini:
//   [config]
//   send=2026          shape of the packets this plugin owns, sent to every client (default 2016 = untouched)
//   verify=1           also build the 2026 shape while sending 2016, and log (2016, 2026) pairs to bridge26-verify.log
//                      (tools/bridge26_verify replays them through the proxy's C# translators: they must match)
//   verify_max=200     pairs logged per opcode
//
// ---- WHERE ---------------------------------------------------------------------------------------------------------
// S->C: every game packet to a client is appended by PacketContainer::pcb_Append(ShineObject*, ProtocolPacket*)
// 0x4C8B20 (__thiscall, ret 8), one unframed packet per call {u8* pp_Buffer (opcode + payload), int pp_BufferSize,
// int pp_PacketLength}; the container copies it straight away, so a translated packet can live in a per-thread buffer.
// Server-to-server traffic never passes here (ProtocolPacket::pp_SendPacket), and S->C is plain (pe_FromServerToClient
// is the identity). Read 2026-10-04 (Zone.exe, the RE notes in the commit).
#include <zonehook.h>

#include <cstdio>
#include <cstring>

#include "bridge26_translate.h"

namespace {

const unsigned kVaPcbAppend = 0x004C8B20u;

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

// ---- the S->C hook ---------------------------------------------------------------------------------------------------
thread_local unsigned char t_out[0x2000];

void __fastcall on_append(void* self, void* edx, void* object, ProtocolPacket* pkt) {
    AppendFn original = (AppendFn)g_append.trampoline;
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
    zone::hook_function("PacketContainer::pcb_Append", zone::rebase(kVaPcbAppend), (void*)on_append, &g_append);
    zone::log("[bridge26] sending %s shapes for %d packet(s)%s", g_send2026 ? "2026" : "2016", kOwnedCount,
              g_verify ? ", verify on" : "");
}
