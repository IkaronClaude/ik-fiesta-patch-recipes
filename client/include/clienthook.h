// clienthook.h - the 2026 client's SERVER PACKETS, for client plugins: the client-side counterpart of the servers'
// hook::proto packet hooks. Include it from a client plugin (build_plugin.bat client <name> puts client\include on the
// path).
//
//     static bool on_avatars(const client::Packet& p) {
//         if (p.op != 0x0C0F) return false;                  // NC_USER_LOGINWORLD_ACK
//         ... read p.data / p.len ...
//         return false;                                      // true = swallow: the client never sees the packet
//     }
//     HOOK_PLUGIN("x") { client::on_packet(on_avatars); }
//
// ---- how the client dispatches a packet (2016 Fiesta.bin + Fiesta.pdb names, 2026 addresses in client_addrs.h) ---------
//
//   PgNet::DispatchMsg(PgFrameWork*, max) 2016 0x8C7B60: per received packet, splits the opcode into dept (>> 10) and
//   cmd (& 0x3FF) and calls the connection's own virtual ProcessNetMsg(dept, cmd, len, data) FIRST (PgNet vtable +0x18;
//   the live object is a Net - caddr::kNetProcessNetMsg, 2026 10.6.6 0x818000). Only when that returns false does the
//   current frame work's ProcessNetMsg get the packet. So this one hook sees every server packet - login, world
//   manager, zone - on the game thread, decrypted (server -> client is not enciphered), payload after the opcode.
//   Returning true from it is the client's own "handled" and skips the frame work: that is how a packet is swallowed.
//
//   OUTBOUND: a packet is built with PgNet::AddNetMsg(data, len) (2016 0x8C79D0, caddr::kNetAddNetMsg) zero or more
//   times, then PgNet::SendNetMsg(data, len) (2016 0x8C7A40, caddr::kNetSendNetMsg) appends the last part and sends;
//   the packet starts with its u16 opcode. client::on_send sees each assembled packet (observe only), before the
//   client enciphers it.
#pragma once
#include <hook_core.h>
#include <client_addrs.h>

namespace client {

struct Packet {
    unsigned op;                  // (dept << 10) | cmd
    unsigned dept, cmd;
    int len;                      // payload bytes after the opcode
    const unsigned char* data;    // the payload
};

// an observer: return true to swallow the packet (later observers and the client never see it)
typedef bool (*PacketFn)(const Packet&);

namespace detail {
enum { kMaxObservers = 32 };
inline PacketFn g_observers[kMaxObservers];
inline int g_count = 0;
inline hook::Detour g_detour;
inline bool g_tried = false, g_ok = false;
typedef bool(__fastcall* NetMsgFn)(void*, void*, int, int, int, void*);

inline bool __fastcall net_msg(void* self, void* edx, int dept, int cmd, int len, void* data) {
    Packet p{(unsigned)((dept << 10) | cmd), (unsigned)dept, (unsigned)cmd, len, (const unsigned char*)data};
    for (int i = 0; i < g_count; i++)
        if (g_observers[i](p)) return true;
    return ((NetMsgFn)g_detour.trampoline)(self, edx, dept, cmd, len, data);
}
}  // namespace detail

// ---- outbound ----------------------------------------------------------------------------------------------------------
typedef void (*SendFn)(const Packet&);

namespace detail {
inline SendFn g_senders[kMaxObservers];
inline int g_send_count = 0;
inline hook::Detour g_add_detour, g_send_detour;
inline bool g_send_tried = false, g_send_ok = false;
typedef void(__fastcall* AddSendFn)(void*, void*, const void*, int);
// the packet being built, per connection (Login, world manager and zone are separate PgNet objects)
struct Building { void* net; unsigned char buf[8192]; int len; };
inline Building g_building[4];

inline Building* building(void* net) {
    for (Building& b : g_building)
        if (b.net == net) return &b;
    for (Building& b : g_building)
        if (!b.net) { b.net = net; b.len = 0; return &b; }
    g_building[0].net = net;
    g_building[0].len = 0;
    return &g_building[0];
}

inline void append(Building* b, const void* data, int len) {
    if (len <= 0 || !data) return;
    int n = b->len + len <= (int)sizeof(b->buf) ? len : (int)sizeof(b->buf) - b->len;
    memcpy(b->buf + b->len, data, n);
    b->len += n;
}

inline void __fastcall add_msg(void* self, void* edx, const void* data, int len) {
    append(building(self), data, len);
    ((AddSendFn)g_add_detour.trampoline)(self, edx, data, len);
}

inline void __fastcall send_msg(void* self, void* edx, const void* data, int len) {
    Building* b = building(self);
    append(b, data, len);
    if (b->len >= 2) {
        unsigned op = b->buf[0] | (b->buf[1] << 8);
        Packet p{op, op >> 10, op & 0x3FF, b->len - 2, b->buf + 2};
        for (int i = 0; i < g_send_count; i++) g_senders[i](p);
    }
    b->len = 0;
    ((AddSendFn)g_send_detour.trampoline)(self, edx, data, len);
}
}  // namespace detail

// Register an observer of every packet the client sends. False when this build lacks the send functions.
inline bool on_send(SendFn fn) {
    using namespace detail;
    if (!g_send_tried) {
        g_send_tried = true;
        if (const char* m = caddr::missing({caddr::kNetAddNetMsg, caddr::kNetSendNetMsg}))
            hook::log("clienthook: %s - no send hook", m);
        else
            g_send_ok = hook::hook_function("PgNet::AddNetMsg", hook::rebase(caddr::va(caddr::kNetAddNetMsg)),
                                            (void*)&add_msg, &g_add_detour) &&
                        hook::hook_function("PgNet::SendNetMsg", hook::rebase(caddr::va(caddr::kNetSendNetMsg)),
                                            (void*)&send_msg, &g_send_detour);
    }
    if (!g_send_ok || g_send_count >= kMaxObservers) return false;
    g_senders[g_send_count++] = fn;
    return true;
}

// Register an observer of every server packet. The first call installs the hook; false when this Fiesta.exe build has
// no Net::ProcessNetMsg in client_addrs.h (the plugin then logs and goes without).
inline bool on_packet(PacketFn fn) {
    using namespace detail;
    if (!g_tried) {
        g_tried = true;
        if (const char* m = caddr::missing({caddr::kNetProcessNetMsg}))
            hook::log("clienthook: %s - no packet hook", m);
        else
            g_ok = hook::hook_function("Net::ProcessNetMsg", hook::rebase(caddr::va(caddr::kNetProcessNetMsg)),
                                       (void*)&net_msg, &g_detour);
    }
    if (!g_ok || g_count >= kMaxObservers) return false;
    g_observers[g_count++] = fn;
    return true;
}

}  // namespace client
