// wm_bridge26 - the WorldManager half of the 2026 client bridge (Fiesta2026on2016; the zone half is zone/plugins/bridge26).
// What fiesta-proxy's Bridge2026 did on the world-manager link, inside the WorldManager, so no proxy is needed.
//
// ---- PER SESSION, NOT PER SETTING ------------------------------------------------------------------------------------
// The WM login itself says which client it is: the 2026 client sends NC_USER_LOGINWORLD_REQ as 0x0C0E, the 2016 one as
// 0x0C0F. A session is marked at that packet and translated only if it is a 2026 one - so 2016 and 2026 clients can use
// the same WorldManager at once, and nothing needs configuring. (It also settles 0x0C18, which is the 2016 logout but a
// mid-login notice from the 2026 client.)
//
// ---- WHAT THE WORLDMANAGER DOES (read from WorldManager.exe + PDB, 2026-10-04) ----------------------------------------
//   WorldManagerServer::ProcessPacket -> CParserClient::Parser(session) 0x419690 (__thiscall, ecx = &gServer + 0xBCBBC):
//     the packet being parsed is the session's CPacket at +0xDC, whose +0xC points at the framed bytes ([len u8] or
//     [00][len u16], then opcode + payload; len counts the opcode). Before the WM login only 3/15 (0x0C0F) is let
//     through - anything else, 0x0C0E included, closes the session - so the 2026 opcode is renamed IN THE BUFFER here.
//     Then handler = rows[op & 0x3FF][op >> 10] of the PROTOCOLFUNCTIONTEMPLETE at that parser (the zone's layout, so
//     hook::proto works), called __thiscall(parser, session, packet = &opcode, len). A 0 return CLOSES the session
//     (state 3); an unregistered opcode logs "invalid protocol" and closes it too.
//   Every send - CWMBaseSession::Send(void*, int) 0x42FCA0 and Send(CSendPacket*) 0x42FC50 - ends in
//     CSocket_IOCP::Send(framed, len) 0x4666F0 on the session's socket at +0x28; the zone sessions use it too, which is
//     why only sessions this plugin has marked as 2026 are translated.
//
// ---- TRANSLATIONS (the proxy's, byte for byte - fiesta-proxy plugins/Bridge2026, Translators.cs / Session.cs) ---------
//   C->S  0x0C0E WM login -> 0x0C0F (the US client already sends the 320-byte 2016 payload; the German 82-byte one is
//         not supported here) | 0x0C15 logout / 0x0C23 {0x0C15, type} -> the 0x0C18 handler | 0x0C1A {b} -> the 0x0C1F
//         avatar-list handler | 0x0C24 -> the 0x0C33 will-world-select handler | 0x0C32 create-open -> answered here
//         (0x0C34 with the first free slot) | 0x0C18 / 0x0C35 from a 2026 client -> dropped | 0x1401 create 26 -> 25 B
//         | any opcode the WM has no handler for -> dropped (logged) instead of closing the session.
//   S->C  0x0C14 avatar list (130 B records) -> 0x0C0F (161 B records + slots / ip / port head) | 0x1406 create-success
//         record 130 -> 161 | 0x741B guild member list head {total, start, count} -> {flag, count} (+ an empty closing
//         chunk after the last) | 0x1097 academy info 741 -> 745 B (4 zero bytes at 41: THE guild login crash)
//         | 0x0C34 will-world-select ack (34 B) -> 0x0C25.
// ini [config]: advertise = the ip[16] of the 2026 avatar list head. Official sends ITS public address there plus a port
// (OfficialUS2.pcapng: "192.99.126.72", port 9350 - a service of unknown purpose; the u16 stays 0 here, as the proxy
// sent it, which worked). The proxy put its own address in; default empty.
#include <hook_core.h>

#include <cstdio>
#include <cstring>
#include <map>
#include <set>

namespace {

const unsigned kVaParser = 0x00419690u;        // CParserClient::Parser(CWMClientSession*), __thiscall, ret 4
const unsigned kVaSocketSend = 0x004666F0u;    // CSocket_IOCP::Send(void* framed, int len), __thiscall, ret 8
const unsigned kVaBaseSend = 0x0042FCA0u;      // CWMBaseSession::Send(void* framed, int len)
const unsigned kVaGServer = 0x0049A028u;       // gServer (WorldManagerServer)
const unsigned kParserInServer = 0xBCBBCu;     // its CParserClient = the client protocol table
const unsigned kSessionPacket = 0xDC;          // CWMBaseSession: the CPacket being parsed
const unsigned kPacketFramed = 0xC;            // CPacket: the framed bytes
const unsigned kSessionSocket = 0x28;          // CWMBaseSession: its CSocket_IOCP

const unsigned short kWmLogin2026 = 0x0C0E, kWmLogin2016 = 0x0C0F, kAvatars2016 = 0x0C14, kAvatars2026 = 0x0C0F;
const unsigned short kLogout2026 = 0x0C15, kWrapped2026 = 0x0C23, kLogout2016 = 0x0C18, kMidLogin2026 = 0x0C18;
const unsigned short kAvatarList2026 = 0x0C1A, kAvatarList2016 = 0x0C1F, kBack2026 = 0x0C24, kWillSelect2016 = 0x0C33;
const unsigned short kCreateOpen2026 = 0x0C32, kCreateOpenAck2026 = 0x0C34, kPostCreate2026 = 0x0C35;
const unsigned short kCreateReq = 0x1401, kCreateSucc = 0x1406, kCharLoginReq = 0x1001;
const unsigned short kGuildMembers = 0x741B, kAcademyInfo = 0x1097;
const unsigned short kWillSelectAck2016 = 0x0C34, kBackAck2026 = 0x0C25;   // 0x0C34 is ALSO 2026's create-open ack
const int kWillSelectAck = 34;                                              // {nError, sOTP[32]}: told apart by size
const int kWmLoginPayloadUs = 320;
const int kAvatar2016 = 130, kAvatar2026 = 161, kAvatarSlotAt = 26;
const int kEquipAt = 48, kOldSlots = 20, kNewSlots = 35;    // u16 item ids in the avatar record; 0xFFFF = none
const int kGuildMember = 110, kAcademy2016 = 741, kAcademyNewAt = 5 + 36;
const unsigned char kCreateOpenHead[2] = { 0x39, 0x8E };
const unsigned char kAvatarSlots = 0x0C;       // character slots the 2026 head says this account may use
const int kCreateReq2026 = 26;

struct Sess { bool is2026 = false; std::set<unsigned char> used; };
std::map<void*, Sess> g_sess;
CRITICAL_SECTION g_lock;
char g_advertise[16] = {};
void* g_table = 0;
void* g_unknown = 0;
void* g_h_logout = 0;
void* g_h_avlist = 0;
void* g_h_will = 0;
hook::Detour g_parser, g_send;

typedef hook::u32(__fastcall* Handler)(void* parser, void*, hook::u32 session, hook::u32 pkt, hook::u32 len);
typedef int(__fastcall* SockSendFn)(void* sock, void*, unsigned char* framed, int len);
typedef int(__fastcall* ParserFn)(void* parser, void*, void* session);

bool is2026(void* session) {
    EnterCriticalSection(&g_lock);
    std::map<void*, Sess>::const_iterator it = g_sess.find(session);
    bool r = it != g_sess.end() && it->second.is2026;
    LeaveCriticalSection(&g_lock);
    return r;
}

// [len u8] or [00][len u16]; returns the header size, 0 = not a frame
int frame_head(const unsigned char* f, int avail, int* size) {
    if (avail < 1) return 0;
    if (f[0]) { *size = f[0]; return 1; }
    if (avail < 3) return 0;
    *size = f[1] | (f[2] << 8);
    return 3;
}
int frame(unsigned char* o, unsigned short op, const unsigned char* payload, int n) {
    int size = n + 2, h;
    if (size < 256) { o[0] = (unsigned char)size; h = 1; }
    else { o[0] = 0; o[1] = (unsigned char)(size & 0xFF); o[2] = (unsigned char)(size >> 8); h = 3; }
    o[h] = (unsigned char)(op & 0xFF); o[h + 1] = (unsigned char)(op >> 8);
    memcpy(o + h + 2, payload, n);
    return h + 2 + n;
}

// ---- C->S: the WM login, renamed before the parser's pre-login gate ----------------------------------------------------
int __fastcall on_parser(void* parser, void*, void* session) {
    unsigned char* f = session ? *(unsigned char**)((char*)session + kSessionPacket + kPacketFramed) : 0;
    int size = 0, h = f ? frame_head(f, 3, &size) : 0;
    if (h && size >= 2) {
        unsigned op = f[h] | (f[h + 1] << 8);
        if (op == kWmLogin2026 || op == kWmLogin2016) {
            bool new26 = op == kWmLogin2026;
            EnterCriticalSection(&g_lock);
            Sess& s = g_sess[session];
            s = Sess();
            s.is2026 = new26;
            LeaveCriticalSection(&g_lock);
            if (new26) {
                if (size - 2 == kWmLoginPayloadUs) {
                    f[h] = (unsigned char)(kWmLogin2016 & 0xFF); f[h + 1] = (unsigned char)(kWmLogin2016 >> 8);
                    hook::log("wm_bridge26: 2026 client - WM login 0x0C0E -> 0x0C0F (%d B)", size - 2);
                } else {
                    hook::log("wm_bridge26: 2026 WM login of %d B (not the US 320) - the German form is not supported here",
                              size - 2);
                }
            }
        }
    }
    return ((ParserFn)g_parser.trampoline)(parser, nullptr, session);
}

// ---- C->S: the table ---------------------------------------------------------------------------------------------------
thread_local unsigned char t_cmd[8][0x200];
thread_local int t_cmd_next = 0;

hook::u32 call_handler(void* h, hook::proto::Call& c, unsigned short op, const unsigned char* payload, int n) {
    unsigned char* t = t_cmd[t_cmd_next++ & 7];
    if (!h || n + 2 > (int)sizeof t_cmd[0]) return 1;
    t[0] = (unsigned char)(op & 0xFF); t[1] = (unsigned char)(op >> 8);
    memcpy(t + 2, payload, n);
    return ((Handler)h)(c.self, 0, c.args[0], (hook::u32)t, (hook::u32)(n + 2));
}

void send_to(void* session, unsigned short op, const unsigned char* payload, int n) {
    unsigned char b[0x100];
    int m = frame(b, op, payload, n);
    typedef int(__fastcall * SendFn)(void*, void*, void*, int);
    ((SendFn)hook::rebase(kVaBaseSend))(session, nullptr, b, m);
}

void on_client(hook::proto::Call& c) {
    void* session = (void*)c.args[0];
    if (!is2026(session)) { c.original(); return; }          // a 2016 client: stock, unknown opcodes included
    const unsigned char* p = (const unsigned char*)c.args[1] + 2;
    int n = (int)c.args[2] - 2;
    switch (c.op) {
    case kLogout2026:
        if (n == 1) { c.result = call_handler(g_h_logout, c, kLogout2016, p, 1); hook::log("wm_bridge26: 0x0C15 -> logout (type %u)", p[0]); }
        return;
    case kWrapped2026:
        if (n == 3 && (p[0] | (p[1] << 8)) == kLogout2026) {
            c.result = call_handler(g_h_logout, c, kLogout2016, p + 2, 1);
            hook::log("wm_bridge26: 0x0C23 {0x0C15} -> logout (type %u, instant)", p[2]);
        } else {
            hook::log("wm_bridge26: 0x0C23 wraps 0x%04x (%d B): no translation, dropped", n >= 2 ? (p[0] | (p[1] << 8)) : 0, n - 2);
        }
        return;
    case kAvatarList2026:
        if (n == 1) { c.result = call_handler(g_h_avlist, c, kAvatarList2016, p, 1); hook::log("wm_bridge26: 0x0C1A -> avatar list request"); }
        return;
    case kBack2026:
        c.result = call_handler(g_h_will, c, kWillSelect2016, p, n);
        hook::log("wm_bridge26: 0x0C24 -> will-world-select");
        return;
    case kCreateOpen2026: {
        unsigned char free = 0;
        EnterCriticalSection(&g_lock);
        const std::set<unsigned char>& used = g_sess[session].used;
        while (used.count(free) && free < 64) free++;
        LeaveCriticalSection(&g_lock);
        unsigned char ack[6] = { kCreateOpenHead[0], kCreateOpenHead[1], free, 0, 0, 0 };
        send_to(session, kCreateOpenAck2026, ack, sizeof ack);
        hook::log("wm_bridge26: create-open answered, first free slot %u", free);
        return;
    }
    case kMidLogin2026:                                   // = 0x0C18: a 2016 logout, but a 2026 mid-login notice
    case kPostCreate2026:
        return;
    case kCreateReq:
        if (n == kCreateReq2026) c.args[2] = (hook::u32)(kCreateReq2026 - 1 + 2);   // the 5th appearance byte is new
        c.original();
        return;
    case kCharLoginReq:
        if (n == 1) hook::log("wm_bridge26: character slot %u selected", p[0]);
        c.original();
        return;
    }
    c.original();
}

std::map<unsigned, int> g_dropped;
hook::u32 __fastcall cover(void* parser, void*, hook::u32 session, hook::u32 pkt, hook::u32 len) {
    if (!is2026((void*)session)) return ((Handler)g_unknown)(parser, 0, session, pkt, len);   // 2016: stock (closes)
    const unsigned char* c = (const unsigned char*)pkt;
    unsigned op = c ? (unsigned)(c[0] | (c[1] << 8)) : 0xFFFF;
    EnterCriticalSection(&g_lock);
    int k = ++g_dropped[op];
    LeaveCriticalSection(&g_lock);
    if (k <= 3) hook::log("wm_bridge26: dropped 0x%04x (%u B) from a 2026 client: no handler in the 2016 WM%s", op, len,
                          k == 3 ? " (last report)" : "");
    return 1;
}

const unsigned short kHooked[] = { kLogout2026, kWrapped2026, kAvatarList2026, kBack2026, kCreateOpen2026,
                                   kMidLogin2026, kPostCreate2026, kCreateReq, kCharLoginReq };

// ---- S->C ---------------------------------------------------------------------------------------------------------------
thread_local unsigned char t_out[0x4000];

int avatars(const unsigned char* p, int n, unsigned char* o, std::set<unsigned char>* used) {
    if (n < 3) return 0;
    int count = p[2], m = 0;
    memcpy(o, p, 3); m = 3;
    o[m++] = kAvatarSlots;
    memcpy(o + m, g_advertise, 16); m += 16;
    o[m++] = 0; o[m++] = 0;
    const int upgrade = kEquipAt + kOldSlots * 2, added = (kNewSlots - kOldSlots) * 2;
    for (int i = 0; i < count; i++) {
        const unsigned char* a = p + 3 + kAvatar2016 * i;
        if (3 + kAvatar2016 * (i + 1) > n || m + kAvatar2026 > (int)sizeof t_out - 8) break;
        used->insert(a[kAvatarSlotAt]);
        memcpy(o + m, a, upgrade); m += upgrade;
        memset(o + m, 0xFF, added + 1); m += added + 1;          // the new slots, plus the upgrade field's extra byte
        memcpy(o + m, a + upgrade, kAvatar2016 - upgrade); m += kAvatar2016 - upgrade;
    }
    return m;
}

int __fastcall on_send(void* sock, void*, unsigned char* f, int len) {
    SockSendFn real = (SockSendFn)g_send.trampoline;
    void* session = f ? (char*)sock - kSessionSocket : 0;
    if (!session || !is2026(session)) return real(sock, nullptr, f, len);
    int size = 0, h = frame_head(f, len, &size);
    if (!h || size < 2 || h + size > len) return real(sock, nullptr, f, len);
    unsigned op = f[h] | (f[h + 1] << 8);
    const unsigned char* p = f + h + 2;
    int n = size - 2, m = 0;
    unsigned char body[0x2000];
    switch (op) {
    case kAvatars2016: {
        EnterCriticalSection(&g_lock);
        std::set<unsigned char> used;
        m = avatars(p, n, body, &used);
        g_sess[session].used = used;
        LeaveCriticalSection(&g_lock);
        if (!m) break;
        int k = frame(t_out, kAvatars2026, body, m);
        hook::log("wm_bridge26: avatar list -> 2026 (%d character(s))", n >= 3 ? p[2] : 0);
        return real(sock, nullptr, t_out, k);
    }
    case kCreateSucc:
        if (n != 1 + kAvatar2016) break;
        body[0] = p[0];
        {
            const int upgrade = kEquipAt + kOldSlots * 2, added = (kNewSlots - kOldSlots) * 2;
            const unsigned char* a = p + 1;
            m = 1;
            memcpy(body + m, a, upgrade); m += upgrade;
            memset(body + m, 0xFF, added + 1); m += added + 1;
            memcpy(body + m, a + upgrade, kAvatar2016 - upgrade); m += kAvatar2016 - upgrade;
        }
        return real(sock, nullptr, t_out, frame(t_out, (unsigned short)op, body, m));
    case kGuildMembers: {
        if (n < 6) break;
        int total = p[0] | (p[1] << 8), start = p[2] | (p[3] << 8), count = p[4] | (p[5] << 8);
        if (n != 6 + count * kGuildMember || 3 + count * kGuildMember > (int)sizeof body) break;
        body[0] = (unsigned char)(start == 0 ? 1 : 0); body[1] = p[4]; body[2] = p[5];
        memcpy(body + 3, p + 6, count * kGuildMember);
        int r = real(sock, nullptr, t_out, frame(t_out, (unsigned short)op, body, 3 + count * kGuildMember));
        if (start + count >= total) {
            const unsigned char end[3] = { 0, 0, 0 };
            real(sock, nullptr, t_out, frame(t_out, (unsigned short)op, end, 3));
        }
        return r;
    }
    case kWillSelectAck2016:                              // our own 6-byte create-open ack passes here too
        if (n != kWillSelectAck) break;
        return real(sock, nullptr, t_out, frame(t_out, kBackAck2026, p, n));
    case kAcademyInfo:
        if (n != kAcademy2016) break;
        memcpy(body, p, kAcademyNewAt);
        memset(body + kAcademyNewAt, 0, 4);
        memcpy(body + kAcademyNewAt + 4, p + kAcademyNewAt, n - kAcademyNewAt);
        return real(sock, nullptr, t_out, frame(t_out, (unsigned short)op, body, n + 4));
    }
    return real(sock, nullptr, f, len);
}

}  // namespace

HOOK_PLUGIN("wm_bridge26") {
    InitializeCriticalSection(&g_lock);
    char ip[32] = "";
    hook::config_str("advertise", "", ip, sizeof ip);
    strncpy_s(g_advertise, ip, 15);
    g_table = hook::rebase(kVaGServer + kParserInServer);
    g_unknown = hook::proto::unknown_handler(g_table);
    bool ready = hook::proto::is_registered(g_table, kWmLogin2016);
    g_h_logout = hook::proto::is_registered(g_table, kLogout2016) ? hook::proto::get(g_table, kLogout2016) : 0;
    g_h_avlist = hook::proto::is_registered(g_table, kAvatarList2016) ? hook::proto::get(g_table, kAvatarList2016) : 0;
    g_h_will = hook::proto::is_registered(g_table, kWillSelect2016) ? hook::proto::get(g_table, kWillSelect2016) : 0;
    if (!ready) {
        hook::log("wm_bridge26: the client protocol table is not filled yet (no 0x0C0F handler) - NOT installed");
        return;
    }
    int ok = 0;
    for (unsigned short op : kHooked)
        ok += hook::proto::hook_opcode<0>(g_table, op, on_client, hook::proto::kPacketArg2) ? 1 : 0;
    int covered = hook::proto::cover_unregistered(g_table, (void*)&cover);
    bool a = hook::detour(hook::rebase(kVaParser), (void*)on_parser, &g_parser);
    bool b = hook::detour(hook::rebase(kVaSocketSend), (void*)on_send, &g_send);
    hook::log("wm_bridge26: parser %s, send %s, %d of %d request hook(s), %d unregistered slot(s) covered; handlers "
              "0x0C18 %s, 0x0C1F %s, 0x0C33 %s; advertise '%s'", a ? "hooked" : "NOT hooked", b ? "hooked" : "NOT hooked",
              ok, (int)(sizeof kHooked / sizeof kHooked[0]), covered, g_h_logout ? "ok" : "MISSING",
              g_h_avlist ? "ok" : "MISSING", g_h_will ? "ok" : "MISSING", g_advertise);
}
