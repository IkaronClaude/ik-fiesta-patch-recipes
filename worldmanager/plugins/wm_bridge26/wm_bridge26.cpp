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
//         | 0x0C34 will-world-select ack (34 B) -> 0x0C25 | 0x980E academy member list head {total, index, count} ->
//         {flag (index 0 = clear first), count} (2026 store 0x908BA0 reads u8 + u16 + 109-byte members from 3; the
//         2016 head read as "clear, 0 members" left the official's academy member tab empty) | 0x9808 MY_GUILD_ACADEMY_
//         INFO_ACK 738 -> 742 B (GUILD_ACADEMY_CLIENT's dAcademyBuffUntilTime widened: 4 zero bytes at 2 + 36, as
//         0x1097's; the 2026 handler 0x83E161 reads an i64 at data 32 - the 2016 4 bytes + sIntro's first showed
//         "Guild Buff Remaining Time: -1:44").
// ini [config]: advertise = the ip[16] of the 2026 avatar list head. Official sends ITS public address there plus a port
// (OfficialUS2.pcapng: "192.99.126.72", port 9350 - a service of unknown purpose; the u16 stays 0 here, as the proxy
// sent it, which worked). The proxy put its own address in; default empty. advertise_port = the port beside it: the 2026
// client's item shop (PurchaseNetFrameWork 0x4ACF10) connects THERE - the official's purchase server (9350); 0 = none.
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
// THE PACKET IS STILL ENCRYPTED IN THE PARSER DETOUR: Parser decrypts it in place with 0x45D4B0 (byte ^= table[pos],
// pos = u16 at session+0x11E, table at 0x497840, wrapping at 0x1F3 - the 499-byte XOR table). Found 2026-10-05 on the
// Login twin (first live 2026 login refused); the WM login rename read and wrote encrypted bytes the same way.
const unsigned kVaXorTable = 0x00497840u;
const unsigned kSessionXorPos = 0x11E;
const unsigned kXorLen = 0x1F3;

const unsigned short kWmLogin2026 = 0x0C0E, kWmLogin2016 = 0x0C0F, kAvatars2016 = 0x0C14, kAvatars2026 = 0x0C0F;
const unsigned short kLogout2026 = 0x0C15, kWrapped2026 = 0x0C23, kLogout2016 = 0x0C18, kMidLogin2026 = 0x0C18;
const unsigned short kAvatarList2026 = 0x0C1A, kAvatarList2016 = 0x0C1F, kBack2026 = 0x0C24, kWillSelect2016 = 0x0C33;
const unsigned short kCreateOpen2026 = 0x0C32, kCreateOpenAck2026 = 0x0C34, kPostCreate2026 = 0x0C35;
const unsigned short kCreateReq = 0x1401, kCreateSucc = 0x1406, kCharLoginReq = 0x1001;
const unsigned short kGuildMembers = 0x741B, kAcademyInfo = 0x1097, kAcademyMembers = 0x980E;
const int kAcademyMember = 109;                           // GUILD_ACADEMY_MEMBER_CLIENT
const unsigned short kAcademyInfoAck = 0x9808;
const int kAcademyInfoAck2016 = 2 + 736, kAcademyInfoAckNewAt = 2 + 36;
const unsigned short kWillSelectAck2016 = 0x0C34, kBackAck2026 = 0x0C25;   // 0x0C34 is ALSO 2026's create-open ack
const int kWillSelectAck = 34;                                              // {nError, sOTP[32]}: told apart by size
const int kWmLoginPayloadUs = 320;
const int kAvatar2016 = 130, kAvatar2026 = 161, kAvatarSlotAt = 26;
const int kEquipAt = 48, kOldSlots = 20, kNewSlots = 35;    // u16 item ids in the avatar record; 0xFFFF = none
const int kGuildMember = 110, kAcademy2016 = 741, kAcademyNewAt = 5 + 36;
const unsigned char kCreateOpenHead[2] = { 0x39, 0x8E };
const unsigned char kAvatarSlots = 6;          // character slots the 2026 head says this account may use: the 2016
                                                // server's own count (CREATE refuses slot >= 6 with err 133 "Max Slot
                                                // Number", TutorialLoginProcess 0x4371BE stops at 6, the WM session holds
                                                // 6 x 0x82 avatar records at +0x23C) - 12 offered slots the server refuses
const int kCreateReq2026 = 26;

struct Sess { bool is2026 = false; std::set<unsigned char> used; };
std::map<void*, Sess> g_sess;
CRITICAL_SECTION g_lock;
char g_advertise[16] = {};
unsigned short g_advertise_port = 0;      // ini [config] advertise_port: the purchase (item shop) server's port
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

// the XOR stream byte at pos + i
unsigned char key_at(unsigned pos, int i) {
    return ((const unsigned char*)hook::rebase(kVaXorTable))[(pos + (unsigned)i) % kXorLen];
}

// ---- C->S: the WM login, renamed before the parser's pre-login gate ----------------------------------------------------
int __fastcall on_parser(void* parser, void*, void* session) {
    unsigned char* f = session ? *(unsigned char**)((char*)session + kSessionPacket + kPacketFramed) : 0;
    int size = 0, h = f ? frame_head(f, 3, &size) : 0;
    if (h && size >= 2) {
        unsigned pos = *(unsigned short*)((char*)session + kSessionXorPos);
        unsigned op = (unsigned)(f[h] ^ key_at(pos, 0)) | ((unsigned)(f[h + 1] ^ key_at(pos, 1)) << 8);
        if (op == kWmLogin2026 || op == kWmLogin2016) {
            bool new26 = op == kWmLogin2026;
            EnterCriticalSection(&g_lock);
            Sess& s = g_sess[session];
            s = Sess();
            s.is2026 = new26;
            LeaveCriticalSection(&g_lock);
            if (new26) {
                if (size - 2 == kWmLoginPayloadUs) {
                    // same length, so the stream stays in step: only the two opcode bytes change, encrypted at pos
                    f[h] = (unsigned char)((kWmLogin2016 & 0xFF) ^ key_at(pos, 0));
                    f[h + 1] = (unsigned char)((kWmLogin2016 >> 8) ^ key_at(pos, 1));
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

// one 130 B 2016 avatar record -> the 161 B 2026 one, as the official server lays it out (docs/EQUIP-SLOTS-2026.md, read
// from Official1.pcapng 0x0C0F): the 2016 bytes up to and with PROTO_EQUIPMENT's upgrade[3] (record 0..90) unchanged,
// then the 15 new u16 slots (all 0xFFFF: the 2016 server has none) and one byte (0x00, as official), then the rest of
// the 2016 record. (Was: the new slots inserted BEFORE upgrade[3] - the client read the + levels from 2016's slots.)
int avatar_record(const unsigned char* a, unsigned char* o) {
    const int upgrade_end = kEquipAt + kOldSlots * 2 + 3, added = (kNewSlots - kOldSlots) * 2;
    int m = 0;
    memcpy(o + m, a, upgrade_end); m += upgrade_end;
    memset(o + m, 0xFF, added); m += added;
    o[m++] = 0;
    memcpy(o + m, a + upgrade_end, kAvatar2016 - upgrade_end); m += kAvatar2016 - upgrade_end;
    return m;
}

int avatars(const unsigned char* p, int n, unsigned char* o, std::set<unsigned char>* used) {
    if (n < 3) return 0;
    int count = p[2], m = 0;
    memcpy(o, p, 3); m = 3;
    o[m++] = kAvatarSlots;
    memcpy(o + m, g_advertise, 16); m += 16;
    o[m++] = (unsigned char)(g_advertise_port & 0xFF); o[m++] = (unsigned char)(g_advertise_port >> 8);
    for (int i = 0; i < count; i++) {
        const unsigned char* a = p + 3 + kAvatar2016 * i;
        if (3 + kAvatar2016 * (i + 1) > n || m + kAvatar2026 > (int)sizeof t_out - 8) break;
        used->insert(a[kAvatarSlotAt]);
        m += avatar_record(a, o + m);
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
    // [config] trace_out=1: every S->C opcode to a 2026 client logged (debugging what the official is sent)
    static int trace_out = hook::config_int("trace_out", 0, "config");
    if (trace_out) hook::log("wm_bridge26: S->C 0x%04x (%d B)", op, size - 2);
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
        m = 1 + avatar_record(p + 1, body + 1);
        return real(sock, nullptr, t_out, frame(t_out, (unsigned short)op, body, m));
    case 0x5407:                                          // NC_FRIEND_LIST_CMD: 2016 {n, info x n (72 B)}, 2026 {n, flags
        if (n < 1 || n != 1 + p[0] * 72 || n + 1 > (int)sizeof body) break;   // (bit 0: clear first), info x n} - the 2026
        body[0] = p[0]; body[1] = 1;                      // client read the 2016 list a byte late ("ot8655" for Bot8655)
        memcpy(body + 2, p + 1, n - 1);
        return real(sock, nullptr, t_out, frame(t_out, (unsigned short)op, body, n + 1));
    case 0x541E:                                          // NC_FRIEND_POINT_ACK: 2016 {u16}, 2026 {u32} (the 2026
        if (n != 2) break;                                // client read 4 B: "Friend Points: 4587522" for 2)
        body[0] = p[0]; body[1] = p[1]; body[2] = 0; body[3] = 0;
        return real(sock, nullptr, t_out, frame(t_out, (unsigned short)op, body, 4));
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
    case kAcademyMembers: {
        if (n < 6) break;
        int start = p[2] | (p[3] << 8), count = p[4] | (p[5] << 8);
        if (n != 6 + count * kAcademyMember || 3 + count * kAcademyMember > (int)sizeof body) break;
        body[0] = (unsigned char)(start == 0 ? 1 : 0); body[1] = p[4]; body[2] = p[5];
        memcpy(body + 3, p + 6, count * kAcademyMember);
        return real(sock, nullptr, t_out, frame(t_out, (unsigned short)op, body, 3 + count * kAcademyMember));
    }
    case kWillSelectAck2016:                              // our own 6-byte create-open ack passes here too
        if (n != kWillSelectAck) break;
        return real(sock, nullptr, t_out, frame(t_out, kBackAck2026, p, n));
    case kAcademyInfoAck:
        if (n != kAcademyInfoAck2016) break;
        memcpy(body, p, kAcademyInfoAckNewAt);
        memset(body + kAcademyInfoAckNewAt, 0, 4);
        memcpy(body + kAcademyInfoAckNewAt + 4, p + kAcademyInfoAckNewAt, n - kAcademyInfoAckNewAt);
        return real(sock, nullptr, t_out, frame(t_out, (unsigned short)op, body, n + 4));
    case kAcademyInfo:
        if (n != kAcademy2016) break;
        memcpy(body, p, kAcademyNewAt);
        memset(body + kAcademyNewAt, 0, 4);
        memcpy(body + kAcademyNewAt + 4, p + kAcademyNewAt, n - kAcademyNewAt);
        return real(sock, nullptr, t_out, frame(t_out, (unsigned short)op, body, n + 4));
    }
    return real(sock, nullptr, f, len);
}

// ---- whispers from the ZONE (bridge26) ---------------------------------------------------------------------------------
// The 2026 client sends NC_ACT_WHISPER_REQ 0x200C to the zone, not here; the zone half (bridge26) sends it on over its WM
// link as 0x200C {wldmanhandle u16, the client's payload}. This registers that opcode in the ZONE protocol table
// (CParserZone at gServer + 0xC1E94: its ctor 0x42F540 is called on [esi + 0xC1E94] in WorldManagerServer's ctor 0x406B40;
// its Register(dept, cmd, fn) rows have no 8/0x0C) and runs the stock client handler for the sender's session:
// CWMClientSessionManager::GetSession(handle) 0x437860 on 0x556BB0 (as fc_NC_CHAR_ZONE_AUTO_PICK_CMD 0x429C30 finds its
// client), then CParserClient::fc_NC_ACT_WHISPER_REQ (the client table's 0x200C) with the client's packet - so the answers
// (SUCCESS / FAIL to the sender, SOMEONEWHISPER to the receiver) go out exactly as for a 2016 client.
const unsigned kZoneParserInServer = 0xC1E94u;
const unsigned kVaClientSessions = 0x00556BB0u, kVaGetSession = 0x00437860u;
// The party / guild / academy chat come the same way (NC_ACT_PARTYCHAT_REQ 0x2014, NC_GUILD_CHAT_REQ 0x7473,
// NC_GUILD_ACADEMY_CHAT_REQ 0x9868 - the 2026 client sends them to the zone too) and go to their own client handlers
// (fc_NC_ACT_PARTYCHAT_REQ / fc_NC_GUILD_CHAT_REQ / fc_NC_GUILD_ACADEMY_CHAT_REQ, the client table's rows).
const unsigned short kWhisperReq = 0x200C;
const unsigned short kRelayed[] = {kWhisperReq, 0x2014, 0x7473, 0x9868};
void* g_h_relayed[4] = {};
hook::u32 __fastcall zone_whisper(void* zparser, void*, hook::u32 zsession, hook::u32 pkt, hook::u32 len) {
    const unsigned char* p = (const unsigned char*)pkt + 2;
    int n = (int)len - 2;
    unsigned short op = (unsigned short)(((const unsigned char*)pkt)[0] | (((const unsigned char*)pkt)[1] << 8));
    void* h_client = 0;
    for (int i = 0; i < 4; i++)
        if (kRelayed[i] == op) h_client = g_h_relayed[i];
    if (n < 2 + 2 || !h_client) return 1;
    unsigned short h = (unsigned short)(p[0] | (p[1] << 8));
    typedef void*(__fastcall * GetSession)(void*, void*, unsigned short);
    void* cs = ((GetSession)hook::rebase(kVaGetSession))(hook::rebase(kVaClientSessions), 0, h);
    if (!cs) {
        hook::log("wm_bridge26: 0x%04x from the zone for client handle %u: no such session", op, h);
        return 1;
    }
    unsigned char* t = t_cmd[t_cmd_next++ & 7];
    if (n - 2 + 2 > (int)sizeof t_cmd[0]) return 1;
    t[0] = (unsigned char)(op & 0xFF); t[1] = (unsigned char)(op >> 8);
    memcpy(t + 2, p + 2, n - 2);
    ((Handler)h_client)(g_table, 0, (hook::u32)cs, (hook::u32)t, (hook::u32)n);
    return 1;                                         // the ZONE session stays (0 would close the zone link)
}

}  // namespace

HOOK_PLUGIN("wm_bridge26") {
    InitializeCriticalSection(&g_lock);
    char ip[32] = "";
    hook::config_str("advertise", "", ip, sizeof ip);
    strncpy_s(g_advertise, ip, 15);
    g_advertise_port = (unsigned short)hook::config_int("advertise_port", 0);
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
    // whispers relayed by the zone (see zone_whisper): only into a free zone-table slot
    void* ztable = hook::rebase(kVaGServer + kZoneParserInServer);
    for (int i = 0; i < 4; i++) {
        unsigned short op = kRelayed[i];
        g_h_relayed[i] = hook::proto::is_registered(g_table, op) ? hook::proto::get(g_table, op) : 0;
        bool zw = false;
        if (g_h_relayed[i] && !hook::proto::is_registered(ztable, op))
            zw = hook::proto::set(ztable, op, (void*)zone_whisper) != 0;
        hook::log("wm_bridge26: zone-relayed 0x%04x %s", op, zw ? "on" : (g_h_relayed[i] ? "NOT installed (zone table slot taken)" :
                                                                         "NOT installed (no client handler)"));
    }
    bool a = hook::detour(hook::rebase(kVaParser), (void*)on_parser, &g_parser);
    bool b = hook::detour(hook::rebase(kVaSocketSend), (void*)on_send, &g_send);
    hook::log("wm_bridge26: parser %s, send %s, %d of %d request hook(s), %d unregistered slot(s) covered; handlers "
              "0x0C18 %s, 0x0C1F %s, 0x0C33 %s; advertise '%s'", a ? "hooked" : "NOT hooked", b ? "hooked" : "NOT hooked",
              ok, (int)(sizeof kHooked / sizeof kHooked[0]), covered, g_h_logout ? "ok" : "MISSING",
              g_h_avlist ? "ok" : "MISSING", g_h_will ? "ok" : "MISSING", g_advertise);
}
