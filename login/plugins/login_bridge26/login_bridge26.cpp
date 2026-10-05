// login_bridge26 - the Login half of the 2026 client bridge (Fiesta2026on2016; zone half zone/plugins/bridge26, WM half
// worldmanager/plugins/wm_bridge26). What fiesta-proxy's Bridge2026 did on the login link, inside Login.exe.
//
// ---- PER SESSION ----------------------------------------------------------------------------------------------------
// The first packet says which client it is: a 2016 client sends NC_USER_CLIENT_VERSION_CHECK_REQ 0x0C65 with a 64-byte
// key, the 2026 client 0x0C2C + its build's numbering shift with 32 bytes (German shift 0; the US build numbers the
// dept-3 commands from 0x2C up higher - the shift is measured off this packet, as the proxy did). 2016 sessions stay stock.
//
// ---- WHAT LOGIN.EXE DOES (read from Login.exe + PDB, 2026-10-04) ----------------------------------------------------
//   CParserClient::Parser(session) 0x406680 reads the packet from the session's CPacket at +0xDC (its +0xC = the framed
//   bytes), gates by session state - state 0 lets only 0x0C65 through, state 1 only 0x0C37 (login with OTP) or the
//   configured login opcode (0x0C5A here) - then dispatches rows[op & 0x3FF][op >> 10] like the zone. So a 2026 request
//   is translated by POINTING THAT CPacket AT A 2016 FRAME for the duration of the original Parser call (restored after):
//   one mechanism for renames, length changes and gated opcodes alike.
//   Every send ends in CSocket_IOCP::Send(framed, len) 0x411030 on the session's socket at +0x28
//   (CLoginBaseSession::Send 0x408E20 is `add ecx, 0x28; jmp`), where the replies of a 2026 session are translated.
//   THE PACKET IS STILL ENCRYPTED WHEN THE DETOUR SEES IT (2026-10-05, first live 2026 login: "Not registered protocol
//   3/46" and a bare disconnect). Parser fetches data/len through the CPacket's vtable (+0x18/+0x14) and decrypts IN PLACE
//   with 0x40B170: byte ^= table[pos], pos = u16 at session+0x10C, table at 0x430430, wrapping at 0x1F3 (the 499-byte
//   XOR table). So the detour decrypts a COPY at pos to read the opcode; a substituted 2016 frame is ENCRYPTED at pos
//   (Parser decrypts it); and afterwards pos is set to where the CLIENT's stream is - pos + the original packet's
//   length - also for packets answered or dropped here, which the stock parser never sees.
//   The version check compares the key with the server's own list (ClientVersionKeyInfo.txt, loaded into 64-byte
//   entries at 0x44264C, count at 0x44278C): the 2026 request is answered with the FIRST of those - no constant.
//   No XTrap: NC_USER_XTRAP_REQ 0x0C04 only acks (0x0C05 {1}) and sets nothing the login needs, so nothing fakes one
//   (the proxy did), and the 2026 client (XIGNCODE) never sends one.
//
// ---- TRANSLATIONS (the proxy's - fiesta-proxy plugins/Bridge2026) ----------------------------------------------------
//   C->S  version -> 0x0C65 {the server's first key} | 0x0C01 login 349 B -> 0x0C5A 316 B (minus the leading 32 B and the
//         byte before spawnapps), or 0x0C37 {otp[32]} when the leading 32 B are a hex OTP | 8-byte will-select -> dropped
//         | 65-byte challenge answer -> answered here with the OTP frame | 0x0C0A {world} -> 0x0C0B.
//   S->C  0x0C67 version ack -> U(0x0C2D) {f6} | 0x0C09 fail -> 0x0C07 (the 2026 login
//         scene has no case for 9: the player saw a bare disconnect) | 0x0C0A world list -> U(0x0C40){1}, U(0x0C47){1},
//         0x0C06 {n, 00 05 00 60, entries}, U(0x0C3E) {challenge} | 0x0C0C world-select ack 83 B -> 0x0C0B 84 B (+ world).
//   The challenge, the OTP frame and the world-list head are 2026 handshake bytes the 2016 server has no notion of,
//   replayed from the official captures exactly as the proxy replayed them.
#include <hook_core.h>

#include <cstring>
#include <map>

namespace {

const unsigned kVaParser = 0x00406680u;        // CParserClient::Parser(CLoginClientSession*), __thiscall, ret 4
const unsigned kVaSocketSend = 0x00411030u;    // CSocket_IOCP::Send(void* framed, int len), __thiscall, ret 8
const unsigned kVaVersionKeys = 0x0044264Cu;   // the loaded ClientVersionKeyInfo keys, 64 B each
const unsigned kVaVersionKeyCount = 0x0044278Cu;
const unsigned kSessionPacket = 0xDC, kPacketFramed = 0xC, kSessionSocket = 0x28;
const unsigned kVaXorTable = 0x00430430u;      // the C->S XOR table 0x40B170 decrypts with
const unsigned kSessionXorPos = 0x10C;         // u16 stream position, advanced per byte by 0x40B170
const unsigned kXorLen = 0x1F3;

const unsigned short kVersion2016 = 0x0C65, kVersion2026 = 0x0C2C;         // 2026: + the build's shift
const unsigned short kLogin2026 = 0x0C01, kLogin2016 = 0x0C5A, kLoginOtp2016 = 0x0C37;
const unsigned short kWorldSelect2026 = 0x0C0A, kWorldSelect2016 = 0x0C0B;
const unsigned short kVersionAck2016 = 0x0C67, kLoginFail2016 = 0x0C09, kLoginAck2016 = 0x0C0A;
const unsigned short kWorldSelectAck2016 = 0x0C0C;
const unsigned short kVersionAck2026 = 0x0C2D, kLoginFail2026 = 0x0C07, kAck1 = 0x0C40, kAck2 = 0x0C47;
const unsigned short kWorldList2026 = 0x0C06, kChallenge2026 = 0x0C3E, kOtp2026 = 0x0C35, kWorldSelectAck2026 = 0x0C0B;
const int kShiftFrom = 0x2C;                   // the US build shifts dept-3 commands from here up (Opcodes.ShiftFrom)
const int kVersionKey2026 = 32, kVersionKey2016 = 64, kLoginLen2026 = 349, kOtpLen = 32;
const int kWillSelect2026 = 8, kChallengeAnswer2026 = 65, kWorldEntry = 18, kWorldSelectAck16Len = 83;

const unsigned char kWorldListHead[4] = { 0x00, 0x05, 0x00, 0x60 };
const unsigned char kChallenge[] = {
    0x33, 0x35, 0x36, 0x38, 0x34, 0x34, 0x31, 0x31, 0x37, 0x38, 0x39, 0x33, 0x31, 0x39, 0x36, 0x35, 0x30, 0x00, 0x0c, 0x60,
    0x00, 0x00, 0x00, 0x40, 0x38, 0x29, 0x0c, 0x65, 0xdb, 0xa3, 0x77, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x00,
    0x28, 0x00, 0x00, 0x00, 0xd0 };
const unsigned char kOtpReply[8] = { 0x39, 0x73, 0x36, 0x00, 0x06, 0x00, 0x00, 0x00 };

struct Sess { bool is2026 = false; int shift = 0; unsigned char world = 0; };
std::map<void*, Sess> g_sess;
CRITICAL_SECTION g_lock;
hook::Detour g_parser, g_send;

typedef int(__fastcall* ParserFn)(void* parser, void*, void* session);
typedef int(__fastcall* SockSendFn)(void* sock, void*, const unsigned char* framed, int len);

bool get(void* session, Sess* out) {
    EnterCriticalSection(&g_lock);
    std::map<void*, Sess>::const_iterator it = g_sess.find(session);
    bool r = it != g_sess.end();
    if (r) *out = it->second;
    LeaveCriticalSection(&g_lock);
    return r && out->is2026;
}

unsigned short U(unsigned short op, int shift) {
    return shift && op >= 0x0C00 && op < 0x1000 && (op & 0x3FF) >= kShiftFrom ? (unsigned short)(op + shift) : op;
}

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
    if (n) memcpy(o + h + 2, payload, n);
    return h + 2 + n;
}

void to_client(void* session, unsigned short op, const unsigned char* payload, int n) {
    unsigned char b[0x200];
    if (n + 5 > (int)sizeof b) return;
    ((SockSendFn)g_send.trampoline)((char*)session + kSessionSocket, nullptr, b, frame(b, op, payload, n));
}

unsigned short* xor_pos(void* session) { return (unsigned short*)((char*)session + kSessionXorPos); }
// XOR n bytes with the stream from pos - decrypts and encrypts alike, leaves the session's position alone
void xor_at(unsigned char* b, int n, unsigned pos) {
    const unsigned char* t = (const unsigned char*)hook::rebase(kVaXorTable);
    for (int i = 0; i < n; i++) { b[i] ^= t[pos]; if (++pos >= kXorLen) pos = 0; }
}
// the client encrypted `consumed` bytes for this packet: move the server's stream there
void consume(void* session, unsigned start, int consumed) {
    *xor_pos(session) = (unsigned short)((start + (unsigned)consumed) % kXorLen);
}

bool hex_otp(const unsigned char* p) {
    if (!p[0]) return false;
    for (int i = 0; i < kOtpLen; i++) {
        unsigned char c = p[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
    }
    return true;
}

// run the stock Parser on a 2016 frame instead of the received one
thread_local unsigned char t_in[0x400];
// `consumed` = op + payload bytes of the packet the client actually sent (its stream advanced by that much)
int parse_as(void* parser, void* session, unsigned short op, const unsigned char* payload, int n, int consumed) {
    unsigned char** at = (unsigned char**)((char*)session + kSessionPacket + kPacketFramed);
    unsigned char* was = *at;
    unsigned start = *xor_pos(session);
    if (n + 5 > (int)sizeof t_in) { consume(session, start, consumed); return 1; }
    frame(t_in, op, payload, n);
    int h = t_in[0] ? 1 : 3;
    xor_at(t_in + h, n + 2, start);                                  // Parser decrypts it back at the same position
    *at = t_in;
    int r = ((ParserFn)g_parser.trampoline)(parser, nullptr, session);
    *at = was;
    consume(session, start, consumed);
    return r;
}

int __fastcall on_parser(void* parser, void*, void* session) {
    ParserFn real = (ParserFn)g_parser.trampoline;
    unsigned char* f = session ? *(unsigned char**)((char*)session + kSessionPacket + kPacketFramed) : 0;
    int size = 0, h = f ? frame_head(f, 3, &size) : 0;
    if (!h || size < 2) return real(parser, nullptr, session);
    // read a DECRYPTED copy; the received bytes stay encrypted for the stock parser
    static thread_local unsigned char plain[0x400];
    if (size > (int)sizeof plain) return real(parser, nullptr, session);
    unsigned start = *xor_pos(session);
    memcpy(plain, f + h, size);
    xor_at(plain, size, start);
    unsigned op = plain[0] | (plain[1] << 8);
    const unsigned char* p = plain + 2;
    int n = size - 2;

    if (op == kVersion2016 && n == kVersionKey2016) {                // a 2016 client: stock from here on
        EnterCriticalSection(&g_lock); g_sess[session] = Sess(); LeaveCriticalSection(&g_lock);
        return real(parser, nullptr, session);
    }
    if (n == kVersionKey2026 && op >= kVersion2026 && op < 0x1000) {  // the 2026 version check: the session is marked
        Sess s; s.is2026 = true; s.shift = (int)op - kVersion2026;
        EnterCriticalSection(&g_lock); g_sess[session] = s; LeaveCriticalSection(&g_lock);
        int count = *(int*)hook::rebase(kVaVersionKeyCount);
        unsigned char key[kVersionKey2016] = {};
        if (count > 0) memcpy(key, hook::rebase(kVaVersionKeys), kVersionKey2016);
        // wsprintf (hook::log) has no '+' flag: "%+d" misparsed the arguments and handed %s an int - Login.exe died in
        // WPRINTF_GetLen on the first 2026 version check (2026-10-05). Plain %d, and a terminated copy of the key.
        char shown[21] = {};
        memcpy(shown, key, sizeof shown - 1);
        hook::log("login_bridge26: 2026 client (%s numbering, shift %d) - version check answered with the server's key '%s'",
                  s.shift ? "US" : "German", s.shift, shown);
        return parse_as(parser, session, kVersion2016, key, kVersionKey2016, size);
    }
    Sess s;
    if (!get(session, &s)) return real(parser, nullptr, session);

    if (op == kLogin2026 && n == kLoginLen2026) {
        if (hex_otp(p)) {
            hook::log("login_bridge26: 2026 login carries an OTP -> NC_USER_LOGIN_WITH_OTP_REQ");
            return parse_as(parser, session, kLoginOtp2016, p, kOtpLen, size);
        }
        unsigned char l[kLoginLen2026];
        memcpy(l, p + 32, 328 - 32);
        memcpy(l + (328 - 32), p + 329, kLoginLen2026 - 329);
        return parse_as(parser, session, kLogin2016, l, kLoginLen2026 - 33, size);
    }
    if (n == kWillSelect2026) { consume(session, start, size); return 1; }   // nothing to relay
    if (n == kChallengeAnswer2026) {                                  // not verified: answered with the OTP frame
        to_client(session, U(kOtp2026, s.shift), kOtpReply, sizeof kOtpReply);
        consume(session, start, size);
        return 1;
    }
    if (op == U(kWorldSelect2026, s.shift) && n == 1) {
        EnterCriticalSection(&g_lock); g_sess[session].world = p[0]; LeaveCriticalSection(&g_lock);
        return parse_as(parser, session, kWorldSelect2016, p, 1, size);
    }
    return real(parser, nullptr, session);
}

thread_local unsigned char t_out[0x1000];

int __fastcall on_send(void* sock, void*, const unsigned char* f, int len) {
    SockSendFn real = (SockSendFn)g_send.trampoline;
    void* session = f ? (char*)sock - kSessionSocket : 0;
    Sess s;
    if (!session || !get(session, &s)) return real(sock, nullptr, f, len);
    int size = 0, h = frame_head(f, len, &size);
    if (!h || size < 2 || h + size > len) return real(sock, nullptr, f, len);
    unsigned op = f[h] | (f[h + 1] << 8);
    const unsigned char* p = f + h + 2;
    int n = size - 2;
    unsigned char body[0x800];
    switch (op) {
    case kVersionAck2016: {
        const unsigned char ok = 0xF6;
        return real(sock, nullptr, t_out, frame(t_out, U(kVersionAck2026, s.shift), &ok, 1));
    }
    case kLoginFail2016:
        hook::log("login_bridge26: the login refused a 2026 client, err %d", n >= 2 ? p[0] | (p[1] << 8) : -1);
        return real(sock, nullptr, t_out, frame(t_out, kLoginFail2026, p, n));
    case kLoginAck2016: {
        if (n < 1 || n < 1 + kWorldEntry * p[0] || 5 + kWorldEntry * p[0] > (int)sizeof body) break;
        const unsigned char one = 1;
        to_client(session, U(kAck1, s.shift), &one, 1);
        to_client(session, U(kAck2, s.shift), &one, 1);
        body[0] = p[0];
        memcpy(body + 1, kWorldListHead, 4);
        memcpy(body + 5, p + 1, kWorldEntry * p[0]);
        int r = real(sock, nullptr, t_out, frame(t_out, kWorldList2026, body, 5 + kWorldEntry * p[0]));
        to_client(session, U(kChallenge2026, s.shift), kChallenge, sizeof kChallenge);
        hook::log("login_bridge26: world list -> 2026 (%d world(s)) + challenge", p[0]);
        return r;
    }
    case kWorldSelectAck2016:
        if (n < kWorldSelectAck16Len) break;
        memcpy(body, p, kWorldSelectAck16Len);                         // status, the WM's ip[16] + port, validate[64]
        body[kWorldSelectAck16Len] = s.world;
        return real(sock, nullptr, t_out, frame(t_out, kWorldSelectAck2026, body, kWorldSelectAck16Len + 1));
    }
    return real(sock, nullptr, f, len);
}

}  // namespace

HOOK_PLUGIN("login_bridge26") {
    InitializeCriticalSection(&g_lock);
    bool a = hook::detour(hook::rebase(kVaParser), (void*)on_parser, &g_parser);
    bool b = hook::detour(hook::rebase(kVaSocketSend), (void*)on_send, &g_send);
    hook::log("login_bridge26: parser %s, send %s; %d version key(s) loaded by the server", a ? "hooked" : "NOT hooked",
              b ? "hooked" : "NOT hooked", *(int*)hook::rebase(kVaVersionKeyCount));
}
