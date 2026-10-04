// bridge26_translate.h - the 2026 wire translators of zone/plugins/bridge26, shared by the plugin and its vector test
// (common: no hook, no CRT beyond memset/memcpy). Each is the proxy's T.* function of the same name (fiesta-proxy
// plugins/Bridge2026/Translators.cs), byte for byte - checked by fiesta-proxy tests ZoneHookParityTests.
#pragma once
#include <cstring>

namespace bridge26 {

// 2016 payload -> 2026 payload in `out` (room for 0x2000); returns its length, 0 = not this shape (leave the packet alone)
typedef int (*Translate)(const unsigned char* p, int n, unsigned char* out);

inline void put_u32(unsigned char* o, unsigned v) { o[0] = (unsigned char)v; o[1] = (unsigned char)(v >> 8); o[2] = (unsigned char)(v >> 16); o[3] = (unsigned char)(v >> 24); }
inline unsigned get_u16(const unsigned char* p) { return p[0] | (p[1] << 8); }

// NC_BAT_SWING_DAMAGE 16 -> 25: attacker, defender, flag (6); damage u16 -> u32; resthp, order, index, sequence (8); 7 zero
inline int swing(const unsigned char* p, int n, unsigned char* o) {
    if (n != 16) return 0;
    memset(o, 0, 25);
    memcpy(o, p, 6);
    put_u32(o + 6, get_u16(p + 6));
    memcpy(o + 10, p + 8, 8);
    return 25;
}

// NC_BAT_TARGETINFO 30 -> 41: the head unchanged, hpchangeorder u16 -> u32, nine zero bytes follow
inline int targetinfo(const unsigned char* p, int n, unsigned char* o) {
    if (n != 30) return 0;
    memset(o, 0, 41);
    memcpy(o, p, 28);
    put_u32(o + 28, get_u16(p + 28));
    return 41;
}

// DOTDAMAGE / SOMEONESWING_DAMAGE 13 -> 20: the 2016 layout, then 7 zero bytes
inline int tail7(const unsigned char* p, int n, unsigned char* o) {
    if (n != 13) return 0;
    memcpy(o, p, 13);
    memset(o + 13, 0, 7);
    return 20;
}

// NC_BAT_SKILLBASH_HIT_DAMAGE {index u16, caster u16, n u8} + n x 14 -> the head, skill u16 (0), 0xFFFF, n x 21 (+7 zero)
inline int skillhit(const unsigned char* p, int n, unsigned char* o) {
    if (n < 5) return 0;
    int k = p[4];
    if (n != 5 + 14 * k) return 0;
    int len = 9 + 21 * k;
    memset(o, 0, len);
    memcpy(o, p, 5);
    o[7] = 0xFF; o[8] = 0xFF;
    for (int i = 0; i < k; i++) memcpy(o + 9 + 21 * i, p + 5 + 14 * i, 14);
    return len;
}

// the four NC_BAT_SKILLBASH *_START frames: the 2016 struct, then a u32 (1 - what a single hit carries; the 2026 client
// reads its cast bookkeeping out of it: a 2016-width frame leaves the cast open and every later cast is refused)
template <int Size>
inline int hitstart(const unsigned char* p, int n, unsigned char* o) {
    if (n != Size) return 0;
    memcpy(o, p, Size);
    put_u32(o + Size, 1);
    return Size + 4;
}

// ---- client -> server (2026 -> 2016) ----------------------------------------------------------------------------------

// NC_SKILL_EMPOWALLOC_REQ 0x4811: 2026 {skill u16, plus 6 B, minus 6 B} (12 nibbles each) -> 2016 {skill u16, plus u16,
// minus u16} = nibbles 7..10 of each 48-bit block (T.SkillEmpowAlloc2026To2016). 0 = not the 14-byte 2026 shape.
inline unsigned empow_block(const unsigned char* p) {
    unsigned long long v = 0;
    for (int i = 5; i >= 0; i--) v = (v << 8) | p[i];
    return (unsigned)((v >> 28) & 0xFFFF);
}
inline int empower_2026_to_2016(const unsigned char* p, int n, unsigned char* o) {
    if (n != 14) return 0;
    o[0] = p[0]; o[1] = p[1];
    unsigned a = empow_block(p + 2), b = empow_block(p + 8);
    o[2] = (unsigned char)a; o[3] = (unsigned char)(a >> 8);
    o[4] = (unsigned char)b; o[5] = (unsigned char)(b >> 8);
    return 6;
}

struct Owned { unsigned short op; Translate fn; const char* name; };
// ---- batch 4 ---------------------------------------------------------------------------------------------------------
// CHARGEDBUFF {count u16} + n x 14 -> {u32 0, count u16} + n x 22 (the 14 bytes, then 8 zero) - T.ChargedBuff2016To2026
inline int chargedbuff(const unsigned char* p, int n, unsigned char* o) {
    if (n < 2) return 0;
    int k = get_u16(p);
    if (n != 2 + 14 * k || 6 + 22 * k > 0x1FF0) return 0;
    memset(o, 0, 6 + 22 * k);
    o[4] = p[0]; o[5] = p[1];
    for (int i = 0; i < k; i++) memcpy(o + 6 + 22 * i, p + 2 + 14 * i, 14);
    return 6 + 22 * k;
}
// CHARGED_BUFFSTART 14 -> 22 (8 zero: the 2026 handler reads a u32 at +14 that picks its list) - T.ChargedBuffStart2016To2026
inline int chargedbuff_start(const unsigned char* p, int n, unsigned char* o) {
    if (n != 14) return 0;
    memcpy(o, p, 14);
    memset(o + 14, 0, 8);
    return 22;
}
// CHARGED_BUFFTERMINATE {key u32} + one 0 byte (the normal list) - T.ChargedBuffTerminate2016To2026
inline int chargedbuff_terminate(const unsigned char* p, int n, unsigned char* o) {
    if (n != 4) return 0;
    memcpy(o, p, 4);
    o[4] = 0;
    return 5;
}
// SHOPOPEN* and their TABLE forms: {itemnum u16, npc u16} + n x {slot u8, item u16} -> slot widened to u32 - T.ShopTable2016To2026
inline int shoptable(const unsigned char* p, int n, unsigned char* o) {
    if (n < 4) return 0;
    int k = get_u16(p);
    if (n != 4 + 3 * k || 4 + 6 * k > 0x1FF0) return 0;
    memset(o, 0, 4 + 6 * k);
    memcpy(o, p, 4);
    for (int i = 0; i < k; i++) {
        o[4 + 6 * i] = p[4 + 3 * i];
        o[4 + 6 * i + 4] = p[5 + 3 * i];
        o[4 + 6 * i + 5] = p[6 + 3 * i];
    }
    return 4 + 6 * k;
}
// NC_CHAR_CLIENT_BASE 105 -> the US 362: one byte inserted at 54, zero-padded - T.ClientBase2016To2026(p, ClientBaseUs)
inline int clientbase(const unsigned char* p, int n, unsigned char* o) {
    if (n != 105) return 0;
    memset(o, 0, 362);
    memcpy(o, p, 54);
    memcpy(o + 55, p + 54, 105 - 54);
    return 362;
}

// ---- batch 5: briefinfo records. The US build's records are ONE byte longer than the German's (in the abstate padding);
// the proxy targets the US build - g_us_extra = 1 (ini build=us), 0 for the German build (build=de).
inline int g_us_extra = 1;

// REGENMOB row 149 -> 187 + extra: 37 + extra zero bytes after the 99-byte abstate array at 114, one zero at the end
inline int regenmob_row(const unsigned char* p, unsigned char* o) {
    int e = g_us_extra;
    memcpy(o, p, 114);
    memset(o + 114, 0, 37 + e);
    memcpy(o + 151 + e, p + 114, 35);
    o[186 + e] = 0;
    return 187 + e;
}
// NC_BRIEFINFO_REGENMOB_CMD: one row - T.RegenMobRow2016To2026
inline int regenmob(const unsigned char* p, int n, unsigned char* o) {
    if (n != 149) return 0;
    return regenmob_row(p, o);
}
// NC_BRIEFINFO_MOB_CMD {count u8} + n rows - T.MobCmd2016To2026
inline int mobcmd(const unsigned char* p, int n, unsigned char* o) {
    if (n < 1) return 0;
    int k = p[0];
    if (k == 0 || n != 1 + 149 * k || 1 + (187 + g_us_extra) * k > 0x1FF0) return 0;
    o[0] = (unsigned char)k;
    int at = 1;
    for (int i = 0; i < k; i++) at += regenmob_row(p + 1 + 149 * i, o + at);
    return at;
}
// NC_BRIEFINFO_REGENMOVER_CMD 139 -> 176 + extra: the abstate array grows - T.RegenMover2016To2026
inline int regenmover(const unsigned char* p, int n, unsigned char* o) {
    if (n != 139) return 0;
    int e = g_us_extra;
    memcpy(o, p, 118);
    memset(o + 118, 0, 37 + e);
    memcpy(o + 155 + e, p + 118, 21);
    return 176 + e;
}
// LOGINCHARACTER 235 -> 304 + extra (T.LoginCharacter2016To2026): head + shape to 82, 31 more equipment bytes, 9 bytes,
// one byte, the 99 old bitset bytes, 36 + extra new ones (bits 792-1079 at 222, filled by the plugin), the tail, 2 bytes
const int kLoginCharacterExtraBitsAt = 222;
inline int logincharacter_row(const unsigned char* p, unsigned char* o) {
    int e = g_us_extra, at = 0;
    memcpy(o + at, p, 82); at += 82;
    memset(o + at, 0, 31); at += 31;
    memcpy(o + at, p + 82, 9); at += 9;
    o[at++] = 0;
    memcpy(o + at, p + 91, 99); at += 99;
    memset(o + at, 0, 36 + e); at += 36 + e;
    memcpy(o + at, p + 190, 44); at += 44;
    o[at++] = 0; o[at++] = 0;
    return at;
}
inline int logincharacter(const unsigned char* p, int n, unsigned char* o) {
    if (n != 235) return 0;
    return logincharacter_row(p, o);
}
// NC_BRIEFINFO_CHARACTER_CMD {count u8} + n x LOGINCHARACTER - T.CharacterList2016To2026
inline int characterlist(const unsigned char* p, int n, unsigned char* o) {
    if (n < 1) return 0;
    int k = p[0];
    if (n != 1 + 235 * k || 1 + (304 + g_us_extra) * k > 0x1FF0) return 0;
    o[0] = (unsigned char)k;
    int at = 1;
    for (int i = 0; i < k; i++) at += logincharacter_row(p + 1 + 235 * i, o + at);
    return at;
}

const Owned kOwned[] = {
    { 0x2448, swing, "SWING_DAMAGE" },
    { 0x2449, tail7, "SOMEONESWING_DAMAGE" },
    { 0x243C, tail7, "DOTDAMAGE" },
    { 0x2452, skillhit, "SKILLBASH_HIT_DAMAGE" },
    { 0x2402, targetinfo, "TARGETINFO" },
    { 0x244E, hitstart<6>, "SKILLBASH_HIT_OBJ_START" },
    { 0x2450, hitstart<12>, "SKILLBASH_HIT_FLD_START" },
    { 0x244F, hitstart<8>, "SKILLBASH_SOMEONE_HIT_OBJ_START" },
    { 0x2451, hitstart<14>, "SKILLBASH_SOMEONE_HIT_FLD_START" },
    // batch 4
    { 0x104A, chargedbuff, "CHAR_CLIENT_CHARGEDBUFF" },
    { 0x9003, chargedbuff_start, "CHARGED_BUFFSTART" },
    { 0x9004, chargedbuff_terminate, "CHARGED_BUFFTERMINATE" },
    { 0x3C03, shoptable, "MENU_SHOPOPEN 3C03" },
    { 0x3C04, shoptable, "MENU_SHOPOPEN 3C04" },
    { 0x3C06, shoptable, "MENU_SHOPOPEN 3C06" },
    { 0x3C09, shoptable, "MENU_SHOPOPEN 3C09" },
    { 0x3C0A, shoptable, "MENU_SHOPOPEN 3C0A" },
    { 0x3C0B, shoptable, "MENU_SHOPOPEN 3C0B" },
    { 0x1038, clientbase, "CHAR_CLIENT_BASE" },
    // batch 5
    { 0x1C08, regenmob, "BRIEFINFO_REGENMOB" },
    { 0x1C09, mobcmd, "BRIEFINFO_MOB" },
    { 0x1C1A, regenmover, "BRIEFINFO_REGENMOVER" },
    { 0x1C06, logincharacter, "BRIEFINFO_LOGINCHARACTER" },
    { 0x1C07, characterlist, "BRIEFINFO_CHARACTER" },
};
const int kOwnedCount = sizeof kOwned / sizeof kOwned[0];

inline const Owned* owned(unsigned op) {
    for (int i = 0; i < kOwnedCount; i++) if (kOwned[i].op == op) return &kOwned[i];
    return 0;
}

}  // namespace bridge26
