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
};
const int kOwnedCount = sizeof kOwned / sizeof kOwned[0];

inline const Owned* owned(unsigned op) {
    for (int i = 0; i < kOwnedCount; i++) if (kOwned[i].op == op) return &kOwned[i];
    return 0;
}

}  // namespace bridge26
