// zonehook runs WITHOUT the C runtime, on purpose.
//
// Measured 2026-09-19: a DLL that pulls in the static CRT (/MT) and is loaded as a STATIC IMPORT of
// Zone.exe overflows the main thread's stack during CRT start-up under Wine, before DllMain is reached -
// "virtual_setup_exception stack overflow 824 bytes". Two probe DLLs settled it: one with no CRT wrote its
// file and the zone carried on exactly as the stock exe does; the same DLL plus a single _snprintf_s call
// died and wrote nothing. The zone's own start-up has very little stack to spare at that moment, and the
// CRT's initialisation wants more than is there.
//
// So: no CRT. The entry point is DllMain itself (/ENTRY), nothing links msvcrt, and the handful of things
// the CRT would have provided come from Win32 or from here. This also makes the DLL tiny and free of any
// redistributable, which is what you want in something a server loads.
#pragma once
#include <windows.h>

namespace zh {

inline void* mem_copy(void* dst, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    while (n--) *d++ = *s++;
    return dst;
}

inline void* mem_set(void* dst, int v, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    while (n--) *d++ = (unsigned char)v;
    return dst;
}

inline size_t str_len(const char* s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

inline int str_cmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

inline void str_copy(char* dst, size_t cap, const char* src) {
    size_t i = 0;
    for (; src[i] && i + 1 < cap; i++) dst[i] = src[i];
    if (cap) dst[i] = 0;
}

// wvsprintfA is USER32, not the CRT. It understands %s %d %u %x %c %% and width/precision, which is all
// the logging here needs. It does NOT do %p or floating point - use %x for pointers.
inline int format(char* buf, size_t cap, const char* fmt, va_list ap) {
    (void)cap;                       // wvsprintfA has a hard 1024-byte limit of its own
    return wvsprintfA(buf, fmt, ap);
}

}  // namespace zh

// The compiler emits calls to these on its own for struct copies and zeroing, so they must exist as real
// symbols. Defined in nocrt.cpp - they cannot be inline.
extern "C" {
void* memcpy(void* dst, const void* src, size_t n);
void* memset(void* dst, int v, size_t n);
}
