// Real definitions for the two functions the compiler emits calls to on its own (struct copies, zeroing).
// They cannot be inline: the code generator references them by name, so they must exist as symbols.
//
// The LOADER is built with no C runtime at all. That is a choice rather than a necessity - measured
// 2026-09-19, a STATIC CRT (/MT) in a DLL statically imported by Zone.exe overflows the main thread's
// stack during its start-up, before DllMain is reached, while the DYNAMIC CRT (/MD) was verified working
// in exactly that position. Staying CRT-free leaves the loader with no redistributable dependency, which
// is what you want in something a server loads on every start. Plugins in hooks/ are under no such
// restriction: they are loaded later, from the service thread, and may use the full CRT.
#include "../include/hook_core.h"

extern "C" {

#pragma function(memcpy, memset)

void* memcpy(void* dst, const void* src, size_t n) { return hook::detail::mem_copy(dst, src, n); }
void* memset(void* dst, int v, size_t n) { return hook::detail::mem_set(dst, v, n); }

}  // extern "C"
