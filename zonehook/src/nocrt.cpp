// Real definitions for the two functions the compiler emits calls to on its own (struct copies, zeroing).
// They cannot be inline: the code generator references them by name, so they must exist as symbols.
// See nocrt.h for why there is no C runtime at all.
#include "nocrt.h"

extern "C" {

#pragma function(memcpy, memset)

void* memcpy(void* dst, const void* src, size_t n) { return zh::mem_copy(dst, src, n); }
void* memset(void* dst, int v, size_t n) { return zh::mem_set(dst, v, n); }

}  // extern "C"
