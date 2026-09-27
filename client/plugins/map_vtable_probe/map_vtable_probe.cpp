// map_vtable_probe - DIAGNOSTIC: which FullMapWin virtual runs when the operator clicks the full map's quest legend
// (2026 client). map_command_probe hooked the slot-97 function (0x60F8B0, a 12-way command switch shaped like 2016's
// FullMapWin::OnCommand) and logged NOTHING while the operator opened the map and clicked legend rows, 2026-09-27.
//
// Every slot of the 2026 FullMapWin vtable (0xB20334) gets a thunk: it logs "slot N (args a1 a2)" - the first 3 calls of
// that slot, then every 2^k-th, so per-frame slots stay quiet - and jumps to the original. The vtable is shared by every
// FullMapWin, so the probe also sees calls made through base-class pointers. Remove once the click route is known.
#include <hook_core.h>

#include <windows.h>

namespace {

const unsigned kVaVtable = 0x00B20334u;   // FullMapWin::`vftable' (RTTI COL 0xBBDC60)
const int kSlots = 160;

volatile LONG g_count[kSlots];
void* g_orig[kSlots];

extern "C" void __stdcall probe_log(int slot, unsigned* esp) {
    LONG n = InterlockedIncrement(&g_count[slot]);
    if (n <= 3 || (n & (n - 1)) == 0)      // 1, 2, 3, 4, 8, 16, ...
        hook::log("FullMapWin slot %d call #%ld  this %p  args %08X %08X %08X", slot, n, (void*)esp[-1], esp[1], esp[2], esp[3]);
}

// thunk per slot:  push ecx; pushad; pushfd; lea eax,[esp+0x28]; push eax; push slot; call probe_log; popfd; popad;
//                  pop ecx; jmp [g_orig+4*slot]      (esp[-1] as seen by probe_log = the saved ecx = this)
unsigned char* make_thunk(int slot) {
    unsigned char* p = (unsigned char*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!p) return nullptr;
    unsigned char* q = p;
    *q++ = 0x51;                                           // push ecx
    *q++ = 0x60;                                           // pushad
    *q++ = 0x9C;                                           // pushfd
    *q++ = 0x8D; *q++ = 0x44; *q++ = 0x24; *q++ = 0x28;    // lea eax, [esp+0x28] -> the return address slot
    *q++ = 0x50;                                           // push eax
    *q++ = 0x68; *(int*)q = slot; q += 4;                  // push slot
    *q++ = 0xE8; *(int*)q = (int)((unsigned char*)&probe_log - (q + 4)); q += 4;   // call probe_log (stdcall, pops 8)
    *q++ = 0x9D;                                           // popfd
    *q++ = 0x61;                                           // popad
    *q++ = 0x59;                                           // pop ecx
    *q++ = 0xFF; *q++ = 0x25; *(void***)q = &g_orig[slot]; q += 4;                 // jmp [g_orig + 4*slot]
    return p;
}

}  // namespace

HOOK_PLUGIN("map_vtable_probe") {
    void** vt = (void**)hook::rebase(kVaVtable);
    int n = 0;
    for (int i = 0; i < kSlots; ++i) {
        void* f = vt[i];
        // stop at the end of the table: an entry that is not a code address in the image
        if ((unsigned)f < (unsigned)hook::rebase(0x00401000u) || (unsigned)f > (unsigned)hook::rebase(0x00B00000u)) break;
        g_orig[i] = f;
        unsigned char* t = make_thunk(i);
        if (!t) break;
        hook::vtable_set(vt, i, t);
        ++n;
    }
    hook::log("FullMapWin vtable %p: %d slots instrumented", (void*)vt, n);
}
