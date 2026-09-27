// msg_probe - DIAGNOSTIC: logs every PgWin::PostMsg(target, msg, wParam, lParam) of the 2026 client with the RTTI class
// of the sender and the target, to find where a click on the full map's quest legend goes (the FullMapWin vtable probe
// saw no virtual of FullMapWin run on those clicks, 2026-09-27). Remove once the route is known.
//
// 2026 PgWin::PostMsg = 0x877A40 (2016 0x8B2640, same body): thiscall(this = sender, PgWin* target, unsigned msg,
// unsigned wParam, long lParam), queues the message with the window manager (0xD1B810).
#include <hook_core.h>

#include <windows.h>

namespace {

const unsigned kVaPostMsg = 0x00877A40u;
hook::Detour g_post;
volatile LONG g_n;

// MSVC RTTI: vtable[-1] = CompleteObjectLocator; COL+0xC = TypeDescriptor*; TypeDescriptor+8 = ".?AVName@@"
const char* class_of(void* obj) {
    __try {
        if (!obj) return "null";
        void** vt = *(void***)obj;
        char* col = (char*)vt[-1];
        char* td = *(char**)(col + 0xC);
        return td + 8;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return "?";
    }
}

bool __fastcall post(void* self, void*, void* target, unsigned msg, unsigned wparam, long lparam) {
    if (InterlockedIncrement(&g_n) < 5000)
        hook::log("PostMsg %s %p -> %s %p  msg %u wParam %u lParam %ld", class_of(self), self, class_of(target), target, msg,
                  wparam, lparam);
    return ((bool(__fastcall*)(void*, void*, void*, unsigned, unsigned, long))g_post.trampoline)(self, 0, target, msg, wparam,
                                                                                              lparam);
}

}  // namespace

HOOK_PLUGIN("msg_probe") {
    hook::hook_function("PgWin::PostMsg 0x877A40 (log posted window messages)", hook::rebase(kVaPostMsg), (void*)post, &g_post);
}
