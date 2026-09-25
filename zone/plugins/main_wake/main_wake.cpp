// main_wake - the zone's idle main loop waits for network data instead of polling Sleep(1).
//
// ---- what the sleep gates (read from Zone.exe, 2026-09-25) ------------------------------------------------------
//
//   ZoneServer::zs_mainthreadfunction 0x5ACA30 is the ONE thread that parses and handles every packet: player
//   sessions and the server links (WM, the DB bridges) alike - zs_PacketProcess / SocketBundle::sb_Routine run
//   there. The IOCP worker threads only move bytes: IOCPProcessSession::IOCP_Process 0x5A6820, on a receive
//   completion, adds the byte count to the session buffer (+0xF4) and re-arms CSocket_IOCP::Receive - nothing else.
//   So a packet that arrives while the main loop sleeps waits for the sleep to end.
//
//   The loop's pacing is SleepManager::sm_Routine 0x5AA610: with no work it calls sm_Sleep 0x5AA5B0 - Sleep(1) -
//   every other pass. The zone never raises the timer resolution, so on Windows that Sleep(1) lasts a 15.625 ms
//   tick (up to ~15.6 ms added to every packet on an idle zone, ~64 idle passes/s); Wine sleeps the exact
//   millisecond (~2,000 full main-loop passes/s over every map = the idle CPU burn, ticket STACK IDLE CPU SPIN).
//
// ---- what this plugin does ---------------------------------------------------------------------------------------
//
//   sm_Sleep waits on an auto-reset event for at most kIdleMs instead of Sleep(1), and the IOCP completion handler
//   sets that event whenever bytes arrive (after the stock handler has queued them). Idle: ~64 passes/s, as on
//   Windows. Data arriving: the loop wakes at once - lower latency than Windows. Busy periods are untouched:
//   sm_Routine only calls sm_Sleep when its load ratio allows (the skip counter logic stays the zone's).
#include <zonehook.h>
#include <zone_functions.h>

#include <windows.h>

namespace {

const DWORD kIdleMs = 15;                          // Windows' default tick (15.625 ms), rounded down
const unsigned kVaIocpProcess = 0x005A6820u;       // IOCPProcessSession::IOCP_Process (virtual, not in the header)
const unsigned kSleepManagerSkip = 4;              // SleepManager +4: the skip counter sm_Sleep resets

HANDLE g_wake;
zone::Detour g_sleep, g_iocp;

void __fastcall sleep_impl(void* self, void*) {
    WaitForSingleObject(g_wake, kIdleMs);
    *(int*)((char*)self + kSleepManagerSkip) = 0;  // what the stock sm_Sleep does after its Sleep(1)
}

int __fastcall iocp_impl(void* self, void*, void* overlapped, unsigned long bytes) {
    typedef int(__fastcall * Orig)(void*, void*, void*, unsigned long);
    int r = ((Orig)g_iocp.trampoline)(self, 0, overlapped, bytes);
    if (bytes) SetEvent(g_wake);                   // a receive (or a send) completed: let the main loop look now
    return r;
}

void __declspec(naked) sleep_thunk() { __asm { jmp sleep_impl } }
void __declspec(naked) iocp_thunk() { __asm { jmp iocp_impl } }

}  // namespace

ZONEHOOK_PLUGIN("main_wake") {
    g_wake = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!g_wake) {
        zone::log("main_wake: CreateEvent failed (%u) - the zone keeps its stock Sleep(1)", GetLastError());
        return;
    }
    zone::hook_function("SleepManager::sm_Sleep (idle wait -> network event, max 15 ms)",
                        (void*)zone::fn::SleepManager__sm_Sleep(), (void*)sleep_thunk, &g_sleep);
    zone::hook_function("IOCPProcessSession::IOCP_Process (bytes arrived -> wake the main loop)",
                        (void*)zone::rebase(kVaIocpProcess), (void*)iocp_thunk, &g_iocp);
}
