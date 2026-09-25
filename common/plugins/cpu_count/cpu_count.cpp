// cpu_count - the CPU count a server exe sizes its thread pools by, from the environment (Fiesta2026on2016 Q53).
//
// Operator 2026-09-25: the number of DB bridges' / servers' worker threads "as an argument". Every Fiesta server exe
// sizes its pools from GetSystemInfo().dwNumberOfProcessors - Account.exe (DataServer::OnStart_Service 0x401F3E):
// CIOCP::Start(5 x CPUs) IOCP workers, CSessionWorkerManager::Start(-1) -> a CPU-derived DB session-worker count
// capped at 81 (0x4068FE); the zone and the other servers use the same CIOCP / session-worker library. On a 16-core
// box that is ~80 + ~80 threads per DB server, mostly asleep.
//
// With FIESTA_CPUS=<n> (1..64) in the process environment, this plugin answers the exe's GetSystemInfo import with
// dwNumberOfProcessors = n (everything else as the real call returns it). Unset or invalid = the exe runs exactly
// as before. Built once (target "common"); deploy the DLL into the hooks\ folder of any exe that carries the loader
// (zone, Character, Account, AccountLog, GameLog, Login - recipes dll-loader*). The loader runs plugins before
// ServiceMain, i.e. before the pools are created.
#include <hook_core.h>

#include <cstdlib>
#include <cstring>

namespace {

typedef void(WINAPI* GetSystemInfoFn)(LPSYSTEM_INFO);
GetSystemInfoFn g_real = nullptr;
DWORD g_cpus = 0;

void WINAPI fake_GetSystemInfo(LPSYSTEM_INFO info) {
    g_real(info);
    if (info && g_cpus) info->dwNumberOfProcessors = g_cpus;
}

// Under Wine the exe runs as a service started by services.exe, which gives it a fresh WINDOWS environment - the
// container's variables are not in it (seen 2026-09-25: FIESTA_CPUS missing from GetEnvironmentVariable) but they
// ARE in the process's Unix environment, readable through Wine's Z: = / as /proc/self/environ (NUL-separated).
bool unix_env(const char* name, char* out, size_t cap) {
    HANDLE f = CreateFileA("Z:\\proc\\self\\environ", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return false;
    static char buf[65536];
    DWORD got = 0;
    BOOL ok = ReadFile(f, buf, sizeof buf - 1, &got, NULL);
    CloseHandle(f);
    if (!ok) return false;
    buf[got] = 0;
    size_t n = std::strlen(name);
    for (DWORD i = 0; i < got; i += (DWORD)std::strlen(buf + i) + 1) {
        if (std::strncmp(buf + i, name, n) == 0 && buf[i + n] == '=') {
            strncpy_s(out, cap, buf + i + n + 1, _TRUNCATE);
            return true;
        }
    }
    return false;
}

}  // namespace

HOOK_PLUGIN("cpu_count") {
    char buf[16];
    DWORD n = GetEnvironmentVariableA("FIESTA_CPUS", buf, sizeof buf);
    if ((!n || n >= sizeof buf) && unix_env("FIESTA_CPUS", buf, sizeof buf)) n = (DWORD)std::strlen(buf);
    if (!n || n >= sizeof buf) {
        hook::log("cpu_count: FIESTA_CPUS not set - the exe sizes its thread pools from the real CPU count");
        return;
    }
    long v = std::strtol(buf, nullptr, 10);
    if (v < 1 || v > 64) {
        hook::log("cpu_count: FIESTA_CPUS=%s out of range (1..64) - ignored", buf);
        return;
    }
    g_cpus = (DWORD)v;
    g_real = (GetSystemInfoFn)hook::iat_hook(NULL, "kernel32.dll", "GetSystemInfo", (void*)fake_GetSystemInfo);
    if (!g_real) {
        hook::log("cpu_count: this exe does not import kernel32!GetSystemInfo - nothing to do");
        g_cpus = 0;
        return;
    }
    hook::log("cpu_count: GetSystemInfo reports %u CPUs (FIESTA_CPUS) - thread pools sized from that", g_cpus);
}
