// login_address - the login server's address from hooks\login_address.ini instead of only the -i / -p command line
// (Fiesta2026on2016, operator 2026-11-07: "allow the URL to be changed via e.g. ini file ... login server ip port
// (currently passed with -i and -p)").
//
// ---- what the stock client does (10.6.6) --------------------------------------------------------------------------------
// The game frame's start-up calls the command-line parser (CmdLineParseCall -> 0x538AE0): "-i <ip>" copies the string into
// LoginIp (char[16], strncpy 16) and LoginIpCopy, "-p <port>" puts atoi() into LoginPort. Nothing reads the login address
// from a file (Fiesta.ini holds only "Original" / "SpawnApps"; ItemMall.ini is a data file).
// The item shop's purchase connection needs no hook: PurchaseNetFrameWork connects to the WM's address from the
// world-select answer (LoginWorldNetFrameWork 0x5583DB -> [0xC3253C] / [0xC3254C]) - its server lives in the WM.
// ---- this plugin ---------------------------------------------------------------------------------------------------------
// The loader loads plugins at the client's first CreateWindowExA - AFTER the parser ran (tested 2026-11-07: a stub on the
// parser call never fired), so [login] ip= / port= from hooks\login_address.ini (when set) overwrite the three globals at
// load; the parser call also goes through a stub that re-applies them, should a build parse later. No .ini, or empty keys
// = the command line's values (stock).
#include <hook_core.h>
#include <client_addrs.h>

#include <windows.h>

#include <cstring>

namespace {

unsigned g_parser = 0;
char* g_ip = nullptr;
char* g_ip_copy = nullptr;
int* g_port = nullptr;

void apply_ini() {
    char ip[64] = {0};
    hook::config_str("ip", "", ip, sizeof ip, "login");
    int port = hook::config_int("port", 0, "login");
    if (ip[0]) {
        std::memset(g_ip, 0, 16);
        strncpy_s(g_ip, 16, ip, _TRUNCATE);
        strcpy_s(g_ip_copy, 16, g_ip);
    }
    if (port > 0 && port < 65536) *g_port = port;
    hook::log("login_address: login server %s:%d (%s)", g_ip, *g_port, ip[0] || port ? "from login_address.ini" : "the command line");
}

void __declspec(naked) parse_then_override() {
    __asm {
        call dword ptr [g_parser]
        pushad
        call apply_ini
        popad
        ret
    }
}

}  // namespace

HOOK_PLUGIN("login_address") {
    if (const char* m = caddr::missing({caddr::kCmdLineParseCall, caddr::kLoginIp, caddr::kLoginIpCopy, caddr::kLoginPort})) {
        hook::log("login_address: %s - not hooked", m);
        return;
    }
    unsigned char* site = (unsigned char*)hook::rebase(caddr::va(caddr::kCmdLineParseCall));
    if (site[0] != 0xE8) {
        hook::log("login_address: the command-line parser call is not a call - not hooked");
        return;
    }
    g_parser = (unsigned)(site + 5 + *(int*)(site + 1));
    g_ip = (char*)hook::rebase(caddr::va(caddr::kLoginIp));
    g_ip_copy = (char*)hook::rebase(caddr::va(caddr::kLoginIpCopy));
    g_port = (int*)hook::rebase(caddr::va(caddr::kLoginPort));
    unsigned char call[5] = {0xE8, 0, 0, 0, 0};
    *(int*)(call + 1) = (int)((unsigned char*)parse_then_override - (site + 5));
    if (hook::write_code(site, call, sizeof call))
        hook::log("login_address: the command-line parser now ends with hooks\\login_address.ini [login] ip / port");
    apply_ini();          // the parser already ran (the plugin loads at the first window)
}
