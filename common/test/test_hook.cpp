// Does the hook machinery actually work? Runs as a plain 32-bit exe, no Zone.exe needed.
//
// The risky part of a trampoline detour is insn_len(): copy a wrong number of bytes and the relocated
// prologue is garbage, which shows up as a crash somewhere unrelated. So the test detours real functions,
// checks the replacement ran, checks the trampoline still reaches the original behaviour, and checks
// uninstall puts the bytes back.
#include "../src/hook.h"
#include <stdio.h>

static int g_calls = 0;
static int failures = 0;

#define CHECK(cond, what)                                                        \
    do {                                                                         \
        if (cond) { printf("  ok    %s\n", what); }                              \
        else { printf("  FAIL  %s\n", what); failures++; }                       \
    } while (0)

// __thiscall-shaped, like a zone packet handler: the object is in ECX.
struct Target {
    int value;
    int __declspec(noinline) add(int a, int b) {
        g_calls++;
        return value + a + b;
    }
};

typedef int(__fastcall* AddThunk)(void* self, void* edx, int a, int b);
static zone::Detour g_detour;
static int g_intercepted = 0;

static int __fastcall add_replacement(void* self, void* edx, int a, int b) {
    g_intercepted++;
    int original = ((AddThunk)g_detour.trampoline)(self, edx, a, b);
    return original * 10;          // prove we can change the result
}

// a free function too, with a different prologue shape
static int __declspec(noinline) triple(int x) {
    g_calls++;
    return x * 3;
}
typedef int(*TripleFn)(int);
static zone::Detour g_detour2;
static int __cdecl triple_replacement(int x) {
    return ((TripleFn)g_detour2.trampoline)(x) + 1;
}

int main() {
    printf("zonehook self-test\n");

    // -- insn_len on the shapes a prologue is made of
    const unsigned char push_ebp[]   = { 0x55 };
    const unsigned char mov_ebp_esp[]= { 0x8B, 0xEC };
    const unsigned char sub_esp_8[]  = { 0x83, 0xEC, 0x08 };
    const unsigned char mov_eax_ecx8[]={ 0x8B, 0x41, 0x08 };
    const unsigned char push_imm32[] = { 0x68, 0x44, 0x33, 0x22, 0x11 };
    const unsigned char mov_dw_imm[] = { 0xC7, 0x45, 0xFC, 0, 0, 0, 0 };
    CHECK(zone::insn_len(push_ebp) == 1,    "insn_len push ebp = 1");
    CHECK(zone::insn_len(mov_ebp_esp) == 2, "insn_len mov ebp,esp = 2");
    CHECK(zone::insn_len(sub_esp_8) == 3,   "insn_len sub esp,8 = 3");
    CHECK(zone::insn_len(mov_eax_ecx8) == 3,"insn_len mov eax,[ecx+8] = 3");
    CHECK(zone::insn_len(push_imm32) == 5,  "insn_len push imm32 = 5");
    CHECK(zone::insn_len(mov_dw_imm) == 7,  "insn_len mov [ebp-4],imm32 = 7");
    const unsigned char nonsense[] = { 0x0F, 0x0B };
    CHECK(zone::insn_len(nonsense) == 0,    "insn_len refuses what it does not know");

    // -- a __thiscall method, the packet-handler shape
    Target t; t.value = 100;
    int before = t.add(1, 2);
    CHECK(before == 103, "uninstrumented method returns 103");

    // MSVC will not cast a pointer-to-member to void* directly; the union is the standard way to get at
    // the code address, and it is exactly what a member function pointer holds for a non-virtual method.
    union { int (__thiscall Target::*pm)(int, int); void* p; } cvt;
    cvt.pm = &Target::add;
    void* target = cvt.p;
    bool ok = zone::detour(target, (void*)add_replacement, &g_detour);
    CHECK(ok, "detour installed on a __thiscall method");
    if (ok) {
        g_calls = 0;
        int after = t.add(1, 2);
        CHECK(g_intercepted == 1, "replacement ran");
        CHECK(g_calls == 1, "trampoline reached the original body");
        CHECK(after == 1030, "replacement could change the result (103 * 10)");
        CHECK(zone::undetour(&g_detour), "undetour restored the bytes");
        g_intercepted = 0;
        int restored = t.add(1, 2);
        CHECK(restored == 103 && g_intercepted == 0, "original behaviour is back");
    }

    // -- a plain __cdecl function
    const unsigned char* tb = (const unsigned char*)(void*)triple;
    printf("  ..    triple starts: %02X %02X %02X %02X %02X %02X  (insn_len %u)\n",
           tb[0], tb[1], tb[2], tb[3], tb[4], tb[5], (unsigned)zone::insn_len(tb));
    bool ok2 = zone::detour((void*)triple, (void*)triple_replacement, &g_detour2);
    CHECK(ok2, "detour installed on a __cdecl function");
    if (ok2) {
        CHECK(triple(5) == 16, "trampoline + replacement composed (5*3 + 1)");
        CHECK(zone::undetour(&g_detour2), "undetour restored the bytes");
        CHECK(triple(5) == 15, "original behaviour is back");
    }

    // -- vtable swap
    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
