// Does the hook machinery actually work? Runs as a plain 32-bit exe, no Zone.exe needed.
// Build + run: common	estuild.bat  (the same 32-bit toolchain as the loader).
//
// The risky part of a trampoline detour is insn_len(): copy a wrong number of bytes and the relocated
// prologue is garbage, which shows up as a crash somewhere unrelated. So the test detours real functions,
// checks the replacement ran, checks the trampoline still reaches the original behaviour, and checks
// uninstall puts the bytes back.
#include <hook_core.h>
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
static hook::Detour g_detour;
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
static hook::Detour g_detour2;
static int __cdecl triple_replacement(int x) {
    return ((TripleFn)g_detour2.trampoline)(x) + 1;
}

// protocol-table fixtures: handlers with the zone's __thiscall shape (cmd, len, a3), written as the equivalent __fastcall
static unsigned g_proto_seen, g_proto_original, g_proto_len, g_proto_new, g_proto_unknown;
static hook::u32 __fastcall proto_swing(void*, void*, hook::u32, hook::u32 len, hook::u32) {
    g_proto_original++;
    g_proto_len = len;
    return 0;
}
static hook::u32 __fastcall proto_unknown(void*, void*, hook::u32, hook::u32, hook::u32) { g_proto_unknown++; return 0; }
static void proto_on_dept(hook::proto::Call& c) {
    g_proto_seen = c.op;
    c.args[1] = 3;                 // a translator would point args[0] at a new buffer and set its length here
    c.original();
}
static void proto_on_new(hook::proto::Call&) { g_proto_new++; }   // a NEW opcode: never call the unknown handler
// what ClientSession::zbs_Parsing does: handler = rows[op & 0x3FF][op >> 10]; handler(ecx=player, cmd, len, a3)
static hook::u32 proto_dispatch(void* table, unsigned char* cmd, int len) {
    unsigned op = cmd[0] | (cmd[1] << 8);
    typedef hook::u32(__fastcall * H)(void*, void*, hook::u32, hook::u32, hook::u32);
    return ((H)hook::proto::get(table, op))((void*)0x1234, NULL, (hook::u32)cmd, (hook::u32)len, 0);
}
static unsigned g_proto_covered;
static hook::u32 __fastcall proto_cover(void*, void*, hook::u32, hook::u32, hook::u32) { g_proto_covered++; return 1; }

int main() {
    printf("zonehook self-test\n");

    // -- insn_len on the shapes a prologue is made of
    const unsigned char push_ebp[]   = { 0x55 };
    const unsigned char mov_ebp_esp[]= { 0x8B, 0xEC };
    const unsigned char sub_esp_8[]  = { 0x83, 0xEC, 0x08 };
    const unsigned char mov_eax_ecx8[]={ 0x8B, 0x41, 0x08 };
    const unsigned char push_imm32[] = { 0x68, 0x44, 0x33, 0x22, 0x11 };
    const unsigned char mov_dw_imm[] = { 0xC7, 0x45, 0xFC, 0, 0, 0, 0 };
    CHECK(hook::insn_len(push_ebp) == 1,    "insn_len push ebp = 1");
    CHECK(hook::insn_len(mov_ebp_esp) == 2, "insn_len mov ebp,esp = 2");
    CHECK(hook::insn_len(sub_esp_8) == 3,   "insn_len sub esp,8 = 3");
    CHECK(hook::insn_len(mov_eax_ecx8) == 3,"insn_len mov eax,[ecx+8] = 3");
    CHECK(hook::insn_len(push_imm32) == 5,  "insn_len push imm32 = 5");
    CHECK(hook::insn_len(mov_dw_imm) == 7,  "insn_len mov [ebp-4],imm32 = 7");
    const unsigned char nonsense[] = { 0x0F, 0x0B };
    CHECK(hook::insn_len(nonsense) == 0,    "insn_len refuses what it does not know");

    // -- a __thiscall method, the packet-handler shape
    Target t; t.value = 100;
    int before = t.add(1, 2);
    CHECK(before == 103, "uninstrumented method returns 103");

    // MSVC will not cast a pointer-to-member to void* directly; the union is the standard way to get at
    // the code address, and it is exactly what a member function pointer holds for a non-virtual method.
    union { int (__thiscall Target::*pm)(int, int); void* p; } cvt;
    cvt.pm = &Target::add;
    void* target = cvt.p;
    bool ok = hook::detour(target, (void*)add_replacement, &g_detour);
    CHECK(ok, "detour installed on a __thiscall method");
    if (ok) {
        g_calls = 0;
        int after = t.add(1, 2);
        CHECK(g_intercepted == 1, "replacement ran");
        CHECK(g_calls == 1, "trampoline reached the original body");
        CHECK(after == 1030, "replacement could change the result (103 * 10)");
        CHECK(hook::undetour(&g_detour), "undetour restored the bytes");
        g_intercepted = 0;
        int restored = t.add(1, 2);
        CHECK(restored == 103 && g_intercepted == 0, "original behaviour is back");
    }

    // -- a plain __cdecl function
    const unsigned char* tb = (const unsigned char*)(void*)triple;
    printf("  ..    triple starts: %02X %02X %02X %02X %02X %02X  (insn_len %u)\n",
           tb[0], tb[1], tb[2], tb[3], tb[4], tb[5], (unsigned)hook::insn_len(tb));
    bool ok2 = hook::detour((void*)triple, (void*)triple_replacement, &g_detour2);
    CHECK(ok2, "detour installed on a __cdecl function");
    if (ok2) {
        CHECK(triple(5) == 16, "trampoline + replacement composed (5*3 + 1)");
        CHECK(hook::undetour(&g_detour2), "undetour restored the bytes");
        CHECK(triple(5) == 15, "original behaviour is back");
    }

    // -- vtable swap: the mechanism quest_gate and void_bag use on ShinePlayer
    void* fake_vt[3] = { (void*)0x1111, (void*)triple, (void*)0x3333 };
    void* prev = hook::vtable_set(fake_vt, 1, (void*)triple_replacement);
    CHECK(prev == (void*)triple && fake_vt[1] == (void*)triple_replacement, "vtable_set swaps one slot and returns the old entry");
    CHECK(fake_vt[0] == (void*)0x1111 && fake_vt[2] == (void*)0x3333, "vtable_set leaves the neighbours alone");

    // -- protocol tables: the layout Zone / Login / WM dispatch through (hook::proto)
    {
        struct FakeTable { void* vt; void** rows[1024]; void* def[64]; void* unknown; };
        static FakeTable t;
        t.unknown = (void*)proto_unknown;
        for (int i = 0; i < 64; i++) t.def[i] = t.unknown;
        for (int i = 0; i < 1024; i++) t.rows[i] = t.def;
        // the server's registration: dept 9 cmd 0x48 (0x2448) gets its own row
        static void* row48[64];
        for (int i = 0; i < 64; i++) row48[i] = t.unknown;
        row48[9] = (void*)proto_swing;
        t.rows[0x48] = row48;

        CHECK(hook::proto::get(&t, 0x2448) == (void*)proto_swing, "proto::get = rows[cmd][dept]");
        CHECK(!hook::proto::is_registered(&t, 0x2449), "an unregistered opcode reads as the unknown handler");
        CHECK(hook::proto::for_each_in_department(&t, 9, [](unsigned, void*) {}) == 1, "for_each_in_department finds the one handler");

        unsigned char pkt[4] = { 0x48, 0x24, 7, 0 };
        g_proto_seen = 0;
        CHECK(hook::proto::hook_department<0>(&t, 9, proto_on_dept, hook::proto::kPacketArg1) == 1, "hook_department hooks it");
        CHECK(proto_dispatch(&t, pkt, 4) == 0, "the slot returns what the original returned (the WM closes on 0)");
        CHECK(g_proto_seen == 0x2448 && g_proto_original == 1, "department callback saw 0x2448 and ran the original");
        CHECK(g_proto_len == 3, "the callback rewrote the length the original got");

        unsigned char newpkt[2] = { 0x50, 0x24 };    // 0x2450: nothing registered, cmd 0x50 still on the default row
        CHECK(t.rows[0x50] == t.def, "cmd 0x50 starts on the shared default row");
        CHECK(hook::proto::hook_opcode<1>(&t, 0x2450, proto_on_new, hook::proto::kPacketArg1), "hook_opcode registers a new opcode");
        CHECK(t.rows[0x50] != t.def && t.def[9] == t.unknown, "it got its own row; the shared default row is untouched");
        CHECK(t.rows[0x51] == t.def, "a neighbouring command still shares the default row");
        g_proto_new = 0;
        CHECK(proto_dispatch(&t, newpkt, 2) == 1, "a callback that swallows the packet returns 1 (handled)");
        CHECK(g_proto_new == 1 && g_proto_unknown == 0, "the new opcode reached its callback, not the unknown handler");

        hook::uninstall_all();
        CHECK(hook::proto::get(&t, 0x2448) == (void*)proto_swing && hook::proto::get(&t, 0x2450) == t.unknown,
              "uninstall_all restored both slots");

        // cover_unregistered: every unknown entry -> the cover handler, registered ones untouched
        int covered = hook::proto::cover_unregistered(&t, (void*)proto_cover);
        CHECK(covered == 64 + 63 + 64, "covers the default row (64), cmd 0x48's unregistered depts (63) and cmd 0x50's own row (64, left by hook_opcode)");
        CHECK(hook::proto::get(&t, 0x2448) == (void*)proto_swing, "a registered handler is left alone");
        g_proto_covered = 0; g_proto_unknown = 0;
        unsigned char stray[2] = { 0x77, 0x31 };     // 0x3177: nothing registered anywhere
        CHECK(proto_dispatch(&t, stray, 2) == 1 && g_proto_covered == 1 && g_proto_unknown == 0,
              "an unregistered opcode reaches the cover handler, never the unknown one");
    }

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
