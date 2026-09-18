#include "hook.h"
#include <stdio.h>
#include <stdarg.h>

namespace zone {

// ---- logging --------------------------------------------------------------------------------------

static HANDLE g_log = INVALID_HANDLE_VALUE;

void log_init(const wchar_t* filename) {
    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(GetModuleHandleW(NULL), path, MAX_PATH);
    if (!n || n == MAX_PATH) return;
    wchar_t* slash = wcsrchr(path, L'\\');
    if (slash) *(slash + 1) = 0;
    wcsncat_s(path, MAX_PATH, filename, _TRUNCATE);
    g_log = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

void log(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = _vsnprintf_s(buf, sizeof(buf) - 2, _TRUNCATE, fmt, ap);
    va_end(ap);
    if (n < 0) n = (int)strlen(buf);
    buf[n] = '\n';
    buf[n + 1] = 0;
    OutputDebugStringA(buf);
    if (g_log != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(g_log, buf, (DWORD)(n + 1), &written, NULL);
        FlushFileBuffers(g_log);
    }
}

// ---- instruction length ---------------------------------------------------------------------------
//
// Deliberately partial. It handles the prologue shapes MSVC emits for __thiscall members in this build -
// push reg / mov reg,reg / sub esp,imm / mov reg,[reg+disp] / push imm / lea / test / cmp / the 0x8B-0x8D
// group - and returns 0 for anything it does not recognise, which makes detour() refuse rather than
// truncate an instruction it half-understood.
size_t insn_len(const uint8_t* p) {
    size_t i = 0;
    // prefixes we might plausibly meet at a function head
    while (p[i] == 0x66 || p[i] == 0x67 || p[i] == 0xF2 || p[i] == 0xF3) i++;
    const bool opsize = (p[i - 1] == 0x66) && i > 0;
    const uint8_t op = p[i];

    // one-byte, no operand
    if ((op >= 0x50 && op <= 0x5F) ||        // push/pop reg
        op == 0x90 || op == 0xC3 || op == 0xC9 || op == 0xCC) return i + 1;
    if (op == 0xC2) return i + 3;            // ret imm16
    if (op == 0x68) return i + 5;            // push imm32
    if (op == 0x6A) return i + 2;            // push imm8
    // mov eax,[moffs32] and friends (A0-A3). MSVC emits A1 right after the frame set-up whenever the
    // function reads a global, which is most of them - found by test_hook, where `triple` began
    // 55 8B EC A1 ... and the decoder refused (correctly) rather than cutting the A1 in half.
    if (op >= 0xA0 && op <= 0xA3) return i + 1 + 4;
    if (op >= 0xB8 && op <= 0xBF) return i + 1 + (opsize ? 2 : 4);   // mov r32, imm32
    if (op >= 0xB0 && op <= 0xB7) return i + 2;                      // mov r8, imm8
    if (op == 0xE8 || op == 0xE9) return i + 5;   // call/jmp rel32  (relocated by detour())
    if (op == 0xEB) return i + 2;                 // jmp rel8

    // modrm group: 00-3F arithmetic, 84/85 test, 88-8B mov, 8D lea, 31/33 xor ...
    const bool has_modrm =
        (op <= 0x3F && (op & 7) <= 3) || op == 0x84 || op == 0x85 || op == 0x63 ||
        (op >= 0x88 && op <= 0x8B) || op == 0x8D || op == 0x8F ||
        op == 0xC6 || op == 0xC7 || op == 0xF6 || op == 0xF7 || op == 0xFF ||
        (op >= 0x80 && op <= 0x83);
    if (!has_modrm) return 0;

    size_t j = i + 1;
    const uint8_t modrm = p[j++];
    const uint8_t mod = modrm >> 6, rm = modrm & 7;
    if (mod != 3 && rm == 4) j++;                       // SIB
    if (mod == 1) j += 1;                               // disp8
    else if (mod == 2) j += 4;                          // disp32
    else if (mod == 0 && rm == 5) j += 4;               // disp32 (no base)
    if (op == 0xC6 || op == 0x80 || (op >= 0x81 && op <= 0x83 && op != 0x82)) {
        j += (op == 0xC6 || op == 0x80 || op == 0x83) ? 1 : (opsize ? 2 : 4);
    } else if (op == 0xC7) {
        j += opsize ? 2 : 4;
    } else if (op == 0xF6) {
        if (((modrm >> 3) & 7) <= 1) j += 1;            // test r/m8, imm8
    } else if (op == 0xF7) {
        if (((modrm >> 3) & 7) <= 1) j += opsize ? 2 : 4;
    }
    return j;
}

// ---- detour ---------------------------------------------------------------------------------------

static const size_t kJmpLen = 5;

static uint8_t* alloc_near(size_t n) {
    // A trampoline reached by a rel32 JMP has to be within +-2GB; on 32-bit everything is, so a plain
    // executable allocation is enough. Kept separate so the 64-bit port has one place to change.
    return (uint8_t*)VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

bool detour(void* target, void* replacement, Detour* out) {
    if (!target || !replacement || !out) return false;
    memset(out, 0, sizeof(*out));
    uint8_t* t = (uint8_t*)target;

    size_t len = 0;
    while (len < kJmpLen) {
        size_t n = insn_len(t + len);
        if (!n || len + n > sizeof(out->saved)) {
            log("[hook] REFUSED %p: cannot decode the prologue at +%u (byte %02X)", target,
                (unsigned)len, t[len]);
            return false;
        }
        len += n;
    }

    uint8_t* tramp = alloc_near(len + kJmpLen);
    if (!tramp) { log("[hook] REFUSED %p: no memory for a trampoline", target); return false; }

    // the displaced bytes, then a jump back to the rest of the function
    memcpy(tramp, t, len);
    // a displaced rel32 call/jmp would point at the wrong place from its new home: fix the one case that
    // can appear this early, and refuse the rest rather than relocate blind
    for (size_t k = 0; k < len; ) {
        size_t n = insn_len(t + k);
        if ((t[k] == 0xE8 || t[k] == 0xE9) && n == 5) {
            int32_t rel = *(int32_t*)(t + k + 1);
            int32_t adj = (int32_t)((t + k) - (tramp + k));
            *(int32_t*)(tramp + k + 1) = rel + adj;
        } else if (t[k] == 0xEB) {
            log("[hook] REFUSED %p: a short jump in the first %u bytes", target, (unsigned)len);
            VirtualFree(tramp, 0, MEM_RELEASE);
            return false;
        }
        k += n;
    }
    tramp[len] = 0xE9;
    *(int32_t*)(tramp + len + 1) = (int32_t)((t + len) - (tramp + len + kJmpLen));

    Unprotect up(t, len);
    if (!up.ok()) {
        log("[hook] REFUSED %p: VirtualProtect failed (%lu)", target, GetLastError());
        VirtualFree(tramp, 0, MEM_RELEASE);
        return false;
    }
    memcpy(out->saved, t, len);
    out->saved_len = len;
    t[0] = 0xE9;
    *(int32_t*)(t + 1) = (int32_t)((uint8_t*)replacement - (t + kJmpLen));
    for (size_t k = kJmpLen; k < len; k++) t[k] = 0x90;   // pad the remainder so a disassembler stays sane

    out->target = target;
    out->trampoline = tramp;
    out->installed = true;
    return true;
}

bool undetour(Detour* d) {
    if (!d || !d->installed) return false;
    Unprotect up(d->target, d->saved_len);
    if (!up.ok()) return false;
    memcpy(d->target, d->saved, d->saved_len);
    d->installed = false;
    VirtualFree(d->trampoline, 0, MEM_RELEASE);
    d->trampoline = NULL;
    return true;
}

// ---- vtable ---------------------------------------------------------------------------------------

void* vtable_set(void** vtable, int index, void* replacement) {
    if (!vtable) return NULL;
    Unprotect up(&vtable[index], sizeof(void*));   // vtables live in .rdata: read-only until asked
    if (!up.ok()) return NULL;
    void* old = vtable[index];
    vtable[index] = replacement;
    return old;
}

}  // namespace zone
