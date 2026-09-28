// zone_shn.h - SHN INJECTION: hand the zone different bytes for a table file than the ones on disk, in memory.
//
//     #include <zone_shn.h>
//     bool mine(void* ctx, const char* path, const unsigned char* data, unsigned len, std::vector<unsigned char>& out) {
//         out = ...;             // a complete .shn image (crypt header, length, encrypted body) - as a file would hold
//         return true;           // false = leave the bytes as read
//     }
//     zone::shn::inject("UpgradeInfo.shn", mine, ctx);      // from your plugin entry point
//
// ---- WHERE IT SITS (read from Zone.exe) ----------------------------------------------------------------------------------
//   CDataReader::Read(const char* path) (0x62A780) is the zone's one SHN reader: fopen -> _filelength -> this->len (+4) ->
//   a buffer of that size (this->data +0x34, capacity +8) -> ONE fread of the whole file (the call at 0x62A825) ->
//   fclose -> decrypt -> header / row-length checks -> row index -> checksum registration (InitDataFileCheckSum).
//   Everything after the fread reads the buffer and the length back from `this`. So the injection point is that one
//   call: the real fread runs, the file's bytes are handed to the injector, and a replacement image is put in the
//   reader's buffer (grown with the exe's own operator new[] / delete, which is what frees it later). The zone's own
//   decrypt, checks, parse and checksum then run on the injected bytes, unchanged. Nothing is written to disk.
//
//   The checksum the zone registers is therefore the INJECTED image's. A plugin that wants the client to be checked
//   against something else (client_tables: the client's original file) sets that slot after Read returns.
//
// ---- SEVERAL PLUGINS -----------------------------------------------------------------------------------------------------
//   Each plugin carries its own copy of this header (hook_core.h: a plugin owns its hooks), so there is no registry to
//   share. Instead the call site CHAINS: the first inject() in a plugin points the call at that plugin's thunk and keeps
//   the target that was there before (the real fread, or another plugin's thunk) as "next". A thunk calls next first,
//   then applies its own injectors - so plugins compose in load order, each one seeing what the previous left in the
//   buffer. Load order is the hooks/ folder order.
//
//   The thunk relies on what Read holds across the call: esi = this (0x62A7B4 mov esi,ecx) and [ebp+8] = the path.
//   Both are checked with the bytes around the call site before anything is patched; a mismatch = nothing is injected
//   and the zone reads its files as they are.
#pragma once

#include "zonehook.h"

#include <cstring>
#include <vector>

namespace zone {
namespace shn {

// data/len = the file as read (or as the previous plugin left it). Fill `out` with a whole .shn image and return true
// to replace it; return false to pass it through. Called on the thread that loads the tables (the zone's start-up).
typedef bool (*Injector)(void* ctx, const char* path, const unsigned char* data, unsigned len,
                         std::vector<unsigned char>& out);

namespace detail {

const unsigned kVaRead = 0x0062A780u;          // CDataReader::Read(char*)
const unsigned kVaFreadCall = 0x0062A825u;     // its one `call _fread`
const unsigned kVaNew = 0x00654F0Bu;           // operator new[] - what Read allocates the buffer with
const unsigned kVaDelete = 0x0065677Fu;        // operator delete - what Read frees it with
const unsigned kOffLen = 0x04, kOffCap = 0x08, kOffData = 0x34;   // CDataReader: file length, capacity, buffer

struct Entry { char file[64]; Injector fn; void* ctx; };

inline std::vector<Entry>& entries() { static std::vector<Entry> e; return e; }
inline void* g_next = 0;                       // the call's previous target: _fread or another plugin's thunk

inline const char* base_name(const char* p) {
    const char* b = p;
    for (; *p; ++p) if (*p == '/' || *p == '\\') b = p + 1;
    return b;
}

// after the real fread (and any earlier plugin's): swap in this plugin's image. Returns fread's result.
inline int __cdecl after_fread(unsigned char* reader, const char* path, int result) {
    if (result != 1 || !reader || !path) return result;
    const char* bn = base_name(path);
    for (auto& e : entries()) {
        if (_stricmp(e.file, bn)) continue;
        unsigned char*& data = *(unsigned char**)(reader + kOffData);
        unsigned& len = *(unsigned*)(reader + kOffLen);
        unsigned& cap = *(unsigned*)(reader + kOffCap);
        std::vector<unsigned char> out;
        if (!e.fn(e.ctx, path, data, len, out) || out.empty()) continue;
        if (out.size() > cap) {
            typedef void*(__cdecl * NewFn)(size_t);
            typedef void(__cdecl * DeleteFn)(void*);
            ((DeleteFn)rebase(kVaDelete))(data);
            data = (unsigned char*)((NewFn)rebase(kVaNew))(out.size());
            cap = (unsigned)out.size();
        }
        std::memcpy(data, out.data(), out.size());
        len = (unsigned)out.size();
    }
    return result;
}

// in place of `call _fread` inside Read: [esp+4..16] = fread's four arguments, esi = the reader, [ebp+8] = the path
__declspec(naked) inline void fread_thunk() {
    __asm {
        push dword ptr [esp + 16]      // stream
        push dword ptr [esp + 16]      // count
        push dword ptr [esp + 16]      // size
        push dword ptr [esp + 16]      // buffer
        mov eax, g_next
        call eax                       // the real fread, or the previous plugin's thunk
        add esp, 16
        push eax
        push dword ptr [ebp + 8]
        push esi
        call after_fread
        add esp, 12
        ret
    }
}

// the bytes around the call that pin the register contract: mov esi,ecx at 0x62A7B4, and push edi / push 1 /
// push edx / push eax just before the call, mov [ebp-0x34],eax after it
inline bool site_ok() {
    const unsigned char* s = (const unsigned char*)rebase(0x0062A7B4u);
    const unsigned char* c = (const unsigned char*)rebase(kVaFreadCall);
    static const unsigned char kMov[] = {0x8B, 0xF1};
    static const unsigned char kBefore[] = {0x57, 0x6A, 0x01, 0x52, 0x50};
    static const unsigned char kAfter[] = {0x57, 0x89, 0x45, 0xCC};
    return !std::memcmp(s, kMov, 2) && !std::memcmp(c - 5, kBefore, 5) && c[0] == 0xE8 && !std::memcmp(c + 5, kAfter, 4);
}

inline bool install() {
    static int state = 0;                      // 0 = not yet, 1 = in place, -1 = refused
    if (state) return state > 0;
    state = -1;
    if (!site_ok()) {
        log("[shn] CDataReader::Read's fread call at %x is not the expected code - no SHN injection", kVaFreadCall);
        return false;
    }
    unsigned char* c = (unsigned char*)rebase(kVaFreadCall);
    int rel;
    std::memcpy(&rel, c + 1, 4);
    g_next = c + 5 + rel;
    unsigned char patch[5] = {0xE8};
    int nrel = (int)((unsigned char*)&fread_thunk - (c + 5));
    std::memcpy(patch + 1, &nrel, 4);
    if (!write_code(c, patch, 5)) return false;
    state = 1;
    log("[shn] injection point at %x (next: %x%s)", c, g_next,
        g_next == rebase(0x00658D30u) ? " = _fread" : " = another plugin's injector");
    return true;
}

}  // namespace detail

// serve `fn`'s bytes whenever the zone reads a file of this name (base name, case-insensitive). False = the call site
// is not the expected code (logged) - the zone then reads the file as it is.
inline bool inject(const char* file, Injector fn, void* ctx) {
    if (!detail::install()) return false;
    detail::Entry e = {};
    strncpy_s(e.file, file, _TRUNCATE);
    e.fn = fn;
    e.ctx = ctx;
    detail::entries().push_back(e);
    return true;
}

}  // namespace shn
}  // namespace zone
