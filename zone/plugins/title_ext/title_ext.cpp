// title_ext - character titles past type 127 (2026 has 150; 2016 keeps 128).
//
// ---- THE LIMIT --------------------------------------------------------------------------------------
//
// CCharacterTitle (Zone.pdb) keeps one status byte per title TYPE - four 2-bit element levels - inline:
//
//     +0x004  u8 status[128]      <- the limit: GetGroupTitle(type) returns NULL for type >= 0x80
//     +0x084  int  view count
//     +0x088  {u8 type, u8 element}[512]  the owned-title list (the client's list; byte types, no limit)
//     +0x488  current title / element / mob, +0x498 u64 counters[128] (16-byte stride)
//
// Everything else about a title already carries a BYTE type: the DB row (tCharacterTitle.nType tinyint),
// the save packet (NC_CT_DB_SET_CMD {CT_INFO}), the login list and the client's title list. So a 2026 title
// (128..149 - Hunter's Union Newbie ... Benny's Best Friend, eight of them quest rewards since migration
// 0340) was stored and listed, but the zone could never mark it known / usable / current. The array cannot
// grow in place (the view list follows it), so types 128..255 live in a side table here, per object:
//
//     GetGroupTitle   0x62E160   the pointer every caller goes through (SetTitleStatusZone etc.)
//     GetTitleStatus  0x62E180   inlined the array read      - replaced
//     SetTitleStatus  0x62E440   inlined the array write     - replaced (then AddView, as stock)
//     GetMyTitleCount 0x62E3B0   loop to 0x80                - replaced, loop to 0x100
//     Clear           0x62E370 / ctor 0x62E4E0              - stock, then the side row zeroed
//
// The zone recycles player objects, so the side row is keyed by the object and zeroed whenever the stock
// code zeroes its own array (Clear and the constructor), never left over for the next player.
//
// NOT HERE (needs the character-server side too): Character.exe dropped type >= 128 rows when it built the
// login block and when it saved the usable state - recipe character/recipes/character-title-types.
// NOT PORTED: the stat bonus of a title (CharacterTitleStateServer, [128][4] records inline in
// CCharacterTitleDataStateServer); 2026 describes bonuses for the new titles but ships no server rows.
#include <zonehook.h>
#include <zone_functions.h>

#include <cstring>
#include <mutex>
#include <unordered_map>

namespace {

const int kStockTypes = 0x80;
const int kTypes = 0x100;                     // the type is a byte everywhere else
const int kSpecialType = 10;                  // stock: type 10 counts as 4 titles in GetMyTitleCount

struct Extra { unsigned char status[kTypes - kStockTypes]; };
std::mutex g_mu;
std::unordered_map<void*, Extra>* g_side = nullptr;   // node-based: a returned pointer stays valid

unsigned char* status_byte(void* self, unsigned type) {
    if (type < (unsigned)kStockTypes) return (unsigned char*)self + 4 + type;
    std::lock_guard<std::mutex> lk(g_mu);
    Extra& e = (*g_side)[self];                    // value-initialised (zero) on first use
    return &e.status[type - kStockTypes];
}

void zero_side(void* self) {
    std::lock_guard<std::mutex> lk(g_mu);
    auto it = g_side->find(self);
    if (it != g_side->end()) memset(it->second.status, 0, sizeof(it->second.status));
}

zone::Detour g_get, g_status, g_set, g_count, g_clear, g_ctor;

void* __fastcall get_group_title(void* self, void*, unsigned char type) {
    return status_byte(self, type);
}

int __fastcall get_title_status(void* self, void*, unsigned char type, unsigned char elem) {
    if (elem > 3) return 0;
    return (*status_byte(self, type) >> (elem * 2)) & 3;
}

int __fastcall set_title_status(void* self, void*, unsigned char type, unsigned char elem, int value) {
    if (elem > 3) return 0;
    unsigned char* p = status_byte(self, type);
    const unsigned shift = elem * 2;
    *p = (unsigned char)((*p & ~(3u << shift)) | ((unsigned)(value & 3) << shift));
    zone::fn::CCharacterTitle__AddView()(self, nullptr, type, elem);   // stock does this after every write
    return 1;
}

unsigned long __fastcall get_my_title_count(void* self, void*) {
    unsigned long n = 0;
    for (int t = 0; t < kTypes; t++) {
        if (t == kSpecialType) { n += 4; continue; }
        const unsigned char s = *status_byte(self, t);
        for (int e = 0; e < 4; e++)
            if (((s >> (e * 2)) & 3) >= 1) n++;
    }
    return n;
}

void __fastcall clear(void* self, void*) {
    ((void (__fastcall*)(void*, void*))g_clear.trampoline)(self, nullptr);
    zero_side(self);
}

void __fastcall ctor(void* self, void*, void* data) {
    ((void (__fastcall*)(void*, void*, void*))g_ctor.trampoline)(self, nullptr, data);
    zero_side(self);
}

bool install(const char* what, unsigned va, void* repl, zone::Detour* d) {
    void* target = zone::rebase(va);
    if (!zone::detour(target, repl, d)) { zone::log("%s: NOT hooked", what); return false; }
    zone::log("%s at %x -> %x", what, target, repl);
    return true;
}

}  // namespace

HOOK_PLUGIN("title_ext") {
    g_side = new std::unordered_map<void*, Extra>();
    bool ok = install("CCharacterTitle::GetGroupTitle", zone::fn::kVa_CCharacterTitle__GetGroupTitle, (void*)get_group_title, &g_get)
            & install("CCharacterTitle::GetTitleStatus", zone::fn::kVa_CCharacterTitle__GetTitleStatus, (void*)get_title_status, &g_status)
            & install("CCharacterTitle::SetTitleStatus", zone::fn::kVa_CCharacterTitle__SetTitleStatus, (void*)set_title_status, &g_set)
            & install("CCharacterTitle::GetMyTitleCount", zone::fn::kVa_CCharacterTitle__GetMyTitleCount, (void*)get_my_title_count, &g_count)
            & install("CCharacterTitle::Clear", zone::fn::kVa_CCharacterTitle__Clear, (void*)clear, &g_clear)
            & install("CCharacterTitle::CCharacterTitle", zone::fn::kVa_CCharacterTitle__CCharacterTitle, (void*)ctor, &g_ctor);
    zone::log(ok ? "title types 0..%d (stock 0..%d)" : "PARTIAL: title types past %d NOT fully supported", kTypes - 1,
              kStockTypes - 1);
}
