// client_checksums - the zone checks the 2026 client's OWN table checksums at map login (Fiesta2026on2016, operator
// 2026-09-27 P1: "move the zone shn hash comparison from the bridge into the zone exe").
//
// ---- THE STOCK CODE (read from Zone.exe) ------------------------------------------------------------------------------
//   NC_MAP_LOGIN_REQ carries Name8 checksum[49] (32 ASCII hex characters each: MD5 of the SHN header + decrypted body).
//   CShnDataFileCheckSum::DataFileCheck(Name8*) (0x631350, global ShnDataFile) compares all 49 with the zone's own
//   CheckSumData[i].CheckSum (MD5 of ITS copy of each table, computed at load) and returns -1 if every one matches,
//   otherwise the index of the first mismatch -> "Client has been illegally manipulated". The 2026 client's tables are
//   2026 files, so their checksums never equal the 2016 zone's: until now ik-fiesta-proxy threw the client's checksums
//   away and substituted the zone's (zone-checksums.txt) - nothing verified the client, and a table change without a
//   regenerated proxy file locked every player out.
//
// ---- THIS PLUGIN -------------------------------------------------------------------------------------------------------
//   Detours DataFileCheck. Slot i passes when the client's checksum equals the zone's own (stock), OR is listed for slot i
//   in 9Data/Shine/ClientChecksums.txt (the checksums of the legitimate client's files; Fiesta2026on2016
//   tools/client_checksums.py writes it at deploy), OR slot i is listed as '*' (a table the 2026 client does not check:
//   MapLinkPoint, MapWayPoint). The proxy now forwards the client's REAL checksums, mapped onto the 49 slots.
//   A mismatch is logged with the table and both values - a stale list shows up in fiestahook.log, not as a mystery.
//   No list file = stock behaviour (the zone's own checksums only).
#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>

namespace {

const char* kList = "../9Data/Shine/ClientChecksums.txt";
const int kSlots = 49;
const unsigned kVaDataFileCheck = 0x00631350u;

zone::Detour g_check;
std::set<std::string> g_allowed[kSlots];
bool g_any[kSlots] = {};
unsigned g_logged = 0, g_passed = 0, g_refused = 0;

std::string lower32(const char* p) {
    std::string s(p, 32);
    for (auto& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

int __fastcall data_file_check(zone::types::CShnDataFileCheckSum* self, void*, zone::types::Name8* sums) {
    const char* client = (const char*)sums;
    for (int i = 0; i < kSlots; ++i) {
        const char* got = client + 32 * i;
        const char* own = (const char*)&self->CheckSumData[i].CheckSum;
        if (!std::memcmp(got, own, 32) || g_any[i]) continue;
        std::string g = lower32(got);
        if (g_allowed[i].count(g) || g == lower32(own)) continue;
        ++g_refused;
        if (++g_logged <= 50)
            zone::log("client_checksums: REFUSED - slot %d %.32s: client %.32s, zone %.32s, %u listed",
                      i, self->CheckSumData[i].DataFileName, got, own, (unsigned)g_allowed[i].size());
        return i;
    }
    if (++g_passed <= 5 || g_passed % 100 == 0) zone::log("client_checksums: map login checksums OK (%u so far)", g_passed);
    return -1;
}

bool load() {
    FILE* f = std::fopen(kList, "r");
    if (!f) return false;
    char line[256];
    int n = 0;
    while (std::fgets(line, sizeof line, f)) {
        if (line[0] == '#') continue;
        int slot = -1;
        char sum[64] = "";
        if (std::sscanf(line, "%d %63s", &slot, sum) != 2 || slot < 0 || slot >= kSlots) continue;
        if (!std::strcmp(sum, "*")) g_any[slot] = true;
        else if (std::strlen(sum) == 32) g_allowed[slot].insert(lower32(sum));
        else continue;
        ++n;
    }
    std::fclose(f);
    return n > 0;
}

}  // namespace

ZONEHOOK_PLUGIN("client_checksums") {
    if (!load()) {
        zone::log("client_checksums: no %s (or it lists nothing) - the zone checks its own checksums only (stock)", kList);
        return;
    }
    int listed = 0, any = 0;
    for (int i = 0; i < kSlots; ++i) { listed += (int)g_allowed[i].size(); any += g_any[i]; }
    zone::hook_function("CShnDataFileCheckSum::DataFileCheck 0x631350 (accept the legitimate client's checksums)",
                        zone::rebase(kVaDataFileCheck), (void*)data_file_check, &g_check);
    zone::log("client_checksums: %s - %d client checksums over %d slots, %d slot(s) the client does not check",
              kList, listed, kSlots, any);
}
