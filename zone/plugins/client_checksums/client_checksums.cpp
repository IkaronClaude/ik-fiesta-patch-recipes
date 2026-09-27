// client_checksums - the zone checks the 2026 client's OWN table checksums at map login (Fiesta2026on2016, operator
// 2026-09-27/28 P1: "move the zone shn hash comparison into the zone", then "one set of tables").
//
// ---- THE STOCK CODE (read from Zone.exe) ------------------------------------------------------------------------------
//   NC_MAP_LOGIN_REQ carries Name8 checksum[49] (32 ASCII hex characters each: MD5 of the SHN header + decrypted body).
//   CShnDataFileCheckSum::DataFileCheck(Name8*) (0x631350, global ShnDataFile) compares all 49 with the zone's own
//   CheckSumData[i].CheckSum - CDataReader::Read (0x62A780), the one SHN reader, registers each file's MD5 while loading -
//   and returns -1 if every one matches, otherwise the first mismatching index -> "Client has been illegally manipulated".
//
// ---- ONE SET OF TABLES --------------------------------------------------------------------------------------------------
//   The server's copies of 40 of the 49 tables ARE the 2026 client's files (Fiesta2026on2016 tools/client_to_server.py
//   copies them), so the zone's own checksum already equals the client's - stock check, nothing to do. 7 tables the 2016
//   zone cannot read as the 2026 client writes them are CONVERTED (layout + 2016-legal values); client_to_server keeps the
//   client's ORIGINAL of each in 9Data/ClientTables/. This plugin hashes every file there at start-up, exactly like the
//   stock code hashes its own, and a slot also passes when the client's checksum equals the hash of its ClientTables file.
//   A slot the client sends as 32 '0's is one the 2026 client does not check (ik-fiesta-proxy fills MapLinkPoint /
//   MapWayPoint so) and passes. Refusals are logged with the table and the values. No ClientTables folder = stock.
#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <windows.h>
#include <wincrypt.h>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace {

const char* kDir = "../9Data/ClientTables/";
const int kSlots = 49;
const unsigned kVaDataFileCheck = 0x00631350u;

zone::Detour g_check;
std::string g_client[kSlots];          // the checksum of the client's original, where one is kept in ClientTables
unsigned g_logged = 0, g_passed = 0;

// the SHN body XOR (symmetric): the key stream depends only on the length (Fiesta2026on2016 tools/shn.py crypt_py)
void shn_crypt(std::vector<unsigned char>& d, size_t from) {
    size_t n = d.size() - from;
    unsigned char key = (unsigned char)(n & 0xFF);
    for (size_t k = n; k-- > 0;) {
        d[from + k] ^= key;
        unsigned char nk = (unsigned char)(((k & 0xFF) & 0x0F) + 0x55);
        nk ^= (unsigned char)(((k & 0xFF) * 11) & 0xFF);
        nk ^= key;
        nk ^= 0xAA;
        key = nk;
    }
}

bool md5_hex(const std::vector<unsigned char>& d, char out[33]) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH h = 0;
    bool ok = CryptAcquireContextA(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) &&
              CryptCreateHash(prov, CALG_MD5, 0, 0, &h) && CryptHashData(h, d.data(), (DWORD)d.size(), 0);
    if (ok) {
        BYTE b[16];
        DWORD len = sizeof b;
        ok = CryptGetHashParam(h, HP_HASHVAL, b, &len, 0) != 0;
        for (int i = 0; ok && i < 16; ++i) std::sprintf(out + 2 * i, "%02x", b[i]);
    }
    if (h) CryptDestroyHash(h);
    if (prov) CryptReleaseContext(prov, 0);
    return ok;
}

// MD5 of the SHN header (0x24 bytes) + the decrypted body, as the zone and the client compute it
bool shn_checksum(const std::string& path, char out[33]) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    std::vector<unsigned char> d;
    unsigned char buf[65536];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) d.insert(d.end(), buf, buf + n);
    std::fclose(f);
    if (d.size() < 0x24) return false;
    shn_crypt(d, 0x24);
    return md5_hex(d, out);
}

std::string lower32(const char* p) {
    std::string s(p, 32);
    for (auto& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

bool g_hashed = false;

// hash every ClientTables file named by a zone slot (CheckSumData[i].DataFileName, e.g. "ItemInfo.shn")
int hash_client_tables(zone::types::CShnDataFileCheckSum* cs) {
    int kept = 0, named = 0;
    for (int i = 0; i < kSlots; ++i) {
        char name[33] = {};
        std::memcpy(name, cs->CheckSumData[i].DataFileName, 32);
        if (!name[0]) continue;
        ++named;
        char sum[33] = {};
        if (shn_checksum(std::string(kDir) + name, sum)) {
            g_client[i] = sum;
            ++kept;
            zone::log("client_checksums: slot %d %s - client original %s", i, name, sum);
        }
    }
    if (named) g_hashed = true;                   // names known: done, whatever was found
    return kept;
}

int __fastcall data_file_check(zone::types::CShnDataFileCheckSum* self, void*, zone::types::Name8* sums) {
    if (!g_hashed) hash_client_tables(self);      // slot names were not filled yet at plugin start-up
    const char* client = (const char*)sums;
    for (int i = 0; i < kSlots; ++i) {
        const char* got = client + 32 * i;
        const char* own = (const char*)&self->CheckSumData[i].CheckSum;
        if (!std::memcmp(got, own, 32)) continue;                                   // stock: the zone's own file
        std::string g = lower32(got);
        if (g == lower32(own) || (!g_client[i].empty() && g == g_client[i])) continue;
        if (g == std::string(32, '0')) continue;                                    // a table the client does not check
        if (++g_logged <= 50)
            zone::log("client_checksums: REFUSED - slot %d %.32s: client %.32s, zone %.32s, ClientTables %s",
                      i, self->CheckSumData[i].DataFileName, got, own, g_client[i].empty() ? "-" : g_client[i].c_str());
        return i;
    }
    if (++g_passed <= 5 || g_passed % 100 == 0) zone::log("client_checksums: map login checksums OK (%u so far)", g_passed);
    return -1;
}

}  // namespace

ZONEHOOK_PLUGIN("client_checksums") {
    if (GetFileAttributesA(kDir) == INVALID_FILE_ATTRIBUTES) {
        zone::log("client_checksums: no %s - the zone checks its own checksums only (stock)", kDir);
        return;
    }
    int kept = hash_client_tables(zone::global::ShnDataFile());
    zone::hook_function("CShnDataFileCheckSum::DataFileCheck 0x631350 (accept the client's own table checksums)",
                        zone::rebase(kVaDataFileCheck), (void*)data_file_check, &g_check);
    zone::log("client_checksums: %s - %d client original(s) hashed; the other slots compare with the zone's own files", kDir, kept);
}
