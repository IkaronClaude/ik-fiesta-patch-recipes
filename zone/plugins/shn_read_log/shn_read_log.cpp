// shn_read_log - logs every SHN the zone reads through CDataReader::Read, with the calling code (P1 "one set of tables",
// stage 1: which of the 49 checksummed client tables the zone actually parses, and who parses them).
//
//   CDataReader::Read(const char* file) (0x62A780) is the zone's generic SHN reader; while reading it registers the file's
//   MD5 with CShnDataFileCheckSum (InitDataFileCheckSum) - so it is also where a future hook can feed the zone the 2026
//   client's own file, converted. This plugin only records: "shn_read_log: <file> <- <return address>" (resolve the
//   address with the PDB: tools/disasm_at.py). A diagnostic - active only with 9Data/Shine/ShnReadLog.flag.
#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cstring>

#include <intrin.h>

namespace {

const char* kFlag = "../9Data/Shine/ShnReadLog.flag";
zone::Detour g_read, g_read2;
unsigned g_n = 0;

int __fastcall read(void* self, void*, char* file) {
    // the return address as a default-base VA (the exe may be relocated), ready for tools/disasm_at.py
    unsigned ret = (unsigned)_ReturnAddress() - ((unsigned)zone::rebase(0x00400000u) - 0x00400000u);
    ++g_n;
    zone::log("shn_read_log: #%u %s <- 0x%08X", g_n, file ? file : "(null)", ret);
    int r = ((int(__fastcall*)(void*, void*, char*))g_read.trampoline)(self, nullptr, file);
    // the checksum the zone just registered for it (CShnDataFileCheckSum entry with this file name), if any
    if (file) {
        const char* base = std::strrchr(file, '/');
        base = base ? base + 1 : file;
        auto* cs = zone::global::ShnDataFile();
        for (int i = 0; i < 49; ++i) {
            const auto& e = cs->CheckSumData[i];
            if (e.Marking && !_strnicmp(e.DataFileName, base, sizeof e.DataFileName)) {
                zone::log("shn_read_log: checksum slot %d %s = %.32s", i, e.DataFileName, (const char*)&e.CheckSum);
                break;
            }
        }
    }
    return r;
}

// CDataReader::Read(const char*, unsigned long, unsigned long) (0x62A9E0) - what most loaders call; it forwards to
// Read(const char*), so its caller is the real reader of the file
int __fastcall read2(void* self, void*, char* file, unsigned long a, unsigned long b) {
    unsigned ret = (unsigned)_ReturnAddress() - ((unsigned)zone::rebase(0x00400000u) - 0x00400000u);
    zone::log("shn_read_log: via Read(file,%lu,%lu) %s <- 0x%08X", a, b, file ? file : "(null)", ret);
    return ((int(__fastcall*)(void*, void*, char*, unsigned long, unsigned long))g_read2.trampoline)(self, nullptr, file, a, b);
}

}  // namespace

ZONEHOOK_PLUGIN("shn_read_log") {
    if (GetFileAttributesA(kFlag) == INVALID_FILE_ATTRIBUTES) return;
    zone::hook_function("CDataReader::Read 0x62A780 (log every SHN read)", zone::rebase(0x0062A780u), (void*)read, &g_read);
    zone::hook_function("CDataReader::Read(file,a,b) 0x62A9E0", zone::rebase(0x0062A9E0u), (void*)read2, &g_read2);
    zone::log("shn_read_log: %s - logging every CDataReader::Read", kFlag);
}
