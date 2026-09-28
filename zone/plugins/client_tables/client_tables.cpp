// client_tables - the zone reads the 2026 CLIENT'S OWN table files and converts the few it cannot take as they are, in
// memory, at load (Fiesta2026on2016, operator 2026-09-28: "one set of tables" - "hijack the stream and rewrite the
// original 2026 shn on the fly to be 2016 compatible").
//
// ---- WHAT THE ZONE DOES (read from Zone.exe) ----------------------------------------------------------------------------
//   CDataReader::Read(const char* file) (0x62A780) is the zone's one SHN reader. While reading it registers the file's MD5
//   (header + decrypted body) with CShnDataFileCheckSum (InitDataFileCheckSum, by file name); at map login
//   DataFileCheck compares the client's 49 checksums with those. Only the zones read the tables (shn_open_log, 2026-09-28:
//   Login / WorldManager / Character / Account / AccountLog / GameLog open none), so 9Data/Shine can hold the client's
//   files. 40 of the 49 the 2016 zone reads exactly as the 2026 client writes them.
//
// ---- THIS PLUGIN ---------------------------------------------------------------------------------------------------------
//   Injects (zone::shn::inject) every table listed in the layout file and detours CDataReader::Read. For a table listed in 9Data/Shine/ClientTableLayouts.txt (ActiveSkill, ChargedEffect,
//   ItemDismantle, ItemInfo, MobInfo, SubAbstate, UpgradeInfo) it reads the client's file, re-lays every row into the
//   2016 table's columns (names, types, widths - from the layout file: 2026-only columns dropped, strings re-sized, wider
//   integers CLAMPED, never wrapped), applies the rules below, orders the rows like the table's server-only lockstep
//   companion (MobInfoServer, ItemInfoServer - the zone asserts "DataOrder mismatch" otherwise) and hands the zone that
//   image instead of the file's bytes (zone_shn.h: in memory, at Read's fread - nothing is written to disk). After Read
//   it puts the checksum of the client's ORIGINAL into the table's checksum slot, so the stock check compares the client with itself. A table listed "unchecked"
//   (MapLinkPoint, MapWayPoint: 2016-only, the 2026 client neither has nor checks them) gets 32 '0's - what the proxy
//   forwards for them. The rules mirror Fiesta2026on2016 tools/client_to_server.py (the offline form of the same thing).
//   No layout file = stock.
#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>
#include <zone_shn.h>

#include <windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace {

const char* kLayouts = "../9Data/Shine/ClientTableLayouts.txt";
const char* kMobLoca = "../9Data/Shine/Loca/MobLoca.shn";
const unsigned kVaRead = 0x0062A780u;

enum { T_FLOAT = 5, T_VARSTR = 26 };
bool padded(unsigned t) { return t == 9 || t == 10 || t == 24; }
bool is_string(unsigned t) { return padded(t) || t == T_VARSTR; }

struct Col { std::string name; unsigned type; int len; std::string raw; };   // raw = the 48-byte name block ("" = build)
struct Val { bool str = false; bool flt = false; long long i = 0; double f = 0; std::string s; };
typedef std::map<std::string, Val> Row;
struct Table { std::string crypt; unsigned header = 0; std::vector<Col> cols; std::vector<Row> rows; };
struct Layout { std::string companion; std::string crypt; unsigned header = 0; std::vector<Col> cols; };

std::map<std::string, Layout> g_layouts;          // lower-case table name -> the 2016 layout
std::map<std::string, bool> g_unchecked;          // lower-case table name
std::map<long long, long long> g_fold;            // 2026 equip slot -> 2016 slot
std::map<long long, std::string> g_mobloca;       // MobLoca id -> name (raw bytes)
bool g_mobloca_loaded = false;
zone::Detour g_read;

std::string lower(std::string s) { for (auto& c : s) c = (char)tolower((unsigned char)c); return s; }
std::string base_name(const char* p) { const char* b = std::strrchr(p, '/'); const char* b2 = std::strrchr(p, '\\');
    if (b2 > b) b = b2; return b ? b + 1 : p; }
std::string stem(const std::string& f) { size_t d = f.rfind('.'); return d == std::string::npos ? f : f.substr(0, d); }

bool read_file(const std::string& path, std::vector<unsigned char>& d) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    unsigned char buf[65536];
    size_t n;
    d.clear();
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) d.insert(d.end(), buf, buf + n);
    std::fclose(f);
    return true;
}

void shn_crypt(unsigned char* d, size_t n) {       // symmetric; key stream depends only on the length (tools/shn.py)
    unsigned char key = (unsigned char)(n & 0xFF);
    for (size_t k = n; k-- > 0;) {
        d[k] ^= key;
        unsigned char nk = (unsigned char)(((k & 0xFF) & 0x0F) + 0x55);
        nk ^= (unsigned char)(((k & 0xFF) * 11) & 0xFF);
        nk ^= key;
        nk ^= 0xAA;
        key = nk;
    }
}

bool md5_hex(const unsigned char* p, size_t n, char out[33]) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH h = 0;
    bool ok = CryptAcquireContextA(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) &&
              CryptCreateHash(prov, CALG_MD5, 0, 0, &h) && CryptHashData(h, p, (DWORD)n, 0);
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

bool is_signed(unsigned t) { return t == 13 || t == 20 || t == 21 || t == 22; }

// parse a column SHN (tools/shn.py _read); md5 = checksum of header + decrypted body (what the client sends)
bool parse(const std::vector<unsigned char>& file, Table& t, char md5[33]) {
    if (file.size() < 36 + 16) return false;
    unsigned dl;
    std::memcpy(&dl, &file[32], 4);
    if (dl != file.size()) return false;
    std::vector<unsigned char> d(file.begin(), file.end());
    shn_crypt(&d[36], d.size() - 36);
    if (md5) {
        std::vector<unsigned char> sum(d.begin(), d.begin() + 0x24);
        sum.insert(sum.end(), d.begin() + 36, d.end());
        md5_hex(sum.data(), sum.size(), md5);
    }
    t.crypt.assign((const char*)&file[0], 32);
    const unsigned char* b = &d[36];
    size_t n = d.size() - 36, o = 16;
    unsigned rc, cc;
    std::memcpy(&t.header, b, 4);
    std::memcpy(&rc, b + 4, 4);
    std::memcpy(&cc, b + 12, 4);
    int unk = 0;
    for (unsigned i = 0; i < cc; ++i) {
        if (o + 56 > n) return false;
        Col c;
        c.raw.assign((const char*)b + o, 48);
        std::string nm((const char*)b + o, strnlen((const char*)b + o, 48));
        while (!nm.empty() && (nm.back() == ' ')) nm.pop_back();
        while (!nm.empty() && (nm.front() == ' ')) nm.erase(0, 1);
        if (nm.size() < 2) { char u[24]; std::sprintf(u, "Undefined%d", unk++); nm = u; }
        c.name = nm;
        std::memcpy(&c.type, b + o + 48, 4);
        std::memcpy(&c.len, b + o + 52, 4);
        t.cols.push_back(c);
        o += 56;
    }
    t.rows.reserve(rc);
    for (unsigned r = 0; r < rc; ++r) {
        size_t p = o + 2;
        Row row;
        for (auto& c : t.cols) {
            Val v;
            if (padded(c.type)) {
                if (p + c.len > n) return false;
                v.str = true;
                v.s.assign((const char*)b + p, strnlen((const char*)b + p, c.len));
                p += c.len;
            } else if (c.type == T_VARSTR) {
                size_t e = p;
                while (e < n && b[e]) ++e;
                v.str = true;
                v.s.assign((const char*)b + p, e - p);
                p = e + 1;
            } else if (c.type == T_FLOAT) {
                float f;
                std::memcpy(&f, b + p, 4);
                v.flt = true;
                v.f = f;
                p += 4;
            } else {
                unsigned long long u = 0;
                for (int k = 0; k < c.len; ++k) u |= (unsigned long long)b[p + k] << (8 * k);
                long long x = (long long)u;
                if (is_signed(c.type) && c.len < 8 && (u >> (8 * c.len - 1)) & 1) x -= 1LL << (8 * c.len);
                v.i = x;
                p += c.len;
            }
            row[c.name] = v;
        }
        t.rows.push_back(std::move(row));
        o = p;
    }
    return true;
}

std::vector<unsigned char> build_shn(const Layout& L, const std::vector<Row>& rows) {
    std::vector<unsigned char> body;
    auto put32 = [&](unsigned x) { for (int k = 0; k < 4; ++k) body.push_back((unsigned char)(x >> (8 * k))); };
    unsigned reclen = 2;
    for (auto& c : L.cols) reclen += c.len;
    put32(L.header);
    put32((unsigned)rows.size());
    put32(reclen);
    put32((unsigned)L.cols.size());
    for (auto& c : L.cols) {
        std::string nb = c.raw;
        if (nb.size() != 48) { nb = c.name.rfind("Undefined", 0) == 0 ? std::string(" ") : c.name; nb.resize(48, '\0'); }
        body.insert(body.end(), nb.begin(), nb.end());
        put32(c.type);
        put32((unsigned)c.len);
    }
    for (auto& r : rows) {
        std::vector<unsigned char> rb;
        for (auto& c : L.cols) {
            auto it = r.find(c.name);
            Val v = it == r.end() ? Val() : it->second;
            if (padded(c.type)) {
                std::string s = v.str ? v.s : std::string();
                s.resize(c.len, '\0');
                rb.insert(rb.end(), s.begin(), s.end());
            } else if (c.type == T_VARSTR) {
                std::string s = v.str ? v.s : std::string();
                rb.insert(rb.end(), s.begin(), s.end());
                rb.push_back(0);
            } else if (c.type == T_FLOAT) {
                float f = (float)(v.flt ? v.f : (double)v.i);
                unsigned char fb[4];
                std::memcpy(fb, &f, 4);
                rb.insert(rb.end(), fb, fb + 4);
            } else {
                long long x = v.flt ? (long long)v.f : v.i;
                if (c.len < 8) {
                    long long maxu = (1LL << (8 * c.len)) - 1;
                    if (x > maxu) x = maxu;              // too wide for the 2016 field: CLAMP, never wrap
                }
                unsigned long long u = (unsigned long long)x;
                for (int k = 0; k < c.len; ++k) rb.push_back((unsigned char)(u >> (8 * k)));
            }
        }
        unsigned short rl = (unsigned short)(rb.size() + 2);
        body.push_back((unsigned char)rl);
        body.push_back((unsigned char)(rl >> 8));
        body.insert(body.end(), rb.begin(), rb.end());
    }
    shn_crypt(body.data(), body.size());
    std::vector<unsigned char> img(L.crypt.begin(), L.crypt.end());
    unsigned total = (unsigned)body.size() + 36;
    for (int k = 0; k < 4; ++k) img.push_back((unsigned char)(total >> (8 * k)));
    img.insert(img.end(), body.begin(), body.end());
    return img;
}

// ---- the rules: 2026 values the 2016 zone cannot take (mirror tools/client_to_server.py) -------------------------------
long long get(Row& r, const char* c) { auto it = r.find(c); return it == r.end() ? 0 : it->second.i; }
void set(Row& r, const char* c, long long x) { auto it = r.find(c); if (it != r.end()) it->second.i = x; }

void load_mobloca() {
    g_mobloca_loaded = true;
    std::vector<unsigned char> f;
    Table t;
    if (!read_file(kMobLoca, f) || !parse(f, t, nullptr)) {
        zone::log("client_tables: no %s - MobInfo names stay the client's ids' fallback (InxName)", kMobLoca);
        return;
    }
    for (auto& r : t.rows) g_mobloca[r["Identifier"].i] = r["Translation"].s;
}

void rules(const std::string& table, Row& r) {
    if (table == "activeskill") {
        if (get(r, "MaxStep") > 20) set(r, "MaxStep", 20);      // the 2016 skill system has 20 steps
        if (get(r, "Step") > 20) set(r, "Step", 20);
        if (get(r, "EffectType") == 16) set(r, "EffectType", 0); // a 2026-only effect type (TevaHero skills)
    } else if (table == "iteminfo") {
        long long e = get(r, "Equip");                            // 2026 equipment slots 30+ fold onto a 2016 slot
        if (e >= 30) { auto it = g_fold.find(e); set(r, "Equip", it == g_fold.end() ? 0 : it->second); }
        auto inx = r.find("InxName"), us = r.find("ItemUseSkill");
        if (inx != r.end() && us != r.end() && inx->second.s.find("QExpBoost") != std::string::npos && us->second.s == "-")
            us->second.s = "UseSkill";                            // the Quest EXP Booster needs a use-skill on 2016
    } else if (table == "mobinfo") {
        auto nm = r.find("Name");                                 // the 2026 client names mobs by a MobLoca id
        if (nm != r.end() && !nm->second.str) {
            if (!g_mobloca_loaded) load_mobloca();
            auto it = g_mobloca.find(nm->second.i);
            Val v;
            v.str = true;
            v.s = it != g_mobloca.end() ? it->second : r["InxName"].s;
            nm->second = v;
        }
    } else if (table == "subabstate") {
        if (get(r, "ActionIndexA") >= 121) set(r, "ActionIndexA", 0);   // 2026-only action kinds: no 2016 handler
        if (get(r, "Type") >= 120) set(r, "Type", 0);
    }
}

// ---- UpgradeInfo at 32 bits (operator 2026-09-28: "just change the column type in the shn to a 32 bit one") ------------
//   The 2026 client widened UpgradeInfo's 12 per-enchant-level values (Updata, Undefined0-10) from u16 to u32; 72 values
//   of 57 endgame weapons exceed 65535. The zone keeps the FILE's row layout (UpgradeDataBox::udb_Load indexes
//   CDataReader::GetRecord rows), so a 32-bit column only needs:
//     - BinaryDataBox<UpGradeInfo>::bdb_ReadData's expected row size (Read(file, 0xA2B, 62) at 0x596178): 62 -> 86;
//     - the ONE reader, ShinePlayer::so_RecalcEquipParam (0x4CB2F3..0x4CB38A): Updata[level] is read as a word at
//       +0x24 + level*2 and ADDED to 32-bit player stats - re-encoded to a dword at +0x22 + level*4 (same bytes, NOP pad).
//   All or nothing: every site is checked first; any unexpected byte -> nothing patched, the values stay clamped to 16
//   bits (the 2016 layout).
struct Patch { unsigned va; unsigned char orig[5]; unsigned char neu[5]; int n; };
const Patch kWide[] = {
    {0x596178, {0x6A, 0x3E}, {0x6A, 0x56}, 2},                                    // push 62 -> push 86 (row size)
    {0x4CB2F3, {0x0F, 0xB7, 0x44, 0x50, 0x24}, {0x8B, 0x44, 0x90, 0x22, 0x90}, 5}, // movzx eax,w[eax+edx*2+24] -> mov eax,[eax+edx*4+22]
    {0x4CB307, {0x0F, 0xB7, 0x54, 0x48, 0x24}, {0x8B, 0x54, 0x88, 0x22, 0x90}, 5}, // movzx edx,w[eax+ecx*2+24] -> mov edx,[eax+ecx*4+22]
    {0x4CB318, {0x8D, 0x44, 0x48, 0x24}, {0x8D, 0x44, 0x88, 0x22}, 4},             // lea eax,[eax+ecx*2+24] -> [eax+ecx*4+22]
    {0x4CB31C, {0x0F, 0xB7, 0x10}, {0x8B, 0x10, 0x90}, 3},                         // movzx edx,w[eax] -> mov edx,[eax]
    {0x4CB325, {0x0F, 0xB7, 0x00}, {0x8B, 0x00, 0x90}, 3},                         // movzx eax,w[eax] -> mov eax,[eax]
    {0x4CB334, {0x8D, 0x44, 0x48, 0x24}, {0x8D, 0x44, 0x88, 0x22}, 4},
    {0x4CB338, {0x0F, 0xB7, 0x10}, {0x8B, 0x10, 0x90}, 3},
    {0x4CB341, {0x0F, 0xB7, 0x00}, {0x8B, 0x00, 0x90}, 3},
    {0x4CB350, {0x0F, 0xB7, 0x54, 0x48, 0x24}, {0x8B, 0x54, 0x88, 0x22, 0x90}, 5},
    {0x4CB361, {0x8D, 0x44, 0x48, 0x24}, {0x8D, 0x44, 0x88, 0x22}, 4},
    {0x4CB365, {0x0F, 0xB7, 0x10}, {0x8B, 0x10, 0x90}, 3},
    {0x4CB36E, {0x0F, 0xB7, 0x08}, {0x8B, 0x08, 0x90}, 3},                         // movzx ecx,w[eax] -> mov ecx,[eax]
    {0x4CB37D, {0x8D, 0x44, 0x48, 0x24}, {0x8D, 0x44, 0x88, 0x22}, 4},
    {0x4CB381, {0x0F, 0xB7, 0x10}, {0x8B, 0x10, 0x90}, 3},
    {0x4CB38A, {0x0F, 0xB7, 0x00}, {0x8B, 0x00, 0x90}, 3},
};
bool g_wide_upgrade = false;

bool widen_upgradeinfo() {
    for (auto& p : kWide)
        if (std::memcmp(zone::rebase(p.va), p.orig, p.n)) {
            zone::log("client_tables: UpgradeInfo stays 16-bit - unexpected bytes at 0x%X", p.va);
            return false;
        }
    for (auto& p : kWide)
        if (!zone::write_code(zone::rebase(p.va), p.neu, p.n)) {
            zone::log("client_tables: UpgradeInfo patch at 0x%X FAILED to write - the zone may be half-patched", p.va);
            return false;
        }
    return true;
}

bool upgrade_value_column(const std::string& name) {
    return name == "Updata" || (name.rfind("Undefined", 0) == 0 && name.size() <= 11);
}

// ---- the conversion ----------------------------------------------------------------------------------------------------
bool convert(const std::string& table, const Layout& L, const unsigned char* data, unsigned len,
             std::vector<unsigned char>& out, char md5[33]) {
    std::vector<unsigned char> f(data, data + len);
    Table t;
    if (!parse(f, t, md5)) {
        zone::log("client_tables: %s - cannot parse the client's file", table.c_str());
        return false;
    }
    for (auto& r : t.rows) rules(table, r);
    Layout wide;
    const Layout* use = &L;
    if (table == "upgradeinfo" && g_wide_upgrade) {           // the 12 values at 32 bits, as the 2026 client has them
        wide = L;
        for (auto& c : wide.cols)
            if (upgrade_value_column(c.name)) { c.type = 22; c.len = 4; }   // the 2026 file's own type (22 = u32, 21 = u16)
        use = &wide;
    }
    if (!L.companion.empty()) {                                   // the order of the lockstep companion
        std::vector<unsigned char> cf;
        Table ct;
        std::string cp = std::string("../9Data/Shine/") + L.companion + ".shn";
        if (!read_file(cp, cf) || !parse(cf, ct, nullptr)) {
            zone::log("client_tables: %s - cannot read its companion %s", table.c_str(), cp.c_str());
            return false;
        }
        std::map<long long, size_t> order;
        for (size_t i = 0; i < ct.rows.size(); ++i) order[ct.rows[i][ct.cols[0].name].i] = i;
        const std::string key = t.cols[0].name;
        size_t missing = 0;
        for (auto& r : t.rows) if (!order.count(r[key].i)) ++missing;
        if (missing || ct.rows.size() != t.rows.size())
            zone::log("client_tables: %s - %u row(s) the companion %s lacks, %d row(s) difference - the zone will assert",
                      table.c_str(), (unsigned)missing, L.companion.c_str(), (int)ct.rows.size() - (int)t.rows.size());
        std::vector<std::pair<size_t, size_t>> pos;              // (companion position, original index)
        pos.reserve(t.rows.size());
        for (size_t i = 0; i < t.rows.size(); ++i) {
            auto io = order.find(t.rows[i][key].i);
            pos.emplace_back(io == order.end() ? (size_t)-1 : io->second, i);
        }
        std::stable_sort(pos.begin(), pos.end());
        std::vector<Row> sorted;
        sorted.reserve(t.rows.size());
        for (auto& pr : pos) sorted.push_back(std::move(t.rows[pr.second]));
        t.rows.swap(sorted);
    }
    out = build_shn(*use, t.rows);
    return true;
}

// one per layout table: what the injector did for the Read in progress (the Read detour reports it and sets the slot)
struct Job { std::string key; bool done = false; char sum[33] = {}; };
std::map<std::string, Job> g_jobs;

bool inject(void* ctx, const char*, const unsigned char* data, unsigned len, std::vector<unsigned char>& out) {
    Job& j = *(Job*)ctx;
    j.done = convert(j.key, g_layouts[j.key], data, len, out, j.sum);
    return j.done;
}

void set_slot_checksum(const std::string& file, const char* sum) {
    auto* cs = zone::global::ShnDataFile();
    for (int i = 0; i < 49; ++i) {
        auto& e = cs->CheckSumData[i];
        if (!_strnicmp(e.DataFileName, file.c_str(), sizeof e.DataFileName)) {
            std::memcpy((char*)&e.CheckSum, sum, 32);
            return;
        }
    }
}

int __fastcall read(void* self, void*, char* file) {
    typedef int(__fastcall * ReadFn)(void*, void*, char*);
    auto real = (ReadFn)g_read.trampoline;
    if (!file) return real(self, nullptr, file);
    std::string bn = base_name(file), key = lower(stem(bn));
    auto it = g_layouts.find(key);
    auto jt = g_jobs.find(key);
    if (it != g_layouts.end() && jt != g_jobs.end()) {
        Job& j = jt->second;
        j.done = false;
        int r = real(self, nullptr, file);                        // the injector converts inside, at the fread
        if (j.done) {
            set_slot_checksum(bn, j.sum);                         // the check compares the client with its own file
            zone::log("client_tables: %s converted from the client's file in memory (checksum %s)", bn.c_str(), j.sum);
        } else {
            zone::log("client_tables: %s NOT converted - the zone reads it as it is", bn.c_str());
        }
        return r;
    }
    int r = real(self, nullptr, file);
    if (g_unchecked.count(key)) set_slot_checksum(bn, "00000000000000000000000000000000");
    return r;
}

std::string unhex(const std::string& h) {
    std::string out;
    for (size_t i = 0; i + 1 < h.size(); i += 2) out.push_back((char)std::stoi(h.substr(i, 2), nullptr, 16));
    return out;
}

bool load_layouts() {
    FILE* f = std::fopen(kLayouts, "r");
    if (!f) return false;
    char line[1024];
    Layout* cur = nullptr;
    while (std::fgets(line, sizeof line, f)) {
        char a[64] = "", b[128] = "", c[64] = "", d[128] = "", e[64] = "", g[160] = "";
        int n = std::sscanf(line, "%63s %127s %63s %127s %63s %159s", a, b, c, d, e, g);
        if (n <= 0 || a[0] == '#') continue;
        std::string k = a;
        if (k == "table" && n >= 2) {                             // table <name> companion <name|-> header <u32> crypt <hex>
            cur = &g_layouts[lower(b)];
            if (n >= 4 && std::strcmp(d, "-")) cur->companion = d;
        } else if (k == "header" && cur) cur->header = (unsigned)std::stoul(b);
        else if (k == "crypt" && cur) cur->crypt = unhex(b);
        else if (k == "col" && cur && n >= 4) {                   // col <name> <type> <len> [rawhex]
            Col col;
            col.name = b;
            col.type = (unsigned)std::stoul(c);
            col.len = std::stoi(d);
            if (n >= 5 && std::strcmp(e, "-")) col.raw = unhex(e);
            cur->cols.push_back(col);
        } else if (k == "fold" && n >= 3) g_fold[std::stoll(b)] = std::stoll(c);
        else if (k == "unchecked" && n >= 2) g_unchecked[lower(b)] = true;
    }
    std::fclose(f);
    for (auto it = g_layouts.begin(); it != g_layouts.end();)
        if (it->second.cols.empty() || it->second.crypt.size() != 32) it = g_layouts.erase(it); else ++it;
    return !g_layouts.empty();
}

}  // namespace

ZONEHOOK_PLUGIN("client_tables") {
    if (!load_layouts()) {
        zone::log("client_tables: no %s (or no usable layout) - the zone reads its tables as they are (stock)", kLayouts);
        return;
    }
    if (g_layouts.count("upgradeinfo")) {
        g_wide_upgrade = widen_upgradeinfo();
        zone::log("client_tables: UpgradeInfo %s", g_wide_upgrade ? "WIDE - its 12 values read at 32 bits (16 sites patched)"
                                                                : "16-bit (clamped)");
    }
    for (auto& l : g_layouts) {
        Job& j = g_jobs[l.first];
        j.key = l.first;
        if (!zone::shn::inject((l.first + ".shn").c_str(), inject, &j)) {
            g_jobs.clear();
            zone::log("client_tables: no SHN injection point - the zone reads its tables as they are (stock)");
            return;
        }
    }
    zone::hook_function("CDataReader::Read 0x62A780 (the 2026 client's tables, converted on the fly)",
                        zone::rebase(kVaRead), (void*)read, &g_read);
    zone::log("client_tables: %s - %u table(s) converted at load, %u unchecked, %u equip folds",
              kLayouts, (unsigned)g_layouts.size(), (unsigned)g_unchecked.size(), (unsigned)g_fold.size());
}
