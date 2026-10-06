// instance_dismantle_text - the 2026 client's dismantle window (MakeKarisWin) knows instance set pieces dismantle into
// their instance COIN (Fiesta2026on2016 Rebalanced, operator 2026-10-06: "instead of 'gives 0 Karis' for these set
// items it will say 'gives 2 Leviathan Coin'. Via Client hook"; "Putting a +0 item into the window just shows 'The item
// cannot be dismantled'"). The server half is the zone plugin instance_dismantle (a piece priced in a REB_IDCoin* coin
// in ItemMoney dismantles into ONE of that coin); this mirrors its rule so the window shows what the server will do.
//
// ---- THE STOCK CODE (2026 Fiesta.exe, 10.6.6 addresses, read 2026-10-06) ----------------------------------------------
//   Three places compute the Karis count from the client's ItemDismantle table (row by the item, column by the item's
//   Grade and kind) and leave it in a register with the item object in esi (its ItemInfo row at [esi+0x70]):
//     preview 1  0x6556B2  mov edi,[ebp-0xc] ; push ebx (count) ; push 0x952059C5 "%d Karis will be created ..."
//     preview 2  0x655D0D  the same nine bytes
//     click      0x655E9A  test eax,eax (count) ; jle 0x655FA5 "This item cannot be dismantled." (0xD27B2055)
//   A set piece's row says 0 - the window refuses it although the server would dismantle it.
//   The texts are TextData ids read through the cdecl lookup 0x458CC0 (u32 id -> const char*), each used once here:
//     0xAF23C4AE "Dismantle Karis." (the button)   0x58E4D180 "Karis dismantle circle." (title)   0xD8A31FCA "<Warning>\nItem dismantled by Karis cannot\n be restored."
//
// ---- THIS PLUGIN ------------------------------------------------------------------------------------------------------
//   The three count sites jump to stubs that ask coin_count(item, count): a piece whose ItemMoney price is a
//   "REB_IDCoin*" coin gets count kCoinCount and the coin's ItemInfo Name is remembered; anything else keeps its count.
//   The TextData lookup is wrapped: the count text is rewritten with the coin's name while one is remembered, the title
//   and the warning always (operator's wording). ItemMoney / ItemInfo are the client's OWN ressystem tables, read once.
//   Only the Rebalanced client: hooks\instance_dismantle_text.ini [plugin] enabled=1.
#include <hook_core.h>
#include <client_addrs.h>

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace {

const unsigned long kCoinCount = 1;           // the zone plugin's count (instance_dismantle: always 1, below the price)
const char kCoinPrefix[] = "REB_IDCoin";
const unsigned kTextCount = 0x952059C5u, kTextTitle = 0x58E4D180u, kTextWarning = 0xD8A31FCAu, kTextButton = 0xAF23C4AEu;
const char kTitle[] = "Dismantle";       // also the button (stock "Dismantle Karis.")
const char kWarning[] = "<Warning>\nDismantled items cannot\n be restored.";
const unsigned kItemRow = 0x70, kRowInxName = 2;   // item object -> ItemInfo row; row +2 = InxName (32)

const unsigned char kStockAB[9] = {0x8B, 0x7D, 0xF4, 0x53, 0x68, 0xC5, 0x59, 0x20, 0x95};
const unsigned char kStockC[2] = {0x85, 0xC0};     // test eax,eax ; then 0F 8E rel32 (jle -> DismantleRefuseC)

// ---- the client's own tables ---------------------------------------------------------------------------------------
std::map<std::string, std::string> g_piece_coin;   // set piece InxName -> coin InxName (ItemMoney, coin rows only)
std::map<std::string, std::string> g_coin_name;    // coin InxName -> ItemInfo Name
bool g_loaded = false;

void shn_crypt(unsigned char* d, size_t n) {
    unsigned char key = (unsigned char)n;
    for (size_t k = n; k-- > 0;) {
        d[k] ^= key;
        unsigned char i = (unsigned char)k;
        unsigned char nk = (unsigned char)((i & 0x0F) + 0x55);
        nk ^= (unsigned char)(i * 11);
        nk ^= key;
        nk ^= 0xAA;
        key = nk;
    }
}

struct Col { std::string name; unsigned type; int len; };
const unsigned kVarStr = 26;                        // the one variable-length type (zero-terminated)

// rows of a column SHN as {column -> raw field bytes}; only the named columns are kept
bool shn_read(const char* path, const std::vector<std::string>& want, std::vector<std::map<std::string, std::string>>& out) {
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f) return false;
    std::vector<unsigned char> b;
    unsigned char buf[65536];
    size_t r;
    while ((r = std::fread(buf, 1, sizeof buf, f)) > 0) b.insert(b.end(), buf, buf + r);
    std::fclose(f);
    if (b.size() < 36 + 16 || *(unsigned*)&b[32] != b.size()) return false;
    unsigned char* d = &b[36];
    size_t n = b.size() - 36;
    shn_crypt(d, n);
    unsigned rc = *(unsigned*)(d + 4), cc = *(unsigned*)(d + 12);
    size_t o = 16;
    std::vector<Col> cols;
    for (unsigned c = 0; c < cc; c++) {
        if (o + 56 > n) return false;
        cols.push_back({std::string((const char*)d + o, strnlen((const char*)d + o, 48)), *(unsigned*)(d + o + 48),
                        *(int*)(d + o + 52)});
        o += 56;
    }
    for (unsigned row = 0; row < rc; row++) {
        size_t p = o + 2;                               // the row length prefix
        std::map<std::string, std::string> m;
        for (const Col& c : cols) {
            size_t len = c.type == kVarStr ? strnlen((const char*)d + p, n - p) + 1 : (size_t)c.len;
            if (p + len > n) return false;
            for (const std::string& w : want)
                if (w == c.name) m[c.name] = std::string((const char*)d + p, strnlen((const char*)d + p, len));
            p += len;
        }
        out.push_back(m);
        o = p;
    }
    return true;
}

void load_tables() {
    if (g_loaded) return;
    g_loaded = true;
    char dir[MAX_PATH];
    DWORD k = GetModuleFileNameA(nullptr, dir, MAX_PATH);
    while (k > 0 && dir[k - 1] != '\\' && dir[k - 1] != '/') k--;
    dir[k] = 0;
    std::string res = std::string(dir) + "ressystem\\";
    std::vector<std::map<std::string, std::string>> money, items;
    if (!shn_read((res + "ItemMoney.shn").c_str(), {"IM_ItemIDX", "IM_MoneyIDX"}, money)) {
        hook::log("instance_dismantle_text: cannot read %sItemMoney.shn - set pieces keep the stock count", res.c_str());
        return;
    }
    for (auto& m : money)
        if (m["IM_MoneyIDX"].compare(0, sizeof kCoinPrefix - 1, kCoinPrefix) == 0) g_piece_coin[m["IM_ItemIDX"]] = m["IM_MoneyIDX"];
    if (shn_read((res + "ItemInfo.shn").c_str(), {"InxName", "Name"}, items))
        for (auto& m : items)
            if (m["InxName"].compare(0, sizeof kCoinPrefix - 1, kCoinPrefix) == 0) g_coin_name[m["InxName"]] = m["Name"];
    hook::log("instance_dismantle_text: %u set pieces priced in %u instance coins (ItemMoney / ItemInfo)",
              (unsigned)g_piece_coin.size(), (unsigned)g_coin_name.size());
}

// ---- the count sites -----------------------------------------------------------------------------------------------
char g_coin[80];                                     // the coin the last counted item dismantles into ("" = Karis)

// the coin a piece dismantles into (its ItemMoney price is a REB_IDCoin* coin), named into g_coin; false otherwise
bool coin_of(const char* row) {
    load_tables();
    std::string inx(row + kRowInxName, strnlen(row + kRowInxName, 32));
    auto it = g_piece_coin.find(inx);
    if (it == g_piece_coin.end()) return false;
    auto nm = g_coin_name.find(it->second);
    const std::string& name = nm != g_coin_name.end() ? nm->second : it->second;
    strncpy_s(g_coin, sizeof g_coin, name.c_str(), _TRUNCATE);
    return true;
}

bool coin_of_guarded(void* item) {
    __try {
        const char* row = item ? *(const char**)((const char*)item + kItemRow) : nullptr;
        return row && coin_of(row);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

unsigned long __cdecl coin_count(void* item, unsigned long count) {
    g_coin[0] = 0;
    if (coin_of_guarded(item)) return kCoinCount;
    g_coin[0] = 0;
    return count;
}

void* g_backA = nullptr;
void* g_backB = nullptr;
void* g_backC = nullptr;
void* g_refuseC = nullptr;

#define COUNT_STUB(NAME, BACK)                                                                                         \
    __declspec(naked) void NAME() {                                                                                    \
        __asm pushad                                                                                                   \
        __asm push ebx                                                                                                 \
        __asm push esi                                                                                                 \
        __asm call coin_count                                                                                          \
        __asm add esp, 8                                                                                               \
        __asm mov [esp + 16], eax                                                                                      \
        __asm popad                                                                                                    \
        __asm mov edi, [ebp - 0xC]                                                                                     \
        __asm push ebx                                                                                                 \
        __asm push 0x952059C5                                                                                          \
        __asm jmp BACK                                                                                                 \
    }
COUNT_STUB(stub_a, g_backA)
COUNT_STUB(stub_b, g_backB)

__declspec(naked) void stub_c() {
    __asm {
        pushad
        push eax
        push esi
        call coin_count
        add esp, 8
        mov [esp + 28], eax
        popad
        test eax, eax
        jg go_on
        jmp g_refuseC
    go_on:
        jmp g_backC
    }
}

// ---- the texts -----------------------------------------------------------------------------------------------------
hook::Detour g_text;
typedef const char*(__cdecl* TextFn)(unsigned id);
char g_count_text[256];

const char* __cdecl text_impl(unsigned id) {
    if (id == kTextTitle || id == kTextButton) return kTitle;
    if (id == kTextWarning) return kWarning;
    const char* s = ((TextFn)g_text.trampoline)(id);
    if (id == kTextCount && g_coin[0]) {
        // the stock "%d Karis will be created \nwhen you dismantle this item." with the coin in place of Karis;
        // a '%' in the coin's name is doubled (the caller formats the result with the count)
        std::string esc;
        for (const char* c = g_coin; *c; c++) esc += *c == '%' ? std::string("%%") : std::string(1, *c);
        std::snprintf(g_count_text, sizeof g_count_text, "%%d %s will be created \nwhen you dismantle this item.", esc.c_str());
        return g_count_text;
    }
    return s;
}

bool jump_to(unsigned char* at, void* to, size_t cover) {
    unsigned char b[16];
    std::memset(b, 0x90, sizeof b);
    b[0] = 0xE9;
    int rel = (int)((unsigned char*)to - (at + 5));
    std::memcpy(b + 1, &rel, 4);
    return hook::write_code(at, b, cover);
}

}  // namespace

HOOK_PLUGIN("instance_dismantle_text") {
    if (const char* m = caddr::missing({caddr::kTextDataGet, caddr::kDismantleCountA, caddr::kDismantleCountB,
                                        caddr::kDismantleCountC, caddr::kDismantleRefuseC})) {
        hook::log("instance_dismantle_text: %s - not hooked", m);
        return;
    }
    if (!hook::ini_opted_in()) {
        hook::log("instance_dismantle_text.ini does not say enabled=1 - the dismantle window stays stock");
        return;
    }
    unsigned char* a = (unsigned char*)hook::rebase(caddr::va(caddr::kDismantleCountA));
    unsigned char* b = (unsigned char*)hook::rebase(caddr::va(caddr::kDismantleCountB));
    unsigned char* c = (unsigned char*)hook::rebase(caddr::va(caddr::kDismantleCountC));
    unsigned char* refuse = (unsigned char*)hook::rebase(caddr::va(caddr::kDismantleRefuseC));
    if (std::memcmp(a, kStockAB, sizeof kStockAB) || std::memcmp(b, kStockAB, sizeof kStockAB) ||
        std::memcmp(c, kStockC, sizeof kStockC) || c[2] != 0x0F || c[3] != 0x8E || c + 8 + *(int*)(c + 4) != refuse) {
        hook::log("instance_dismantle_text: unexpected bytes at a count site - NOT patched");
        return;
    }
    g_backA = a + sizeof kStockAB;
    g_backB = b + sizeof kStockAB;
    g_backC = c + 8;
    g_refuseC = refuse;
    if (!hook::hook_function("TextData lookup (dismantle texts)", hook::rebase(caddr::va(caddr::kTextDataGet)),
                             (void*)text_impl, &g_text))
        return;
    if (jump_to(a, (void*)stub_a, sizeof kStockAB) && jump_to(b, (void*)stub_b, sizeof kStockAB) &&
        jump_to(c, (void*)stub_c, 8))
        hook::log("instance_dismantle_text: enabled - instance set pieces preview / dismantle as %lu of their coin",
                  kCoinCount);
}
