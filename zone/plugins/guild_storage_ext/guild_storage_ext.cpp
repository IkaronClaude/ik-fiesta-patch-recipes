// guild_storage_ext - guild storage beyond the 2016 zone's 72 cells, 36 per page like the 2026 client's window
// (operator 2026-09-29: "do guild storage"; ChargedEffect 43 "Small / Large Guild Storage Box" = +1 / +2 pages).
//
// ---- THE STOCK CODE (read from Zone.exe + Zone.pdb) --------------------------------------------------------------------
//   The guild storage is GuildAcademyRewardStorageElement (one per guild, kept BY VALUE in a List - operator= copies it):
//     +0x0000  ItemGuildAcademyRewardStorage  vftable + ItemInventoryCell igars_Array[72]   (sizeof 8356)
//     +0x20A8  money u64    +0x20B0  guild number    +0x20B4  active flag
//   ItemGuildAcademyRewardStorage's vtable (0x70AEFC): [0] ib_GetInventoryCell(int) = 0x643000 (shared with other bags:
//   `i < this->vtbl[2]() ? this + 4 + i * 0x74 : 0`), [1] ib_BagSizeInput, [2] ib_BagSizeOutput = `return 0x48`. Every
//   ItemBag helper (clear, count, fill, the open list) walks the bag through [0] and [2], and the Character DB procs take
//   any slot number - so the size is these two slots.
//
// ---- THIS PLUGIN -------------------------------------------------------------------------------------------------------
//   Replaces vtable slots [0] and [2] of ItemGuildAcademyRewardStorage only (0x643000 itself stays - other bags use it):
//     size(guild)            = 72 + 36 * pages(guild)
//     cell(i), i < 72        = the stock cell
//     cell(i), 72 <= i < size = a side cell of that GUILD (keyed by the guild number at +0x20B0, since elements are
//                               copied), constructed with the zone's own ItemInventoryCell constructor (0x6447B0)
//   pages(guild) = hooks\guild_storage_ext.ini [config] pages=N for every guild (0 = stock 72; QoL / Avocado can give
//   every guild the maximum). The per-guild boxes (ChargedEffect 43) come on top in the next step.
#include <zonehook.h>

#include <map>

namespace {

const unsigned kVaVtable = 0x0070AEFCu;          // ItemGuildAcademyRewardStorage::`vftable'
const unsigned kVaGetCell = 0x00643000u;         // stock [0] (checked before patching)
const unsigned kVaSizeOut = 0x00643360u;         // stock [2] (checked)
const unsigned kVaCellCtor = 0x006447B0u;        // ItemInventoryCell::ItemInventoryCell(), thiscall
const int kStockCells = 72;
const int kPageCells = 36;
const int kCellSize = 0x74;
const unsigned kOffGuild = 0x20B0;               // the element's guild number (the bag is at element +0)
const int kMaxPages = 8;

int g_pages = 0;                                 // every guild's extra pages (ini)
std::map<unsigned, unsigned char*> g_side;      // guild -> its cells past 72: kMaxPages pages, allocated ONCE and never
                                                // moved (the zone keeps cell pointers), never freed (guilds are few)

int pages_of(unsigned /*guild*/) { return g_pages; }

int __fastcall size_out(void* bag, void*) {
    return kStockCells + kPageCells * pages_of(*(unsigned*)((char*)bag + kOffGuild));
}

unsigned char* side_cells(unsigned guild) {
    unsigned char*& v = g_side[guild];
    if (!v) {
        const int n = kMaxPages * kPageCells;
        v = new unsigned char[(size_t)n * kCellSize];
        typedef void(__fastcall * Ctor)(void*, void*);
        for (int k = 0; k < n; ++k) ((Ctor)zone::rebase(kVaCellCtor))(v + (size_t)k * kCellSize, nullptr);
    }
    return v;
}

void* __fastcall get_cell(void* bag, void*, int i) {
    if (i < 0) return nullptr;
    if (i < kStockCells) return (char*)bag + 4 + i * kCellSize;
    const unsigned guild = *(unsigned*)((char*)bag + kOffGuild);
    if (i >= kStockCells + kPageCells * pages_of(guild)) return nullptr;
    return side_cells(guild) + (size_t)(i - kStockCells) * kCellSize;
}

}  // namespace

ZONEHOOK_PLUGIN("guild_storage_ext") {
    g_pages = hook::config_int("pages", 0);
    if (g_pages < 0) g_pages = 0;
    if (g_pages > kMaxPages) g_pages = kMaxPages;
    void** vt = (void**)zone::rebase(kVaVtable);
    if (vt[0] != zone::rebase(kVaGetCell) || vt[2] != zone::rebase(kVaSizeOut)) {
        zone::log("guild_storage_ext: ItemGuildAcademyRewardStorage's vtable is not the expected one - stock 72 cells");
        return;
    }
    void* cell = (void*)get_cell;
    void* size = (void*)size_out;
    if (!zone::write_code(&vt[0], &cell, 4) || !zone::write_code(&vt[2], &size, 4)) return;
    zone::log("guild_storage_ext: guild storage = %d cells (72 + %d page(s) of 36) for every guild", kStockCells + kPageCells * g_pages,
              g_pages);
}
