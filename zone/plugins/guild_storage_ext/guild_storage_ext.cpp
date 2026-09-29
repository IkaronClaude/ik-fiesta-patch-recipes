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
//   every guild the maximum).
//
// ---- THE STORAGE BOXES (ChargedEffect 43) ------------------------------------------------------------------------------
//   GuildStorageIncrease1_* (Small, EffectValue 1) / 2_* (Large, 2), timed or permanent. The 2026 client greys the
//   window's pages past 2 unless the VIEWING player has enum-43 charged effects active - "like inventory" (operator
//   2026-09-29): it is a charged buff of the player, as the Iron Case's enum 2 is. The 2016 zone refuses to USE any
//   charged item past enum 38: UseItemChargedBuff::uib_CanUseItem switches on EffectEnum (`cmp eax, 0x26; ja -> 0x713`
//   "no effect when used"). Everything after that check is enum-agnostic (so_ply_ChargedBuff consumes the item, dates
//   it, adds the list element, saves it and sends 0x9003; the login list 0x104A carries it back) - see void_bag, which
//   does the same for enum 45. So this plugin answers the check for enum 43: allowed while the player's active enum-43
//   pages + the item's value stay within the pages the server holds (pages= above), else 0x713.
//   NOT ENFORCED SERVER-SIDE: which of the server's pages a player may put items in - the client's greying is the gate.
#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cstddef>
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

// ---- the storage boxes --------------------------------------------------------------------------------------------------
const int kEffectGuildStorage = 43;             // the 2026 ChargedEffect table's enum for both boxes
const unsigned short kUseOk = 0x700;            // uib_CanUseItem's two answers
const unsigned short kUseNoEffect = 0x713;

// chargedbuffdatabox's array: {u16 item id, u16 pad, ChargedItemEffect*} per entry (uib_CanUseItem walks it in 8s)
struct ChargedBuffEntry { unsigned short item, pad; const zone::types::ChargedItemEffect* effect; };
static_assert(sizeof(ChargedBuffEntry) == 8, "the zone walks this table in 8-byte steps");

const zone::types::ChargedItemEffect* charged_effect_of(unsigned short item_id) {
    const auto* box = zone::global::chargedbuffdatabox();
    auto* arr = (const ChargedBuffEntry*)box->cideb_Array;
    for (int i = 0; arr && i < box->cideb_Total; i++)
        if (arr[i].item == item_id) return arr[i].effect;
    return nullptr;
}

// The player's active enum-43 pages: ChargedItem::ci_List sits right before the container so_ply_ChargedEffectContainer
// returns (as void_bag reads it).
int box_pages(void* player) {
    using ChargedItem = zone::types::ChargedItemEffectList__ChargedItem;
    const void* c = player ? zone::fn::ShineObjectClass__ShinePlayer__so_ply_ChargedEffectContainer()(player, 0) : nullptr;
    if (!c) return 0;
    auto* item = (const ChargedItem*)((const char*)c - offsetof(ChargedItem, ci_Effect));
    int pages = 0;
    for (const auto& el : item->ci_List.cel_Effect)
        if (el.ciee_Index && (int)el.ciee_Index->EffectEnum == kEffectGuildStorage) pages += el.ciee_Index->EffectValue;
    return pages;
}

zone::Detour g_canuse;

unsigned short __fastcall can_use(void* self, void*, void* player, void* itemp) {
    auto* item = (const zone::types::ItemTotalInformation*)itemp;
    const zone::types::ChargedItemEffect* eff = item ? charged_effect_of(item->iti_itemstruct.itemid) : nullptr;
    if (eff && (int)eff->EffectEnum == kEffectGuildStorage) {
        const int have = box_pages(player);
        const unsigned short r = have + (int)eff->EffectValue <= g_pages ? kUseOk : kUseNoEffect;
        zone::log("guild storage box %u: player %x has %d page(s), +%u of %d -> %s", (unsigned)item->iti_itemstruct.itemid,
                  player, have, (unsigned)eff->EffectValue, g_pages, r == kUseOk ? "ALLOWED" : "refused, at the maximum");
        return r;
    }
    return ((unsigned short(__fastcall*)(void*, void*, void*, void*))g_canuse.trampoline)(self, nullptr, player, itemp);
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
    if (g_pages > 0)
        zone::hook_function("UseItemChargedBuff::uib_CanUseItem (guild storage boxes, enum 43)",
                            (void*)zone::fn::UseEffect__UseItemChargedBuff__uib_CanUseItem(), (void*)can_use, &g_canuse);
}
