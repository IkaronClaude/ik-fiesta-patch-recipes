// shop_random_option - gear BOUGHT from an NPC for cen rolls its random options like a dropped one (Fiesta2026on2016,
// operator 2026-09-27 P2: "a hook that auto rolls randomoption weapons etc. on purchase" - for the Rebalanced reward
// selector NPCs, which would otherwise sell flat items).
//
// ---- THE STOCK CODE (read from Zone.exe) ------------------------------------------------------------------------------
//   Every item-creation path rolls options with ItemRandomOption::RandomOptionTable::rot_FillOption (0x493590):
//   drops, &makeitem, Mystery Vaults, treasure chests, quest rewards, Lua rewards and the ITEM-MONEY (coin) shop
//   ItemInventory::ii_ItemMoneyBuyAll (0x525BDC..0x525C11):
//       datum   = RandomOptionTable[0x0D6249D4] [ ItemInfoServer.RandomOptionDropGroup (index->dataserv +0x89) ]
//       storage = ItemAttributeClass (ItemAttributeClassContainer 0x150BA478 [item id]) ->vtable +0x70 (&attr)
//       if (datum && storage) rot_FillOption(storage, datum)
//   just before ItemTotalInformation::iti_mkregnum stamps the new item. The CEN shop, ItemInventory::ii_BuyAll
//   (0x523CE0), builds the same ItemTotalInformation (at ebp-0x80, its attribute at +8) and stamps it at 0x523E4C
//   WITHOUT the roll - so a bought weapon is always flat.
//
// ---- THIS PLUGIN -----------------------------------------------------------------------------------------------------
//   Detours iti_mkregnum (0x640710); when the caller is ii_BuyAll's stamp (return address 0x523E51) and the item is
//   listed in the flag file, it runs the coin shop's three steps on the item first. Every other caller is untouched
//   (they roll already). An item with no RandomOptionDropGroup ('-', no datum) stays flat, as when dropped.
//
// Gameplay, not parity - stock shops stay stock: active only for the items named in 9Data/Shine/ShopRandomOption.flag
// (one ItemInfo InxName per line; '*' = every item that rolls when dropped). A variant step that lays a shop whose
// goods should roll writes that list. No flag file, or an empty one = nothing changes.
#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <intrin.h>

#include <cstdio>
#include <cstring>
#include <set>
#include <string>

namespace {

const char* kFlag = "../9Data/Shine/ShopRandomOption.flag";
const unsigned kVaBuyStampReturn = 0x00523E51u;      // ii_BuyAll, the instruction after `call iti_mkregnum`
const unsigned kVaRandomOptionTable = 0x0D6249D4u;   // mov ecx, 0xd6249d4 at every rot_FillOption call
const unsigned kVaAttributeClasses = 0x150BA478u;    // mov ecx, 0x150ba478 at every attribute-class lookup
const unsigned kAttrOffset = 8;                      // ItemTotalInformation -> its attribute block
const unsigned kOptionStorageSlot = 0x70;            // ItemAttributeClass vtable: attr -> ItemOptionStorage*

zone::Detour g_stamp;
std::set<std::string> g_items;
bool g_all = false;
unsigned g_rolled = 0;

bool wanted(const char* inx) { return g_all || g_items.count(inx) != 0; }

void roll(void* iti, unsigned short item) {
    auto* idx = zone::fn::ItemDataBox__operator__()(zone::global::itemdatabox(), nullptr, item);
    if (!idx || !idx->data || !idx->dataserv || !wanted(idx->data->InxName)) return;
    char group[34];
    std::strncpy(group, idx->dataserv->RandomOptionDropGroup, sizeof group - 1);
    group[sizeof group - 1] = 0;
    if (!group[0] || !std::strcmp(group, "-")) return;
    void* table = zone::rebase(kVaRandomOptionTable);
    auto* datum = zone::fn::ItemRandomOption__RandomOptionTable__operator__()(table, nullptr, group);
    auto* cls = zone::fn::ItemAttributeClassContainer__operator__()(zone::rebase(kVaAttributeClasses), nullptr, item);
    if (!datum || !cls) return;
    typedef void*(__fastcall * StorageOf)(void*, void*, void*);
    void* storage = ((StorageOf)(*(void***)cls)[kOptionStorageSlot / 4])((void*)cls, nullptr, (char*)iti + kAttrOffset);
    if (!storage) return;
    zone::fn::ItemRandomOption__RandomOptionTable__rot_FillOption()(table, nullptr, (zone::types::ItemOptionStorage*)storage, datum);
    if (++g_rolled <= 20 || g_rolled % 100 == 0)
        zone::log("shop_random_option: bought %s rolled from %s (%u so far)", idx->data->InxName, group, g_rolled);
}

void __fastcall stamp(void* iti, void*, unsigned short item, int a, int b, int c) {
    if ((unsigned)_ReturnAddress() == (unsigned)zone::rebase(kVaBuyStampReturn)) roll(iti, item);
    ((void(__fastcall*)(void*, void*, unsigned short, int, int, int))g_stamp.trampoline)(iti, nullptr, item, a, b, c);
}

bool load() {
    FILE* f = std::fopen(kFlag, "r");
    if (!f) return false;
    char line[128];
    while (std::fgets(line, sizeof line, f)) {
        char* p = line + std::strspn(line, " \t");
        p[std::strcspn(p, "\r\n \t#")] = 0;
        if (!*p) continue;
        if (!std::strcmp(p, "*")) g_all = true;
        else g_items.insert(p);
    }
    std::fclose(f);
    return g_all || !g_items.empty();
}

}  // namespace

ZONEHOOK_PLUGIN("shop_random_option") {
    if (!load()) {
        zone::log("shop_random_option: no %s (or it names nothing) - bought gear stays flat (stock)", kFlag);
        return;
    }
    zone::hook_function("ItemTotalInformation::iti_mkregnum 0x640710 (cen-shop goods roll random options)",
                        zone::rebase(0x00640710u), (void*)stamp, &g_stamp);
    zone::log("shop_random_option: %s - %s roll random options when bought", kFlag,
              g_all ? "every item that rolls when dropped" : (std::to_string(g_items.size()) + " listed item(s)").c_str());
}
