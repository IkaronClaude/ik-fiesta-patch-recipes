// piggyback_drops - an item that DROPS brings its PIGGYBACK item with it (Fiesta2026on2016, operator 2026-10-08 P2:
// "a plugin that allows us to piggyback drops: if Male drops a sword, sword has knight shield as piggyback item, so
// when it is rolled, the shield is also dropped"; "just use a new server side .txt shine table").
//
// ---- DATA ----------------------------------------------------------------------------------------------------------------
//   9Data/Shine/Script/ItemDropTogether.txt, read with the zone's own OptionReader (no side format):
//     #table       ItemDropTogether
//     #columntype  INDEX   STRING[64]
//     #columnname  ItemIDX TogetherIDX
//     #record      B_CrackerAndrasSword    B_CrackerAndrasShield
//   A row is packed: the INDEX token (20 bytes) then the string (64) - the layout of every OptionReader row
//   (NPCManager__LinkInformTemplete: index[20], linktoserver[33], ...). No file = the plugin is off (parity).
//
// ---- THE STOCK CODE (read from Zone.exe) ----------------------------------------------------------------------------------
//   Every item put on the ground goes through ShineObject::so_IsDropping (0x4B0A20): the mob loot roll
//   (ItemDropFromMob::DropItemListInGroup::dilig_Drop 0x48E529), KQ drops, Pine script drops and Lua cDropItem.
//   cDropItem (0x5D9A30) shows how an item is MADE from its id before that call:
//     iti_clear; iti_mkregnum(id, 3, worlddata+0x10, worlddata+0xC); iti+8 = id;
//     attr = ItemAttributeClassContainer[id]; attr->vfunc(+0x2C)(&iti, &param, rand(1000), dropper->vfunc(+0x708)())
//       (param: 0x60 bytes, zero but +0x3C = 0x10001);
//     options: ItemDataBox[id]->(+4)->+0x89 is the RandomOption name; attr->vfunc(+0x70)(&iti+8) is the storage;
//       RandomOptionTable::rot_FillOption(storage, datum);
//     dropper->so_IsDropping(&iti, db, handle, owner handle, owner regnum, attr, 0).
//
// ---- THIS PLUGIN ---------------------------------------------------------------------------------------------------------
//   Detours so_IsDropping. After a SUCCESSFUL drop of an item that has a piggyback, it makes the piggyback item exactly
//   as cDropItem makes one and drops it through the same call with the same owner / handle / database, so it lands
//   beside the first and belongs to the same looter. A piggyback is never itself piggybacked (no chains, no loops).
#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <map>

namespace {
using namespace zone::types;

const char kFile[] = "../9Data/Shine/Script/ItemDropTogether.txt";   // beside its collab template (ETC_Script)
const char kTable[] = "ItemDropTogether";
const unsigned kVtLevel = 0x708;              // ShineObject: the level an item's attributes are made at (cDropItem 0x5D9D5A)
const unsigned kVtAttrCreate = 0x2C;          // ItemAttributeClass: make the item's attributes (cDropItem 0x5D9D80)
const unsigned kVtAttrOptions = 0x70;         // ItemAttributeClass: the item's option storage (cDropItem 0x5D9DD6)
const unsigned kRowRandomOption = 0x89;       // the ItemInfo row (ItemDataBoxIndex +4): RandomOption name
const unsigned kParamFlags = 0x3C;            // cDropItem's create param: 0x10001 at +0x3C, the rest zero

zone::Detour g_drop;
std::map<unsigned short, unsigned short> g_piggy;
bool g_loaded = false, g_in = false;
alignas(8) unsigned char g_reader[sizeof(OptionReader)];
unsigned g_seed = 0;

typedef unsigned char(__fastcall* DropFn)(void*, void*, ItemTotalInformation*, ShineObjectClass__DataBase, void*,
                                          unsigned short, unsigned long, ItemAttributeClass*, int);
typedef unsigned short(__fastcall* LevelFn)(void*, void*);
typedef unsigned char(__fastcall* CreateFn)(void*, void*, ItemTotalInformation*, void*, unsigned, unsigned);
typedef ItemOptionStorage*(__fastcall* OptFn)(void*, void*, void*);

template <class F> F vfn(void* obj, unsigned off) { return *(F*)(*(unsigned char**)obj + off); }

unsigned rnd(unsigned n) {                    // xorshift; only feeds the attribute roll (the stock passes rand(1000))
    if (!g_seed) g_seed = GetTickCount() | 1;
    g_seed ^= g_seed << 13; g_seed ^= g_seed >> 17; g_seed ^= g_seed << 5;
    return g_seed % n;
}

unsigned short item_id(const char* inx) {
    return zone::fn::ItemDataBox__idb_2itemid()(zone::global::itemdatabox(), 0, (unsigned char*)inx);
}

// the table, once, on the first drop (the item table is loaded by then; plugins start before it)
void load() {
    g_loaded = true;
    zone::fn::OptionReader__OptionReader()(g_reader, 0);
    if (!zone::fn::OptionReader__or_Read()(g_reader, 0, (char*)kFile)) {
        zone::log("piggyback_drops: no %s - off", kFile);
        return;
    }
    ORToken table;
    zone::fn::ORToken__ORToken()(&table, 0, (char*)kTable);
    int bad = 0;
    for (int i = 0; i < 65536; ++i) {
        auto* row = (unsigned char*)zone::fn::OptionReader__or_SelectFromOrder()(g_reader, 0, table, i);
        if (!row) break;
        char a[24] = {0}, b[65] = {0};
        zone::fn::ORToken__ort_GetString()(row, 0, a);
        std::memcpy(b, row + 20, 64);
        unsigned short ia = item_id(a), ib = item_id(b);
        if (ia == 0xFFFF || ib == 0xFFFF) {
            zone::log("piggyback_drops: row %d %s -> %s: unknown item - skipped", i, a, b);
            ++bad;
            continue;
        }
        g_piggy[ia] = ib;
    }
    zone::log("piggyback_drops: %u piggyback(s) from %s (%d bad row(s))", (unsigned)g_piggy.size(), kFile, bad);
}

// make item `id` as cDropItem does and drop it like the item it rides on
void drop_piggyback(void* dropper, unsigned short id, ShineObjectClass__DataBase db, void* handle, unsigned short owner,
                    unsigned long owner_reg, int a7, unsigned short rider) {
    ItemTotalInformation iti;
    zone::fn::ItemTotalInformation__iti_clear()(&iti, 0);
    auto* wd = (unsigned char*)zone::fn::ZoneServer__zs_worlddata()(zone::global::zoneserver(), 0);
    zone::fn::ItemTotalInformation__iti_mkregnum()(&iti, 0, id, 3, *(int*)(wd + 0x10), *(int*)(wd + 0xC));
    *(unsigned short*)((unsigned char*)&iti + 8) = id;
    auto* attr = zone::fn::ItemAttributeClassContainer__operator__()(zone::global::itmattcontainer(), 0, id);
    if (!attr) { zone::log("piggyback_drops: %u has no attribute class - not dropped", id); return; }
    unsigned char param[0x60] = {0};
    *(unsigned*)(param + kParamFlags) = 0x10001;
    unsigned lv = vfn<LevelFn>(dropper, kVtLevel)(dropper, 0);
    if (!vfn<CreateFn>(attr, kVtAttrCreate)(attr, 0, &iti, param, rnd(1000), lv)) {
        zone::log("piggyback_drops: %u - attribute create refused, not dropped", id);
        return;
    }
    if (auto* idx = (unsigned char*)zone::fn::ItemDataBox__operator__()(zone::global::itemdatabox(), 0, id)) {
        auto* info = *(unsigned char**)(idx + 4);
        if (info) {
            auto* table = zone::global::itemrandomoptiontable();
            auto* datum = zone::fn::ItemRandomOption__RandomOptionTable__operator__()(table, 0, (char*)(info + kRowRandomOption));
            auto* storage = vfn<OptFn>(attr, kVtAttrOptions)(attr, 0, (unsigned char*)&iti + 8);
            if (datum && storage) zone::fn::ItemRandomOption__RandomOptionTable__rot_FillOption()(table, 0, storage, datum);
        }
    }
    unsigned char ok = ((DropFn)g_drop.trampoline)(dropper, 0, &iti, db, handle, owner, owner_reg, attr, a7);
    zone::log("piggyback_drops: %u rode on %u - %s", id, rider, ok ? "dropped" : "drop REFUSED");
}

unsigned char __fastcall drop_hook(void* self, void* edx, ItemTotalInformation* iti, ShineObjectClass__DataBase db,
                                   void* handle, unsigned short owner, unsigned long owner_reg, ItemAttributeClass* attr,
                                   int a7) {
    unsigned char ok = ((DropFn)g_drop.trampoline)(self, edx, iti, db, handle, owner, owner_reg, attr, a7);
    if (!ok || g_in || !iti || !self) return ok;
    if (!g_loaded) load();
    if (g_piggy.empty()) return ok;
    unsigned short id = *(unsigned short*)((unsigned char*)iti + 8);
    auto it = g_piggy.find(id);
    if (it == g_piggy.end()) return ok;
    g_in = true;
    drop_piggyback(self, it->second, db, handle, owner, owner_reg, a7, id);
    g_in = false;
    return ok;
}

}  // namespace

ZONEHOOK_PLUGIN("piggyback_drops") {
    zone::hook_function("ShineObject::so_IsDropping (an item drops its piggyback too)",
                        (void*)zone::fn::ShineObjectClass__ShineObject__so_IsDropping(), (void*)drop_hook, &g_drop);
    zone::log("piggyback_drops: up - reads %s on the first drop", kFile);
}
