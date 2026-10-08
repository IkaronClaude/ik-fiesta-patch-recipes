// piggyback_drops - an item that DROPS brings its PIGGYBACK item with it (Fiesta2026on2016, operator 2026-10-08 P2:
// "a plugin that allows us to piggyback drops: if Male drops a sword, sword has knight shield as piggyback item, so
// when it is rolled, the shield is also dropped"; "just use a new server side .txt shine table").
//
// ---- DATA ----------------------------------------------------------------------------------------------------------------
//   9Data/Shine/ItemDropTogether.txt, read with the zone's own OptionReader (no side format):
//     #table       ItemDropTogether
//     #columntype  STRING[33] STRING[33] DWRD  STRING[33] DWRD  STRING[33] DWRD
//     #columnname  ItemIDX Together1  Rate1 Together2  Rate2 Together3  Rate3
//     #record      B_CrackerAndrasSword    B_CrackerAndrasShield 1000000 - 0 - 0
//   Up to three partners per item (operator 2026-10-08 P5 "multi-piggyback (1 item leads to 2 others)"), each with its
//   own chance out of 1,000,000 (P5 "percentage chance piggyback ... build it ready"; 1000000 = always, 0 = never - a real
//   value, not "unset"); '-' = no partner. A row is PACKED, no alignment - the layout of every OptionReader row
//   (NPCManager__LinkInformTemplete: index[20], linktoserver[33], linktoclient[33], coordx DWRD at 86, sizeof 97).
//   No file = the plugin is off (parity).
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
#include <vector>

namespace {
using namespace zone::types;

const char kFile[] = "../9Data/Shine/ItemDropTogether.txt";
const int kPartners = 3;
const unsigned kRate100 = 1000000;
// packed row offsets: ItemIDX STRING[33] (an INDEX column holds only 20 bytes - "B_CrackerAscalonHammer" read as
// "B_CrackerAscalonHamm" and the Kellon Hammer never brought its shield, operator 2026-10-08), then per partner
// STRING[33] + DWRD (37)
const unsigned kRowFirst = 33, kPartnerStride = 37, kNameLen = 33;
const char kTable[] = "ItemDropTogether";
const unsigned kVtLevel = 0x708;              // ShineObject: the level an item's attributes are made at (cDropItem 0x5D9D5A)
const unsigned kVtAttrCreate = 0x2C;          // ItemAttributeClass: make the item's attributes (cDropItem 0x5D9D80)
const unsigned kVtAttrOptions = 0x70;         // ItemAttributeClass: the item's option storage (cDropItem 0x5D9DD6)
const unsigned kRowRandomOption = 0x89;       // the ItemInfo row (ItemDataBoxIndex +4): RandomOption name
const unsigned kParamFlags = 0x3C;            // cDropItem's create param: 0x10001 at +0x3C, the rest zero

zone::Detour g_drop;
struct Partner { unsigned short id; unsigned rate; char name[kNameLen + 1]; };
std::map<unsigned short, std::vector<Partner>> g_piggy;
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
        char a[kNameLen + 1] = {0};
        std::memcpy(a, row, kNameLen);
        unsigned short ia = item_id(a);
        if (ia == 0xFFFF) { zone::log("piggyback_drops: row %d: unknown item %s - skipped", i, a); ++bad; continue; }
        for (int k = 0; k < kPartners; ++k) {
            const unsigned char* f = row + kRowFirst + k * kPartnerStride;
            char b[kNameLen + 1] = {0};
            std::memcpy(b, f, kNameLen);
            if (!b[0] || (b[0] == '-' && !b[1])) continue;
            unsigned rate = *(const unsigned*)(f + kNameLen);
            unsigned short ib = item_id(b);
            if (ib == 0xFFFF) { zone::log("piggyback_drops: row %d %s: unknown partner %s - skipped", i, a, b); ++bad; continue; }
            Partner pt = {ib, rate > kRate100 ? kRate100 : rate, {0}};
            std::memcpy(pt.name, b, kNameLen);
            g_piggy[ia].push_back(pt);
        }
    }
    unsigned n = 0;
    for (auto& kv : g_piggy) n += (unsigned)kv.second.size();
    zone::log("piggyback_drops: %u item(s), %u partner(s) from %s (%d bad)", (unsigned)g_piggy.size(), n, kFile, bad);
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

// ---- REWARDS: lists (cRewardItem / cRewardItem_AllInMap / the slot machine), containers (sp_MagicContainerMake: a
// box the shop or &makeitem makes) and KQ boxes (sp_KQReward) - operator 2026-10-08 P5 "expand item piggyback to kq
// rewards, chest rewards, vault items, etc. Basically everywhere it can be acquired". A reward item is MADE the way
// cRewardItem (0x5E17E0) makes one: attr->vfunc(+0x14)(id, &iti, "-o"); iti_mkregnum(id, 0xB, worlddata+0x10, +0xC);
// attr->vfunc(+0x20)(&iti+8, lot); then the random options as for a drop.
const unsigned kVtAttrInit = 0x14, kVtAttrLot = 0x20;
zone::Detour g_ilm, g_tcm, g_tcm2;
typedef unsigned short(__fastcall* MakeFn)(void*, void*, ItemTotalInformation*);
typedef unsigned short(__fastcall* KqMakeFn)(void*, void*, int, ShineReward*, unsigned long);
typedef void(__fastcall* InitFn)(void*, void*, unsigned short, ItemTotalInformation*, const char*);
typedef void(__fastcall* LotFn)(void*, void*, void*, unsigned);
char g_tag[] = "-o";

bool make_reward_item(unsigned short id, ItemTotalInformation& iti) {
    zone::fn::ItemTotalInformation__iti_clear()(&iti, 0);
    auto* attr = zone::fn::ItemAttributeClassContainer__operator__()(zone::global::itmattcontainer(), 0, id);
    if (!attr) return false;
    vfn<InitFn>(attr, kVtAttrInit)(attr, 0, id, &iti, g_tag);
    auto* wd = (unsigned char*)zone::fn::ZoneServer__zs_worlddata()(zone::global::zoneserver(), 0);
    zone::fn::ItemTotalInformation__iti_mkregnum()(&iti, 0, id, 0xB, *(int*)(wd + 0x10), *(int*)(wd + 0xC));
    vfn<LotFn>(attr, kVtAttrLot)(attr, 0, (unsigned char*)&iti + 8, 1);
    if (auto* idx = (unsigned char*)zone::fn::ItemDataBox__operator__()(zone::global::itemdatabox(), 0, id)) {
        auto* info = *(unsigned char**)(idx + 4);
        if (info) {
            auto* table = zone::global::itemrandomoptiontable();
            auto* datum = zone::fn::ItemRandomOption__RandomOptionTable__operator__()(table, 0, (char*)(info + kRowRandomOption));
            auto* storage = vfn<OptFn>(attr, kVtAttrOptions)(attr, 0, (unsigned char*)&iti + 8);
            if (datum && storage) zone::fn::ItemRandomOption__RandomOptionTable__rot_FillOption()(table, 0, storage, datum);
        }
    }
    return true;
}

const std::vector<Partner>* partners_of(unsigned short id) {
    if (!g_loaded) load();
    auto it = g_piggy.find(id);
    return it == g_piggy.end() ? nullptr : &it->second;
}
bool rolls(const Partner& pt) { return pt.rate >= kRate100 || rnd(kRate100) < pt.rate; }

// a list or container that took a made item: add its partners the same way
unsigned short list_add(zone::Detour& d, const char* what, void* self, void* edx, ItemTotalInformation* iti) {
    unsigned short r = ((MakeFn)d.trampoline)(self, edx, iti);
    if (r == 0xFFFF || g_in || !iti) return r;
    unsigned short id = *(unsigned short*)((unsigned char*)iti + 8);
    auto* list = partners_of(id);
    if (!list) return r;
    g_in = true;
    for (const Partner& pt : *list) {
        if (!rolls(pt)) continue;
        ItemTotalInformation p;
        bool ok = make_reward_item(pt.id, p) && ((MakeFn)d.trampoline)(self, edx, &p) != 0xFFFF;
        zone::log("piggyback_drops: %u rode on %u into a %s - %s", pt.id, id, what, ok ? "added" : "NOT added");
    }
    g_in = false;
    return r;
}
unsigned short __fastcall ilm_hook(void* self, void* edx, ItemTotalInformation* iti) { return list_add(g_ilm, "reward", self, edx, iti); }
unsigned short __fastcall tcm_hook(void* self, void* edx, ItemTotalInformation* iti) { return list_add(g_tcm, "container", self, edx, iti); }

// a KQ box: the reward names its item; the partner goes in as the same reward naming the partner, quantity 1
const unsigned char kRewardItem = 1;
unsigned short __fastcall tcm2_hook(void* self, void* edx, int type, ShineReward* rw, unsigned long who) {
    unsigned short r = ((KqMakeFn)g_tcm2.trampoline)(self, edx, type, rw, who);
    if (r == 0xFFFF || g_in || !rw || rw->RewardType != kRewardItem) return r;
    auto* list = partners_of(item_id(rw->Argument));
    if (!list) return r;
    g_in = true;
    for (const Partner& pt : *list) {
        if (!rolls(pt)) continue;
        ShineReward p = *rw;
        std::memset(p.Argument, 0, sizeof p.Argument);
        std::memcpy(p.Argument, pt.name, sizeof p.Argument - 1);
        p.Quantity = 1;
        std::memset(p.Upgrade, 0, sizeof p.Upgrade);
        bool ok = ((KqMakeFn)g_tcm2.trampoline)(self, edx, type, &p, who) != 0xFFFF;
        zone::log("piggyback_drops: %s rode on %.33s into a KQ box - %s", pt.name, rw->Argument, ok ? "added" : "NOT added");
    }
    g_in = false;
    return r;
}

// ---- NPC PURCHASES (hooks\piggyback_drops.ini [config] npc_buy=1; OFF by default - operator 2026-10-08 "except npc
// purchases - or that could be cool, maybe build it but default disabled via hook ini"). ItemInventory::ii_BuyAll
// (0x523CE0) builds the bought item inline - no maker to hook - and is void; it calls CCharacterTitleZone::CT_BuyNPC
// (0x5CC020, at 0x5241A6) only at the end of a SUCCESSFUL buy, so that call is the success marker. The partner is then
// GIVEN the way Lua cRewardItem (0x5E17E0..0x5E1B05) gives an item, step for step:
//   buf = *(ProtocolPacket 0x84D908); buf+0 = 0x344D; buf+0xE = the char no (*(*(player+0x7A)+0x10)); buf+0x10/+0x14 = 0
//   make the item (make_reward_item); ItemListMaker lm(2); lm.ilm_ItemMake(&iti); n = lm.ilm_PutInto(buf+0x18, 0, 0, 2)
//   buf+8 = buf+4 = player->vfunc(+0x344)(); buf+2 = player+4 (the handle);
//   buf+0xC = so_GetZoneHandle_ItemLooter(player->vfunc(+0x7D4)() = its cell lock)
//   if pp_SetPacketLen(n + 0x19) -> pp_SendPacket(the DB session, bundle 0x14D454B8); lock->vfunc(+0x48)(buf+0xC, 0, 0, 1);
//   icl_IncIndex(lock); ~ItemListMaker
// The player checks cRewardItem makes first: vfunc(+0x300)() != 1, vfunc(+0x4D0)() == 2, *(player+0x7A) != 0.
const unsigned kVaPacket = 0x84D908, kVaDbBundle = 0x14D454B8;
const unsigned short kOpItemCreate = 0x344D;
const unsigned kVtGone = 0x300, kVtKind = 0x4D0, kVtRegnum = 0x344, kVtCellLock = 0x7D4, kVtLockMark = 0x48;
const unsigned kOffCharData = 0x7A;
const unsigned char kKindPlayer = 2;
bool g_npc_buy = false;
zone::Detour g_buy, g_title;
void* g_buyer = nullptr;
unsigned short g_buy_id = 0xFFFF;
bool g_bought = false;

typedef unsigned char(__fastcall* ByteFn)(void*, void*);
typedef unsigned(__fastcall* DwordFn)(void*, void*);
typedef void*(__fastcall* PtrFn)(void*, void*);
typedef void(__fastcall* MarkFn)(void*, void*, unsigned short, int, int, int);

bool give_item(void* player, unsigned short id) {
    if (vfn<ByteFn>(player, kVtGone)(player, 0) == 1 || vfn<ByteFn>(player, kVtKind)(player, 0) != kKindPlayer) return false;
    auto* chr = *(unsigned char**)((unsigned char*)player + kOffCharData);
    if (!chr) return false;
    ItemTotalInformation iti;
    if (!make_reward_item(id, iti)) return false;
    void* pkt = zone::rebase(kVaPacket);
    auto* buf = *(unsigned char**)pkt;
    *(unsigned short*)buf = kOpItemCreate;
    *(unsigned short*)(buf + 0xE) = **(unsigned short**)(chr + 0x10);
    *(unsigned*)(buf + 0x10) = 0;
    *(unsigned*)(buf + 0x14) = 0;
    alignas(8) unsigned char lm[0x400];
    zone::fn::ItemListMaker__ItemListMaker()(lm, 0, 2);
    zone::fn::ItemListMaker__ilm_ItemMake()(lm, 0, &iti);
    int n = zone::fn::ItemListMaker__ilm_PutInto()(lm, 0, (PROTO_ITEM_CMD*)(buf + 0x18), 0, nullptr, 2);
    unsigned reg = vfn<DwordFn>(player, kVtRegnum)(player, 0);
    *(unsigned*)(buf + 8) = reg;
    *(unsigned short*)(buf + 2) = *(unsigned short*)((unsigned char*)player + 4);
    *(unsigned*)(buf + 4) = vfn<DwordFn>(player, kVtRegnum)(player, 0);
    void* lock = vfn<PtrFn>(player, kVtCellLock)(player, 0);
    *(unsigned short*)(buf + 0xC) = zone::fn::ShineObjectClass__ShineObject__so_GetZoneHandle_ItemLooter()(lock, 0);
    bool sent = false;
    if (zone::fn::ProtocolPacket__pp_SetPacketLen()(pkt, 0, n + 0x19)) {
        auto* db = zone::fn::SocketBundle_GameDBSession___sb_GetSocket()(zone::rebase(kVaDbBundle), 0);
        zone::fn::ProtocolPacket__pp_SendPacket()(pkt, 0, (ZoneBaseSession*)db);
        sent = true;
    }
    lock = vfn<PtrFn>(player, kVtCellLock)(player, 0);
    vfn<MarkFn>(lock, kVtLockMark)(lock, 0, *(unsigned short*)(buf + 0xC), 0, 0, 1);
    lock = vfn<PtrFn>(player, kVtCellLock)(player, 0);
    zone::fn::InventoryLocking__InventoryCellLock__icl_IncIndex()(lock, 0);
    zone::fn::ItemListMaker___ItemListMaker()(lm, 0);
    return sent;
}

void __fastcall title_hook(void* self, void* edx, SHINE_ITEM_REGISTNUMBER reg, unsigned short a2) {
    if (g_buyer) g_bought = true;
    ((zone::fn::CCharacterTitleZone__CT_BuyNPC_t)g_title.trampoline)(self, edx, reg, a2);
}

void __fastcall buy_hook(void* self, void* edx, ShineObjectClass__ShinePlayer* player, unsigned short a2,
                         PROTO_NC_ITEM_BUY_REQ* req, unsigned long long a4, unsigned long a5, unsigned long a6) {
    bool outer = !g_buyer && !g_in;
    if (outer) { g_buyer = player; g_bought = false; g_buy_id = req ? *(unsigned short*)req : 0xFFFF; }
    ((zone::fn::ItemInventory__ii_BuyAll_t)g_buy.trampoline)(self, edx, player, a2, req, a4, a5, a6);
    if (!outer) return;
    bool bought = g_bought;
    g_buyer = nullptr;
    if (!bought) return;
    auto* list = partners_of(g_buy_id);
    if (!list) return;
    g_in = true;
    for (const Partner& pt : *list)
        if (rolls(pt))
            zone::log("piggyback_drops: %u came with bought %u - %s", pt.id, g_buy_id,
                      give_item(player, pt.id) ? "given" : "NOT given");
    g_in = false;
}

unsigned char __fastcall drop_hook(void* self, void* edx, ItemTotalInformation* iti, ShineObjectClass__DataBase db,
                                   void* handle, unsigned short owner, unsigned long owner_reg, ItemAttributeClass* attr,
                                   int a7) {
    unsigned char ok = ((DropFn)g_drop.trampoline)(self, edx, iti, db, handle, owner, owner_reg, attr, a7);
    if (!ok || g_in || !iti || !self) return ok;
    unsigned short id = *(unsigned short*)((unsigned char*)iti + 8);
    auto* list = partners_of(id);
    if (!list) return ok;
    g_in = true;
    for (const Partner& pt : *list)
        if (rolls(pt)) drop_piggyback(self, pt.id, db, handle, owner, owner_reg, a7, id);
    g_in = false;
    return ok;
}

}  // namespace

ZONEHOOK_PLUGIN("piggyback_drops") {
    zone::hook_function("ShineObject::so_IsDropping (an item drops its piggyback too)",
                        (void*)zone::fn::ShineObjectClass__ShineObject__so_IsDropping(), (void*)drop_hook, &g_drop);
    zone::hook_function("ItemListMaker::ilm_ItemMake (a reward brings its partner)",
                        (void*)zone::fn::ItemListMaker__ilm_ItemMake(), (void*)ilm_hook, &g_ilm);
    zone::hook_function("TreasureChestMaker::tcm_ItemMake (a container brings its partner)",
                        (void*)zone::fn::TreasureChestMaker__tcm_ItemMake(), (void*)tcm_hook, &g_tcm);
    zone::hook_function("TreasureChestMaker::tcm_ItemMake(KQ reward) (a KQ box brings its partner)",
                        (void*)zone::fn::TreasureChestMaker__tcm_ItemMake_2(), (void*)tcm2_hook, &g_tcm2);
    g_npc_buy = hook::config_int("npc_buy", 0) != 0;
    if (g_npc_buy) {
        zone::hook_function("ItemInventory::ii_BuyAll (a bought item brings its partner)",
                            (void*)zone::fn::ItemInventory__ii_BuyAll(), (void*)buy_hook, &g_buy);
        zone::hook_function("CCharacterTitleZone::CT_BuyNPC (the buy succeeded)",
                            (void*)zone::fn::CCharacterTitleZone__CT_BuyNPC(), (void*)title_hook, &g_title);
    }
    zone::log("piggyback_drops: up - drops, rewards, containers, KQ boxes%s; reads %s on first use",
              g_npc_buy ? ", NPC purchases (npc_buy=1)" : " (NPC purchases off: npc_buy=0)", kFile);
}
