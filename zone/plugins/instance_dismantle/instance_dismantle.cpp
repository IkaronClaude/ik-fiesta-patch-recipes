// instance_dismantle - dismantling an instance set piece gives that instance's COIN instead of Karis (Fiesta2026on2016
// Rebalanced, operator 2026-10-06: "Dismantle is already built for Karis, we could simply adjust the code so instance
// dungeon items, on dismantle, give instance coins instead"; "You destroy the Leviathan Instance Armor to get the coins";
// "sacrificing a leviathan item should never give > buy cost number of coins").
//
// ---- WHICH ITEMS (the server's own table, no side file) ----------------------------------------------------------------
// A piece's coin is its coin-shop price: ItemMoney (the stock coin-shop table - the instance exchangers sell the pieces for
// coins). ItemDataBox[item] +0x24 = its ItemMoney row (+0x20 the money item's InxName, +0x40 the lot) - the lookup
// NPCRole_Merchant::nrb_ItemBuyItemMoney (0x4C7590) does. A piece priced in an instance coin (InxName "REB_IDCoin...")
// dismantles into ONE of that coin - always below the price (the data asserts PIECE_COST > TRADE_IN).
//
// ---- THE DISMANTLE (read from Zone.exe) ---------------------------------------------------------------------------------
// ShinePlayer::sp_NC_ITEM_DISMANTLE_REQ (0x529390) reads the item's grade row of gItemDismantle, takes the COUNT for the
// item's category (0x5296A4..: armour / boots / shield / weapon / accessory column; 0 = refused, 0x168A) and builds
// ItemDismantleProducer(player, PRODUCT ITEM ID - the one global Karis id at 0x14D504C2, count, bag, slot) (0x528A90):
// +8 = the product id, +0xC = the count, +0x211C a copy of the item (ItemTotalInformation: +8 itemid). Its space check
// (idp_WhereDismantleProductStore) and execute (NC_ITEMDB_DISMANTLE_REQ: the item removed, the product made) read +8 / +0xC.
// Hooked after the constructor: a coin piece gets product = its coin, count = 1 - the stock check, DB request and client
// ack then handle the coin exactly as they would Karis (no item is given outside the stock flow).
#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cstring>

namespace {

const unsigned kProductId = 0x8, kProductCount = 0xC;   // ItemDismantleProducer: what it makes, how many
const unsigned kItemId = 0x211C + 8;                      // its copy of the item: ItemTotalInformation +8 = itemid
const unsigned kItemMoney = 0x24;                         // ItemDataBoxIndex -> ItemMoney row
const unsigned kMoneyName = 0x20, kMoneyLot = 0x40;
const char kCoinPrefix[] = "REB_IDCoin";

zone::Detour g_ctor;

typedef void(__fastcall* CtorFn)(void*, void*, zone::types::ShineObjectClass__ShinePlayer*, unsigned short, unsigned long,
                                 zone::types::ItemBag*, unsigned char);

void __fastcall ctor(void* self, void*, zone::types::ShineObjectClass__ShinePlayer* player, unsigned short product,
                     unsigned long count, zone::types::ItemBag* bag, unsigned char slot) {
    ((CtorFn)g_ctor.trampoline)(self, 0, player, product, count, bag, slot);
    unsigned short item = *(unsigned short*)((char*)self + kItemId);
    auto* idx = zone::fn::ItemDataBox__operator__()(zone::global::itemdatabox(), 0, item);
    const char* money = idx ? *(const char**)((char*)idx + kItemMoney) : nullptr;
    if (!money || std::strncmp(money + kMoneyName, kCoinPrefix, sizeof kCoinPrefix - 1) != 0) return;
    char coin_name[33] = {0};
    std::memcpy(coin_name, money + kMoneyName, 32);
    unsigned short coin = zone::fn::ItemDataBox__idb_2itemid()(zone::global::itemdatabox(), 0, (unsigned char*)coin_name);
    if (coin == 0xFFFF) return;
    *(unsigned short*)((char*)self + kProductId) = coin;
    *(unsigned long*)((char*)self + kProductCount) = 1;      // always below the price (ItemMoney lot)
    zone::log("instance_dismantle: item %u dismantles into 1 %s (price %u) instead of %lu x item %u", item, coin_name,
              (unsigned)*(unsigned short*)(money + kMoneyLot), count, product);
}

}  // namespace

ZONEHOOK_PLUGIN("instance_dismantle") {
    zone::hook_function("ItemDismantleProducer::ItemDismantleProducer (instance pieces make their coin)",
                        (void*)zone::fn::ItemDismantleProducer__ItemDismantleProducer(), (void*)ctor, &g_ctor);
    zone::log("instance_dismantle: a piece priced in REB_IDCoin* (ItemMoney) dismantles into one of that coin");
}
