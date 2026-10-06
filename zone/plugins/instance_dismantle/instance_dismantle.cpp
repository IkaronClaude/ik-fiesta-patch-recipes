// instance_dismantle - an item listed in ItemDismantleProduct.shn dismantles into the product that table names, instead
// of Karis (Fiesta2026on2016 Rebalanced, operator 2026-10-06: "Dismantle is already built for Karis, we could simply
// adjust the code so instance dungeon items, on dismantle, give instance coins instead"; 2026-10-07: "These dismantle
// tables should go into a .shn that's shared between client and server" - "(no hash check required)").
//
// ---- THE TABLE --------------------------------------------------------------------------------------------------------
// ../9Data/Shine/ItemDismantleProduct.shn {ItemIDX string[32], ProductIDX string[32], ProductLot u16} - written by the
// Rebalanced step migrations-rebalance/0039 (each instance set piece -> its instance coin: the full price for mid-game
// instances, 1 of 3 for end-game; the step asserts a lot never tops the piece's price). The 2026 client carries the same
// file (client plugin instance_dismantle_text shows it). Read once with the zone's own CDataReader (not one of the 49
// checksummed tables, so the read registers nothing). No table = stock Karis for everything.
//
// ---- THE DISMANTLE (read from Zone.exe) ---------------------------------------------------------------------------------
// ShinePlayer::sp_NC_ITEM_DISMANTLE_REQ (0x529390) reads the item's grade row of gItemDismantle, takes the COUNT for the
// item's category (0x5296A4..: armour / boots / shield / weapon / accessory column; 0 = refused, 0x168A) and builds
// ItemDismantleProducer(player, PRODUCT ITEM ID - the one global Karis id at 0x14D504C2, count, bag, slot) (0x528A90):
// +8 = the product id, +0xC = the count, +0x211C a copy of the item (ItemTotalInformation: +8 itemid). Its space check
// (idp_WhereDismantleProductStore) and execute (NC_ITEMDB_DISMANTLE_REQ: the item removed, the product made) read +8 / +0xC.
// Hooked after the constructor: a listed item gets product / count from the table - the stock check, DB request and
// client ack then handle the product exactly as they would Karis (nothing is given outside the stock flow).
#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>
#include <zone_types.h>

#include <cstring>
#include <map>
#include <string>
#include <utility>

namespace {

const unsigned kProductId = 0x8, kProductCount = 0xC;   // ItemDismantleProducer: what it makes, how many
const unsigned kItemId = 0x211C + 8;                      // its copy of the item: ItemTotalInformation +8 = itemid
const char kTable[] = "../9Data/Shine/ItemDismantleProduct.shn";

struct Row { std::string product; unsigned long lot; };
std::map<std::string, Row>* g_rows = nullptr;                                         // item InxName -> its product
std::map<unsigned short, std::pair<unsigned short, unsigned long> >* g_ids = nullptr;   // item id -> (product id, lot)
bool g_resolved = false;

zone::Detour g_ctor;

struct Col { int off = -1; int size = 0; };

bool read_table() {
    using zone::types::CDataReader;
    using zone::types::CDataReader__FIELD;
    using zone::types::CDataReader__HEAD;
    const char* names[3] = {"ItemIDX", "ProductIDX", "ProductLot"};
    void* reader = ::operator new(sizeof(CDataReader));
    zone::fn::CDataReader__CDataReader()(reader, nullptr);
    bool ok = zone::fn::CDataReader__Read()(reader, nullptr, (char*)kTable) != 0;
    Col c[3];
    if (ok) {
        CDataReader* r = (CDataReader*)reader;
        const CDataReader__FIELD* f = (const CDataReader__FIELD*)((const unsigned char*)r->m_pHead + sizeof(CDataReader__HEAD));
        int off = 0;
        for (unsigned i = 0; i < r->m_pHead->nNumOfField; ++i) {
            for (int k = 0; k < 3; ++k)
                if (!std::strcmp(f[i].Name, names[k])) { c[k].off = off; c[k].size = (int)f[i].Size; }
            off += (int)f[i].Size;
        }
        for (int k = 0; k < 3 && ok; ++k)
            if (c[k].off < 0) { zone::log("instance_dismantle: %s has no %s column", kTable, names[k]); ok = false; }
    }
    if (ok) {
        unsigned long rows = zone::fn::CDataReader__GetNumOfRecord()(reader, nullptr);
        for (unsigned long i = 0; i < rows; ++i) {
            const unsigned char* rec = (const unsigned char*)zone::fn::CDataReader__GetRecord()(reader, nullptr, i);
            if (!rec) continue;
            std::string item((const char*)rec + c[0].off, strnlen((const char*)rec + c[0].off, c[0].size));
            std::string product((const char*)rec + c[1].off, strnlen((const char*)rec + c[1].off, c[1].size));
            unsigned long lot = c[2].size == 1 ? rec[c[2].off] : c[2].size == 2 ? *(const unsigned short*)(rec + c[2].off)
                                                                                 : *(const unsigned long*)(rec + c[2].off);
            if (!item.empty() && !product.empty() && lot > 0) (*g_rows)[item] = Row{product, lot};
        }
    }
    zone::fn::CDataReader___CDataReader()(reader, nullptr);
    ::operator delete(reader);
    return ok && !g_rows->empty();
}

// InxName -> id needs the ItemDataBox, which is loaded after the plugins: resolved on the first dismantle
void resolve() {
    g_resolved = true;
    unsigned bad = 0;
    for (auto& kv : *g_rows) {
        unsigned short item = zone::fn::ItemDataBox__idb_2itemid()(zone::global::itemdatabox(), 0, (unsigned char*)kv.first.c_str());
        unsigned short product = zone::fn::ItemDataBox__idb_2itemid()(zone::global::itemdatabox(), 0,
                                                                      (unsigned char*)kv.second.product.c_str());
        if (item == 0xFFFF || product == 0xFFFF) { bad++; continue; }
        (*g_ids)[item] = std::make_pair(product, kv.second.lot);
    }
    zone::log("instance_dismantle: %u of %u table rows resolved to item ids (%u name(s) unknown to this zone)",
              (unsigned)g_ids->size(), (unsigned)g_rows->size(), bad);
}

typedef void(__fastcall* CtorFn)(void*, void*, zone::types::ShineObjectClass__ShinePlayer*, unsigned short, unsigned long,
                                 zone::types::ItemBag*, unsigned char);

void __fastcall ctor(void* self, void*, zone::types::ShineObjectClass__ShinePlayer* player, unsigned short product,
                     unsigned long count, zone::types::ItemBag* bag, unsigned char slot) {
    ((CtorFn)g_ctor.trampoline)(self, 0, player, product, count, bag, slot);
    if (!g_resolved) resolve();
    unsigned short item = *(unsigned short*)((char*)self + kItemId);
    auto it = g_ids->find(item);
    if (it == g_ids->end()) return;
    *(unsigned short*)((char*)self + kProductId) = it->second.first;
    *(unsigned long*)((char*)self + kProductCount) = it->second.second;
    zone::log("instance_dismantle: item %u dismantles into %lu x item %u instead of %lu x item %u", item, it->second.second,
              it->second.first, count, product);
}

}  // namespace

ZONEHOOK_PLUGIN("instance_dismantle") {
    g_rows = new std::map<std::string, Row>();
    g_ids = new std::map<unsigned short, std::pair<unsigned short, unsigned long> >();
    if (!read_table()) {
        zone::log("instance_dismantle: no %s (or no rows in it) - dismantling stays stock", kTable);
        return;
    }
    zone::hook_function("ItemDismantleProducer::ItemDismantleProducer (listed items make their product)",
                        (void*)zone::fn::ItemDismantleProducer__ItemDismantleProducer(), (void*)ctor, &g_ctor);
    zone::log("instance_dismantle: %u items dismantle by %s", (unsigned)g_rows->size(), kTable);
}
