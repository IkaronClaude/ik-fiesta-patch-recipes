// eternal_revive - an item that lets its holder revive in place without using anything up (Fiesta2026on2016 Rebalanced
// "Tear of Legel (Eternal)", operator 2026-10-03: "a non-consumable version of Tears of Legel").
//
// ---- THE STOCK PATH (read from Zone.exe) --------------------------------------------------------------------------------
//   ShinePlayer::sp_NC_ITEM_REVIVEITEMUSE_CMD (0x417580), the "revive with item" button of the death dialog:
//     not dead (player+0x7A state, byte +0x20C bit 0 clear)    -> so_ply_... error (0x12, 0x3A, 0x701)
//     item = ItemDataBox::idb_SpecialItems()->sii_JustReviveItem (+0x40 - the ONE revive item, Tear of Legel)
//     no such item                                             -> error 0x71F
//     sp_FindItemFromInventory(item, &out) finds none          -> error 0x71E
//     UseItemNormal::uib_AfterCast(player, bag, item, cell) (0x540080): the revive AND one Tear used up
//   ShinePlayer::so_ReviveByItem (0x417850, virtual): sp_ReviveNow(1000) - the revive itself, nothing consumed.
//   ShinePlayer::so_ply_SendCanUseReviveItem (0x5616F0) sends 0x182B {dead u8} only - the client decides from its own
//   bag whether to offer the button.
//
// ---- THIS PLUGIN --------------------------------------------------------------------------------------------------------
//   ../9Data/Shine/EternalRevive.txt lists the item ids (one per line, '#' comments; written by the variant step
//   migrations-rebalance/0008b-vault-teva-legel.py). The revive handler is detoured: a DEAD player who holds one of
//   them revives through so_ReviveByItem and nothing is used up; anyone else takes the stock path (a normal Tear is used
//   up as before). No file / no ids = stock.

#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cstdio>
#include <vector>

namespace {

const char* kListPath = "../9Data/Shine/EternalRevive.txt";
std::vector<unsigned short>* g_items = nullptr;
zone::Detour g_revive_use;
unsigned g_used = 0;

bool is_dead(void* player) {
    void* state = *(void**)((char*)player + 0x7A);
    return state && (*((unsigned char*)state + 0x20C) & 1);
}

unsigned short held_eternal(void* player) {
    for (unsigned short id : *g_items) {
        unsigned char out[16] = {};
        if (zone::fn::ShineObjectClass__ShinePlayer__sp_FindItemFromInventory()(player, nullptr, id, out)) return id;
    }
    return 0;
}

void __fastcall revive_use(void* self, void*, zone::types::NETCOMMAND* cmd, int len, unsigned short handle) {
    if (is_dead(self)) {
        const unsigned short id = held_eternal(self);
        if (id) {
            zone::fn::ShineObjectClass__ShinePlayer__so_ReviveByItem()(self, nullptr);
            if (g_used++ < 200 || g_used % 1000 == 0)
                zone::log("eternal revive: revived in place with item %u, nothing used up (#%u)", id, g_used);
            return;
        }
    }
    ((void (__fastcall*)(void*, void*, zone::types::NETCOMMAND*, int, unsigned short))g_revive_use.trampoline)(self, nullptr, cmd,
                                                                                                          len, handle);
}

bool load_list() {
    FILE* f = std::fopen(kListPath, "r");
    if (!f) return false;
    char line[128];
    while (std::fgets(line, sizeof line, f)) {
        if (line[0] == '#') continue;
        unsigned id = 0;
        if (std::sscanf(line, "%u", &id) == 1 && id > 0 && id < 0xFFFF) g_items->push_back((unsigned short)id);
    }
    std::fclose(f);
    return !g_items->empty();
}

}  // namespace

HOOK_PLUGIN("eternal_revive") {
    g_items = new std::vector<unsigned short>();
    if (!load_list()) {
        zone::log("no %s (or no ids in it) - revive items stay stock", kListPath);
        return;
    }
    zone::log("eternal revive items: %u (first %u)", (unsigned)g_items->size(), (*g_items)[0]);
    zone::hook_function("ShinePlayer::sp_NC_ITEM_REVIVEITEMUSE_CMD (revive without using up an eternal item)",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__sp_NC_ITEM_REVIVEITEMUSE_CMD(), (void*)revive_use,
                        &g_revive_use);
}
