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
//   LEVEL (operator 2026-10-03: "Ensure the level limit for the eternal tear is checked before deciding to display the can
//   revive"): a line may carry the item's use level after the id ("<id> <level>"); a player below it is not revived by
//   it (ShinePlayer::so_GetLevel, vtable +0x4D8) and takes the stock path. The client still offers the button (it decides
//   from its own bag, 0x182B carries only "dead") - pressing it below the level gets the stock error.

#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <cstdio>
#include <vector>

namespace {

const char* kListPath = "../9Data/Shine/EternalRevive.txt";
std::vector<unsigned short>* g_items = nullptr;
std::vector<unsigned char>* g_levels = nullptr;    // per item: the use level (0 = none)
const int kSlotGetLevel = 0x4D8 / 4;               // ShinePlayer::so_GetLevel() -> u8
zone::Detour g_revive_use;
unsigned g_used = 0;

bool is_dead(void* player) {
    void* state = *(void**)((char*)player + 0x7A);
    return state && (*((unsigned char*)state + 0x20C) & 1);
}

unsigned level_of(void* player) {
    __try {
        return ((unsigned char(__fastcall*)(void*, void*))(*(void***)player)[kSlotGetLevel])(player, nullptr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// the first held eternal item the player is level enough for; *under = an item held but its level not reached
unsigned short held_eternal(void* player, unsigned short* under) {
    *under = 0;
    for (size_t k = 0; k < g_items->size(); k++) {
        unsigned short id = (*g_items)[k];
        unsigned char out[16] = {};
        if (!zone::fn::ShineObjectClass__ShinePlayer__sp_FindItemFromInventory()(player, nullptr, id, out)) continue;
        if ((*g_levels)[k] && level_of(player) < (*g_levels)[k]) {
            *under = id;
            continue;
        }
        return id;
    }
    return 0;
}

void __fastcall revive_use(void* self, void*, zone::types::NETCOMMAND* cmd, int len, unsigned short handle) {
    if (is_dead(self)) {
        unsigned short under = 0;
        const unsigned short id = held_eternal(self, &under);
        if (!id && under)
            zone::log("eternal revive: item %u held below its level (player level %u) - stock path", under, level_of(self));
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
        unsigned id = 0, lv = 0;
        int n = std::sscanf(line, "%u %u", &id, &lv);
        if (n >= 1 && id > 0 && id < 0xFFFF) {
            g_items->push_back((unsigned short)id);
            g_levels->push_back((unsigned char)(n == 2 && lv < 256 ? lv : 0));
        }
    }
    std::fclose(f);
    return !g_items->empty();
}

}  // namespace

HOOK_PLUGIN("eternal_revive") {
    g_items = new std::vector<unsigned short>();
    g_levels = new std::vector<unsigned char>();
    if (!load_list()) {
        zone::log("no %s (or no ids in it) - revive items stay stock", kListPath);
        return;
    }
    zone::log("eternal revive items: %u (first %u, level %u)", (unsigned)g_items->size(), (*g_items)[0], (unsigned)(*g_levels)[0]);
    zone::hook_function("ShinePlayer::sp_NC_ITEM_REVIVEITEMUSE_CMD (revive without using up an eternal item)",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__sp_NC_ITEM_REVIVEITEMUSE_CMD(), (void*)revive_use,
                        &g_revive_use);
}
