// start_item_quests - a quest that needs a start item is listed under "Available" once that item is in the bag (and not
// before).
//
// Operator 2026-10-03 (Kiera's Tears, 60211): "it should NOT show in the log UNTIL the start item has been acquired" - and
// then it should.
//
// ---- the 2026 client (US Fiesta.exe) ---------------------------------------------------------------------------------
//   CQuest::IsSoonableQuest (0x900260) already requires the start item: if QuestData.Type & 0x20, the bag count of ItemID
//   (vtable+0x68 -> the main inventory 0xCF5AC8, 192 slots) must reach ItemLot - so without the item the quest never gets
//   the "available" state 5 (the state function 0x8FF5C0). The soonable_probe plugin measured Kiera's Tears WITH the stone:
//   IsSoonable 1, state 5. It still never appears, because BOTH quest-list builders throw out every state-5 quest that has
//   the start-item bit, whether the item is held or not:
//     0x736320:  cmp eax, 5 / jne ... / mov cl, [edi+0x14] / test cl, 0x20 / jne skip (0x7363AD: 75 74) / test cl, 2 / je skip
//     0x738FA0:  mov al, [esi+0x14] / test al, 0x20 / jne skip (0x73927C: 75 25) / test al, 2 / je skip
// ---- this plugin -----------------------------------------------------------------------------------------------------
//   Turns those two jumps into NOPs. The "not visible (Type & 0x02) -> skip" right after each stays, and IsSoonableQuest's
//   own start-item test keeps an unheld item's quest out - so a start-item quest shows exactly while its item is held.

#include <hook_core.h>
#include <client_addrs.h>

#include <cstring>

namespace {

struct Site {
    unsigned va;
    unsigned char stock[2];
    const char* where;
};
const Site kSites[] = {
    {caddr::va(caddr::kQuestListSkipA), {0x75, 0x74}, "quest list builder 0x736320"},
    {caddr::va(caddr::kQuestListSkipB), {0x75, 0x25}, "quest list builder 0x738FA0"},
};
const unsigned char kNop2[2] = {0x90, 0x90};

}  // namespace

HOOK_PLUGIN("start_item_quests") {
    if (const char* m = caddr::missing({caddr::kQuestListSkipA, caddr::kQuestListSkipB})) {
        hook::log("start_item_quests: %s - not hooked", m);
        return;
    }
    for (const Site& s : kSites) {
        unsigned char* p = (unsigned char*)hook::rebase(s.va);
        if (std::memcmp(p, s.stock, 2) != 0) {
            hook::log("start_item_quests: unexpected bytes %02X %02X in the %s - NOT patched", p[0], p[1], s.where);
            continue;
        }
        if (hook::write_code(p, kNop2, sizeof kNop2))
            hook::log("start_item_quests: %s lists start-item quests whose item is held", s.where);
    }
}
