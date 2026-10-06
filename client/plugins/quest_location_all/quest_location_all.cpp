// quest_location_all - the quest window's location button shows EVERY circle of the quest, not only its first mob's
// (Fiesta2026on2016 ticket P4, operator 2026-10-06: The Final Ingredient's Strengthening Herb showed IS_Herb01's one circle
// instead of all six of IS_Herb01/02/03).
//
// ---- THE STOCK CODE (2026 Fiesta.exe, 10.6.4 reference addresses, read 2026-10-06) -----------------------------------------
//   CQuestWin2::OnCommand (vtable slot 97, 0x738090) -> FullMapWin::LocationInfo(selected quest) 0x610CE0 (2016 0x5038D0):
//   it takes the quest's FIRST MobCoordinate mob into [ebp-4], picks the map, AddQuestHelper, then walks the label marks
//   (+0x5C8) and the area marks (+0x334), showing a mark only when its quest == the quest AND its mob == [ebp-4]:
//       cmp ax, [ebp-4] ; jne hide        66 3B 45 FC 75 11      (QuestLocationLabelMobCmp / QuestLocationAreaMobCmp)
//
// ---- THIS PLUGIN ---------------------------------------------------------------------------------------------------------
//   Both "jne hide" become NOPs: the mob test is dropped, the quest test stays - every mark of the quest on that map shows.
#include <hook_core.h>
#include <client_addrs.h>

#include <cstring>

namespace {

const unsigned char kStock[6] = {0x66, 0x3B, 0x45, 0xFC, 0x75, 0x11};   // cmp ax, [ebp-4] ; jne +0x11
const unsigned char kNop2[2] = {0x90, 0x90};

}  // namespace

HOOK_PLUGIN("quest_location_all") {
    if (const char* m = caddr::missing({caddr::kQuestLocationLabelMobCmp, caddr::kQuestLocationAreaMobCmp})) {
        hook::log("quest_location_all: %s - not hooked", m);
        return;
    }
    unsigned char* sites[2] = {(unsigned char*)hook::rebase(caddr::va(caddr::kQuestLocationLabelMobCmp)),
                               (unsigned char*)hook::rebase(caddr::va(caddr::kQuestLocationAreaMobCmp))};
    for (unsigned char* s : sites) {
        if (std::memcmp(s, kStock, sizeof kStock) != 0) {
            hook::log("quest_location_all: LocationInfo's mob test is not the expected code - stock (first mob only)");
            return;
        }
    }
    int n = 0;
    for (unsigned char* s : sites) n += hook::write_code(s + 4, kNop2, sizeof kNop2) ? 1 : 0;
    hook::log("quest_location_all: %d of 2 mark loops show every circle of the quest (not only its first mob's)", n);
}
