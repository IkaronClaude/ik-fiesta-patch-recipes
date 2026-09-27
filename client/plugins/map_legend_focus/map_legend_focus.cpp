// map_legend_focus - clicking a quest (or one of its "Mob n/m" lines) in the full map's legend shows that quest's (or
// that mob's) MobCoordinate circles on the map, whatever way the map was opened (ticket P1 CLIENT FEATURE: QUEST
// LOCATIONS FROM THE MAP LEGEND, operator 2026-09-27; the 2016 client did it too).
//
// ---- the stock client (2016 Fiesta.bin + Fiesta.pdb; the 2026 Fiesta.exe is the same design, addresses below) -----
//
//   The legend = FullMapWin::AddQuestList: a SlideListWin row per quest on the viewed map (its name) and a row per
//   objective under it ("Mob 0/5", QuestHelperMgr::AddMobConditionText); each row carries a data value (SetData).
//   A row click = FullMapWin::OnCommand command 9 -> UpdateArea(row) (2026 0x6129D0, thiscall, ret 4): it works out
//   the clicked row's quest and mob and then, for every QuestHelperMarkWin (quest marker) and MobAreaMarkWin (blue
//   circle) on the map, calls the mark's vtable +0x100 (show) with 1 if it belongs to that quest (and mob) and 0 if
//   not - so the map narrows to the clicked quest or mob.
//   The marks exist only after FullMapWin::AddQuestHelper (2026 0x610610, thiscall, no args) - it resets the marks
//   (ResetQuestHelper) and creates them for every legend quest on the viewed map. Stock callers: the minimap's "all
//   map" button, a map-list click and the quest window's Location button (LocationInfo 0x610CE0). Opened any other
//   way, the map has no marks, and a legend click shows nothing - the operator's "click does nothing".
//
// ---- this plugin ----------------------------------------------------------------------------------------------------
//
//   Around UpdateArea: AddQuestHelper(this) first (rebuilds the marks for the viewed map - it resets itself, so running
//   it again is harmless), then the stock UpdateArea(row), which shows only the clicked quest's / mob's marks.
#include <hook_core.h>

namespace {

const unsigned kVaUpdateArea = 0x006129D0u;      // FullMapWin::UpdateArea(unsigned row), thiscall, ret 4
const unsigned kVaAddQuestHelper = 0x00610610u;  // FullMapWin::AddQuestHelper(), thiscall, ret

hook::Detour g_update_area;

void __fastcall update_area(void* map, void*, unsigned row) {
    typedef void(__fastcall * AddQuestHelper)(void*, void*);
    typedef void(__fastcall * UpdateArea)(void*, void*, unsigned);
    ((AddQuestHelper)hook::rebase(kVaAddQuestHelper))(map, 0);
    ((UpdateArea)g_update_area.trampoline)(map, 0, row);
    hook::log("legend row %u clicked: quest markers rebuilt, map narrowed to that row", row);
}

}  // namespace

HOOK_PLUGIN("map_legend_focus") {
    hook::hook_function("FullMapWin::UpdateArea 0x6129D0 (legend click shows the quest's / mob's circles)",
                        hook::rebase(kVaUpdateArea), (void*)update_area, &g_update_area);
}
