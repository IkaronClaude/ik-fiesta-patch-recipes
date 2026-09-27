// map_legend_focus - clicking a quest (or one of its "Mob n/m" lines) in the full map's legend shows that quest's (or
// that mob's) MobCoordinate circles on the map (ticket P1 CLIENT FEATURE: QUEST LOCATIONS FROM THE MAP LEGEND, operator
// 2026-09-27; the 2016 client did it).
//
// ---- 2016 (Fiesta.bin + Fiesta.pdb) --------------------------------------------------------------------------------------
//   A legend row click: the row's ColumnBut sends the SlideListWin a button release (msg 7, wParam 2);
//   SlideListWin::OnClickItem(row) then sends its PARENT (the FullMapWin) msg 5 = command (the list's command id 9, row)
//   -> FullMapWin::OnCommand(9, row) -> OnQuestListLClick -> UpdateArea(row): show only the marks (QuestHelperMarkWin /
//   MobAreaMarkWin) of the clicked quest / mob. The marks come from FullMapWin::AddQuestHelper.
//
// ---- 2026 (US Fiesta.exe, measured on the operator's client with win_msg_probe, 2026-09-27) ------------------------------
//   The same release reaches the list, and the list's command goes out - but to the LIST ITSELF with command id 0
//   ("deliver SlideListWin msg 5 wParam 0 lParam <row>", row 0 = the quest name, 1 = its mob line): the 2026 FullMapWin
//   creates its quest list without wiring it to itself, so FullMapWin::OnCommand (0x60F8B0) never runs and nothing
//   happens. (The map's own path still exists: command 9 -> UpdateArea(row) 0x6129D0.) The marks are only built by
//   AddQuestHelper (0x610610), which stock runs only from the minimap all-map button, a map-list click and Location.
//
// ---- this plugin (pgwin_msg.h) -------------------------------------------------------------------------------------------
//   When a SlideListWin receives msg 5 and it is the quest list of a FullMapWin (FullMapWin +0x54C, the list 2026
//   OnCommand cases 9/10 use), do what 2016 did: AddQuestHelper(map), then UpdateArea(map, row). The list's own handling
//   (row selection) is left as it was. The owning map is found as a FullMapWin pointer among the list's first fields
//   (its parent / owner), by RTTI, and cached per list.
#include <pgwin_msg.h>

namespace {

const unsigned kVaUpdateArea = 0x006129D0u;      // FullMapWin::UpdateArea(unsigned row), thiscall, ret 4
const unsigned kVaAddQuestHelper = 0x00610610u;  // FullMapWin::AddQuestHelper(), thiscall
const unsigned kMapQuestList = 0x54C;           // FullMapWin -> its quest legend SlideListWin
const unsigned kOwnerScan = 0x80;               // bytes of the list searched for the owning FullMapWin

void* g_list = nullptr;
void* g_map = nullptr;

// the FullMapWin whose quest list `list` is, or nullptr
void* owner_map(void* list) {
    if (list == g_list && pgwin::alive(g_map) && *(void**)((char*)g_map + kMapQuestList) == list) return g_map;
    for (unsigned off = 4; off < kOwnerScan; off += 4) {
        void* p = *(void**)((char*)list + off);
        if (!p || (unsigned)p < 0x10000 || !pgwin::is(p, "FullMapWin")) continue;
        __try {
            if (*(void**)((char*)p + kMapQuestList) != list) continue;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }
        if (list != g_list) hook::log("quest legend list %p belongs to FullMapWin %p (found at list +0x%X)", list, p, off);
        g_list = list;
        g_map = p;
        return p;
    }
    return nullptr;
}

bool on_process(pgwin::Message& m) {
    if (m.msg != pgwin::kCommand || !pgwin::is(m.window, "SlideListWin")) return false;
    void* map = owner_map(m.window);
    if (!map) return false;
    typedef void(__fastcall * AddQuestHelper)(void*, void*);
    typedef void(__fastcall * UpdateArea)(void*, void*, unsigned);
    ((AddQuestHelper)hook::rebase(kVaAddQuestHelper))(map, 0);
    ((UpdateArea)hook::rebase(kVaUpdateArea))(map, 0, (unsigned)m.lparam);
    hook::log("legend row %ld clicked: quest markers built, map narrowed to that row", m.lparam);
    return false;
}

}  // namespace

HOOK_PLUGIN("map_legend_focus") {
    pgwin::on_process(on_process);
    pgwin::install();
}
