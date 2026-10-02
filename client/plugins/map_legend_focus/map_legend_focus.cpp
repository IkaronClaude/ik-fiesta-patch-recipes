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
//
// ---- NOT UpdateArea (2026-10-02, operator: Swamp of Dawn quests "missing location circles ... appears inconsistent") --
//   The 2026 UpdateArea(row) 0x6129D0 picks the circles wrongly. Legend rows carry a value (SlideListWin item data,
//   0x5255C0(index, &out)): a quest heading 0x10000 + k (k = its row-button slot, see the builder 0x6127C0), a mob line
//   the MOB id. UpdateArea takes the clicked line's value as the mob, but the QUEST by position: it counts the headings
//   above the click and takes the quest of that many distinct quests along the area-mark list (FullMapWin +0x334) -
//   which AddQuestHelper builds in MobCoordinate order, and which holds no quest that has no circle on this map. With
//   several quests tracked the count lands on another quest and the clicked mob's circles are hidden.
//   So the plugin shows the marks itself: a mob line = every mark of that mob; a heading = every mark of the mob lines
//   under it (up to the next heading). Area marks (+0x334: quest 0x663EA0, mob 0x663EB0) and quest-number labels
//   (+0x5C8: quest 0x664190, mob 0x6641A0), each shown / hidden with vtable +0x100(bool), as UpdateArea does. A click
//   whose mobs match no mark leaves every mark shown (and says so in the log) rather than an empty map.
#include <pgwin_msg.h>

#include <set>

namespace {

const unsigned kVaAddQuestHelper = 0x00610610u;  // FullMapWin::AddQuestHelper(), thiscall
const unsigned kVaGetItemData = 0x005255C0u;     // SlideListWin item data (index, unsigned* out) -> bool, thiscall
const unsigned kVaAreaQuest = 0x00663EA0u, kVaAreaMob = 0x00663EB0u;     // MobAreaMarkWin, thiscall -> u16
const unsigned kVaLabelQuest = 0x00664190u, kVaLabelMob = 0x006641A0u;   // QuestHelperMarkWin, thiscall -> u16
const unsigned kMapQuestList = 0x54C;           // FullMapWin -> its quest legend SlideListWin
const unsigned kMapAreaMarks = 0x334, kMapLabelMarks = 0x5C8;   // FullMapWin -> list nodes {next, prev, mark}
const unsigned kListTop = 0x150;                // SlideListWin: the first item shown (scroll offset)
const unsigned kListDirty = 0x154;              // SlideListWin byte UpdateArea clears at its end
const int kSlotShow = 0x100 / 4;
const unsigned kHeading = 0xFFFF;               // item data above this = a quest heading, else a mob id
const unsigned kMaxRows = 512;
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

typedef bool(__fastcall* GetItemDataFn)(void* list, void*, unsigned index, unsigned* out);
typedef unsigned short(__fastcall* U16Fn)(void* mark, void*);
typedef void(__fastcall* ShowFn)(void* mark, void*, int show);

bool item_data(void* list, unsigned index, unsigned* out) {
    __try {
        return ((GetItemDataFn)hook::rebase(kVaGetItemData))(list, 0, index, out);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

struct Node {
    Node* next;
    void* prev;
    void* mark;
};

// show the marks of `mobs` in one mark list (all of them when `all`); returns how many matched
int show_marks(void* map, unsigned list_off, unsigned va_quest, unsigned va_mob, const std::set<unsigned>& mobs, bool all,
               bool log_each) {
    int matched = 0;
    __try {
        for (Node* n = *(Node**)((char*)map + list_off); n; n = n->next) {
            if (!n->mark) continue;
            unsigned mob = ((U16Fn)hook::rebase(va_mob))(n->mark, 0);
            bool on = mobs.count(mob) != 0;
            matched += on;
            if (log_each)
                hook::log("  mark %s: quest %u mob %u", list_off == kMapAreaMarks ? "area" : "label",
                          (unsigned)((U16Fn)hook::rebase(va_quest))(n->mark, 0), mob);
            if (!all) ((ShowFn)pgwin::vtable_entry(n->mark, kSlotShow))(n->mark, 0, on ? 1 : 0);
        }
        if (all)
            for (Node* n = *(Node**)((char*)map + list_off); n; n = n->next)
                if (n->mark) ((ShowFn)pgwin::vtable_entry(n->mark, kSlotShow))(n->mark, 0, 1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook::log("map_legend_focus: fault walking the marks at +0x%X", list_off);
    }
    return matched;
}

int count_marks(void* map, unsigned list_off, unsigned va_mob, const std::set<unsigned>& mobs) {
    int matched = 0;
    __try {
        for (Node* n = *(Node**)((char*)map + list_off); n; n = n->next)
            if (n->mark && mobs.count(((U16Fn)hook::rebase(va_mob))(n->mark, 0))) matched++;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return matched;
}

unsigned read_u32(void* p, unsigned off) {
    __try {
        return *(unsigned*)((char*)p + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

void clear_byte(void* p, unsigned off) {
    __try {
        *((unsigned char*)p + off) = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

bool on_process(pgwin::Message& m) {
    if (m.msg != pgwin::kCommand || !pgwin::is(m.window, "SlideListWin")) return false;
    void* list = m.window;
    void* map = owner_map(list);
    if (!map) return false;
    typedef void(__fastcall * AddQuestHelper)(void*, void*);
    ((AddQuestHelper)hook::rebase(kVaAddQuestHelper))(map, 0);

    // every legend row's value, logged so a line that shows nothing can be read off the log
    unsigned data[kMaxRows];
    unsigned rows = 0;
    while (rows < kMaxRows && item_data(list, rows, &data[rows])) rows++;
    unsigned top = read_u32(list, kListTop);
    unsigned row = (unsigned)m.lparam;
    hook::log("legend row %u clicked (list top %u, %u rows)", row, top, rows);
    for (unsigned i = 0; i < rows; i++)
        hook::log("  row %u: %s %u", i, data[i] > kHeading ? "quest heading" : "mob", data[i] > kHeading ? data[i] - kHeading - 1 : data[i]);
    if (row >= rows) {
        hook::log("  row %u is past the list - every mark left shown", row);
        return false;
    }

    std::set<unsigned> mobs;
    if (data[row] <= kHeading) {
        mobs.insert(data[row]);
    } else {
        for (unsigned i = row + 1; i < rows && data[i] <= kHeading; i++) mobs.insert(data[i]);
    }
    int areas = count_marks(map, kMapAreaMarks, kVaAreaMob, mobs);
    bool all = areas == 0;
    show_marks(map, kMapAreaMarks, kVaAreaQuest, kVaAreaMob, mobs, all, all);
    int labels = show_marks(map, kMapLabelMarks, kVaLabelQuest, kVaLabelMob, mobs, all, all);
    clear_byte(list, kListDirty);
    if (all)
        hook::log("  row %u (%s): its %u mob(s) have no mark on this map - every mark left shown (marks listed above)", row,
                  data[row] > kHeading ? "quest heading" : "mob line", (unsigned)mobs.size());
    else
        hook::log("  row %u (%s): %d circle(s) and %d label(s) of %u mob(s) shown, the rest hidden", row,
                  data[row] > kHeading ? "quest heading" : "mob line", areas, labels, (unsigned)mobs.size());
    return false;
}

}  // namespace

HOOK_PLUGIN("map_legend_focus") {
    pgwin::on_process(on_process);
    pgwin::install();
}
