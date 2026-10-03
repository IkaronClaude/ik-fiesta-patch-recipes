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
//   (+0x5C8: quest 0x664190, mob 0x6641A0), each shown / hidden with vtable +0x100(bool), as UpdateArea does.
//
// ---- BY QUEST AND MOB (2026-10-03, operator: "renders something when I click the empty row between quests and
//      frequently renders multiple quests together") --------------------------------------------------------------------
//   Read off the legend builder (10.6.6 0x611B40) and the client's own log of the clicks: the rows are, per quest, a
//   heading, its mob lines, then a spacer whose value is 0. A heading's value is 0xFFFF + n, n counting the quests in the
//   order the builder walks them (its counter [ebp-0xD4], the quest pointer [ebp-0xAC]) - so the FIRST heading is 0xFFFF
//   itself, which the old test (> 0xFFFF) read as "mob 65535". A spacer read as "mob 0" matched no mark, so every mark
//   was shown; and a mob several quests need (mob 9390: three quests) showed every one of those quests' circles.
//   Now the builder's numbering step (MapLegendHeading, mov ecx,[ebp-0xD4], 6 bytes) is detoured to record n -> quest
//   id. A heading shows the marks of its quest; a mob line the marks of that quest AND that mob (its quest = the heading
//   above it); a spacer changes nothing. A row whose quest has no mark on this map hides every mark (logged). Without
//   the n -> quest record (site check failed) it falls back to the mob test alone.
#include <pgwin_msg.h>

#include <cstring>
#include <map>
#include <set>

namespace {

const unsigned kVaAddQuestHelper = caddr::va(caddr::kFullMapAddQuestHelper);  // FullMapWin::AddQuestHelper(), thiscall
const unsigned kVaGetItemData = caddr::va(caddr::kSlideListGetItemData);     // SlideListWin item data (index, unsigned* out) -> bool, thiscall
const unsigned kVaAreaQuest = caddr::va(caddr::kMobAreaMarkQuest), kVaAreaMob = caddr::va(caddr::kMobAreaMarkMob);     // MobAreaMarkWin, thiscall -> u16
const unsigned kVaLabelQuest = caddr::va(caddr::kQuestHelperMarkQuest), kVaLabelMob = caddr::va(caddr::kQuestHelperMarkMob);   // QuestHelperMarkWin, thiscall -> u16
const unsigned kMapQuestList = 0x54C;           // FullMapWin -> its quest legend SlideListWin
const unsigned kMapAreaMarks = 0x334, kMapLabelMarks = 0x5C8;   // FullMapWin -> list nodes {next, prev, mark}
const unsigned kListTop = 0x150;                // SlideListWin: the first item shown (scroll offset)
const unsigned kListDirty = 0x154;              // SlideListWin byte UpdateArea clears at its end
const int kSlotShow = 0x100 / 4;
const unsigned kHeading = 0xFFFF;               // item data from this up = a quest heading (0xFFFF + n); 0 = a spacer
const unsigned kVaHeading = caddr::va(caddr::kMapLegendHeading);
// mov ecx,[ebp-0xD4]; lea eax,[ecx+0xFFFF]
const unsigned char kHeadingSite[] = {0x8B, 0x8D, 0x2C, 0xFF, 0xFF, 0xFF, 0x8D, 0x81, 0xFF, 0xFF, 0x00, 0x00};
const unsigned kMaxRows = 512;
const unsigned kOwnerScan = 0x80;               // bytes of the list searched for the owning FullMapWin

void* g_list = nullptr;
void* g_map = nullptr;
std::map<unsigned, unsigned> g_heading_quest;   // heading n -> quest id, as the builder last numbered them
void* g_heading_cont = nullptr;

void __cdecl heading(unsigned n, const unsigned short* quest) {
    if (n == 0) g_heading_quest.clear();
    unsigned q = 0;
    __try {
        if (quest) q = *quest;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    g_heading_quest[n] = q;
}

// in place of the builder's `mov ecx,[ebp-0xD4]`
__declspec(naked) void heading_site() {
    __asm {
        pushad
        pushfd
        push dword ptr [ebp - 0xAC]
        push dword ptr [ebp - 0xD4]
        call heading
        add esp, 8
        popfd
        popad
        mov ecx, [ebp - 0xD4]
        jmp g_heading_cont
    }
}

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

// what a click selects: a quest (0 = unknown) and its mobs (empty = every mob of the quest)
struct Pick {
    unsigned quest;
    std::set<unsigned> mobs;
};

bool picked(const Pick& p, unsigned quest, unsigned mob) {
    if (p.quest && quest != p.quest) return false;
    return p.mobs.empty() || p.mobs.count(mob) != 0;
}

// show the picked marks of one mark list and hide the rest; returns how many are shown
int show_marks(void* map, unsigned list_off, unsigned va_quest, unsigned va_mob, const Pick& p) {
    int shown = 0;
    __try {
        for (Node* n = *(Node**)((char*)map + list_off); n; n = n->next) {
            if (!n->mark) continue;
            bool on = picked(p, ((U16Fn)hook::rebase(va_quest))(n->mark, 0), ((U16Fn)hook::rebase(va_mob))(n->mark, 0));
            shown += on;
            ((ShowFn)pgwin::vtable_entry(n->mark, kSlotShow))(n->mark, 0, on ? 1 : 0);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook::log("map_legend_focus: fault walking the marks at +0x%X", list_off);
    }
    return shown;
}

void log_marks(void* map, unsigned list_off, unsigned va_quest, unsigned va_mob) {
    __try {
        for (Node* n = *(Node**)((char*)map + list_off); n; n = n->next)
            if (n->mark)
                hook::log("  mark %s: quest %u mob %u", list_off == kMapAreaMarks ? "area" : "label",
                          (unsigned)((U16Fn)hook::rebase(va_quest))(n->mark, 0), (unsigned)((U16Fn)hook::rebase(va_mob))(n->mark, 0));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

unsigned quest_of(unsigned n) {
    auto it = g_heading_quest.find(n);
    return it == g_heading_quest.end() ? 0u : it->second;
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
    for (unsigned i = 0; i < rows; i++) {
        if (data[i] >= kHeading)
            hook::log("  row %u: quest heading %u = quest %u", i, data[i] - kHeading, quest_of(data[i] - kHeading));
        else if (data[i])
            hook::log("  row %u: mob %u", i, data[i]);
        else
            hook::log("  row %u: spacer", i);
    }
    if (row >= rows) {
        hook::log("  row %u is past the list - marks left as they are", row);
        return false;
    }
    if (data[row] == 0) {
        hook::log("  row %u is a spacer - marks left as they are", row);
        return false;
    }

    // the quest: the clicked heading, or the heading above the clicked mob line
    unsigned h = row;
    while (h > 0 && data[h] < kHeading) h--;
    Pick p;
    p.quest = data[h] >= kHeading ? quest_of(data[h] - kHeading) : 0;
    if (data[row] < kHeading) {
        p.mobs.insert(data[row]);
    } else if (!p.quest) {
        for (unsigned i = row + 1; i < rows && data[i] && data[i] < kHeading; i++) p.mobs.insert(data[i]);
    }
    int areas = show_marks(map, kMapAreaMarks, kVaAreaQuest, kVaAreaMob, p);
    int labels = show_marks(map, kMapLabelMarks, kVaLabelQuest, kVaLabelMob, p);
    clear_byte(list, kListDirty);
    const char* what = data[row] >= kHeading ? "quest heading" : "mob line";
    if (!areas && !labels) {
        hook::log("  row %u (%s): quest %u%s has no mark on this map - every mark hidden (marks below)", row, what, p.quest,
                  p.quest ? "" : " (unknown: the heading record is not in)");
        log_marks(map, kMapAreaMarks, kVaAreaQuest, kVaAreaMob);
        log_marks(map, kMapLabelMarks, kVaLabelQuest, kVaLabelMob);
    } else {
        hook::log("  row %u (%s): quest %u, %s: %d circle(s) and %d label(s) shown, the rest hidden", row, what, p.quest,
                  p.mobs.empty() ? "every mob" : "one mob", areas, labels);
    }
    return false;
}

}  // namespace

HOOK_PLUGIN("map_legend_focus") {
    if (const char* m = caddr::missing({caddr::kFullMapAddQuestHelper, caddr::kMobAreaMarkMob, caddr::kMobAreaMarkQuest, caddr::kPgWinPostMsg, caddr::kPgWinProcessMsg, caddr::kQuestHelperMarkMob, caddr::kQuestHelperMarkQuest, caddr::kSlideListGetItemData, caddr::kWinMgrIsIn})) {
        hook::log("map_legend_focus: %s - not hooked", m);
        return;
    }
    const unsigned char* site = (const unsigned char*)hook::rebase(kVaHeading);
    if (caddr::missing({caddr::kMapLegendHeading}) || std::memcmp(site, kHeadingSite, sizeof kHeadingSite)) {
        hook::log("map_legend_focus: the legend builder's heading numbering is not the expected code - clicks pick by mob only");
    } else {
        g_heading_cont = (void*)(site + 6);
        unsigned char jmp[6] = {0xE9, 0, 0, 0, 0, 0x90};
        int rel = (int)((unsigned char*)&heading_site - (site + 5));
        std::memcpy(jmp + 1, &rel, 4);
        bool ok = hook::write_code((void*)site, jmp, sizeof jmp);
        hook::log("map_legend_focus: legend headings -> quests recorded at %p%s", site, ok ? "" : " - WRITE FAILED");
    }
    pgwin::on_process(on_process);
    pgwin::install();
}
