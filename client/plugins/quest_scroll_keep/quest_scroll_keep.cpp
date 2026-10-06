// quest_scroll_keep - opening the quest window from the quest-finished popup keeps the list where it was (Fiesta2026on2016
// ticket P5, operator 2026-10-03: "When you click the quest finished popup, it opens to that quest. BUT: The Acceptable
// tab scrolls to the top, very annoying with 50+ quests to manage. Should retain its scroll pos but with bounds check").
//
// ---- THE STOCK CODE (2026 Fiesta.exe, 10.6.4 reference addresses; names from the 2016 PDB, read 2026-10-06) ---------------
//   QuestFinishWin::OnCommand (vtable slot 97, 0x730C00) pops the finished quest and calls
//   GameFrameWork::OpenQuestWin(quest, tab) 0x5845C0: questwin = this+0x358 -> CQuestWin2::SelectTab(tab) 0x7362C0
//   (tab +0x15C; rebuilds the list from the top, 0x738FA0) -> SetSelectedID(quest) 0x7362A0.
//   The list: SlideListWin at questwin+0x170 (row count +0x148, top row +0x150, redraw UpdateViewList 0x5259F0); its
//   SlideBar at questwin+0x174 (split count +0x130, position +0x134; SetSplitCnt 0x522C50 clamps the position to
//   [0, n-1]). The rebuild ends with exactly that: SetSplitCnt(count); list.top = bar.position; UpdateViewList.
//
// ---- THIS PLUGIN ---------------------------------------------------------------------------------------------------------
//   OpenQuestWin is wrapped. Before: the current tab's bar position is remembered (per tab). After: the new tab's
//   remembered position goes back through the same three steps (SetSplitCnt does the bounds check against the new list).
#include <hook_core.h>
#include <client_addrs.h>

#include <windows.h>

#include <cstring>

namespace {

const unsigned kFrameQuestWin = 0x358;
const unsigned kWinTab = 0x15C;
const unsigned kWinList = 0x170;
const unsigned kWinBar = 0x174;
const unsigned kListCount = 0x148;
const unsigned kListTop = 0x150;
const unsigned kBarPos = 0x134;
const int kTabs = 8;
const unsigned char kStockOpen[12] = {0x55, 0x8B, 0xEC, 0x56, 0x8B, 0xF1, 0x8B, 0x8E, 0x58, 0x03, 0x00, 0x00};

hook::Detour g_open;
int g_pos[kTabs];
bool g_have[kTabs];

typedef void(__fastcall* OpenFn)(void* frame, void* edx, int quest, int tab);
typedef void(__fastcall* SplitFn)(void* bar, void* edx, int n);
typedef void(__fastcall* ViewFn)(void* list, void* edx);

template <class T> T& at(void* p, unsigned off) { return *(T*)((char*)p + off); }

void* quest_win(void* frame) { return at<void*>(frame, kFrameQuestWin); }

void remember(void* win) {
    void* bar = at<void*>(win, kWinBar);
    int tab = at<int>(win, kWinTab);
    if (!bar || tab < 0 || tab >= kTabs) return;
    g_pos[tab] = at<int>(bar, kBarPos);
    g_have[tab] = true;
}

void restore(void* win) {
    void* bar = at<void*>(win, kWinBar);
    void* list = at<void*>(win, kWinList);
    int tab = at<int>(win, kWinTab);
    if (!bar || !list || tab < 0 || tab >= kTabs || !g_have[tab] || g_pos[tab] <= 0) return;
    at<int>(bar, kBarPos) = g_pos[tab];
    ((SplitFn)hook::rebase(caddr::va(caddr::kSlideBarSetSplitCnt)))(bar, 0, at<int>(list, kListCount));   // clamps
    at<int>(list, kListTop) = at<int>(bar, kBarPos);
    ((ViewFn)hook::rebase(caddr::va(caddr::kSlideListUpdateView)))(list, 0);
    hook::log("quest_scroll_keep: tab %d back at row %d (wanted %d, %d rows)", tab, at<int>(bar, kBarPos), g_pos[tab],
              at<int>(list, kListCount));
}

void __fastcall open_impl(void* frame, void* /*edx*/, int quest, int tab) {
    void* win = nullptr;
    __try {
        win = quest_win(frame);
        if (win) remember(win);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        win = nullptr;
    }
    ((OpenFn)g_open.trampoline)(frame, 0, quest, tab);
    __try {
        win = quest_win(frame);
        if (win) restore(win);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook::log("quest_scroll_keep: fault restoring the list position - left where the window put it");
    }
}

}  // namespace

HOOK_PLUGIN("quest_scroll_keep") {
    if (const char* m = caddr::missing({caddr::kOpenQuestWin, caddr::kSlideBarSetSplitCnt, caddr::kSlideListUpdateView})) {
        hook::log("quest_scroll_keep: %s - not hooked", m);
        return;
    }
    unsigned char* p = (unsigned char*)hook::rebase(caddr::va(caddr::kOpenQuestWin));
    if (std::memcmp(p, kStockOpen, sizeof kStockOpen) != 0) {
        hook::log("quest_scroll_keep: OpenQuestWin is not the expected code (questwin at +0x358) - not hooked");
        return;
    }
    if (hook::hook_function("GameFrameWork::OpenQuestWin", p, (void*)open_impl, &g_open))
        hook::log("quest_scroll_keep: the quest list keeps its scroll position when the window is opened from a popup");
}
