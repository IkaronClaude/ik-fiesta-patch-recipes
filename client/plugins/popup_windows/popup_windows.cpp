// popup_windows - the small game popups can be dragged, and keep where they were put (operator 2026-10-01: "make the
// little 'Quest rewards available, from this npc <icon>' thing draggable ... it ALWAYS ends up behind the quest list";
// "Please make the mystery vault icon draggable too. Importantly, I want the location of these windows to save").
//
//   QuestFinishWin   the "quest completed - rewards available from this NPC" popup
//   QuestNewsWin     the new-quest notice (Game/NewQuest.nif)
//   MysteryVaultWin  the Mystery Vault icon (OnReachTheLevel)
//
// DRAG - press, move, release; a press released in place is still a click (operator: "Try option 2 first").
// The popups are PgWinFrames, but their whole face is a child button (QuestFinishWin::OnQuestCheckClick), so the frame's
// own drag (PgWinFrame::ProcessMeInput 2016 0x8B0BC0: only on a press on the frame's OWN surface, then GetMovable) never
// starts - forcing GetMovable true (first try) changed nothing. So the drag is done here, from the raw mouse messages
// (a WH_GETMESSAGE hook on the UI thread):
//   WM_LBUTTONDOWN inside a SHOWN popup's rectangle -> remember the cursor and the window position (the press still goes
//       to the game). "Shown" = PgWinMgr::IsIn (2016: CloseWin removes the window from the manager's list).
//   WM_MOUSEMOVE with the button held -> past kDragPixels the window follows the cursor (its own move, vtable +0x134,
//       the call MachineOpt::SetWinPostion makes).
//   release after a drag -> the button's release (PgWin message 7, wParam 2 - the click) to the popup is swallowed.
// Rectangle: GetXPos / GetYPos (vtable +0xA4 / +0xA8, the calls MachineOpt::RegistereWinPostion makes), GetWidth /
// GetHeight (+0x90 / +0x94, 2016 PgWin; below the slot where the 2026 table shifts). Cursor pixels -> UI units by the
// screen size globals SetWinPostion scales with (2026 0xC321C0 width, 0xC321C4 height) over the client rectangle.
//
// POSITION - the client's own window-position option (MachineOpt, saved with the other UI options, keyed by window
// name, x/y as a fraction of the screen):
//     MachineOpt::RegistereWinPostion(PgWin*)  2026 0x7D8A60  cdecl - store the window's current position
//     MachineOpt::SetWinPostion(PgWin*)        2026 0x7D8C30  cdecl - move the window to its stored position
//     GameFrameWork::RegistereWinPostion()     2026 0x569F70  thiscall - stores the ~43 windows the game tracks
//     GameFrameWork::SetWindowsPosOption()     2026 0x56A2D0  thiscall - restores them
//     GameFrameWork::TerminateWindow()         2026 0x56F4F0  thiscall - stores each window, then destroys it
// Our three are added to those passes (stored after RegistereWinPostion and before TerminateWindow, restored after
// SetWindowsPosOption); they are found in the GameFrameWork object by RTTI.
#include <hook_core.h>
#include <pgwin_msg.h>

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

const char* const kWindows[] = {"QuestFinishWin", "QuestNewsWin", "MysteryVaultWin"};
const int kNumWindows = sizeof kWindows / sizeof kWindows[0];

const unsigned kVaRegisterPos = 0x007D8A60u;
const unsigned kVaSetPos = 0x007D8C30u;
const unsigned kVaFwRegister = 0x00569F70u;
const unsigned kVaFwRestore = 0x0056A2D0u;
const unsigned kVaFwTerminate = 0x0056F4F0u;
const unsigned kVaScreenW = 0x00C321C0u, kVaScreenH = 0x00C321C4u;
const unsigned kScanFrom = 0x100, kScanTo = 0x1400;     // GameFrameWork's window-pointer fields
const int kSlotWidth = 0x90 / 4, kSlotHeight = 0x94 / 4, kSlotX = 0xA4 / 4, kSlotY = 0xA8 / 4, kSlotMove = 0x134 / 4;
const int kDragPixels = 4;                              // UI units the cursor moves before it is a drag, not a click
const DWORD kSwallowMs = 400;                           // after a drop: the click messages to the popup are dropped
// QUEST-COMPLETED POPUP AFTER ACCEPTING (operator 2026-10-01: a talk / delivery quest is completable the moment it is
// accepted, "but they just sit in the quest log as Reward without ever showing in the small popup (unless you relog)";
// "Don't call it every second, instead, add a call right after starting a new quest"). QuestFinishWin::UpdateQuest
// (2026 0x730250) pops it; the client runs it on a quest mob kill, an item pick-up or a quest script command, not on an
// accept. (First try: a hook on what looked like CQuest::SetQuestAccept, 2026 0x901F70 - it never ran on the operator's
// accepts.) So the player's quest list is watched instead: the quest manager (0x7EB840, what UpdateQuest asks) holds it
// at +4 count / +8 present / +0xC entries of 0x25 bytes, quest id u16 at +0 (2026 GetNewQuestStatus(QUEST_DATA*)
// 0x8FF5C0). At most every kQuestCheckMs, on a UI message, each quest's COMPUTED status (GetNewQuestStatus(id) 0x8FF590 -
// a delivery quest turns 8 when its item is in the bag, the stored byte does not) is folded into a fingerprint; when it
// changes - an accept, an item arriving, a hand-in - UpdateQuest runs once. Its already-shown list stops repeats.
const unsigned kVaUpdateQuest = 0x00730250u;
const unsigned kVaGetQuestMgr = 0x007EB840u;
const unsigned kVaGetStatus = 0x008FF590u;
const unsigned kOffQuestCount = 0x4, kOffQuestList = 0x8, kOffQuestEntries = 0xC, kQuestEntry = 0x25;
const DWORD kQuestCheckMs = 250;

hook::Detour g_fw_register, g_fw_restore, g_fw_terminate;
void* g_win[kNumWindows] = {};                          // the popups, as found in the GameFrameWork
HHOOK g_msg_hook = nullptr;
DWORD g_quest_checked_at = 0;
unsigned g_quest_print = 0;                             // fingerprint of the quest list (0 = not taken yet)

struct Drag {
    void* win = nullptr;
    int cursor_x = 0, cursor_y = 0, win_x = 0, win_y = 0;
    bool moved = false;
    DWORD released_at = 0;                              // GetTickCount of the release ending a real drag
    void* released_win = nullptr;
} g_drag;

typedef bool(__cdecl* WinPosFn)(void* win);
typedef void(__fastcall* FwFn)(void* self, void* edx);
typedef int(__fastcall* IntGetter)(void* self, void* edx);
typedef void(__fastcall* MoveFn)(void* self, void* edx, int x, int y);

int which(const void* w) {
    for (int i = 0; i < kNumWindows; i++)
        if (pgwin::is(w, kWindows[i])) return i;
    return -1;
}

int vcall_int(void* w, int slot) { return ((IntGetter)pgwin::vtable_entry(w, slot))(w, 0); }

void find_windows(void* fw) {
    void* found[kNumWindows] = {};
    for (unsigned o = kScanFrom; o < kScanTo; o += 4) {
        void* p = nullptr;
        __try {
            p = *(void**)((char*)fw + o);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
        if (!p || (unsigned)p < 0x10000) continue;
        int k = which(p);
        if (k >= 0 && !found[k]) found[k] = p;
    }
    for (int i = 0; i < kNumWindows; i++) g_win[i] = found[i];
}

// cursor (client pixels of the message's window) -> UI units
void to_ui(HWND hwnd, LPARAM lp, int* x, int* y) {
    int px = (short)LOWORD(lp), py = (short)HIWORD(lp);
    RECT rc;
    int sw = *(int*)hook::rebase(kVaScreenW), sh = *(int*)hook::rebase(kVaScreenH);
    if (hwnd && GetClientRect(hwnd, &rc) && rc.right > 0 && rc.bottom > 0 && sw > 0 && sh > 0) {
        *x = MulDiv(px, sw, rc.right);
        *y = MulDiv(py, sh, rc.bottom);
    } else {
        *x = px;
        *y = py;
    }
}

void* popup_at(int x, int y) {
    for (int i = 0; i < kNumWindows; i++) {
        void* w = g_win[i];
        if (!w) continue;
        __try {
            if (!pgwin::alive(w)) continue;              // not shown
            int wx = vcall_int(w, kSlotX), wy = vcall_int(w, kSlotY);
            int ww = vcall_int(w, kSlotWidth), wh = vcall_int(w, kSlotHeight);
            if (x >= wx && x < wx + ww && y >= wy && y < wy + wh) return w;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    return nullptr;
}

void update_quest(const char* why) {
    void* w = g_win[0];                                 // QuestFinishWin
    if (!w) return;
    __try {
        ((FwFn)hook::rebase(kVaUpdateQuest))(w, 0);
        hook::log("popup_windows: QuestFinishWin::UpdateQuest after %s", why);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook::log("popup_windows: exception in UpdateQuest after %s", why);
    }
}

typedef void*(__cdecl* GetQuestMgr)();
typedef int(__fastcall* GetStatus)(void* mgr, void* edx, unsigned id);

// fingerprint of (count, every quest's id + computed status); 0 if the list cannot be read
unsigned quest_print() {
    unsigned h = 2166136261u;
    __try {
        char* mgr = (char*)((GetQuestMgr)hook::rebase(kVaGetQuestMgr))();
        if (!mgr || !*(void**)(mgr + kOffQuestList)) return 0;
        int n = *(int*)(mgr + kOffQuestCount);
        char* e = *(char**)(mgr + kOffQuestEntries);
        if (n < 0 || n > 4096 || !e) return 0;
        GetStatus status = (GetStatus)hook::rebase(kVaGetStatus);
        h = (h ^ (unsigned)n) * 16777619u;
        for (int i = 0; i < n; i++) {
            unsigned id = *(unsigned short*)(e + i * kQuestEntry);
            h = (h ^ id) * 16777619u;
            h = (h ^ (unsigned)status(mgr, 0, id)) * 16777619u;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return h ? h : 1;
}

void check_quests() {
    DWORD now = GetTickCount();
    if (now - g_quest_checked_at < kQuestCheckMs || !g_win[0]) return;
    g_quest_checked_at = now;
    unsigned p = quest_print();
    if (!p) return;
    bool changed = g_quest_print && p != g_quest_print;
    g_quest_print = p;
    if (changed) update_quest("a quest list change (accept / item / hand-in)");
}

// OWN POSITION FILE (operator 2026-10-01: the positions "save only until zone restart, they survive 'Switch Character' but
// ... after a while they're back where they started"). MachineOpt keeps them in memory and writes its option file only on a
// clean client exit - a kick (zone restart) or a crash skips that, so the next start loads the old file. Each drop is
// written at once to <hooks>/popup_windows.pos.ini (x, y as 1/100000 of the screen, the way MachineOpt stores them) and
// applied after the client's own restore at every login.
const int kPosScale = 100000;

const char* pos_file() {
    static char path[MAX_PATH] = {0};
    if (!path[0]) {
        HMODULE me = nullptr;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)&pos_file, &me);
        GetModuleFileNameA(me, path, MAX_PATH);
        char* slash = std::strrchr(path, '\\');
        char* name = slash ? slash + 1 : path;
        strcpy_s(name, MAX_PATH - (name - path), "popup_windows.pos.ini");
    }
    return path;
}

void save_pos(int k, void* w) {
    if (k < 0) return;
    int sw = *(int*)hook::rebase(kVaScreenW), sh = *(int*)hook::rebase(kVaScreenH);
    if (sw <= 0 || sh <= 0) return;
    char v[48];
    wsprintfA(v, "%d,%d", MulDiv(vcall_int(w, kSlotX), kPosScale, sw), MulDiv(vcall_int(w, kSlotY), kPosScale, sh));
    WritePrivateProfileStringA("positions", kWindows[k], v, pos_file());
}

void load_positions() {
    int sw = *(int*)hook::rebase(kVaScreenW), sh = *(int*)hook::rebase(kVaScreenH);
    if (sw <= 0 || sh <= 0) return;
    for (int i = 0; i < kNumWindows; i++) {
        char v[48] = {0};
        int fx, fy;
        if (!g_win[i] || !GetPrivateProfileStringA("positions", kWindows[i], "", v, sizeof v, pos_file()) ||
            sscanf_s(v, "%d,%d", &fx, &fy) != 2)
            continue;
        __try {
            ((MoveFn)pgwin::vtable_entry(g_win[i], kSlotMove))(g_win[i], 0, MulDiv(fx, sw, kPosScale), MulDiv(fy, sh, kPosScale));
            hook::log("popup_windows: %s placed from %s at %d,%d", kWindows[i], "popup_windows.pos.ini",
                      MulDiv(fx, sw, kPosScale), MulDiv(fy, sh, kPosScale));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
}

LRESULT CALLBACK msg_hook(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION && wp == PM_REMOVE) check_quests();
    if (code == HC_ACTION && wp == PM_REMOVE) {
        MSG* m = (MSG*)lp;
        __try {
            if (m->message == WM_LBUTTONDOWN) {
                int x, y;
                to_ui(m->hwnd, m->lParam, &x, &y);
                void* w = popup_at(x, y);
                g_drag.win = w;
                g_drag.moved = false;
                if (w) {
                    g_drag.cursor_x = x;
                    g_drag.cursor_y = y;
                    g_drag.win_x = vcall_int(w, kSlotX);
                    g_drag.win_y = vcall_int(w, kSlotY);
                }
            } else if (m->message == WM_MOUSEMOVE && g_drag.win) {
                if (!(m->wParam & MK_LBUTTON) || !pgwin::alive(g_drag.win)) {
                    g_drag.win = nullptr;
                } else {
                    int x, y;
                    to_ui(m->hwnd, m->lParam, &x, &y);
                    int dx = x - g_drag.cursor_x, dy = y - g_drag.cursor_y;
                    if (!g_drag.moved && (std::abs(dx) > kDragPixels || std::abs(dy) > kDragPixels)) {
                        g_drag.moved = true;
                        hook::log("popup_windows: dragging %s %p", kWindows[which(g_drag.win)], g_drag.win);
                    }
                    if (g_drag.moved)
                        ((MoveFn)pgwin::vtable_entry(g_drag.win, kSlotMove))(g_drag.win, 0, g_drag.win_x + dx,
                                                                              g_drag.win_y + dy);
                }
            } else if (m->message == WM_LBUTTONUP && g_drag.win) {
                if (g_drag.moved) {
                    g_drag.released_at = GetTickCount();
                    g_drag.released_win = g_drag.win;
                    // the release lands far off the window, so a button that clicks on "released over me" does not
                    m->lParam = MAKELPARAM((WORD)(short)-30000, (WORD)(short)-30000);
                    hook::log("popup_windows: dropped %s at %d,%d", kWindows[which(g_drag.win)],
                              vcall_int(g_drag.win, kSlotX), vcall_int(g_drag.win, kSlotY));
                    save_pos(which(g_drag.win), g_drag.win);
                }
                g_drag.win = nullptr;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            g_drag.win = nullptr;
        }
    }
    return CallNextHookEx(g_msg_hook, code, wp, lp);
}

// the click a drag ends with: the button's release (message 7, wParam 2) reaching the popup right after the drop
// (operator 2026-10-01: swallowing the release alone was not enough - "the button press still goes through at the end of
// the drag"): the command the button sends its window (message 5) is swallowed too, for kSwallowMs after the drop.
bool swallow_click(pgwin::Message& m) {
    if (!g_drag.released_win || m.window != g_drag.released_win) return false;
    if (GetTickCount() - g_drag.released_at > kSwallowMs) {
        g_drag.released_win = nullptr;
        return false;
    }
    bool release = m.msg == pgwin::kButtonState && m.wparam == pgwin::kRelease;
    if (!release && m.msg != pgwin::kCommand) return false;
    hook::log("popup_windows: %s after the drag swallowed (msg %u, wparam %u)", release ? "button release" : "command",
              m.msg, m.wparam);
    return true;
}

void ensure_msg_hook() {
    if (g_msg_hook) return;
    g_msg_hook = SetWindowsHookExA(WH_GETMESSAGE, msg_hook, nullptr, GetCurrentThreadId());
    hook::log("popup_windows: mouse hook on UI thread %u %s", GetCurrentThreadId(), g_msg_hook ? "installed" : "FAILED");
}

void apply(void* fw, unsigned va, const char* what) {
    find_windows(fw);
    WinPosFn fn = (WinPosFn)hook::rebase(va);
    for (int i = 0; i < kNumWindows; i++) {
        if (!g_win[i]) {
            hook::log("popup_windows: %s - %s not created yet", what, kWindows[i]);
            continue;
        }
        bool ok = false;
        __try {
            ok = fn(g_win[i]);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            hook::log("popup_windows: %s - exception on %s", what, kWindows[i]);
            continue;
        }
        hook::log("popup_windows: %s %s %p -> %s", what, kWindows[i], g_win[i], ok ? "ok" : "nothing stored / no name");
    }
}

void __fastcall fw_register_impl(void* self, void* /*edx*/) {
    ((FwFn)g_fw_register.trampoline)(self, 0);
    apply(self, kVaRegisterPos, "store");
}

void __fastcall fw_restore_impl(void* self, void* /*edx*/) {
    ((FwFn)g_fw_restore.trampoline)(self, 0);
    apply(self, kVaSetPos, "restore");
    load_positions();                                   // our own file wins: it is written on every drop
    ensure_msg_hook();                                  // runs on the UI thread
}

void __fastcall fw_terminate_impl(void* self, void* /*edx*/) {
    apply(self, kVaRegisterPos, "store before terminate");
    for (int i = 0; i < kNumWindows; i++) g_win[i] = nullptr;
    g_drag.win = g_drag.released_win = nullptr;
    g_quest_print = 0;                                  // the next character's list is not a "change"
    ((FwFn)g_fw_terminate.trampoline)(self, 0);
}

}  // namespace

HOOK_PLUGIN("popup_windows") {
    hook::hook_function("GameFrameWork::RegistereWinPostion 0x569F70 (+popups)", hook::rebase(kVaFwRegister),
                        (void*)fw_register_impl, &g_fw_register);
    hook::hook_function("GameFrameWork::SetWindowsPosOption 0x56A2D0 (+popups, mouse hook)", hook::rebase(kVaFwRestore),
                        (void*)fw_restore_impl, &g_fw_restore);
    hook::hook_function("GameFrameWork::TerminateWindow 0x56F4F0 (+popups)", hook::rebase(kVaFwTerminate),
                        (void*)fw_terminate_impl, &g_fw_terminate);
    pgwin::on_process(swallow_click);
    pgwin::install();
}
