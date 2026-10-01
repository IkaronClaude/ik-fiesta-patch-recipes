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
// accept. CQuest::SetQuestAccept (2016 0x727CA0, 2026 0x901F70: sets the player quest's status byte +2 to 6; its only
// caller is On_NC_QUEST_SCRIPT_CMD_REQ) is hooked: after it, UpdateQuest runs on the next UI message, and once more
// kAcceptLateMs later for a delivery item that arrives just after the accept. Its already-shown list stops repeats.
const unsigned kVaUpdateQuest = 0x00730250u;
const unsigned kVaSetQuestAccept = 0x00901F70u;
const DWORD kAcceptLateMs = 1500;

hook::Detour g_fw_register, g_fw_restore, g_fw_terminate;
void* g_win[kNumWindows] = {};                          // the popups, as found in the GameFrameWork
HHOOK g_msg_hook = nullptr;
hook::Detour g_accept;
bool g_update_now = false;                              // a quest was accepted: UpdateQuest on the next UI message
DWORD g_update_late_at = 0;                             // ... and once more at this tick (0 = none)

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

void run_pending_updates() {
    if (g_update_now) {
        g_update_now = false;
        update_quest("a quest accept");
    }
    if (g_update_late_at && (int)(GetTickCount() - g_update_late_at) >= 0) {
        g_update_late_at = 0;
        update_quest("a quest accept (late, for a delivery item)");
    }
}

int __fastcall accept_impl(void* self, void* /*edx*/, unsigned id) {
    typedef int(__fastcall * Orig)(void*, void*, unsigned);
    int r = ((Orig)g_accept.trampoline)(self, 0, id);
    hook::log("popup_windows: quest %u accepted - the completed popup is checked next", id & 0xFFFF);
    g_update_now = true;
    g_update_late_at = GetTickCount() + kAcceptLateMs;
    if (!g_update_late_at) g_update_late_at = 1;
    return r;
}

LRESULT CALLBACK msg_hook(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION && wp == PM_REMOVE) run_pending_updates();
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
    ensure_msg_hook();                                  // runs on the UI thread
}

void __fastcall fw_terminate_impl(void* self, void* /*edx*/) {
    apply(self, kVaRegisterPos, "store before terminate");
    for (int i = 0; i < kNumWindows; i++) g_win[i] = nullptr;
    g_drag.win = g_drag.released_win = nullptr;
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
    const unsigned char kAcceptStock[7] = {0x55, 0x8B, 0xEC, 0x83, 0x79, 0x08, 0x00};   // push ebp; mov ebp,esp; cmp [ecx+8],0
    unsigned char* acc = (unsigned char*)hook::rebase(kVaSetQuestAccept);
    if (std::memcmp(acc, kAcceptStock, sizeof kAcceptStock) == 0)
        hook::hook_function("CQuest::SetQuestAccept 0x901F70 (completed popup after an accept)", acc, (void*)accept_impl,
                            &g_accept);
    else
        hook::log("popup_windows: unexpected bytes at CQuest::SetQuestAccept 0x901F70 - accept hook NOT installed");
    pgwin::on_process(swallow_click);
    pgwin::install();
}
