// popup_windows - the small game popups can be dragged, and keep where they were put (operator 2026-10-01: "make the
// little 'Quest rewards available, from this npc <icon>' thing draggable ... it ALWAYS ends up behind the quest list";
// "Please make the mystery vault icon draggable too. Importantly, I want the location of these windows to save").
//
//   QuestFinishWin   the "quest completed - rewards available from this NPC" popup
//   QuestNewsWin     the new-quest notice (Game/NewQuest.nif)
//   MysteryVaultWin  the Mystery Vault icon (OnReachTheLevel)
// All three are PgWinFrames (their constructors call PgWinFrame's, 2016 0x8B0A20).
//
// DRAG - PgWinFrame::ProcessMeInput (2016 0x8B0BC0) moves a window on a press only if the virtual GetMovable (vtable
// +0x20C) says so; GetMovable returns the frame's movable byte, which none of the three sets:
//     2016 0x402390 / 2026 0x459150   8A 81 34 01 00 00 C3   mov al, [ecx+0x134] ; ret
// Detoured: the three answer true, every other window its own byte.
//
// POSITION - the client's own window-position option (MachineOpt, saved with the other UI options, keyed by window
// name, x/y as a fraction of the screen):
//     MachineOpt::RegistereWinPostion(PgWin*)  2026 0x7D8A60  cdecl - store the window's current position
//     MachineOpt::SetWinPostion(PgWin*)        2026 0x7D8C30  cdecl - move the window to its stored position
//     GameFrameWork::RegistereWinPostion()     2026 0x569F70  thiscall - stores the ~43 windows the game tracks
//     GameFrameWork::SetWindowsPosOption()     2026 0x56A2D0  thiscall - restores them
//     GameFrameWork::TerminateWindow()         2026 0x56F4F0  thiscall - stores each window, then destroys it
// (found from the 2016 PDB names: the 43-call register run, GetWinPosInList 0x7DADC0 and its two callers, the list
// globals 0xC31C6C..0xC31C78). Our three are added to those passes: stored after RegistereWinPostion and before
// TerminateWindow, restored after SetWindowsPosOption. The windows are found in the GameFrameWork object by RTTI.
#include <hook_core.h>
#include <pgwin_msg.h>

#include <windows.h>

#include <cstring>

namespace {

const char* const kWindows[] = {"QuestFinishWin", "QuestNewsWin", "MysteryVaultWin"};
const int kNumWindows = sizeof kWindows / sizeof kWindows[0];

const unsigned kVaGetMovable = 0x00459150u;
const unsigned kVaRegisterPos = 0x007D8A60u;
const unsigned kVaSetPos = 0x007D8C30u;
const unsigned kVaFwRegister = 0x00569F70u;
const unsigned kVaFwRestore = 0x0056A2D0u;
const unsigned kVaFwTerminate = 0x0056F4F0u;
const unsigned char kGetMovableStock[7] = {0x8A, 0x81, 0x34, 0x01, 0x00, 0x00, 0xC3};
const unsigned kScanFrom = 0x100, kScanTo = 0x1400;     // GameFrameWork's window-pointer fields

hook::Detour g_get_movable, g_fw_register, g_fw_restore, g_fw_terminate;
bool g_logged_drag = false;

typedef bool(__cdecl* WinPosFn)(void* win);
typedef void(__fastcall* FwFn)(void* self, void* edx);

int which(const void* w) {
    for (int i = 0; i < kNumWindows; i++)
        if (pgwin::is(w, kWindows[i])) return i;
    return -1;
}

// the three windows held by the GameFrameWork (null where not created)
void find_windows(void* fw, void* out[kNumWindows]) {
    for (int i = 0; i < kNumWindows; i++) out[i] = nullptr;
    for (unsigned o = kScanFrom; o < kScanTo; o += 4) {
        void* p = nullptr;
        __try {
            p = *(void**)((char*)fw + o);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return;
        }
        if (!p || (unsigned)p < 0x10000) continue;
        int k = which(p);
        if (k >= 0 && !out[k]) out[k] = p;
    }
}

void apply(void* fw, unsigned va, const char* what) {
    void* w[kNumWindows];
    find_windows(fw, w);
    WinPosFn fn = (WinPosFn)hook::rebase(va);
    for (int i = 0; i < kNumWindows; i++) {
        if (!w[i]) {
            hook::log("popup_windows: %s - %s not created yet", what, kWindows[i]);
            continue;
        }
        bool ok = false;
        __try {
            ok = fn(w[i]);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            hook::log("popup_windows: %s - exception on %s", what, kWindows[i]);
            continue;
        }
        hook::log("popup_windows: %s %s %p -> %s", what, kWindows[i], w[i], ok ? "ok" : "nothing stored / no name");
    }
}

bool __fastcall get_movable_impl(void* self, void* /*edx*/) {
    int k = which(self);
    if (k >= 0) {
        if (!g_logged_drag) {
            g_logged_drag = true;
            hook::log("popup_windows: %s %p asked GetMovable - answering true (draggable)", kWindows[k], self);
        }
        return true;
    }
    typedef bool(__fastcall * Orig)(void*, void*);
    return ((Orig)g_get_movable.trampoline)(self, 0);
}

void __fastcall fw_register_impl(void* self, void* /*edx*/) {
    ((FwFn)g_fw_register.trampoline)(self, 0);
    apply(self, kVaRegisterPos, "store");
}

void __fastcall fw_restore_impl(void* self, void* /*edx*/) {
    ((FwFn)g_fw_restore.trampoline)(self, 0);
    apply(self, kVaSetPos, "restore");
}

void __fastcall fw_terminate_impl(void* self, void* /*edx*/) {
    apply(self, kVaRegisterPos, "store before terminate");
    ((FwFn)g_fw_terminate.trampoline)(self, 0);
}

}  // namespace

HOOK_PLUGIN("popup_windows") {
    unsigned char* gm = (unsigned char*)hook::rebase(kVaGetMovable);
    if (std::memcmp(gm, kGetMovableStock, sizeof kGetMovableStock) != 0) {
        hook::log("popup_windows: unexpected bytes at PgWinFrame::GetMovable 0x459150 - NOTHING hooked");
        return;
    }
    hook::hook_function("PgWinFrame::GetMovable 0x459150 (popups draggable)", gm, (void*)get_movable_impl, &g_get_movable);
    hook::hook_function("GameFrameWork::RegistereWinPostion 0x569F70 (+popups)", hook::rebase(kVaFwRegister),
                        (void*)fw_register_impl, &g_fw_register);
    hook::hook_function("GameFrameWork::SetWindowsPosOption 0x56A2D0 (+popups)", hook::rebase(kVaFwRestore),
                        (void*)fw_restore_impl, &g_fw_restore);
    hook::hook_function("GameFrameWork::TerminateWindow 0x56F4F0 (+popups)", hook::rebase(kVaFwTerminate),
                        (void*)fw_terminate_impl, &g_fw_terminate);
}
