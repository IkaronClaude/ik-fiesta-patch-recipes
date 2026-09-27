// pgwin_msg.h - header-only hooks for the 2026 client's WINDOW MESSAGING (the PgWin / PgWinMgr message pump).
//
// Operator 2026-09-27: "a hooking utility header only lib ... specifically for hooking this message pump / window
// messaging". Include it from a client plugin (build_plugin.bat client <name> puts client\include on the path).
//
// ---- how the client's windows talk (2016 Fiesta.bin + Fiesta.pdb names, 2026 US Fiesta.exe addresses) ------------------
//
//   PgWin::PostMsg(target, msg, wParam, lParam)   2026 0x877A40 (2016 0x8B2640)  thiscall(sender, ...) -> bool, ret 0x10
//       queues the message with the window manager PgWinMgr (2026 instance 0xD1B810, 2016 0xB59720) after
//       PgWinMgr::IsIn(target) (2026 0x881DA0) says the target still exists.
//   PgWin::SendMsg(target, msg, wParam, lParam)   2016 0x8B26B0; INLINED in 2026 (IsIn + a direct ProcessMsg call).
//   PgWin::ProcessMsg(msg, wParam, lParam)        2026 0x8784C0 (2016 0x8B2500)  thiscall(receiver, ...), ret 0xC
//       THE FUNNEL: every message a window receives - queued or sent - goes through here. An 8-way switch on msg
//       calls one virtual of the receiver (table kHandlerSlot); msg 1 and 2 are handled without a virtual.
//   The 2026 PgWin vtable is the 2016 one shifted by 2 slots from about slot 60 on (e.g. OnCommand 95 -> 97).
//
//   Messages seen / read (2026-09-27, probes map_vtable_probe / msg_probe on the operator's client):
//     1  close                     (a PgWinCloseBut posts it to its window after a release)
//     4  edit text notification    (PgWinEditText -> EditWin -> AccountWin, wParam = field)
//     5  COMMAND to the owner      -> OnCommand(wParam = the control's command id, lParam = argument, e.g. a list row).
//                                     2016 SlideListWin::OnClickItem(row) sends (5, list command id, row) to its parent.
//     7  BUTTON STATE from a child -> vtable slot 100; wParam 0 hover / 1 press / 2 release; lParam = the button (PgWin*).
//                                     Buttons repost it every frame while hovered, so filter wParam 0.
//
// ---- this header ---------------------------------------------------------------------------------------------------------
//
//   pgwin::on_process(fn)  fn(Message&) runs BEFORE the receiver's ProcessMsg; return true to swallow the message.
//   pgwin::on_post(fn)     fn(sender, Message&) runs before a PostMsg is queued; return true to drop it.
//   pgwin::install()       installs both detours (once per plugin DLL; several plugins chain - hook_core relocates the
//                          previous plugin's JMP into its trampoline).
//   pgwin::process(w, ...) deliver a message NOW, the way the inlined SendMsg does (checks IsIn first).
//   pgwin::post(from, to, ...), pgwin::alive(w), pgwin::class_of(w) (RTTI name), pgwin::is(w, "SlideListWin").
#pragma once

#include <hook_core.h>

#include <windows.h>

#include <cstring>

namespace pgwin {

// ---- 2026 US Fiesta.exe (rebased at runtime; the client is ASLR'd) ----
const unsigned kVaPostMsg = 0x00877A40u;
const unsigned kVaProcessMsg = 0x008784C0u;
const unsigned kVaWinMgr = 0x00D1B810u;
const unsigned kVaWinMgrIsIn = 0x00881DA0u;

enum Msg : unsigned { kClose = 1, kEditNotify = 4, kCommand = 5, kButtonState = 7 };
enum ButtonPhase : unsigned { kHover = 0, kPress = 1, kRelease = 2 };

// msg -> the receiver's vtable slot ProcessMsg calls (2026). -1 = no virtual. 2016 = the same minus 2.
const int kHandlerSlot[9] = {-1, -1, -1, 94, 95, 97, 98, 100, 96};

struct Message {
    void* window;       // the receiver (ProcessMsg) or the target (PostMsg)
    unsigned msg;
    unsigned wparam;
    long lparam;
};

typedef bool (*ProcessFn)(Message& m);            // true = swallow
typedef bool (*PostFn)(void* sender, Message& m);  // true = drop

// ---- RTTI ----
// MSVC: vtable[-1] = CompleteObjectLocator, +0xC = TypeDescriptor*, +8 = the decorated name ".?AVFullMapWin@@".
inline const char* class_of(const void* w) {
    __try {
        if (!w) return "null";
        void** vt = *(void***)w;
        char* col = (char*)vt[-1];
        char* td = *(char**)(col + 0xC);
        return td + 8;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return "?";
    }
}

// is(w, "SlideListWin") - exact class (not a base class)
inline bool is(const void* w, const char* cls) {
    const char* n = class_of(w);
    size_t k = std::strlen(cls);
    return std::strncmp(n, ".?AV", 4) == 0 && std::strncmp(n + 4, cls, k) == 0 && std::strcmp(n + 4 + k, "@@") == 0;
}

inline void* vtable_entry(const void* w, int slot) { return w ? (*(void***)w)[slot] : nullptr; }

// ---- calls into the game ----
inline bool alive(void* w) {
    typedef bool(__fastcall * IsIn)(void*, void*, void*);
    return w && ((IsIn)hook::rebase(kVaWinMgrIsIn))(hook::rebase(kVaWinMgr), 0, w);
}

namespace detail {
struct State {
    hook::Detour process, post;
    ProcessFn on_process[8] = {};
    PostFn on_post[8] = {};
    bool installed = false;
};
inline State& state() {
    static State s;
    return s;
}
typedef void(__fastcall* ProcessMsgFn)(void*, void*, unsigned, unsigned, long);
typedef bool(__fastcall* PostMsgFn)(void*, void*, void*, unsigned, unsigned, long);

inline void __fastcall process_hook(void* w, void*, unsigned msg, unsigned wparam, long lparam) {
    Message m{w, msg, wparam, lparam};
    for (ProcessFn f : state().on_process)
        if (f && f(m)) return;
    ((ProcessMsgFn)state().process.trampoline)(w, 0, m.msg, m.wparam, m.lparam);
}

inline bool __fastcall post_hook(void* sender, void*, void* target, unsigned msg, unsigned wparam, long lparam) {
    Message m{target, msg, wparam, lparam};
    for (PostFn f : state().on_post)
        if (f && f(sender, m)) return false;
    return ((PostMsgFn)state().post.trampoline)(sender, 0, m.window, m.msg, m.wparam, m.lparam);
}
}  // namespace detail

// deliver now: what the 2026 client's inlined SendMsg does
inline void process(void* w, unsigned msg, unsigned wparam, long lparam) {
    if (!alive(w)) return;
    void* f = detail::state().process.trampoline ? detail::state().process.trampoline : hook::rebase(kVaProcessMsg);
    ((detail::ProcessMsgFn)f)(w, 0, msg, wparam, lparam);
}

inline bool post(void* sender, void* target, unsigned msg, unsigned wparam, long lparam) {
    void* f = detail::state().post.trampoline ? detail::state().post.trampoline : hook::rebase(kVaPostMsg);
    return ((detail::PostMsgFn)f)(sender, 0, target, msg, wparam, lparam);
}

inline bool on_process(ProcessFn fn) {
    for (ProcessFn& f : detail::state().on_process)
        if (!f) { f = fn; return true; }
    return false;
}

inline bool on_post(PostFn fn) {
    for (PostFn& f : detail::state().on_post)
        if (!f) { f = fn; return true; }
    return false;
}

inline void install() {
    detail::State& s = detail::state();
    if (s.installed) return;
    s.installed = true;
    hook::hook_function("PgWin::ProcessMsg 0x8784C0 (pgwin_msg: every delivered window message)", hook::rebase(kVaProcessMsg),
                        (void*)detail::process_hook, &s.process);
    hook::hook_function("PgWin::PostMsg 0x877A40 (pgwin_msg: every queued window message)", hook::rebase(kVaPostMsg),
                        (void*)detail::post_hook, &s.post);
}

}  // namespace pgwin
