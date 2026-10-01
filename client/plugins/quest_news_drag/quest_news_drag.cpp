// quest_news_drag - the round "quest rewards available from this NPC" notice can be dragged (operator 2026-10-01: "make
// the little 'Quest rewards available, from this npc <icon>' thing draggable. It's just a small like 64x64 circle UI
// element but it ALWAYS ends up behind the quest list").
//
// The notice is QuestNewsWin (2026 RTTI .?AVQuestNewsWin@@; Game\NewQuest.nif, a "Picking" node), a PgWinFrame. Dragging
// is PgWinFrame's own: ProcessMeInput (2016 0x8B0BC0) asks the virtual GetMovable (vtable +0x20C) on a press and only then
// moves the window. GetMovable returns the frame's movable byte:
//
//     2016 0x402390 / 2026 0x459150   8A 81 34 01 00 00  mov al, [ecx+0x134]
//                                     C3                 ret
//
// QuestNewsWin never sets it. This detours GetMovable: a QuestNewsWin answers true, every other window its own byte.
#include <hook_core.h>
#include <pgwin_msg.h>

#include <windows.h>

#include <cstring>

namespace {

const unsigned kVaGetMovable = 0x00459150u;      // PgWinFrame::GetMovable, 2026 US Fiesta.exe
const unsigned char kStock[7] = {0x8A, 0x81, 0x34, 0x01, 0x00, 0x00, 0xC3};

hook::Detour g_get_movable;
bool g_logged = false;

bool __fastcall get_movable_impl(void* self, void* /*edx*/) {
    if (pgwin::is(self, "QuestNewsWin")) {
        if (!g_logged) {
            g_logged = true;
            hook::log("quest_news_drag: QuestNewsWin %p asked GetMovable - answering true (draggable)", self);
        }
        return true;
    }
    typedef bool(__fastcall * Orig)(void*, void*);
    return ((Orig)g_get_movable.trampoline)(self, 0);
}

}  // namespace

HOOK_PLUGIN("quest_news_drag") {
    unsigned char* p = (unsigned char*)hook::rebase(kVaGetMovable);
    if (std::memcmp(p, kStock, sizeof kStock) != 0) {
        hook::log("quest_news_drag: unexpected bytes at PgWinFrame::GetMovable 0x459150 - NOT hooked");
        return;
    }
    hook::hook_function("PgWinFrame::GetMovable 0x459150 (QuestNewsWin draggable)", p, (void*)get_movable_impl,
                        &g_get_movable);
}
