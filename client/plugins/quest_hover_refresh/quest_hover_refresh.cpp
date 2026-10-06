// quest_hover_refresh - the mob hover box shows the quests you have NOW, not the ones you had when you first pointed at
// the mob (Fiesta2026on2016 ticket P3 "MOB HOVER QUEST INFO SOMETIMES MISSING UNTIL THE MAP IS REOPENED"; operator
// 2026-10-06: "I re-accepted a quest for this mob while fighting it ... no quest hover box appearing at all").
//
// The hover box is QuestHelperMgr's condition tooltip (2016 names, 2016 PDB; 2026 10.6.6 addresses):
//   GameFrameWork::ProcessInput (0x576377) -> AddConditionToolTip(Char*) 0x7ED470 builds the text into mgr+0x10 from
//   the in-progress quest list (static PgTList<QuestMC*> 0xC32F4C), then MoveConditionToolTip shows it if non-empty.
//   AddConditionToolTip SKIPS the rebuild while the hovered object's handle (Char+0x254) equals a cached handle,
//   the u16 at mgr+0x38, which it sets at its end (0x7ED846).
//   The only other writer of that cache is FullMapWin::AddQuestHelper (0x610BE9: mov word [mgr+0x38], 0xFFFF) - which is
//   why opening the map brought the box back. Accepting or dropping a quest (AddProgressQuest 0x7ECDC0 from the quest
//   script ACCEPT, RemoveProgressQuest 0x7ECF80 from give-up / script DONE) changes the list but leaves the cache, so a
//   text built in between - e.g. after a hand-in, before the re-accept, with the mob still under the cursor - stays
//   (empty = no box at all) for that mob until the map is opened. 2016 has the same cache (+0x3C), reset only by its map.
//
// The plugin wraps both list changes and clears the cache after each (0xFFFF, the value the map writes), so the next
// hover frame rebuilds from the current list. No exe bytes change beyond the two detours.
#include <hook_core.h>
#include <client_addrs.h>

#include <windows.h>

#include <cstring>

namespace {

const unsigned kVaAdd = caddr::va(caddr::kQuestHelperAddProgress);
const unsigned kVaRemove = caddr::va(caddr::kQuestHelperRemoveProgress);
const unsigned kOffHoverHandle = 0x38;   // QuestHelperMgr: u16 handle the tooltip text was last built for
const unsigned short kNoHandle = 0xFFFF;
const unsigned char kStockAdd[5] = {0x55, 0x8B, 0xEC, 0x6A, 0xFF};      // push ebp ; mov ebp, esp ; push -1
const unsigned char kStockRemove[5] = {0x55, 0x8B, 0xEC, 0x53, 0x56};   // push ebp ; mov ebp, esp ; push ebx ; push esi

hook::Detour g_add, g_remove;

typedef void(__fastcall* ProgressFn)(void* mgr, void* edx, unsigned quest);

void reset(void* mgr, const char* what, unsigned quest) {
    __try {
        unsigned short* h = (unsigned short*)((char*)mgr + kOffHoverHandle);
        if (*h != kNoHandle) hook::log("quest_hover_refresh: quest %u %s - hover cache for handle %u cleared", quest & 0xFFFF, what, *h);
        *h = kNoHandle;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook::log("quest_hover_refresh: fault clearing the hover cache - left as it was");
    }
}

void __fastcall add_impl(void* mgr, void* /*edx*/, unsigned quest) {
    ((ProgressFn)g_add.trampoline)(mgr, 0, quest);
    reset(mgr, "accepted", quest);
}

void __fastcall remove_impl(void* mgr, void* /*edx*/, unsigned quest) {
    ((ProgressFn)g_remove.trampoline)(mgr, 0, quest);
    reset(mgr, "left the list", quest);
}

bool hook_one(const char* name, unsigned va, const unsigned char* stock, void* impl, hook::Detour* d) {
    unsigned char* p = (unsigned char*)hook::rebase(va);
    if (std::memcmp(p, stock, 5) != 0) {
        hook::log("quest_hover_refresh: unexpected bytes at %s 0x%X - NOT hooked", name, va);
        return false;
    }
    return hook::hook_function(name, p, impl, d);
}

}  // namespace

HOOK_PLUGIN("quest_hover_refresh") {
    if (const char* m = caddr::missing({caddr::kQuestHelperAddProgress, caddr::kQuestHelperRemoveProgress})) {
        hook::log("quest_hover_refresh: %s - not hooked", m);
        return;
    }
    hook_one("QuestHelperMgr::AddProgressQuest", kVaAdd, kStockAdd, (void*)add_impl, &g_add);
    hook_one("QuestHelperMgr::RemoveProgressQuest", kVaRemove, kStockRemove, (void*)remove_impl, &g_remove);
}
