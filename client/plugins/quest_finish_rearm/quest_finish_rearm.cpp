// quest_finish_rearm - the "quest completed - rewards available from this NPC" popup shows again for a repeatable quest
// finished again in the same session (operator 2026-10-01: "fix that the quest ... window only displays once for
// repeatable quests"; ticket Q48).
//
// The popup is QuestFinishWin. QuestFinishWin::UpdateQuest (2016 0x5FC2A0, 2026 0x730250; run on every quest mob kill,
// item pick-up and quest script command) walks the quests in progress:
//   status 8 (completable): if the id is in the ALREADY-SHOWN list (+0x174 begin / +0x178 end, a vector<WORD>), skip;
//       else add it there and to the DISPLAYED list (+0x168 / +0x16C) and show the popup.
//   any other status:      remove the id from the DISPLAYED list only (0x730349..0x73038A).
// Nothing ever removes an id from the already-shown list, so a quest pops once per client session - a repeatable handed
// in and done again stays silent. This hook runs that missing cleanup before UpdateQuest: every already-shown id whose
// quest is no longer completable is dropped, so the next completion pops again. A quest still completable stays listed,
// so the popup does not repeat on every kill.
// It also drops a quest that is no longer completable from the popup's DISPLAYED list after every update (a quest handed
// in is skipped by UpdateQuest's own cleanup - "<X>'s Blessing" quests, operator 2026-10-03); the popup's live draw then
// removes its dot and hides the window only when the list is empty.
//
// 2026 US Fiesta.exe: 0x7EB840 returns the quest manager (UpdateQuest's own `call 0x7eb840` at 0x7302C2),
// 0x8FF590 = its GetNewQuestStatus(WORD id), thiscall (UpdateQuest's call at 0x73033F, then `cmp eax, 8`).
#include <hook_core.h>

#include <windows.h>

#include <cstring>

namespace {

const unsigned kVaUpdateQuest = 0x00730250u;
const unsigned kVaGetQuestMgr = 0x007EB840u;
const unsigned kVaGetStatus = 0x008FF590u;
const unsigned kOffShownBegin = 0x174, kOffShownEnd = 0x178;
const unsigned kOffDisplayedBegin = 0x168, kOffDisplayedEnd = 0x16C;
const int kCompletable = 8;
const unsigned char kStock[5] = {0x55, 0x8B, 0xEC, 0x6A, 0xFF};    // push ebp ; mov ebp, esp ; push -1

hook::Detour g_update;

typedef void*(__cdecl* GetQuestMgr)();
typedef int(__fastcall* GetStatus)(void* mgr, void* edx, unsigned id);
typedef void(__fastcall* UpdateQuest)(void* self, void* edx);

void rearm(void* self) {
    __try {
        unsigned short** begin = (unsigned short**)((char*)self + kOffShownBegin);
        unsigned short** end = (unsigned short**)((char*)self + kOffShownEnd);
        if (!*begin || *end <= *begin) return;
        void* mgr = ((GetQuestMgr)hook::rebase(kVaGetQuestMgr))();
        if (!mgr) return;
        GetStatus status = (GetStatus)hook::rebase(kVaGetStatus);
        unsigned short* out = *begin;
        for (unsigned short* p = *begin; p < *end; ++p) {
            int st = status(mgr, 0, *p);
            if (st == kCompletable) {
                *out++ = *p;
            } else {
                hook::log("quest_finish_rearm: quest %u no longer completable (status %d) - its popup can show again", *p, st);
            }
        }
        *end = out;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook::log("quest_finish_rearm: exception while re-arming - list left as it was");
    }
}

// The popup is drawn LIVE from its DISPLAYED list (+0x168 begin / +0x16C end, vector<WORD>): QuestFinishWin's per-frame
// update (2026 0x730160, vtable slot 83) hides the window when the list is empty and shows one dot per entry (10 dot
// widgets +0x194..+0x1B8). UpdateQuest only removes an entry whose quest is still among the quests in progress
// (0x8FFE60) and no longer completable - a quest handed in is no longer in progress, so its entry was never removed.
// "<X>'s Blessing" quests are accepted AND handed in by one dialogue (operator 2026-10-03): completable for a moment
// (entry added, popup shown), then done - the popup kept a dot for a hand-in that had already happened. So after every
// update every entry whose quest is not completable any more is dropped from the DISPLAYED list - its dot goes, the
// others stay, and the window hides by itself only when that empties the list (operator: "just remove the quest from
// its display list. Only close when that makes the list hit 0").
void prune_displayed(void* self) {
    __try {
        unsigned short** begin = (unsigned short**)((char*)self + kOffDisplayedBegin);
        unsigned short** end = (unsigned short**)((char*)self + kOffDisplayedEnd);
        if (!*begin || *end <= *begin) return;
        void* mgr = ((GetQuestMgr)hook::rebase(kVaGetQuestMgr))();
        if (!mgr) return;
        GetStatus status = (GetStatus)hook::rebase(kVaGetStatus);
        unsigned short* out = *begin;
        for (unsigned short* p = *begin; p < *end; ++p) {
            const int st = status(mgr, 0, *p);
            if (st == kCompletable) {
                *out++ = *p;
            } else {
                hook::log("quest_finish_rearm: quest %u no longer completable (status %d) - its dot leaves the popup", *p, st);
            }
        }
        *end = out;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook::log("quest_finish_rearm: exception while pruning the displayed list - left as it was");
    }
}

void __fastcall update_impl(void* self, void* /*edx*/) {
    rearm(self);
    ((UpdateQuest)g_update.trampoline)(self, 0);
    prune_displayed(self);
}

}  // namespace

HOOK_PLUGIN("quest_finish_rearm") {
    unsigned char* p = (unsigned char*)hook::rebase(kVaUpdateQuest);
    if (std::memcmp(p, kStock, sizeof kStock) != 0) {
        hook::log("quest_finish_rearm: unexpected bytes at QuestFinishWin::UpdateQuest 0x730250 - NOT hooked");
        return;
    }
    hook::hook_function("QuestFinishWin::UpdateQuest 0x730250 (re-arm repeatables)", p, (void*)update_impl, &g_update);
}
