// dialog_advance - quest dialog pages advance on space / a background click unless the page is a REAL choice
// (ticket Q36, operator 2026-09-25: "flip through all pages automatically but force a text mouse click JUST on"
// the true multiple-choice page; "TRUE meaning it actually matters ... Options > 2 is a good gate").
//
// ---- what the stock 2026 client does (Fiesta.exe, read 2026-09-25) --------------------------------------------
//
//   NpcDialogWin input handler 0x7275C0 (vtable slot at 0xB48DC0, thiscall(this, arg), ret 4), every frame:
//     a mouse click inside the window, or a newly pressed confirm key ([0xCE49C8]+0x28 / +0x48 bit 2) ->
//       rec = QuestRecord(this->quest @+0x1E0)            0x5C5550 (cdecl, u16 quest id)
//       if (rec->[+2] == 2) skip                           <- QuestData.Q_TYPE 2 = EPIC
//       else press the FIRST control whose "action" attribute starts with "quest_ack" (DirectMessage 0x12FD1)
//     then the base window handler 0x87F110.
//   So on EPIC quests (Mage's New Power, Imp Leader...) nothing but a click on the button text advances, and a
//   space tap falls through to the base handler, which pressed the button under the resting cursor - button 2,
//   "decline", on two ~175-character pages (bridge logs: 87 of 89 space-speed two-button replies were 1).
//
// ---- this plugin ----------------------------------------------------------------------------------------------
//
// Decide per PAGE instead of per quest type: count the page's quest_ack controls (the same list the handler walks:
// this->[+0x1BC] -> count @+0x1A0, controls @+0x1A4). <= 2 (next / yes-no) -> auto-advance to the first, whatever
// the quest type; > 2 (a quiz, e.g. Robin's "It's the HOME key") -> no auto-advance, a click on the option is
// needed. Done by answering the handler's ONE quest-record lookup with a copy whose type byte says "not EPIC"
// (advance) or "EPIC" (block); every later lookup (the base handler) sees the real record.
#include <hook_core.h>

#include <cstring>

namespace {

const unsigned kVaHandler = 0x007275C0u;   // NpcDialogWin input handler, thiscall(this, arg), ret 4
const unsigned kVaLookup = 0x005C5550u;    // cdecl quest record lookup (u16 quest id) -> record*
const unsigned kVaAttr = 0x0097FAD0u;      // thiscall control->attribute(const char* name) -> attr*
const unsigned kControls = 0x1BC, kCount = 0x1A0, kFirst = 0x1A4, kAttrValue = 0xC, kType = 2;
const int kEpic = 2, kMaxAutoChoices = 2;

enum Mode { kNone, kAdvance, kBlock };
thread_local Mode t_mode = kNone;
thread_local int t_choices = 0;
thread_local unsigned char t_record[64];

hook::Detour g_handler, g_lookup;

int quest_ack_controls(void* win) {
    typedef void*(__fastcall * Attr)(void*, void*, const char*);
    const char* list = *(const char**)((const char*)win + kControls);
    if (!list) return 0;
    int n = *(const int*)(list + kCount), found = 0;
    for (int i = 0; i < n && i < 64; i++) {
        void* ctl = *(void* const*)(list + kFirst + 4 * i);
        if (!ctl) continue;
        void* attr = ((Attr)hook::rebase(kVaAttr))(ctl, 0, "action");
        const char* v = attr ? *(const char* const*)((const char*)attr + kAttrValue) : nullptr;
        if (v && std::strncmp(v, "quest_ack", 9) == 0) found++;
    }
    return found;
}

void __fastcall handler_impl(void* self, void*, int arg) {
    typedef void(__fastcall * Orig)(void*, void*, int);
    t_choices = quest_ack_controls(self);
    t_mode = t_choices > kMaxAutoChoices ? kBlock : kAdvance;
    ((Orig)g_handler.trampoline)(self, 0, arg);
    t_mode = kNone;
}

void* __cdecl lookup_impl(unsigned short quest) {
    typedef void*(__cdecl * Orig)(unsigned short);
    unsigned char* rec = (unsigned char*)((Orig)g_lookup.trampoline)(quest);
    Mode mode = t_mode;
    if (mode == kNone || !rec) return rec;
    t_mode = kNone;                                  // one-shot: only the handler's own gate lookup
    std::memcpy(t_record, rec, sizeof t_record);
    int type = *(int*)(t_record + kType);
    int want = mode == kBlock ? kEpic : (type == kEpic ? 0 : type);
    if (want == type) return rec;
    *(int*)(t_record + kType) = want;
    hook::log("quest %u: page with %d choice(s) -> %s", quest, t_choices,
              mode == kBlock ? "click required (real choice)" : "advances on space / background (EPIC gate lifted)");
    return t_record;
}

void __declspec(naked) handler_thunk() { __asm { jmp handler_impl } }

}  // namespace

HOOK_PLUGIN("dialog_advance") {
    hook::hook_function("NpcDialogWin input handler 0x7275C0", hook::rebase(kVaHandler), (void*)handler_thunk, &g_handler);
    hook::hook_function("quest record lookup 0x5C5550", hook::rebase(kVaLookup), (void*)lookup_impl, &g_lookup);
}
