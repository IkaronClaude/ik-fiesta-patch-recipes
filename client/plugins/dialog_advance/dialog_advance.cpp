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
//
// ---- GUARDED quests: their real choice pages keep the stock EPIC rule (operator 2026-10-02) --------------------------
//
// "Decision [Job Change Quest] ... does NOT allow spacebar advance on the screen with the class selection. It currently
// does and picks the FIRST option. This is irreversible": its pages ("It'll be the Gladiator / Knight", then "Yes / No")
// have 2 buttons each, so the gate above advanced them to the first - and SCENARIO 16 changed the class. Operator: the
// stock EPIC rule (no advance on a window click or space) already exists and this plugin lifts it - "restore this
// functionality JUST for these pages, the ones with a REAL dialogue choice". So a GUARDED quest's page with 2+ choices
// keeps it (kBlock): only a click on the option answers.
// The guarded quests come from hooks\dialog_advance.ini, [config] click_required_quests=<id,id,...>, written by the
// build (Fiesta2026on2016 tools/build_variant.py): every quest whose START script runs a SCENARIO (job changes, the
// promotion / Over Time and Space / Prelude War instance entries) - data-derived, no list in here. No .ini = none.
#include <hook_core.h>
#include <client_addrs.h>

#include <cstring>

namespace {

const unsigned kVaHandler = caddr::va(caddr::kNpcDialogHandler);   // NpcDialogWin input handler, thiscall(this, arg), ret 4
const unsigned kVaLookup = caddr::va(caddr::kQuestRecordLookup);    // cdecl quest record lookup (u16 quest id) -> record*
const unsigned kVaAttr = caddr::va(caddr::kControlAttribute);      // thiscall control->attribute(const char* name) -> attr*
const unsigned kControls = 0x1BC, kCount = 0x1A0, kFirst = 0x1A4, kAttrValue = 0xC, kType = 2;
const int kEpic = 2, kMaxAutoChoices = 2;
const unsigned kQuestId = 0x1E0;                          // NpcDialogWin -> u16 quest id (the handler's lookup argument)
const int kMaxGuarded = 256;
unsigned short g_guarded[kMaxGuarded];
int g_nguarded = 0;
unsigned short g_logged_quest = 0;

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

bool guarded(unsigned short quest) {
    for (int i = 0; i < g_nguarded; i++)
        if (g_guarded[i] == quest) return true;
    return false;
}

void __fastcall handler_impl(void* self, void*, int arg) {
    typedef void(__fastcall * Orig)(void*, void*, int);
    t_choices = quest_ack_controls(self);
    t_mode = t_choices > kMaxAutoChoices ? kBlock : kAdvance;
    if (g_nguarded && t_choices >= 2) {
        unsigned short quest = 0;
        __try {
            quest = *(unsigned short*)((char*)self + kQuestId);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        if (guarded(quest)) {
            t_mode = kBlock;
            if (g_logged_quest != quest)
                hook::log("quest %u: guarded quest, %d-choice page - stock EPIC rule kept (click the option)", quest, t_choices);
            g_logged_quest = quest;
        }
    }
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

void load_guarded() {
    char buf[4096];
    hook::config_str("click_required_quests", "", buf, sizeof buf);
    unsigned v = 0;
    bool in_num = false;
    for (const char* p = buf;; p++) {
        if (*p >= '0' && *p <= '9') {
            v = v * 10 + (unsigned)(*p - '0');
            in_num = true;
        } else {
            if (in_num && v <= 0xFFFF && g_nguarded < kMaxGuarded) g_guarded[g_nguarded++] = (unsigned short)v;
            v = 0;
            in_num = false;
            if (!*p) break;
        }
    }
    hook::log("dialog_advance: %d guarded quest(s) - their choice pages keep the stock EPIC rule", g_nguarded);
}

HOOK_PLUGIN("dialog_advance") {
    if (const char* m = caddr::missing({caddr::kControlAttribute, caddr::kNpcDialogHandler, caddr::kQuestRecordLookup})) {
        hook::log("dialog_advance: %s - not hooked", m);
        return;
    }
    load_guarded();
    hook::hook_function("NpcDialogWin input handler 0x7275C0", hook::rebase(kVaHandler), (void*)handler_thunk, &g_handler);
    hook::hook_function("quest record lookup 0x5C5550", hook::rebase(kVaLookup), (void*)lookup_impl, &g_lookup);
}
