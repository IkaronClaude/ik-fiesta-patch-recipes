// map_mark_dedupe - one quest-number label per spot on the full map (operator 2026-09-29: Curly's Storage Key showed
// "1 1 1 1 1 1 1 1 1" at one spot - "the client already gathers a list. Per spot. Why not just make entries unique?").
//
// ---- THE STOCK CODE (2016 Fiesta.bin + PDB: FullMapWin::AddQuestHelper; the same block in the 2026 US Fiesta.exe) ----
//   AddQuestHelper (2026 0x610610) walks MobCoordinate for the tracked quests' mobs. Per row it ALWAYS makes the area
//   circle (MobAreaMarkWin, the block at 0x610959) and makes the quest-number label (QuestHelperMarkWin::CreateWin,
//   0x61079E) only when the (quest, mob) pair differs from the previous row's:
//       0x61076E  cmp cx,[eax]      quest == last quest?
//       0x610779  cmp ax,[esi]      mob == last mob?     -> je 0x610959 (areas only)
//       0x610782  mov eax,[ebp-2C]  the label path;      the label's position is [ebp-68] / [ebp-64] (floats)
//   So a quest item several mob kinds drop, whose MobCoordinate rows are the same areas (the official file gives the 9
//   herb / wood / mushroom nodes of Curly's Storage Key identical rows), gets one label PER MOB at the same spot, and
//   the map lays them side by side.
//
// ---- THIS PLUGIN ----------------------------------------------------------------------------------------------------
//   The label path also takes the stock skip when this quest already has a label at exactly this position. The areas
//   are untouched (every mob keeps its circles), and a mob whose area is different still gets its label there. The
//   set of (quest, x, y) is cleared at every AddQuestHelper call. All sites are byte-checked first; a mismatch = stock.
#include <hook_core.h>
#include <client_addrs.h>

#include <cstring>
#include <set>
#include <tuple>

namespace {

const unsigned kVaAddQuestHelper = caddr::va(caddr::kFullMapAddQuestHelper);
const unsigned kVaLabelPath = caddr::va(caddr::kMapMarkLabelPath);      // mov eax,[ebp-0x2C]; mov [ebp-0x30],esi   (6 bytes, replaced)
const unsigned kVaLabelCont = caddr::va(caddr::kMapMarkLabelCont);      // push [eax+0x310] ... QuestHelperMarkWin::CreateWin
const unsigned kVaAreasOnly = caddr::va(caddr::kMapMarkAreasOnly);      // the stock skip target: the area circle only
// MapMarkSite..MapMarkLabelCont: the quest / mob test and the label path's first two instructions; the je rel32
// (bytes 16..19) goes to MapMarkAreasOnly
const unsigned char kSite[] = {0x66, 0x3B, 0x08, 0x75, 0x0F, 0x8B, 0x45, 0xC8, 0x89, 0x75, 0xD0, 0x66, 0x3B,
                               0x06, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x45, 0xD4, 0x89, 0x75, 0xD0};
const int kSiteJeRel = 16;

hook::Detour g_aqh;
std::set<std::tuple<unsigned, unsigned, unsigned>> g_seen;   // (quest, x bits, y bits) labelled in this build
void* g_cont = nullptr;
void* g_skip = nullptr;
int g_dup = 0;
unsigned g_skipped = 0;

// 1 = this quest already has a label at (x, y)
int __cdecl seen(unsigned quest, float x, float y) {
    unsigned xb, yb;
    std::memcpy(&xb, &x, 4);
    std::memcpy(&yb, &y, 4);
    if (g_seen.insert(std::make_tuple(quest, xb, yb)).second) return 0;
    ++g_skipped;
    return 1;
}

// in place of the label path's first 6 bytes: edi -> the quest pointer (quest id = its first word), the label's
// position at [ebp-0x68] / [ebp-0x64]
__declspec(naked) void label_path() {
    __asm {
        pushad
        pushfd
        push dword ptr [ebp - 0x64]
        push dword ptr [ebp - 0x68]
        mov eax, [edi]
        movzx eax, word ptr [eax]
        push eax
        call seen
        add esp, 12
        mov g_dup, eax
        popfd
        popad
        mov [ebp - 0x30], esi          // both stock paths set it
        cmp g_dup, 0
        jne dup
        mov eax, [ebp - 0x2C]          // the displaced first instruction
        jmp g_cont
    dup:
        jmp g_skip
    }
}

void __fastcall add_quest_helper(void* map, void* edx) {
    g_seen.clear();
    g_skipped = 0;
    ((void(__fastcall*)(void*, void*))g_aqh.trampoline)(map, edx);
    if (g_skipped) hook::log("map_mark_dedupe: %u duplicate quest label(s) left out (same quest, same spot)", g_skipped);
}

}  // namespace

HOOK_PLUGIN("map_mark_dedupe") {
    if (const char* m = caddr::missing({caddr::kMapMarkSite, caddr::kFullMapAddQuestHelper, caddr::kMapMarkLabelPath,
                                        caddr::kMapMarkLabelCont, caddr::kMapMarkAreasOnly})) {
        hook::log("map_mark_dedupe: %s - not hooked", m);
        return;
    }
    const unsigned char* site = (const unsigned char*)hook::rebase(caddr::va(caddr::kMapMarkSite));
    const int je_end = kSiteJeRel + 4;
    if (std::memcmp(site, kSite, kSiteJeRel) || std::memcmp(site + je_end, kSite + je_end, sizeof kSite - je_end) ||
        site + je_end + *(const int*)(site + kSiteJeRel) != (const unsigned char*)hook::rebase(kVaAreasOnly)) {
        hook::log("map_mark_dedupe: AddQuestHelper's label test is not the expected code - stock labels");
        return;
    }
    g_cont = hook::rebase(kVaLabelCont);
    g_skip = hook::rebase(kVaAreasOnly);
    if (!hook::hook_function("FullMapWin::AddQuestHelper 0x610610 (the label set is per build)",
                             hook::rebase(kVaAddQuestHelper), (void*)add_quest_helper, &g_aqh))
        return;
    unsigned char* at = (unsigned char*)hook::rebase(kVaLabelPath);
    unsigned char jmp[6] = {0xE9, 0, 0, 0, 0, 0x90};
    int rel = (int)((unsigned char*)&label_path - (at + 5));
    std::memcpy(jmp + 1, &rel, 4);
    if (hook::write_code(at, jmp, sizeof jmp))
        hook::log("map_mark_dedupe: one quest label per spot (label path at %p)", at);
}
