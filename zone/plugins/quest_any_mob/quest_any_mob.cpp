// quest_any_mob - a quest drop / kill action whose target mob is 0xFFFE (-2) matches ANY mob (operator 2026-10-01: "add a
// -1 or -2 quest drop index that causes the item to drop from ANY MOB").
//
// THE STOCK MATCH (Zone.exe): CQuestZone::IsConnectionAction (0x5B9B60, QUEST_DATA*, action index, killed mob) takes an
// action whose IfType is 1 (kill), reads its ConditionTarget (u16 at action +0x8 of the 32-byte QUEST_ACTION) and its
// range byte, and asks MobDataBox::mdb_IsSpeciesDistanceByQuest (0x641020, thiscall (target, killed, range) -> bool):
// the same mob, or a mob of the same QuestSpecies group. 0xFFFF already means "never" (an unused slot) and 0 is Slime, so
// there was no "any".
//
// THIS PLUGIN: mdb_IsSpeciesDistanceByQuest answers true when the target is 0xFFFE; every other target takes the stock
// path. Data opts in by writing 65534 into a QuestAction's ConditionTarget (no row uses it today).
#include <zonehook.h>
#include <zone_functions.h>

namespace {

const unsigned short kAnyMob = 0xFFFE;
zone::Detour g_species;
unsigned g_hits = 0;

bool __fastcall species(void* self, void*, unsigned short target, unsigned short killed, unsigned char range) {
    if (target == kAnyMob) {
        if (g_hits++ < 20 || g_hits % 1000 == 0)
            zone::log("quest_any_mob: a quest action on any mob matched mob %u (#%u)", killed, g_hits);
        return true;
    }
    return ((bool (__fastcall*)(void*, void*, unsigned short, unsigned short, unsigned char))g_species.trampoline)(
        self, nullptr, target, killed, range);
}

}  // namespace

ZONEHOOK_PLUGIN("quest_any_mob") {
    if (zone::hook_function("MobDataBox::mdb_IsSpeciesDistanceByQuest 0x641020 (target 0xFFFE = any mob)",
                            (void*)zone::fn::MobDataBox__mdb_IsSpeciesDistanceByQuest(), (void*)species, &g_species))
        zone::log("quest_any_mob: installed - a quest action whose target mob is 65534 matches any mob");
}
