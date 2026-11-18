// WorldManager.exe's hook header: hook_core plus the generated symbol headers.
//
//     #include <wmhook.h>
//     #include <wm_functions.h>   // wm::fn::CParserClient__Parser() ...   (opt-in, large)
//     #include <wm_globals.h>     // wm::global::gServer() ...
//
// The generated headers come from YOUR WorldManager.pdb (BYO, gitignored), with the same generator as the zone's:
//     python zone/tools/mk_types.py --ns wm --pdb <WorldManager.pdb> --exe <WorldManager.exe> --out worldmanager/include
// For a WorldManager rebuilt from source, tools/recipe_port.py headers moves every address to the rebuild (README).
#pragma once
#include "hook_core.h"

namespace wm {
// everything in the core is reachable as wm::... too - wm::log, wm::detour, wm::rebase (what the generated
// accessors call)
using namespace ::hook;
}  // namespace wm
