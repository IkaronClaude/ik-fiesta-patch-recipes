// Login.exe's hook header: hook_core plus the generated symbol headers.
//
//     #include <loginhook.h>
//     #include <login_functions.h>   // login::fn::CParserClient__Parser() ...   (opt-in, large)
//     #include <login_globals.h>     // login::global::gServer() ...
//
// The generated headers come from YOUR Login.pdb (BYO, gitignored), with the same generator as the zone's:
//     python zone/tools/mk_types.py --ns login --pdb <Login.pdb> --exe <Login.exe> --out login/include
// For a Login rebuilt from source, tools/recipe_port.py headers moves every address to the rebuild (README).
#pragma once
#include "hook_core.h"

namespace login {
// everything in the core is reachable as login::... too - login::log, login::detour, login::rebase (what the generated
// accessors call)
using namespace ::hook;
}  // namespace login
