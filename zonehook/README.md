# zonehook

Write zone features in C++ instead of hand-assembled bytes.

Zone.exe is patched once to import `zonehook.dll` (`recipes/dll-loader.json`). That loader then loads
every DLL in a `hooks/` folder beside the exe, immediately before the zone's own `ServiceMain`. Features
live in those plugins; the loader itself never changes.

```
zonehook.dll          the loader. CRT-free, does one thing.
hooks/*.dll           your features. Full CRT, full C++.
include/zonehook.h    header-only library - detour, vtable, IAT, packet macros, logging
include/zone_types.h      466 enums, 3540 structs, 54 unions   generated from Zone.pdb
include/zone_functions.h  10261 typed function pointers        generated from Zone.pdb
include/zone_globals.h    372 global objects (the loaded tables)
include/zonehook_lua.h    the zone's Lua 5.2 engine
docs/HOOK-TARGETS.md      WHERE to hook, and with which tool
```

## Build

```bash
./build.bat                     # zonehook.dll
hooks/build_hook.bat void_bag   # hooks/build/void_bag.dll
```

Deploy `zonehook.dll` next to the patched Zone.exe and the plugins in `hooks/`. Rebuild the exe with
`python build_zone.py --exe <stock Zone.exe> --out Zone.exe --experimental`.

## A plugin

```cpp
#include <zonehook.h>

ZONE_HOOK_PACKET(NC_ITEM_RELOC_REQ, {
    zone::log("reloc from player %x", self);
    ZONE_CALL_ORIGINAL_OF(NC_ITEM_RELOC_REQ);     // omit to swallow the packet
});

ZONEHOOK_PLUGIN("my_feature") {
    ZONE_INSTALL_PACKET(NC_ITEM_RELOC_REQ);
}
```

Everything logs to `zonehook.log` beside the exe, one file, each line tagged with the module that wrote
it — one chronological narrative rather than five separate logs.

## Two things worth knowing

**Why plugins load at service start, not in DllMain.** `LoadLibrary` inside `DllMain` does work and would
put plugins up before `WinMain`. It is not used, because it runs the plugin's `DllMain` under the loader
lock, on a barely-committed stack, where a static CRT dies outright. Loading from the service thread
gives every plugin a normal 1 MB stack, no loader lock, and the full CRT - and still runs before a single
line of zone code, because `WinMain` only registers the service. Nothing is lost by waiting.

**Why the generated headers are trustworthy.** Every struct carries a `static_assert` on its size against
the binary, so a wrong layout fails the *build*. Field offsets come from the PDB and are reproduced under
`#pragma pack(1)` with explicit padding. A member whose type cannot be spelled exactly becomes raw bytes
of the right width with the original type in a comment - never a guess. And all 246 packet-handler
addresses cross-check between two independent extraction paths.

## Verified live

Under Wine, in the docker stack, 2026-09-19:

```
[loader] loaded; exe base 400000, 246 known packet handlers
[loader] [service] table entry 0: 'ZoneServer' ServiceMain 653480 -> 789023c0
[loader] [service] '_Zone0' starting; running set-up before its ServiceMain at 653480
[void_bag] CRT ok - inventory is 192 cells of 116 bytes
[void_bag] [hook] NC_ITEM_RELOC_REQ at 537170 -> 788683c0 (trampoline 30d20000, 5 bytes displaced)
[void_bag] [hook] LuaScript::ls_FunctionCall at 5d7bc0 -> 78862b7b
[loader] 1 plugin(s) up
[void_bag] script -> chrlghk (state 3ed60df0)
```

The zone went on to load all its maps normally.
