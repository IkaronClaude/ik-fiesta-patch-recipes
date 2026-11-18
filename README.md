# ik-fiesta-patch-recipes

Declarative binary patches for the Fiesta server executables, as **data plus a runner** rather than a
pile of one-off scripts. A recipe records every byte it changes, what it expects to find there, and why —
so re-running it after a parameter change is one command, and so the reasoning survives long enough to be
checked by someone who wasn't there.

```bash
# see what a recipe would do, without writing anything
python apply.py zone/recipes/mob-spawn-group-cap.json --exe Z:/ServerSource/Zone00/Zone.exe --dry-run

# produce a patched binary (never in place)
python apply.py zone/recipes/mob-spawn-group-cap.json --exe Z:/ServerSource/Zone00/Zone.exe --out build/Zone.exe

# change a parameter without editing the recipe
python apply.py zone/recipes/mob-spawn-group-cap.json --exe ... --out build/Zone.exe --set groups=32768

# prove a binary you already have is the patched one
python apply.py zone/recipes/mob-spawn-group-cap.json --exe ... --verify build/Zone.exe
```

Stdlib only. A recipe you can't run because a dependency moved is not repeatable.

Byte patches reach their limit quickly - they can move a constant or repoint a global, but they cannot add a
class, a packet handler or a DB round trip. For that the exes load **hook plugins**: C++ DLLs written against a
header library generated from the game's own symbols. See [Hooks](#hooks).

## Layout

```
README.md        this file: recipes, the build, hooks
apply.py         the recipe runner (one recipe, one exe)
build.py         a whole chain from a STOCK exe: --target zone (default) | character
tools/           recipe_port.py - recipes and plugins onto an exe rebuilt from source (see Rebuilt exes)
build/           every output (patched exes, fiestahook.dll, plugins/) - gitignored

common/          shared by every target
  loader/        fiestahook.dll - the loader the patched exes import (build.bat)
  include/       hook_core.h - the exe-agnostic core of the hook library
  tools/         xref_range.py - reference scanner for recipes
  build_plugin.bat  build one plugin: <target> <name>
zone/            Zone.exe:      recipes/ plugins/ include/ tools/ docs/   - see zone/README.md
character/       Character.exe: recipes/ plugins/ include/ tools/         - see character/README.md
client/          the client:    recipes/                                  - see client/README.md
```

## Building

```bash
# the patched exes, from the stock ones (never in place; every recipe re-verified on the result)
python build.py --exe Z:/ServerSource/Zone00/Zone.exe --out build/Zone.hooked.exe --experimental
python build.py --target character --exe Z:/ServerSource/Character/Character.exe --out build/Character.hooked.exe
# WorldManager.exe: the world-wide instance-dungeon cap (32 -> 127 rows); only needed past 32 rows
python build.py --target worldmanager --exe <Server2016>/WorldManager/WorldManager.exe --out build/WorldManager.hooked.exe

# the loader and the plugins (Visual Studio, 32-bit toolchain)
common\loader\build.bat                          # -> build\fiestahook.dll
common\build_plugin.bat zone void_bag             # -> build\plugins\void_bag.dll
common\build_plugin.bat zone quest_gate           # -> build\plugins\quest_gate.dll  (quest-gated map entry, the 2026 rule)
common\build_plugin.bat zone main_wake            # -> build\plugins\main_wake.dll   (idle main loop waits for network data, max 15 ms)
common\test\build.bat                             # the hook library self-test (detour / trampoline / vtable swap): a plain 32-bit exe, must PASS
common\build_plugin.bat character char_void       # -> build\plugins\char_void.dll

# the generated headers - from YOUR OWN Zone.exe + Zone.pdb (BYO, like every game file); not shipped,
# gitignored, needed before any zone plugin builds. Rerun after a new exe/pdb.
python zone/tools/mk_types.py   --pdb <path>/Zone.pdb --exe <path>/Zone.exe --out zone/include   # types, functions, globals
python zone/tools/mk_symbols.py --pdb <path>/Zone.pdb --exe <path>/Zone.exe                      # -> zone/include/zone_symbols.h
python character/tools/mk_char_symbols.py
```

`--experimental` adds the recipes that are built and verified but not in the default chain yet (the hook loader
among them). The chain order lives in `build.py`: recipes that add memory take arena space in order, so the same
recipes in another order give a different - still working - binary.

## What the runner guarantees

| rule | why it exists |
|---|---|
| **Never in place** | Input opened read-only, output to a new file. A half-applied patch over your only copy is unrecoverable. |
| **Every edit declares what it expects** | If a site doesn't hold the expected value, *nothing* is written. A patch landing on the wrong offset doesn't crash — it corrupts one instruction and kills the process somewhere unrelated a week later. |
| **All or nothing** | Every site is validated before any is applied. There is no half-patched state. |
| **Target hash is recorded** | Offsets were read out of one specific build. Applying them to another is refused unless you say `--allow-hash-mismatch`. |
| **Limits are declared** | A recipe can state a ceiling (and why), so an over-large parameter is refused rather than silently producing a broken binary. |

Expressions in a recipe are arithmetic over its own `params`/`consts`, evaluated by a small parser —
deliberately **not** `eval()`. Recipe files are data; data from a file should not run code.

## Writing a recipe

```json
{
  "params":  { "groups": 16384 },
  "consts":  { "elem_size": 6584, "old_groups": 4096, "old_object_va": "0x13389A48" },
  "limits":  { "groups": { "max": "65534", "why": "..." } },
  "new_section": { "name": ".mobhat", "size": "groups*elem_size + hdr_size" },
  "edits": [
    { "why": "ctor: l_MakeList capacity", "at": "0x004B4010",
      "expect": "old_groups", "write": "groups" }
  ]
}
```

- `at` / `expect` / `write` are expressions. Every edit is a 32-bit little-endian write.
- Write addresses and sizes as **hex strings** (`"0x19B8000"`). Transcribing an address from a
  disassembler into decimal is a reliable way to get it wrong — it happened while writing the first
  recipe here, and the `expect` check is what caught it.
- `@newbase` resolves to the virtual address of `new_section`, which lets a recipe relocate a large
  static object without needing a code cave or an allocator.
- `code` blobs place instructions: `emit` is a list of hex strings and computed fields - `{"rel32": x}`
  (a jump/call target), `{"u32": x}` (a plain constant) and `{"abs32": x}` (an **address**). Every address
  operand in a cave must be `abs32`: it is also added to the base relocation directory, so the loader moves it
  with the image. The 2026 client is DYNAMICBASE and Windows loads it at a random base - a cave with a bare
  `u32` address crashed it live (2026-09-25). The zone runs under Wine at its preferred base, but use `abs32`
  there too. Prefer a hook plugin over a cave wherever the loader is in the exe.

## Hooks

### How a hook gets into the server

```
Zone.exe (patched by dll-loader)
  imports fiestahook.dll!ZoneHookInit ──► Windows maps fiestahook.dll before the exe's entry point
      DllMain: rewrites the IAT slot of StartServiceCtrlDispatcherA
  WinMain ──► StartServiceCtrlDispatcherA (ours) ──► swaps the service table's ServiceMain for ours
  SCM starts the service ──► our ServiceMain:
      LoadLibrary every hooks\*.dll beside the exe      (each plugin's DllMain installs its hooks)
      then the server's own ServiceMain                  (the server starts, already hooked)
```

1. **The import.** The `dll-loader` recipe (and `dll-loader-character`) copies the exe's import descriptors into
   arena space with one entry added, `fiestahook.dll!ZoneHookInit`, and points the import directory at the copy.
   No code is patched. Windows (or Wine) then maps the loader before the exe runs a single instruction, and a
   missing DLL fails loudly at startup instead of silently.
2. **The loader is CRT-free.** It is mapped during loader init, on a barely committed stack, where C runtime
   start-up has been measured to overflow. So it does almost nothing there: it hooks the one import every
   Fiesta server exe uses to become a Windows service, and waits.
3. **Plugins load at service start.** These exes are services: `WinMain` only registers the service table, and
   the server really starts when the SCM calls `ServiceMain`. The loader runs its set-up in front of that call:
   every DLL in the `hooks\` folder beside the exe is loaded, then the real `ServiceMain` runs. So a plugin gets
   a normal 1 MB stack, no loader lock, the full CRT and STL - and still runs before one line of server code.
4. **A plugin installs its hooks in its `DllMain`** (the `HOOK_PLUGIN` macro) and is then called by the server
   like any function it already calls.

The same loader goes into Zone.exe and Character.exe; each has its own `hooks\` folder, so a plugin only ever
loads into the exe it was written for. Everything logs to one `fiestahook.log` beside the exe, each line tagged
with the module that wrote it.

### The header library

```
common/include/hook_core.h       detours (with trampolines), vtable and IAT hooks, logging, rebase(),
                                 arena_region() - the core, exe-agnostic
zone/include/zonehook.h          packet-handler hooks (ZONE_HOOK_PACKET), the zone:: namespace
zone/include/zonehook_lua.h      the zone's Lua 5.2 engine: register functions, observe every script call
zone/include/zone_shn.h          SHN injection: serve other bytes for a table file, in memory (chains across plugins)
zone/include/zone_types.h        466 enums, 3540 structs, 54 unions        - generated from Zone.pdb
zone/include/zone_functions.h    ~11,000 typed function pointers          - generated
zone/include/zone_globals.h      ~1,000 typed globals, ~800 vtables       - generated
character/include/charhook.h     Character handler hooks (CHAR_HOOK_HANDLER), verify_known()
character/include/dbhook.h       the handler's worker DB connection: query / fetch / read / commit
character/include/character_symbols.h   generated without a PDB - see character/README.md
```

**Every address is a typed accessor.** A plugin never writes an address, a `rebase` or a cast:

```cpp
zone::fn::ItemBag__ib_Initializetotal()(bag, 0, &count, items, 18);     // a function, typed from the PDB
zone::global::gpp();                                                    // GlobalProtocolPacket*
zone::fn::SocketBundle_GameDBSession___sb_GetSocket()(zone::global::sock2gameDB(), 0);
zone::vtable::ItemInventory();                                          // void** - a class's vtable
chr::fn::DBRecord_query()(record, "%s", sql);                           // Character, no PDB
```

The generators produce these from the PDB's module symbols, its global stream, and the public names (demangled
with `undname`, which is how template members and COMDAT-folded functions get a typed entry). The exe's base is
looked up once. `__thiscall` is spelled `__fastcall` with a dead `edx` - the same ABI, callee-clean.

**Why the generated headers are trustworthy.** Every struct carries a `static_assert` on its size against the
binary, so a wrong layout fails the *build*. Field offsets come from the PDB and are reproduced under
`#pragma pack(1)` with explicit padding. A member whose type cannot be spelled exactly becomes raw bytes of the
right width with the original type in a comment, never a guess. A function whose signature cannot be spelled
from types the header defines is left out.

### A plugin

```cpp
#include <zonehook.h>

ZONE_HOOK_PACKET(NC_ITEM_RELOC_REQ, {
    zone::log("reloc from player %x", self);
    ZONE_CALL_ORIGINAL_OF(NC_ITEM_RELOC_REQ);     // omit to swallow the packet
});

HOOK_PLUGIN("my_feature") {
    ZONE_INSTALL_PACKET(NC_ITEM_RELOC_REQ);
    zone::hook_function("ShinePlayer::so_StoreInventoryFromServer",
                        (void*)zone::fn::ShineObjectClass__ShinePlayer__so_StoreInventoryFromServer(),
                        (void*)my_thunk, &my_detour);                 // any function, by its typed accessor
}
```

Character is the same with `#include <charhook.h>`, `CHAR_HOOK_HANDLER(fc_NC_..., {...})` and
`CHAR_INSTALL_HANDLER`. Build with `common\build_plugin.bat <target> <name>`; deploy the DLL into that exe's
`hooks\` folder beside `fiestahook.dll`.

**Recipe or plugin?** A recipe when the change is a constant, a table, a cap or a moved object - it is reviewable
and verifiable byte by byte. A plugin when it is behaviour: a new class, a packet, a DB round trip. The two meet
through **slots**: a recipe reserves a labelled region in the exe's arena (a jump-table case, a function pointer),
and the plugin finds it with `arena_region(".label")` and fills it. A null slot takes the stock path, so a patched
exe without its plugin behaves exactly as unpatched. `void-bag-reloc` + `void_bag` and `char-itemlist-void` +
`char_void` are built that way. `quest_gate` needs no recipe at all: it swaps one vtable slot
(`ShinePlayer::so_LinkTo`, the funnel of every map transfer) and reads its table with the zone's own `CDataReader`
- a plugin that reuses the exe's readers cannot drift from what the exe accepts, so never hand-write a parser.
The same plugin pre-checks a GM `&linkto` destination with the zone's own block map (`fc_FindMap`, `fm_InMap`,
`fm_IsBlock`): a blocked spot used to disconnect the player (error 1669), and a recipe that skipped that
disconnect left the player unmarked in limbo - the check has to run before the exe unwinds anything.

**Per-plugin settings: `hooks\<name>.ini`** beside `hooks\<name>.dll` (optional; no file = defaults):

```ini
[plugin]
enabled=0          ; the loader skips this DLL (default 1)
after=void_bag     ; load after these plugins (comma list, DLL names without .dll); a missing name or a cycle is
                   ; logged and the plugin still loads
[config]           ; the plugin's own settings
max_items=10
```

The loader reads `[plugin]`; a plugin reads its own `[config]` with `hook::config_int("max_items", 10)` /
`hook::config_str(...)` (hook_core.h - the file is found from the plugin's own DLL path, no loader API). A plugin
that must stay OFF unless something ships its file checks `hook::ini_opted_in()` (= `[plugin] enabled=1` present):
`enhance_no_warning` does, and the Fiesta2026on2016 Avocado layer ships its `.ini`. `common\test\build_loader_test.bat`
checks the rules on dummy plugins (order, disable, missing dependency, cycle, `[config]`); it must print PASS.

### Live

Proven under Wine in the docker stack on 2026-09-19. Zone.exe and Character.exe both run with the loader, and
the Void Inventory works end to end through both plugins.

**Plugins name addresses only through symbols.** A function, global or vtable comes from the generated headers
(`zone::fn::X()`, `zone::global::X()`, `zone::vtable::X()`, `wm::...`, `login::...`, the `kVa...` anchors of
zone_symbols.h). An address no header can name - a site inside a function, a return address, a string literal - is
written as `hook::site(0x...)` (a pointer) or `constexpr unsigned kVaX = hook::site_va(0x...);` (a number), with the
ORIGINAL exe's address. On the stock exe that is the address; on a rebuilt exe the build supplies a table that moves
each one (next section). `tools/recipe_port.py plugins` lists any other address literal and does not build that plugin.

## Rebuilt exes (fiesta-decomp's ProjectF2)

The exes rebuilt from source hold the same code laid out differently. `tools/recipe_port.py` (needs capstone and
llvm-pdbutil) ports everything here onto one, never by a guess:

```bash
# the recipes: ported, applied (build.py --recipes-dir ... --rebuilt), and the patched original compared with the
# patched rebuild function by function, cave by cave, import by import
python tools/recipe_port.py port --target zone --experimental \
    --orig-exe Z:/ServerSource/Zone00/Zone.exe --orig-pdb Z:/ServerSource/Zone00/Zone.pdb \
    --new-exe <ProjectF2>/build/Zone/Zone.exe --new-pdb <ProjectF2>/build/Zone/Zone.pdb \
    --out-dir build/ported/Zone --build build/rebuilt/Zone.hooked.exe

# the plugins: the generated headers with every address moved to the rebuild, the hook::site table, every plugin of
# the target built into build/rebuilt/plugins/<target>/   (the stock generated headers must exist - see Building)
python tools/recipe_port.py plugins --target zone --orig-exe ... --orig-pdb ... --new-exe ... --new-pdb ... \
    --out-dir build/rebuilt

# one address, explained
python tools/recipe_port.py where 0x0053D025 --orig-exe ... --orig-pdb ... --new-exe ... --new-pdb ...
```

How an address moves: it is (the original PDB symbol that contains it, offset), and the symbol is found in our PDB by
its mangled name (a static: by its object's data piece, from the section contributions - our PDB has no CodeView).
Data moves with its symbol. Code moves with its function when the function is identical in our build - every address
operand naming the same symbol + offset, switch tables and the compiler's symbol-less EH stubs compared by structure -
or, when it is not, only where the patched instructions align with identical ones. A recipe with a code cave needs
every function the cave jumps into or out of identical. Whatever cannot be mapped exactly (a missing symbol, an
identical-code fold the two links resolved differently, an unaligned site) refuses the whole target.

`--rebuilt` adds the recipes only a rebuilt exe needs (build.py REBUILT_ONLY): the shipped WorldManager carries two
hotfixes in its own .custom section that the source does not have, so `wm-shipped-hotfixes` ("reference":
"unpatched") goes onto the rebuild.

### Recipes as source (fiesta-decomp branch `2026`)

fiesta-decomp's branch `2026` carries every Zone recipe as SOURCE behind the CMake option `FIESTA_2026`
(`ProjectF2/build_2026.cmd`; list and per-recipe notes in its `docs/Zone-2026.md`), so that Zone.exe needs no recipe
here at all - not even dll-loader (it imports fiestahook.dll!ZoneHookInit itself). Its PDB has full CodeView
(`FIESTA_DEBUGINFO`). What a recipe set aside for a plugin is an exported global of that exe instead of an arena
region (`hook::exe_export(name)`: `g_Fiesta2026ExpGainHigh` for quest_exp, `g_Fiesta2026VoidBagOf` for void_bag; both
plugins try it first). Plugins for it: `python tools/recipe_port.py plugins --target zone ... --new-exe
<ProjectF2>/build_2026/Zone/Zone.exe --new-pdb <same>/Zone.pdb --out-dir build/rebuilt2026` (the stock generated
headers remapped by mangled name - the layouts are the source's; the types the 2026 build resizes are not used by
any plugin).

## Targets

- [zone/README.md](zone/README.md) - Zone.exe: the caps (spawn groups, quests, maps, NPC table, handles), damage
  overflow, quest-dialog fixes, and the Void Inventory.
- [character/README.md](character/README.md) - Character.exe: the Void Inventory's DB side, the 192-item
  inventory load, and how its symbols are found without a PDB.
- [client/README.md](client/README.md) - the 2026 client's quest-dialog close.
