# zonehook — write zone features in C++ instead of byte patches

Every 2026 feature the zone still lacks is **code**, not data: the void bag is a new `ItemBag` subclass, the
Corruption event is a whole packet department, quest-gated map entry is a check the 2016 exes never had. A
recipe in this repo can move a constant or repoint a global; it cannot add a class or a packet handler. So
the zone gets a DLL, and the features get written in C++.

## How it loads

`recipes/dll-loader.json` adds one import to Zone.exe. The Windows loader then maps `zonehook.dll` and runs
its `DllMain` **before the exe's entry point** — ahead of the CRT, before any zone thread exists. No code is
patched to make this happen, and it is undone by rewriting one data directory.

The import descriptor array (8 entries in `.rdata`) is *copied* into a new `.zhook` section with a ninth
appended; the originals keep their ILT/IAT/name RVAs. `apply.py` refuses if the image has a bound-import
directory, because a bound image may skip the descriptor array entirely and silently drop the new entry.
Zone.exe has none.

```
python apply.py recipes/dll-loader.json --exe Z:/ServerSource/Zone00/Zone.exe --out build/Zone.hooked.exe
cd zonehook && build.bat
copy zonehook\build\zonehook.dll  <next to Zone.hooked.exe>
```

Verified with an independent parser: `pefile` reads the patched image as
`zonehook.dll -> ZoneHookInit (hint 0)`, and the eight original imports are byte-identical.

## What's in the box

| | |
|---|---|
| `src/hook.h/.cpp` | trampoline `detour()`, `vtable_set()`, `rebase()`, logging |
| `src/packet_hook.h/.cpp` | hook a zone packet handler **by name** |
| `src/zone_symbols.h` | generated — 246 handler addresses straight from Zone.pdb |
| `tools/mk_symbols.py` | regenerates the above for a different Zone build |
| `test/test_hook.cpp` | self-test; runs standalone, no Zone.exe needed |

## Hooking a packet

The zone dispatches to `ShinePlayer::sp_NC_<NAME>(TNETCOMMAND*, int, unsigned short)`. **None of these is
virtual** — the mangling is `QAE` (public `__thiscall`), not `UAE` — so there is no vtable slot to swap and
the call sites are direct. Each hook is a trampoline on the function itself, at an address taken from the
PDB rather than typed in.

```cpp
ZONE_HOOK_PACKET(NC_ITEM_RELOC_REQ, {
    const unsigned char* p = (const unsigned char*)cmd;
    unsigned short from = *(const unsigned short*)(p + 2);   // past the opcode
    unsigned short to   = *(const unsigned short*)(p + 4);
    zone::log("[reloc] %u:%u -> %u:%u", from >> 10, from & 0x3FF, to >> 10, to & 0x3FF);
    ZONE_CALL_ORIGINAL_OF(NC_ITEM_RELOC_REQ);                // omit to swallow the packet
});
...
ZONE_INSTALL_PACKET(NC_ITEM_RELOC_REQ);
```

`__thiscall` puts the `ShinePlayer*` in ECX, which a free function cannot declare portably — hence the
macro, which emits a naked thunk and hands the body an explicit `self`.

`vtable_set()` is there for genuinely virtual methods, where swapping a slot is cheaper and safer than
rewriting `.text`.

## Things that will bite

- **Install only from `DllMain`.** Rewriting code another thread is executing is how you get a crash that
  reproduces once a week. At `DLL_PROCESS_ATTACH` no zone thread exists yet.
- **Don't *call* zone code from `DllMain`.** The CRT has not run and the globals are not constructed. Do
  that work in a hook body, which by definition fires once the zone is alive.
- **`insn_len()` is deliberately partial.** It decodes the prologue shapes this build actually uses and
  returns 0 for anything else, so `detour()` refuses instead of truncating an instruction. If a hook is
  refused, the log names the address and the byte — add that opcode rather than working around it. The
  `A0-A3` moffs group was added exactly this way, after `test_hook` caught `55 8B EC A1 ...`.
- **Zone.exe sets DYNAMIC_BASE**, so it can load away from 0x00400000. Every address goes through
  `zone::rebase()`; never use a PDB VA as a raw pointer.
- **32-bit only.** Zone.exe is PE32; a 64-bit DLL will not load into it. `build.bat` uses `vcvars32.bat`.
- **The symbol table is per-build.** `zone_symbols.h` records the exe's SHA-256; regenerate with
  `mk_symbols.py` against a different Zone.

## Status

Built and self-tested on 2026-09-19. The import injection is verified structurally with `pefile`; the hook
machinery passes `test_hook.exe` (trampoline on a `__thiscall` method, on a `__cdecl` function, result
rewriting, and clean uninstall). **Not yet run inside a live zone** — that needs the docker stack with the
patched exe and the DLL beside it.
