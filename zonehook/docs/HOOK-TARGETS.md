# Where to hook the zone

A survey of Zone.pdb, for deciding *which* function to intercept and *with which of the four tools*.
Counts and addresses come from the generated headers (`mk_types.py`, `mk_symbols.py`); nothing here is
typed in by hand. Where something is unverified it says so.

**Pick the weakest tool that works.** `iat_hook` rewrites no code at all, `vtable_set` rewrites one pointer
in `.rdata`, `detour` rewrites `.text` and has to decode a prologue. In that order.

---

## The four tools, and when each is right

| tool | rewrites | use it for |
|---|---|---|
| `iat_hook` | one IAT slot | anything the exe **imports**. How the loader gets in front of `ServiceMain`. |
| `vtable_set` | one `.rdata` pointer | genuinely `virtual` methods — `ShineObject` has 776 `so_*`. |
| `detour` | 5+ bytes of `.text` | non-virtual members and free functions. Every packet handler. |
| `write_code` | a few bytes | flipping a branch or a constant, where a whole detour is overkill. |

A **binpatch recipe** is the fifth option and often the right one: if the change is a constant, a jump
table or a cap, declaring it in `recipes/` is reviewable and verifiable in a way a DLL patching bytes at
runtime is not. Hooks are for *behaviour*, recipes are for *limits*.

---

## Packet handlers — 246, all non-virtual

`ShinePlayer::sp_NC_<NAME>(TNETCOMMAND*, int, unsigned short)`. The mangling is `QAE` (public
`__thiscall`), **not** `UAE` — so none of them is virtual, no vtable holds their address, and every call
site is direct. They must be detoured.

Use `ZONE_HOOK_PACKET` / `ZONE_INSTALL_PACKET`; it handles the `__thiscall` ECX for you.

> All 246 addresses cross-check between two independent extraction paths (`S_PUB32` scan vs
> `S_GPROC32` + TPI). 0 mismatches. That check is worth keeping — it caught a real bug, where
> `llvm-pdbutil` prints a symbol's section offset in **decimal** and reading it as hex put
> `sp_NC_ITEM_RELOC_REQ` at `0x01671128` instead of its true `0x00537170`.

## S2S — `GameDBSession`, 222 handlers

The zone's session to the Character/DB bridge. Inbound S2S packets land on `gds_NC_<NAME>_ACK`, the exact
mirror of `sp_NC_*` for client packets, and the outbound side is `Send_NC_*_DB_REQ` on the owning system:

```
CQuestZone::Send_NC_QUEST_DB_SET_INFO_REQ      zone -> bridge
GameDBSession::gds_NC_CHARSAVE_ALL_ACK         bridge -> zone
```

**This is the persistence path** — a feature that must survive a relogin needs a request here and a
handler for its answer, not a write into some table. Same shape as the packet handlers (`__thiscall`,
non-virtual), so `hook_function` with the address from `zone_functions.h`.

*Unverified:* whether a new S2S opcode can be added without a matching change in the bridge exe. Almost
certainly not — the bridge dispatches on the opcode, so a genuinely new message needs both ends. Reusing
an existing DB call is the cheaper route and should be checked first.

## Handle resolution — `ShineObjectManager`

```
som_GetObject           handle -> object            the one you want
som_GetObjectAbsolute   handle -> object, unfiltered
som_FindPlayer / som_FindNPC / som_FindMover
som_AllocObject         where a handle is born
som_Getlist
```

A handle is only meaningful **per map** — see `fiesta-packetlog-analysis-traps`. Resolve it through the
manager that owns it; do not cache the pointer across a map change.

## Virtuals — `ShineObject`, 776 `so_*`

The place for `vtable_set`: `vtable_by_name()` takes a table from `kVtables`, `vtable_of(obj)` takes it
off a live object. Cheaper and safer than a trampoline, because nothing in `.text` changes.

## Locking — and the inventory in particular

130 symbols. The one that matters for a bag feature is the `InventoryLocking::InvenCellReleaser*` family
— a whole cell-reservation framework (`icr_Reserv`, `icr_Apply`, `lc_Free`) with a subclass per
operation (`_CellChange`, `_CenChange`, `_CardOpen`, …).

**Read this before writing to an inventory cell.** The zone reserves cells and applies the change later;
a hook that writes a cell directly will fight it. `CIOSpinLock::Wait` is the low-level primitive.

## Tables — read the LOADED ones

`CDataReader` is the zone's own reader (`Read`, `GetNumOfRecord`, `GetRecord`, and `Encription`, the SHN
cipher). But prefer `<zone_globals.h>`: 372 global objects, among them the containers the zone has
**already loaded**. Re-reading a file off disk answers a different question — what is on disk, not what
this server is running — and the two differ exactly when something was patched or overridden.

*Unverified:* whether the `.txt` tables (`Field.txt`) go through `CDataReader` in this build, or a
separate text path. Each table also has its own `<prefix>_Load`.

## Lua — 5.2, statically linked, symbols intact

Per **map**, not per process: `FieldMap::fm_GetLuaScript() -> LuaField -> LuaScript::ls_LuaObject`.
See `<zonehook_lua.h>`. Everything enters through
`LuaScript::ls_FunctionCall(const char*, LuaArgumentDefault*)`, so one detour observes every script call
by name — **verified live**: `script -> chrlghk`.

### NPC dialogue is already a script callback — do not build it

The engine passes typed arguments into script for 17 events, including:

```
LuaArgumentNPCMenu   { NPC, Player, SelectMenu }     a dialogue RESPONSE
LuaArgumentNPCClick  { NPC, Player, String }         an NPC clicked
LuaArgumentObjectDied, LuaArgumentItemUse, LuaArgumentMobAI, LuaArgumentPlayerLogin, ...
```

So "run a function when a given response is sent to a given dialogue" is a script switching on
`SelectMenu` — no C++ hook required. `on_function_call` is for *watching* it from C++, which is the
quickest way to find out what a map's script is actually called.

## PineScript

A second, older scripting system: `PineEventScriptNode`, `PineScriptToken`, `CCsl::ReadScript`, and
auto-registration tables (`index_npcclickhandle`, `index_npcclickindex`, `index_mobeliminate`,
`index_pickupitemindex`), all reachable in `<zone_globals.h>`.

*Unverified:* its execution entry point. `CCsl::ProcCmd` is the likely candidate but has not been
confirmed against a running script, so it is not wrapped in a helper yet.

---

## Getting in front of the service

Zone.exe **has no exports at all**, and `ServiceMain` is not a name — it is a callback in a
`SERVICE_TABLE_ENTRY` handed to `StartServiceCtrlDispatcherA`. Hooking that one import yields the table
before the SCM sees it, so the wrapper is literally `{ our_setup(); OriginalServiceMain(argc, argv); }`.
No PDB, no address, no instruction decoding — it works on every Fiesta exe that is a service.

Verified live:

```
[loader] [service] table entry 0: 'ZoneServer' ServiceMain 653480 -> 789023c0
[loader] [service] '_Zone0' starting; running set-up before its ServiceMain at 653480
```
