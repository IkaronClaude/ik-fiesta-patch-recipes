# ik-fiesta-patch-recipes

Declarative binary patches for the Fiesta server executables, as **data plus a runner** rather than a
pile of one-off scripts. A recipe records every byte it changes, what it expects to find there, and why —
so re-running it after a parameter change is one command, and so the reasoning survives long enough to be
checked by someone who wasn't there.

```bash
# see what a recipe would do, without writing anything
python apply.py recipes/mob-spawn-group-cap.json --exe Z:/ServerSource/Zone00/Zone.exe --dry-run

# produce a patched binary (never in place)
python apply.py recipes/mob-spawn-group-cap.json --exe Z:/ServerSource/Zone00/Zone.exe --out build/Zone.exe

# change a parameter without editing the recipe
python apply.py recipes/mob-spawn-group-cap.json --exe ... --out build/Zone.exe --set groups=32768

# prove a binary you already have is the patched one
python apply.py recipes/mob-spawn-group-cap.json --exe ... --verify build/Zone.exe
```

Stdlib only. A recipe you can't run because a dependency moved is not repeatable.

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

## Recipes

### `mob-spawn-group-cap` — lift Zone.exe's 4096 spawn-group ceiling

`MobHatchery` stores its spawn groups as an **inline fixed array**, not a pointer: the constructor
(`0x4B3FC0`) runs the eh vector-constructor iterator over `0x1000` elements of `0x19B8` bytes and puts the
`List<MobBreederGroup>` header at a baked `+0x19B8000`. That's 25.7 MB embedded in the object.

It is **static, not heap** — `0x5AD987` stores the constant `0x13389A48` into the global pointer
`?mobhatchery@@3PAVMobHatchery@@A`, and a CRT init stub does `mov ecx,0x13389A48; call ctor`. (The `PAV`
in the symbol is a pointer *variable* aimed at a static, which is exactly what makes it look
heap-allocated.) It cannot grow in place either: the array ends at `0x14D41A48` and `?clockwatch@@…`
starts at `0x14D41A60` — **24 bytes** of headroom.

It *can* be relocated, and that's the whole trick. All 14 call sites reach the object through the global
pointer; only three instructions carry its raw address. So the recipe appends a section with room, repoints
those three immediates, and rewrites every constant the layout is built from — **22 edits, no code cave
and no allocator call**. (An earlier draft said "and therefore no new runtime failure mode". That did not
follow and was not true: relocating into a fresh section is itself a new failure mode, and the first two
attempts crashed. See Status.)

**The overflow guards need no patching.** `mh_Load` and `mh_ScriptBreed` don't compare against a literal;
they test whether the List handed back the invalid-handle sentinel (`cmp ax, 0xFFFF` at `0x4B6595`). The
bound is the List's stored capacity, which `l_MakeList` sets from the constant this recipe changes. A
`[4096]` seen in `mh_View` output is `%d` rendered from that same field and will follow automatically.
There are zero 16- or 32-bit compares against 4096 anywhere in the regen code.

**Ceiling: 65534.** Handles are `unsigned short`, and `0xFFFF` is both the invalid-handle sentinel and a
capacity `l_MakeList` explicitly refuses (`0x4B3B57` nulls the array and returns an unusable list). Going
beyond means retyping the `List` template — every handle, and probably the wire protocol.

**Sizing.** Shipped content is 6,038 `MobRegenGroup` records across 88 files (per zone: 1628 / 1962 /
1942 / 261). One process therefore needs more than 4096 *today*, before any 2026 content.

| groups | memory | vs current content |
|---|---|---|
| 8,192 | 51 MB | 1.4× |
| **16,384** (default) | **103 MB** | **2.7×** |
| 32,768 | 206 MB | 5.4× |
| 65,534 | 412 MB | hard ceiling |

This is a large net *saving*, not a cost: one process replaces five, each of which carried its own 25.7 MB
hatchery inside a 334 MB `.data` image.

### `damage-overflow-saturate` — stop huge hits landing for 1

`roe_CalcDamage` returns `int`, but the damage pipeline under it works in **double**. The conversion is
one call to `__ftol2_sse`, which returns the x86 *integer indefinite* `0x80000000` when the value doesn't
fit an `int32`. That negative survives three modifiers and reaches the tail:

```
test eax, eax
jg   ok
mov  dword ptr [ebp-0x10], 1     <-- the biggest hit in the game lands for 1
```

**The clamp is not the bug and must not be touched** — that `1` is also the floor for legitimately
non-positive damage (defence ≥ attack), so rewriting it to a maximum would make every weak hit maximal. By
the clamp the magnitude is already gone, so the fix goes at the conversion.

Both damage-producing conversions (`roe_CalcDamage` 0x506187, `roe_AttackPowerCalcDamage` 0x504A27) are
redirected to a 36-byte stub in an appended executable section. It saturates on the indefinite result
**only when the original double was positive** — `__ftol2_sse` also returns `0x80000000` for negative
overflow and NaN, and saturating those would invent enormous damage from a broken calculation. The sign is
taken with `FTST` before the call and stashed across it.

Default `saturate_to` is `0x00FFFFFF` rather than `INT_MAX`, because modifiers run *after* the conversion
and at least one multiplies — `0x7FFFFFFF` would just wrap again and land back on the clamp.

The other 207 `__ftol2_sse` sites convert rates and stats (`roe_AC`, `roe_MinWC`, `roe_HitRate`, …) and are
deliberately left alone.

### `quest-count-cap` — Zone.exe won't start above 3000 quests

`ZoneServer_zs_start_sink` checks the quest file header at startup and kills the process:

```
movzx edi, word ptr [eax+2]    ; QUEST_DATA_HEAD.NumOfQuest (u16)
mov   eax, 0xBB8               ; 3000
cmp   di, ax
jbe   ok
      ac_As("Too Many Quest - MAXQUEST")  ->  ShineExit
```

**Unlike the spawn-group cap, nothing is sized by this number** — the quest body is allocated from
`__filelength`, the lookups are STL hash maps, `GetQuestDataByIndex` bounds against `NumOfQuest` from the
header, and the player's array is `malloc(n*32)` on demand. A scan for 3000 and its derived sizes (375 =
3000 bits, 376, ×2, ×4, ±1) finds nothing in quest code at all. So it really is one 32-bit immediate — no
relocation, no code, no structure growth. That contrast is the reason this recipe is one edit and
`mob-spawn-group-cap` is twenty-two.

Hard ceiling 65535: `NumOfQuest` is a `u16` and the guard compares 16-bit (`cmp di, ax`), so a larger
constant would silently truncate. The runner refuses it. Default 16384 keeps the guard useful against a
corrupt header while clearing 2026's 3100+.

### `block-distribute-map-cap`, `block-info-cap`, `instance-cluster-cap` — the per-process map limits

Three caps bind when one zone process hosts many maps; `recipes/NOTES-map-caps.md` has the full reading.

| recipe | stock cap | assert | what moves |
|---|---|---|---|
| `block-distribute-map-cap` | 64 distinct maps (`bdm_Array[64]`, a 1 KB static) | `bdm_Find` ShineExits | the array to `.bdmarr`; 3 `this` immediates + 6 counts (9 edits) |
| `block-info-cap` | 256 block infos (`mbib_array[256]` + count, 741 KB static) | `mbib_Load: Too many block info[256]` | the box to `.mbibox`; 4 addresses, 2 vector counts, the bound, 6 count-member offsets (12 edits) |
| `instance-cluster-cap` | 10 instance clusters (`Clusters[10]` mid-object) + List capacity 14 | `AddInstanceDungeonCluster: Cannot Add[10]` | only the array, to `.clusarr`: three `lea reg,[this+0x28068]` become `mov reg, imm32; nop`, two imm8 bounds, the dtor trip count, the `push 0xe` (13 edits) |

Two things these needed that earlier recipes did not:

- **Byte-width edits.** imm8 operands (`cmp esi, 0x40`, `push 0xe`) and the opcode / padding bytes of the
  lea->mov rewrite are single bytes inside instructions whose other bytes must stay. `"width": 1` (or 2)
  on an edit reads, expects and writes just that many bytes; the default stays 4.
- **Range scans.** `tools/xref_range.py --range lo-hi` lists every instruction whose imm32 / absolute
  disp32 lands inside a static object, and `--disp lo-hi` every register-relative member access — the
  form a mid-object array takes. This is how the three `lea` sites and the five `mbib_Number` accesses
  were found, and how "no absolute reference to a slot" was established rather than assumed.

Limits are imm8-shaped: 124 maps (multiple of 4 for the unrolled destructor), 123 clusters; block infos
are imm32 everywhere (1024 by default). Chained on top of `mob-spawn-group-cap` + `quest-count-cap`:

```bash
python apply.py recipes/block-distribute-map-cap.json --exe build/Zone.quest.exe --out build/Zone.maps1.exe --allow-hash-mismatch
python apply.py recipes/block-info-cap.json           --exe build/Zone.maps1.exe --out build/Zone.maps2.exe --allow-hash-mismatch
python apply.py recipes/instance-cluster-cap.json     --exe build/Zone.maps2.exe --out build/Zone.maps.exe  --allow-hash-mismatch
# every recipe verifies against the final image:
python apply.py recipes/<any>.json --exe Z:/ServerSource/Zone00/Zone.exe --verify build/Zone.maps.exe
```

### `npc-click-quest-fallthrough` — an NPC with an EMPTY quest script ignores every click

`ShinePlayer::InteractWithNPC` decides between "quest" and "the NPC's own role" *before* running anything,
then discards the quest click's result. A quest sitting on an empty DOING or END script (245 + 83 in the 2016
data, 262 + 91 in the 2026 set) therefore runs nothing, sends nothing, and never reaches the menu or shop: the
NPC is dead to that player. A 24-byte cave makes a quest click that ran nothing fall through to the role.

Proven live with a scripted client. The cave has to **push the stack argument again** - `call`ing a
`__thiscall` with a stack argument from a cave puts a second return address in front of it, and the first
build of this recipe crashed the zone on one click because of exactly that. The recipe carries the callstack.

### `client-2026-npc-dialog-self-close` — the first CLIENT recipe: let the 2026 quest dialog close itself

The runner does not care which executable it is pointed at, so client patches live here too. This one
targets the 2026 US **`Fiesta.exe`** (not the stale `Fiesta.bin` that ships beside it).

A 2016 client closes its quest dialog on every button click and lets the server's next page reopen it.
The 2026 client put a global in front of that close, set only by a new packet (`0x442E`) that no 2016
server sends — so against one, *Next* and *Complete Quest* do nothing on the last page of a script, Esc
closes the window, and the quest turns out to have progressed anyway.

    2016  NpcDialogWin::DirectMessage, msg 0x24:  if (keepOpen) keepOpen = 0;  else CloseWin(this);
    2026                                          if (keepOpen) keepOpen = 0;  if (g_C319D5 == 1) CloseWin(this);

Three bytes restore the 2016 branch exactly. The recipe carries the full disassembly and the reasoning.

```bash
python apply.py recipes/client-2026-npc-dialog-self-close.json --exe <client>/Fiesta.exe --out build/client2026/Fiesta.exe
# on a copy that already carries other byte patches the file hash differs; the per-site expect checks still hold:
python apply.py recipes/client-2026-npc-dialog-self-close.json --exe <patched>/Fiesta.exe --out build/client2026/Fiesta.exe --allow-hash-mismatch
```

It does **not** remove the close-and-reopen between pages: that is native 2016 behaviour. Keeping the
window up between pages needs the server to say which page is the last one. The no-client-patch
alternative is fiesta-proxy's Bridge2026, which sends the `0x442E` itself; run it with `-NoDialogClose`
when testing this recipe so it is the patch being tested and not the bridge. **Untested live as of
2026-09-17.**

## Status

`mob-spawn-group-cap` **works**: boots clean at `groups=16384` under Wine, 91 maps loaded, and on an
all-maps-on-one-zone layout (5,845 groups) it clears the spawn-group ceiling and stops on a different,
unpatched limit — the instance-dungeon cluster cap, written up in
`recipes/NOTES-instance-dungeon-cluster-cap.md`.

Getting there took two failed rounds, and both failures generalise to any recipe in this repo:

**Search the offset RANGE, not the value.** Only 8 of 15 sites bake exactly `0x19B8000`; seven more bake
`base+0x4/+0x8/+0xC/+0xE` to reach members of the structure that follows the array. An exact-value search
finds the 8, and the binary then reads a garbage free-list head from inside the array and faults in
`l_AllocZ+0x1F`. One nearby hit (`0x019B820F` in `MoveManager::mm_Step`) is coincidence — a range search
needs a human to separate real offsets from collisions.

**Look for unrolled loops.** The constructor's node-linking loop is unrolled four ways and bakes the
*iteration* count (`0x400` = 1024), not the element count (4096). Nothing matching `0x1000` exists at that
site. Without it, only the first 4096 nodes are linked and everything above hands back an unlinked node.

The diagnostic that isolated both: build with `--set groups=4096` — relocation applied, count unchanged.
That booted clean, while `groups=4097` crashed, which ruled out the section, the relocation, the image
size and address space in one run, and pointed squarely at the count.

Untested: whether a virtual-only (BSS) section works. The only virtual-only run used a count that failed
for unrelated reasons, so `materialise: true` is simply the configuration that has been exercised.
