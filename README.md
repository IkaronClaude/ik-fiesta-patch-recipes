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
