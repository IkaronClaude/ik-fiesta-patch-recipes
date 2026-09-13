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
pointer; only three instructions carry its raw address. So the recipe appends a BSS section with room,
repoints those three immediates, and rewrites the two size constants the layout is built from — **14
edits, no code cave, no allocator call, no new runtime failure mode**.

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

## Status

The patched binary is produced and statically verified — 14 sites confirmed, PE re-parses, the constructor
disassembles to `push 0x4000` / `lea esi,[ebx+0x66e0000]`, `.mobhat` present with zero file bytes.

**It has not been run.** Nothing here has been executed by a zone process, under Wine or otherwise. Two
things to watch on first boot:

- A BSS section with `PointerToRawData = 0` is standard, but this build runs under Wine via SCM — worth
  confirming the loader commits it rather than assuming.
- `SizeOfImage` grows to 440 MB. The image is `LARGE_ADDRESS_AWARE`, so this is well within a 32-bit
  process's reach, but it is reserved at load.
