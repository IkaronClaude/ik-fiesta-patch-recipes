# Instance-dungeon cluster cap (10) — findings, and why there is no recipe yet

Hit immediately after `mob-spawn-group-cap` clears the spawn-group ceiling. With every map on one zone,
`Field.txt` puts **15** `InstanceDungeon` rows on that zone and the server asserts:

```
AssertClass::ac_AssertFail : MapClusterManager::ClusterManager::AddInstanceDungeonCluster : Cannot Add[10]
```

## Where the 10 lives

`AddInstanceDungeonCluster` (0x484850) walks a fixed pointer array looking for a free slot:

```
lea ecx, [esi + 0x28068]      ; the array, inside ClusterManager
loop:
  cmp dword ptr [ecx], 0      ; free slot?
  je  found
  inc eax
  add ecx, 4                  ; 4-byte entries -> pointers
  cmp eax, 0xa                ; <-- the cap, imm8 at 0x00484889 (+3 = 0x0048488B)
  jl  loop
xor al, al                    ; full -> "Cannot Add"
```

`cm_AddTutorialMapCluster` (0x4A09B5 / bound at 0x4A09C8) walks the **same array with the same bound**.

## Why it is not a constants-only patch

The array is `void*[10]` at `+0x28068`, and the constructor zeroes **ten individual slots**:

```
+0x28068 +0x2806C +0x28070 +0x28074 +0x28078
+0x2807C +0x28080 +0x28084 +0x28088 +0x2808C
```

10 × 4 = 40 bytes, ending at `+0x28090` — and **`+0x28090` and `+0x28094` are different members**, written
by both the constructor (0x4A1081, 0x4A10D6, 0x4A10DC) and the destructor (0x4A0385). There is no
headroom, exactly as with `MobHatchery`.

The difference that matters: the hatchery's array was at **offset 0** with only a List header after it, so
relocating the whole object and rewriting two size constants was enough. This array sits **mid-object**, so
growing it in place shifts every member above `+0x28090`, and those offsets are baked across the class.

Two workable designs, neither of which is a constant edit:

1. **Move just the array.** Point the three base references (`AddInstanceDungeonCluster`,
   `cm_AddTutorialMapCluster`, the dtor at 0x4A034C) at a fresh zero-filled section and raise both `0xa`
   bounds. A zeroed section gives all N slots a null start, which is what the ctor's ten writes achieve —
   so the ctor's unrolled zeroing does not need extending. But `lea ecx,[esi+0x28068]` (6 bytes) has to
   become `mov ecx, imm32` (5 bytes + padding), i.e. **instruction rewriting**, which `apply.py`'s
   edit model (32-bit value replacement at an address) does not express.

2. **Relocate ClusterManager** the way the hatchery was relocated, growing the array and shifting the
   following members. Needs every `+0x2809x`-and-above offset found and rewritten. Note
   `?mapclustermanager@@3VClusterManager@MapClusterManager@@A` (0x0D742B30) is typed `V`, not `PAV` — the
   object *is* the static, not a pointer to one, so absolute references to it may be more numerous than
   the hatchery's three.

Also raise, in either design: the `List<MapCluster>` capacity, `push 0xe` (14) at **0x004A0F2D** in the
ClusterManager constructor. 14 is already below the 15 dungeons the all-maps layout wants, so it binds too.

## Before building this

Apply both lessons from `mob-spawn-group-cap`, which cost two failed test rounds:

- **Search the offset RANGE, not the value.** `+0x28068` is reached as `+0x2806C`, `+0x28070`, … by the
  members after it. An exact-value search finds a fraction of the sites.
- **Look for unrolled loops.** The hatchery's node-link loop baked a trip count of `count/4`. The
  ClusterManager ctor's ten slot writes are the same compiler habit, fully unrolled; anything similar that
  iterates the cluster array needs finding before the bound is changed.

## Unknown

Whether 15 `InstanceDungeon` rows actually need 15 clusters — clusters may be keyed by dungeon name, so the
real requirement could be lower than the row count. Worth measuring before choosing a size; if the answer
is ≤ 14 then only the two `0xa` bounds need raising and design (1) collapses to two byte edits.
