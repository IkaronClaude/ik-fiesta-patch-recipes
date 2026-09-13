# Map caps in Zone.exe (2016 build) - where each limit lives and how each recipe lifts it

Read 2026-09-14 out of `Z:/ServerSource/Zone00/Zone.exe` + `Zone.pdb` (capstone; `tools/xref_range.py` for the
reference scans). Three separate caps bind when a zone process hosts many maps:

| cap | assert | object | limit lives in |
|---|---|---|---|
| distinct maps per zone | `BlockDistributeManager::bdm_Find : ...` (ShineExit) | `?blockdistmanager@@3VBlockDistributeManager@BlockDistribute@@A` @ 0x8B7018, 64 x 16 B | imm8 loop bounds |
| block infos per zone | `MapBlockInformationBox::mbib_Load : Too many block info[256]` | `?blockinfobox@@3VMapBlockInformationBox@MapBlock@@A` @ 0xD68AB10, 256 x 0xB50 B + count | imm32 bound + count member offset |
| instance-dungeon clusters | `ClusterManager::AddInstanceDungeonCluster : Cannot Add[10]` | `?mapclustermanager@@3VClusterManager@MapClusterManager@@A` @ 0xD742B30, `Clusters[10]` at +0x28068 mid-object | imm8 loop bounds + List capacity 14 |

## 1. BlockDistribute (recipe `block-distribute-map-cap`)

`BlockDistributeManager` is exactly `bdm_Array[64]` of `{Name3 mapid; BlockingDistribute* block}` (16 B) -
1024 bytes, the whole object. `bdm_Find` (0x438F70) linear-searches the array by map name, takes the first
empty slot, and ShineExits when all 64 are taken: one slot per DISTINCT map name in the process.

References into 0x8B7018..0x8B7418 (`xref_range --range`): exactly three, all `mov ecx, imm32`:
`mbi_Load+0x519` (0x49E8CA), the CRT ctor stub (0x695161) and the atexit dtor stub (0x69C661). No
data-section pointer. So the object relocates to a new section with three immediates.

Counts to rewrite (the array is walked by count, never by end pointer):

| site | instruction | operand |
|---|---|---|
| 0x438AD2 | ctor `push 0x40` (eh vector ctor count) | imm8 |
| 0x438AE4 | ctor `mov edi, 0x40` (name init loop) | imm32 |
| 0x438FCA | bdm_Find `cmp esi, 0x40` | imm8 |
| 0x438FCF | bdm_Find `cmp esi, 0x40` (the assert test) | imm8 |
| 0x438B26 | dtor `mov esi, 0x10` = count/4, loop unrolled x4 (`add eax, 0x40`) | imm32 |
| 0x438B63 | dtor `push 0x40` (eh vector dtor count) | imm8 |

Limits: imm8 operands are sign-extended, so **N <= 127**; the unrolled dtor needs **N % 4 == 0** -> max 124.
Enough: 4 zone processes x 124 = 496 distinct maps, and the mob object pool (~8100 live mobs per process)
binds long before that.

## 2. MapBlockInformationBox (recipe `block-info-cap`)

`MapBlockInformationBox` = `mbib_array[256]` of 0xB50 B (`Name3 mapid; xsize; ysize; MapBlockInformation`)
followed by `int mbib_Number` at +0xB5000. `mbib_Load` (0x49E940) looks the map up by name, else appends at
`mbib_Number` and asserts at 256. The object has no ctor symbol: the CRT stub at 0x696800 runs the eh vector
ctor over it (`push 0x100; push 0xB50; push 0xD68AB10`) and zeroes the count with an absolute store to
0xD73FB10; the atexit stub at 0x69D890 runs the vector dtor with the same count.

References: `fm_Init+0x19D` (`mov ecx, 0xD68AB10`), the two stubs (imm32 pushes, the abs count store), and
five `[esi + 0xB5000]` accesses to `mbib_Number` inside `mbib_Load`. No data-section pointer.

Relocate to a section of `N*0xB50 + 4`; rewrite the four object addresses, the two vector counts
(imm32), the bound `cmp eax, 0x100` (imm32 at 0x49E98E), and the six count-member offsets
(`N*0xB50`). All imm32/disp32 - no small-operand limit. 1024 entries = 2.97 MB.

## 3. Instance-dungeon clusters (recipe `instance-cluster-cap`)

`ClusterManager` keeps `MapCluster* Clusters[10]` at +0x28068, then `Metronome cm_EmptyCheck` at +0x28090
(end of object, size 0x28098). Users of the array (`xref_range --disp 0x28068-0x28098`, plus the absolute
range 0xD742B30..): the ctor's ten unrolled zero stores, and three walkers that each load the array base with
`lea reg, [this + 0x28068]` and count to 10:

| function | base load | bound |
|---|---|---|
| `AddInstanceDungeonCluster` 0x484850 | 0x484879 `lea ecx, [esi+0x28068]` | 0x48488B imm8 (`cmp eax, 0xa`) |
| `cm_AddTutorialMapCluster` 0x4A0860 | 0x4A09B3 `lea ecx, [edi+0x28068]` | 0x4A09CA imm8 |
| `~ClusterManager` 0x4A0310 | 0x4A034A `lea ebx, [esi+0x28068]` | 0x4A0356 imm32 (`mov [ebp-0x10], 0xa`) |

Nothing addresses a slot absolutely (0xD76AB98..0xD76ABC0 has no reference; 0xD76ABC0/4 are the Metronome).

Design chosen: **leave the object where it is and move only the array** into a zero-filled section. Each
`lea reg, [this+disp32]` (6 bytes: `8D /r disp32`) becomes `mov reg, imm32` (5 bytes: `B8+r imm32`) plus a
`nop`: one byte of opcode, four of address, one of padding - three edits per site. The ctor's ten stores
still zero the old in-object array (harmless); the new slots start zero because the section does. The
relocated-object alternative would have meant rewriting ~45 `this` immediates.

Also: a new cluster's slot index doubles as its node index in the `List<MapCluster>` base
(`AddInstanceDungeonCluster+0x9C..0xC5` indexes `[this+8]` by the slot), whose capacity is `push 0xe` in the
ctor at 0x4A0F2E (imm8) - raise it to N + 4 (the 2016 headroom over 10).

Limits: `cmp eax, imm8` and `push imm8` -> **N + 4 <= 127**. Field.txt has 17 InstanceDungeon rows in total
(13 distinct maps), so 32 covers every layout.

## Tooling

`apply.py` edits were 32-bit only; imm8 sites and the opcode/nop bytes of the lea->mov rewrite need
`"width": 1` (also 2), added for these recipes. `tools/xref_range.py` is the reference scanner.
