# Shine object handles, pools and per-kind caps (Zone.exe)

Written while lifting the NPC cap (`npc-object-pool-cap.json`), 2026-09-15. Read this before moving any other
kind's capacity — the numbers below are what makes a "cap" take four or five edits instead of one.

## A handle is a u16 carved into per-kind ranges

`sohu_HandleSplit` (**0x00633650**) is an if-chain of literal bounds, not a table. Each block tests BOTH its
bounds and returns `(kind, index)`:

```
    mov ecx, <lower> ; cmp cx, ax ; ja  next
    mov edx, <upper> ; cmp ax, dx ; jae next
    add eax, -<lower>            ; index = handle - lower
    mov al, <kind>
```

Because every block carries both bounds, **the blocks do not have to stay in ascending order** — a kind can be
moved anywhere free in the u16 space by editing its three immediates, with no cascade through the others. That
is how the NPC recipe avoids touching kinds 8..11.

Ranges in the stock 2016 `Zone.exe` (upper is exclusive; span = the kind's capacity):

| upper | kind | span | what (confirmed where noted) |
|---|---|---|---|
| 0x1F40 | 5 | 8000 | mobs (live probe: pool +0x10C holds 8000) |
| 0x251C | 2 | 1500 | players ([[zone_live.py]] saw one live slot per bot) |
| 0x2904 | 3 | 1000 | |
| 0x34BC | 1 | 3000 | |
| 0x42BC | 0 | 3584 | |
| 0x43BC | 4 | 256 | **NPCs** |
| 0x4BBC | 8 | 2048 | |
| 0x4FA4 | 9 | 1000 | |
| 0x509E | 6 | 250 | |
| 0x5486 | 7 | 1000 | |
| 0x567A | 10 | 500 | |
| 0x5A62 | 11 | 1000 | |
| 0x6232 | .. | | the chain ends here, so 0x6232+ is free space |

Two places COMPOSE an NPC handle (`add eax, 0x42BC`): **0x00548F3A** and **0x00557CA2**. Each kind has its own
pair; find them by searching the code section for that kind's base as an imm32.

## A kind's capacity is SIX constants, not one

For NPCs (factory type 4, pool at manager+0xCC, manager singleton **0x132826B8**):

| VA | stock | what |
|---|---|---|
| 0x0055765D | 0x100 | `ShineObjectPool::Create` element count, in the manager ctor |
| 0x0055C6B7 | 0x256C04 | `operator new` byte count for the object array (`count * 0x256C + 4`) |
| 0x0055C6D9 | 0x100 | eh vector ctor element count |
| 0x0055C6E8 | 0x100 | array cookie (`mov dword [eax], 0x100`), read by the dtor |
| 0x0055C7AE | 0xC00 | **fill loop bound, in SLOT BYTES** (`count * 12`) |
| 0x00548F27 | 0x100 | handle maker A: `index < span` check, else returns **0xFFFF** |
| 0x00557C81 | 0x100 | handle maker B: the same check |

The fill loop is the one that hides: it walks slots 12 bytes at a time and object array entries `0x256C` at a
time, and ends on `cmp eax, <count*12>` rather than on the pool's own count field. Raise everything else and it
still attaches only 256 objects; the factory then hands out slots whose object pointer is NULL and the caller
asserts. **The assert count goes UP, which reads like the patch made things worse.**

The two handle makers are the ones that hide NEXT: each is `mov edx, <span> ; cmp dx, ax ; ja compose ; mov eax, 0xFFFF`.
Leave them at 0x100 and NPC number 257 onward is created without any assert but carries the INVALID handle
0xFFFF. Nothing can look it up afterwards: `cIsObjectDead(0xFFFF)` reports dead, so an AI script takes its dead
branch and the zone logs `lss_Routine : function call error` 40 times a second with no hint of the cause. The way
to see the real cause is a `pcall` wrapper in the staged script that logs through the `cAssertLog` binding: it
printed `handle=65535 dead=1 ... attempt to index global 'PuzzleMemory'`.

The pool above NPCs uses the identical shape — `cmp eax, 0x4650` = 1500 * 12 — so the same five edits, with the
kind's own element size, should lift any other kind.

## How to find the rest of a cap: read the live process

Static search kept missing the fill loop. `tools/zone_npcpool_probe.pl` (run it with
`docker exec --privileged <zone> perl /tmp/n.pl`) prints, for each sub-pool: element count, slot table address,
how many slots carry an object, and the object address span. "1024 slots, 256 with an object" pointed straight
at the attach loop. Pool layout, from `ShineObjectPool::Create` (0x005546F0):

```
    +0x04 u16 count   +0x08 ptr slot table   +0x0C u16 free head   +0x0E u16 free tail
    slot = 12 bytes { obj u32, next u16, prev u16, live u8 }
```

## Side effect worth expecting

Objects the stock server silently DROPPED start existing, which can expose content defects that were masked by
the cap. Do not blame the content first: the puzzle-game AI NPCs (Xiaoming/Oluming/Toryming on Eld) failed every
tick after the lift and it was the recipe (the maker span checks above), not their scripts.
