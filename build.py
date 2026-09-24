"""Build a patched server exe from the stock one: every recipe of its chain in order, each verified on the result.

    python build.py --exe Z:/ServerSource/Zone00/Zone.exe --out build/Zone.2026.exe [--experimental]
    python build.py --exe ... --out ... --upto damage-overflow-saturate            # a shorter chain
    python build.py --target character --exe Z:/ServerSource/Character/Character.exe --out build/Character.hooked.exe

A chain's recipes live in <target>/recipes/ (zone/, character/).

The chain used to be applied by hand, one apply.py call at a time. The ORDER matters: recipes that add a
section place it after whatever is already there, so the same recipes in another order give a different
(still working) binary, and nobody could say which order a given build/ file came from. This file is that
order, and the parameters each recipe was built with.

Stacking needs --allow-hash-mismatch for every recipe after the first (each pins the stock sha256); that
is safe because every site still declares the bytes it expects, and every recipe is --verify'd on the
final binary before this reports success.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# (recipe, --set overrides). Order is load order.
CHAIN = [
    ('mob-spawn-group-cap', []),
    ('quest-count-cap', []),
    ('block-distribute-map-cap', []),
    ('block-info-cap', []),
    ('instance-cluster-cap', []),
    # NPC handles at 0x525C, where the 2026 client expects them (handle-layout-2026 moves every other kind).
    ('npc-object-pool-cap', ['handle_base=0x525C']),
    ('damage-overflow-saturate', []),
    ('npc-click-quest-fallthrough', []),
    ('quest-script-end-notify', []),
    ('handle-layout-2026', []),
    # NPC.txt rows 1024 -> 4096: the whole NPCManager global moves to its own section
    ('npc-table-cap', []),
]

# Built and verified but NOT yet booted on a live zone: applied only with --experimental, so nobody gets an untested
# binary by running the default chain. Move an entry up into CHAIN once it has run.
EXPERIMENTAL = [
    # Adds an import for zonehook.dll so features can be written in C++ (see "Hooks" in README.md). Structurally
    # verified with pefile and the hook library passes its own self-test, but no zone has booted with it yet.
    ('dll-loader', []),
    # Third permanent inventory expansion (8 pages, as in 2026) - the 2026 client's prerequisite for the void
    # inventory. One imm8 in UseItemChargedBuff::uib_CanUseItem; see the recipe.
    ('inventory-expansion-cap', []),
    # Bag 18 (the 2026 Void Inventory) in item moves: widens sp_ItemReloc's two bag switches and hands case 18
    # to the void_bag plugin through a slot. Inert without the plugin (a null slot takes the default).
    ('void-bag-reloc', []),
    # AbStataIndex list 792 -> 2048 slots: the whole dic_abstate global moves to its own section (the 2026 AbState
    # table needs 1083; the 1032 / 1040 `Invalid skill idx` asserts). Data stays 2016 until AbState / SubAbState /
    # AbStateView switch to 2026 in Fiesta2026on2016; the relocation itself is inert with the 2016 tables.
    ('abstate-index-cap', []),
    # Mob pool 8000 -> 12000 (the 2026 client's mob handle range; needs the player base handle-layout-2026 moved).
    ('mob-object-pool-cap', []),
    # Title stat bonuses for 2026 title types 128..255 (the state array moved to its own region; the loader wrote
    # unbounded). Pairs with the title_ext plugin and character-title-types.
    ('title-state-types', []),
    # Merchant shop lists 100 -> 1024 ("Too many merchants[100]", counted per NPC.txt PLACEMENT of a listed
    # merchant): the whole ?npcitemlist global moves to its own section (zone/tools/mk_npcitemlist_cap.py).
    ('npcitemlist-cap', []),
    # NOT a recipe: the disconnect a same-zone link onto an unmarkable spot causes (error 1669) cannot be skipped -
    # so_Unmark has already run and the exe never re-marks, so the player ends up in limbo (tried 2026-09-23,
    # withdrawn). The quest_gate plugin pre-checks a GM &linkto destination instead.
]

# Character.exe (--target character): the same loader, and bag 18 in NC_CHAR_GET_ITEMLIST_BY_TYPE_REQ. Both are
# experimental in the same sense as above: built and verified, not yet booted.
CHARACTER_CHAIN = [
    ('dll-loader-character', []),
    # bag 18 through the char_void plugin's packer; inert (answers 0x1202 as before) without the plugin
    ('char-itemlist-void', []),
    # Creation accepts the 2026 starter grade (1) instead of 2016's (0) - the stack uses the 2026 HairInfo /
    # HairColorInfo / FaceInfo, which have no grade 0, so every 2026-client creation failed with 0x183.
    ('creation-grade-2026', []),
    # Beauty coupons: HairShop06 (2026 'Extravagant', grade-6 styles) becomes the top tier - the per-tier array
    # widens 6 -> 7 so it does not collide with the gender-change slot - and HairShop00_TD counts as Basic.
    ('beauty-coupon-tier6', []),
    # Titles past type 127 load and save (2026 has 150); the zone half is the title_ext plugin.
    ('character-title-types', []),
]

# WorldManager.exe (--target worldmanager): the world-wide instance-dungeon cap. Built and statically verified,
# not yet run by a WM process - the stack uses 17 of the stock 32 rows, so it is not needed until the 2026
# instance maps land (Fiesta2026on2016 tickets.md, "HOST THE 56 NON-FIELD 2026 MAPS").
WORLDMANAGER_CHAIN = [
    ('indun-map-list-cap', []),
    # 0x107D carries 7 coupon pairs (2026 client); pairs with character's beauty-coupon-tier6. DEPLOYED 2026-09-23 on
    # its own (stock + this) - indun-map-list-cap has still never been booted.
    ('beauty-coupon-list-7', []),
]

# The chain as it was before handle-layout-2026, for reproducing build/Zone.maps.npc.dmg.exe exactly.
LEGACY = {'npc-object-pool-cap': []}


def recipe_path(target, recipe):
    return os.path.join(HERE, target, 'recipes', recipe + '.json')


def apply(target, recipe, sets, src, dst, first):
    cmd = [sys.executable, os.path.join(HERE, 'apply.py'), recipe_path(target, recipe),
           '--exe', src, '--out', dst]
    if not first:
        cmd.append('--allow-hash-mismatch')
    for s in sets:
        cmd += ['--set', s]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit('%s FAILED:\n%s%s' % (recipe, r.stdout, r.stderr))


def verify(target, recipe, sets, stock, built):
    # --verify checks the patched values at every site; the input only supplies the layout reference
    cmd = [sys.executable, os.path.join(HERE, 'apply.py'), recipe_path(target, recipe),
           '--exe', stock, '--verify', built, '--allow-hash-mismatch']
    for s in sets:
        cmd += ['--set', s]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip().splitlines()[-1:] or ['']


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--target', choices=('zone', 'character', 'worldmanager'), default='zone')
    ap.add_argument('--exe', required=True, help='the STOCK Zone.exe (or Character.exe / WorldManager.exe); opened read-only')
    ap.add_argument('--out', required=True)
    ap.add_argument('--upto', help='stop after this recipe')
    ap.add_argument('--experimental', action='store_true', help='also apply the recipes that have not been booted yet')
    ap.add_argument('--legacy', action='store_true', help='NPC handles at the old 0xA000 (reproduces older builds)')
    a = ap.parse_args()

    chain = []
    for name, sets in {'character': CHARACTER_CHAIN, 'worldmanager': WORLDMANAGER_CHAIN}.get(a.target, CHAIN):
        chain.append((name, LEGACY.get(name, sets) if a.legacy else sets))
        if name == a.upto:
            break
    if a.legacy and not a.upto:
        chain = [c for c in chain if c[0] != 'handle-layout-2026']
    if a.experimental and not a.upto and not a.legacy and a.target == 'zone':
        chain += EXPERIMENTAL

    work = tempfile.mkdtemp(prefix='zonebuild-')
    try:
        cur = a.exe
        for i, (name, sets) in enumerate(chain):
            nxt = os.path.join(work, '%02d-%s.exe' % (i, name))
            apply(a.target, name, sets, cur, nxt, first=(i == 0))
            print('  applied  %-30s %s' % (name, ' '.join(sets)))
            cur = nxt
        # Each recipe is verified against its own input, not the stock exe: sections added earlier move the
        # addresses a later recipe's @newbase resolves to.
        prev = a.exe
        bad = 0
        for i, (name, sets) in enumerate(chain):
            ok, tail = verify(a.target, name, sets, prev if i == 0 else os.path.join(work, '%02d-%s.exe' % (i - 1, chain[i - 1][0])), cur)
            print('  verify   %-30s %s' % (name, 'ok' if ok else 'FAILED: ' + tail[0]))
            bad += not ok
        if bad:
            raise SystemExit('%d recipe(s) do not hold on the result; nothing written' % bad)
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        shutil.copyfile(cur, a.out)
        print('wrote %s' % a.out)
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    main()
