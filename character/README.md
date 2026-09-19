# character/ - Character.exe (the Character DB server)

Everything that patches or extends **Character.exe**, the server that reads and writes characters and their
items for the zones. How recipes and hooks work in general is in the [root README](../README.md).

```
recipes/     dll-loader-character, char-itemlist-void   (chain: ../build.py --target character)
plugins/     char_void/ - Character's half of the Void Inventory, and the 192-item inventory load
include/     charhook.h (handlers), dbhook.h (the worker's DB connection), character_symbols.h (generated)
tools/       mk_char_symbols.py (symbols without a PDB), mk_char_itemlist_void.py (recipe generator)
```

```bash
python build.py --target character --exe Z:/ServerSource/Character/Character.exe --out build/Character.hooked.exe
common\build_plugin.bat character char_void           # -> build\plugins\char_void.dll
```

Deploy: `Character.hooked.exe` as `Character\Character.exe`, `build\fiestahook.dll` beside it,
`char_void.dll` in `Character\hooks\`. Its log is `fiestahook.log` beside the exe.

## No PDB - where the symbols come from

There is no `Character.pdb`. `tools/mk_char_symbols.py` builds `character_symbols.h` four ways, and leaves out
anything it cannot establish rather than guess:

1. **Handlers by their log strings.** Every `CPFsCharacter::fc_NC_*` handler writes its own name into its error
   log; the handler is the function that pushes that string.
2. **Handlers by the reply they build.** A handler that logs no name still answers with its `_ACK`
   (`push <ack opcode>`); when exactly one handler-shaped function builds an `_ACK`, it is the `_REQ`'s handler
   (+67 handlers). A function two `_ACK`s claim is left unnamed.
3. **Framework functions from Account.pdb.** Account, AccountLog and Character share one DB-bridge framework,
   so `DBRecord::query` and friends are found by their Account.exe bytes (addresses masked), and typed from their
   mangled names with `undname`: `chr::fn::DBRecord_query()`.
4. **Functions found by reading the disassembly** (`KNOWN` in the tool): kept only if the exe has the bytes
   they were found with, and emitted with those bytes so a plugin can check the exe it is actually loaded into
   with `chr::verify_known()`.

## Recipes

- `dll-loader-character` - the same `fiestahook.dll` import as the zone's `dll-loader`; plugins load from
  `Character\hooks\`, so a zone plugin never ends up in Character.
- `char-itemlist-void` - `NC_CHAR_GET_ITEMLIST_BY_TYPE_REQ`'s bag switch widened to 18, case 18 handed to the
  plugin through a `.charvoid` slot; the two list readers accept type 18 (`p_Item_GetListType` is generic).
  Without the plugin Character answers 18 with the `0x1202` it always did.

## Plugin: `char_void`

- **Bag 18.** Fills the `.charvoid` slot with a packer for bag 18 (288 items), so the zone's request for the
  Void Inventory is answered.
- **The inventory, 144 -> 192.** Stock Character reads at most 144 inventory items into a stack buffer sized
  for exactly that - items past it "disappeared" on relog while staying in `tItem`. The plugin replaces the
  inventory packer with one that reads 192 into a heap buffer and packs it with the stock packer.
  NOT changed: the style-change path (`fc_NC_CHAR_SET_STYLE_DB_REQ`) still reads 144.

Proven live 2026-09-19: 152 inventory items and 3 void items loaded for one character.
