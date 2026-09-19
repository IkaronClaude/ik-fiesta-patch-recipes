# client/ - the game client

Client patches use the same runner: `apply.py` does not care which executable it is pointed at. How recipes work
is in the [root README](../README.md).

## `client-2026-npc-dialog-self-close` — the first CLIENT recipe: let the 2026 quest dialog close itself

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
python apply.py client/recipes/client-2026-npc-dialog-self-close.json --exe <client>/Fiesta.exe --out build/client2026/Fiesta.exe
# on a copy that already carries other byte patches the file hash differs; the per-site expect checks still hold:
python apply.py client/recipes/client-2026-npc-dialog-self-close.json --exe <patched>/Fiesta.exe --out build/client2026/Fiesta.exe --allow-hash-mismatch
```

It does **not** remove the close-and-reopen between pages: that is native 2016 behaviour. Keeping the
window up between pages needs the server to say which page is the last one. The no-client-patch
alternative is fiesta-proxy's Bridge2026, which sends the `0x442E` itself; run it with `-NoDialogClose`
when testing this recipe so it is the patch being tested and not the bridge. **Untested live as of
2026-09-17.**

