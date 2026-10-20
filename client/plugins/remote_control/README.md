# remote_control - drive the official client from a script

Lets a test harness log the 2026 client in, press keys / click, and take screenshots at set times, so a reimplementation
(fiesta-godot) can be compared frame for frame against the real client. The driver is
`fiesta-godot/tools/remote_client.py`.

Build: `common\build_plugin.bat client remote_control`; deploy `build\plugins\remote_control.dll` into the client's
`hooks\` folder.

## Launch arguments

| argument | effect |
|---|---|
| `-i <ip> -p <port>` | the client's own: the login server (the bridge's 10.6.6 login port, e.g. `127.0.0.1 19010`) |
| `-stdinlogin` | read `<user>\n<password>\n` from stdin at load; typed into the login form the moment its edit field has the focus, then wiped. The password never sits on a command line. |
| `-world <index>` | join the server list's entry `<index>` (display order). Without it, a list of exactly one world is joined. |
| `-char <slot>` | select character slot `<slot>` at char select and enter with it |
| `-charname <name>` | the same, by name: the slot comes from the character list packet (NC_USER_LOGINWORLD_ACK 0x0C0F, caught with `clienthook.h`) |

`python tools/remote_client.py launch --user botgate [--world 0] [--char 0 | --charname StyleTest]` does all of this (password from
`FIESTA_PASS` or a prompt, piped).

## hooks\remote_control.ini

```ini
[config]
port=27015            ; TCP control port
bind=127.0.0.1
remap=172.31.248.91>127.0.0.1   ; connect() to the first address goes to the second (same port)
```

`remap` is for a client on the bridge's own machine: the bridge hands out its advertised LAN address, which that
machine may not reach.

## Control protocol (one line per command, one line per reply)

`ping`, `size`, `stats`, `key <vk> [press|down|up]`, `text <string>`, `move|click|down|up <x> <y> [left|right]`,
`wheel <x> <y> <delta>`, `shot <path.bmp>`, `peek <va> [len]` (2026 VA, rebased; `*<addr>` for an absolute one).

## How it works

- **Screenshots:** `Direct3DCreate9` is detoured to reach `IDirect3DDevice9::Present` / `IDirect3DSwapChain9::Present`
  (code-detoured: a vtable swap only caught a handful of calls); the back buffer is saved on the next present.
  Works with the window behind others. Fallbacks: PrintWindow on a worker thread, then a screen BitBlt.
- **Input:** the game reads DirectInput8, not window messages (only its PgEditWin edit controls take `WM_CHAR`).
  `DirectInput8Create` (IAT) -> `CreateDevice` (vtable) -> `GetDeviceState` / `GetDeviceData` (code detours) merge the
  injected keys / buttons and queue per-device events; `GetCursorPos` / `GetAsyncKeyState` (IAT) answer the injected
  cursor. Each injected move also reports its relative motion.
  - The game creates two keyboards and two mice and polls both mice: every device gets its own event queue.
  - With the window in the background the devices are never acquired and every read fails `DIERR_NOTACQUIRED` -
    including the per-frame flush - and NiInputMouse then drops its button state: the press counter
    (PgWin 0xD1C7B4, 2016 `ms_kbLbutPressed`) never rose and the char-select pick never ran. Once remote input is in
    use an unacquired device reads as a healthy, empty one.
- **Auto world / char** call the client's own functions on the game thread. Every address comes from the registry
  (`client/addresses`, `caddr::k*`; the VAs below are 10.6.6's), rebased (the exe is ASLR-relocated); a build that lacks
  one turns auto select off:
  - `WorldSelectWin::UpdateServerBtnState(btn)` 0x55DF30 (page `+0x158`, selected world number `+0x15C`; world count
    0xC32584, list 0xC32588 - 18-byte entries, number at +0x10) then `OnCmdOk(1)` 0x55E120 -> `WorldSelectOk` 0x5573D0
    -> `NcUserWorldSelectReq` 0x554DA0 (0x0C0A). The window object is captured by naked stubs on its own virtuals
    (0x55C340, 0x55E4B0, 0x55CA80, 0x55CC00, 0x55E020) and acted on from Present.
  - `CharSelectFrameWork::ProcessInput` 0x4746A0 (2016 0x411F20) is the tick; `SelectAvatar(page slot)` 0x473A60 (page
    `+0x134`, 6 per page). A second call on the selected slot is the second click that enters (its `bl == dl` branch).
    The pick maps the hit node's name `Avatar0`..`Avatar6` to the slot.

- **`-charname`:** each avatar record of 0x0C0F starts like the 2016 PDB's `PROTO_AVATARINFORMATION` (chrregnum +0, name
  +4, level +0x18, slot +0x1A) but is 161 bytes on the 2026 wire (130 in 2016) - read from a capture, the rest of the
  2026 record is not traced. The list is logged (`avatar list: slot N name level L`).

## Not done

- `-char` on a later page (only the shown page is selectable).
