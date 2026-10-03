// enhance_no_warning - the 2026 client's "Protection stones have not been added. Proceed anyway?" confirm is skipped
// where enhancing cannot fail (Fiesta2026on2016 Rebalanced; operator 2026-09-27 P3).
//
// ---- THE CLIENT CODE (2026 US Fiesta.exe, found 2026-09-27) ------------------------------------------------------------
//   Enhance = ItemUpgradeWin command 12 (win_msg_probe: "deliver ItemUpgradeWin msg 5 wParam 12"; OnCommand = vtable
//   0xB25F7C slot 97 = 0x646D10, jump table 0x646EE8 -> 0x646EAD -> 0x646500). After its checks 0x646500 stores the
//   chosen stones (this+0x2D8..0x2E0) and branches on this+0x2E8 ("needs the warning", set at 0x6449E0):
//       0x646A07  cmp byte ptr [edi+0x2e8], 0
//       0x646A41  jne 0x646a51     ; set:   PgWinMgr::ShowWin(this+0x2E4) = ItemUpgradeMsgWin, the warning
//       0x646A43  call 0x647d60    ; clear: send the enhance request (0x647D60 -> 0x59AD80 -> C->S 0x3017)
//   The warning's Yes (ItemUpgradeMsgWin command 0) ends in the same request - so going straight on is exactly
//   "the player clicked Yes".
//
// ---- THIS PLUGIN -------------------------------------------------------------------------------------------------------
//   The jne (75 0E) becomes two NOPs: Enhance always sends. Only the Rebalanced client (enhancing always succeeds
//   there, server EnchantAlwaysSucceeds.flag): active only when hooks\enhance_no_warning.ini says [plugin] enabled=1 - the Rebalanced
//   layer ships it (migrations-rebalance/0023-enhance-no-warning.py).
#include <hook_core.h>
#include <client_addrs.h>

#include <cstring>

namespace {

const unsigned kVaWarnJump = caddr::va(caddr::kEnhanceWarnJump);
const unsigned char kStock[2] = {0x75, 0x0E};      // jne 0x646a51
const unsigned char kGoOn[2] = {0x90, 0x90};

}  // namespace

HOOK_PLUGIN("enhance_no_warning") {
    if (const char* m = caddr::missing({caddr::kEnhanceWarnJump})) {
        hook::log("enhance_no_warning: %s - not hooked", m);
        return;
    }
    if (!hook::ini_opted_in()) {
        hook::log("enhance_no_warning.ini does not say enabled=1 - the protection-stone warning stays (stock)");
        return;
    }
    unsigned char* p = (unsigned char*)hook::rebase(kVaWarnJump);
    if (std::memcmp(p, kStock, sizeof kStock) != 0) {
        hook::log("unexpected bytes at EnhanceWarnJump 0x%X (%02X %02X) - NOT patched", kVaWarnJump, p[0], p[1]);
        return;
    }
    if (hook::write_code(p, kGoOn, sizeof kGoOn))
        hook::log("enhance_no_warning.ini: enabled - Enhance no longer asks about protection stones");
}
