// menu_escape - Escape on a server menu cancels it, whatever the menu holds (Fiesta2026on2016, operator 2026-10-07:
// "Pressing Escape on a 3 option window always picks the 3rd option, normally cancel, but for our instance windows, it
// means we enter" - "Fix client side").
//
// ---- what the stock client does (2016 Fiesta.pdb names, the 2026 code is the same) -------------------------------------
// ServerMenuWin (NC_MENU_SERVERMENU_REQ) shows at most 3 options (SetServerMenu clamps the count, 2026 10.6.6 0x69D59B)
// and keeps each button's reply byte at a slot that depends on the layout:
//     1 option:  [+0x180]                2 options: [+0x181] [+0x182]          3 options: [+0x184] [+0x180] [+0x183]
// OnBut0..OnBut4 send [+0x180..+0x184] (NC_MENU_SERVERMENU_ACK) and close. Escape - the frame's window-close path - and a
// higher-priority window replacing the menu both call OnBut2 (2016: CancelServerMenuWin = jmp OnBut2): right for the
// 2-option yes / no menu (its 2nd = No), but on a 3-option menu [+0x182] is whatever an EARLIER menu left there. Our
// instance gate menu ([raid, Instance, Instance Hard, Cancel] - its Cancel is past the 3 shown) then entered an instance.
// ---- the zone ------------------------------------------------------------------------------------------------------------
// sp_NC_MENU_SERVERMENU_ACK -> 0x50FD40: a reply >= 10 is "no such item" - logged, the menu cleared, nothing run; the same
// clear as its own cancel path.
// ---- this plugin ---------------------------------------------------------------------------------------------------------
// Both OnBut2 calls go through a stub that writes reply 0xFF into [+0x182] first: Escape (or a replacing window) always
// answers "none of these", the zone closes the menu and runs nothing. A click on a button is unchanged.
#include <hook_core.h>
#include <client_addrs.h>

#include <windows.h>

#include <cstring>

namespace {

const unsigned char kOnBut2Stock[10] = {0x56, 0x8B, 0xF1, 0x0F, 0xB6, 0x86, 0x82, 0x01, 0x00, 0x00};   // movzx eax, [esi+0x182]
unsigned g_onbut2 = 0;

void __declspec(naked) cancel_menu() {
    __asm {
        mov  byte ptr [ecx + 0x182], 0xFF
        jmp  dword ptr [g_onbut2]
    }
}

// a call site: E8 rel32 to OnBut2 -> E8 rel32 to cancel_menu
bool redirect(const char* what, caddr::Sym site) {
    unsigned char* p = (unsigned char*)hook::rebase(caddr::va(site));
    if (p[0] != 0xE8 || (unsigned)(p + 5 + *(int*)(p + 1)) != g_onbut2) {
        hook::log("menu_escape: %s is not a call to ServerMenuWin::OnBut2 - left stock", what);
        return false;
    }
    unsigned char call[5] = {0xE8, 0, 0, 0, 0};
    *(int*)(call + 1) = (int)((unsigned char*)cancel_menu - (p + 5));
    return hook::write_code(p, call, sizeof call);
}

}  // namespace

HOOK_PLUGIN("menu_escape") {
    if (const char* m = caddr::missing({caddr::kServerMenuOnBut2, caddr::kServerMenuEscCall, caddr::kServerMenuPriorityCall})) {
        hook::log("menu_escape: %s - not hooked", m);
        return;
    }
    unsigned char* onbut2 = (unsigned char*)hook::rebase(caddr::va(caddr::kServerMenuOnBut2));
    if (std::memcmp(onbut2, kOnBut2Stock, sizeof kOnBut2Stock) != 0) {
        hook::log("menu_escape: ServerMenuWin::OnBut2 does not read [this+0x182] - not hooked");
        return;
    }
    g_onbut2 = (unsigned)onbut2;
    bool esc = redirect("the Escape call", caddr::kServerMenuEscCall);
    bool pri = redirect("the replacing-window call", caddr::kServerMenuPriorityCall);
    hook::log("menu_escape: Escape on a server menu %s; a replacing window %s", esc ? "cancels it (reply 0xFF)" : "is STOCK",
              pri ? "cancels it too" : "is stock");
}
