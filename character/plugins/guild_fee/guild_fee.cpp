// guild_fee - the cen a guild costs to found, from hooks\guild_fee.ini (operator 2026-09-29 P4: "Guild creation should cost 50
// gold instead of 1 (50M cen)").
//
// ---- THE STOCK CODE (Character.exe, no PDB; read 2026-09-29) --------------------------------------------------------------
//   The WM forwards NC_GUILD_MAKE_REQ to Character as PROTO_NC_GUILD_DB_MAKE_REQ {hWMChar, nCharNo, sCharID, Make} - no fee
//   in it. Character fills the p_Guild_Make2 call itself (string 0x4BF6EC, caller 0x453860):
//     0x438597  mov word [ebp-0x286], 0x64        MaxMembers 100
//     0x43859E  mov dword [ebp-0x27C], 0xF4240    MakerPay low dword  = 1,000,000 cen (1 gold)
//     0x4385A8  mov dword [ebp-0x278], ebx        MakerPay high dword = 0
//     0x4385AE  mov dword [ebp-0x274], 0xFFFF     MakerNeedItemID none
//   p_Guild_Make2 takes @nMakerPay with p_Char_MoneySub (error -4 "not enough maker money").
//
// ---- THIS PLUGIN ------------------------------------------------------------------------------------------------------------
//   [config] fee=<cen> replaces the immediate (up to 2^31-1). No ini, or fee=0, = the stock 1 gold. Avocado ships fee=50000000.
#include <charhook.h>

#include <cstring>

namespace {

const unsigned kVaFee = 0x0043859Eu;
const unsigned char kSite[] = {0xC7, 0x85, 0x84, 0xFD, 0xFF, 0xFF, 0x40, 0x42, 0x0F, 0x00, 0x89, 0x9D, 0x88, 0xFD, 0xFF, 0xFF};

}  // namespace

HOOK_PLUGIN("guild_fee") {
    const int fee = hook::config_int("fee", 0);
    if (fee <= 0) {
        hook::log("guild_fee: no fee configured - guilds cost the stock 1,000,000 cen");
        return;
    }
    unsigned char* site = (unsigned char*)hook::rebase(kVaFee, chr::kImageBase);
    if (std::memcmp(site, kSite, sizeof kSite)) {
        hook::log("guild_fee: the guild-make call at 0x43859E is not the expected code - stock fee");
        return;
    }
    const unsigned v = (unsigned)fee;
    if (hook::write_code(site + 6, &v, 4))
        hook::log("guild_fee: founding a guild costs %u cen (stock 1,000,000)", v);
}
