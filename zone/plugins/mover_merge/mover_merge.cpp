// mover_merge - mount merging (upgrading) works for mounts that need NO feeding and are NOT timed
// (Fiesta2026on2016 QoL, operator 2026-09-27: "Remove ALL LifeDust feeding requirements ... and patch the check to
// only work for mounts that require NO FEEDING and are NOT TIMED").
//
// ---- THE STOCK CHECK (read from Zone.exe) ----------------------------------------------------------------
//
//   ShinePlayer::sp_NC_ITEM_MOVER_UPGRADE_REQ(NETCOMMAND*, int, u16)   0x51C850, request {main slot, sub slot}
//     for the main and the sub mount alike: the item must be class 23, then
//       a Mover mount (MoverDataBox by item InxName):  idb_2itemid(MoverHG.FeedType) == [0x14D504D0]
//                                                      and MoverMain.DurationHour (+0x30) == 0
//       a Riding mount (ChargedItemEffect RIDING):     idb_2itemid(feed item, +0x84) == [0x14D504D0]
//                                                      and UseTime (+0x82) == 0
//     else NC_ITEM_MOVER_UPGRADE_ACK err 0x322A ("These mounts cannot be merged").
//   [0x14D504D0] is the LifeDust item (2529, "LifeDust Ration", read from a live zone): 2016 made the mounts that eat
//   LifeDust the upgradeable ones. 2026 removed feeding - every MoverHG.FeedType is '-' - and moved upgradeability to
//   MoverMain.UpgradeType, which the 2016 zone does not have, so every merge was refused.
//
// ---- THIS PLUGIN -----------------------------------------------------------------------------------------
//
// The four feed comparisons (main / sub x Mover / Riding) compare with 0xFFFF instead - what idb_2itemid (0x418FF0)
// answers for a name that is no item, i.e. FeedType '-': "needs no feeding". The not-timed checks right after each
// are the stock ones and stay. The 2026 client offers only UpgradeType-1 mounts in its merge window.
//     66 3B 05 D0 04 D5 14   cmp ax, word ptr [0x14D504D0]
//  -> 66 3D FF FF 0F 1F 00   cmp ax, 0xFFFF ; nop
//
// Gameplay, not parity: active only when the server data carries the flag the QoL layer ships
// (Fiesta2026on2016 migrations-qol/overrides/server/Shine/MoverMergeNoFeed.flag).
#include <zonehook.h>

#include <cstring>

namespace {

const char* kFlag = "../9Data/Shine/MoverMergeNoFeed.flag";
const unsigned kSites[] = {0x0051CEFCu, 0x0051D004u, 0x0051D06Bu, 0x0051D368u};   // riding main, mover main, riding sub, mover sub
const unsigned char kStock[7] = {0x66, 0x3B, 0x05, 0xD0, 0x04, 0xD5, 0x14};
const unsigned char kNoFeed[7] = {0x66, 0x3D, 0xFF, 0xFF, 0x0F, 0x1F, 0x00};

}  // namespace

ZONEHOOK_PLUGIN("mover_merge") {
    if (GetFileAttributesA(kFlag) == INVALID_FILE_ATTRIBUTES) {
        zone::log("mover_merge: no %s - only LifeDust-fed mounts merge (stock)", kFlag);
        return;
    }
    int done = 0;
    for (unsigned va : kSites) {
        unsigned char* p = (unsigned char*)zone::rebase(va);
        if (std::memcmp(p, kStock, sizeof kStock) != 0) {
            zone::log("mover_merge: unexpected bytes at 0x%X - that feed check is NOT patched", va);
            continue;
        }
        if (hook::write_code(p, kNoFeed, sizeof kNoFeed)) ++done;
    }
    zone::log("mover_merge: %s present - %d/4 feed checks now accept 'no feeding' ('-') instead of LifeDust; "
              "timed mounts still refused (stock)", kFlag, done);
}
