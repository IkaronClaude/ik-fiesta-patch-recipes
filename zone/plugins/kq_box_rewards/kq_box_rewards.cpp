// kq_box_rewards - a Kingdom Quest reward box made OUTSIDE a KQ (bought from an NPC, &makeitem) holds what the KQ
// itself would put in it, with the KQ's own odds (Fiesta2026on2016, operator 2026-09-27 P2: "Ensure KQ boxes purchased
// from NPC can roll randomly" - chosen: "Exact KQ odds (plugin)").
//
// ---- THE STOCK CODE (read from Zone.exe) ------------------------------------------------------------------------------
//   KQ end, ShinePlayer::sp_KQReward(KINGDOM_QUEST_REW*) (0x52DA70): TreasureChestMaker(box, 7, ..); then for each of
//   the row's 15 rewards  if (well512_GetRandom(1000) < RewardRate[i])  ShineReward = RewardData::rd_FindHandle(
//   Reward[i]); type 1 (item) -> tcm_ItemMake(7, reward, sp_GetItemWhoEquip_ClassGroup()) (0x595D00, which also
//   rolls the item's random options); types 2/3 (exp / money) are paid to the player, not put in the box. Then
//   tcm_PutInto puts the filled chest in the inventory.
//   Every other maker of a chest item (class 15) - the cen shop ItemInventory::ii_BuyAll and &makeitem
//   (sp_CreateItemByAdmin) - goes through ShinePlayer::sp_MagicContainerMake (0x49C050): TreasureChestMaker(box, 6,
//   0); tcm_GetItemNum (0x5956B0, 0 = not a chest) at 0x49C11D; then the box's TreasureReward.txt `Container` row
//   (or_SelectFrom 0x648310 at 0x49C163): MinLot..MaxLot weighted picks from `Content`, each tcm_ItemMake(ITI*);
//   then the same tcm_PutInto. A KQ box has no Container row, so this fails (assert "no container") and the shop
//   refuses the buy (0x340A) / &makeitem makes nothing.
//
// ---- THIS PLUGIN -------------------------------------------------------------------------------------------------------
//   Detours sp_MagicContainerMake to note which box is being made. When it is a KQ box (named in a KingdomQuestRew
//   row's KQBoxItemIDX - the zone's own table, kqreward 0x0D67A058):
//     - tcm_GetItemNum, when called from sp_MagicContainerMake (return 0x49C122) and nonzero, then fills the chest with
//       sp_KQReward's rolls, item rewards only (the exp / money of a KQ is a KQ-end payment, no box holds it);
//     - or_SelectFrom, when called for the Container row (return 0x49C168), answers an empty row (Min/MaxLot 0) so
//       the stock loop adds nothing and the stock code puts the chest in the inventory as usual.
//   Any other box, or a KQ box made by sp_KQReward itself, is untouched. The creation type passed to tcm_ItemMake is
//   the container path's 6 (the chest maker was built with 6), not the KQ's 7.
//
// Gameplay, not parity: active only when 9Data/Shine/KQBoxRewards.flag exists (a variant writes it).
#include <zonehook.h>
#include <zone_functions.h>
#include <zone_globals.h>

#include <intrin.h>

#include <cstdio>
#include <cstring>

namespace {

const char* kFlag = "../9Data/Shine/KQBoxRewards.flag";
const unsigned kVaMagicContainerMake = 0x0049C050u;
const unsigned kVaGetItemNum = 0x005956B0u;
const unsigned kVaSelectFrom = 0x00648310u;
const unsigned kVaGetItemNumReturn = 0x0049C122u;   // sp_MagicContainerMake, after `call tcm_GetItemNum`
const unsigned kVaContainerRowReturn = 0x0049C168u; // sp_MagicContainerMake, after the Container or_SelectFrom
const unsigned kVaWell512 = 0x150BA418u;            // mov ecx, 0x150ba418 at every well512_GetRandom call
const unsigned kItemNumOffset = 0x3E8;              // tcm_GetItemNum: mov eax, [ecx+0x3e8]
const unsigned char kRewardItem = 1;                // ShineReward.RewardType (sp_KQReward jump table 0x52E348)
const int kMakeType = 6;                            // the container path's creation type

zone::Detour g_make, g_num, g_select;
const zone::types::KINGDOM_QUEST_REW* g_row = nullptr;   // the KQ box being made right now, if any
void* g_player = nullptr;
bool g_filled = false;
unsigned char g_emptyContainer[64] = {};                 // a Container row with MinLot 0, MaxLot 0
unsigned g_boxes = 0;

const zone::types::KINGDOM_QUEST_REW* kq_row(const char* inx) {
    auto* box = zone::global::kqreward();
    int n = *(int*)(*(char**)((char*)box + 0x34) + 0x28);   // KQRewardDataBox::operator[] (0x49A950): the row count
    for (int i = 0; i < n; ++i) {
        auto* r = (const zone::types::KINGDOM_QUEST_REW*)zone::fn::CDataReader__GetRecord()(box, nullptr, i);
        if (r && !std::strncmp(r->KQBoxItemIDX, inx, sizeof r->KQBoxItemIDX)) return r;
    }
    return nullptr;
}

unsigned char __fastcall make(void* player, void*, zone::types::ItemTotalInformation* iti, unsigned long long a) {
    g_row = nullptr;
    g_filled = false;
    if (iti) {
        unsigned short item = *(unsigned short*)((char*)iti + 8);
        auto* idx = zone::fn::ItemDataBox__operator__()(zone::global::itemdatabox(), nullptr, item);
        if (idx && idx->data) g_row = kq_row(idx->data->InxName);
    }
    g_player = player;
    auto r = ((unsigned char(__fastcall*)(void*, void*, zone::types::ItemTotalInformation*, unsigned long long))
                  g_make.trampoline)(player, nullptr, iti, a);
    if (g_row && !g_filled) zone::log("kq_box_rewards: %s - not a chest here, nothing rolled", g_row->KQBoxItemIDX);
    g_row = nullptr;
    return r;
}

void fill(void* tcm) {
    const auto* row = g_row;
    unsigned long group = zone::fn::ShineObjectClass__ShinePlayer__sp_GetItemWhoEquip_ClassGroup()(g_player, nullptr);
    char won[160] = "";
    int made = 0;
    for (int i = 0; i < 15; ++i) {
        if (!row->Reward[i] || !row->RewardRate[i]) continue;
        unsigned roll = zone::fn::cWell512Random__well512_GetRandom_3()(zone::rebase(kVaWell512), nullptr, 1000) & 0xFFFF;
        if (roll >= row->RewardRate[i]) continue;
        auto* reward = zone::fn::RewardData__rd_FindHandle()(zone::global::rewarddata(), nullptr, row->Reward[i]);
        if (!reward) {
            zone::log("kq_box_rewards: %s reward %u - no ShineReward row", row->KQBoxItemIDX, row->Reward[i]);
            continue;
        }
        if (reward->RewardType != kRewardItem) continue;   // exp / money: paid at KQ end, not boxed
        zone::fn::TreasureChestMaker__tcm_ItemMake_2()(tcm, nullptr, kMakeType, reward, group);
        ++made;
        size_t len = std::strlen(won);
        if (len + 40 < sizeof won) std::snprintf(won + len, sizeof won - len, "%s%.32s", len ? ", " : "", reward->Argument);
    }
    g_filled = true;
    if (++g_boxes <= 50 || g_boxes % 100 == 0)
        zone::log("kq_box_rewards: %s made - %d item reward(s) won: %s (%u boxes so far)", row->KQBoxItemIDX, made,
                  made ? won : "none", g_boxes);
}

int __fastcall item_num(void* tcm, void*) {
    int n = *(int*)((char*)tcm + kItemNumOffset);
    if (g_row && !g_filled && n && (unsigned)_ReturnAddress() == (unsigned)zone::rebase(kVaGetItemNumReturn)) fill(tcm);
    return n;
}

void* __fastcall select_from(void* reader, void*, zone::types::ORToken table, char* column, int value, int a4) {
    if (g_row && g_filled && (unsigned)_ReturnAddress() == (unsigned)zone::rebase(kVaContainerRowReturn))
        return g_emptyContainer;
    return ((void*(__fastcall*)(void*, void*, zone::types::ORToken, char*, int, int))g_select.trampoline)(
        reader, nullptr, table, column, value, a4);
}

}  // namespace

ZONEHOOK_PLUGIN("kq_box_rewards") {
    if (GetFileAttributesA(kFlag) == INVALID_FILE_ATTRIBUTES) {
        zone::log("kq_box_rewards: no %s - a KQ box made outside a KQ stays empty (stock)", kFlag);
        return;
    }
    zone::hook_function("ShinePlayer::sp_MagicContainerMake 0x49C050 (note the box being made)",
                        zone::rebase(kVaMagicContainerMake), (void*)make, &g_make);
    zone::hook_function("TreasureChestMaker::tcm_GetItemNum 0x5956B0 (fill a KQ box with the KQ's rolls)",
                        zone::rebase(kVaGetItemNum), (void*)item_num, &g_num);
    zone::hook_function("OptionReader::or_SelectFrom 0x648310 (a KQ box has no Container row: answer an empty one)",
                        zone::rebase(kVaSelectFrom), (void*)select_from, &g_select);
    zone::log("kq_box_rewards: %s - KQ boxes bought / made hold the KQ's rewards, rolled with its odds", kFlag);
}
