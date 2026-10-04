// bridge26_items.h - inventory records 2016 -> 2026 (batch 6), the proxy's ItemAttr (fiesta-proxy
// plugins/Bridge2026/ItemAttributes.cs) byte for byte - see that file for where every width comes from.
//
// A record is  datasize u8 | location u16 | itemid u16 | attributes. The 2026 client ignores datasize and sizes the
// attribute block from the item's CLASS (Fiesta.exe 0x79D410), so a 2016 record must be rewritten to the 2026 width or the
// rest of the box is walked at the wrong stride. The class comes from g_class_of (the plugin: the 2026 ItemInfo it reads
// natively; the vector tool: a list on stdin).
#pragma once
#include <cstring>

namespace bridge26 {

inline int (*g_class_of)(int item) = 0;           // 2026 attribute class of an item id, -1 = unknown

inline int class_of(int item) { return g_class_of ? g_class_of(item) : -1; }

const int kRecordHead = 5;                         // datasize, location, item id
const int kClass39 = 39, kClass39Width = 16;       // 2026 tickets / keys: our zone loads them as class 0 (1 lot byte)

inline int constant_width(int cls) {
    static const int w[40] = {
        1, 2, 4, 2, -1, -1, -1, -1, -1, 36, 8, 1, 1, -1, 1, -1,
        1, -1, 4, 1, 1, 2, 1, 19, 4, 1, 4, 4, 1, 12, 9, 5,
        -1, 1, 1, 2, 26, 4, -1, 16,
    };
    return cls >= 0 && cls < 40 ? w[cls] : -1;
}
// classes whose 2026 width is Fixed + (count >> 1) * 3 with the count byte last in the fixed part; 2016 is one byte shorter
inline int enchantable_fixed(int cls) {
    switch (cls) { case 4: return 39; case 5: return 66; case 6: case 7: case 8: case 38: return 14; default: return -1; }
}
inline int insert_at_2016(int cls, int fixed2016) { return cls == 4 ? 8 : fixed2016 - 1; }   // amulet: inside 0..8

inline int width2026(int cls, const unsigned char* a, int n) {
    int fx = enchantable_fixed(cls);
    if (fx > 0) return n < fx ? -1 : fx + (a[fx - 1] >> 1) * 3;
    if (cls == 13) return n < 1 ? -1 : 1 + a[0] * 10;
    if (cls == 15) return n < 1 ? -1 : 1 + (a[0] & 0xf) * 8;
    return constant_width(cls);
}
inline int width2016(int cls, const unsigned char* a, int n) {
    int fx = enchantable_fixed(cls);
    if (fx > 0) { int f16 = fx - 1; return n < f16 ? -1 : f16 + (a[f16 - 1] >> 1) * 3; }
    return width2026(cls, a, n);
}

// one 2016 record at r (len bytes, datasize included) -> o; returns the 2026 length, -1 = refuse (relay the original)
inline int record(const unsigned char* r, int len, unsigned char* o) {
    if (len < kRecordHead) return -1;
    int item = r[3] | (r[4] << 8), attr = len - kRecordHead;
    if (item == 0xFFFF) { if (attr) return -1; memcpy(o, r, len); return len; }
    int cls = class_of(item);
    if (cls < 0) return -1;
    int fx = enchantable_fixed(cls);
    if (fx > 0) {
        int f16 = fx - 1;
        if (attr < f16) return -1;
        int count = r[kRecordHead + f16 - 1] >> 1;
        if (attr != f16 + count * 3) return -1;
        int ins = insert_at_2016(cls, f16);
        memcpy(o, r, kRecordHead + ins);
        o[kRecordHead + ins] = 0;
        memcpy(o + kRecordHead + ins + 1, r + kRecordHead + ins, attr - ins);
        o[0] = (unsigned char)len;                 // datasize = (len + 1) - 1
        return len + 1;
    }
    if (cls == kClass39 && attr == 1) {
        memset(o, 0, kRecordHead + kClass39Width);
        memcpy(o, r, kRecordHead + 1);
        o[0] = (unsigned char)(kRecordHead + kClass39Width - 1);
        return kRecordHead + kClass39Width;
    }
    if (width2026(cls, r + kRecordHead, attr) != attr) return -1;
    memcpy(o, r, len);
    return len;
}

// a record whose item id sits itemAt bytes in (inventory 3; booth search 15): the head rides along, datasize grows
inline int long_record(const unsigned char* r, int len, int itemAt, unsigned char* o) {
    if (itemAt == kRecordHead - 2) return record(r, len, o);
    int extra = itemAt - (kRecordHead - 2);
    unsigned char inner[512], t[512];
    if (len - extra > (int)sizeof inner || len - extra < kRecordHead) return -1;
    memcpy(inner + kRecordHead - 2, r + itemAt, len - itemAt);
    inner[0] = (unsigned char)(len - extra - 1);
    inner[1] = inner[2] = 0;
    int m = record(inner, len - extra, t);
    if (m < 0) return -1;
    memcpy(o, r, itemAt);
    memcpy(o + itemAt, t + kRecordHead - 2, m - (kRecordHead - 2));
    int total = itemAt + m - (kRecordHead - 2);
    o[0] = (unsigned char)(total - 1);
    return total;
}

// CLIENT_ITEM {count u8, box u8, flag u8, records} -> {count u32, box, flag, records}; 0 = refuse
inline int client_item(const unsigned char* p, int n, unsigned char* o) {
    if (n < 3) return 0;
    o[0] = p[0]; o[1] = o[2] = o[3] = 0; o[4] = p[1]; o[5] = p[2];
    int at = 3, m = 6;
    while (at < n) {
        int len = p[at] + 1;
        if (len < kRecordHead || at + len > n || m + len + 32 > 0x1FF0) return 0;
        int k = record(p + at, len, o + m);
        if (k < 0) return 0;
        m += k; at += len;
    }
    return m;
}
// the header-only form (T.ClientItem2016To2026), used when a record cannot be translated
inline int client_item_head(const unsigned char* p, int n, unsigned char* o) {
    if (n < 3 || n + 3 > 0x1FF0) return 0;
    o[0] = p[0]; o[1] = o[2] = o[3] = 0;
    memcpy(o + 4, p + 1, n - 1);
    return n + 3;
}

// header | count u8 | records | <=1 byte  ->  header | count u32 | records (2026 widths) | 4 zero bytes; 0 = refuse
inline int record_list(const unsigned char* p, int n, int countAt, int itemAt, unsigned char* o) {
    if (n < countAt + 1) return 0;
    int count = p[countAt];
    memcpy(o, p, countAt);
    o[countAt] = (unsigned char)count; o[countAt + 1] = o[countAt + 2] = o[countAt + 3] = 0;
    int at = countAt + 1, m = countAt + 4;
    for (int k = 0; k < count; k++) {
        if (at >= n) return 0;
        int len = p[at] + 1;
        if (len < itemAt + 2 || at + len > n || m + len + 32 > 0x1FF0) return 0;
        int w = long_record(p + at, len, itemAt, o + m);
        if (w < 0) return 0;
        m += w; at += len;
    }
    if (n - at > 1) return 0;
    memset(o + m, 0, 4);
    return m + 4;
}

// a packet whose LAST field is one item {itemid u16, attributes} (no size byte) at `at`
inline int trailing_item(const unsigned char* p, int n, int at, unsigned char* o) {
    int body = n - at;
    if (body < 2 || body + kRecordHead - 2 > 255) return 0;
    unsigned char rec[260], t[300];
    rec[0] = (unsigned char)(body + kRecordHead - 3);
    rec[1] = rec[2] = 0;
    memcpy(rec + kRecordHead - 2, p + at, body);
    int m = record(rec, body + kRecordHead - 2, t);
    if (m < 0) return 0;
    memcpy(o, p, at);
    memcpy(o + at, t + kRecordHead - 2, m - (kRecordHead - 2));
    return at + m - (kRecordHead - 2);
}

// an item at `at` carried at its used width or padded to the full struct; padded keeps the packet size
inline int leading_item(const unsigned char* p, int n, int at, unsigned char* o) {
    if (n < at + 2) return 0;
    int id = p[at] | (p[at + 1] << 8);
    if (id == 0xFFFF) { memcpy(o, p, n); return n; }
    int cls = class_of(id);
    int width = cls < 0 ? -1 : width2016(cls, p + at + 2, n - at - 2);
    if (width < 0 || at + 2 + width > n) return 0;
    int used = at + 2 + width;
    unsigned char t[600];
    if (used > 512) return 0;
    int m = trailing_item(p, used, at, t);
    if (!m) return 0;
    int padding = n - used;
    if (padding == 0) { memcpy(o, t, m); return m; }
    memset(o, 0, n);
    memcpy(o, t, m < n ? m : n);
    if (m < n) memcpy(o + m, p + used + 1, n - m);
    return n;
}

}  // namespace bridge26
