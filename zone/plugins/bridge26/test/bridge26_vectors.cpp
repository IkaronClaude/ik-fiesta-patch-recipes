// bridge26_vectors - the zone plugin's translators over recorded payloads, for fiesta-proxy ZoneHookParityTests.
// stdin: "OPCODE PAYLOADHEX" per line (2016 shapes, e.g. extracted from a 2016 capture); stdout: the plugin's verify-log
// format "OPCODE 2016HEX 2026HEX|-" for every line whose opcode the plugin owns.
//   zone\plugins\bridge26\test\build.bat  -> build\bridge26_vectors.exe
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "../bridge26_translate.h"
#include "../bridge26_items.h"
#include <map>

// item classes for the item opcodes: "CLASS <id> <class>" lines on stdin (a test input - the plugin reads the 2026
// ItemInfo itself)
std::map<int, int> g_classes;
int class_lookup(int id) { std::map<int, int>::const_iterator it = g_classes.find(id); return it == g_classes.end() ? -1 : it->second; }

// the plugin's on_item_packet, minus the sending: 0 = left as it is
int item_op(unsigned op, const unsigned char* p, int n, unsigned char* o) {
    int m = 0;
    switch (op) {
    case 0x3001: m = bridge26::trailing_item(p, n, 4, o); return m == n ? 0 : m;
    case 0x3002: m = bridge26::trailing_item(p, n, 3, o); return m == n ? 0 : m;
    case 0x1047: m = bridge26::client_item(p, n, o); return m ? m : bridge26::client_item_head(p, n, o);
    case 0x305B: return bridge26::record_list(p, n, 0, 3, o);
    case 0x7492: return bridge26::record_list(p, n, 18, 3, o);
    case 0x6814: return bridge26::record_list(p, n, 2, 15, o);
    case 0x986E: return bridge26::record_list(p, n, 10, 3, o);
    case 0x302D: return bridge26::record_list(p, n, 0, 3, o);
    case 0x3C08: return bridge26::record_list(p, n, 11, 3, o);
    case 0x305C: m = bridge26::leading_item(p, n, 2, o); return (m == n && !memcmp(o, p, n)) ? 0 : m;
    case 0x4C10: m = bridge26::leading_item(p, n, 1, o); return (m == n && !memcmp(o, p, n)) ? 0 : m;
    case 0xC407: m = bridge26::leading_item(p, n, 3, o); return (m == n && !memcmp(o, p, n)) ? 0 : m;
    }
    return -1;
}

int main() {
    bridge26::g_class_of = class_lookup;
    static char line[0x10000];
    static unsigned char in[0x4000], out[0x4000];
    while (fgets(line, sizeof line, stdin)) {
        unsigned op = 0;
        char hex[0x8000];
        int cid, ccls;
        if (sscanf_s(line, "CLASS %d %d", &cid, &ccls) == 2) { g_classes[cid] = ccls; continue; }
        if (sscanf_s(line, "%x %32767s", &op, hex, (unsigned)sizeof hex) != 2) continue;
        const bridge26::Owned* o = bridge26::owned(op);
        bool item = !o && item_op(op, 0, 0, 0) != -1;
        if (!o && !item) continue;
        int n = (int)strlen(hex) / 2;
        for (int i = 0; i < n; i++) { char b[3] = { hex[2 * i], hex[2 * i + 1], 0 }; in[i] = (unsigned char)strtoul(b, 0, 16); }
        int m = o ? o->fn(in, n, out) : item_op(op, in, n, out);
        printf("%04X %s ", op, hex);
        if (m) for (int i = 0; i < m; i++) printf("%02X", out[i]); else printf("-");
        printf("\n");
    }
    return 0;
}
