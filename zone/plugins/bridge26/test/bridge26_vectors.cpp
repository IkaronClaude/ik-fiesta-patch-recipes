// bridge26_vectors - the zone plugin's translators over recorded payloads, for fiesta-proxy ZoneHookParityTests.
// stdin: "OPCODE PAYLOADHEX" per line (2016 shapes, e.g. extracted from a 2016 capture); stdout: the plugin's verify-log
// format "OPCODE 2016HEX 2026HEX|-" for every line whose opcode the plugin owns.
//   zone\plugins\bridge26\test\build.bat  -> build\bridge26_vectors.exe
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "../bridge26_translate.h"

int main() {
    static char line[0x10000];
    static unsigned char in[0x4000], out[0x4000];
    while (fgets(line, sizeof line, stdin)) {
        unsigned op = 0;
        char hex[0x8000];
        if (sscanf_s(line, "%x %32767s", &op, hex, (unsigned)sizeof hex) != 2) continue;
        const bridge26::Owned* o = bridge26::owned(op);
        if (!o) continue;
        int n = (int)strlen(hex) / 2;
        for (int i = 0; i < n; i++) { char b[3] = { hex[2 * i], hex[2 * i + 1], 0 }; in[i] = (unsigned char)strtoul(b, 0, 16); }
        int m = o->fn(in, n, out);
        printf("%04X %s ", op, hex);
        if (m) for (int i = 0; i < m; i++) printf("%02X", out[i]); else printf("-");
        printf("\n");
    }
    return 0;
}
