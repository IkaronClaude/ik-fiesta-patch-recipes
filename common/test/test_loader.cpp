// test_loader - the hooks\<name>.ini rules of common/loader/plugins.cpp, on dummy plugins (build_loader_test.bat).
//   a.ini  after=c, [config] n=7     -> c loads before a, a reads n=7
//   b.ini  enabled=0                 -> not loaded
//   c      no .ini                   -> loaded, n = the default (-1)
//   d.ini  after=missing, a          -> the missing name is ignored, d loads after a
//   e.ini  after=f / f.ini after=e   -> a cycle: both still load
// Expected order.txt: c=-1, a=7, d=-1, then e and f (in either order). Exit code 0 = PASS.
#include "../loader/plugins.cpp"

#include <stdio.h>
#include <string.h>

static void put(const char* path, const char* text) {
    FILE* f = fopen(path, "wb");
    if (f) { fputs(text, f); fclose(f); }
}

int main() {
    CreateDirectoryA("hooks", 0);
    const char* names[] = {"a", "b", "c", "d", "e", "f"};
    for (const char* n : names) {
        char dst[64];
        sprintf(dst, "hooks\\%s.dll", n);
        if (!CopyFileA("loader_dummy.dll", dst, FALSE)) { printf("cannot copy loader_dummy.dll\n"); return 2; }
    }
    put("hooks\\a.ini", "[plugin]\r\nafter=c\r\n[config]\r\nn=7\r\n");
    put("hooks\\b.ini", "[plugin]\r\nenabled=0\r\n");
    put("hooks\\d.ini", "[plugin]\r\nafter=missing, a\r\n");
    put("hooks\\e.ini", "[plugin]\r\nafter=f\r\n");
    put("hooks\\f.ini", "[plugin]\r\nafter=e\r\n");
    DeleteFileA("order.txt");

    hook::log_init("test_loader", L"test_loader.log");
    int loaded = hook::load_plugins(L"hooks");

    char buf[512] = {0};
    FILE* f = fopen("order.txt", "rb");
    if (f) { fread(buf, 1, sizeof buf - 1, f); fclose(f); }
    printf("loaded %d\n%s", loaded, buf);
    const char* c = strstr(buf, "c.dll=-1"), *a = strstr(buf, "a.dll=7"), *d = strstr(buf, "d.dll=-1");
    bool ok = loaded == 5 && !strstr(buf, "b.dll") && c && a && d && c < a && a < d && strstr(buf, "e.dll") && strstr(buf, "f.dll");
    printf("%s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
