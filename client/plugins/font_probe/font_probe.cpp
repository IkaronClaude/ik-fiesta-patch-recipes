// font_probe - DIAGNOSTIC: what fonts the 2026 client really creates and what GDI resolves them to (fiesta-godot needs
// its UI text 1:1 with the client's; operator 2026-10-09: "I still want a 1:1 match on the font render").
//
// ---- WHY ---------------------------------------------------------------------------------------------------------------
//   The 2016 Fiesta.bin's Font::FontInit gives every Font::Type but DEFAULT ("verdana") an EMPTY face, so GDI's font
//   mapper picks the face at run time - and the text follows Windows' smoothing setting (ClearType on = stretched,
//   purple text, operator). Which face that ends up as on a player's machine is not in any file: this asks GDI.
//
// ---- THIS PLUGIN -------------------------------------------------------------------------------------------------------
//   IAT-hooks gdi32 CreateFontA / CreateFontIndirectA in the exe. For each distinct (face, height, weight, quality) it logs
//   the arguments, the caller (exe RVA), GDI's resolved face (GetTextFaceA) and metrics, plus the system smoothing state
//   once; and writes hooks\font_probe_<n>.bmp - "3581/3581 Normal Academy Whisper Annaaa" drawn white on black with that
//   font the way PgFont draws (a CreateCompatibleDC memory DC, MM_TEXT), so its pixels can be diffed exactly.
//   hooks\font_probe.ini  [config] scale_percent=300   -> every font created that much larger (faces easy to tell apart
//   on screen; 100 or no .ini = unchanged). Remove once fiesta-godot's fonts are pinned.
#include <hook_core.h>

#include <windows.h>

#include <intrin.h>
#pragma comment(lib, "gdi32.lib")

#include <cstdio>
#include <cstring>

namespace {

typedef HFONT(WINAPI* CreateFontAFn)(int, int, int, int, int, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD,
                                      LPCSTR);
typedef HFONT(WINAPI* CreateFontIndirectAFn)(const LOGFONTA*);
CreateFontAFn g_create = nullptr;
CreateFontIndirectAFn g_create_ind = nullptr;
int g_scale = 100;
int g_n = 0;
char g_seen[64][96];
int g_nseen = 0;
CRITICAL_SECTION g_lock;

bool first_time(const char* key) {
    for (int i = 0; i < g_nseen; i++)
        if (strcmp(g_seen[i], key) == 0) return false;
    if (g_nseen < 64) strncpy_s(g_seen[g_nseen++], key, _TRUNCATE);
    return true;
}

void dump_bmp(HFONT f, int n) {
    const char* sample = "3581/3581 Normal Academy Whisper Annaaa 0123456789";
    HDC dc = CreateCompatibleDC(nullptr);
    SetMapMode(dc, MM_TEXT);
    HGDIOBJ of = SelectObject(dc, f);
    SIZE sz{};
    GetTextExtentPoint32A(dc, sample, (int)strlen(sample), &sz);
    int W = sz.cx + 8, H = sz.cy + 4;
    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = W;
    bi.bmiHeader.biHeight = -H;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    void* bits = nullptr;
    HBITMAP bmp = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    HGDIOBJ ob = SelectObject(dc, bmp);
    memset(bits, 0, (size_t)W * H * 4);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(255, 255, 255));
    TextOutA(dc, 4, 2, sample, (int)strlen(sample));
    GdiFlush();
    char path[MAX_PATH];
    HMODULE self = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&dump_bmp, &self);
    GetModuleFileNameA(self, path, MAX_PATH);
    char* slash = strrchr(path, '\\');
    if (slash) sprintf_s(slash + 1, MAX_PATH - (slash + 1 - path), "font_probe_%02d.bmp", n);
    BITMAPFILEHEADER fh{};
    fh.bfType = 0x4D42;
    fh.bfOffBits = sizeof(fh) + sizeof(BITMAPINFOHEADER);
    fh.bfSize = fh.bfOffBits + (DWORD)W * H * 4;
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD wr;
        WriteFile(h, &fh, sizeof fh, &wr, nullptr);
        WriteFile(h, &bi.bmiHeader, sizeof(BITMAPINFOHEADER), &wr, nullptr);
        WriteFile(h, bits, (DWORD)W * H * 4, &wr, nullptr);
        CloseHandle(h);
    }
    SelectObject(dc, ob);
    DeleteObject(bmp);
    SelectObject(dc, of);
    DeleteDC(dc);
}

void report(HFONT f, const LOGFONTA& lf, void* caller, const char* via) {
    if (!f) return;
    char key[96];
    sprintf_s(key, "%s|%ld|%ld|%u", lf.lfFaceName, lf.lfHeight, lf.lfWeight, (unsigned)lf.lfQuality);
    EnterCriticalSection(&g_lock);
    bool first = first_time(key);
    int n = first ? g_n++ : -1;
    LeaveCriticalSection(&g_lock);
    if (!first) return;
    HDC dc = CreateCompatibleDC(nullptr);
    HGDIOBJ of = SelectObject(dc, f);
    char face[LF_FACESIZE] = {};
    GetTextFaceA(dc, LF_FACESIZE, face);
    TEXTMETRICA tm{};
    GetTextMetricsA(dc, &tm);
    SIZE sz{};
    GetTextExtentPoint32A(dc, "3581/3581", 9, &sz);
    SelectObject(dc, of);
    DeleteDC(dc);
    hook::log("#%02d %s face='%s' h=%ld w=%ld weight=%ld italic=%u charset=%u out=%u clip=%u quality=%u pitch=%u caller=exe+0x%X"
              " -> GDI face '%s' tmHeight=%ld asc=%ld desc=%ld avgw=%ld weight=%ld '3581/3581'=%ld px",
              n, via, lf.lfFaceName, lf.lfHeight, lf.lfWidth, lf.lfWeight, lf.lfItalic, lf.lfCharSet, lf.lfOutPrecision,
              lf.lfClipPrecision, lf.lfQuality, lf.lfPitchAndFamily, (unsigned)((uintptr_t)caller - hook::module_base()),
              face, tm.tmHeight, tm.tmAscent, tm.tmDescent, tm.tmAveCharWidth, tm.tmWeight, sz.cx);
    dump_bmp(f, n);
}

HFONT WINAPI my_create(int h, int w, int esc, int ori, int weight, DWORD italic, DWORD under, DWORD strike, DWORD charset,
                       DWORD outp, DWORD clip, DWORD quality, DWORD pitch, LPCSTR face) {
    void* caller = _ReturnAddress();
    int hh = h * g_scale / 100;
    HFONT f = g_create(hh, w * g_scale / 100, esc, ori, weight, italic, under, strike, charset, outp, clip, quality, pitch,
                       face);
    LOGFONTA lf{};
    lf.lfHeight = h, lf.lfWidth = w, lf.lfWeight = weight, lf.lfItalic = (BYTE)italic, lf.lfCharSet = (BYTE)charset;
    lf.lfOutPrecision = (BYTE)outp, lf.lfClipPrecision = (BYTE)clip, lf.lfQuality = (BYTE)quality;
    lf.lfPitchAndFamily = (BYTE)pitch;
    if (face) strncpy_s(lf.lfFaceName, face, _TRUNCATE);
    report(f, lf, caller, "CreateFontA");
    return f;
}

HFONT WINAPI my_create_ind(const LOGFONTA* lf) {
    void* caller = _ReturnAddress();
    LOGFONTA scaled = *lf;
    scaled.lfHeight = lf->lfHeight * g_scale / 100;
    scaled.lfWidth = lf->lfWidth * g_scale / 100;
    HFONT f = g_create_ind(&scaled);
    report(f, *lf, caller, "CreateFontIndirectA");
    return f;
}

// [config] extent_needle=<text>: every GetTextExtentPoint32A of a string containing it logged with the result and the
// DC's selected font (GetCurrentObject + GetObject) - which font the text-fit measure (PgWinAbbreviateText) really uses
typedef BOOL(WINAPI* ExtentFn)(HDC, LPCSTR, int, LPSIZE);
ExtentFn g_extent = nullptr;
char g_needle[64] = "";
int g_extent_logs = 0;

BOOL WINAPI my_extent(HDC dc, LPCSTR s, int n, LPSIZE sz) {
    BOOL r = g_extent(dc, s, n, sz);
    if (g_needle[0] && s && n > 0 && n < 200 && g_extent_logs < 400) {
        char buf[256];
        memcpy(buf, s, n); buf[n] = 0;
        if (strstr(buf, g_needle)) {
            g_extent_logs++;
            LOGFONTA lf = {};
            HGDIOBJ f = GetCurrentObject(dc, OBJ_FONT);
            GetObjectA(f, sizeof lf, &lf);
            char face[64] = "";
            GetTextFaceA(dc, sizeof face, face);
            hook::log("extent '%s' -> %ld x %ld  font face='%s' (resolved '%s') h=%ld w=%ld weight=%ld quality=%u caller=exe+0x%X",
                      buf, sz ? sz->cx : -1, sz ? sz->cy : -1, lf.lfFaceName, face, lf.lfHeight, lf.lfWidth, lf.lfWeight,
                      lf.lfQuality, (unsigned)((uintptr_t)_ReturnAddress() - hook::module_base()));
        }
    }
    return r;
}

// [config] fit_trace=1: the 2026 text-fit routine (PgWinAbbreviateText 0x891E10, thiscall) logged on entry - the
// control's width / height fields (+0xF4 / +0xF8) and its source text (+0x124 std::string) when it holds g_needle
hook::Detour g_fit;
typedef void(__fastcall* FitFn)(void*, void*);
int g_fit_logs = 0;
void __fastcall my_fit(void* self, void* edx) {
    const unsigned char* o = (const unsigned char*)self;
    const char* txt = nullptr;
    unsigned cap = *(const unsigned*)(o + 0x124 + 0x14);
    txt = cap >= 16 ? *(const char* const*)(o + 0x124) : (const char*)(o + 0x124);
    static int any = 0;
    if (any < 40) {
        any++;
        hook::log("fit#%d cap %u w=%u h=%u '%.40s'", any, cap, *(const unsigned*)(o + 0xF4), *(const unsigned*)(o + 0xF8), txt ? txt : "");
    }
    if (g_fit_logs < 300 && txt && g_needle[0] && strstr(txt, g_needle)) {
        g_fit_logs++;
        hook::log("fit '%s' w=%u h=%u", txt, *(const unsigned*)(o + 0xF4), *(const unsigned*)(o + 0xF8));
    }
    ((FitFn)g_fit.trampoline)(self, edx);
}

}  // namespace

HOOK_PLUGIN("font_probe") {
    InitializeCriticalSection(&g_lock);
    g_scale = hook::config_int("scale_percent", 100);
    if (g_scale < 10 || g_scale > 1000) g_scale = 100;
    BOOL smoothing = FALSE;
    UINT type = 0, contrast = 0;
    SystemParametersInfoA(SPI_GETFONTSMOOTHING, 0, &smoothing, 0);
    SystemParametersInfoA(SPI_GETFONTSMOOTHINGTYPE, 0, &type, 0);
    SystemParametersInfoA(SPI_GETFONTSMOOTHINGCONTRAST, 0, &contrast, 0);
    hook::log("font_probe: Windows font smoothing %s, type %u (1 standard, 2 ClearType), contrast %u; scale_percent %d",
              smoothing ? "ON" : "off", type, contrast, g_scale);
    HMODULE exe = GetModuleHandleA(nullptr);
    g_create = (CreateFontAFn)hook::iat_hook(exe, "gdi32.dll", "CreateFontA", (void*)&my_create);
    g_create_ind = (CreateFontIndirectAFn)hook::iat_hook(exe, "gdi32.dll", "CreateFontIndirectA", (void*)&my_create_ind);
    hook::config_str("extent_needle", "", g_needle, sizeof g_needle);
    if (hook::config_int("fit_trace", 0)) hook::hook_function("PgWinAbbreviateText fit 0x891E10", hook::rebase(0x891E10), (void*)&my_fit, &g_fit);
    if (g_needle[0] && !hook::config_int("fit_trace", 0))
        g_extent = (ExtentFn)hook::iat_hook(exe, "gdi32.dll", "GetTextExtentPoint32A", (void*)&my_extent);
    hook::log("font_probe: extent_needle '%s' -> GetTextExtentPoint32A %s", g_needle, g_extent ? "hooked" : "not hooked");
    hook::log("font_probe: CreateFontA %s, CreateFontIndirectA %s", g_create ? "hooked" : "NOT in the exe's imports",
              g_create_ind ? "hooked" : "NOT in the exe's imports");
}
