// remote_control - DIAGNOSTIC / TEST: drive the official 2026 client from outside, so fiesta-godot's visuals can be
// compared with the baseline under the same inputs (operator 2026-10-17: "log in using the official client and cast
// skills and screenshot at specific times etc.").
//
// ---- THIS PLUGIN -------------------------------------------------------------------------------------------------------
//   A TCP listener on 127.0.0.1 (port from hooks\remote_control.ini [config] port=, default 27015; bind=0.0.0.0 to
//   allow another machine - only on a trusted network: anyone who can connect can type into the client). One command
//   per line, one reply line each ("ok ..." / "err ..."). Input goes to the game's own top-level window as the window
//   messages Windows would send (the client reads keys / mouse from its WndProc), so nothing in the exe changes:
//     ping                          -> ok pong
//     size                          -> ok <w> <h>            the client area
//     key <vk> [press|down|up]      a virtual key (decimal or 0x..), default press = down + up
//     text <string...>              WM_CHAR per character (a chat line, a login name)
//     say <line...>                 a chat line sent: Enter, wait for the chat input, type, Enter (GM commands)
//     move <x> <y>                  WM_MOUSEMOVE at client (x, y)
//     click <x> <y> [left|right]    move + button down + up
//     down <x> <y> [left|right] / up <x> <y> [left|right]   (drags, held camera turns)
//     wheel <x> <y> <delta>         WM_MOUSEWHEEL (120 = one notch away)
//     shot <path>                   the client area as a 32-bit BMP (PrintWindow, also under other windows; 3 s limit,
//                                   "err capture failed" while the game is busy loading)
//   Input is POSTED (the game's thread is busy for seconds while it loads a map; nothing here waits on it).
//     quit                          closes this connection
//   Driver: fiesta-godot tools/remote_client.py (timed sequences: log in, cast, screenshot at given times).
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <d3d9.h>
#define DIRECTINPUT_VERSION 0x0800
#include <dinput.h>
#pragma comment(lib, "dxguid.lib")

#include <hook_core.h>
#include <client_addrs.h>
#include <clienthook.h>
#include <pgwin_msg.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

int g_port = 27015;
char g_bind[64] = "127.0.0.1";

struct FindCtx {
    DWORD pid;
    HWND best;
    int area;
};

BOOL CALLBACK find_proc(HWND h, LPARAM lp) {
    FindCtx* c = (FindCtx*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid != c->pid || !IsWindowVisible(h) || GetWindow(h, GW_OWNER) != nullptr) return TRUE;
    RECT r{};
    GetClientRect(h, &r);
    int a = (r.right - r.left) * (r.bottom - r.top);
    if (a > c->area) {
        c->area = a;
        c->best = h;
    }
    return TRUE;
}

// the game window: this process's largest visible top-level window
HWND game_window() {
    FindCtx c{GetCurrentProcessId(), nullptr, 0};
    EnumWindows(find_proc, (LPARAM)&c);
    return c.best;
}

// the window that takes the game's input: the top-level window's child of the same class ("Gamebryo Application", the
// render window, live 2026-10-20), else the top-level one
HWND input_window(HWND top) {
    HWND c = FindWindowExA(top, nullptr, "Gamebryo Application", nullptr);
    return c ? c : top;
}

// where typed keys go: the focused window of the game's UI thread when it is one of the client's edit controls (the
// login name / password, chat: real Win32 child windows of class "PgEditWin"), else the render window
HWND key_window(HWND top) {
    GUITHREADINFO gi{};
    gi.cbSize = sizeof(gi);
    if (GetGUIThreadInfo(GetWindowThreadProcessId(top, nullptr), &gi) && gi.hwndFocus) {
        char cls[64] = {0};
        GetClassNameA(gi.hwndFocus, cls, sizeof(cls));
        if (strcmp(cls, "PgEditWin") == 0) return gi.hwndFocus;
    }
    return input_window(top);
}

LPARAM key_lparam(UINT vk, bool up) {
    UINT sc = MapVirtualKeyA(vk, MAPVK_VK_TO_VSC);
    LPARAM lp = 1 | (sc << 16);
    if (vk == VK_LEFT || vk == VK_RIGHT || vk == VK_UP || vk == VK_DOWN || vk == VK_INSERT || vk == VK_DELETE ||
        vk == VK_HOME || vk == VK_END || vk == VK_PRIOR || vk == VK_NEXT)
        lp |= 1 << 24;
    if (up) lp |= (1u << 30) | (1u << 31);
    return lp;
}

void send_key(HWND w, UINT vk, int mode) {   // 0 press, 1 down, 2 up
    UINT down = (vk == VK_MENU || vk == VK_F10) ? WM_SYSKEYDOWN : WM_KEYDOWN;
    UINT up = (vk == VK_MENU || vk == VK_F10) ? WM_SYSKEYUP : WM_KEYUP;
    if (mode != 2) PostMessageA(w, down, vk, key_lparam(vk, false));
    if (mode != 1) {
        if (mode == 0) Sleep(30);
        PostMessageA(w, up, vk, key_lparam(vk, true));
    }
}

void mouse(HWND w, UINT msg, int x, int y, WPARAM keys) {
    PostMessageA(w, msg, keys, MAKELPARAM(x, y));
}

bool write_bmp(const char* path, HBITMAP bmp, int W, int H, HDC dc) {
    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = W;
    bi.bmiHeader.biHeight = -H;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    std::string px((size_t)W * H * 4, '\0');
    if (!GetDIBits(dc, bmp, 0, H, &px[0], &bi, DIB_RGB_COLORS)) return false;
    BITMAPFILEHEADER fh{};
    fh.bfType = 0x4D42;
    fh.bfOffBits = sizeof(fh) + sizeof(BITMAPINFOHEADER);
    fh.bfSize = fh.bfOffBits + (DWORD)px.size();
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD n = 0;
    WriteFile(h, &fh, sizeof(fh), &n, nullptr);
    WriteFile(h, &bi.bmiHeader, sizeof(BITMAPINFOHEADER), &n, nullptr);
    WriteFile(h, px.data(), (DWORD)px.size(), &n, nullptr);
    CloseHandle(h);
    return true;
}

bool screenshot(HWND w, const char* path) {
    RECT r{};
    GetClientRect(w, &r);
    int W = r.right, H = r.bottom;
    if (W <= 0 || H <= 0) return false;
    HDC wdc = GetDC(w);
    HDC mem = CreateCompatibleDC(wdc);
    HBITMAP bmp = CreateCompatibleBitmap(wdc, W, H);
    HGDIOBJ old = SelectObject(mem, bmp);
    // PrintWindow (PW_CLIENTONLY | PW_RENDERFULLCONTENT) reads the composed image even under other windows, but it needs
    // the game's UI thread, which is busy for seconds while a map loads: it runs on a worker with a 3 s limit (a late
    // one is left to finish on its own - its bitmap is then leaked, not freed under it); then the screen under the
    // client area, which needs the window uncovered
    struct Job {
        HWND w;
        HDC dc;
        BOOL ok;
    };
    Job* job = new Job{w, mem, FALSE};
    HANDLE th = CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
        Job* j = (Job*)p;
        j->ok = PrintWindow(j->w, j->dc, 0x1 | 0x2);
        return 0;
    }, job, 0, nullptr);
    if (th && WaitForSingleObject(th, 3000) != WAIT_OBJECT_0) {
        CloseHandle(th);
        hook::log("shot: PrintWindow busy - left running");
        return false;                           // mem / bmp / job stay alive for the late PrintWindow
    }
    if (th) CloseHandle(th);
    BOOL ok = job->ok;
    delete job;
    if (!ok) {
        POINT p{0, 0};
        ClientToScreen(w, &p);
        HDC sdc = GetDC(nullptr);
        ok = BitBlt(mem, 0, 0, W, H, sdc, p.x, p.y, SRCCOPY | CAPTUREBLT);
        ReleaseDC(nullptr, sdc);
    }
    SelectObject(mem, old);
    bool done = ok && write_bmp(path, bmp, W, H, mem);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(w, wdc);
    return done;
}

// ---- Direct3D 9 capture -----------------------------------------------------------------------------------------------
// The client loads d3d9.dll itself (no static import): the plugin, loaded before any window, detours the exported
// Direct3DCreate9, patches the returned IDirect3D9's CreateDevice (vtable 16) and the new device's Present (17). A "shot"
// asks the next Present to copy the back buffer (GetRenderTargetData into a SYSTEMMEM surface) and write it - exactly
// the frame the game shows, covered window or not.
typedef IDirect3D9*(WINAPI* Create9Fn)(UINT);
typedef HRESULT(STDMETHODCALLTYPE* CreateDeviceFn)(IDirect3D9*, UINT, D3DDEVTYPE, HWND, DWORD, D3DPRESENT_PARAMETERS*,
                                                     IDirect3DDevice9**);
typedef HRESULT(STDMETHODCALLTYPE* PresentFn)(IDirect3DDevice9*, const RECT*, const RECT*, HWND, const RGNDATA*);
hook::Detour g_create9_detour;
CreateDeviceFn g_create_device = nullptr;
PresentFn g_present = nullptr;          // (set once any device is hooked)
// every vtable patched -> its own original Present (a capability-check device and the real one may differ)
struct VPatch {
    void** vt;
    void* orig;
};
VPatch g_dev_vts[8];
int g_ndev = 0;
VPatch g_sc_vts[8];
int g_nsc = 0;
typedef HRESULT(STDMETHODCALLTYPE* ScPresentFn)(IDirect3DSwapChain9*, const RECT*, const RECT*, HWND, const RGNDATA*,
                                                  DWORD);
void* orig_of(VPatch* v, int n, void** vt) {
    for (int i = 0; i < n; i++)
        if (v[i].vt == vt) return v[i].orig;
    return nullptr;
}
CRITICAL_SECTION g_cap_lock;
char g_cap_path[MAX_PATH] = {0};
HANDLE g_cap_done = nullptr;
bool g_cap_ok = false;
volatile LONG g_presents = 0;

bool save_surface(IDirect3DDevice9* dev, const char* path) {
    IDirect3DSurface9* bb = nullptr;
    if (FAILED(dev->GetBackBuffer(0, 0, D3DBACKBUFFER_TYPE_MONO, &bb)) || !bb) return false;
    D3DSURFACE_DESC d{};
    bb->GetDesc(&d);
    // a multisampled back buffer is resolved into a plain render target first (GetRenderTargetData refuses MSAA)
    IDirect3DSurface9* src = bb;
    IDirect3DSurface9* resolved = nullptr;
    if (d.MultiSampleType != D3DMULTISAMPLE_NONE &&
        SUCCEEDED(dev->CreateRenderTarget(d.Width, d.Height, d.Format, D3DMULTISAMPLE_NONE, 0, FALSE, &resolved, nullptr)) &&
        SUCCEEDED(dev->StretchRect(bb, nullptr, resolved, nullptr, D3DTEXF_NONE)))
        src = resolved;
    IDirect3DSurface9* sys = nullptr;
    bool ok = false;
    if (SUCCEEDED(dev->CreateOffscreenPlainSurface(d.Width, d.Height, d.Format, D3DPOOL_SYSTEMMEM, &sys, nullptr)) &&
        SUCCEEDED(dev->GetRenderTargetData(src, sys))) {
        D3DLOCKED_RECT lr{};
        if (SUCCEEDED(sys->LockRect(&lr, nullptr, D3DLOCK_READONLY))) {
            if (d.Format == D3DFMT_X8R8G8B8 || d.Format == D3DFMT_A8R8G8B8) {
                int W = (int)d.Width, H = (int)d.Height;
                BITMAPINFOHEADER bh{};
                bh.biSize = sizeof(bh);
                bh.biWidth = W;
                bh.biHeight = -H;
                bh.biPlanes = 1;
                bh.biBitCount = 32;
                BITMAPFILEHEADER fh{};
                fh.bfType = 0x4D42;
                fh.bfOffBits = sizeof(fh) + sizeof(bh);
                fh.bfSize = fh.bfOffBits + (DWORD)W * H * 4;
                HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (h != INVALID_HANDLE_VALUE) {
                    DWORD n = 0;
                    WriteFile(h, &fh, sizeof(fh), &n, nullptr);
                    WriteFile(h, &bh, sizeof(bh), &n, nullptr);
                    for (int y = 0; y < H; y++) {
                        unsigned char* row = (unsigned char*)lr.pBits + (size_t)y * lr.Pitch;
                        for (int x = 0; x < W; x++) row[x * 4 + 3] = 255;   // X8: opaque
                        WriteFile(h, row, (DWORD)W * 4, &n, nullptr);
                    }
                    CloseHandle(h);
                    ok = true;
                }
            } else {
                hook::log("shot: back buffer format %d not handled", (int)d.Format);
            }
            sys->UnlockRect();
        }
    }
    if (sys) sys->Release();
    if (resolved) resolved->Release();
    bb->Release();
    return ok;
}

void capture_now(IDirect3DDevice9* dev) {
    InterlockedIncrement(&g_presents);
    EnterCriticalSection(&g_cap_lock);
    if (g_cap_path[0]) {
        g_cap_ok = save_surface(dev, g_cap_path);
        if (!g_cap_ok) hook::log("shot: the back buffer copy failed");
        g_cap_path[0] = 0;
        SetEvent(g_cap_done);
    }
    LeaveCriticalSection(&g_cap_lock);
}

// Present is DETOURED in its code, not swapped in the vtable: patching the vtable slot caught 8 Presents in 30 s from
// a client drawing ~10 fps (live 2026-10-20) - the renderer reaches the function some other way
hook::Detour g_present_detour;
hook::Detour g_sc_present_detour;

void auto_world_tick();
void auto_char_tick(void* cs);
void wins_tick();

HRESULT STDMETHODCALLTYPE my_present(IDirect3DDevice9* dev, const RECT* a, const RECT* b, HWND w, const RGNDATA* r) {
    capture_now(dev);
    auto_world_tick();
    wins_tick();
    return ((PresentFn)g_present_detour.trampoline)(dev, a, b, w, r);
}

HRESULT STDMETHODCALLTYPE my_sc_present(IDirect3DSwapChain9* sc, const RECT* a, const RECT* b, HWND w, const RGNDATA* r,
                                        DWORD f) {
    IDirect3DDevice9* dev = nullptr;
    if (SUCCEEDED(sc->GetDevice(&dev)) && dev) {
        capture_now(dev);
        dev->Release();
    }
    return ((ScPresentFn)g_sc_present_detour.trampoline)(sc, a, b, w, r, f);
}

HRESULT STDMETHODCALLTYPE my_create_device(IDirect3D9* d3d, UINT ad, D3DDEVTYPE t, HWND w, DWORD f,
                                           D3DPRESENT_PARAMETERS* pp, IDirect3DDevice9** out) {
    HRESULT hr = g_create_device(d3d, ad, t, w, f, pp, out);
    if (SUCCEEDED(hr) && out && *out) {
        void** vt = hook::vtable_of(*out);
        if (!g_present_detour.installed && hook::hook_function("IDirect3DDevice9::Present", vt[17], (void*)&my_present,
                                                               &g_present_detour))
            g_present = (PresentFn)g_present_detour.trampoline;
        IDirect3DSwapChain9* sc = nullptr;
        if (SUCCEEDED((*out)->GetSwapChain(0, &sc)) && sc) {
            if (!g_sc_present_detour.installed)
                hook::hook_function("IDirect3DSwapChain9::Present", hook::vtable_of(sc)[3], (void*)&my_sc_present,
                                    &g_sc_present_detour);
            sc->Release();
        }
        hook::log("Direct3D device %p (%ux%u fmt %d ms %d, flags %x): Present hooked", *out, pp ? pp->BackBufferWidth : 0,
                  pp ? pp->BackBufferHeight : 0, pp ? (int)pp->BackBufferFormat : -1, pp ? (int)pp->MultiSampleType : -1, f);
    }
    return hr;
}

// ---- extra display modes (operator 2026-10-22: test the official at 1600 x 900 windowed) --------------------------------
// The client builds its resolution list - and checks the saved Option.mco size against it at start (2026 0x5351F0, the
// "Error" box) - from IDirect3D9::GetAdapterModeCount / EnumAdapterModes. A remote-desktop display offers only its own
// size, so every other size is refused even windowed. GetAdapterModeCount (vtable 6) gains the sizes below that the
// adapter lacks, EnumAdapterModes (7) returns them past the real modes, as the first real mode with only width / height
// changed (same format / refresh). Windowed play never switches the display mode, so a listed size just sizes the window.
typedef UINT(STDMETHODCALLTYPE* ModeCountFn)(IDirect3D9*, UINT, D3DFORMAT);
typedef HRESULT(STDMETHODCALLTYPE* EnumModesFn)(IDirect3D9*, UINT, D3DFORMAT, UINT, D3DDISPLAYMODE*);
ModeCountFn g_mode_count = nullptr;
EnumModesFn g_enum_modes = nullptr;
// 16:9 / 16:10 and the 4:3 sizes (operator: 1280 x 960 etc.)
const UINT kExtraModes[][2] = {{800, 600}, {1024, 768}, {1152, 864}, {1280, 960}, {1400, 1050}, {1600, 1200},
                               {1280, 720}, {1280, 800}, {1366, 768}, {1440, 900}, {1600, 900}, {1680, 1050},
                               {1920, 1080}};

// the extra sizes this adapter / format does not already list, in order
int extra_modes(IDirect3D9* d, UINT adapter, D3DFORMAT fmt, UINT real, UINT out[][2]) {
    int n = 0;
    for (auto& m : kExtraModes) {
        bool have = false;
        for (UINT i = 0; i < real && !have; i++) {
            D3DDISPLAYMODE dm{};
            if (SUCCEEDED(g_enum_modes(d, adapter, fmt, i, &dm)) && dm.Width == m[0] && dm.Height == m[1]) have = true;
        }
        if (!have) {
            out[n][0] = m[0];
            out[n][1] = m[1];
            n++;
        }
    }
    return n;
}

UINT STDMETHODCALLTYPE my_mode_count(IDirect3D9* d, UINT adapter, D3DFORMAT fmt) {
    UINT real = g_mode_count(d, adapter, fmt);
    UINT ex[32][2];
    int n = real ? extra_modes(d, adapter, fmt, real, ex) : 0;
    static int logged = 0;
    if (logged++ < 8) hook::log("GetAdapterModeCount(adapter %u, format %d): %u real + %d", adapter, (int)fmt, real, n);
    return real + n;
}

HRESULT STDMETHODCALLTYPE my_enum_modes(IDirect3D9* d, UINT adapter, D3DFORMAT fmt, UINT i, D3DDISPLAYMODE* out) {
    UINT real = g_mode_count(d, adapter, fmt);
    if (i < real) return g_enum_modes(d, adapter, fmt, i, out);
    UINT ex[32][2];
    int n = extra_modes(d, adapter, fmt, real, ex);
    if (real == 0 || (int)(i - real) >= n) return D3DERR_INVALIDCALL;
    HRESULT hr = g_enum_modes(d, adapter, fmt, 0, out);
    if (FAILED(hr)) return hr;
    out->Width = ex[i - real][0];
    out->Height = ex[i - real][1];
    return D3D_OK;
}

// ---- every MessageBoxA the client shows: its text and the call stack (operator: the "Error" box at start) -----------
// Return addresses walked off the frame-pointer chain (CaptureStackBackTrace), each as exe+offset when inside Fiesta.exe
// (its base from GetModuleHandle) so they read straight against the 2026 disassembly.
typedef int(WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t g_message_box = nullptr;

int WINAPI my_message_box(HWND hwnd, LPCSTR text, LPCSTR caption, UINT type) {
    void* frames[32];
    USHORT n = CaptureStackBackTrace(1, 32, frames, nullptr);
    uintptr_t base = (uintptr_t)GetModuleHandleA(nullptr);
    std::string st;
    char b[48];
    for (USHORT i = 0; i < n; i++) {
        uintptr_t a = (uintptr_t)frames[i];
        HMODULE m = nullptr;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)a, &m);
        if ((uintptr_t)m == base)
            sprintf_s(b, " exe+%X(=%X)", (unsigned)(a - base), (unsigned)(a - base + 0x400000));
        else
            sprintf_s(b, " %p", (void*)a);
        st += b;
    }
    hook::log("MessageBoxA \"%s\" / \"%s\" type %X; stack:%s", caption ? caption : "", text ? text : "", type, st.c_str());
    return g_message_box(hwnd, text, caption, type);
}

IDirect3D9* WINAPI my_create9(UINT v) {
    IDirect3D9* d = ((Create9Fn)g_create9_detour.trampoline)(v);
    if (d && !g_create_device) {
        g_create_device = (CreateDeviceFn)hook::vtable_set(hook::vtable_of(d), 16, (void*)&my_create_device);
        hook::log("IDirect3D9 %p: CreateDevice hooked", d);
    }
    if (d && !g_mode_count) {
        g_mode_count = (ModeCountFn)hook::vtable_set(hook::vtable_of(d), 6, (void*)&my_mode_count);
        g_enum_modes = (EnumModesFn)hook::vtable_set(hook::vtable_of(d), 7, (void*)&my_enum_modes);
        hook::log("IDirect3D9 %p: display modes extended (GetAdapterModeCount / EnumAdapterModes)", d);
    }
    return d;
}

// the game's own frame: wait for the next Present to write it (3 s); false when Present is not hooked / not running
bool d3d_shot(const char* path) {
    if (!g_present) return false;
    EnterCriticalSection(&g_cap_lock);
    strcpy_s(g_cap_path, path);
    ResetEvent(g_cap_done);
    LeaveCriticalSection(&g_cap_lock);
    if (WaitForSingleObject(g_cap_done, 3000) != WAIT_OBJECT_0) {
        hook::log("shot: no Present in 3 s (%ld presents so far)", g_presents);
        EnterCriticalSection(&g_cap_lock);
        g_cap_path[0] = 0;
        LeaveCriticalSection(&g_cap_lock);
        return false;
    }
    return g_cap_ok;
}

// wait until the game has presented `n` more frames (input is read once per frame: a key must stay down across a frame
// the game polls, and a window opened by a key - the chat input after Enter - exists only a frame later). Falls back
// to time when Present is not hooked; gives up after `timeout_ms`
void wait_frames(int n, DWORD timeout_ms = 3000) {
    if (!g_present) {
        Sleep(150 * n);
        return;
    }
    LONG target = g_presents + n;
    DWORD t0 = GetTickCount();
    while (g_presents < target && GetTickCount() - t0 < timeout_ms) Sleep(5);
}

// ---- input: DirectInput 8 -----------------------------------------------------------------------------------------------
// The client reads keyboard and mouse through DirectInput 8 (DINPUT8 DirectInput8Create import), the cursor through
// GetCursorPos and buttons partly through GetAsyncKeyState - posted window messages reach only its edit controls
// (WM_CHAR typed into the login name, live; clicks and keys were ignored). So input is injected below the game:
// DirectInput8Create -> IDirectInput8::CreateDevice (vtable 3) learns which device is the keyboard / mouse; their
// GetDeviceState / GetDeviceData (detoured in the shared CDIDev code, vtable 9 / 10) report the injected keys and
// buttons as held / as buffered events, also while the device is not acquired (window in the background);
// GetCursorPos answers the injected position and GetAsyncKeyState the injected buttons while remote input is active.
typedef HRESULT(WINAPI* DI8CreateFn)(HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN);
typedef HRESULT(STDMETHODCALLTYPE* DICreateDeviceFn)(IDirectInput8A*, REFGUID, LPDIRECTINPUTDEVICE8A*, LPUNKNOWN);
typedef HRESULT(STDMETHODCALLTYPE* GetStateFn)(IDirectInputDevice8A*, DWORD, LPVOID);
typedef HRESULT(STDMETHODCALLTYPE* GetDataFn)(IDirectInputDevice8A*, DWORD, LPDIDEVICEOBJECTDATA, LPDWORD, DWORD);
typedef BOOL(WINAPI* GetCursorPosFn)(LPPOINT);
typedef SHORT(WINAPI* GetAsyncKeyStateFn)(int);
DI8CreateFn g_di8_create = nullptr;
DICreateDeviceFn g_di_create_device = nullptr;
hook::Detour g_getstate_detour, g_getdata_detour;
GetCursorPosFn g_get_cursor = nullptr;
GetAsyncKeyStateFn g_get_async = nullptr;
// every keyboard / mouse device the game creates (live: two of each - the one polled is not always the last)
IDirectInputDevice8A* g_kbs[4] = {nullptr};
IDirectInputDevice8A* g_mice[4] = {nullptr};
int g_nkb = 0, g_nmice = 0;
bool is_kb(IDirectInputDevice8A* d) {
    for (int i = 0; i < g_nkb; i++)
        if (g_kbs[i] == d) return true;
    return false;
}
bool is_mouse(IDirectInputDevice8A* d) {
    for (int i = 0; i < g_nmice; i++)
        if (g_mice[i] == d) return true;
    return false;
}
CRITICAL_SECTION g_in_lock;
unsigned char g_keys[256] = {0};             // DIK -> 0x80 held
volatile bool g_remote_used = false;         // set by the first injected key / click: from then on keep the devices "healthy"
unsigned char g_buttons[8] = {0};            // mouse buttons held
bool g_cursor_on = false;                    // GetCursorPos answers g_cursor
POINT g_cursor{0, 0};
// one event queue PER DEVICE: the game polls two mice each frame (live, "stats") - a shared queue went to whichever
// polled first, and the click never reached the NiInputMouse that PgWinMgr::ProcessInput asks (2016 0x8B860F)
std::vector<DIDEVICEOBJECTDATA> g_kb_q[4], g_ms_q[4];
DWORD g_seq = 1;
LONG g_ms_dx[4] = {0}, g_ms_dy[4] = {0}, g_ms_dz[4] = {0};  // relative motion owed to each mouse's next polled state (di_cursor)
// diagnostics ("stats"): how the game polls its input
volatile LONG g_n_cursor = 0, g_n_async = 0, g_n_state_kb = 0, g_n_state_ms = 0, g_n_data_kb = 0, g_n_data_ms = 0,
              g_n_state_fail = 0, g_n_wndmsg = 0;
POINT g_last_cursor{0, 0};

void push_event(std::vector<DIDEVICEOBJECTDATA>& q, DWORD ofs, DWORD data) {
    DIDEVICEOBJECTDATA e{};
    e.dwOfs = ofs;
    e.dwData = data;
    e.dwTimeStamp = GetTickCount();
    e.dwSequence = g_seq++;
    q.push_back(e);
}

HRESULT STDMETHODCALLTYPE my_get_state(IDirectInputDevice8A* dev, DWORD cb, LPVOID data) {
    HRESULT hr = ((GetStateFn)g_getstate_detour.trampoline)(dev, cb, data);
    bool kb = is_kb(dev), ms = is_mouse(dev);
    if (!kb && !ms) return hr;
    InterlockedIncrement(kb ? &g_n_state_kb : &g_n_state_ms);
    if (FAILED(hr)) InterlockedIncrement(&g_n_state_fail);
    EnterCriticalSection(&g_in_lock);
    bool any = g_cursor_on;
    for (int i = 0; i < 256 && !any; i++) any = g_keys[i] != 0;
    // an unacquired device (the client window not foreground - the operator watching another window) fails EVERY read;
    // between two injected keys the game then saw a lost keyboard and missed the next press edge (2026-10-23: Enter did
    // not open the chat, "state kb N (failed N)"). Once remote input has been used, a failed read is a healthy, empty one
    if (FAILED(hr) && (any || g_remote_used) && data && (hr == DIERR_NOTACQUIRED || hr == DIERR_INPUTLOST || any)) {
        memset(data, 0, cb);
        hr = DI_OK;
    }
    if (SUCCEEDED(hr) && data) {
        if (kb && cb >= 256) {
            for (int i = 0; i < 256; i++) ((unsigned char*)data)[i] |= g_keys[i];
        } else if (ms && cb >= sizeof(DIMOUSESTATE)) {
            DIMOUSESTATE* m = (DIMOUSESTATE*)data;
            for (int i = 0; i < 4; i++) m->rgbButtons[i] |= g_buttons[i];
            for (int i = 0; i < g_nmice; i++)
                if (g_mice[i] == dev) {
                    m->lX += g_ms_dx[i];
                    m->lZ += g_ms_dz[i];
                    m->lY += g_ms_dy[i];
                    g_ms_dx[i] = g_ms_dy[i] = g_ms_dz[i] = 0;
                }
        }
    }
    LeaveCriticalSection(&g_in_lock);
    return hr;
}

HRESULT STDMETHODCALLTYPE my_get_data(IDirectInputDevice8A* dev, DWORD cbo, LPDIDEVICEOBJECTDATA rg, LPDWORD inout,
                                      DWORD flags) {
    DWORD cap = inout ? *inout : 0;
    HRESULT hr = ((GetDataFn)g_getdata_detour.trampoline)(dev, cbo, rg, inout, flags);
    bool kb = is_kb(dev), ms = is_mouse(dev);
    if (kb || ms) InterlockedIncrement(kb ? &g_n_data_kb : &g_n_data_ms);
    if ((!kb && !ms) || !inout) return hr;
    // an unacquired device (the window is not foreground) fails every read, the per-frame flush (rg NULL) included, and
    // NiInputMouse then treats it as lost and drops its button state - so the injected press never became
    // ButtonWasPressed (PgWin press counter 0xD1C7B4 stayed 0, the char-select pick never ran). Once remote input is in
    // use, an unacquired device reads as a healthy, empty one.
    if (g_cursor_on && (hr == DIERR_NOTACQUIRED || hr == DIERR_INPUTLOST)) {
        *inout = 0;
        hr = DI_OK;
    }
    if (!rg || (flags & DIGDD_PEEK)) return hr;
    EnterCriticalSection(&g_in_lock);
    int qi = 0;
    for (int i = 0; i < 4; i++)
        if ((kb ? g_kbs[i] : g_mice[i]) == dev) qi = i;
    std::vector<DIDEVICEOBJECTDATA>& q = kb ? g_kb_q[qi] : g_ms_q[qi];
    if (!q.empty()) {
        if (FAILED(hr)) {
            *inout = 0;
            hr = DI_OK;
        }
        DWORD n = *inout;
        size_t used = 0;
        while (used < q.size() && n < cap) {
            memcpy((char*)rg + (size_t)n * cbo, &q[used],
                   cbo < sizeof(DIDEVICEOBJECTDATA) ? cbo : sizeof(DIDEVICEOBJECTDATA));
            n++;
            used++;
        }
        q.erase(q.begin(), q.begin() + used);
        *inout = n;
    }
    LeaveCriticalSection(&g_in_lock);
    return hr;
}

HRESULT STDMETHODCALLTYPE my_di_create_device(IDirectInput8A* di, REFGUID g, LPDIRECTINPUTDEVICE8A* out, LPUNKNOWN u) {
    HRESULT hr = g_di_create_device(di, g, out, u);
    if (SUCCEEDED(hr) && out && *out) {
        bool kb = IsEqualGUID(g, GUID_SysKeyboard) != 0, ms = IsEqualGUID(g, GUID_SysMouse) != 0;
        if (kb && g_nkb < 4) g_kbs[g_nkb++] = *out;
        if (ms && g_nmice < 4) g_mice[g_nmice++] = *out;
        void** vt = hook::vtable_of(*out);
        if (!g_getstate_detour.installed)
            hook::hook_function("IDirectInputDevice8::GetDeviceState", vt[9], (void*)&my_get_state, &g_getstate_detour);
        if (!g_getdata_detour.installed)
            hook::hook_function("IDirectInputDevice8::GetDeviceData", vt[10], (void*)&my_get_data, &g_getdata_detour);
        hook::log("DirectInput device %p (%s)", *out, kb ? "keyboard" : (ms ? "mouse" : "other"));
    }
    return hr;
}

HRESULT WINAPI my_di8_create(HINSTANCE h, DWORD v, REFIID r, LPVOID* out, LPUNKNOWN u) {
    HRESULT hr = g_di8_create(h, v, r, out, u);
    if (SUCCEEDED(hr) && out && *out && !g_di_create_device)
        g_di_create_device = (DICreateDeviceFn)hook::vtable_set(hook::vtable_of(*out), 3, (void*)&my_di_create_device);
    return hr;
}

BOOL WINAPI my_get_cursor(LPPOINT p) {
    InterlockedIncrement(&g_n_cursor);
    EnterCriticalSection(&g_in_lock);
    bool on = g_cursor_on;
    POINT c = g_cursor;
    LeaveCriticalSection(&g_in_lock);
    if (on && p) {
        *p = c;
        g_last_cursor = c;
        return TRUE;
    }
    BOOL r = g_get_cursor(p);
    if (p) g_last_cursor = *p;
    return r;
}

SHORT WINAPI my_get_async(int vk) {
    InterlockedIncrement(&g_n_async);
    SHORT r = g_get_async(vk);
    EnterCriticalSection(&g_in_lock);
    if (vk == VK_LBUTTON && g_buttons[0]) r |= (SHORT)0x8000;
    if (vk == VK_RBUTTON && g_buttons[1]) r |= (SHORT)0x8000;
    UINT sc = MapVirtualKeyA((UINT)vk, MAPVK_VK_TO_VSC);
    if (sc && sc < 256 && g_keys[sc]) r |= (SHORT)0x8000;
    LeaveCriticalSection(&g_in_lock);
    return r;
}

// the DIK of a virtual key (its scan code; extended keys | 0x80)
UINT dik_of(UINT vk) {
    UINT sc = MapVirtualKeyA(vk, MAPVK_VK_TO_VSC);
    if (vk == VK_LEFT || vk == VK_RIGHT || vk == VK_UP || vk == VK_DOWN || vk == VK_INSERT || vk == VK_DELETE ||
        vk == VK_HOME || vk == VK_END || vk == VK_PRIOR || vk == VK_NEXT || vk == VK_RCONTROL || vk == VK_RMENU)
        sc |= 0x80;
    return sc & 0xFF;
}

void di_key(UINT vk, bool down) {
    UINT dik = dik_of(vk);
    if (!dik) return;
    g_remote_used = true;
    EnterCriticalSection(&g_in_lock);
    g_keys[dik] = down ? 0x80 : 0;
    for (int i = 0; i < g_nkb; i++) push_event(g_kb_q[i], dik, down ? 0x80 : 0);
    LeaveCriticalSection(&g_in_lock);
}

void di_button(int b, bool down) {
    EnterCriticalSection(&g_in_lock);
    g_buttons[b] = down ? 0x80 : 0;
    for (int i = 0; i < g_nmice; i++) push_event(g_ms_q[i], DIMOFS_BUTTON0 + b, down ? 0x80 : 0);
    LeaveCriticalSection(&g_in_lock);
}

// a teleported cursor alone is not enough: the window manager re-hit-tests on mouse MOTION, so without DI deltas the
// click went to the window the cursor was last seen moving over (which consumed the press counter, PgWin 0xD1C7B4).
// Every move also reports the relative motion, as axis events and in the next polled state.
void di_cursor(POINT screen) {
    EnterCriticalSection(&g_in_lock);
    POINT from = g_cursor;
    if (!g_cursor_on) g_get_cursor(&from);
    LONG dx = screen.x - from.x, dy = screen.y - from.y;
    if (!dx && !dy) dx = 1;  // still a motion: the game hit-tests on it
    for (int i = 0; i < g_nmice; i++) {
        push_event(g_ms_q[i], DIMOFS_X, (DWORD)dx);
        push_event(g_ms_q[i], DIMOFS_Y, (DWORD)dy);
        g_ms_dx[i] += dx;
        g_ms_dy[i] += dy;
    }
    g_cursor_on = true;
    g_cursor = screen;
    LeaveCriticalSection(&g_in_lock);
}

// the wheel: the game reads it from DirectInput's mouse Z axis (the camera zoom), not WM_MOUSEWHEEL - as an axis event and
// in the next polled state, like the motion (WHEEL_DELTA 120 per notch, positive = away from the user)
void di_wheel(LONG dz) {
    g_remote_used = true;
    EnterCriticalSection(&g_in_lock);
    for (int i = 0; i < g_nmice; i++) {
        push_event(g_ms_q[i], DIMOFS_Z, (DWORD)dz);
        g_ms_dz[i] += dz;
    }
    LeaveCriticalSection(&g_in_lock);
}

// ---- address remap ---------------------------------------------------------------------------------------------------
// hooks\remote_control.ini [config] remap=<from ip>><to ip>: a connect() to <from> goes to <to> (same port). For a client
// on the bridge's own machine: the bridge hands out its advertised address (the LAN one the operator's client dials),
// which this machine may not reach - remap=172.31.248.91>127.0.0.1. ws2_32!connect is detoured (any import path).
typedef int(WSAAPI* ConnectFn)(SOCKET, const sockaddr*, int);
hook::Detour g_connect_detour;
in_addr g_remap_from{}, g_remap_to{};
bool g_remap = false;

int WSAAPI my_connect(SOCKET s, const sockaddr* a, int len) {
    if (g_remap && a && a->sa_family == AF_INET && len >= (int)sizeof(sockaddr_in) &&
        ((const sockaddr_in*)a)->sin_addr.s_addr == g_remap_from.s_addr) {
        sockaddr_in c = *(const sockaddr_in*)a;
        c.sin_addr = g_remap_to;
        hook::log("connect: remapped to port %u on the local address", ntohs(c.sin_port));
        return ((ConnectFn)g_connect_detour.trampoline)(s, (const sockaddr*)&c, sizeof(c));
    }
    return ((ConnectFn)g_connect_detour.trampoline)(s, a, len);
}

// a client address for the running build (client_addrs.h), rebased - the exe is ASLR-relocated
void* at(caddr::Sym s) { return hook::rebase(caddr::va(s)); }

// 2026 0x4746A0 = CharSelectFrameWork::ProcessInput (thiscall, no args; 2016 0x411F20): the game-thread tick -char uses

typedef void(__fastcall* VoidThisFn)(void*, void*);
hook::Detour g_csinput_detour;
volatile void* g_cs = nullptr;   // the live CharSelectFrameWork ("stats" shows it)
void __fastcall my_cs_input(void* self, void* edx) {
    g_cs = self;
    ((VoidThisFn)g_csinput_detour.trampoline)(self, edx);
    auto_char_tick(self);
}

// ---- -stdinlogin ------------------------------------------------------------------------------------------------------
// Fiesta.exe ... -stdinlogin: the launcher pipes "<user>\n<password>\n" into stdin (never on the command line, where the
// process list would show it). Read once at load; the moment the login form has a focused PgEditWin the account is
// typed, Tab, the password, Enter - no waiting on a scripted delay. The buffer is wiped once used.
char g_login[2][128] = {{0}};
bool g_stdin_login = false;

void read_stdin_login() {
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    if (!in || in == INVALID_HANDLE_VALUE) {
        hook::log("-stdinlogin: no stdin");
        return;
    }
    char buf[300] = {0};
    DWORD got = 0, n = 0;
    while (got < sizeof(buf) - 1 && ReadFile(in, buf + got, (DWORD)(sizeof(buf) - 1 - got), &n, nullptr) && n) {
        got += n;
        int lines = 0;
        for (DWORD i = 0; i < got; i++) lines += buf[i] == '\n';
        if (lines >= 2) break;
    }
    int f = 0, k = 0;
    for (DWORD i = 0; i < got && f < 2; i++) {
        char c = buf[i];
        if (c == '\r') continue;
        if (c == '\n') { f++; k = 0; continue; }
        if (k < 127) g_login[f][k++] = c;
    }
    SecureZeroMemory(buf, sizeof(buf));
    g_stdin_login = g_login[0][0] && g_login[1][0];
    hook::log("-stdinlogin: %s", g_stdin_login ? "account read" : "stdin had no user/password lines");
}

void tap(HWND top, UINT vk) {
    HWND kw = key_window(top);
    if (kw != input_window(top)) send_key(kw, vk, 1);
    di_key(vk, true);
    Sleep(150);
    di_key(vk, false);
    if (kw != input_window(top)) send_key(kw, vk, 2);
}

void type_into_focus(HWND top, const char* t) {
    HWND kw = key_window(top);
    for (const char* p = t; *p; p++) PostMessageA(kw, WM_CHAR, (unsigned char)*p, 1);
}

DWORD WINAPI auto_login(LPVOID) {
    for (int i = 0; i < 6000; i++) {   // up to 10 min of patch / intro
        HWND top = game_window();
        if (top && key_window(top) != input_window(top)) {
            Sleep(300);                  // let the form finish building around the field
            type_into_focus(top, g_login[0]);
            Sleep(100);
            tap(top, VK_TAB);
            Sleep(100);
            type_into_focus(top, g_login[1]);
            Sleep(100);
            tap(top, VK_RETURN);
            hook::log("-stdinlogin: login form filled and submitted after %d ms", i * 100);
            SecureZeroMemory(g_login, sizeof(g_login));
            return 0;
        }
        Sleep(100);
    }
    hook::log("-stdinlogin: no login field appeared");
    SecureZeroMemory(g_login, sizeof(g_login));
    return 0;
}

// ---- auto world / character select ------------------------------------------------------------------------------------
// -world <index>: the server list's index (display order) to join; without it, a list of exactly one world is joined.
// -char <slot>: the character slot to select at char select (then Enter). Both act on the game thread (Present),
// through the client's own functions:
//   WorldSelectWin::UpdateServerBtnState(btn) 2026 0x55DF30 (page [+0x158], selected world number [+0x15C]; world
//   count 0xC32584, list 0xC32588: 18-byte entries, number at +0x10) and OnCmdOk(bool) 0x55E120 -> WorldSelectOk ->
//   NC_USER_WORLDSELECT_REQ; CharSelectFrameWork::SelectAvatar(page slot) 0x473A60 (page [+0x134], 6 per page).
// The WorldSelectWin object is captured by signature-agnostic stubs on its own virtuals (2026 vtable 0xB15xxx).
int g_want_world = -1, g_want_char = -1;
volatile void* g_ws = nullptr;
volatile DWORD g_ws_tick = 0;
bool g_world_done = false;
typedef void(__fastcall* IntThisFn)(void*, void*, int);

#define WS_STUB(N, VA)                                                                                                  \
    hook::Detour g_ws_detour##N;                                                                                        \
    void* g_ws_tramp##N = nullptr;                                                                                      \
    __declspec(naked) void ws_stub##N() {                                                                               \
        __asm { mov g_ws, ecx }                                                                                         \
        __asm { jmp g_ws_tramp##N }                                                                                     \
    }
WS_STUB(0, 0x55C340)
WS_STUB(1, 0x55E4B0)
WS_STUB(2, 0x55CA80)
WS_STUB(3, 0x55CC00)
WS_STUB(4, 0x55E020)

void hook_ws_stubs() {
    struct { caddr::Sym sym; void* stub; hook::Detour* d; void** tramp; } t[] = {
        {caddr::kWorldSelectVirtual0, (void*)&ws_stub0, &g_ws_detour0, &g_ws_tramp0},
        {caddr::kWorldSelectVirtual1, (void*)&ws_stub1, &g_ws_detour1, &g_ws_tramp1},
        {caddr::kWorldSelectVirtual2, (void*)&ws_stub2, &g_ws_detour2, &g_ws_tramp2},
        {caddr::kWorldSelectVirtual3, (void*)&ws_stub3, &g_ws_detour3, &g_ws_tramp3},
        {caddr::kWorldSelectVirtual4, (void*)&ws_stub4, &g_ws_detour4, &g_ws_tramp4}};
    for (auto& e : t)
        if (hook::hook_function(caddr::kNames[e.sym], at(e.sym), e.stub, e.d)) *e.tramp = e.d->trampoline;
}

// the switch itself, as a whole word ("-char" is not "-charname"), or nullptr
const char* find_switch(const char* name) {
    size_t n = strlen(name);
    for (const char* c = strstr(GetCommandLineA(), name); c; c = strstr(c + 1, name))
        if (c[n] == ' ' || c[n] == 0) return c + n;
    return nullptr;
}

int arg_int(const char* name) {
    const char* c = find_switch(name);
    if (!c) return -1;
    while (*c == ' ') c++;
    return (*c >= '0' && *c <= '9') ? atoi(c) : -1;
}

// the value after a command-line switch ("-charname GateBot"), up to the next space
void arg_str(const char* name, char* out, size_t cap) {
    out[0] = 0;
    const char* c = find_switch(name);
    if (!c) return;
    while (*c == ' ') c++;
    size_t k = 0;
    while (*c && *c != ' ' && *c != '"' && k + 1 < cap) out[k++] = *c++;
    out[k] = 0;
}

// -charname: the slot comes from the character list, NC_USER_LOGINWORLD_ACK (0x0C0F) from the world manager:
// [worldmanager u16][numofavatar u8] ... numofavatar records. Each record starts like the 2016 PDB's
// PROTO_AVATARINFORMATION (chrregnum u32 +0, name Name5 +4, level u16 +0x18, slot u8 +0x1A) but is 161 bytes on the
// 2026 wire, not 130 - READ FROM A CAPTURE (bridge log, 5 avatars in 827 bytes: names at 26 + 161*i), the 2026 record
// is not traced field by field. The records are taken as the packet's last numofavatar * 161 bytes.
char g_want_name[32] = {0};
const int kAvatarRecord = 161;

bool on_avatar_list(const client::Packet& p) {
    if (p.op != 0x0C0F || p.len < 3) return false;
    int n = p.data[2];
    int first = p.len - n * kAvatarRecord;
    if (first < 3) {
        hook::log("avatar list: %d avatars do not fit %d bytes of %d-byte records", n, p.len, kAvatarRecord);
        return false;
    }
    for (int i = 0; i < n; i++) {
        const unsigned char* r = p.data + first + i * kAvatarRecord;
        char name[21] = {0};
        memcpy(name, r + 4, 20);
        int slot = r[0x1A], level = r[0x18] | (r[0x19] << 8);
        bool pick = g_want_name[0] && _stricmp(name, g_want_name) == 0;
        if (pick) g_want_char = slot;
        hook::log("avatar list: slot %d %s level %d%s", slot, name, level, pick ? "  <- -charname" : "");
    }
    if (g_want_name[0] && g_want_char < 0) hook::log("avatar list: no character named %s", g_want_name);
    return false;
}

// -burst <dir> [-burstsecs N]: screenshots 4 a second for N seconds (default 10) from the moment the client reports the
// map loaded - it sends NC_MAP_LOGINCOMPLETE_CMD (0x1803) when its loading screen ends - as <dir>/NNN.bmp (frame NNN is
// at NNN * 0.25 s). The same start and cadence as fiesta-godot's --shot-times, for a frame-by-frame comparison.
char g_burst_dir[MAX_PATH] = {0};
int g_burst_secs = 10;
volatile LONG g_burst_started = 0;

DWORD WINAPI burst_worker(LPVOID) {
    DWORD t0 = GetTickCount();
    int frames = g_burst_secs * 4;
    for (int k = 0; k < frames; k++) {
        DWORD due = t0 + (DWORD)k * 250;
        DWORD now = GetTickCount();
        if (due > now) Sleep(due - now);
        char path[MAX_PATH];
        sprintf_s(path, "%s\\%03d.bmp", g_burst_dir, k);
        bool ok = d3d_shot(path);
        if (!ok || k % 4 == 0) hook::log("burst %03d at %lu ms: %s", k, GetTickCount() - t0, ok ? "ok" : "FAILED");
    }
    hook::log("burst: %d frames in %s", frames, g_burst_dir);
    return 0;
}

void on_sent(const client::Packet& p) {
    if (p.op == 0x1803 && g_burst_dir[0] && InterlockedExchange(&g_burst_started, 1) == 0) {
        hook::log("burst: map login complete (0x1803) - %d s of shots at 4/s into %s", g_burst_secs, g_burst_dir);
        CreateThread(nullptr, 0, burst_worker, nullptr, 0, nullptr);
    }
}

// game thread, once per frame
void auto_world_tick() {
    if (g_world_done || !g_ws) return;
    int n = *(int*)at(caddr::kWorldListCount);
    int idx = g_want_world >= 0 ? g_want_world : (n == 1 ? 0 : -1);
    if (n <= 0 || idx < 0) return;
    g_world_done = true;
    if (idx >= n) {
        hook::log("auto world: index %d but the list has %d", idx, n);
        return;
    }
    char* ws = (char*)g_ws;
    *(int*)(ws + 0x158) = idx / 8;
    ((IntThisFn)at(caddr::kWorldSelectBtnState))(ws, nullptr, idx % 8);
    hook::log("auto world: index %d of %d -> world %d, joining", idx, n, *(int*)(ws + 0x15C));
    ((IntThisFn)at(caddr::kWorldSelectCmdOk))(ws, nullptr, 1);
}

// game thread, char select's ProcessInput. SelectAvatar on the already-selected slot is the second click that logs in
// (its bl == dl branch, 2026 0x473AD5 -> 0x473C8D), so: select, and a second later select again.
DWORD g_char_at = 0;
int g_char_step = 0;
void auto_char_tick(void* cs) {
    if (g_char_step >= 2 || g_want_char < 0) return;
    if (g_char_step == 1 && GetTickCount() - g_char_at < 1000) return;
    int page = *(unsigned char*)((char*)cs + 0x134);
    if (g_want_char / 6 != page) {
        g_char_step = 2;
        hook::log("auto char: slot %d is not on the shown page %d", g_want_char, page);
        return;
    }
    ((IntThisFn)at(caddr::kCharSelectSelectAvatar))(cs, nullptr, g_want_char % 6);
    hook::log(g_char_step == 0 ? "auto char: slot %d selected" : "auto char: slot %d confirmed, entering", g_want_char);
    g_char_step++;
    g_char_at = GetTickCount();
}

// ---- "wins [class]": the UI as the client has it ------------------------------------------------------------------------
// Every window the window manager holds (PgWinMgr caddr::kWinMgr: a NiTPointerList at +0x24 - head +0x28, count +0x30;
// items {next, prev, element}, read off PgWinMgr::IsIn 10.6.6 0x8824F0) with its RTTI class and GetXPos / GetYPos /
// GetWidth / GetHeight (vtable +0xA4 / +0xA8 / +0x90 / +0x94, as popup_windows reads them). The list is flat: each
// window is followed by its controls (positions relative to it). For pixel-exact layout comparisons with fiesta-godot.
// (A scan of a window's fields for child controls was removed: it called getters on misidentified objects and hung.)
typedef int(__fastcall* WinGetter)(void*, void*);

bool win_rect(void* w, int* x, int* y, int* wd, int* ht) {
    __try {
        *x = ((WinGetter)pgwin::vtable_entry(w, 0xA4 / 4))(w, nullptr);
        *y = ((WinGetter)pgwin::vtable_entry(w, 0xA8 / 4))(w, nullptr);
        *wd = ((WinGetter)pgwin::vtable_entry(w, 0x90 / 4))(w, nullptr);
        *ht = ((WinGetter)pgwin::vtable_entry(w, 0x94 / 4))(w, nullptr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// an RTTI name only when it looks like one (".?A", printable, NUL within 120): a non-polymorphic object's "class" is
// random bytes, and printing those into a fixed buffer tripped sprintf_s's invalid-parameter handler (the probe hang)
const char* safe_class(void* w) {
    __try {
        const char* c = pgwin::class_of(w);
        if (!c || c[0] != '.' || c[1] != '?' || c[2] != 'A') return "?";
        for (int i = 0; i < 120; i++) {
            if (!c[i]) return c;
            if ((unsigned char)c[i] < 32 || (unsigned char)c[i] > 126) return "?";
        }
        return "?";
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return "?";
    }
}

void* read_ptr(const void* a) {
    __try {
        return *(void* const*)a;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// A window's / control's name and screen place (operator 2026-10-22: the mouse coordinates of individual controls).
// PgWin derives from NiNode: SetWinName (vtable +0x8C, 2016 0x401CA0) is NiObjectNET::SetName, so the name is the
// NiFixedString at +8 (a char*, the NIF sprite's node name - "ClsNor", "Btn01Nor"); GetWinScreenRect (vtable +0xD8,
// 2016 0x401F00, the slot verified against GetXPos +0xA4 / GetWidth +0x90 in the same vtable) gives the screen RECT -
// client-area pixels, what a click takes; the parent NiNode at +0x20 (2016 GetParentWin 0x402410).
typedef void(__fastcall* ScreenRectFn)(void*, void*, RECT*);

bool win_screen_rect(void* w, RECT* r) {
    __try {
        ((ScreenRectFn)pgwin::vtable_entry(w, 0xD8 / 4))(w, nullptr, r);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

const char* win_name(void* w) {
    __try {
        const char* n = *(const char**)((char*)w + 8);
        if (!n) return "";
        for (int i = 0; i < 64; i++) {
            if (!n[i]) return n;
            if ((unsigned char)n[i] < 32 || (unsigned char)n[i] > 126) return "";
        }
        return "";
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return "";
    }
}

// "ctl <name> [n]": the n-th (default first) visible-or-not control whose name equals <name> (case-insensitive):
// "<screen x> <screen y> <w> <h> <class> @<ptr>" - its centre is what a click wants
std::string find_ctl(const char* want, int nth) {
    char* mgr = (char*)hook::rebase(caddr::va(caddr::kWinMgr));
    if (!caddr::va(caddr::kWinMgr)) return "err no PgWinMgr address for this build";
    void* item = read_ptr(mgr + 0x28);
    char b[200];
    for (int n = 0; item && n < 50000; n++, item = read_ptr(item)) {
        void* w = read_ptr((char*)item + 8);
        if (!w || _stricmp(win_name(w), want) != 0) continue;
        if (nth-- > 0) continue;
        RECT r{};
        if (!win_screen_rect(w, &r)) return "err no screen rect";
        sprintf_s(b, "ok %ld %ld %ld %ld %s @%p", r.left, r.top, r.right - r.left, r.bottom - r.top, safe_class(w), w);
        return b;
    }
    return "err no such control";
}

// "probe <ptr>": each dword of an object's first 0x200 bytes that points at something with an NiObjectNET-style name
// (+8) or an RTTI class - to find where a control keeps the NIF sprites it was built from
std::string probe(void* o) {
    std::string out = "ok";
    char b[320];
    for (int off = 0; off < 0x200; off += 4) {
        void* p = read_ptr((char*)o + off);
        if (!p || (uintptr_t)p < 0x10000) continue;
        const char* nm = win_name(p);
        const char* cls = safe_class(p);
        if ((nm && nm[0]) || (cls && cls[0] != '?')) {
            sprintf_s(b, " | +%X %p %s \"%s\"", off, p, cls, nm);
            out += b;
        }
    }
    return out;
}

std::string dump_wins(const char* filter) {
    std::string out = "ok";
    char* mgr = (char*)hook::rebase(caddr::va(caddr::kWinMgr));
    if (!caddr::va(caddr::kWinMgr)) return "err no PgWinMgr address for this build";
    void* item = read_ptr(mgr + 0x28);
    char b[300];
    int tail = 0;                        // with a filter: a matching window and the 40 entries after it (its controls)
    for (int n = 0; item && n < 50000; n++, item = read_ptr(item)) {
        void* w = read_ptr((char*)item + 8);
        if (!w) continue;
        int x = 0, y = 0, wd = 0, ht = 0;
        if (!win_rect(w, &x, &y, &wd, &ht)) continue;
        const char* cls = safe_class(w);
        if (filter[0]) {
            if (strstr(cls, filter) || strstr(win_name(w), filter)) tail = 41;
            if (tail <= 0) continue;
            tail--;
        }
        RECT sr{};
        bool has_sr = win_screen_rect(w, &sr);
        sprintf_s(b, " | %s \"%s\" %d %d %d %d screen %ld %ld @%p parent %p", cls, win_name(w), x, y, wd, ht,
                  has_sr ? sr.left : -1L, has_sr ? sr.top : -1L, w, read_ptr((char*)w + 0x20));
        out += b;
    }
    return out;
}

// "wins" runs on the game thread (the window list changes under it otherwise): the serve thread posts the request, the
// Present hook answers it, the serve thread waits up to 3 s
CRITICAL_SECTION g_wins_lock;
HANDLE g_wins_done = nullptr;
volatile LONG g_wins_pending = 0;
volatile LONG g_ctl_pending = 0;      // the request is "ctl", not "wins"
std::string g_wins_result;
std::string g_wins_filter;

void wins_tick() {
    if (!g_wins_pending) return;
    std::string r;
    if (g_ctl_pending) {
        char name[128] = {0};
        int nth = 0;
        sscanf_s(g_wins_filter.c_str(), "%127s %d", name, (unsigned)sizeof(name), &nth);
        r = find_ctl(name, nth);
        InterlockedExchange(&g_ctl_pending, 0);
    } else {
        r = dump_wins(g_wins_filter.c_str());
    }
    EnterCriticalSection(&g_wins_lock);
    g_wins_result = r;
    LeaveCriticalSection(&g_wins_lock);
    InterlockedExchange(&g_wins_pending, 0);
    SetEvent(g_wins_done);
}

std::string wins_on_game_thread(const char* filter) {
    g_wins_filter = filter;
    ResetEvent(g_wins_done);
    InterlockedExchange(&g_wins_pending, 1);
    if (WaitForSingleObject(g_wins_done, 3000) != WAIT_OBJECT_0) {
        InterlockedExchange(&g_wins_pending, 0);
        return "err the game thread did not answer (no frame presented)";
    }
    EnterCriticalSection(&g_wins_lock);
    std::string r = g_wins_result;
    LeaveCriticalSection(&g_wins_lock);
    return r;
}

// "ctl" rides the "wins" game-thread channel with a flag
std::string ctl_on_game_thread(const char* arg) {
    InterlockedExchange(&g_ctl_pending, 1);
    return wins_on_game_thread(arg);
}

std::string handle(const std::string& line) {
    char cmd[32] = {0};
    if (sscanf_s(line.c_str(), "%31s", cmd, (unsigned)sizeof(cmd)) != 1) return "err empty";
    std::string c = cmd;
    if (c == "ping") return "ok pong";
    HWND w = game_window();
    if (!w) return "err no game window";
    const char* rest = line.c_str() + c.size();
    while (*rest == ' ') rest++;
    if (c == "peek") {   // peek <va> [len]: exe-relative (2026 VA, rebased) or, with *, an absolute address; hex + ascii
        char as[32] = {0};
        unsigned len = 64;
        sscanf_s(rest, "%31s %u", as, (unsigned)sizeof(as), &len);
        const char* t = as[0] == '*' ? as + 1 : as;
        DWORD v = strtoul(t, nullptr, 16);
        const unsigned char* src = as[0] == '*' ? (const unsigned char*)(uintptr_t)v : (const unsigned char*)hook::rebase(v);
        if (len > 4096) len = 4096;
        std::vector<unsigned char> buf(len);
        SIZE_T got = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), src, buf.data(), len, &got) || !got) return "err unreadable";
        std::string out = "ok";
        char h[16];
        for (SIZE_T i = 0; i < got; i++) {
            if (i % 16 == 0) { sprintf_s(h, " | %04x ", (unsigned)i); out += h; }
            sprintf_s(h, "%02x", buf[i]);
            out += h;
            if (i % 16 == 15 || i + 1 == got) {
                out += "  ";
                for (SIZE_T j = i - i % 16; j <= i; j++) out += (buf[j] >= 32 && buf[j] < 127) ? (char)buf[j] : '.';
            }
        }
        return out;
    }
    if (c == "find") {   // find <text>: addresses (up to 16) of <text> in committed read/write memory
        std::string needle(rest);
        if (needle.empty()) return "err find <text>";
        std::string out = "ok";
        int hits = 0;
        MEMORY_BASIC_INFORMATION mi;
        for (char* a = nullptr; hits < 16 && VirtualQuery(a, &mi, sizeof(mi)) == sizeof(mi);
             a = (char*)mi.BaseAddress + mi.RegionSize) {
            if (mi.State != MEM_COMMIT || (mi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) ||
                !(mi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)))
                continue;
            std::vector<char> buf(mi.RegionSize);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), mi.BaseAddress, buf.data(), mi.RegionSize, &got)) continue;
            for (size_t i = 0; hits < 16 && i + needle.size() <= got; i++)
                if (buf[i] == needle[0] && memcmp(&buf[i], needle.data(), needle.size()) == 0) {
                    char h[24];
                    sprintf_s(h, " %p", (char*)mi.BaseAddress + i);
                    out += h;
                    hits++;
                }
        }
        return out;
    }
    if (c == "wins") return wins_on_game_thread(rest);
    if (c == "ctl") return ctl_on_game_thread(rest);
    if (c == "probe") return probe((void*)strtoul(rest, nullptr, 16));
    if (c == "char") {   // char <slot>: pick (and enter) that character again at the next character select
        g_want_char = atoi(rest);
        g_char_step = 0;
        return "ok";
    }
    if (c == "stats") {
        char b[400];
        sprintf_s(b, "ok cs %p ms %d,%d cursor %ld (last %ld,%ld) async %ld state kb %ld ms %ld (failed %ld) data kb %ld ms %ld devices kb %d ms %d",
                  g_cs, ((int*)at(caddr::kPgWinMouseX))[0], ((int*)at(caddr::kPgWinMouseX))[1], g_n_cursor, g_last_cursor.x, g_last_cursor.y, g_n_async, g_n_state_kb, g_n_state_ms, g_n_state_fail,
                  g_n_data_kb, g_n_data_ms, g_nkb, g_nmice);
        return b;
    }
    if (c == "size") {
        RECT r{};
        GetClientRect(w, &r);
        char b[64];
        sprintf_s(b, "ok %ld %ld", r.right, r.bottom);
        return b;
    }
    if (c == "key") {
        char vks[32] = {0}, mode[16] = "press";
        if (sscanf_s(rest, "%31s %15s", vks, (unsigned)sizeof(vks), mode, (unsigned)sizeof(mode)) < 1) return "err key <vk>";
        UINT vk = (UINT)strtoul(vks, nullptr, 0);
        int m = strcmp(mode, "down") == 0 ? 1 : (strcmp(mode, "up") == 0 ? 2 : 0);
        // both paths: an edit control with the focus takes its own WM_KEYDOWN / UP (Backspace in a field); the game
        // itself reads DirectInput (Tab between the login fields, Enter through the menus)
        HWND kw = key_window(w);
        if (kw != input_window(w)) send_key(kw, vk, m == 0 ? 1 : m);
        if (m != 2) di_key(vk, true);
        if (m == 0) wait_frames(2);              // held across two presented frames (one the game surely polled)
        if (m != 1) di_key(vk, false);
        if (m == 0 && kw != input_window(w)) send_key(kw, vk, 2);
        if (m == 0) wait_frames(1);              // its effect (a window opening) is there before the next command
        return "ok";
    }
    if (c == "text") {
        wait_frames(1);                          // a field focused by the previous command takes it from the next frame
        HWND kw = key_window(w);
        for (const char* p = rest; *p; p++) PostMessageA(kw, WM_CHAR, (unsigned char)*p, 1);
        wait_frames(1);
        return "ok";
    }
    // say <line>: a chat line (GM commands too) as a player types it - Enter opens the chat input a frame later, the
    // text goes into that edit once it is open, Enter sends
    if (c == "say") {
        auto press = [&](UINT vk) {
            HWND k = key_window(w);
            if (k != input_window(w)) send_key(k, vk, 1);
            di_key(vk, true);
            wait_frames(2);
            di_key(vk, false);
            if (k != input_window(w)) send_key(k, vk, 2);
            wait_frames(1);
        };
        // the 2026 chat input is the game's own edit (no Win32 focus to watch): characters posted to the render window
        // land in it once it is open - Enter, then three presented frames for it to open
        press(VK_RETURN);
        wait_frames(3);
        HWND kw = key_window(w);
        for (const char* p = rest; *p; p++) PostMessageA(kw, WM_CHAR, (unsigned char)*p, 1);
        wait_frames(2);
        press(VK_RETURN);
        return "ok";
    }
    int x = 0, y = 0;
    char btn[16] = "left";
    if (c == "move" || c == "click" || c == "down" || c == "up" || c == "wheel") {
        int extra = 0;
        int got = sscanf_s(rest, "%d %d %15s", &x, &y, btn, (unsigned)sizeof(btn));
        if (got < 2) return "err " + c + " <x> <y>";
        if (c == "wheel") extra = atoi(btn);
        bool right = strcmp(btn, "right") == 0;
        HWND top = w;
        w = input_window(top);
        UINT dn = right ? WM_RBUTTONDOWN : WM_LBUTTONDOWN, upm = right ? WM_RBUTTONUP : WM_LBUTTONUP;
        WPARAM held = right ? MK_RBUTTON : MK_LBUTTON;
        POINT sp{x, y};
        ClientToScreen(top, &sp);
        int b = right ? 1 : 0;
        di_cursor(sp);                           // the game's GetCursorPos reads this from now on
        if (c == "move") {
            mouse(w, WM_MOUSEMOVE, x, y, 0);
        } else if (c == "click") {
            mouse(w, WM_MOUSEMOVE, x, y, 0);
            Sleep(250);                          // a frame or two at the new place before the press
            di_button(b, true);
            mouse(w, dn, x, y, held);
            Sleep(250);
            di_button(b, false);
            mouse(w, upm, x, y, 0);
        } else if (c == "down") {
            di_button(b, true);
            mouse(w, dn, x, y, held);
        } else if (c == "up") {
            di_button(b, false);
            mouse(w, upm, x, y, 0);
        } else {
            di_wheel(extra);
            PostMessageA(w, WM_MOUSEWHEEL, MAKEWPARAM(0, (short)extra), MAKELPARAM(sp.x, sp.y));
        }
        return "ok";
    }
    if (c == "shot") {
        if (!*rest) return "err shot <path>";
        if (d3d_shot(rest)) return "ok";
        return screenshot(input_window(w), rest) ? "ok (window capture)" : "err capture failed";
    }
    return "err unknown command " + c;
}

DWORD WINAPI serve(LPVOID) {
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) {
        hook::log("WSAStartup failed");
        return 0;
    }
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons((u_short)g_port);
    inet_pton(AF_INET, g_bind, &a.sin_addr);
    if (bind(ls, (sockaddr*)&a, sizeof(a)) != 0 || listen(ls, 1) != 0) {
        hook::log("cannot listen on %s:%d (%d)", g_bind, g_port, WSAGetLastError());
        return 0;
    }
    hook::log("listening on %s:%d", g_bind, g_port);
    for (;;) {
        SOCKET s = accept(ls, nullptr, nullptr);
        if (s == INVALID_SOCKET) continue;
        hook::log("controller connected");
        std::string buf;
        char tmp[1024];
        for (;;) {
            int n = recv(s, tmp, sizeof(tmp), 0);
            if (n <= 0) break;
            buf.append(tmp, n);
            size_t nl;
            bool quit = false;
            while ((nl = buf.find('\n')) != std::string::npos) {
                std::string line = buf.substr(0, nl);
                buf.erase(0, nl + 1);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line == "quit") {
                    quit = true;
                    break;
                }
                std::string reply = handle(line) + "\n";
                send(s, reply.data(), (int)reply.size(), 0);
            }
            if (quit) break;
        }
        closesocket(s);
        hook::log("controller gone");
    }
}

}  // namespace

HOOK_PLUGIN("remote_control") {
    char ini[MAX_PATH];
    HMODULE self = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&serve, &self);
    GetModuleFileNameA(self, ini, MAX_PATH);
    char* dot = strrchr(ini, '.');
    if (dot) strcpy_s(dot, MAX_PATH - (dot - ini), ".ini");
    g_port = GetPrivateProfileIntA("config", "port", 27015, ini);
    GetPrivateProfileStringA("config", "bind", "127.0.0.1", g_bind, sizeof(g_bind), ini);
    InitializeCriticalSection(&g_cap_lock);
    InitializeCriticalSection(&g_in_lock);
    InitializeCriticalSection(&g_wins_lock);
    g_wins_done = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (const char* m = caddr::missing({caddr::kCharSelectProcessInput, caddr::kCharSelectSelectAvatar,
                                        caddr::kWorldSelectBtnState, caddr::kWorldSelectCmdOk, caddr::kWorldListCount,
                                        caddr::kPgWinMouseX, caddr::kWorldSelectVirtual0, caddr::kWorldSelectVirtual1,
                                        caddr::kWorldSelectVirtual2, caddr::kWorldSelectVirtual3,
                                        caddr::kWorldSelectVirtual4})) {
        hook::log("remote_control: %s - no auto world / char select", m);
    } else {
        g_want_world = arg_int("-world");
        g_want_char = arg_int("-char");
        arg_str("-charname", g_want_name, sizeof(g_want_name));
        hook::hook_function("CharSelectFrameWork::ProcessInput", at(caddr::kCharSelectProcessInput), (void*)&my_cs_input,
                            &g_csinput_detour);
        hook_ws_stubs();
        if (g_want_name[0] && !client::on_packet(on_avatar_list))
            hook::log("remote_control: no packet hook - -charname %s cannot be resolved", g_want_name);
    }
    char remap[128] = {0};
    GetPrivateProfileStringA("config", "remap", "", remap, sizeof(remap), ini);
    char* gt = strchr(remap, '>');
    if (gt) {
        *gt = 0;
        if (inet_pton(AF_INET, remap, &g_remap_from) == 1 && inet_pton(AF_INET, gt + 1, &g_remap_to) == 1) {
            HMODULE ws = LoadLibraryA("ws2_32.dll");
            g_remap = hook::hook_function("ws2_32!connect", ws ? (void*)GetProcAddress(ws, "connect") : nullptr,
                                          (void*)&my_connect, &g_connect_detour);
            hook::log("remap %s -> %s: %s", remap, gt + 1, g_remap ? "on" : "FAILED");
        }
    }
    if (strstr(GetCommandLineA(), "-stdinlogin")) read_stdin_login();
    arg_str("-burst", g_burst_dir, sizeof(g_burst_dir));
    if (arg_int("-burstsecs") > 0) g_burst_secs = arg_int("-burstsecs");
    if (g_burst_dir[0]) {
        CreateDirectoryA(g_burst_dir, nullptr);
        if (!client::on_send(on_sent)) hook::log("remote_control: no send hook - -burst cannot start");
    }
    HMODULE exe = GetModuleHandleA(nullptr);
    g_di8_create = (DI8CreateFn)hook::iat_hook(exe, "DINPUT8.dll", "DirectInput8Create", (void*)&my_di8_create);
    g_get_cursor = (GetCursorPosFn)hook::iat_hook(exe, "USER32.dll", "GetCursorPos", (void*)&my_get_cursor);
    g_get_async = (GetAsyncKeyStateFn)hook::iat_hook(exe, "USER32.dll", "GetAsyncKeyState", (void*)&my_get_async);
    hook::log("input hooks: DirectInput8Create %s, GetCursorPos %s, GetAsyncKeyState %s", g_di8_create ? "ok" : "MISSING",
              g_get_cursor ? "ok" : "MISSING", g_get_async ? "ok" : "MISSING");
    g_cap_done = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    g_message_box = (MessageBoxA_t)hook::iat_hook(nullptr, "USER32.dll", "MessageBoxA", (void*)&my_message_box);
    hook::log(g_message_box ? "MessageBoxA hooked (text + stack logged)" : "no MessageBoxA import to hook");
    HMODULE d3d9 = LoadLibraryA("d3d9.dll");
    void* c9 = d3d9 ? (void*)GetProcAddress(d3d9, "Direct3DCreate9") : nullptr;
    if (!hook::hook_function("Direct3DCreate9", c9, (void*)&my_create9, &g_create9_detour))
        hook::log("no Direct3DCreate9 hook: shots fall back to the window capture");
    CreateThread(nullptr, 0, serve, nullptr, 0, nullptr);
    if (g_stdin_login) CreateThread(nullptr, 0, auto_login, nullptr, 0, nullptr);
}
