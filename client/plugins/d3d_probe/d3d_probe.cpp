// d3d_probe - logs what the official client hands Direct3D for texture stages: the texture-transform matrices
// (SetTransform D3DTS_TEXTUREn), the stage's texture (SetTexture, its size / format) and the sampler address modes
// (SetSamplerState ADDRESSU / ADDRESSV). A research probe for fiesta-godot's texture-transform parity (operator
// 2026-10-23: "RE the exe, you can write an extra hook to read exact info out of official" - Frost Nova's crystals).
//
// ---- HOW ----------------------------------------------------------------------------------------------------------
//   Every IDirect3DDevice9 shares one vtable inside d3d9.dll. A throw-away device made on a hidden window gives its
//   address; the three entries (SetTransform 44, SetTexture 65, SetSamplerState 69) are patched there, so the game's
//   own device calls ours, which log and forward. Done from a thread a few seconds after load (no loader lock, d3d9
//   loaded by then).
//   Logged only when a stage's matrix / texture / address modes CHANGE and the matrix has a translation (texture
//   animation), at most `limit` lines (hooks\d3d_probe.ini [config] limit=4000). hook::log has no %f: values x 1000.
#include <hook_core.h>

#include <windows.h>
#include <d3d9.h>

#include <cstring>

namespace {

typedef HRESULT(__stdcall* SetTransformFn)(IDirect3DDevice9*, D3DTRANSFORMSTATETYPE, const D3DMATRIX*);
typedef HRESULT(__stdcall* SetTextureFn)(IDirect3DDevice9*, DWORD, IDirect3DBaseTexture9*);
typedef HRESULT(__stdcall* SetSamplerFn)(IDirect3DDevice9*, DWORD, D3DSAMPLERSTATETYPE, DWORD);

SetTransformFn g_set_transform = nullptr;
SetTextureFn g_set_texture = nullptr;
SetSamplerFn g_set_sampler = nullptr;

struct Stage {
    IDirect3DBaseTexture9* tex = nullptr;
    UINT w = 0, h = 0;
    DWORD fmt = 0;
    DWORD addr_u = 1, addr_v = 1;
    float m[6] = {1, 0, 0, 1, 0, 0};   // _11 _12 _21 _22 _31 _32
};
Stage g_st[8];
int g_lines = 0, g_limit = 4000;


// [config] dump_textures=1: every texture seen at SetTexture (each pointer once, up to dump_max) saved as
// <client>\hooks	exdump\<pointer>_<w>x<h>.png through the client's own d3dx9_43.dll - so a texture in the transform
// log can be identified by its picture
typedef HRESULT(WINAPI* SaveTexFn)(LPCSTR, DWORD, IDirect3DBaseTexture9*, const PALETTEENTRY*);
SaveTexFn g_save_tex = nullptr;
int g_dump = 0, g_dumped = 0, g_dump_max = 3000;
IDirect3DBaseTexture9* g_seen[4096];
int g_nseen = 0;
char g_dump_dir[MAX_PATH];

void dump_texture(IDirect3DBaseTexture9* tex, UINT w, UINT h) {
    if (!g_dump || !g_save_tex || g_dumped >= g_dump_max) return;
    for (int i = 0; i < g_nseen; i++) if (g_seen[i] == tex) return;
    if (g_nseen < 4096) g_seen[g_nseen++] = tex;
    char path[MAX_PATH];
    wsprintfA(path, "%s/%p_%ux%u.png", g_dump_dir, (void*)tex, w, h);
    if (SUCCEEDED(g_save_tex(path, 3 /* D3DXIFF_PNG */, tex, nullptr))) g_dumped++;
}

volatile LONG g_n_tex = 0, g_n_samp = 0, g_n_xf = 0, g_n_xf_tex = 0;

HRESULT __stdcall my_set_texture(IDirect3DDevice9* dev, DWORD stage, IDirect3DBaseTexture9* tex) {
    InterlockedIncrement(&g_n_tex);
    if (stage < 8 && g_st[stage].tex != tex) {
        Stage& s = g_st[stage];
        s.tex = tex;
        s.w = s.h = 0;
        s.fmt = 0;
        if (tex && tex->GetType() == D3DRTYPE_TEXTURE) {
            D3DSURFACE_DESC d;
            if (SUCCEEDED(((IDirect3DTexture9*)tex)->GetLevelDesc(0, &d))) s.w = d.Width, s.h = d.Height, s.fmt = d.Format;
            dump_texture(tex, s.w, s.h);
        }
    }
    return g_set_texture(dev, stage, tex);
}

HRESULT __stdcall my_set_sampler(IDirect3DDevice9* dev, DWORD stage, D3DSAMPLERSTATETYPE type, DWORD value) {
    InterlockedIncrement(&g_n_samp);
    if (stage < 8) {
        if (type == D3DSAMP_ADDRESSU) g_st[stage].addr_u = value;
        if (type == D3DSAMP_ADDRESSV) g_st[stage].addr_v = value;
    }
    return g_set_sampler(dev, stage, type, value);
}

HRESULT __stdcall my_set_transform(IDirect3DDevice9* dev, D3DTRANSFORMSTATETYPE state, const D3DMATRIX* m) {
    InterlockedIncrement(&g_n_xf);
    int stage = (int)state - (int)D3DTS_TEXTURE0;
    if (stage >= 0 && stage < 8) InterlockedIncrement(&g_n_xf_tex);
    if (m && stage >= 0 && stage < 8 && g_lines < g_limit) {
        Stage& s = g_st[stage];
        float v[6] = {m->_11, m->_12, m->_21, m->_22, m->_31, m->_32};
        bool moved = std::memcmp(v, s.m, sizeof v) != 0;
        if (moved && (v[4] != 0.0f || v[5] != 0.0f)) {
            g_lines++;
            hook::logf("tt stage %d tick %lu tex %p %ux%u fmt %lu addr %lu/%lu | %.4f %.4f %.4f %.4f | 31 %.4f 32 %.4f | 41 %.4f 42 %.4f",
                       stage, GetTickCount(), (void*)s.tex, s.w, s.h, s.fmt, s.addr_u, s.addr_v, m->_11, m->_12, m->_21,
                       m->_22, m->_31, m->_32, m->_41, m->_42);
        }
        std::memcpy(s.m, v, sizeof v);
    }
    return g_set_transform(dev, state, m);
}

bool patch(void** vt, int idx, void* fn, void** orig) {
    if (vt[idx] == fn) return true;                  // patched already (a second device on the same vtable)
    DWORD old;
    if (!VirtualProtect(&vt[idx], sizeof(void*), PAGE_EXECUTE_READWRITE, &old)) return false;
    *orig = vt[idx];
    vt[idx] = fn;
    VirtualProtect(&vt[idx], sizeof(void*), old, &old);
    return true;
}

// the game's own device: IDirect3D9::CreateDevice (vtable 16) patched at load, before the client makes its window;
// each device it returns gets its vtable's three entries patched (a wrapper such as DXVK gives the device a vtable
// of its own - patching a throw-away device's did not reach the game's)
typedef HRESULT(__stdcall* CreateDeviceFn)(IDirect3D9*, UINT, D3DDEVTYPE, HWND, DWORD, D3DPRESENT_PARAMETERS*,
                                           IDirect3DDevice9**);
CreateDeviceFn g_create_device = nullptr;
IDirect3DDevice9* g_dev = nullptr;

// another layer (an overlay / anti-cheat) gives the device a private heap vtable and may swap or re-patch it: the
// device's CURRENT vtable is checked and our three entries (re)written
void ensure_patched(const char* why) {
    if (!g_dev) return;
    void** vt = *(void***)g_dev;
    if (vt[44] == (void*)my_set_transform && vt[65] == (void*)my_set_texture && vt[69] == (void*)my_set_sampler) return;
    void* o44 = vt[44] == (void*)my_set_transform ? (void*)g_set_transform : vt[44];
    void* o65 = vt[65] == (void*)my_set_texture ? (void*)g_set_texture : vt[65];
    void* o69 = vt[69] == (void*)my_set_sampler ? (void*)g_set_sampler : vt[69];
    DWORD old;
    if (!VirtualProtect(&vt[44], 26 * sizeof(void*), PAGE_EXECUTE_READWRITE, &old)) return;
    g_set_transform = (SetTransformFn)o44, g_set_texture = (SetTextureFn)o65, g_set_sampler = (SetSamplerFn)o69;
    vt[44] = (void*)my_set_transform, vt[65] = (void*)my_set_texture, vt[69] = (void*)my_set_sampler;
    VirtualProtect(&vt[44], 26 * sizeof(void*), old, &old);
    hook::logf("d3d_probe: (re)patched vtable %p (%s): SetTransform %p SetTexture %p SetSamplerState %p", (void*)vt, why,
               o44, o65, o69);
}

HRESULT __stdcall my_create_device(IDirect3D9* d, UINT a, D3DDEVTYPE t, HWND w, DWORD f, D3DPRESENT_PARAMETERS* pp,
                                   IDirect3DDevice9** out) {
    HRESULT hr = g_create_device(d, a, t, w, f, pp, out);
    if (SUCCEEDED(hr) && out && *out) {
        g_dev = *out;
        void** vt = *(void***)*out;
        bool ok = patch(vt, 44, (void*)my_set_transform, (void**)&g_set_transform) &&
                  patch(vt, 65, (void*)my_set_texture, (void**)&g_set_texture) &&
                  patch(vt, 69, (void*)my_set_sampler, (void**)&g_set_sampler);
        hook::logf("d3d_probe: the game's device %p, vtable %p patched %d", (void*)*out, (void*)vt, ok ? 1 : 0);
    }
    return hr;
}

DWORD WINAPI stats(LPVOID) {
    for (;;) {
        Sleep(5000);
        ensure_patched("check");
        hook::logf("d3d_probe: calls SetTexture %ld SetSamplerState %ld SetTransform %ld (texture stages %ld)", g_n_tex,
                   g_n_samp, g_n_xf, g_n_xf_tex);
    }
}

void setup_dump() {
    g_dump = hook::config_int("dump_textures", 0, "config");
    g_dump_max = hook::config_int("dump_max", 3000, "config");
    if (!g_dump) return;
    HMODULE x = LoadLibraryA("d3dx9_43.dll");
    g_save_tex = x ? (SaveTexFn)GetProcAddress(x, "D3DXSaveTextureToFileA") : nullptr;
    DWORD n = GetModuleFileNameA(nullptr, g_dump_dir, MAX_PATH);
    while (n > 0 && g_dump_dir[n - 1] != 0x5C) n--;
    g_dump_dir[n] = 0;
    lstrcatA(g_dump_dir, "hooks/texdump");
    CreateDirectoryA(g_dump_dir, nullptr);
    hook::logf("d3d_probe: dumping textures to %s (D3DXSaveTextureToFileA %p)", g_dump_dir, (void*)g_save_tex);
}

void install() {
    setup_dump();
    CloseHandle(CreateThread(nullptr, 0, stats, nullptr, 0, nullptr));
    HMODULE d3d = LoadLibraryA("d3d9.dll");
    typedef IDirect3D9*(WINAPI * CreateFn)(UINT);
    CreateFn create = d3d ? (CreateFn)GetProcAddress(d3d, "Direct3DCreate9") : nullptr;
    IDirect3D9* d = create ? create(D3D_SDK_VERSION) : nullptr;
    if (!d) {
        hook::log("d3d_probe: no Direct3D9");
        return;
    }
    void** vt = *(void***)d;
    bool ok = patch(vt, 16, (void*)my_create_device, (void**)&g_create_device);
    hook::logf("d3d_probe: IDirect3D9 vtable %p CreateDevice patched %d", (void*)vt, ok ? 1 : 0);
    // (the object is kept: releasing the last IDirect3D9 may unload a wrapper's state the vtable lives in)
}

}  // namespace

HOOK_PLUGIN("d3d_probe") {
    if (hook::config_int("enabled", 1, "plugin") == 0) return;
    g_limit = hook::config_int("limit", 4000, "config");
    install();
}
