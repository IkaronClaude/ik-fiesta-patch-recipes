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
typedef HRESULT(__stdcall* SetLightFn)(IDirect3DDevice9*, DWORD, const D3DLIGHT9*);
typedef HRESULT(__stdcall* LightEnableFn)(IDirect3DDevice9*, DWORD, BOOL);
typedef HRESULT(__stdcall* SetRSFn)(IDirect3DDevice9*, D3DRENDERSTATETYPE, DWORD);
typedef HRESULT(__stdcall* DrawIdxFn)(IDirect3DDevice9*, D3DPRIMITIVETYPE, INT, UINT, UINT, UINT, UINT);

SetTransformFn g_set_transform = nullptr;
SetTextureFn g_set_texture = nullptr;
SetSamplerFn g_set_sampler = nullptr;
DrawIdxFn g_draw_idx = nullptr;
SetLightFn g_set_light = nullptr;
SetRSFn g_set_rs = nullptr;

int g_log_lights = 0, g_light_lines = 0;
D3DLIGHT9 g_lights[64];
DWORD g_ambient = 0xFFFFFFFF, g_fogcol = 0xFFFFFFFF;

// [config] log_lights=1: every light (index < 8) set with new values, the ambient and fog colour render states on
// change - the scene lighting the official feeds D3D (terrain / object colour parity)
HRESULT __stdcall my_set_light(IDirect3DDevice9* dev, DWORD i, const D3DLIGHT9* l) {
    if (g_log_lights && l && i < 64 && std::memcmp(&g_lights[i], l, sizeof *l) != 0 && g_light_lines < 400) {
        g_lights[i] = *l;
        g_light_lines++;
        hook::logf("light %lu type %d diffuse %.3f %.3f %.3f ambient %.3f %.3f %.3f specular %.3f %.3f %.3f dir %.3f %.3f %.3f pos %.1f %.1f %.1f range %g att %g %g %g",
                   i, (int)l->Type, l->Diffuse.r, l->Diffuse.g, l->Diffuse.b, l->Ambient.r, l->Ambient.g, l->Ambient.b,
                   l->Specular.r, l->Specular.g, l->Specular.b, l->Direction.x, l->Direction.y, l->Direction.z,
                   l->Position.x, l->Position.y, l->Position.z, l->Range, l->Attenuation0, l->Attenuation1, l->Attenuation2);
    }
    return g_set_light(dev, i, l);
}

HRESULT __stdcall my_set_rs(IDirect3DDevice9* dev, D3DRENDERSTATETYPE t, DWORD v) {
    if (g_log_lights && g_light_lines < 400) {
        if (t == D3DRS_AMBIENT && v != g_ambient) g_ambient = v, g_light_lines++, hook::logf("rs ambient %08lx", v);
        if (t == D3DRS_FOGCOLOR && v != g_fogcol) g_fogcol = v, g_light_lines++, hook::logf("rs fogcolor %08lx", v);
    }
    return g_set_rs(dev, t, v);
}

LightEnableFn g_light_enable = nullptr;
int g_le_lines = 0;

// log_lights: every LightEnable whose index or state changes (any index - Gamebryo may use more than 8)
HRESULT __stdcall my_light_enable(IDirect3DDevice9* dev, DWORD i, BOOL on) {
    static BOOL last[64];
    static bool seen[64];
    // [config] lights_after=S: LightEnable is logged only S seconds after load (character select toggles 0 / 1 per draw)
    static int la = hook::config_int("lights_after", 0, "config");
    static DWORD t0 = GetTickCount();
    if (g_log_lights && g_le_lines < 400 && GetTickCount() - t0 >= (DWORD)la * 1000 &&
        (i >= 64 || !seen[i] || last[i] != on)) {
        if (i < 64) seen[i] = true, last[i] = on;
        g_le_lines++;
        hook::logf("light_enable %lu %d", i, (int)on);
    }
    return g_light_enable(dev, i, on);
}
int g_watch_rot = 0, g_draw_lines = 0;

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
    if (m && stage >= 0 && stage < 8) {          // the stage's matrix is always kept (watch_rot reads it); logged up to limit
        Stage& s = g_st[stage];
        float v[6] = {m->_11, m->_12, m->_21, m->_22, m->_31, m->_32};
        bool moved = std::memcmp(v, s.m, sizeof v) != 0;
        if (moved && (v[4] != 0.0f || v[5] != 0.0f) && g_lines < g_limit) {
            g_lines++;
            hook::logf("tt stage %d tick %lu tex %p %ux%u fmt %lu addr %lu/%lu | %.4f %.4f %.4f %.4f | 31 %.4f 32 %.4f | 41 %.4f 42 %.4f",
                       stage, GetTickCount(), (void*)s.tex, s.w, s.h, s.fmt, s.addr_u, s.addr_v, m->_11, m->_12, m->_21,
                       m->_22, m->_31, m->_32, m->_41, m->_42);
        }
        std::memcpy(s.m, v, sizeof v);
    }
    return g_set_transform(dev, state, m);
}

// [config] watch_rot=1: every draw whose stage-0 texture matrix is rotated (_11 < 0 - Frost Nova's crystals) logs
// its whole fixed-function state: blend / alpha test / lighting / texture factor / material, stages 0..3 ops,
// arguments, texture sizes - what our material must reproduce
void dump_draw(IDirect3DDevice9* dev, UINT prims) {
    static const struct { DWORD id; const char* n; } rs[] = {
        {D3DRS_ALPHABLENDENABLE, "blend"}, {D3DRS_SRCBLEND, "src"}, {D3DRS_DESTBLEND, "dst"}, {D3DRS_BLENDOP, "op"},
        {D3DRS_ALPHATESTENABLE, "atest"}, {D3DRS_ALPHAREF, "aref"}, {D3DRS_ALPHAFUNC, "afunc"}, {D3DRS_ZENABLE, "z"},
        {D3DRS_ZWRITEENABLE, "zw"}, {D3DRS_LIGHTING, "light"}, {D3DRS_TEXTUREFACTOR, "tfactor"},
        {D3DRS_DIFFUSEMATERIALSOURCE, "dsrc"}, {D3DRS_EMISSIVEMATERIALSOURCE, "esrc"},
        {D3DRS_AMBIENTMATERIALSOURCE, "asrc"}, {D3DRS_COLORVERTEX, "colvtx"}, {D3DRS_AMBIENT, "ambient"},
        {D3DRS_CULLMODE, "cull"}, {D3DRS_FOGENABLE, "fog"}, {D3DRS_SPECULARENABLE, "spec"}};
    char line[1024];
    int n = wsprintfA(line, "draw prims %u |", prims);
    for (const auto& r : rs) {
        DWORD v = 0;
        dev->GetRenderState((D3DRENDERSTATETYPE)r.id, &v);
        n += wsprintfA(line + n, " %s %lx", r.n, v);
    }
    char le[64];
    int ln = 0;
    for (DWORD li = 0; li < 32; li++) {   // Gamebryo uses indices past 8 (the world's lights are 17 / 18)
        BOOL on = FALSE;
        dev->GetLightEnable(li, &on);
        if (on) ln += std::snprintf(le + ln, sizeof(le) - ln, "%lu,", li);
    }
    if (!ln) le[ln++] = '-';
    le[ln] = 0;
    IDirect3DVertexShader9* vs = nullptr;
    IDirect3DPixelShader9* ps = nullptr;
    dev->GetVertexShader(&vs), dev->GetPixelShader(&ps);
    hook::logf("%s | lights %s | vs %p ps %p", line, le, (void*)vs, (void*)ps);
    // [config] dump_vs_consts=N: the first N float4 vertex-shader constants of a draw with a vertex shader
    static int vsc = hook::config_int("dump_vs_consts", 0, "config");
    if (vs && vsc > 0) {
        float c[4 * 64] = {0};
        int n = vsc > 64 ? 64 : vsc;
        dev->GetVertexShaderConstantF(0, c, n);
        for (int i = 0; i < n; i++)
            hook::logf("  vsc %d %.4f %.4f %.4f %.4f", i, c[4 * i], c[4 * i + 1], c[4 * i + 2], c[4 * i + 3]);
    }
    {   // the fog the draw gets: table / vertex mode, range fog, start / end (floats in the DWORD), density, colour
        DWORD fe = 0, tm = 0, vm = 0, rf = 0, fc = 0, fs = 0, fend = 0, fd = 0;
        dev->GetRenderState(D3DRS_FOGENABLE, &fe);
        if (fe) {
            dev->GetRenderState(D3DRS_FOGTABLEMODE, &tm), dev->GetRenderState(D3DRS_FOGVERTEXMODE, &vm);
            dev->GetRenderState(D3DRS_RANGEFOGENABLE, &rf), dev->GetRenderState(D3DRS_FOGCOLOR, &fc);
            dev->GetRenderState(D3DRS_FOGSTART, &fs), dev->GetRenderState(D3DRS_FOGEND, &fend), dev->GetRenderState(D3DRS_FOGDENSITY, &fd);
            float f0, f1, f2;
            std::memcpy(&f0, &fs, 4), std::memcpy(&f1, &fend, 4), std::memcpy(&f2, &fd, 4);
            hook::logf("  fog table %lu vertex %lu range %lu colour %08lx start %g end %g density %g", tm, vm, rf, fc, f0, f1, f2);
        }
    }
    for (DWORD li = 0; li < 32; li++) {   // each enabled light, read back
        BOOL on = FALSE;
        D3DLIGHT9 l{};
        if (FAILED(dev->GetLightEnable(li, &on)) || !on || FAILED(dev->GetLight(li, &l))) continue;
        hook::logf("  light %lu type %d diffuse %.3f %.3f %.3f ambient %.3f %.3f %.3f dir %.3f %.3f %.3f", li, (int)l.Type,
                   l.Diffuse.r, l.Diffuse.g, l.Diffuse.b, l.Ambient.r, l.Ambient.g, l.Ambient.b, l.Direction.x,
                   l.Direction.y, l.Direction.z);
    }
    if (vs) vs->Release();
    if (ps) ps->Release();
    for (DWORD st = 0; st < 4; st++) {
        DWORD cop = 0, c1 = 0, c2 = 0, aop = 0, a1 = 0, a2 = 0, tci = 0, res = 0;
        dev->GetTextureStageState(st, D3DTSS_COLOROP, &cop);
        if (cop == D3DTOP_DISABLE && st > 0) break;
        dev->GetTextureStageState(st, D3DTSS_COLORARG1, &c1);
        dev->GetTextureStageState(st, D3DTSS_COLORARG2, &c2);
        dev->GetTextureStageState(st, D3DTSS_ALPHAOP, &aop);
        dev->GetTextureStageState(st, D3DTSS_ALPHAARG1, &a1);
        dev->GetTextureStageState(st, D3DTSS_ALPHAARG2, &a2);
        dev->GetTextureStageState(st, D3DTSS_TEXCOORDINDEX, &tci);
        dev->GetTextureStageState(st, D3DTSS_RESULTARG, &res);
        Stage& s = g_st[st];
        hook::logf("  stage %lu tex %p %ux%u | colorop %lu (%lx, %lx) alphaop %lu (%lx, %lx) tci %lx res %lx | m %.3f %.3f %.3f %.3f t %.3f %.3f",
                   st, (void*)s.tex, s.w, s.h, cop, c1, c2, aop, a1, a2, tci, res, s.m[0], s.m[1], s.m[2], s.m[3], s.m[4], s.m[5]);
    }
    D3DMATERIAL9 mt;
    if (SUCCEEDED(dev->GetMaterial(&mt)))
        hook::logf("  material diffuse %.3f %.3f %.3f %.3f ambient %.3f %.3f %.3f emissive %.3f %.3f %.3f", mt.Diffuse.r,
                   mt.Diffuse.g, mt.Diffuse.b, mt.Diffuse.a, mt.Ambient.r, mt.Ambient.g, mt.Ambient.b, mt.Emissive.r,
                   mt.Emissive.g, mt.Emissive.b);
}

HRESULT __stdcall my_draw_idx(IDirect3DDevice9* dev, D3DPRIMITIVETYPE t, INT base, UINT minv, UINT nv, UINT start, UINT prims) {
    // [config] watch_w / watch_h narrow it to a stage-0 texture size; watch_tu to a U translation (x 1000)
    static int ww = hook::config_int("watch_w", 0, "config"), wh = hook::config_int("watch_h", 0, "config");
    static int wtu = hook::config_int("watch_tu", -99999, "config");
    const Stage& s0 = g_st[0];
    bool hit = g_watch_rot && s0.m[0] < -0.5f && (!ww || (int)s0.w == ww) && (!wh || (int)s0.h == wh) &&
               (wtu == -99999 || (int)(s0.m[4] * 1000.0f + 0.5f) == wtu);
    // [config] watch_minprims=N: any draw of at least N primitives (the terrain chunks, big map objects)
    static int wmp = hook::config_int("watch_minprims", 0, "config");
    if (wmp > 0 && (int)prims >= wmp) hit = true;
    // [config] watch_after=S: no draw dumps for the first S seconds after load (login / character select)
    static int wa = hook::config_int("watch_after", 0, "config");
    static DWORD t0 = GetTickCount();
    if (wa > 0 && GetTickCount() - t0 < (DWORD)wa * 1000) hit = false;
    // [config] frame_dump=N: once watch_after has passed, the next N draws, every one (a whole frame's state, to find a
    // draw by its texture / material)
    static int fd = hook::config_int("frame_dump", 0, "config");
    static DWORD fd_start = 0;
    static int fd_lines = 0;
    if (fd && (wa <= 0 || GetTickCount() - t0 >= (DWORD)wa * 1000)) {
        if (!fd_start) fd_start = GetTickCount(), hook::logf("frame_dump: start");
        if (fd_lines < fd) {
            fd_lines++;
            dump_draw(dev, prims);
        }
    }
    if (hit && g_draw_lines < 60) {
        g_draw_lines++;
        dump_draw(dev, prims);
    }
    return g_draw_idx(dev, t, base, minv, nv, start, prims);
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
    if (vt[44] == (void*)my_set_transform && vt[65] == (void*)my_set_texture && vt[69] == (void*)my_set_sampler &&
        vt[82] == (void*)my_draw_idx && vt[51] == (void*)my_set_light && vt[57] == (void*)my_set_rs &&
        vt[53] == (void*)my_light_enable) return;
    void* o53 = vt[53] == (void*)my_light_enable ? (void*)g_light_enable : vt[53];
    void* o51 = vt[51] == (void*)my_set_light ? (void*)g_set_light : vt[51];
    void* o57 = vt[57] == (void*)my_set_rs ? (void*)g_set_rs : vt[57];
    void* o82 = vt[82] == (void*)my_draw_idx ? (void*)g_draw_idx : vt[82];
    void* o44 = vt[44] == (void*)my_set_transform ? (void*)g_set_transform : vt[44];
    void* o65 = vt[65] == (void*)my_set_texture ? (void*)g_set_texture : vt[65];
    void* o69 = vt[69] == (void*)my_set_sampler ? (void*)g_set_sampler : vt[69];
    DWORD old;
    if (!VirtualProtect(&vt[44], 40 * sizeof(void*), PAGE_EXECUTE_READWRITE, &old)) return;
    g_set_light = (SetLightFn)o51, vt[51] = (void*)my_set_light;
    g_set_rs = (SetRSFn)o57, vt[57] = (void*)my_set_rs;
    g_light_enable = (LightEnableFn)o53, vt[53] = (void*)my_light_enable;
    g_draw_idx = (DrawIdxFn)o82, vt[82] = (void*)my_draw_idx;
    g_set_transform = (SetTransformFn)o44, g_set_texture = (SetTextureFn)o65, g_set_sampler = (SetSamplerFn)o69;
    vt[44] = (void*)my_set_transform, vt[65] = (void*)my_set_texture, vt[69] = (void*)my_set_sampler;
    VirtualProtect(&vt[44], 40 * sizeof(void*), old, &old);
    static int told = 0;
    if (++told <= 3 || told % 500 == 0)
        hook::logf("d3d_probe: (re)patched vtable %p (%s, #%d): SetTransform %p SetTexture %p SetSamplerState %p", (void*)vt, why,
               told, o44, o65, o69);
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
        for (int i = 0; i < 100; i++) {          // 5 s of 50 ms checks: the other layer restores the entries often
            Sleep(50);
            ensure_patched("check");
        }
        hook::logf("d3d_probe: calls SetTexture %ld SetSamplerState %ld SetTransform %ld (texture stages %ld)", g_n_tex,
                   g_n_samp, g_n_xf, g_n_xf_tex);
    }
}

void setup_dump() {
    g_dump = hook::config_int("dump_textures", 0, "config");
    g_watch_rot = hook::config_int("watch_rot", 0, "config");
    g_log_lights = hook::config_int("log_lights", 0, "config");
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
