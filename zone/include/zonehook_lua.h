// Talking to the zone's Lua engine.
//
// The zone statically links LUA 5.2 with symbols intact (luaL_checkunsigned, luaL_buffinitsize and
// lua_Debug settle the version), so there is no second interpreter to embed and no ABI to guess - every
// lua_* and luaL_* entry point is already in <zone_functions.h> with its real address.
//
// HOW THE ZONE USES IT. Lua is PER MAP, not per process:
//
//     FieldMap::fm_GetLuaScript()  ->  FieldMap::LuaField*
//         LuaField::LuaScript      ->  LuaScriptScenario*  (a LuaScript)
//             LuaScript::ls_LuaObject  ->  lua_State*
//
// so a script global registered on one map is invisible on another. `for_each_state` is the usual thing
// to want: register on every map the zone has loaded.
//
// Everything the scripts call goes through LuaScript::ls_FunctionCall(const char* name, LuaArgumentDefault*),
// which is why on_function_call() can see every script entry point by name with a single detour.
#pragma once
#include "zonehook.h"
#include "zone_functions.h"

namespace zone {
namespace lua {

using ::zone::types::LuaScript;
using ::zone::types::lua_State;

// Lua's own C function shape. lua_CFunction is __cdecl, like the rest of the Lua API.
typedef int(__cdecl* CFunction)(lua_State* L);

// The generated signatures spell `const char*` as `char*`: zone_types.h drops CV qualifiers, which cannot
// change a layout or a calling convention but does mean string arguments need a cast at the call. Lua does
// not write to them.

// ---- reaching a state -----------------------------------------------------------------------------

// The lua_State a LuaScript owns. Null when the map has no script loaded, which is normal for most maps.
inline lua_State* state_of(LuaScript* script) {
    return script ? script->ls_LuaObject : NULL;
}

// The lua_State belonging to a FieldMap. `map` is a FieldMap*; the lookup is the chain in the header note.
inline lua_State* state_of_field(void* map) {
    if (!map) return NULL;
    auto get = ::zone::fn::FieldMap__fm_GetLuaScript();
    if (!get) return NULL;
    ::zone::types::FieldMap__LuaField* field = get(map, 0);
    return field ? state_of((LuaScript*)field->LuaScript) : NULL;
}

// ---- registering a function -----------------------------------------------------------------------

// Make `fn` callable from script as the global `name`. Returns false when the state is null.
//
//     static int __cdecl l_void_bag_size(lua_State* L) {
//         zone::fn::lua_pushinteger()(L, 144);
//         return 1;                       // one return value, as Lua expects
//     }
//     zone::lua::register_function(L, "VoidBagSize", l_void_bag_size);
inline bool register_function(lua_State* L, const char* name, CFunction fn) {
    if (!L || !name || !fn) return false;
    auto push = ::zone::fn::lua_pushcclosure();
    auto setg = ::zone::fn::lua_setglobal();
    if (!push || !setg) { log("[lua] lua_pushcclosure/lua_setglobal missing"); return false; }
    push(L, (void*)fn, 0);                 // 0 upvalues: a plain function, not a closure
    setg(L, (char*)name);
    log("[lua] registered %s on state %x", name, L);
    return true;
}

// Run a chunk of script in a state. For one-off set-up and for testing a hook from the log.
inline bool run_string(lua_State* L, const char* code) {
    if (!L || !code) return false;
    auto load = ::zone::fn::luaL_loadstring();
    auto call = ::zone::fn::lua_pcallk();
    if (!load || !call) return false;
    if (load(L, (char*)code) != 0) {              // LUA_OK is 0
        auto tostr = ::zone::fn::lua_tolstring();
        log("[lua] load failed: %s", tostr ? tostr(L, -1, 0) : (char*)"(no message)");
        return false;
    }
    if (call(L, 0, 0, 0, 0, 0) != 0) {
        auto tostr = ::zone::fn::lua_tolstring();
        log("[lua] call failed: %s", tostr ? tostr(L, -1, 0) : (char*)"(no message)");
        return false;
    }
    return true;
}

// ---- every script call ----------------------------------------------------------------------------
//
// LuaScript::ls_FunctionCall is the single door the zone uses to enter a script, so one detour here sees
// every call by name: OnPlayerMapLogin, OnObjectDied, an NPC's click handler, a quest step.
//
//     zone::lua::on_function_call([](LuaScript* s, const char* name, void* args) {
//         zone::log("[script] %s", name);
//         return true;                    // false SWALLOWS the call - the script does not run
//     });

typedef bool (*FunctionCallHook)(LuaScript* script, const char* name, void* args);

namespace detail {

inline Detour g_fncall_detour;
inline FunctionCallHook g_fncall_hook = NULL;

inline bool __fastcall fncall_impl(void* self, void* /*edx*/, const char* name, void* args) {
    if (g_fncall_hook && !g_fncall_hook((LuaScript*)self, name, args)) {
        return false;                      // swallowed: report "did not run" the way the zone would
    }
    typedef bool(__fastcall* Orig)(void*, void*, const char*, void*);
    return ((Orig)g_fncall_detour.trampoline)(self, 0, name, args);
}

inline void __declspec(naked) fncall_thunk() {
    __asm { jmp fncall_impl }
}

}  // namespace detail

// Install the observer. Call it once, from your plugin entry point. Returns false if the detour refused,
// which is logged with the reason.
inline bool on_function_call(FunctionCallHook hook) {
    detail::g_fncall_hook = hook;
    if (detail::g_fncall_detour.installed) return true;
    return hook_function("LuaScript::ls_FunctionCall",
                         rebase(::zone::fn::kVa_LuaScript__ls_FunctionCall),
                         (void*)detail::fncall_thunk, &detail::g_fncall_detour);
}

// ---- reading arguments off the stack ---------------------------------------------------------------
//
// Thin wrappers so a plugin does not have to remember which Lua 5.2 entry point took an extra parameter.
// Indices are Lua's: 1 is the first argument, -1 is the top.

inline int arg_count(lua_State* L) {
    auto f = ::zone::fn::lua_gettop();
    return f ? f(L) : 0;
}

inline int arg_int(lua_State* L, int index, int fallback = 0) {
    auto f = ::zone::fn::lua_tointegerx();
    if (!f) return fallback;
    int ok = 0;
    int v = f(L, index, &ok);
    return ok ? v : fallback;
}

inline const char* arg_string(lua_State* L, int index) {
    auto f = ::zone::fn::lua_tolstring();
    return f ? (const char*)f(L, index, 0) : NULL;
}

inline void push_int(lua_State* L, int v) {
    auto f = ::zone::fn::lua_pushinteger();
    if (f) f(L, v);
}

inline void push_string(lua_State* L, const char* s) {
    auto f = ::zone::fn::lua_pushstring();
    if (f) f(L, (char*)s);
}

}  // namespace lua
}  // namespace zone
