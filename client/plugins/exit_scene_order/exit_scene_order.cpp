// exit_scene_order - the 2026 client no longer crashes when it is closed (operator 2026-10-03: "Crash report on client closure"
// - "Stock definitely does this. Try to find the actual cause").
//
// ---- THE CAUSE (US Fiesta.exe, from the crash report of 2026-10-03 10:05 + static reading) -------------------------------
//   WinMain (0x9DEB60) ends: delete the application object, then NiShutdown (0x9D71B0) - every Gamebryo library's shutdown
//   function, then 0x9D7B90 -> 0x9D8280, which destroys and frees the memory manager's 16 small-object pools (0xD1E690[16],
//   0x108-byte allocators), and 0x9D75E0, which deletes the memory manager itself. WinMain returns and the CRT's exit()
//   runs the atexit list - including the destructor of the map singleton at 0xC54E00 (a function-local static, the
//   constructor 0x7A4970 references "nonMap"; guard 0xCE1E40 = -1 once built; atexit thunk 0xAEAF90 -> destructor 0x7A51F0).
//   That destructor still holds the scene: it releases its NiPointer members (+0x470, +0x46C, +0x468 ...), the last
//   reference to a scene graph goes, NiNode destructors (0x984060) recurse down the tree, and NiAVObject's destructor
//   (0x982510) walks its property list (+0x9C) - list nodes that came from the pools NiShutdown already freed. The read of a
//   node (0x982535 mov edi,[edi]) faults: ACCESS_VIOLATION. Gamebryo objects released after NiShutdown - an exit-order bug.
//
// ---- THIS PLUGIN --------------------------------------------------------------------------------------------------------
//   Puts the release back where it belongs: NiShutdown is detoured, and when the map singleton was built (guard -1) its
//   destructor runs FIRST, while Gamebryo is still alive; the atexit thunk is then patched to a bare `ret` so exit() does
//   not destroy it a second time. Then NiShutdown runs as stock.

#include <hook_core.h>

namespace {

const unsigned kVaNiShutdown = 0x009D71B0u;     // push esi / xor esi,esi / cmp [0xD1E568],esi
const unsigned kVaMapSingleton = 0x00C54E00u;
const unsigned kVaMapGuard = 0x00CE1E40u;       // MSVC thread-safe static: -1 = constructed
const unsigned kVaMapDtor = 0x007A51F0u;        // thiscall
const unsigned kVaMapAtexitThunk = 0x00AEAF90u; // mov ecx,0xC54E00 / jmp 0x7A51F0
const unsigned char kThunkStock[5] = {0xB9, 0x00, 0x4E, 0xC5, 0x00};
const unsigned char kNiShutdownStock[3] = {0x56, 0x33, 0xF6};

hook::Detour g_shutdown;

typedef void (__thiscall* Dtor)(void* self);

void release_map_scene() {
    __try {
        if (*(int*)hook::rebase(kVaMapGuard) != -1) {
            hook::log("exit_scene_order: map singleton never built - nothing to release early");
            return;
        }
        unsigned char* thunk = (unsigned char*)hook::rebase(kVaMapAtexitThunk);
        const unsigned char ret = 0xC3;
        if (!hook::write_code(thunk, &ret, 1)) {
            hook::log("exit_scene_order: could not patch the atexit thunk - left to exit() as stock");
            return;
        }
        ((Dtor)hook::rebase(kVaMapDtor))(hook::rebase(kVaMapSingleton));
        hook::log("exit_scene_order: map singleton destroyed before NiShutdown (its atexit entry is now a no-op)");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook::log("exit_scene_order: exception while releasing the map singleton early");
    }
}

void __cdecl ni_shutdown() {
    release_map_scene();
    ((void (__cdecl*)())g_shutdown.trampoline)();
}

}  // namespace

HOOK_PLUGIN("exit_scene_order") {
    const unsigned char* thunk = (const unsigned char*)hook::rebase(kVaMapAtexitThunk);
    const unsigned char* shut = (const unsigned char*)hook::rebase(kVaNiShutdown);
    for (int i = 0; i < 5; i++)
        if (thunk[i] != kThunkStock[i]) { hook::log("exit_scene_order: atexit thunk is not the expected code - not hooked"); return; }
    for (int i = 0; i < 3; i++)
        if (shut[i] != kNiShutdownStock[i]) { hook::log("exit_scene_order: NiShutdown is not the expected code - not hooked"); return; }
    hook::hook_function("NiShutdown (release the map scene first)", (void*)shut, (void*)ni_shutdown, &g_shutdown);
}
