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
#include <client_addrs.h>

namespace {

const unsigned kVaNiShutdown = caddr::va(caddr::kNiShutdown);     // push esi / xor esi,esi / cmp [0xD1E568],esi
const unsigned kVaMapSingleton = caddr::va(caddr::kMapSingleton);
const unsigned kVaMapGuard = caddr::va(caddr::kMapSingletonGuard);       // MSVC thread-safe static: -1 = constructed
const unsigned kVaMapDtor = caddr::va(caddr::kMapSingletonDtor);        // thiscall
const unsigned kVaMapAtexitThunk = caddr::va(caddr::kMapSingletonAtexit); // mov ecx,MapSingleton / jmp MapSingletonDtor
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
    if (const char* m = caddr::missing({caddr::kNiShutdown, caddr::kMapSingleton, caddr::kMapSingletonGuard,
                                        caddr::kMapSingletonDtor, caddr::kMapSingletonAtexit})) {
        hook::log("exit_scene_order: %s - not hooked", m);
        return;
    }
    const unsigned char* thunk = (const unsigned char*)hook::rebase(kVaMapAtexitThunk);
    const unsigned char* shut = (const unsigned char*)hook::rebase(kVaNiShutdown);
    // the thunk is `mov ecx, <the singleton>` (B9 imm32, relocated with the exe) then the jmp to the destructor
    if (thunk[0] != 0xB9 || *(const unsigned*)(thunk + 1) != (unsigned)(uintptr_t)hook::rebase(kVaMapSingleton)) {
        hook::log("exit_scene_order: atexit thunk is not the expected code - not hooked");
        return;
    }
    for (int i = 0; i < 3; i++)
        if (shut[i] != kNiShutdownStock[i]) { hook::log("exit_scene_order: NiShutdown is not the expected code - not hooked"); return; }
    hook::hook_function("NiShutdown (release the map scene first)", (void*)shut, (void*)ni_shutdown, &g_shutdown);
}
