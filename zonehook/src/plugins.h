// Loading every DLL in the hooks folder.
//
// WHEN, and why it is not DllMain.
//
// The first plan was LoadLibrary from inside our own DllMain, which does work: the loader initialises a
// library synchronously, so a plugin's DllMain has run to completion by the time LoadLibrary returns, and
// since our DllMain runs while the loader is walking the exe's imports, every plugin would be up before
// WinMain. That is the standard ASI-loader trick and it behaves the same under Wine.
//
// We do it from the SERVICE thread instead, for three reasons that all point the same way:
//
//   the loader lock   LoadLibrary inside DllMain runs the plugin's DllMain while we hold the loader lock.
//                     Microsoft does not support it, and a plugin that waits on a thread, joins one, or
//                     pulls in another library re-entrantly deadlocks the process at start-up - with no
//                     log line, because nothing has opened a log yet.
//   the stack         Loader init runs on a main thread stack with very little committed. Measured
//                     2026-09-19: a static-CRT (/MT) DLL in that position overflows it by 824 bytes before
//                     DllMain is reached. The dynamic CRT (/MD) was verified fine there - but a plugin
//                     should not have to know that, and on the service thread it is a normal 1 MB stack.
//   the CRT           A plugin is a normal runtime LoadLibrary at this point, so it may use the full CRT,
//                     static or dynamic, C++ exceptions, iostreams, whatever it likes.
//
// Nothing is lost by waiting: WinMain on these exes only registers the service. The zone starts when the
// SCM calls ServiceMain, and we load the plugins immediately before that (see service_hook.h), so a plugin
// is still up before a single line of zone code has run.
#pragma once
#include "../include/zonehook.h"

namespace zone {

// Load every *.dll in `<folder beside the exe>`. Returns how many loaded. A failure is logged with its
// reason and skipped - one bad plugin must not stop the others or the zone.
int load_plugins(const wchar_t* folder = L"hooks");

}  // namespace zone
