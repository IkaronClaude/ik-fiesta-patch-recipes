// Getting in front of the service routine.
//
// THE PROBLEM. These exes are Windows services. Run one by hand and it registers itself and exits; the
// zone only really starts when the SCM launches it, and the code that does the starting is the service
// routine. That is where set-up has to happen - DllMain is far too early (before the exe's CRT, on a
// stack with almost nothing committed) and anything inside the zone is already too late.
//
// THE ROUTINE IS NOT A SYMBOL. Zone.exe has NO EXPORTS AT ALL (checked 2026-09-19: the export directory
// is empty), so there is nothing to look up by name, and ServiceMain is not a fixed name in the first
// place. A service names itself in a table:
//
//     SERVICE_TABLE_ENTRYA table[] = { { "ZoneServer", ServiceMain }, { 0, 0 } };
//     StartServiceCtrlDispatcherA(table);              // BLOCKS; the SCM calls ServiceMain on its own thread
//
// ServiceMain is a plain static function whose address exists only in that table.
//
// THE WAY IN. The table is the hook point. Zone.exe imports StartServiceCtrlDispatcherA from ADVAPI32, so
// swapping that one IAT slot hands us the table before the SCM has seen it. We copy it, replace each
// lpServiceProc with our own, and call through; the SCM then calls US, and our wrapper is exactly
//
//     { install_everything(); OriginalServiceMain(argc, argv); }
//
// which is the ordering guarantee we want - our code cannot run late, because the original cannot start
// until we return from the first line. It needs no PDB, no address, and no instruction decoding, so it
// works on every Fiesta exe that is a service, not just this one.
#pragma once
#include "../include/zonehook.h"

namespace zone {

typedef void (*ServiceInitFn)();

// Arrange for `fn` to run on the service's thread, immediately before the exe's own service routine.
// Install this from DllMain: it only rewrites an IAT slot, which is safe that early.
//
// Returns false when the exe does not import StartServiceCtrlDispatcher - which also means the exe is not
// a service, and `fn` will never run. Say so in the log rather than assuming it worked.
bool hook_service_main(ServiceInitFn fn);

// True once the service routine has actually been reached. Lets the log distinguish "ran by hand, so the
// service never started" from "the service started and our set-up failed".
bool service_started();

}  // namespace zone
