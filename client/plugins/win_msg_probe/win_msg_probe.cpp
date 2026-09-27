// win_msg_probe - DIAGNOSTIC built on pgwin_msg.h: logs every window message DELIVERED (PgWin::ProcessMsg) and every one
// QUEUED (PgWin::PostMsg), with the RTTI class of the windows involved. Button hover repeats (msg 7, wParam 0) are skipped.
// Written 2026-09-27 to find where a click on the full map's quest legend goes in the 2026 client (FullMapWin::OnCommand
// never ran). Replaces map_command_probe / map_vtable_probe / msg_probe. Remove once the route is known.
#include <pgwin_msg.h>

namespace {

bool noise(const pgwin::Message& m) { return m.msg == pgwin::kButtonState && m.wparam == pgwin::kHover; }

bool on_process(pgwin::Message& m) {
    if (!noise(m))
        hook::log("deliver %s %p  msg %u wParam %u lParam %ld (0x%lX)%s%s", pgwin::class_of(m.window), m.window, m.msg, m.wparam,
                  m.lparam, (unsigned long)m.lparam, m.msg == pgwin::kButtonState ? "  from " : "",
                  m.msg == pgwin::kButtonState ? pgwin::class_of((void*)m.lparam) : "");
    return false;
}

bool on_post(void* sender, pgwin::Message& m) {
    if (!noise(m))
        hook::log("post    %s %p -> %s %p  msg %u wParam %u lParam %ld", pgwin::class_of(sender), sender,
                  pgwin::class_of(m.window), m.window, m.msg, m.wparam, m.lparam);
    return false;
}

}  // namespace

HOOK_PLUGIN("win_msg_probe") {
    pgwin::on_process(on_process);
    pgwin::on_post(on_post);
    pgwin::install();
}
