const std = @import("std");
const c = @import("c.zig").c;

// 0 = uninitialised, 1 = initialising (another thread is inside OQS_init),
// 2 = done.  The release/acquire pair gives the happens-before guarantee
// required by the "safe to call from any thread" contract.
var state = std.atomic.Value(u8).init(0);

fn doInit() void {
    c.OQS_init();
}

/// Initialize liboqs exactly once. Safe to call from any thread.
pub fn ensure() void {
    if (state.load(.acquire) == 2) return;
    if (state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null) {
        doInit();
        state.store(2, .release);
    } else {
        while (state.load(.acquire) != 2) std.atomic.spinLoopHint();
    }
}

test "ensure() is idempotent and exposes a version" {
    ensure();
    ensure();
    const v = c.OQS_version();
    try std.testing.expect(v != null);
}
