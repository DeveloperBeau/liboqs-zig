//! ZigOQS — safe Zig wrapper around liboqs.
pub const version = "0.0.0";

test "module compiles" {
    const std = @import("std");
    try std.testing.expect(version.len > 0);
}
