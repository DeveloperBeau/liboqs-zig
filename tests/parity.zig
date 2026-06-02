const std = @import("std");

test "cref and zref produce byte-identical output" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const cref = try run(a, io, "zig-out/bin/cref");
    defer a.free(cref);
    const zref = try run(a, io, "zig-out/bin/zref");
    defer a.free(zref);
    try std.testing.expectEqualStrings(cref, zref);
}

fn run(a: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    const result = try std.process.run(a, io, .{
        .argv = &.{path},
    });
    defer a.free(result.stderr);
    return result.stdout;
}
