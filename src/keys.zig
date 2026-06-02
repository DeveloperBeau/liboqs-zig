const std = @import("std");

/// A shared secret established via KEM. Owns its bytes; `deinit` securely
/// zeroes them before freeing. The bytes are symmetric-key material — feed
/// `.bytes` to a symmetric cipher (e.g. AES, ChaCha20).
pub const SharedSecret = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,

    /// Takes ownership of an already-allocated slice.
    pub fn fromOwned(allocator: std.mem.Allocator, bytes: []u8) SharedSecret {
        return .{ .allocator = allocator, .bytes = bytes };
    }

    pub fn deinit(self: *SharedSecret) void {
        zeroAndFree(self.allocator, self.bytes);
        self.* = undefined;
    }
};

/// Securely zero `bytes`, then free with `allocator`. Use for any secret slice.
pub fn zeroAndFree(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}

test "deinit zeroes the secret" {
    // This test can only observe our secureZero in NON-safety builds. In safety
    // builds (Debug/ReleaseSafe) `Allocator.free` overwrites the freed region
    // with the 0xAA `undefined` poison *after* our secureZero runs, so the
    // freed bytes are 0xAA regardless of whether we zeroed — the toolchain, not
    // our code, would be under test. We therefore skip there and let the
    // ReleaseFast run in build.zig be the real guard: it executes this exact
    // deinit path with no poison, so deleting secureZero from zeroAndFree makes
    // it fail (the bytes stay the original secret instead of zero).
    if (std.debug.runtime_safety) return error.SkipZigTest;
    // FBA over a stack buffer: free is a no-op rewind, so the bytes stay
    // inspectable after deinit and reflect only what secureZero wrote.
    var backing: [4]u8 = .{ 1, 2, 3, 4 };
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var ss = SharedSecret.fromOwned(fba.allocator(), backing[0..]);
    ss.deinit();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, &backing);
}
