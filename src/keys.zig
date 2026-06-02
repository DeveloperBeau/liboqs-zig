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

test "SharedSecret does not survive deinit" {
    // The security property — the secret is gone after deinit — holds in every
    // build mode, but the mechanism differs, so assert what's observable:
    //   - safety builds (Debug/ReleaseSafe): `Allocator.free` overwrites the
    //     freed region with the 0xAA `undefined` poison *after* our secureZero,
    //     so we can only assert the secret no longer survives (poison ≠ secret).
    //   - ReleaseFast/ReleaseSmall: no poison, so secureZero is the only thing
    //     that clears it — assert exact zeroing. This is the case that catches
    //     a deleted secureZero (the build's ReleaseFast test run exercises it).
    // Back the secret with a fixed buffer so the memory stays valid and
    // inspectable after deinit frees it (FBA's free is a no-op rewind here).
    const secret = [_]u8{ 1, 2, 3, 4 };
    var backing: [4]u8 = secret;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var ss = SharedSecret.fromOwned(fba.allocator(), backing[0..]);
    ss.deinit();
    if (std.debug.runtime_safety) {
        try std.testing.expect(!std.mem.eql(u8, &backing, &secret));
    } else {
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, &backing);
    }
}
