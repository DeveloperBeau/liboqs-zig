const std = @import("std");

/// A shared secret established via KEM. Owns its bytes; `deinit` zeroes them
/// before freeing. The bytes are symmetric-key material. Feed `.bytes` to a
/// symmetric cipher (e.g. AES, ChaCha20).
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
    if (bytes.len == 0) return;
    // `Allocator.free` would fill the bytes with the 0xAA undefined pattern in
    // safety builds before it reaches the allocator. The bytes are already
    // zero, so they go straight to the allocator. That keeps the wipe visible
    // to the allocator in every build mode. The alignment is that of u8, the
    // same one `Allocator.free` passes for a `[]u8`.
    allocator.rawFree(bytes, .of(u8), @returnAddress());
}

/// Test-only allocator that copies the bytes it is asked to free, then
/// forwards every call to the child allocator.
const FreeRecorder = struct {
    child: std.mem.Allocator,
    freed: [16]u8 = undefined,
    freed_len: usize = 0,
    free_calls: usize = 0,

    fn allocator(self: *FreeRecorder) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *FreeRecorder = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *FreeRecorder = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *FreeRecorder = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(memory, alignment, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *FreeRecorder = @ptrCast(@alignCast(ctx));
        self.free_calls += 1;
        self.freed_len = @min(memory.len, self.freed.len);
        @memcpy(self.freed[0..self.freed_len], memory[0..self.freed_len]);
        self.child.rawFree(memory, alignment, ret_addr);
    }
};

// Runs in every optimize mode. The recorder sees the bytes at the moment
// zeroAndFree hands them to the allocator, after the wipe and before the
// child allocator reuses the memory. The build also runs this file at
// ReleaseFast, where the optimizer could drop a plain store to memory that
// is about to be freed.
test "deinit zeroes the secret before the allocator gets the bytes back" {
    var recorder = FreeRecorder{ .child = std.testing.allocator };
    const a = recorder.allocator();
    const bytes = try a.alloc(u8, 4);
    @memcpy(bytes, &[_]u8{ 1, 2, 3, 4 });
    var ss = SharedSecret.fromOwned(a, bytes);
    ss.deinit();
    try std.testing.expectEqual(@as(usize, 1), recorder.free_calls);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, recorder.freed[0..recorder.freed_len]);
}

test "zeroAndFree of an empty slice frees nothing" {
    var recorder = FreeRecorder{ .child = std.testing.allocator };
    var empty: [0]u8 = .{};
    zeroAndFree(recorder.allocator(), &empty);
    try std.testing.expectEqual(@as(usize, 0), recorder.free_calls);
}
