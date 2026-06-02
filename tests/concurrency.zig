//! Parallel typed operations to surface data races / crashes. Uses the SYSTEM
//! RNG only — never seedKat (the KAT DRBG is serial-only and process-global).
//! Each worker uses the thread-safe smp_allocator.
const std = @import("std");
const oqs = @import("oqs");

fn kemWorker(done: *std.atomic.Value(usize)) void {
    const a = std.heap.smp_allocator; // thread-safe
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        var kp = oqs.kem.MlKem768.generateKeyPair(a) catch return;
        defer kp.public_key.deinit();
        defer kp.secret_key.deinit();
        var enc = kp.public_key.encapsulate() catch return;
        defer enc.deinit();
        var ss = kp.secret_key.decapsulate(enc.ciphertext) catch return;
        defer ss.deinit();
        if (!std.mem.eql(u8, enc.shared_secret.bytes, ss.bytes)) return;
    }
    _ = done.fetchAdd(1, .monotonic);
}

test "concurrent KEM operations do not race or crash" {
    oqs.ensureInitialized();
    const n = 8;
    var done = std.atomic.Value(usize).init(0);
    var threads: [n]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, kemWorker, .{&done});
    for (threads) |t| t.join();
    try std.testing.expectEqual(@as(usize, n), done.load(.monotonic));
}
