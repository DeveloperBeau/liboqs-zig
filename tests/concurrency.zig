//! Parallel typed operations to surface data races or crashes. Uses the system
//! RNG only and never calls seedKat (the KAT DRBG is serial-only and
//! process-global). Each worker uses the thread-safe smp_allocator.
const std = @import("std");
const oqs = @import("oqs");

fn kemWorker(done: *std.atomic.Value(usize)) void {
    const a = std.heap.smp_allocator; // thread-safe
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        kemOnce(a) catch |e| {
            std.debug.print("kem worker failed: {}\n", .{e});
            return;
        };
    }
    _ = done.fetchAdd(1, .monotonic);
}

fn kemOnce(a: std.mem.Allocator) !void {
    var kp = try oqs.kem.MlKem768.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var enc = try kp.public_key.encapsulate();
    defer enc.deinit();
    var ss = try kp.secret_key.decapsulate(enc.ciphertext);
    defer ss.deinit();
    if (!std.mem.eql(u8, enc.shared_secret.bytes, ss.bytes)) return error.SharedSecretMismatch;
}

fn sigWorker(done: *std.atomic.Value(usize)) void {
    const a = std.heap.smp_allocator;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        sigOnce(a) catch |e| {
            std.debug.print("sig worker failed: {}\n", .{e});
            return;
        };
    }
    _ = done.fetchAdd(1, .monotonic);
}

fn sigOnce(a: std.mem.Allocator) !void {
    var kp = try oqs.sig.MlDsa65.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var s = try kp.secret_key.sign("the quick brown fox");
    defer s.deinit();
    if (!try kp.public_key.isValidSignature("the quick brown fox", s.bytes)) return error.VerifyFailed;
}

test "concurrent KEM and SIG operations do not race or crash" {
    oqs.ensureInitialized();
    const per = 4; // threads per kind
    var done = std.atomic.Value(usize).init(0);
    var threads: [per * 2]std.Thread = undefined;
    for (0..per) |i| threads[i] = try std.Thread.spawn(.{}, kemWorker, .{&done});
    for (per..per * 2) |i| threads[i] = try std.Thread.spawn(.{}, sigWorker, .{&done});
    for (threads) |t| t.join();
    try std.testing.expectEqual(@as(usize, per * 2), done.load(.monotonic));
}
