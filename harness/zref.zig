const std = @import("std");
const oqs = @import("oqs");

fn seed() void {
    var e: [48]u8 = undefined;
    for (&e, 0..) |*b, i| b.* = @intCast(i);
    oqs.testing.seedKat(&e);
}

fn emit(w: *std.Io.Writer, algo: []const u8, field: []const u8, buf: []const u8) !void {
    try w.print("{s} {s} ", .{ algo, field });
    for (buf) |b| try w.print("{x:0>2}", .{b});
    try w.print("\n", .{});
}

pub fn main() !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    var buf: [65536]u8 = undefined;
    var fw = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &fw.interface;

    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    const a = da.allocator();

    {
        var kem = try oqs.Kem.init(a, "ML-KEM-768");
        defer kem.deinit();
        seed();
        const kp = try kem.keypair();
        defer a.free(kp.public_key);
        defer a.free(kp.secret_key);
        seed();
        const enc = try kem.encaps(kp.public_key);
        defer a.free(enc.ciphertext);
        defer a.free(enc.shared_secret);
        const ss2 = try kem.decaps(enc.ciphertext, kp.secret_key);
        defer a.free(ss2);
        try emit(w, "ML-KEM-768", "pk", kp.public_key);
        try emit(w, "ML-KEM-768", "sk", kp.secret_key);
        try emit(w, "ML-KEM-768", "ct", enc.ciphertext);
        try emit(w, "ML-KEM-768", "ss", enc.shared_secret);
        try emit(w, "ML-KEM-768", "ss2", ss2);
    }
    inline for (.{ "ML-DSA-65", "MAYO-2" }) |algo| {
        var sig = try oqs.Sig.init(a, algo);
        defer sig.deinit();
        seed();
        const kp = try sig.keypair();
        defer a.free(kp.public_key);
        defer a.free(kp.secret_key);
        const msg = "the quick brown fox";
        seed();
        const s = try sig.sign(msg, kp.secret_key);
        defer a.free(s);
        try emit(w, algo, "pk", kp.public_key);
        try emit(w, algo, "sk", kp.secret_key);
        try emit(w, algo, "sig", s);
    }
    try fw.flush();
}
