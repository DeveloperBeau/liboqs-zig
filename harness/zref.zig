const std = @import("std");
const oqs = @import("oqs");

// libc getenv (the exe links libc via cliboqs); std's env API churned in 0.16.
extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;

fn envUsize(name: [*:0]const u8, default: usize) usize {
    const p = getenv(name) orelse return default;
    return std.fmt.parseInt(usize, std.mem.span(p), 10) catch default;
}

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

    @setEvalBranchQuota(100000);

    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    const a = da.allocator();

    // Sharding for parallelism (full coverage either way): OQS_SHARD / OQS_TOTAL
    // select the algorithms at combined-index % total == shard. Per-op KAT
    // re-seeding makes each algorithm's output independent of the split, so
    // merging all shards reproduces the full single-process output. Unset =
    // run the entire set. Indexing need not match cref's, since the parity
    // comparison is by (algo,field) key, not by position.
    const shard: usize = envUsize("OQS_SHARD", 0);
    var total: usize = envUsize("OQS_TOTAL", 1);
    if (total < 1) total = 1;
    var idx: usize = 0;

    // Drive the Zig side from the typed registry so parity validates the typed
    // API, not just the runtime core. Seed before generateKeyPair: OQS_*_new
    // consumes no RNG, so the DRBG state at keypair time matches cref.
    inline for (@typeInfo(oqs.kem).@"struct".decls) |d| {
        if (idx % total == shard) {
            const T = @field(oqs.kem, d.name);
            std.debug.print("  zref[{d}] {s}\n", .{ shard, T.algorithm_name });
            seed();
            var kp = try T.generateKeyPair(a);
            defer kp.public_key.deinit();
            defer kp.secret_key.deinit();
            seed();
            var enc = try kp.public_key.encapsulate();
            defer enc.deinit();
            var ss2 = try kp.secret_key.decapsulate(enc.ciphertext);
            defer ss2.deinit();
            try emit(w, T.algorithm_name, "pk", kp.public_key.bytes);
            try emit(w, T.algorithm_name, "sk", kp.secret_key.bytes);
            try emit(w, T.algorithm_name, "ct", enc.ciphertext);
            try emit(w, T.algorithm_name, "ss", enc.shared_secret.bytes);
            try emit(w, T.algorithm_name, "ss2", ss2.bytes);
        }
        idx += 1;
    }
    inline for (@typeInfo(oqs.sig).@"struct".decls) |d| {
        if (idx % total == shard) {
            const T = @field(oqs.sig, d.name);
            std.debug.print("  zref[{d}] {s}\n", .{ shard, T.algorithm_name });
            seed();
            var kp = try T.generateKeyPair(a);
            defer kp.public_key.deinit();
            defer kp.secret_key.deinit();
            seed();
            var s = try kp.secret_key.sign("the quick brown fox");
            defer s.deinit();
            try emit(w, T.algorithm_name, "pk", kp.public_key.bytes);
            try emit(w, T.algorithm_name, "sk", kp.secret_key.bytes);
            try emit(w, T.algorithm_name, "sig", s.bytes);
        }
        idx += 1;
    }
    try fw.flush();
}
