//! Zig side of the stateful parity check. It does one keygen and one sign per
//! algorithm through the typed `oqs.sig_stfl` wrappers, under the same NIST-KAT
//! seed and message as harness/stfl_cref.c. It prints the public key, the
//! signature and the counts after that one sign, and checks that the signature
//! verifies through the public key type. The secret key is never printed.
//!
//! The harness walks the typed registry, so an enabled name without a wrapper
//! shows up as a missing algorithm in the compare. Only parameter sets with a
//! total tree height of 16 or less run, unless `OQS_STATEFUL_ALL=1`. With
//! `--list` it prints "run NAME HEIGHT" or "skip NAME HEIGHT" and does nothing
//! else. This stays out of zref.zig so the frozen snapshot has no stateful lines.
const std = @import("std");
const oqs = @import("oqs");
const filter = @import("stfl_filter");

// libc getenv (the exe links libc via cliboqs); std's env API churned in 0.16.
extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;

const message = "the quick brown fox";

fn envUsize(name: [*:0]const u8, default: usize) usize {
    const p = getenv(name) orelse return default;
    return std.fmt.parseInt(usize, std.mem.span(p), 10) catch default;
}

fn envIsOne(name: [*:0]const u8) bool {
    const p = getenv(name) orelse return false;
    return std.mem.eql(u8, std.mem.span(p), "1");
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

// A count is printed as 8 bytes, big-endian, in hex.
fn emitCount(w: *std.Io.Writer, algo: []const u8, field: []const u8, v: u64) !void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .big);
    try emit(w, algo, field, &b);
}

pub fn main(init: std.process.Init.Minimal) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    var buf: [65536]u8 = undefined;
    var fw = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &fw.interface;

    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    const a = da.allocator();

    var args = init.args.iterate();
    _ = args.skip();
    const list = if (args.next()) |arg| std.mem.eql(u8, arg, "--list") else false;
    const all = envIsOne("OQS_STATEFUL_ALL");
    const shard: usize = envUsize("OQS_SHARD", 0);
    var total: usize = envUsize("OQS_TOTAL", 1);
    if (total < 1) total = 1;
    var idx: usize = 0;

    inline for (@typeInfo(oqs.sig_stfl).@"struct".decl_names) |d_name| {
        const T = @field(oqs.sig_stfl, d_name);
        const name = T.algorithm_name;
        const run = filter.isIncluded(name, all);
        if (list) {
            try w.print("{s} {s} {?d}\n", .{ if (run) "run" else "skip", name, filter.totalHeight(name) });
        } else if (run) {
            if (idx % total == shard) try runOne(T, a, w);
            idx += 1;
        }
    }
    try fw.flush();
}

fn runOne(comptime T: type, a: std.mem.Allocator, w: *std.Io.Writer) !void {
    const name = T.algorithm_name;
    std.debug.print("  stfl_zref {s}\n", .{name});
    seed();
    var kp = try T.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    seed();
    var s = try kp.secret_key.sign(message);
    defer s.deinit();
    const verified = try kp.public_key.isValidSignature(message, s.bytes);
    if (!verified) {
        std.debug.print("{s}: signature does not verify through the public key\n", .{name});
        return error.SignatureDoesNotVerify;
    }
    try emit(w, name, "pk", kp.public_key.bytes);
    try emit(w, name, "sig", s.bytes);
    try emit(w, name, "verified", &[_]u8{@intFromBool(verified)});
    try emitCount(w, name, "remaining", try kp.secret_key.sigsRemaining());
    try emitCount(w, name, "total", try kp.secret_key.sigsTotal());
}
