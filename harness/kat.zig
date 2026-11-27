//! The known-answer program. It checks the Zig wrapper against the digests of
//! the liboqs known-answer programs in `kats.json`.
//!
//! `kat run` prints one result line per algorithm. `OQS_SHARD` and `OQS_TOTAL`
//! pick a share of the algorithms, so several processes can split the work.
//! `kat summarize FILE` reads the merged lines of every shard, compares them
//! and prints the verdict. `tools/kat.sh` runs both.
//!
//! `OQS_KAT_ALL=1` compares the `all` digests (100 counts) instead of `single`.
//! `OQS_KAT_FILTER=a,b` covers only the named algorithms.
const std = @import("std");
const oqs = @import("oqs");
const harness = @import("kat_harness");

// libc getenv (the exe links libc via cliboqs), as the parity harnesses do.
extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;

fn envText(name: [*:0]const u8) ?[]const u8 {
    const p = getenv(name) orelse return null;
    return std.mem.span(p);
}

fn envUsize(name: [*:0]const u8, default: usize) usize {
    const text = envText(name) orelse return default;
    return std.fmt.parseInt(usize, text, 10) catch default;
}

fn mode() harness.KatDigests.Mode {
    const text = envText("OQS_KAT_ALL") orelse return .single;
    return if (std.mem.eql(u8, text, "1")) .all else .single;
}

fn selected(name: []const u8, filter: ?[]const u8) bool {
    const list = filter orelse return true;
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |item| {
        if (std.mem.eql(u8, item, name)) return true;
    }
    return false;
}

// The enabled names, in liboqs order, that the filter selects.
fn enabledNames(a: std.mem.Allocator, names: oqs.AlgorithmNames, filter: ?[]const u8) ![]const [:0]const u8 {
    var it = names;
    var list: std.ArrayList([:0]const u8) = .empty;
    while (it.next()) |name| {
        if (selected(name, filter)) try list.append(a, name);
    }
    return list.items;
}

fn run(a: std.mem.Allocator, out: *std.Io.Writer) !void {
    const filter = envText("OQS_KAT_FILTER");
    const the_mode = mode();
    const shard = envUsize("OQS_SHARD", 0);
    const total = @max(envUsize("OQS_TOTAL", 1), 1);

    var kem_digests = try harness.KatDigests.parse(a, harness.kem_kats_json);
    defer kem_digests.deinit();
    var sig_digests = try harness.KatDigests.parse(a, harness.sig_kats_json);
    defer sig_digests.deinit();

    const kems = try enabledNames(a, oqs.Registry.kemNames(), filter);
    const sigs = try enabledNames(a, oqs.Registry.sigNames(), filter);

    var index: usize = 0;
    for (kems) |name| {
        defer index += 1;
        if (index % total != shard) continue;
        if (kem_digests.find(name) == null) {
            try harness.KatReport.writeNoEntry(out, .kem, name);
            continue;
        }
        std.debug.print("  kat[{d}] {s}\n", .{ shard, name });
        const digest = try harness.KatRunner.digestKem(a, name, the_mode);
        try harness.KatReport.writeDigest(out, .kem, name, digest);
    }
    for (sigs) |name| {
        defer index += 1;
        if (index % total != shard) continue;
        if (sig_digests.find(name) == null) {
            try harness.KatReport.writeNoEntry(out, .sig, name);
            continue;
        }
        std.debug.print("  kat[{d}] {s}\n", .{ shard, name });
        const digest = try harness.KatRunner.digestSig(a, name, the_mode);
        try harness.KatReport.writeDigest(out, .sig, name, digest);
    }
}

fn summarize(a: std.mem.Allocator, io: std.Io, path: []const u8, out: *std.Io.Writer) !bool {
    const filter = envText("OQS_KAT_FILTER");
    const lines = try std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(1 << 28));
    var kem_digests = try harness.KatDigests.parse(a, harness.kem_kats_json);
    defer kem_digests.deinit();
    var sig_digests = try harness.KatDigests.parse(a, harness.sig_kats_json);
    defer sig_digests.deinit();

    const kems = try enabledNames(a, oqs.Registry.kemNames(), filter);
    const sigs = try enabledNames(a, oqs.Registry.sigNames(), filter);
    const kem_names = try a.alloc([]const u8, kems.len);
    for (kems, kem_names) |name, *slot| slot.* = name;
    const sig_names = try a.alloc([]const u8, sigs.len);
    for (sigs, sig_names) |name, *slot| slot.* = name;

    const summary = try harness.KatReport.summarize(a, out, .{
        .kem_names = kem_names,
        .sig_names = sig_names,
        .kem_digests = &kem_digests,
        .sig_digests = &sig_digests,
        .mode = mode(),
        .lines = lines,
        .filtered = filter != null,
        .version = oqs.version,
    });
    return summary.problems == 0;
}

pub fn main(init: std.process.Init.Minimal) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var buf: [65536]u8 = undefined;
    var fw = std.Io.File.stdout().writerStreaming(io, &buf);
    const out = &fw.interface;

    var args = init.args.iterate();
    _ = args.skip();
    const command = args.next() orelse "";
    if (std.mem.eql(u8, command, "run")) {
        try run(a, out);
        try fw.flush();
        return;
    }
    if (std.mem.eql(u8, command, "summarize")) {
        const path = args.next() orelse {
            std.debug.print("usage: kat summarize FILE\n", .{});
            std.process.exit(2);
        };
        const ok = try summarize(a, io, path, out);
        try fw.flush();
        if (!ok) std.process.exit(1);
        return;
    }
    std.debug.print("usage: kat run | kat summarize FILE\n", .{});
    std.process.exit(2);
}
