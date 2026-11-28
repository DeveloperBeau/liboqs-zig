//! Behaviour harness: runs the behaviour checks and a short fuzz pass over every
//! enabled KEM and stateless signature scheme, through the core wrappers.
//!
//! `tools/run-shards.sh behaviour` runs it in shards. OQS_SHARD and OQS_TOTAL
//! pick the algorithms whose index modulo the total is the shard. Each
//! algorithm seeds the liboqs KAT generator from the base seed and its index,
//! so a failure repeats with the same seed whatever the split. A shard prints
//! one line per algorithm it finished, then one registry line. The script
//! `tools/behaviour.sh` merges them and fails when the counts do not match.
//!
//! OQS_BEHAVIOUR_SEED sets the base seed. The default is the fuzz seed of the
//! test steps. OQS_BEHAVIOUR_ONLY, a comma separated list of algorithm names,
//! runs just those. It is for trying the harness itself. The registry line then
//! counts only the enabled names on the list, and the script reports a
//! filtered run apart from a full one.
const std = @import("std");
const oqs = @import("oqs");
const checks = @import("behaviour_checks");

// libc getenv (the exe links libc via cliboqs); std's env API churned in 0.16.
extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;

const default_seed: u64 = 0x5717_F022;

// Rounds of the fuzz pass per algorithm. The test steps run many more on a sample.
const fuzz_rounds = 1;

fn envUsize(name: [*:0]const u8, default: usize) usize {
    const p = getenv(name) orelse return default;
    return std.fmt.parseInt(usize, std.mem.span(p), 10) catch default;
}

// The names on OQS_BEHAVIOUR_ONLY, or null when it is not set.
fn onlyList() ?[]const u8 {
    const p = getenv("OQS_BEHAVIOUR_ONLY") orelse return null;
    return std.mem.span(p);
}

fn wanted(only: ?[]const u8, name: []const u8) bool {
    const list = only orelse return true;
    var it = std.mem.tokenizeScalar(u8, list, ',');
    while (it.next()) |item| {
        if (std.mem.eql(u8, item, name)) return true;
    }
    return false;
}

fn envSeed() u64 {
    const p = getenv("OQS_BEHAVIOUR_SEED") orelse return default_seed;
    return std.fmt.parseInt(u64, std.mem.span(p), 0) catch default_seed;
}

pub fn main() !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    var buf: [4096]u8 = undefined;
    var fw = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &fw.interface;

    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    const a = da.allocator();

    const shard = envUsize("OQS_SHARD", 0);
    const total = @max(envUsize("OQS_TOTAL", 1), 1);
    const base_seed = envSeed();
    std.debug.print("behaviour seed 0x{x}, shard {d} of {d}\n", .{ base_seed, shard, total });

    const only = onlyList();
    var index: usize = 0;
    var registry_kems: usize = 0;
    var registry_sigs: usize = 0;

    var kem_names = oqs.Registry.kemNames();
    while (kem_names.next()) |name| : (index += 1) {
        if (!wanted(only, name)) continue;
        registry_kems += 1;
        if (index % total != shard) continue;
        std.debug.print("  behaviour[{d}] KEM {s}\n", .{ shard, name });
        var prng = std.Random.DefaultPrng.init(base_seed +% index);
        try checks.checkKem(a, name, prng.random());
        try checks.fuzzKem(a, name, prng.random(), fuzz_rounds);
        try w.print("KEM {s}\n", .{name});
    }
    var sig_names = oqs.Registry.sigNames();
    while (sig_names.next()) |name| : (index += 1) {
        if (!wanted(only, name)) continue;
        registry_sigs += 1;
        if (index % total != shard) continue;
        std.debug.print("  behaviour[{d}] SIG {s}\n", .{ shard, name });
        var prng = std.Random.DefaultPrng.init(base_seed +% index);
        try checks.checkSig(a, name, prng.random());
        try checks.fuzzSig(a, name, prng.random(), fuzz_rounds);
        try w.print("SIG {s}\n", .{name});
    }
    // What the registry lists, so the script can tell a skipped algorithm from a short list.
    if (only == null) {
        try w.print("REGISTRY {d} {d}\n", .{ oqs.Registry.enabledKemCount(), oqs.Registry.enabledSigCount() });
    } else {
        try w.print("REGISTRY {d} {d} FILTERED\n", .{ registry_kems, registry_sigs });
    }
    try fw.flush();
}
