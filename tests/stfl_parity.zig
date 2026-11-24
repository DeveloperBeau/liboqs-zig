//! Tests for the stateful parity check. They cover the height filter that picks
//! which parameter sets run by default, the compare that the parity script uses,
//! and the typed stateful wrappers against the raw C API under the NIST-KAT seed.
//!
//! Keygen runs only for the two cheapest trees, LMS_SHA256_H5_W8 and
//! XMSS-SHA2_10_256, so a Debug run stays fast. The full 70-algorithm check runs
//! through `zig build parity` instead. Expected sizes and counts are written out
//! by hand from RFC 8554 and RFC 8391. Test output never includes secret key bytes.
const std = @import("std");
const oqs = @import("oqs");
const c = @import("c_api");
const filter = @import("stfl_filter");
const compare = @import("stfl_compare");
const build_options = @import("build_options");

const message = "the quick brown fox";

// --- Height filter ----------------------------------------------------------

test "total height is read from XMSS, XMSS^MT and LMS names as written out by hand" {
    const cases = [_]struct { name: []const u8, height: u32 }{
        .{ .name = "XMSS-SHA2_10_256", .height = 10 },
        .{ .name = "XMSS-SHAKE256_16_192", .height = 16 },
        .{ .name = "XMSS-SHA2_20_512", .height = 20 },
        .{ .name = "XMSSMT-SHA2_20/2_256", .height = 20 },
        .{ .name = "XMSSMT-SHAKE_40/8_256", .height = 40 },
        .{ .name = "XMSSMT-SHA2_60/12_256", .height = 60 },
        .{ .name = "LMS_SHA256_H5_W8", .height = 5 },
        .{ .name = "LMS_SHA256_H25_W1", .height = 25 },
        .{ .name = "LMS_SHA256_H10_W4_H5_W8", .height = 15 },
        .{ .name = "LMS_SHA256_H20_W8_H20_W8", .height = 40 },
    };
    for (cases) |case| {
        try std.testing.expectEqual(@as(?u32, case.height), filter.totalHeight(case.name));
    }
}

test "names at height 16 or less are in the default set and taller names are skipped until the all flag" {
    try std.testing.expect(filter.includedByDefault("XMSS-SHA2_10_256"));
    try std.testing.expect(filter.includedByDefault("XMSS-SHA2_16_256"));
    try std.testing.expect(filter.includedByDefault("LMS_SHA256_H15_W8"));
    try std.testing.expect(filter.includedByDefault("LMS_SHA256_H10_W4_H5_W8"));
    try std.testing.expect(!filter.includedByDefault("XMSS-SHA2_20_256"));
    try std.testing.expect(!filter.includedByDefault("XMSSMT-SHA2_20/2_256"));
    try std.testing.expect(!filter.includedByDefault("LMS_SHA256_H10_W2_H10_W2"));
    try std.testing.expect(!filter.includedByDefault("LMS_SHA256_H25_W8"));
    // The all flag brings the skipped ones back, and changes nothing for the rest.
    try std.testing.expect(!filter.isIncluded("XMSSMT-SHA2_20/2_256", false));
    try std.testing.expect(filter.isIncluded("XMSSMT-SHA2_20/2_256", true));
    try std.testing.expect(filter.isIncluded("XMSS-SHA2_10_256", false));
    try std.testing.expect(filter.isIncluded("XMSS-SHA2_10_256", true));
}

test "every enabled stateful name is classified: 29 run by default, 41 are skipped and all 70 run with the all flag" {
    var by_default: usize = 0;
    var skipped: usize = 0;
    var with_all: usize = 0;
    var lms: usize = 0;
    var xmss: usize = 0;
    var xmssmt: usize = 0;
    var seen: usize = 0;
    const total: usize = @intCast(c.OQS_SIG_STFL_alg_count());
    for (0..total) |i| {
        const name = std.mem.span(c.OQS_SIG_STFL_alg_identifier(i));
        if (c.OQS_SIG_STFL_alg_is_enabled(name.ptr) != 1) continue;
        seen += 1;
        const height = filter.totalHeight(name) orelse {
            std.debug.print("enabled name with no readable height: {s}\n", .{name});
            return error.TestUnexpectedResult;
        };
        if (filter.isIncluded(name, true)) with_all += 1;
        if (filter.isIncluded(name, false)) {
            by_default += 1;
            try std.testing.expect(height <= 16);
            if (std.mem.startsWith(u8, name, "LMS_")) lms += 1;
            if (std.mem.startsWith(u8, name, "XMSS-")) xmss += 1;
            if (std.mem.startsWith(u8, name, "XMSSMT-")) xmssmt += 1;
        } else {
            skipped += 1;
            try std.testing.expect(height > 16);
        }
    }
    try std.testing.expectEqual(@as(usize, 70), seen);
    try std.testing.expectEqual(@as(usize, 70), with_all);
    try std.testing.expectEqual(@as(usize, 29), by_default);
    try std.testing.expectEqual(@as(usize, 41), skipped);
    // 15 LMS and 14 XMSS. Every XMSS^MT set is 20 or taller.
    try std.testing.expectEqual(@as(usize, 15), lms);
    try std.testing.expectEqual(@as(usize, 14), xmss);
    try std.testing.expectEqual(@as(usize, 0), xmssmt);
}

test "every enabled liboqs stateful name has a typed wrapper, so the typed harness cannot miss one" {
    const total: usize = @intCast(c.OQS_SIG_STFL_alg_count());
    for (0..total) |i| {
        const name = std.mem.span(c.OQS_SIG_STFL_alg_identifier(i));
        if (c.OQS_SIG_STFL_alg_is_enabled(name.ptr) != 1) continue;
        var found = false;
        inline for (@typeInfo(oqs.sig_stfl).@"struct".decl_names) |d_name| {
            if (std.mem.eql(u8, @field(oqs.sig_stfl, d_name).algorithm_name, name)) found = true;
        }
        if (!found) {
            std.debug.print("no typed wrapper for {s}\n", .{name});
            return error.TestUnexpectedResult;
        }
    }
}

const hashes = [_][]const u8{ "SHA2", "SHAKE", "SHAKE256" };
const lms_heights = [_]u32{ 5, 10, 15, 20, 25 };
const lms_widths = [_]u32{ 1, 2, 4, 8 };

// The seed comes from build.zig (default 0x5717f022, override with
// -Dfuzz-seed=N). The test prints it at the start of a run and again in every
// failure message.
test "fuzz with a seed from the build: generated names get the right height and decision, and malformed or swapped names are never included" {
    const seed: u64 = build_options.fuzz_seed;
    std.debug.print("fuzz seed 0x{x}\n", .{seed});
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();
    var buf: [128]u8 = undefined;

    for (0..3000) |round| {
        // A valid name is built from parts, and its height is worked out from the parts.
        const family = rand.uintLessThan(u8, 3);
        const hash = hashes[rand.uintLessThan(usize, hashes.len)];
        var height: u32 = undefined;
        var good: []const u8 = undefined;
        // The text of the height field, so mutations can target it.
        var height_text: []const u8 = undefined;
        var height_buf: [16]u8 = undefined;
        switch (family) {
            0 => {
                height = rand.intRangeAtMost(u32, 1, 70);
                good = try std.fmt.bufPrint(&buf, "XMSS-{s}_{d}_{d}", .{ hash, height, rand.intRangeAtMost(u32, 1, 512) });
                height_text = try std.fmt.bufPrint(&height_buf, "{d}", .{height});
            },
            1 => {
                height = rand.intRangeAtMost(u32, 1, 70);
                good = try std.fmt.bufPrint(&buf, "XMSSMT-{s}_{d}/{d}_{d}", .{ hash, height, rand.intRangeAtMost(u32, 1, 12), rand.intRangeAtMost(u32, 1, 512) });
                height_text = try std.fmt.bufPrint(&height_buf, "{d}", .{height});
            },
            else => {
                const h1 = lms_heights[rand.uintLessThan(usize, lms_heights.len)];
                const w1 = lms_widths[rand.uintLessThan(usize, lms_widths.len)];
                if (rand.boolean()) {
                    height = h1;
                    good = try std.fmt.bufPrint(&buf, "LMS_SHA256_H{d}_W{d}", .{ h1, w1 });
                } else {
                    const h2 = lms_heights[rand.uintLessThan(usize, lms_heights.len)];
                    const w2 = lms_widths[rand.uintLessThan(usize, lms_widths.len)];
                    height = h1 + h2;
                    good = try std.fmt.bufPrint(&buf, "LMS_SHA256_H{d}_W{d}_H{d}_W{d}", .{ h1, w1, h2, w2 });
                }
                height_text = try std.fmt.bufPrint(&height_buf, "H{d}", .{h1});
            },
        }

        // False negatives: a valid name keeps its height, and the decision follows it.
        if (filter.totalHeight(good) != height) {
            std.debug.print("{s}: height {?d}, expected {d} (seed 0x{x}, round {d})\n", .{ good, filter.totalHeight(good), height, seed, round });
            return error.TestUnexpectedResult;
        }
        if (filter.includedByDefault(good) != (height <= 16)) {
            std.debug.print("{s}: wrong default decision for height {d} (seed 0x{x}, round {d})\n", .{ good, height, seed, round });
            return error.TestUnexpectedResult;
        }
        if (!filter.isIncluded(good, true)) {
            std.debug.print("{s}: left out with the all flag (seed 0x{x}, round {d})\n", .{ good, seed, round });
            return error.TestUnexpectedResult;
        }

        // False positives: each mutation breaks the shape, so none may be included.
        var mut_storage: [160]u8 = undefined;
        const first_sep = std.mem.indexOfScalar(u8, good, '_').?;
        // Search after the first separator, since the hash name can hold digits too.
        const at = std.mem.indexOfPos(u8, good, first_sep + 1, height_text).?;
        const mutations = [_][]const u8{
            // Junk after the height digits.
            try std.fmt.bufPrint(&mut_storage, "{s}x{s}", .{ good[0 .. at + height_text.len], good[at + height_text.len ..] }),
        };
        var extra: [8][]const u8 = undefined;
        var storage2: [8][160]u8 = undefined;
        var n: usize = 0;
        // The first separator turned into a hyphen.
        extra[n] = try std.fmt.bufPrint(&storage2[n], "{s}-{s}", .{ good[0..first_sep], good[first_sep + 1 ..] });
        n += 1;
        // The first letter dropped.
        extra[n] = good[1..];
        n += 1;
        // A stray extra part.
        extra[n] = try std.fmt.bufPrint(&storage2[n], "{s}_5", .{good});
        n += 1;
        // The prefix in lower case.
        extra[n] = try std.fmt.bufPrint(&storage2[n], "{c}{s}", .{ std.ascii.toLower(good[0]), good[1..] });
        n += 1;
        // A sign or a leading zero before the height.
        extra[n] = try std.fmt.bufPrint(&storage2[n], "{s}{s}0{s}", .{ good[0..at], if (rand.boolean()) "+" else "", good[at..] });
        n += 1;
        // The height emptied.
        extra[n] = try std.fmt.bufPrint(&storage2[n], "{s}{s}", .{ good[0..at], good[at + height_text.len ..] });
        n += 1;
        // Another family's prefix on this family's body.
        const body = good[std.mem.indexOfScalar(u8, good, '_').?..];
        extra[n] = try std.fmt.bufPrint(&storage2[n], "{s}{s}", .{ if (family == 0) "XMSSMT-SHA2" else "XMSS-SHA2", body });
        n += 1;
        if (family == 2) {
            // H and W swapped, so the name starts with a width.
            extra[n] = try std.fmt.bufPrint(&storage2[n], "LMS_SHA256_W{d}_H{d}", .{ lms_widths[rand.uintLessThan(usize, lms_widths.len)], lms_heights[rand.uintLessThan(usize, lms_heights.len)] });
            n += 1;
        }
        for (mutations ++ [_][]const u8{}) |m| try expectNotIncluded(m, good, seed, round);
        for (extra[0..n]) |m| try expectNotIncluded(m, good, seed, round);
    }

    // Random bytes never crash the parser, and a name that does parse starts like a stateful name.
    var junk: [40]u8 = undefined;
    for (0..2000) |_| {
        const len = rand.uintLessThan(usize, junk.len);
        for (junk[0..len]) |*ch| ch.* = rand.intRangeAtMost(u8, 0x20, 0x7e);
        const name = junk[0..len];
        if (filter.totalHeight(name) != null) {
            const ok = std.mem.startsWith(u8, name, "LMS_") or std.mem.startsWith(u8, name, "XMSS-") or std.mem.startsWith(u8, name, "XMSSMT-");
            if (!ok) {
                std.debug.print("odd name read as valid: {s} (seed 0x{x})\n", .{ name, seed });
                return error.TestUnexpectedResult;
            }
        }
    }
}

fn expectNotIncluded(mutated: []const u8, original: []const u8, seed: u64, round: usize) !void {
    if (filter.totalHeight(mutated) != null or filter.includedByDefault(mutated)) {
        std.debug.print("mutated name {s} (from {s}) was accepted (seed 0x{x}, round {d})\n", .{ mutated, original, seed, round });
        return error.TestUnexpectedResult;
    }
}

// --- Compare ---------------------------------------------------------------

const list_text = "run A_ONE 5\nrun B_TWO 10\nskip C_THREE 20\n";
const out_text =
    "A_ONE pk 0a0b\nA_ONE sig 1122\nA_ONE verified 01\nA_ONE remaining 000000000000001e\nA_ONE total 000000000000001f\n" ++
    "B_TWO pk 0c0d\nB_TWO sig 3344\nB_TWO verified 01\nB_TWO remaining 00000000000003fe\nB_TWO total 00000000000003ff\n";

fn runCompare(in: compare.Inputs, report: *std.Io.Writer.Allocating) !compare.Result {
    return compare.compare(std.testing.allocator, in, &report.writer);
}

test "compare passes when both sides agree and counts checked and skipped names" {
    var report: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer report.deinit();
    const r = try runCompare(.{ .cref_list = list_text, .zref_list = list_text, .cref_out = out_text, .zref_out = out_text }, &report);
    try std.testing.expectEqual(@as(usize, 0), r.failures);
    try std.testing.expectEqual(@as(usize, 2), r.checked);
    try std.testing.expectEqual(@as(usize, 1), r.skipped);
}

test "compare fails on a one-byte difference in any one of the five fields" {
    const fields = [_][]const u8{ "pk", "sig", "verified", "remaining", "total" };
    inline for (fields) |field| {
        const needle = "A_ONE " ++ field ++ " ";
        const at = std.mem.indexOf(u8, out_text, needle).? + needle.len;
        var changed: [out_text.len]u8 = undefined;
        @memcpy(&changed, out_text);
        // The last hex digit of the value is bumped from its original.
        const end = std.mem.indexOfScalarPos(u8, out_text, at, '\n').?;
        changed[end - 1] = if (changed[end - 1] == '0') '1' else '0';
        var report: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer report.deinit();
        const r = try runCompare(.{ .cref_list = list_text, .zref_list = list_text, .cref_out = out_text, .zref_out = &changed }, &report);
        try std.testing.expectEqual(@as(usize, 1), r.failures);
        try std.testing.expect(std.mem.indexOf(u8, report.written(), "VALUE DIFF:      A_ONE " ++ field) != null);
    }
}

test "compare fails when a field is missing on one side or on both" {
    const without_total = "A_ONE pk 0a0b\nA_ONE sig 1122\nA_ONE verified 01\nA_ONE remaining 000000000000001e\n" ++
        "B_TWO pk 0c0d\nB_TWO sig 3344\nB_TWO verified 01\nB_TWO remaining 00000000000003fe\nB_TWO total 00000000000003ff\n";
    var report: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer report.deinit();
    var r = try runCompare(.{ .cref_list = list_text, .zref_list = list_text, .cref_out = out_text, .zref_out = without_total }, &report);
    try std.testing.expectEqual(@as(usize, 1), r.failures);
    try std.testing.expect(std.mem.indexOf(u8, report.written(), "MISSING IN ZREF: A_ONE total") != null);
    report.clearRetainingCapacity();
    r = try runCompare(.{ .cref_list = list_text, .zref_list = list_text, .cref_out = without_total, .zref_out = out_text }, &report);
    try std.testing.expectEqual(@as(usize, 1), r.failures);
    try std.testing.expect(std.mem.indexOf(u8, report.written(), "MISSING IN CREF: A_ONE total") != null);
    // Both sides dropping the same field is still a failure.
    report.clearRetainingCapacity();
    r = try runCompare(.{ .cref_list = list_text, .zref_list = list_text, .cref_out = without_total, .zref_out = without_total }, &report);
    try std.testing.expectEqual(@as(usize, 2), r.failures);
}

test "compare fails on a dropped algorithm, an unexpected algorithm and output for a skipped name" {
    const only_a = "A_ONE pk 0a0b\nA_ONE sig 1122\nA_ONE verified 01\nA_ONE remaining 000000000000001e\nA_ONE total 000000000000001f\n";
    var report: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer report.deinit();
    var r = try runCompare(.{ .cref_list = list_text, .zref_list = list_text, .cref_out = out_text, .zref_out = only_a }, &report);
    try std.testing.expectEqual(@as(usize, 5), r.failures);
    report.clearRetainingCapacity();
    const extra = out_text ++ "C_THREE pk ff\n";
    r = try runCompare(.{ .cref_list = list_text, .zref_list = list_text, .cref_out = out_text, .zref_out = extra }, &report);
    try std.testing.expectEqual(@as(usize, 1), r.failures);
    try std.testing.expect(std.mem.indexOf(u8, report.written(), "UNEXPECTED IN ZREF: C_THREE pk") != null);
}

test "compare fails when the two sides disagree about which names run or skip" {
    const other_list = "run A_ONE 5\nskip B_TWO 10\nskip C_THREE 20\n";
    var report: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer report.deinit();
    var r = try runCompare(.{ .cref_list = list_text, .zref_list = other_list, .cref_out = out_text, .zref_out = out_text }, &report);
    try std.testing.expect(r.failures >= 1);
    try std.testing.expect(std.mem.indexOf(u8, report.written(), "LIST DIFF:            B_TWO") != null);
    report.clearRetainingCapacity();
    const short_list = "run A_ONE 5\nrun B_TWO 10\n";
    r = try runCompare(.{ .cref_list = list_text, .zref_list = short_list, .cref_out = out_text, .zref_out = out_text }, &report);
    try std.testing.expect(std.mem.indexOf(u8, report.written(), "LIST MISSING IN ZREF: C_THREE") != null);
    report.clearRetainingCapacity();
    r = try runCompare(.{ .cref_list = short_list, .zref_list = list_text, .cref_out = out_text, .zref_out = out_text }, &report);
    try std.testing.expect(std.mem.indexOf(u8, report.written(), "LIST MISSING IN CREF: C_THREE") != null);
}

test "compare fails when nothing is checked and when one side repeats a field with another value" {
    var report: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer report.deinit();
    var r = try runCompare(.{ .cref_list = "", .zref_list = "", .cref_out = "", .zref_out = "" }, &report);
    try std.testing.expectEqual(@as(usize, 1), r.failures);
    report.clearRetainingCapacity();
    const repeated = out_text ++ "A_ONE pk ffff\n";
    r = try runCompare(.{ .cref_list = list_text, .zref_list = list_text, .cref_out = out_text, .zref_out = repeated }, &report);
    try std.testing.expectEqual(@as(usize, 1), r.failures);
    try std.testing.expect(std.mem.indexOf(u8, report.written(), "DUPLICATE IN ZREF: A_ONE pk") != null);
}

// --- Frozen snapshot -------------------------------------------------------

test "the frozen snapshot still has 262 lines, no stateful names, and its recorded sha256" {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "tests/snapshots/0.16.0.txt", std.testing.allocator, .limited(1 << 20));
    defer std.testing.allocator.free(bytes);
    var lines: usize = 0;
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        lines += 1;
        try std.testing.expect(std.mem.indexOf(u8, line, "XMSS") == null);
        try std.testing.expect(std.mem.indexOf(u8, line, "LMS") == null);
    }
    try std.testing.expectEqual(@as(usize, 262), lines);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    var hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&hex, "{x}", .{&digest});
    try std.testing.expectEqualStrings("0d0eb1c0bfc486244139f21bbd7fa14a67482fd4143d04947e47ae40d99ac36a", &hex);
}

// --- Typed wrappers against the raw C API ------------------------------------

fn seedKat() void {
    var e: [48]u8 = undefined;
    for (&e, 0..) |*b, i| b.* = @intCast(i);
    oqs.testing.seedKat(&e);
}

const Outputs = struct {
    pk: []u8,
    sig: []u8,
    remaining: u64,
    total: u64,

    fn deinit(self: Outputs, a: std.mem.Allocator) void {
        a.free(self.pk);
        a.free(self.sig);
    }
};

// liboqs asks for a store callback before it signs. LMS drops one registered
// with a null context, so the key object stands in as the context.
fn storeOk(sk_buf: [*c]u8, len: usize, ctx: ?*anyopaque) callconv(.c) c.OQS_STATUS {
    _ = sk_buf;
    _ = len;
    _ = ctx;
    return c.OQS_SUCCESS;
}

// One keygen and one sign through the raw C API, the way harness/stfl_cref.c does.
fn rawRun(a: std.mem.Allocator, name: [:0]const u8) !Outputs {
    oqs.ensureInitialized();
    const s = c.OQS_SIG_STFL_new(name.ptr) orelse return error.AlgorithmNotAvailable;
    defer c.OQS_SIG_STFL_free(s);
    const key = c.OQS_SIG_STFL_SECRET_KEY_new(name.ptr) orelse return error.AlgorithmNotAvailable;
    defer c.OQS_SIG_STFL_SECRET_KEY_free(key);
    c.OQS_SIG_STFL_SECRET_KEY_SET_store_cb(key, storeOk, key);
    const pk = try a.alloc(u8, s.*.length_public_key);
    errdefer a.free(pk);
    const sig_buf = try a.alloc(u8, s.*.length_signature);
    defer a.free(sig_buf);
    var sig_len: usize = 0;
    seedKat();
    try std.testing.expectEqual(c.OQS_SUCCESS, c.OQS_SIG_STFL_keypair(s, pk.ptr, key));
    seedKat();
    try std.testing.expectEqual(c.OQS_SUCCESS, c.OQS_SIG_STFL_sign(s, sig_buf.ptr, &sig_len, message.ptr, message.len, key));
    var remaining: c_ulonglong = 0;
    var total: c_ulonglong = 0;
    try std.testing.expectEqual(c.OQS_SUCCESS, c.OQS_SIG_STFL_sigs_remaining(s, &remaining, key));
    try std.testing.expectEqual(c.OQS_SUCCESS, c.OQS_SIG_STFL_sigs_total(s, &total, key));
    return .{ .pk = pk, .sig = try a.dupe(u8, sig_buf[0..sig_len]), .remaining = remaining, .total = total };
}

// The same operations through the typed wrapper, as harness/stfl_zref.zig does.
// `tampered_ok` reports whether a one-byte change to the signature or to the
// message verified, which must stay false.
fn typedRun(comptime T: type, a: std.mem.Allocator) !struct { out: Outputs, valid: bool, tampered_ok: bool } {
    seedKat();
    var kp = try T.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    seedKat();
    var s = try kp.secret_key.sign(message);
    defer s.deinit();
    const valid = try kp.public_key.isValidSignature(message, s.bytes);
    const bad_sig = try a.dupe(u8, s.bytes);
    defer a.free(bad_sig);
    bad_sig[bad_sig.len / 2] ^= 0x01;
    var bad_msg: [message.len]u8 = undefined;
    @memcpy(&bad_msg, message);
    bad_msg[0] ^= 0x01;
    const tampered_ok = try kp.public_key.isValidSignature(message, bad_sig) or
        try kp.public_key.isValidSignature(&bad_msg, s.bytes);
    return .{
        .out = .{
            .pk = try a.dupe(u8, kp.public_key.bytes),
            .sig = try a.dupe(u8, s.bytes),
            .remaining = try kp.secret_key.sigsRemaining(),
            .total = try kp.secret_key.sigsTotal(),
        },
        .valid = valid,
        .tampered_ok = tampered_ok,
    };
}

fn expectTypedMatchesRaw(comptime T: type) !void {
    const a = std.testing.allocator;
    const raw = try rawRun(a, T.algorithm_name);
    defer raw.deinit(a);
    const typed = try typedRun(T, a);
    defer typed.out.deinit(a);
    try std.testing.expectEqualSlices(u8, raw.pk, typed.out.pk);
    try std.testing.expectEqualSlices(u8, raw.sig, typed.out.sig);
    try std.testing.expectEqual(raw.remaining, typed.out.remaining);
    try std.testing.expectEqual(raw.total, typed.out.total);
    try std.testing.expect(typed.valid);
    try std.testing.expect(!typed.tampered_ok);
}

test "LMS_SHA256_H5_W8 typed pk, signature and counts equal the raw C API, with hand-written lengths and counts" {
    try expectTypedMatchesRaw(oqs.sig_stfl.LmsSha256H5W8);
    const raw = try rawRun(std.testing.allocator, "LMS_SHA256_H5_W8");
    defer raw.deinit(std.testing.allocator);
    // RFC 8554: pk is 60 bytes, a one-level H5 W8 signature is 1296 bytes, a
    // tree of height 5 counts 31, and one signature leaves 30.
    try std.testing.expectEqual(@as(usize, 60), raw.pk.len);
    try std.testing.expectEqual(@as(usize, 1296), raw.sig.len);
    try std.testing.expectEqual(@as(u64, 31), raw.total);
    try std.testing.expectEqual(@as(u64, 30), raw.remaining);
}

test "XMSS-SHA2_10_256 typed pk, signature and counts equal the raw C API, with hand-written lengths and counts" {
    try expectTypedMatchesRaw(oqs.sig_stfl.XmssSha256H10);
    const raw = try rawRun(std.testing.allocator, "XMSS-SHA2_10_256");
    defer raw.deinit(std.testing.allocator);
    // RFC 8391: pk is 68 bytes with the OID, the signature is 2500 bytes, a
    // tree of height 10 counts 1023, and one signature leaves 1022.
    try std.testing.expectEqual(@as(usize, 68), raw.pk.len);
    try std.testing.expectEqual(@as(usize, 2500), raw.sig.len);
    try std.testing.expectEqual(@as(u64, 1023), raw.total);
    try std.testing.expectEqual(@as(u64, 1022), raw.remaining);
}

test "typed signing under the same seed and message twice gives the same pk and signature" {
    const a = std.testing.allocator;
    const first = try typedRun(oqs.sig_stfl.LmsSha256H5W8, a);
    defer first.out.deinit(a);
    const second = try typedRun(oqs.sig_stfl.LmsSha256H5W8, a);
    defer second.out.deinit(a);
    try std.testing.expectEqualSlices(u8, first.out.pk, second.out.pk);
    try std.testing.expectEqualSlices(u8, first.out.sig, second.out.sig);
}

// --- Known answers ---------------------------------------------------------
// The values below come from the C library under the NIST-KAT seed (bytes 0 to
// 47) and the message `the quick brown fox`. The LMS public key and the
// digests of the first signatures are the same ones the liboqs-rust tests pin
// from the C oracle. A digest is the first 32 bytes of SHAKE128, in lower case hex.

fn shakeHex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha3.Shake128.hash(bytes, &digest, .{});
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{&digest}) catch unreachable;
    return hex;
}

test "typed LMS_SHA256_H5_W8 public key and signature are the known answers of the C library" {
    const a = std.testing.allocator;
    const typed = try typedRun(oqs.sig_stfl.LmsSha256H5W8, a);
    defer typed.out.deinit(a);
    const pk_hex = "000000010000000500000004056a8c266f9ef97ed08541dbd2e1ffa1bbbc42e0a4141c407bd56a6d260ef91a7cc6d5f8e8bec690ec69cddd1eeeb3c7";
    var expected_pk: [60]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_pk, pk_hex);
    try std.testing.expectEqualSlices(u8, &expected_pk, typed.out.pk);
    const sig_digest = shakeHex(typed.out.sig);
    try std.testing.expectEqualStrings("ec93edda47cc36596b022f7fb3fa29f59ed81ba8e5240231b86b007a6ebeab3b", &sig_digest);
}

test "typed XMSS-SHA2_10_256 public key and signature are the known answers of the C library" {
    const a = std.testing.allocator;
    const typed = try typedRun(oqs.sig_stfl.XmssSha256H10, a);
    defer typed.out.deinit(a);
    const pk_digest = shakeHex(typed.out.pk);
    try std.testing.expectEqualStrings("73c3485907e3c56d2e9fbffcf81215f4a922ca75407c5bf7bdd0f4e9f7fa64e5", &pk_digest);
    const sig_digest = shakeHex(typed.out.sig);
    try std.testing.expectEqualStrings("bd7c22cd19b4b8a145eb5ecbcd91631e20550c49da87858b4b1ed5f4e4d09dd6", &sig_digest);
}
