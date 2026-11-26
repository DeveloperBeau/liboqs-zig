//! Behavioral tests for `oqs.Registry`: the enabled name lists, the enabled
//! checks and counts, and the description lookup. Every expected value is
//! written out by hand from the liboqs 0.16.0 headers and algorithm sources,
//! not read back from the registry. No test here generates a key.
const std = @import("std");
const oqs = @import("oqs");
const build_options = @import("build_options");

const Registry = oqs.Registry;

// --- Counts and lists -----------------------------------------------------

test "this build enables 41 KEMs, 221 signatures and 70 stateful signatures, 262 stateless in all" {
    // OQS_KEM_algs_length is 41 and OQS_SIG_algs_length is 65 + 156 in the
    // 0.16.0 headers, and every family is enabled here.
    try std.testing.expectEqual(@as(usize, 41), Registry.enabledKemCount());
    try std.testing.expectEqual(@as(usize, 221), Registry.enabledSigCount());
    try std.testing.expectEqual(@as(usize, 70), Registry.enabledSigStflCount());
    try std.testing.expectEqual(@as(usize, 262), Registry.enabledKemCount() + Registry.enabledSigCount());
}

const ListCase = struct { names: oqs.AlgorithmNames, first: []const u8, second: []const u8, last: []const u8, count: usize };

fn checkList(e: ListCase) !void {
    var it = e.names;
    var n: usize = 0;
    var previous: []const u8 = "";
    while (it.next()) |name| : (n += 1) {
        if (n == 0) try std.testing.expectEqualStrings(e.first, name);
        if (n == 1) try std.testing.expectEqualStrings(e.second, name);
        previous = name;
    }
    try std.testing.expectEqualStrings(e.last, previous);
    try std.testing.expectEqual(e.count, n);
    // A finished list stays finished.
    try std.testing.expect(it.next() == null);
    try std.testing.expect(it.next() == null);
}

test "each name list is in liboqs order, from its first to its last identifier" {
    // The first, second and last entries of the identifier arrays in kem.c,
    // sig.c and sig_stfl.c.
    try checkList(.{ .names = Registry.kemNames(), .first = "BIKE-L1", .second = "BIKE-L3", .last = "eFrodoKEM-1344-SHAKE", .count = 41 });
    try checkList(.{ .names = Registry.sigNames(), .first = "ML-DSA-44", .second = "ML-DSA-65", .last = "SLH_DSA_SHAKE_256_PREHASH_SHAKE_256F", .count = 221 });
    try checkList(.{ .names = Registry.sigStflNames(), .first = "XMSS-SHA2_10_256", .second = "XMSS-SHA2_16_256", .last = "LMS_SHA256_H20_W8_H20_W8", .count = 70 });
}

test "every name is listed once, and no name is in two kinds" {
    var all: [400][]const u8 = undefined;
    var n: usize = 0;
    inline for (.{ Registry.kemNames(), Registry.sigNames(), Registry.sigStflNames() }) |names| {
        var it = names;
        while (it.next()) |name| : (n += 1) {
            for (all[0..n]) |seen| try std.testing.expect(!std.mem.eql(u8, seen, name));
            all[n] = name;
        }
    }
    try std.testing.expectEqual(@as(usize, 332), n);
}

test "a fresh list starts again from the first name" {
    var a = Registry.kemNames();
    _ = a.next();
    _ = a.next();
    var b = Registry.kemNames();
    try std.testing.expectEqualStrings("BIKE-L1", b.next().?);
}

// --- Descriptions, hand-written from the liboqs sources -----------------

test "ML-KEM-768 description matches the liboqs 0.16.0 values" {
    const d = Registry.kemDescription("ML-KEM-768").?;
    try std.testing.expectEqualStrings("ML-KEM-768", d.name);
    try std.testing.expectEqualStrings("FIPS203", d.algorithmVersion);
    try std.testing.expectEqual(@as(u8, 3), d.claimedNistLevel);
    try std.testing.expect(d.isIndCcaSecure);
    try std.testing.expectEqual(@as(usize, 1184), d.publicKeyLength);
    try std.testing.expectEqual(@as(usize, 2400), d.secretKeyLength);
    try std.testing.expectEqual(@as(usize, 1088), d.ciphertextLength);
    try std.testing.expectEqual(@as(usize, 32), d.sharedSecretLength);
    try std.testing.expectEqual(@as(usize, 64), d.keyPairSeedLength);
    try std.testing.expectEqual(@as(usize, 32), d.encapsulationSeedLength);
}

test "BIKE-L1 description reports IND-CPA, level 1 and no seed lengths" {
    const d = Registry.kemDescription("BIKE-L1").?;
    try std.testing.expectEqualStrings("BIKE-L1", d.name);
    try std.testing.expectEqualStrings("Additional - 01/27/2023", d.algorithmVersion);
    try std.testing.expectEqual(@as(u8, 1), d.claimedNistLevel);
    try std.testing.expect(!d.isIndCcaSecure);
    try std.testing.expectEqual(@as(usize, 1541), d.publicKeyLength);
    try std.testing.expectEqual(@as(usize, 5223), d.secretKeyLength);
    try std.testing.expectEqual(@as(usize, 1573), d.ciphertextLength);
    try std.testing.expectEqual(@as(usize, 32), d.sharedSecretLength);
    try std.testing.expectEqual(@as(usize, 0), d.keyPairSeedLength);
    try std.testing.expectEqual(@as(usize, 0), d.encapsulationSeedLength);
}

test "ML-DSA-65 description matches the liboqs 0.16.0 values and supports a context" {
    const d = Registry.sigDescription("ML-DSA-65").?;
    try std.testing.expectEqualStrings("ML-DSA-65", d.name);
    try std.testing.expectEqualStrings("FIPS204", d.algorithmVersion);
    try std.testing.expectEqual(@as(u8, 3), d.claimedNistLevel);
    try std.testing.expect(d.isEufCmaSecure);
    try std.testing.expect(d.isSufCmaSecure);
    try std.testing.expect(d.supportsContext);
    try std.testing.expectEqual(@as(usize, 1952), d.publicKeyLength);
    try std.testing.expectEqual(@as(usize, 4032), d.secretKeyLength);
    try std.testing.expectEqual(@as(usize, 3309), d.signatureLength);
}

test "Falcon-512 description reports no context support and no SUF-CMA" {
    const d = Registry.sigDescription("Falcon-512").?;
    try std.testing.expectEqualStrings("Falcon-512", d.name);
    try std.testing.expectEqualStrings("20211101 with PQClean patches", d.algorithmVersion);
    try std.testing.expectEqual(@as(u8, 1), d.claimedNistLevel);
    try std.testing.expect(d.isEufCmaSecure);
    try std.testing.expect(!d.isSufCmaSecure);
    try std.testing.expect(!d.supportsContext);
    try std.testing.expectEqual(@as(usize, 897), d.publicKeyLength);
    try std.testing.expectEqual(@as(usize, 1281), d.secretKeyLength);
    try std.testing.expectEqual(@as(usize, 752), d.signatureLength);
}

test "LMS_SHA256_H5_W8 description matches the liboqs 0.16.0 values" {
    const d = Registry.sigStflDescription("LMS_SHA256_H5_W8").?;
    // OQS_LMS_ID_sha256_h5_w8 in sig_stfl_lms.h.
    try std.testing.expectEqual(@as(u32, 0x0154), d.objectIdentifier);
    try std.testing.expectEqualStrings("LMS_SHA256_H5_W8", d.name);
    try std.testing.expectEqualStrings("https://datatracker.ietf.org/doc/html/rfc8554", d.algorithmVersion);
    try std.testing.expect(d.isEufCmaSecure);
    try std.testing.expect(!d.isSufCmaSecure);
    try std.testing.expectEqual(@as(usize, 60), d.publicKeyLength);
    try std.testing.expectEqual(@as(usize, 64), d.secretKeyLength);
    try std.testing.expectEqual(@as(usize, 1296), d.signatureLength);
}

test "XMSS-SHA2_10_256 description matches the liboqs 0.16.0 values" {
    const d = Registry.sigStflDescription("XMSS-SHA2_10_256").?;
    // sig_stfl_xmss.h: OID 0x01, public key 64 + 4, secret key 1373 + 4, signature 2500.
    try std.testing.expectEqual(@as(u32, 0x01), d.objectIdentifier);
    try std.testing.expectEqualStrings("XMSS-SHA2_10_256", d.name);
    try std.testing.expectEqualStrings("https://datatracker.ietf.org/doc/html/rfc8391", d.algorithmVersion);
    try std.testing.expect(d.isEufCmaSecure);
    try std.testing.expect(!d.isSufCmaSecure);
    try std.testing.expectEqual(@as(usize, 68), d.publicKeyLength);
    try std.testing.expectEqual(@as(usize, 1377), d.secretKeyLength);
    try std.testing.expectEqual(@as(usize, 2500), d.signatureLength);
}

// --- Agreement with the typed wrappers ------------------------------------

fn listed(names: oqs.AlgorithmNames, name: []const u8) bool {
    var it = names;
    while (it.next()) |candidate| {
        if (std.mem.eql(u8, candidate, name)) return true;
    }
    return false;
}

test "every typed KEM wrapper has a description with the same name and lengths, and every listed KEM has a wrapper" {
    comptime var count: usize = 0;
    inline for (@typeInfo(oqs.kem).@"struct".decl_names) |d_name| {
        const spec = @field(oqs.kem, d_name).info;
        const d = Registry.kemDescription(spec.name) orelse {
            std.debug.print("no description for typed KEM {s}\n", .{spec.name});
            return error.TestUnexpectedResult;
        };
        try std.testing.expectEqualStrings(spec.name, d.name);
        try std.testing.expectEqual(spec.public_key, d.publicKeyLength);
        try std.testing.expectEqual(spec.secret_key, d.secretKeyLength);
        try std.testing.expectEqual(spec.ciphertext, d.ciphertextLength);
        try std.testing.expectEqual(spec.shared_secret, d.sharedSecretLength);
        count += 1;
    }
    var it = Registry.kemNames();
    var n: usize = 0;
    outer: while (it.next()) |name| : (n += 1) {
        inline for (@typeInfo(oqs.kem).@"struct".decl_names) |d_name| {
            if (std.mem.eql(u8, @field(oqs.kem, d_name).info.name, name)) continue :outer;
        }
        std.debug.print("no typed wrapper for listed KEM {s}\n", .{name});
        return error.TestUnexpectedResult;
    }
    try std.testing.expectEqual(count, n);
}

test "every typed signature wrapper has a description with the same name and lengths, and every listed signature has a wrapper" {
    comptime var count: usize = 0;
    inline for (@typeInfo(oqs.sig).@"struct".decl_names) |d_name| {
        const spec = @field(oqs.sig, d_name).info;
        const d = Registry.sigDescription(spec.name) orelse {
            std.debug.print("no description for typed signature {s}\n", .{spec.name});
            return error.TestUnexpectedResult;
        };
        try std.testing.expectEqualStrings(spec.name, d.name);
        try std.testing.expectEqual(spec.public_key, d.publicKeyLength);
        try std.testing.expectEqual(spec.secret_key, d.secretKeyLength);
        try std.testing.expectEqual(spec.signature_max, d.signatureLength);
        count += 1;
    }
    var it = Registry.sigNames();
    var n: usize = 0;
    @setEvalBranchQuota(100000);
    outer: while (it.next()) |name| : (n += 1) {
        inline for (@typeInfo(oqs.sig).@"struct".decl_names) |d_name| {
            if (std.mem.eql(u8, @field(oqs.sig, d_name).info.name, name)) continue :outer;
        }
        std.debug.print("no typed wrapper for listed signature {s}\n", .{name});
        return error.TestUnexpectedResult;
    }
    try std.testing.expectEqual(count, n);
}

test "every typed stateful wrapper has a description with the same name and lengths, and every listed stateful scheme has a wrapper" {
    comptime var count: usize = 0;
    inline for (@typeInfo(oqs.sig_stfl).@"struct".decl_names) |d_name| {
        const spec = @field(oqs.sig_stfl, d_name).info;
        const d = Registry.sigStflDescription(spec.name) orelse {
            std.debug.print("no description for typed stateful scheme {s}\n", .{spec.name});
            return error.TestUnexpectedResult;
        };
        try std.testing.expectEqualStrings(spec.name, d.name);
        try std.testing.expectEqual(spec.public_key, d.publicKeyLength);
        try std.testing.expectEqual(spec.secret_key, d.secretKeyLength);
        try std.testing.expectEqual(spec.signature_max, d.signatureLength);
        count += 1;
    }
    var it = Registry.sigStflNames();
    var n: usize = 0;
    outer: while (it.next()) |name| : (n += 1) {
        inline for (@typeInfo(oqs.sig_stfl).@"struct".decl_names) |d_name| {
            if (std.mem.eql(u8, @field(oqs.sig_stfl, d_name).info.name, name)) continue :outer;
        }
        std.debug.print("no typed wrapper for listed stateful scheme {s}\n", .{name});
        return error.TestUnexpectedResult;
    }
    try std.testing.expectEqual(count, n);
}

// --- Enabled checks -------------------------------------------------------

test "the enabled checks are true for an enabled name of their own kind" {
    try std.testing.expect(Registry.isKemEnabled("ML-KEM-768"));
    try std.testing.expect(Registry.isSigEnabled("ML-DSA-65"));
    try std.testing.expect(Registry.isSigStflEnabled("LMS_SHA256_H5_W8"));
}

test "the enabled checks are false for another kind, an unknown name and an empty name" {
    try std.testing.expect(!Registry.isKemEnabled("ML-DSA-65"));
    try std.testing.expect(!Registry.isKemEnabled("LMS_SHA256_H5_W8"));
    try std.testing.expect(!Registry.isSigEnabled("ML-KEM-768"));
    try std.testing.expect(!Registry.isSigEnabled("XMSS-SHA2_10_256"));
    try std.testing.expect(!Registry.isSigStflEnabled("ML-DSA-65"));
    try std.testing.expect(!Registry.isSigStflEnabled("ML-KEM-768"));
    try std.testing.expect(!Registry.isKemEnabled("ML-KEM-769"));
    try std.testing.expect(!Registry.isSigEnabled(""));
}

// --- Misuse ---------------------------------------------------------------

// Every family liboqs 0.16.0 defines is enabled in build/enabled-families.txt,
// and the enabled counts equal the liboqs list lengths (41, 221 and 70). So
// no name exists that liboqs knows and this build leaves out, and there is no
// such case to test.
const misuses = [_]struct { kem: []const u8, sig: []const u8, sig_stfl: []const u8 }{
    // Empty.
    .{ .kem = "", .sig = "", .sig_stfl = "" },
    // Trailing space.
    .{ .kem = "ML-KEM-768 ", .sig = "ML-DSA-65 ", .sig_stfl = "LMS_SHA256_H5_W8 " },
    // Leading space.
    .{ .kem = " ML-KEM-768", .sig = " ML-DSA-65", .sig_stfl = " LMS_SHA256_H5_W8" },
    // Lowercase with a trailing space. Case is ignored, the space is not.
    .{ .kem = "ml-kem-768 ", .sig = "ml-dsa-65 ", .sig_stfl = "lms_sha256_h5_w8 " },
    // A prefix of an enabled name.
    .{ .kem = "ML-KEM-76", .sig = "ML-DSA-6", .sig_stfl = "LMS_SHA256_H5_W" },
    // A mixed-case prefix of an enabled name.
    .{ .kem = "ml-KEM-76", .sig = "Ml-dSa-6", .sig_stfl = "lms_SHA256_h5_w" },
    // An enabled name with more after a nul byte, which C would cut off.
    .{ .kem = "ML-KEM-768\x00", .sig = "ML-DSA-65\x00x", .sig_stfl = "LMS_SHA256_H5_W8\x00" },
    .{ .kem = "ml-kem-768\x00", .sig = "ml-dsa-65\x00", .sig_stfl = "lms_sha256_h5_w8\x00X" },
    // A digit or punctuation byte off by 0x20, the bit that ASCII case
    // changes for letters. Only letters are folded.
    .{ .kem = "ML\rKEM-768", .sig = "ML-DSA\r65", .sig_stfl = "LMS\x7fSHA256_H5_W8" },
    .{ .kem = "ML-KEM-\x17\x16\x18", .sig = "ML-DSA-\x16\x15", .sig_stfl = "LMS_SHA256_H\x15_W\x18" },
    // A byte of an enabled name with the high bit set, which is not ASCII.
    .{ .kem = "ML\xadKEM-768", .sig = "\xcdL-DSA-65", .sig_stfl = "LMS_SHA256_H5_W\xb8" },
    // A name of another kind.
    .{ .kem = "ML-DSA-65", .sig = "ML-KEM-768", .sig_stfl = "ML-DSA-65" },
    .{ .kem = "XMSS-SHA2_10_256", .sig = "LMS_SHA256_H5_W8", .sig_stfl = "ML-KEM-768" },
};

test "lookup returns null for an empty, padded, truncated, nul-extended, non-letter-folded or other-kind name" {
    for (misuses) |m| {
        try std.testing.expect(Registry.kemDescription(m.kem) == null);
        try std.testing.expect(!Registry.isKemEnabled(m.kem));
        try std.testing.expect(Registry.sigDescription(m.sig) == null);
        try std.testing.expect(!Registry.isSigEnabled(m.sig));
        try std.testing.expect(Registry.sigStflDescription(m.sig_stfl) == null);
        try std.testing.expect(!Registry.isSigStflEnabled(m.sig_stfl));
    }
}

// --- Case ------------------------------------------------------------------

test "a lookup ignores ASCII case and the description carries the liboqs name" {
    try std.testing.expect(Registry.isKemEnabled("ml-kem-768"));
    try std.testing.expectEqualStrings("ML-KEM-768", Registry.kemDescription("ml-kem-768").?.name);
    try std.testing.expect(Registry.isSigEnabled("Ml-Dsa-65"));
    try std.testing.expectEqualStrings("ML-DSA-65", Registry.sigDescription("Ml-Dsa-65").?.name);
    try std.testing.expect(Registry.isSigStflEnabled("lms_Sha256_h5_W8"));
    try std.testing.expectEqualStrings("LMS_SHA256_H5_W8", Registry.sigStflDescription("lms_Sha256_h5_W8").?.name);
    // A name that liboqs writes in lowercase, looked up in uppercase.
    try std.testing.expect(Registry.isSigEnabled("CROSS-RSDP-128-BALANCED"));
    try std.testing.expectEqualStrings("cross-rsdp-128-balanced", Registry.sigDescription("CROSS-RSDP-128-BALANCED").?.name);
}

test "a name in another case gives the same description as the liboqs name" {
    const upper = Registry.kemDescription("ML-KEM-768").?;
    const lower = Registry.kemDescription("ml-kem-768").?;
    try std.testing.expectEqual(upper.name.ptr, lower.name.ptr);
    try std.testing.expectEqual(upper.publicKeyLength, lower.publicKeyLength);
    try std.testing.expectEqual(upper.ciphertextLength, lower.ciphertextLength);
}

test "the runtime cores and the registry both take a name in any case, as liboqs does" {
    var kem = try oqs.Kem.init(std.testing.allocator, "ml-kem-768");
    defer kem.deinit();
    const d = Registry.kemDescription("ml-kem-768").?;
    try std.testing.expectEqual(d.publicKeyLength, kem.lengthPublicKey());
}

test "a name with a zero byte never matches, even when the bytes before it are an enabled name" {
    // C would stop at the zero byte and match ML-KEM-768. The registry
    // compares the whole slice, so the zero byte is a difference.
    try std.testing.expect(!Registry.isKemEnabled("ML-KEM-768\x00"));
    try std.testing.expect(Registry.kemDescription("ml-kem-768\x00") == null);
    try std.testing.expect(!Registry.isSigEnabled("ML-DSA-65\x00ML-DSA-65"));
    try std.testing.expect(Registry.sigStflDescription("\x00LMS_SHA256_H5_W8") == null);
}

// --- Fuzz -----------------------------------------------------------------

const Kind = enum { kem, sig, sig_stfl };
const kinds = [_]Kind{ .kem, .sig, .sig_stfl };

fn namesOf(kind: Kind) oqs.AlgorithmNames {
    return switch (kind) {
        .kem => Registry.kemNames(),
        .sig => Registry.sigNames(),
        .sig_stfl => Registry.sigStflNames(),
    };
}

// The description name a lookup of `kind` gives, and whether the enabled
// check agrees with it.
fn lookUp(kind: Kind, name: []const u8) !?[]const u8 {
    const found: ?[]const u8, const enabled = switch (kind) {
        .kem => .{ if (Registry.kemDescription(name)) |d| d.name else null, Registry.isKemEnabled(name) },
        .sig => .{ if (Registry.sigDescription(name)) |d| d.name else null, Registry.isSigEnabled(name) },
        .sig_stfl => .{ if (Registry.sigStflDescription(name)) |d| d.name else null, Registry.isSigStflEnabled(name) },
    };
    try std.testing.expectEqual(found != null, enabled);
    return found;
}

// The seed comes from build.zig (default 0x5717f022, override with
// -Dfuzz-seed=N). The test prints it at the start and in every failure
// message, and the run step name carries it too.
// A copy of `name` with the case of each ASCII letter picked at random.
fn randomCase(rand: std.Random, name: []const u8, out: []u8) []u8 {
    for (name, 0..) |ch, i| {
        out[i] = if (!std.ascii.isAlphabetic(ch)) ch else if (rand.boolean()) std.ascii.toUpper(ch) else std.ascii.toLower(ch);
    }
    return out[0..name.len];
}

// The listed name that equals `name` when ASCII case is ignored, or null.
// Written out with a byte loop, not with the std helper the registry uses.
fn listHolds(list: []const []const u8, name: []const u8) ?[]const u8 {
    outer: for (list) |entry| {
        if (entry.len != name.len) continue;
        for (entry, name) |a, b| {
            const fa = if (a >= 'A' and a <= 'Z') a + 32 else a;
            const fb = if (b >= 'A' and b <= 'Z') b + 32 else b;
            if (fa != fb) continue :outer;
        }
        return entry;
    }
    return null;
}

test "fuzz with a seed from the build: every listed name in any case is found as the listed name, and mutated or swapped names are found only when they are listed" {
    const seed: u64 = build_options.fuzz_seed;
    std.debug.print("fuzz seed 0x{x}\n", .{seed});
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();

    var lists: [kinds.len][256][]const u8 = undefined;
    var lengths: [kinds.len]usize = .{ 0, 0, 0 };
    for (kinds, 0..) |kind, k| {
        var it = namesOf(kind);
        while (it.next()) |name| {
            lists[k][lengths[k]] = name;
            lengths[k] += 1;
        }
    }

    // False negatives: every listed name, as listed, all lowercase, all
    // uppercase and in four random cases, is found under its own kind and
    // gives back the listed name.
    var buf: [128]u8 = undefined;
    for (kinds, 0..) |kind, k| {
        for (lists[k][0..lengths[k]]) |name| {
            var variant: usize = 0;
            while (variant < 7) : (variant += 1) {
                const asked: []const u8 = switch (variant) {
                    0 => name,
                    1 => std.ascii.lowerString(&buf, name),
                    2 => std.ascii.upperString(&buf, name),
                    else => randomCase(rand, name, &buf),
                };
                const found = (try lookUp(kind, asked)) orelse {
                    std.debug.print("listed name {s} asked as {s} was not found (seed 0x{x})\n", .{ name, asked, seed });
                    return error.TestUnexpectedResult;
                };
                if (!std.mem.eql(u8, name, found)) {
                    std.debug.print("listed name {s} asked as {s} gave {s} (seed 0x{x})\n", .{ name, asked, found, seed });
                    return error.TestUnexpectedResult;
                }
            }
        }
    }

    // False positives: a mutated name, or a name looked up under another
    // kind, is found only when the list of that kind holds it ignoring
    // ASCII case, and then gives back the listed name.
    const rounds = 2000;
    var round: usize = 0;
    while (round < rounds) : (round += 1) {
        const from = rand.uintLessThan(usize, kinds.len);
        const original = lists[from][rand.uintLessThan(usize, lengths[from])];
        var len = original.len;
        @memcpy(buf[0..len], original);
        // Start from a random case of the name, so that every mutation
        // below also meets mixed case.
        _ = randomCase(rand, original, &buf);
        var into = from;
        switch (rand.uintLessThan(u8, 7)) {
            // Flip one byte.
            0 => buf[rand.uintLessThan(usize, len)] ^= rand.intRangeAtMost(u8, 1, 255),
            // Cut the name short.
            1 => len = rand.uintLessThan(usize, len),
            // Add one to four bytes at the end.
            2 => {
                const extra = rand.intRangeAtMost(usize, 1, 4);
                rand.bytes(buf[len .. len + extra]);
                len += extra;
            },
            // Flip bit 0x20 of one byte that is not a letter, if it is one.
            // For a letter that is a case change, which must still match.
            3 => buf[rand.uintLessThan(usize, len)] ^= 0x20,
            // Replace one byte with a byte outside ASCII.
            4 => buf[rand.uintLessThan(usize, len)] = rand.intRangeAtMost(u8, 0x80, 0xff),
            // Put a zero byte in, or at the end.
            5 => {
                const at = rand.uintLessThan(usize, len + 1);
                if (at == len) len += 1;
                buf[at] = 0;
            },
            // Keep the name but look it up under another kind.
            else => into = (from + rand.intRangeAtMost(usize, 1, kinds.len - 1)) % kinds.len,
        }
        const mutated = buf[0..len];
        const expected = listHolds(lists[into][0..lengths[into]], mutated);
        const found = try lookUp(kinds[into], mutated);
        if ((found != null) != (expected != null)) {
            std.debug.print("mutated name {s} (from {s}) under {s}: found {}, listed {} (seed 0x{x}, round {d})\n", .{ mutated, original, @tagName(kinds[into]), found != null, expected != null, seed, round });
            return error.TestUnexpectedResult;
        }
        if (found) |name| {
            if (!std.mem.eql(u8, expected.?, name)) {
                std.debug.print("mutated name {s} (from {s}) gave {s}, listed {s} (seed 0x{x}, round {d})\n", .{ mutated, original, name, expected.?, seed, round });
                return error.TestUnexpectedResult;
            }
        }
    }
}
