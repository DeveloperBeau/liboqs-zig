//! Behavioral tests for the stateful signature core (XMSS, XMSS^MT and LMS)
//! under the system RNG. Every expected value is written out by hand from the
//! parameter sets in RFC 8391 (XMSS) and RFC 8554 (LMS), not read back from
//! liboqs. This module must never call seedKat.
//!
//! The exercised variants are the smallest of each family, so keygen and
//! signing stay fast in Debug builds. XMSS-SHA2_10_256 is the lowest XMSS
//! height. XMSSMT-SHA2_20/4_256 splits its height into four layers of 5, so
//! keygen builds only small trees. LMS_SHA256_H5_W8 is the lowest LMS height.
//! The exhaustion test uses LMS_SHA256_H5_W1, because liboqs rebuilds the
//! LMS tree on every signature and Winternitz 1 makes that the cheapest.
const std = @import("std");
const oqs = @import("oqs");

// All 70 stateful variants that liboqs 0.16.0 defines, written out by hand.
const stfl_names = [_][:0]const u8{
    "XMSS-SHA2_10_256",
    "XMSS-SHA2_16_256",
    "XMSS-SHA2_20_256",
    "XMSS-SHAKE_10_256",
    "XMSS-SHAKE_16_256",
    "XMSS-SHAKE_20_256",
    "XMSS-SHA2_10_512",
    "XMSS-SHA2_16_512",
    "XMSS-SHA2_20_512",
    "XMSS-SHAKE_10_512",
    "XMSS-SHAKE_16_512",
    "XMSS-SHAKE_20_512",
    "XMSS-SHA2_10_192",
    "XMSS-SHA2_16_192",
    "XMSS-SHA2_20_192",
    "XMSS-SHAKE256_10_192",
    "XMSS-SHAKE256_16_192",
    "XMSS-SHAKE256_20_192",
    "XMSS-SHAKE256_10_256",
    "XMSS-SHAKE256_16_256",
    "XMSS-SHAKE256_20_256",
    "XMSSMT-SHA2_20/2_256",
    "XMSSMT-SHA2_20/4_256",
    "XMSSMT-SHA2_40/2_256",
    "XMSSMT-SHA2_40/4_256",
    "XMSSMT-SHA2_40/8_256",
    "XMSSMT-SHA2_60/3_256",
    "XMSSMT-SHA2_60/6_256",
    "XMSSMT-SHA2_60/12_256",
    "XMSSMT-SHAKE_20/2_256",
    "XMSSMT-SHAKE_20/4_256",
    "XMSSMT-SHAKE_40/2_256",
    "XMSSMT-SHAKE_40/4_256",
    "XMSSMT-SHAKE_40/8_256",
    "XMSSMT-SHAKE_60/3_256",
    "XMSSMT-SHAKE_60/6_256",
    "XMSSMT-SHAKE_60/12_256",
    "LMS_SHA256_H5_W1",
    "LMS_SHA256_H5_W2",
    "LMS_SHA256_H5_W4",
    "LMS_SHA256_H5_W8",
    "LMS_SHA256_H10_W1",
    "LMS_SHA256_H10_W2",
    "LMS_SHA256_H10_W4",
    "LMS_SHA256_H10_W8",
    "LMS_SHA256_H15_W1",
    "LMS_SHA256_H15_W2",
    "LMS_SHA256_H15_W4",
    "LMS_SHA256_H15_W8",
    "LMS_SHA256_H20_W1",
    "LMS_SHA256_H20_W2",
    "LMS_SHA256_H20_W4",
    "LMS_SHA256_H20_W8",
    "LMS_SHA256_H25_W1",
    "LMS_SHA256_H25_W2",
    "LMS_SHA256_H25_W4",
    "LMS_SHA256_H25_W8",
    "LMS_SHA256_H5_W8_H5_W8",
    "LMS_SHA256_H10_W4_H5_W8",
    "LMS_SHA256_H10_W8_H5_W8",
    "LMS_SHA256_H10_W2_H10_W2",
    "LMS_SHA256_H10_W4_H10_W4",
    "LMS_SHA256_H10_W8_H10_W8",
    "LMS_SHA256_H15_W8_H5_W8",
    "LMS_SHA256_H15_W8_H10_W8",
    "LMS_SHA256_H15_W8_H15_W8",
    "LMS_SHA256_H20_W8_H5_W8",
    "LMS_SHA256_H20_W8_H10_W8",
    "LMS_SHA256_H20_W8_H15_W8",
    "LMS_SHA256_H20_W8_H20_W8",
};

/// Hand-written sizes and counts for one exercised variant.
const Expected = struct {
    name: [:0]const u8,
    public_key: usize,
    signature: usize,
    // liboqs counts signatures up to the highest index, so a tree of height h
    // reports 2^h - 1 (xmss_total_signatures and the hash-sigs max_count).
    sigs_total: u64,
};

// XMSS-SHA2_10_256 (n = 32, len = 67, h = 10): pk = 4 (OID) + 32 (root) +
// 32 (seed) = 68. sig = 4 (index) + 32 (R) + 67 * 32 (WOTS) + 10 * 32 (path) = 2500.
const xmss_h10 = Expected{ .name = "XMSS-SHA2_10_256", .public_key = 68, .signature = 2500, .sigs_total = 1023 };

// XMSSMT-SHA2_20/4_256 (h = 20, d = 4, layers of height 5): pk = 68.
// sig = 3 (index) + 32 (R) + 4 * (67 * 32 + 5 * 32) = 9251.
const xmssmt_h20_4 = Expected{ .name = "XMSSMT-SHA2_20/4_256", .public_key = 68, .signature = 9251, .sigs_total = 1048575 };

// LMS_SHA256_H5_W8 as one-level HSS (n = 32, p = 34, h = 5):
// pk = 4 (levels) + 4 (LMS type) + 4 (OTS type) + 16 (I) + 32 (T) = 60.
// sig = 4 (Nspk) + 4 (q) + 4 (OTS type) + 32 (C) + 34 * 32 (y) + 4 (LMS type) + 5 * 32 (path) = 1296.
const lms_h5_w8 = Expected{ .name = "LMS_SHA256_H5_W8", .public_key = 60, .signature = 1296, .sigs_total = 31 };

// LMS_SHA256_H5_W1 (p = 265): pk = 60. sig = 4 + 4 + 4 + 32 + 265 * 32 + 4 + 5 * 32 = 8688.
const lms_h5_w1 = Expected{ .name = "LMS_SHA256_H5_W1", .public_key = 60, .signature = 8688, .sigs_total = 31 };

const exercised = [_]Expected{ xmss_h10, xmssmt_h20_4, lms_h5_w8 };

const message = "the quick brown fox";

/// One algorithm with one fresh key pair, released together.
const Fixture = struct {
    sig: oqs.SigStfl,
    public_key: []u8,
    secret_key: oqs.SigStflSecretKey,

    fn init(name: [:0]const u8) !Fixture {
        var sig = try oqs.SigStfl.init(std.testing.allocator, name);
        errdefer sig.deinit();
        const kp = try sig.keypair();
        return .{ .sig = sig, .public_key = kp.public_key, .secret_key = kp.secret_key };
    }

    fn deinit(self: *Fixture) void {
        std.testing.allocator.free(self.public_key);
        self.secret_key.deinit();
        self.sig.deinit();
    }
};

test "all 70 stateful variants report enabled and the count is 70" {
    try std.testing.expectEqual(@as(usize, 70), stfl_names.len);
    for (stfl_names) |name| {
        if (!oqs.isSigStflEnabled(name)) {
            std.debug.print("stateful variant not enabled: {s}\n", .{name});
            return error.TestExpectedEqual;
        }
    }
    try std.testing.expectEqual(@as(usize, 70), oqs.enabledSigStflCount());
}

test "isSigStflEnabled is false for a stateless and an unknown name" {
    try std.testing.expect(!oqs.isSigStflEnabled("ML-DSA-65"));
    try std.testing.expect(!oqs.isSigStflEnabled("XMSS-NOT-A-VARIANT"));
}

test "stateless signature count is unchanged by the stateful families" {
    // 221 signature variants were enabled before the stateful families. They
    // live in a separate liboqs registry and must not appear in it.
    try std.testing.expectEqual(@as(usize, 221), oqs.enabledSigCount());
}

test "each family round trips: keygen, two signatures at different indices, both verify, hand-written lengths" {
    for (exercised) |e| {
        var f = try Fixture.init(e.name);
        defer f.deinit();
        try std.testing.expectEqual(e.public_key, f.sig.lengthPublicKey());
        try std.testing.expectEqual(e.signature, f.sig.lengthSignatureMax());
        try std.testing.expectEqual(e.public_key, f.public_key.len);

        const s1 = try f.sig.sign(message, &f.secret_key);
        defer std.testing.allocator.free(s1);
        try std.testing.expectEqual(e.signature, s1.len);
        try std.testing.expect(try f.sig.verify(message, s1, f.public_key));

        // The second signature uses the next index, so it differs and verifies too.
        const s2 = try f.sig.sign(message, &f.secret_key);
        defer std.testing.allocator.free(s2);
        try std.testing.expect(!std.mem.eql(u8, s1, s2));
        try std.testing.expect(try f.sig.verify(message, s2, f.public_key));
    }
}

test "sigsTotal is 2^h - 1 and sigsRemaining drops by exactly one per signature" {
    for (exercised) |e| {
        var f = try Fixture.init(e.name);
        defer f.deinit();
        try std.testing.expectEqual(e.sigs_total, try f.sig.sigsTotal(f.secret_key));
        try std.testing.expectEqual(e.sigs_total, try f.sig.sigsRemaining(f.secret_key));
        var i: u64 = 1;
        while (i <= 3) : (i += 1) {
            const s = try f.sig.sign(message, &f.secret_key);
            std.testing.allocator.free(s);
            try std.testing.expectEqual(e.sigs_total - i, try f.sig.sigsRemaining(f.secret_key));
            try std.testing.expectEqual(e.sigs_total, try f.sig.sigsTotal(f.secret_key));
        }
    }
}

test "LMS_SHA256_H5_W1 signs 31 times, then sign fails with SignFailed and sigsRemaining stays 0" {
    var f = try Fixture.init(lms_h5_w1.name);
    defer f.deinit();
    try std.testing.expectEqual(lms_h5_w1.signature, f.sig.lengthSignatureMax());
    var i: u64 = 0;
    while (i < 31) : (i += 1) {
        try std.testing.expectEqual(lms_h5_w1.sigs_total - i, try f.sig.sigsRemaining(f.secret_key));
        const s = try f.sig.sign(message, &f.secret_key);
        defer std.testing.allocator.free(s);
        try std.testing.expect(try f.sig.verify(message, s, f.public_key));
    }
    try std.testing.expectEqual(@as(u64, 0), try f.sig.sigsRemaining(f.secret_key));
    // An error union carries no slice, and std.testing.allocator fails the
    // test on any leaked signature buffer.
    try std.testing.expectError(oqs.OqsError.SignFailed, f.sig.sign(message, &f.secret_key));
    try std.testing.expectError(oqs.OqsError.SignFailed, f.sig.sign(message, &f.secret_key));
    try std.testing.expectEqual(@as(u64, 0), try f.sig.sigsRemaining(f.secret_key));
    try std.testing.expectEqual(@as(u64, 31), try f.sig.sigsTotal(f.secret_key));
}

test "verify rejects a tampered message, a flipped signature byte, another key pair's public key and a truncated or extended signature" {
    for (exercised) |e| {
        var f = try Fixture.init(e.name);
        defer f.deinit();
        var other = try Fixture.init(e.name);
        defer other.deinit();

        const s = try f.sig.sign(message, &f.secret_key);
        defer std.testing.allocator.free(s);
        try std.testing.expect(try f.sig.verify(message, s, f.public_key));

        try std.testing.expect(!try f.sig.verify("the quick brown fax", s, f.public_key));

        const flipped = try std.testing.allocator.dupe(u8, s);
        defer std.testing.allocator.free(flipped);
        flipped[flipped.len / 2] ^= 0x01;
        try std.testing.expect(!try f.sig.verify(message, flipped, f.public_key));

        try std.testing.expect(!try f.sig.verify(message, s, other.public_key));

        // XMSS reads a fixed signature length without checking it, so these
        // must be refused before they reach liboqs.
        try std.testing.expect(!try f.sig.verify(message, s[0 .. s.len - 1], f.public_key));
        try std.testing.expect(!try f.sig.verify(message, s[0..0], f.public_key));

        const longer = try std.testing.allocator.alloc(u8, s.len + 1);
        defer std.testing.allocator.free(longer);
        @memcpy(longer[0..s.len], s);
        longer[s.len] = 0;
        try std.testing.expect(!try f.sig.verify(message, longer, f.public_key));
    }
}

test "init with an unknown name returns AlgorithmNotAvailable" {
    try std.testing.expectError(oqs.OqsError.AlgorithmNotAvailable, oqs.SigStfl.init(std.testing.allocator, "XMSS-NOT-A-VARIANT"));
    try std.testing.expectError(oqs.OqsError.AlgorithmNotAvailable, oqs.SigStfl.init(std.testing.allocator, "ML-DSA-65"));
}

test "verify with a wrong-length public key returns InvalidKeySize" {
    var f = try Fixture.init(lms_h5_w8.name);
    defer f.deinit();
    const s = try f.sig.sign(message, &f.secret_key);
    defer std.testing.allocator.free(s);
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, f.sig.verify(message, s, f.public_key[0 .. f.public_key.len - 1]));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, f.sig.verify(message, s, &[_]u8{}));
}

test "a secret key state from another algorithm returns InvalidKeySize and is not advanced" {
    var lms = try Fixture.init(lms_h5_w8.name);
    defer lms.deinit();
    var lms_w4 = try oqs.SigStfl.init(std.testing.allocator, "LMS_SHA256_H5_W4");
    defer lms_w4.deinit();

    try std.testing.expectError(oqs.OqsError.InvalidKeySize, lms_w4.sign(message, &lms.secret_key));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, lms_w4.sigsRemaining(lms.secret_key));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, lms_w4.sigsTotal(lms.secret_key));
    try std.testing.expectEqual(@as(u64, 31), try lms.sig.sigsRemaining(lms.secret_key));
}

// The seed is fixed so a failure reproduces. It is in the test name, and every
// failure message prints it. A passing run prints nothing, because zig build
// reports any stderr output from a test binary as a failed command.
test "fuzz (seed 0x5717f022): mutated signatures and messages are rejected and the valid pair is always accepted" {
    const seed: u64 = 0x5717_F022;
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();
    const rounds = 48;

    for (exercised) |e| {
        var f = try Fixture.init(e.name);
        defer f.deinit();

        var msg: [64]u8 = undefined;
        rand.bytes(&msg);
        const s = try f.sig.sign(&msg, &f.secret_key);
        defer std.testing.allocator.free(s);

        const bad_sig = try std.testing.allocator.alloc(u8, s.len);
        defer std.testing.allocator.free(bad_sig);
        var bad_msg: [msg.len]u8 = undefined;

        var round: usize = 0;
        while (round < rounds) : (round += 1) {
            // False positives: one byte changed by a nonzero mask must fail.
            @memcpy(bad_sig, s);
            const sig_at = rand.uintLessThan(usize, s.len);
            bad_sig[sig_at] ^= rand.intRangeAtMost(u8, 1, 255);
            if (try f.sig.verify(&msg, bad_sig, f.public_key)) {
                std.debug.print("{s}: accepted a signature mutated at byte {d} (seed 0x{x})\n", .{ e.name, sig_at, seed });
                return error.TestUnexpectedResult;
            }

            bad_msg = msg;
            const msg_at = rand.uintLessThan(usize, msg.len);
            bad_msg[msg_at] ^= rand.intRangeAtMost(u8, 1, 255);
            if (try f.sig.verify(&bad_msg, s, f.public_key)) {
                std.debug.print("{s}: accepted a message mutated at byte {d} (seed 0x{x})\n", .{ e.name, msg_at, seed });
                return error.TestUnexpectedResult;
            }

            // False negatives: the untouched pair must still verify.
            if (!try f.sig.verify(&msg, s, f.public_key)) {
                std.debug.print("{s}: rejected the valid pair in round {d} (seed 0x{x})\n", .{ e.name, round, seed });
                return error.TestUnexpectedResult;
            }
        }
    }
}
