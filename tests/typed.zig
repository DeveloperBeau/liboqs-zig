const std = @import("std");
const oqs = @import("oqs");
const build_options = @import("build_options");

// --- Registry gate ---------------------------------------------------------
// Every generated wrapper must name a runtime-enabled algorithm, and the
// wrapper count must equal liboqs' enabled count. This catches a typo'd or
// not-actually-compiled algorithm that ships silently. The smoke and parity
// tests would not.

test "every KEM wrapper names a runtime-enabled algorithm" {
    comptime var count: usize = 0;
    inline for (@typeInfo(oqs.kem).@"struct".decl_names) |d_name| {
        try std.testing.expect(oqs.isKemEnabled(@field(oqs.kem, d_name).info.name));
        count += 1;
    }
    try std.testing.expectEqual(oqs.enabledKemCount(), count);
}

test "every SIG wrapper names a runtime-enabled algorithm" {
    comptime var count: usize = 0;
    inline for (@typeInfo(oqs.sig).@"struct".decl_names) |d_name| {
        try std.testing.expect(oqs.isSigEnabled(@field(oqs.sig, d_name).info.name));
        count += 1;
    }
    try std.testing.expectEqual(oqs.enabledSigCount(), count);
}

test "every stateful wrapper names a runtime-enabled algorithm and the count is 70" {
    comptime var count: usize = 0;
    inline for (@typeInfo(oqs.sig_stfl).@"struct".decl_names) |d_name| {
        try std.testing.expect(oqs.isSigStflEnabled(@field(oqs.sig_stfl, d_name).info.name));
        count += 1;
    }
    try std.testing.expectEqual(oqs.enabledSigStflCount(), count);
    // 21 XMSS, 16 XMSS^MT and 33 LMS, written out by hand.
    try std.testing.expectEqual(@as(usize, 70), count);
}

// --- Behavior via the public namespaces ------------------------------------

test "namespace round-trip via oqs.kem.MlKem768" {
    const a = std.testing.allocator;
    var kp = try oqs.kem.MlKem768.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var enc = try kp.public_key.encapsulate();
    defer enc.deinit();
    var ss = try kp.secret_key.decapsulate(enc.ciphertext);
    defer ss.deinit();
    try std.testing.expectEqualSlices(u8, enc.shared_secret.bytes, ss.bytes);
}

test "decapsulate rejects wrong-length ciphertext" {
    const a = std.testing.allocator;
    var kp = try oqs.kem.MlKem768.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, kp.secret_key.decapsulate(&[_]u8{ 1, 2, 3 }));
}

test "namespace sign/verify via oqs.sig.MlDsa65" {
    const a = std.testing.allocator;
    var kp = try oqs.sig.MlDsa65.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var s = try kp.secret_key.sign("the quick brown fox");
    defer s.deinit();
    try std.testing.expect(try kp.public_key.isValidSignature("the quick brown fox", s.bytes));
    try std.testing.expect(!try kp.public_key.isValidSignature("tampered", s.bytes));
}

test "signature public key import round-trip and length validation" {
    const a = std.testing.allocator;
    var kp = try oqs.sig.MlDsa65.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var imported = try oqs.sig.MlDsa65.PublicKey.fromBytes(a, kp.public_key.bytes);
    defer imported.deinit();
    try std.testing.expectEqualSlices(u8, kp.public_key.bytes, imported.bytes);
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, oqs.sig.MlDsa65.PublicKey.fromBytes(a, &[_]u8{ 9, 9 }));
}

test "public key import round-trip preserves bytes" {
    const a = std.testing.allocator;
    var kp = try oqs.kem.MlKem768.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var imported = try oqs.kem.MlKem768.PublicKey.fromBytes(a, kp.public_key.bytes);
    defer imported.deinit();
    try std.testing.expectEqualSlices(u8, kp.public_key.bytes, imported.bytes);
}

test "import rejects wrong-length bytes" {
    const a = std.testing.allocator;
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, oqs.kem.MlKem768.PublicKey.fromBytes(a, &[_]u8{ 1, 2, 3 }));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, oqs.sig.MlDsa65.SecretKey.fromBytes(a, &[_]u8{}));
}

test "comptime sizes are exposed" {
    try std.testing.expectEqual(@as(usize, 1184), oqs.kem.MlKem768.public_key_length);
    try std.testing.expectEqual(@as(usize, 32), oqs.kem.MlKem768.shared_secret_length);
    try std.testing.expectEqual(@as(usize, 1952), oqs.sig.MlDsa65.public_key_length);
}

// --- Cross-algorithm type safety -------------------------------------------
// Distinct algorithms produce distinct key types, so a key of one algorithm
// cannot be passed where another's is required (compile error). We can only
// assert the type distinctness at runtime; the compile-time guarantee is the
// real payoff and is verified by the type system itself.

test "distinct algorithms have distinct key types" {
    try std.testing.expect(oqs.kem.MlKem768.PublicKey != oqs.kem.MlKem1024.PublicKey);
    try std.testing.expect(oqs.sig.MlDsa65.SecretKey != oqs.sig.MlDsa87.SecretKey);
}

// --- Typed stateful signatures ---------------------------------------------
// Expected values are written out by hand from the liboqs headers and the
// parameter sets in RFC 8391 (XMSS) and RFC 8554 (LMS). LMS_SHA256_H5_W8 and
// XMSS-SHA2_10_256 are the smallest trees. LMS_SHA256_H5_W1 is the cheapest
// variant to exhaust, because liboqs rebuilds the LMS tree on every signature.

const LmsW8 = oqs.sig_stfl.LmsSha256H5W8;
const LmsW1 = oqs.sig_stfl.LmsSha256H5W1;
const Xmss10 = oqs.sig_stfl.XmssSha256H10;
const message = "the quick brown fox";

test "typed stateful wrappers carry the comptime lengths from the liboqs headers" {
    try std.testing.expectEqual(@as(usize, 60), LmsW8.public_key_length);
    try std.testing.expectEqual(@as(usize, 64), LmsW8.secret_key_length);
    try std.testing.expectEqual(@as(usize, 1296), LmsW8.signature_max_length);
    try std.testing.expectEqualStrings("LMS_SHA256_H5_W8", LmsW8.algorithm_name);
    // (64 + XMSS_OID_LEN) with XMSS_OID_LEN 4, and (1373 + 4).
    try std.testing.expectEqual(@as(usize, 68), Xmss10.public_key_length);
    try std.testing.expectEqual(@as(usize, 1377), Xmss10.secret_key_length);
    try std.testing.expectEqual(@as(usize, 2500), Xmss10.signature_max_length);
    // A two-level LMS variant uses the shared 60 and 64 byte key lengths.
    try std.testing.expectEqual(@as(usize, 60), oqs.sig_stfl.LmsSha256H5W8H5W8.public_key_length);
    try std.testing.expectEqual(@as(usize, 64), oqs.sig_stfl.LmsSha256H5W8H5W8.secret_key_length);
    try std.testing.expectEqual(@as(usize, 2644), oqs.sig_stfl.LmsSha256H5W8H5W8.signature_max_length);
    // XMSS^MT: (64 + 4), (10938 + 4) and 9251.
    try std.testing.expectEqual(@as(usize, 68), oqs.sig_stfl.XmssmtSha256H204.public_key_length);
    try std.testing.expectEqual(@as(usize, 10942), oqs.sig_stfl.XmssmtSha256H204.secret_key_length);
    try std.testing.expectEqual(@as(usize, 9251), oqs.sig_stfl.XmssmtSha256H204.signature_max_length);
}

test "LMS_SHA256_H5_W8 typed key pair signs, verifies, rejects a tampered message and counts signatures" {
    const a = std.testing.allocator;
    var kp = try LmsW8.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    try std.testing.expectEqual(@as(usize, 60), kp.public_key.bytes.len);
    try std.testing.expectEqual(LmsW8.public_key_length, kp.public_key.bytes.len);
    try std.testing.expectEqual(@as(u64, 31), try kp.secret_key.sigsTotal());
    try std.testing.expectEqual(@as(u64, 31), try kp.secret_key.sigsRemaining());

    var s = try kp.secret_key.sign(message);
    defer s.deinit();
    try std.testing.expectEqual(@as(usize, 1296), s.bytes.len);
    // The HSS signature has a 4-byte level count, then the 4-byte index.
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, s.bytes[4..8], .big));
    try std.testing.expectEqual(@as(u64, 30), try kp.secret_key.sigsRemaining());
    try std.testing.expectEqual(@as(u64, 31), try kp.secret_key.sigsTotal());
    try std.testing.expect(try kp.public_key.isValidSignature(message, s.bytes));
    try std.testing.expect(!try kp.public_key.isValidSignature("tampered", s.bytes));

    var s2 = try kp.secret_key.sign(message);
    defer s2.deinit();
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, s2.bytes[4..8], .big));
    try std.testing.expectEqual(@as(u64, 29), try kp.secret_key.sigsRemaining());
    try std.testing.expect(!std.mem.eql(u8, s.bytes, s2.bytes));
}

test "XMSS-SHA2_10_256 typed key pair signs once and verifies" {
    const a = std.testing.allocator;
    var kp = try Xmss10.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    try std.testing.expectEqual(@as(usize, 68), kp.public_key.bytes.len);
    try std.testing.expectEqual(@as(u64, 1023), try kp.secret_key.sigsTotal());

    var s = try kp.secret_key.sign(message);
    defer s.deinit();
    try std.testing.expectEqual(@as(usize, 2500), s.bytes.len);
    // An XMSS signature starts with the 4-byte index.
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, s.bytes[0..4], .big));
    try std.testing.expectEqual(@as(u64, 1022), try kp.secret_key.sigsRemaining());
    try std.testing.expect(try kp.public_key.isValidSignature(message, s.bytes));
    try std.testing.expect(!try kp.public_key.isValidSignature("tampered", s.bytes));
}

test "stateful PublicKey.fromBytes round-trips the right length and rejects any other with InvalidKeySize" {
    const a = std.testing.allocator;
    var kp = try LmsW8.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var imported = try LmsW8.PublicKey.fromBytes(a, kp.public_key.bytes);
    defer imported.deinit();
    try std.testing.expectEqualSlices(u8, kp.public_key.bytes, imported.bytes);

    try std.testing.expectError(oqs.OqsError.InvalidKeySize, LmsW8.PublicKey.fromBytes(a, &[_]u8{}));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, LmsW8.PublicKey.fromBytes(a, kp.public_key.bytes[0..59]));
    var long: [61]u8 = undefined;
    @memset(&long, 0);
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, LmsW8.PublicKey.fromBytes(a, &long));
}

test "LMS public key bytes are rejected by an XMSS public key because 60 is not 68" {
    const a = std.testing.allocator;
    var kp = try LmsW8.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, Xmss10.PublicKey.fromBytes(a, kp.public_key.bytes));
}

test "another key pair's public key rejects a valid signature, even imported under another LMS variant of the same length" {
    const a = std.testing.allocator;
    var kp = try LmsW8.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var other = try LmsW8.generateKeyPair(a);
    defer other.public_key.deinit();
    defer other.secret_key.deinit();
    var s = try kp.secret_key.sign(message);
    defer s.deinit();
    try std.testing.expect(try kp.public_key.isValidSignature(message, s.bytes));
    try std.testing.expect(!try other.public_key.isValidSignature(message, s.bytes));

    var as_w1 = try LmsW1.PublicKey.fromBytes(a, other.public_key.bytes);
    defer as_w1.deinit();
    try std.testing.expect(!try as_w1.isValidSignature(message, s.bytes));
}

// liboqs 0.16.0 runs one verify function for every LMS variant. It reads the
// parameter set from the public key and the signature bytes, not from the
// variant name. So the same-length import below still verifies. Keeping the
// variants apart is the job of the distinct Zig types, tested further down.
test "an LMS H5 W8 public key imported under LMS H5 W1 verifies a genuine H5 W8 signature, as liboqs verify ignores the variant name" {
    const a = std.testing.allocator;
    var kp = try LmsW8.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var s = try kp.secret_key.sign(message);
    defer s.deinit();
    var as_w1 = try LmsW1.PublicKey.fromBytes(a, kp.public_key.bytes);
    defer as_w1.deinit();
    try std.testing.expect(try as_w1.isValidSignature(message, s.bytes));
    try std.testing.expect(!try as_w1.isValidSignature("tampered", s.bytes));
}

test "LMS_SHA256_H5_W1 typed key makes 32 signatures, the 32nd at sigsRemaining 0 verifies, then sign fails with SignFailed" {
    const a = std.testing.allocator;
    var kp = try LmsW1.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    try std.testing.expectEqual(@as(u64, 31), try kp.secret_key.sigsTotal());

    var i: u64 = 0;
    while (i < 31) : (i += 1) {
        var s = try kp.secret_key.sign(message);
        defer s.deinit();
        try std.testing.expectEqual(@as(usize, 8688), s.bytes.len);
        try std.testing.expectEqual(30 - i, try kp.secret_key.sigsRemaining());
    }
    // The extra signature liboqs allows at sigsRemaining 0 still verifies for LMS.
    var last = try kp.secret_key.sign(message);
    defer last.deinit();
    try std.testing.expectEqual(@as(usize, 8688), last.bytes.len);
    try std.testing.expectEqual(@as(u32, 31), std.mem.readInt(u32, last.bytes[4..8], .big));
    try std.testing.expect(try kp.public_key.isValidSignature(message, last.bytes));

    // A used-up key returns SignFailed and no signature. The testing
    // allocator fails the test if one were allocated and not freed.
    try std.testing.expectError(oqs.OqsError.SignFailed, kp.secret_key.sign(message));
    try std.testing.expectError(oqs.OqsError.SignFailed, kp.secret_key.sign(message));
}

// The seed comes from build.zig (default 0x5717f022, override with
// -Dfuzz-seed=N). `zig build test --summary all` shows it in the name of this
// binary's run step. The test itself prints it with every failure, because a
// test that writes to stderr on success is reported as a failed command.
test "fuzz with a seed from the build: typed pairs verify, and mutated or swapped ones are rejected" {
    const seed: u64 = build_options.fuzz_seed;
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();
    const a = std.testing.allocator;
    const pairs = 3;
    const rounds = 6;
    const max_message = 96;

    inline for (.{ LmsW8, Xmss10 }) |T| {
        var kp = try T.generateKeyPair(a);
        defer kp.public_key.deinit();
        defer kp.secret_key.deinit();

        var messages: [pairs][max_message]u8 = undefined;
        var lengths: [pairs]usize = undefined;
        var sigs: [pairs]T.Signature = undefined;
        var made: usize = 0;
        defer for (sigs[0..made]) |*s| s.deinit();
        while (made < pairs) : (made += 1) {
            lengths[made] = rand.intRangeAtMost(usize, 1, max_message);
            rand.bytes(messages[made][0..lengths[made]]);
            sigs[made] = try kp.secret_key.sign(messages[made][0..lengths[made]]);
        }

        const bad_sig = try a.alloc(u8, T.signature_max_length);
        defer a.free(bad_sig);
        var bad_msg: [max_message]u8 = undefined;

        for (0..pairs) |p| {
            const msg = messages[p][0..lengths[p]];
            const sg = sigs[p].bytes;
            for (0..pairs) |q| {
                const other = messages[q][0..lengths[q]];
                if (q == p or std.mem.eql(u8, other, msg)) continue;
                if (try kp.public_key.isValidSignature(other, sg)) {
                    std.debug.print("{s}: accepted signature {d} for message {d} (seed 0x{x})\n", .{ T.algorithm_name, p, q, seed });
                    return error.TestUnexpectedResult;
                }
            }
            var round: usize = 0;
            while (round < rounds) : (round += 1) {
                @memcpy(bad_sig, sg);
                const sig_at = rand.uintLessThan(usize, sg.len);
                bad_sig[sig_at] ^= rand.intRangeAtMost(u8, 1, 255);
                if (try kp.public_key.isValidSignature(msg, bad_sig)) {
                    std.debug.print("{s}: pair {d} accepted a signature mutated at byte {d} (seed 0x{x})\n", .{ T.algorithm_name, p, sig_at, seed });
                    return error.TestUnexpectedResult;
                }
                @memcpy(bad_msg[0..msg.len], msg);
                const msg_at = rand.uintLessThan(usize, msg.len);
                bad_msg[msg_at] ^= rand.intRangeAtMost(u8, 1, 255);
                if (try kp.public_key.isValidSignature(bad_msg[0..msg.len], sg)) {
                    std.debug.print("{s}: pair {d} accepted a message mutated at byte {d} (seed 0x{x})\n", .{ T.algorithm_name, p, msg_at, seed });
                    return error.TestUnexpectedResult;
                }
                if (!try kp.public_key.isValidSignature(msg, sg)) {
                    std.debug.print("{s}: rejected valid pair {d} in round {d} (seed 0x{x})\n", .{ T.algorithm_name, p, round, seed });
                    return error.TestUnexpectedResult;
                }
            }
        }
    }
}

test "distinct stateful algorithms have distinct key types" {
    try std.testing.expect(LmsW8.PublicKey != LmsW1.PublicKey);
    try std.testing.expect(LmsW8.SecretKey != LmsW1.SecretKey);
    try std.testing.expect(LmsW8.Signature != Xmss10.Signature);
    try std.testing.expect(Xmss10.PublicKey != oqs.sig_stfl.XmssSha256H16.PublicKey);
}
