//! Behaviour tests for the KEM and signature wrappers under the system random
//! source: what a caller sees for good input, for bad input and for hostile
//! input. They run a sample of the algorithms, because `zig build behaviour`
//! runs every one. The checks themselves are in harness/behaviour_checks.zig.
//! This module must never call seedKat, which flips a process-global DRBG
//! pointer for the whole binary. The fuzz tests are in behaviour_fuzz.zig.
const std = @import("std");
const oqs = @import("oqs");
const checks = @import("behaviour_checks");
const c = @import("c_api");
const sample = @import("behaviour_sample.zig");

const a = std.testing.allocator;

fn seededRandom(prng: *std.Random.DefaultPrng, salt: u64) std.Random {
    prng.* = std.Random.DefaultPrng.init(0x5717_F022 ^ salt);
    return prng.random();
}

// --- Hand-written counts -----------------------------------------------------

test "the KEM families written out by hand hold 41 KEMs, and each registry name belongs to exactly one family" {
    var total: usize = 0;
    for (checks.kemFamilyCounts()) |family| total += family.count;
    try std.testing.expectEqual(@as(usize, 41), total);
    try std.testing.expectEqual(@as(usize, 41), oqs.Registry.enabledKemCount());

    for (checks.kemFamilyCounts()) |family| {
        var seen: usize = 0;
        var names = oqs.Registry.kemNames();
        while (names.next()) |name| {
            if (std.mem.startsWith(u8, name, family.prefix)) seen += 1;
        }
        try std.testing.expectEqual(family.count, seen);
    }
}

test "the signature families written out by hand hold 221 schemes, 3 of them SUF-CMA, and the liboqs claim of each matches" {
    var total: usize = 0;
    var suf: usize = 0;
    for (checks.sigFamilyCounts()) |family| {
        total += family.count;
        if (family.suf_cma) suf += family.count;
    }
    try std.testing.expectEqual(@as(usize, 221), total);
    try std.testing.expectEqual(@as(usize, 3), suf);
    try std.testing.expectEqual(@as(usize, 221), oqs.Registry.enabledSigCount());

    for (checks.sigFamilyCounts()) |family| {
        var seen: usize = 0;
        var names = oqs.Registry.sigNames();
        while (names.next()) |name| {
            if (!std.mem.startsWith(u8, name, family.prefix)) continue;
            seen += 1;
            // The claim is read from the C object, not from the wrapper.
            var s = try oqs.Sig.init(a, name);
            defer s.deinit();
            try std.testing.expectEqual(family.suf_cma, s.handle.suf_cma);
            try std.testing.expect(s.handle.euf_cma);
        }
        try std.testing.expectEqual(family.count, seen);
    }
}

test "every sample algorithm is enabled" {
    for (sample.kem) |entry| try std.testing.expect(oqs.Registry.isKemEnabled(entry.name));
    for (sample.sig) |entry| try std.testing.expect(oqs.Registry.isSigEnabled(entry.name));
}

test "the family tables name no family for a made-up algorithm" {
    try std.testing.expect(checks.rejectionOf("ML-KEM-512") != null);
    try std.testing.expect(checks.rejectionOf("Made-Up-KEM") == null);
    try std.testing.expectEqual(@as(?bool, true), checks.claimsSufCma("ML-DSA-65"));
    try std.testing.expectEqual(@as(?bool, false), checks.claimsSufCma("Falcon-1024"));
    try std.testing.expectEqual(@as(?bool, null), checks.claimsSufCma("Made-Up-Sig"));
}

// --- Behaviour of the sample ---------------------------------------------------

test "KEM sample: round trip, implicit rejection of changed and random ciphertexts, and wrong lengths" {
    var prng: std.Random.DefaultPrng = undefined;
    const random = seededRandom(&prng, 1);
    for (sample.kem) |entry| try checks.checkKem(a, entry.name, random);
}

test "signature sample: round trip, flipped message and signature bits, other keys, wrong lengths and hostile signatures" {
    var prng: std.Random.DefaultPrng = undefined;
    const random = seededRandom(&prng, 2);
    for (sample.sig) |entry| try checks.checkSig(a, entry.name, random);
}

// --- Facts about single algorithms, from the liboqs sources ---------------------

test "ML-KEM-512 decaps returns DecapsulationFailed for a secret key whose embedded public key or its hash was changed, and a rejection key for a changed secret vector" {
    // FIPS 203 section 7.3: decaps checks H(ek) against the hash stored in the
    // secret key (mlk_kem_check_sk). The 1632 byte key is dk_pke (768 bytes),
    // ek (800), H(ek) (32), z (32).
    var kem = try oqs.Kem.init(a, "ML-KEM-512");
    defer kem.deinit();
    const kp = try kem.keypair();
    defer a.free(kp.public_key);
    defer a.free(kp.secret_key);
    const enc = try kem.encaps(kp.public_key);
    defer a.free(enc.ciphertext);
    defer a.free(enc.shared_secret);

    const bad = try a.dupe(u8, kp.secret_key);
    defer a.free(bad);
    for ([_]usize{ 768 * 8, 768 * 8 + 800 * 8 / 2, (768 + 800 + 32) * 8 - 1 }) |bit| {
        checks.flipBit(bad, bit);
        try std.testing.expectError(oqs.OqsError.DecapsulationFailed, kem.decaps(enc.ciphertext, bad));
        checks.flipBit(bad, bit);
    }
    // In the secret vector the hash check still passes, and the re-encryption check fails.
    for ([_]usize{ 0, 3000, 768 * 8 - 1 }) |bit| {
        checks.flipBit(bad, bit);
        const got = try kem.decaps(enc.ciphertext, bad);
        defer a.free(got);
        try std.testing.expect(!std.mem.eql(u8, got, enc.shared_secret));
        checks.flipBit(bad, bit);
    }
    // The rejection seed z is used only on a failed re-encryption, so flipping it changes nothing for a good ciphertext.
    checks.flipBit(bad, (1632 - 1) * 8);
    const same = try kem.decaps(enc.ciphertext, bad);
    defer a.free(same);
    try std.testing.expectEqualSlices(u8, enc.shared_secret, same);
}

test "Classic-McEliece-348864 has no padding bits, so a changed last byte gives a rejection key and no error" {
    // PK_NROWS is 768, a whole number of bytes, so crypto_kem_dec has no padding check to fail.
    var kem = try oqs.Kem.init(a, "Classic-McEliece-348864");
    defer kem.deinit();
    const kp = try kem.keypair();
    defer a.free(kp.public_key);
    defer a.free(kp.secret_key);
    const enc = try kem.encaps(kp.public_key);
    defer a.free(enc.ciphertext);
    defer a.free(enc.shared_secret);
    enc.ciphertext[enc.ciphertext.len - 1] ^= 0xFF;
    const got = try kem.decaps(enc.ciphertext, kp.secret_key);
    defer a.free(got);
    try std.testing.expect(!std.mem.eql(u8, got, enc.shared_secret));
}

test "Falcon-512 signatures are shorter than the 752 byte maximum, and sign returns the produced length" {
    // The liboqs maximum is 752. A Falcon-512 signature is compressed and its
    // length varies below that. A signature of the full maximum is a bug.
    var sig = try oqs.Sig.init(a, "Falcon-512");
    defer sig.deinit();
    try std.testing.expectEqual(@as(usize, 752), sig.lengthSignatureMax());
    const kp = try sig.keypair();
    defer a.free(kp.public_key);
    defer a.free(kp.secret_key);
    for (0..4) |i| {
        const message = [_]u8{@intCast(i)};
        const signature = try sig.sign(&message, kp.secret_key);
        defer a.free(signature);
        try std.testing.expect(signature.len < 752);
        try std.testing.expect(signature.len > 600);
        try std.testing.expect(try sig.verify(&message, signature, kp.public_key));
    }
}

test "Falcon-padded-512 signatures are always the 666 byte maximum" {
    var sig = try oqs.Sig.init(a, "Falcon-padded-512");
    defer sig.deinit();
    const kp = try sig.keypair();
    defer a.free(kp.public_key);
    defer a.free(kp.secret_key);
    const signature = try sig.sign("m", kp.secret_key);
    defer a.free(signature);
    try std.testing.expectEqual(@as(usize, 666), signature.len);
}

// --- Typed seams --------------------------------------------------------------

test "typed KEM: a changed ciphertext, and the secret key of another pair, give a different secret and no error" {
    const T = oqs.kem.MlKem512;
    var kp = try T.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var other = try T.generateKeyPair(a);
    defer other.public_key.deinit();
    defer other.secret_key.deinit();
    var enc = try kp.public_key.encapsulate();
    defer enc.deinit();

    const bad = try a.dupe(u8, enc.ciphertext);
    defer a.free(bad);
    checks.flipBit(bad, 5);
    var changed = try kp.secret_key.decapsulate(bad);
    defer changed.deinit();
    try std.testing.expect(!std.mem.eql(u8, changed.bytes, enc.shared_secret.bytes));
    var wrong_key = try other.secret_key.decapsulate(enc.ciphertext);
    defer wrong_key.deinit();
    try std.testing.expect(!std.mem.eql(u8, wrong_key.bytes, enc.shared_secret.bytes));
}

test "typed KEM: keys imported from bytes work, and every wrong length gives InvalidKeySize" {
    const T = oqs.kem.MlKem512;
    var kp = try T.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var pk = try T.PublicKey.fromBytes(a, kp.public_key.bytes);
    defer pk.deinit();
    var sk = try T.SecretKey.fromBytes(a, kp.secret_key.bytes);
    defer sk.deinit();
    var enc = try pk.encapsulate();
    defer enc.deinit();
    var ss = try sk.decapsulate(enc.ciphertext);
    defer ss.deinit();
    try std.testing.expectEqualSlices(u8, enc.shared_secret.bytes, ss.bytes);

    const long = try a.alloc(u8, enc.ciphertext.len + 1);
    defer a.free(long);
    @memset(long, 0);
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, sk.decapsulate(long));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, sk.decapsulate(&.{}));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, T.PublicKey.fromBytes(a, kp.public_key.bytes[0..799]));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, T.PublicKey.fromBytes(a, &.{}));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, T.SecretKey.fromBytes(a, kp.secret_key.bytes[0..1631]));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, T.SecretKey.fromBytes(a, &.{}));
}

test "typed signature: imported keys sign and verify, and changed message bits, changed signature bits and hostile signatures never verify" {
    const T = oqs.sig.MlDsa44;
    var kp = try T.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var sk = try T.SecretKey.fromBytes(a, kp.secret_key.bytes);
    defer sk.deinit();
    var pk = try T.PublicKey.fromBytes(a, kp.public_key.bytes);
    defer pk.deinit();

    var message = "the quick brown fox".*;
    var signature = try sk.sign(&message);
    defer signature.deinit();
    try std.testing.expect(try pk.isValidSignature(&message, signature.bytes));

    for ([_]usize{ 0, 70, message.len * 8 - 1 }) |bit| {
        checks.flipBit(&message, bit);
        try std.testing.expect(!try pk.isValidSignature(&message, signature.bytes));
        checks.flipBit(&message, bit);
    }
    // ML-DSA claims SUF-CMA, so a flipped signature bit fails.
    for ([_]usize{ 0, 4000, signature.bytes.len * 8 - 1 }) |bit| {
        checks.flipBit(signature.bytes, bit);
        try std.testing.expect(!try pk.isValidSignature(&message, signature.bytes));
        checks.flipBit(signature.bytes, bit);
    }
    try std.testing.expect(try pk.isValidSignature(&message, signature.bytes));

    const hostile = try a.alloc(u8, T.signature_max_length + 1);
    defer a.free(hostile);
    for ([_]u8{ 0x00, 0xFF }) |fill| {
        @memset(hostile, fill);
        for ([_]usize{ 0, 1, T.signature_max_length, T.signature_max_length + 1 }) |len| {
            try std.testing.expect(!try pk.isValidSignature(&message, hostile[0..len]));
        }
    }
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, T.SecretKey.fromBytes(a, kp.secret_key.bytes[0 .. T.secret_key_length - 1]));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, T.PublicKey.fromBytes(a, &.{}));
}

test "typed signature: a Falcon-512 signature has the produced length, below the maximum, and one byte less does not verify" {
    const T = oqs.sig.Falcon512;
    var kp = try T.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var signature = try kp.secret_key.sign("m");
    defer signature.deinit();
    try std.testing.expect(signature.bytes.len < T.signature_max_length);
    try std.testing.expect(try kp.public_key.isValidSignature("m", signature.bytes));
    try std.testing.expect(!try kp.public_key.isValidSignature("m", signature.bytes[0 .. signature.bytes.len - 1]));
}

// --- What the core does with a liboqs error status ------------------------------

// Stand-ins for the function pointers of the liboqs objects, so a test can make
// liboqs report an error that a real algorithm never reports for good input.
const Stub = struct {
    fn keypairKem(public_key: [*c]u8, secret_key: [*c]u8) callconv(.c) c.OQS_STATUS {
        _ = public_key;
        _ = secret_key;
        return c.OQS_ERROR;
    }
    fn encaps(ciphertext: [*c]u8, shared_secret: [*c]u8, public_key: [*c]const u8) callconv(.c) c.OQS_STATUS {
        _ = ciphertext;
        _ = shared_secret;
        _ = public_key;
        return c.OQS_ERROR;
    }
    fn decaps(shared_secret: [*c]u8, ciphertext: [*c]const u8, secret_key: [*c]const u8) callconv(.c) c.OQS_STATUS {
        _ = shared_secret;
        _ = ciphertext;
        _ = secret_key;
        return c.OQS_ERROR;
    }
    fn keypairSig(public_key: [*c]u8, secret_key: [*c]u8) callconv(.c) c.OQS_STATUS {
        _ = public_key;
        _ = secret_key;
        return c.OQS_ERROR;
    }
    fn sign(signature: [*c]u8, signature_len: [*c]usize, message: [*c]const u8, message_len: usize, secret_key: [*c]const u8) callconv(.c) c.OQS_STATUS {
        _ = signature;
        _ = signature_len;
        _ = message;
        _ = message_len;
        _ = secret_key;
        return c.OQS_ERROR;
    }
    fn verify(message: [*c]const u8, message_len: usize, signature: [*c]const u8, signature_len: usize, public_key: [*c]const u8) callconv(.c) c.OQS_STATUS {
        _ = message;
        _ = message_len;
        _ = signature;
        _ = signature_len;
        _ = public_key;
        return c.OQS_ERROR;
    }
};

test "core Kem turns a liboqs error status into KeyGenerationFailed, EncapsulationFailed and DecapsulationFailed" {
    var kem = try oqs.Kem.init(a, "ML-KEM-512");
    defer kem.deinit();
    const pk: [800]u8 = @splat(0);
    const sk: [1632]u8 = @splat(0);
    const ct: [768]u8 = @splat(0);
    kem.handle.keypair = Stub.keypairKem;
    kem.handle.encaps = Stub.encaps;
    kem.handle.decaps = Stub.decaps;
    try std.testing.expectError(oqs.OqsError.KeyGenerationFailed, kem.keypair());
    try std.testing.expectError(oqs.OqsError.EncapsulationFailed, kem.encaps(&pk));
    try std.testing.expectError(oqs.OqsError.DecapsulationFailed, kem.decaps(&ct, &sk));
}

test "core Sig turns a liboqs error status into KeyGenerationFailed and SignFailed, and verify into false" {
    var sig = try oqs.Sig.init(a, "ML-DSA-44");
    defer sig.deinit();
    const pk: [1312]u8 = @splat(0);
    const sk: [2560]u8 = @splat(0);
    sig.handle.keypair = Stub.keypairSig;
    sig.handle.sign = Stub.sign;
    sig.handle.verify = Stub.verify;
    try std.testing.expectError(oqs.OqsError.KeyGenerationFailed, sig.keypair());
    try std.testing.expectError(oqs.OqsError.SignFailed, sig.sign("m", &sk));
    try std.testing.expect(!try sig.verify("m", "s", &pk));
}
