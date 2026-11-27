//! Fuzz tests for the KEM and signature wrappers. Each one is seeded from the
//! build (default 0x5717f022, override with -Dfuzz-seed=N) and prints the seed
//! first. Each checks both directions. False negatives: valid input is always
//! accepted, with random messages and with key pairs from random seeds of the
//! liboqs KAT generator. False positives: mutated messages, signatures,
//! ciphertexts and keys are never accepted, and never give the real secret.
//!
//! The KAT generator is process global, so these tests live in their own
//! binary. The rounds are few so a Debug run stays quick, and `zig build
//! behaviour` runs a round on every algorithm.
const std = @import("std");
const oqs = @import("oqs");
const checks = @import("behaviour_checks");
const build_options = @import("build_options");
const sample = @import("behaviour_sample.zig");

const a = std.testing.allocator;

// Rounds for the algorithms that are quick in a Debug build, and for the slow ones.
const rounds = 4;
const slow_rounds = 1;

fn start(salt: u64) std.Random.DefaultPrng {
    const seed: u64 = build_options.fuzz_seed;
    std.debug.print("fuzz seed 0x{x}\n", .{seed});
    return std.Random.DefaultPrng.init(seed ^ salt);
}

test "fuzz: KEM key pairs from random KAT seeds agree, and changed or random ciphertexts and other secret keys never give the secret" {
    var prng = start(0x11);
    for (sample.kem) |entry| try checks.fuzzKem(a, entry.name, prng.random(), if (entry.slow) slow_rounds else rounds);
}

test "fuzz: signatures of random messages verify, and changed messages, signatures and keys never do" {
    var prng = start(0x22);
    for (sample.sig) |entry| try checks.fuzzSig(a, entry.name, prng.random(), if (entry.slow) slow_rounds else rounds);
}

fn seedKat(random: std.Random) void {
    var seed: [48]u8 = undefined;
    random.bytes(&seed);
    oqs.testing.seedKat(&seed);
}

test "fuzz: ML-KEM-512 with one bit of the public key or the secret key flipped never gives the encapsulated secret" {
    // Hand-written from the liboqs ML-KEM source. The secret key is dk_pke
    // (768 bytes), ek (800), H(ek) (32), z (32).
    // A changed byte of the public key, below the 768 bytes of t and in the
    // last 32 bytes of rho, gives an encapsulation that the real secret key
    // rejects, or an encapsulation error when a coefficient is out of range.
    // A changed bit in the secret vector gives a rejection key. A changed bit
    // in the embedded public key or its hash fails the hash check.
    var prng = start(0x33);
    const random = prng.random();
    var kem = try oqs.Kem.init(a, "ML-KEM-512");
    defer kem.deinit();
    for (0..rounds * 4) |_| {
        seedKat(random);
        const kp = try kem.keypair();
        defer a.free(kp.public_key);
        defer a.free(kp.secret_key);

        // No false negative: the untouched pair agrees.
        seedKat(random);
        const good = try kem.encaps(kp.public_key);
        defer a.free(good.ciphertext);
        defer a.free(good.shared_secret);
        const back = try kem.decaps(good.ciphertext, kp.secret_key);
        defer a.free(back);
        try std.testing.expect(std.mem.eql(u8, good.shared_secret, back));

        // A flipped public key bit.
        const bad_pk = try a.dupe(u8, kp.public_key);
        defer a.free(bad_pk);
        checks.flipBit(bad_pk, random.uintLessThan(usize, bad_pk.len * 8));
        if (kem.encaps(bad_pk)) |enc| {
            defer a.free(enc.ciphertext);
            defer a.free(enc.shared_secret);
            const got = try kem.decaps(enc.ciphertext, kp.secret_key);
            defer a.free(got);
            try std.testing.expect(!std.mem.eql(u8, got, enc.shared_secret));
        } else |err| try std.testing.expectEqual(oqs.OqsError.EncapsulationFailed, err);

        // A flipped secret vector bit.
        const bad_sk = try a.dupe(u8, kp.secret_key);
        defer a.free(bad_sk);
        checks.flipBit(bad_sk, random.uintLessThan(usize, 768 * 8));
        const rejected = try kem.decaps(good.ciphertext, bad_sk);
        defer a.free(rejected);
        try std.testing.expect(!std.mem.eql(u8, rejected, good.shared_secret));

        // A flipped bit of the embedded public key or its hash.
        @memcpy(bad_sk, kp.secret_key);
        checks.flipBit(bad_sk, 768 * 8 + random.uintLessThan(usize, (800 + 32) * 8));
        try std.testing.expectError(oqs.OqsError.DecapsulationFailed, kem.decaps(good.ciphertext, bad_sk));
    }
}

test "fuzz: typed key pairs agree, and typed mutants never verify or give the secret" {
    var prng = start(0x44);
    const random = prng.random();
    for (0..rounds) |_| {
        // KEM.
        seedKat(random);
        var kp = try oqs.kem.MlKem512.generateKeyPair(a);
        defer kp.public_key.deinit();
        defer kp.secret_key.deinit();
        seedKat(random);
        var enc = try kp.public_key.encapsulate();
        defer enc.deinit();
        var ss = try kp.secret_key.decapsulate(enc.ciphertext);
        defer ss.deinit();
        try std.testing.expect(std.mem.eql(u8, ss.bytes, enc.shared_secret.bytes));
        const bad_ct = try a.dupe(u8, enc.ciphertext);
        defer a.free(bad_ct);
        checks.flipBit(bad_ct, random.uintLessThan(usize, bad_ct.len * 8));
        var rejected = try kp.secret_key.decapsulate(bad_ct);
        defer rejected.deinit();
        try std.testing.expect(!std.mem.eql(u8, rejected.bytes, enc.shared_secret.bytes));

        // Signature.
        seedKat(random);
        var skp = try oqs.sig.MlDsa44.generateKeyPair(a);
        defer skp.public_key.deinit();
        defer skp.secret_key.deinit();
        var message_buf: [200]u8 = undefined;
        const message = message_buf[0..random.uintAtMost(usize, 200)];
        random.bytes(message);
        seedKat(random);
        var s = try skp.secret_key.sign(message);
        defer s.deinit();
        try std.testing.expect(try skp.public_key.isValidSignature(message, s.bytes));
        checks.flipBit(s.bytes, random.uintLessThan(usize, s.bytes.len * 8));
        try std.testing.expect(!try skp.public_key.isValidSignature(message, s.bytes));
        if (message.len > 0) {
            // The signature is already changed, so sign again for a message mutant.
            var s2 = try skp.secret_key.sign(message);
            defer s2.deinit();
            checks.flipBit(message, random.uintLessThan(usize, message.len * 8));
            try std.testing.expect(!try skp.public_key.isValidSignature(message, s2.bytes));
        }
    }
}
