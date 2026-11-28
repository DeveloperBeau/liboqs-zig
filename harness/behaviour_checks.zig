//! Behaviour checks for one KEM or one signature scheme, driven through the
//! core `oqs.Kem` and `oqs.Sig`. The `behaviour` harness runs them over every
//! enabled algorithm and the tests run them over a sample.
//!
//! The checks follow the liboqs programs test_kem.c and test_sig.c, and the
//! Rust behaviour programs. Every expectation about an algorithm family is
//! written out here by hand from the liboqs 0.16.0 sources, never read back
//! from the code under test. A failure names the algorithm and the check and
//! never prints key or shared secret bytes, only a yes or no.
const std = @import("std");
const oqs = @import("oqs");

/// The one error a failed expectation returns, after it printed which one failed.
pub const Failure = error{BehaviourCheckFailed};

/// How many bit positions of a ciphertext, message or signature a check flips.
/// The first, the last and the middle bit are always among them.
const flip_count = 6;

fn require(name: []const u8, what: []const u8, ok: bool) Failure!void {
    if (ok) return;
    std.debug.print("BEHAVIOUR FAIL {s}: {s}\n", .{ name, what });
    return error.BehaviourCheckFailed;
}

/// Flips bit `bit_index` of `bytes`, counting from the least significant bit of byte 0.
pub fn flipBit(bytes: []u8, bit_index: usize) void {
    bytes[bit_index / 8] ^= @as(u8, 1) << @intCast(bit_index % 8);
}

fn wipeFree(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}

/// The bit positions a check flips in a buffer of `bit_len` bits: the first,
/// the middle and the last bit, then random ones. Positions can repeat, which
/// only costs a repeated check.
fn flipPositions(random: std.Random, bit_len: usize) [flip_count]usize {
    var out: [flip_count]usize = undefined;
    out[0] = 0;
    out[1] = bit_len / 2;
    out[2] = bit_len - 1;
    for (out[3..]) |*p| p.* = random.uintLessThan(usize, bit_len);
    return out;
}

// --- Hand-written family tables ------------------------------------------

const KemFamily = struct { prefix: []const u8, count: usize };

// Each family implements the FO transform with implicit rejection: decaps of
// every one returns success for a ciphertext of the right length, and gives a
// secret that is not the encapsulated one. The count is how many enabled KEMs
// the family has.
const kem_family_rejection = [_]KemFamily{
    .{ .prefix = "BIKE-", .count = 3 },
    .{ .prefix = "Classic-McEliece-", .count = 10 },
    .{ .prefix = "FrodoKEM-", .count = 6 },
    .{ .prefix = "eFrodoKEM-", .count = 6 },
    .{ .prefix = "HQC-", .count = 3 },
    .{ .prefix = "Kyber", .count = 3 },
    .{ .prefix = "ML-KEM-", .count = 3 },
    .{ .prefix = "NTRU-", .count = 6 },
    .{ .prefix = "sntrup", .count = 1 },
};

/// How many enabled KEMs each family has, as the table above lists them. The
/// total is 41.
pub fn kemFamilyCounts() []const KemFamily {
    return &kem_family_rejection;
}

/// True when `name` starts with a KEM family prefix in the table, so a family
/// with implicit rejection claims it. False for a name no family claims.
pub fn rejectionOf(name: []const u8) bool {
    for (kem_family_rejection) |family| {
        if (std.mem.startsWith(u8, name, family.prefix)) return true;
    }
    return false;
}

const SigFamily = struct { prefix: []const u8, suf_cma: bool, count: usize };

const sig_families = [_]SigFamily{
    // Only ML-DSA claims strong unforgeability. The count is how many enabled
    // schemes the family has. 3 claim SUF-CMA and 218 do not.
    .{ .prefix = "ML-DSA-", .suf_cma = true, .count = 3 },
    .{ .prefix = "SLH_DSA_", .suf_cma = false, .count = 156 },
    .{ .prefix = "Falcon-", .suf_cma = false, .count = 4 },
    .{ .prefix = "MAYO-", .suf_cma = false, .count = 4 },
    .{ .prefix = "cross-", .suf_cma = false, .count = 18 },
    .{ .prefix = "mqom2_", .suf_cma = false, .count = 12 },
    .{ .prefix = "SNOVA_", .suf_cma = false, .count = 12 },
    .{ .prefix = "OV-", .suf_cma = false, .count = 12 },
};

/// The signature families, with how many enabled schemes each has and whether
/// they claim SUF-CMA. The counts add up to 221.
pub fn sigFamilyCounts() []const SigFamily {
    return &sig_families;
}

/// True if the scheme `name` claims SUF-CMA, so a flipped signature bit must fail verify. Null for a name no family claims.
pub fn claimsSufCma(name: []const u8) ?bool {
    for (sig_families) |family| {
        if (std.mem.startsWith(u8, name, family.prefix)) return family.suf_cma;
    }
    return null;
}

// --- KEM ------------------------------------------------------------------

const KemPair = struct {
    kem: oqs.Kem,
    public_key: []u8,
    secret_key: []u8,

    /// Makes a key pair with `kem`. The pair does not own `kem`.
    fn init(kem: oqs.Kem) !KemPair {
        const kp = try kem.keypair();
        return .{ .kem = kem, .public_key = kp.public_key, .secret_key = kp.secret_key };
    }

    fn deinit(self: *KemPair) void {
        const allocator = self.kem.allocator;
        allocator.free(self.public_key);
        wipeFree(allocator, self.secret_key);
    }
};

fn sameBytes(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Checks one KEM through the core wrapper, as test_kem.c does and more.
///
/// 1. keypair, encaps and decaps give the same shared secret, and decaps is repeatable.
/// 2. A ciphertext with one bit flipped, and one with one byte inverted, gives
///    a different secret and no error, because every family rejects implicitly.
///    The one exception is a nonzero padding bit in Classic McEliece 6960119,
///    which gives DecapsulationFailed.
/// 3. A random ciphertext of the right length gives the same as in 2.
/// 4. A ciphertext, public key or secret key of the wrong length gives InvalidKeySize.
pub fn checkKem(allocator: std.mem.Allocator, name: [:0]const u8, random: std.Random) !void {
    var kem = try oqs.Kem.init(allocator, name);
    defer kem.deinit();
    try checkKemWith(name, kem, random);
}

/// The same checks on a `kem` the caller made, so a test can pass an object
/// whose function pointers misbehave and see that a check fails. `name` picks
/// the family rules. The caller keeps `kem` and frees it.
pub fn checkKemWith(name: []const u8, kem: oqs.Kem, random: std.Random) !void {
    const allocator = kem.allocator;
    try require(name, "no rejection rule is written for this KEM family", rejectionOf(name));

    var pair = try KemPair.init(kem);
    defer pair.deinit();
    try require(name, "key and ciphertext lengths are zero", kem.lengthPublicKey() > 0 and kem.lengthSecretKey() > 0 and kem.lengthCiphertext() > 0);
    try require(name, "the shared secret is not 16, 24 or 32 bytes", kem.lengthSharedSecret() == 16 or kem.lengthSharedSecret() == 24 or kem.lengthSharedSecret() == 32);

    const enc = try kem.encaps(pair.public_key);
    defer allocator.free(enc.ciphertext);
    var encapsulated = oqs.SharedSecret.fromOwned(allocator, enc.shared_secret);
    defer encapsulated.deinit();

    // The round trip, twice.
    for (0..2) |_| {
        var decapsulated = oqs.SharedSecret.fromOwned(allocator, try kem.decaps(enc.ciphertext, pair.secret_key));
        defer decapsulated.deinit();
        try require(name, "decaps did not give the encapsulated shared secret", sameBytes(encapsulated.bytes, decapsulated.bytes));
    }

    // One bit of the ciphertext changed, at the first, middle and last bit and at random ones.
    const mutated = try allocator.dupe(u8, enc.ciphertext);
    defer allocator.free(mutated);
    for (flipPositions(random, mutated.len * 8)) |bit| {
        flipBit(mutated, bit);
        try requireRejected(allocator, name, kem, mutated, pair.secret_key, encapsulated.bytes);
        flipBit(mutated, bit);
    }
    // One byte of the ciphertext changed in every bit.
    for ([_]usize{ 0, mutated.len / 2, mutated.len - 1 }) |at| {
        mutated[at] ^= 0xFF;
        try requireRejected(allocator, name, kem, mutated, pair.secret_key, encapsulated.bytes);
        mutated[at] ^= 0xFF;
    }
    try require(name, "the test changed the ciphertext it should have restored", sameBytes(mutated, enc.ciphertext));

    // A random ciphertext of the right length.
    random.bytes(mutated);
    try requireRejected(allocator, name, kem, mutated, pair.secret_key, encapsulated.bytes);

    try checkKemLengths(allocator, name, pair, enc.ciphertext);
}

/// True if liboqs decaps returns an error, not a rejection key, for `ciphertext`.
///
/// Written out from the PQClean sources of Classic McEliece. The syndrome of
/// 6960119 has 1547 bits, so the top 5 bits of the last ciphertext byte are
/// padding, and crypto_kem_dec returns -1 when any of them is set
/// (check_c_padding). The other eight sets have a whole number of syndrome
/// bytes, and every other family has no such check.
pub fn decapsErrorsFor(name: []const u8, ciphertext: []const u8) bool {
    const has_padding_check = std.mem.eql(u8, name, "Classic-McEliece-6960119") or std.mem.eql(u8, name, "Classic-McEliece-6960119f");
    return has_padding_check and (ciphertext[ciphertext.len - 1] >> 3) != 0;
}

/// Decapsulates a ciphertext that is not the one `real` came from. A family
/// with implicit rejection gives a different secret and no error, and the one
/// case `decapsErrorsFor` lists gives DecapsulationFailed.
fn requireRejected(allocator: std.mem.Allocator, name: []const u8, kem: oqs.Kem, ciphertext: []const u8, secret_key: []const u8, real: []const u8) !void {
    const got = kem.decaps(ciphertext, secret_key) catch |err| {
        try require(name, "decaps returned an error that the family does not give for this ciphertext", err == oqs.OqsError.DecapsulationFailed and decapsErrorsFor(name, ciphertext));
        return;
    };
    var secret = oqs.SharedSecret.fromOwned(allocator, got);
    defer secret.deinit();
    try require(name, "decaps gave a secret where the family returns an error", !decapsErrorsFor(name, ciphertext));
    try require(name, "decaps of a changed ciphertext gave the encapsulated shared secret", !sameBytes(real, secret.bytes));
}

fn checkKemLengths(allocator: std.mem.Allocator, name: []const u8, pair: KemPair, ciphertext: []const u8) !void {
    const kem = pair.kem;
    const sizes = [_]struct { delta: isize, what: []const u8 }{
        .{ .delta = -1, .what = "one byte short" },
        .{ .delta = 1, .what = "one byte long" },
    };
    for (sizes) |size| {
        const pk = try resized(allocator, pair.public_key, size.delta);
        defer allocator.free(pk);
        const ct = try resized(allocator, ciphertext, size.delta);
        defer allocator.free(ct);
        const sk = try resized(allocator, pair.secret_key, size.delta);
        defer wipeFree(allocator, sk);
        try require(name, size.what, isInvalidKeySize(kem.encaps(pk)));
        try require(name, size.what, isInvalidKeySize(kem.decaps(ct, pair.secret_key)));
        try require(name, size.what, isInvalidKeySize(kem.decaps(ciphertext, sk)));
    }
    const empty: []const u8 = &.{};
    try require(name, "an empty public key", isInvalidKeySize(kem.encaps(empty)));
    try require(name, "an empty ciphertext", isInvalidKeySize(kem.decaps(empty, pair.secret_key)));
    try require(name, "an empty secret key", isInvalidKeySize(kem.decaps(ciphertext, empty)));
}

/// True if `result` is the InvalidKeySize error. A success returns false and
/// leaves the allocation to the caller's allocator, which only matters when a
/// check is already failing.
fn isInvalidKeySize(result: anytype) bool {
    if (result) |_| return false else |err| return err == oqs.OqsError.InvalidKeySize;
}

/// A copy of `bytes` that is `delta` bytes longer, or shorter when negative, with the new tail zero.
fn resized(allocator: std.mem.Allocator, bytes: []const u8, delta: isize) ![]u8 {
    const len: usize = @intCast(@as(isize, @intCast(bytes.len)) + delta);
    const out = try allocator.alloc(u8, len);
    @memset(out, 0);
    @memcpy(out[0..@min(len, bytes.len)], bytes[0..@min(len, bytes.len)]);
    return out;
}

// --- Signature ---------------------------------------------------------------

const SigPair = struct {
    sig: oqs.Sig,
    public_key: []u8,
    secret_key: []u8,

    /// Makes a key pair with `sig`. The pair does not own `sig`.
    fn init(sig: oqs.Sig) !SigPair {
        const kp = try sig.keypair();
        return .{ .sig = sig, .public_key = kp.public_key, .secret_key = kp.secret_key };
    }

    fn deinit(self: *SigPair) void {
        const allocator = self.sig.allocator;
        allocator.free(self.public_key);
        wipeFree(allocator, self.secret_key);
    }
};

/// Checks one signature scheme through the core wrapper, as test_sig.c does and more.
///
/// 1. sign and verify agree, for a message of 0 bytes and one of 32 bytes. The
///    signature is at most the maximum length and never empty.
/// 2. Flipping a bit of the message, at the first, middle and last bit and at
///    random ones, fails verify.
/// 3. Flipping a bit of the signature fails verify when the scheme claims
///    SUF-CMA. The claim is read from the liboqs object and compared with the
///    hand-written family table first.
/// 4. A signature fails under another key pair.
/// 5. A key of the wrong length gives InvalidKeySize.
/// 6. Signatures of all zero bytes, all ones and random bytes, at the maximum
///    length, the produced length, 1, half the maximum, 0 and one over the
///    maximum, never verify.
pub fn checkSig(allocator: std.mem.Allocator, name: [:0]const u8, random: std.Random) !void {
    var sig = try oqs.Sig.init(allocator, name);
    defer sig.deinit();
    try checkSigWith(name, sig, random);
}

/// The same checks on a `sig` the caller made, like `checkKemWith`.
pub fn checkSigWith(name: []const u8, sig: oqs.Sig, random: std.Random) !void {
    const allocator = sig.allocator;
    const claim = claimsSufCma(name) orelse {
        try require(name, "no SUF-CMA claim is written for this signature family", false);
        unreachable;
    };

    var pair = try SigPair.init(sig);
    defer pair.deinit();
    try require(name, "the liboqs object does not claim EUF-CMA", sig.handle.euf_cma);
    try require(name, "the liboqs SUF-CMA claim differs from the hand-written one", sig.handle.suf_cma == claim);
    try require(name, "key lengths are zero", sig.lengthPublicKey() > 0 and sig.lengthSecretKey() > 0 and sig.lengthSignatureMax() > 0);

    // The empty message.
    {
        const signature = try sig.sign("", pair.secret_key);
        defer allocator.free(signature);
        try require(name, "the signature of the empty message was rejected", try sig.verify("", signature, pair.public_key));
    }

    var message: [32]u8 = undefined;
    random.bytes(&message);
    const signature = try sig.sign(&message, pair.secret_key);
    defer allocator.free(signature);
    try require(name, "the signature length is 0 or over the maximum", signature.len > 0 and signature.len <= sig.lengthSignatureMax());
    try require(name, "a valid signature was rejected", try sig.verify(&message, signature, pair.public_key));
    // A repeated verify gives the same answer.
    try require(name, "a valid signature was rejected the second time", try sig.verify(&message, signature, pair.public_key));

    // Message bits.
    var bad_message = message;
    for (flipPositions(random, message.len * 8)) |bit| {
        flipBit(&bad_message, bit);
        try require(name, "a message with a flipped bit verified", !try sig.verify(&bad_message, signature, pair.public_key));
        flipBit(&bad_message, bit);
    }
    try require(name, "a shorter message verified", !try sig.verify(message[0 .. message.len - 1], signature, pair.public_key));
    try require(name, "a longer message verified", !try sig.verify(&(message ++ [_]u8{0}), signature, pair.public_key));

    // Signature bits, for the schemes that claim SUF-CMA.
    const bad_signature = try allocator.dupe(u8, signature);
    defer allocator.free(bad_signature);
    for (flipPositions(random, signature.len * 8)) |bit| {
        flipBit(bad_signature, bit);
        const accepted = try sig.verify(&message, bad_signature, pair.public_key);
        if (claim) try require(name, "a SUF-CMA scheme verified a signature with a flipped bit", !accepted);
        flipBit(bad_signature, bit);
    }
    // A signature cut short or stretched by one byte.
    try require(name, "a signature one byte short verified", !try sig.verify(&message, signature[0 .. signature.len - 1], pair.public_key));
    const longer = try resized(allocator, signature, 1);
    defer allocator.free(longer);
    try require(name, "a signature one byte long verified", !try sig.verify(&message, longer, pair.public_key));

    // Another key pair.
    {
        var other = try SigPair.init(sig);
        defer other.deinit();
        try require(name, "a signature verified under another public key", !try sig.verify(&message, signature, other.public_key));
        try require(name, "two key pairs have the same public key", !sameBytes(pair.public_key, other.public_key));
    }

    try checkSigLengths(allocator, name, pair, &message, signature);
    try checkHostileSignatures(allocator, name, random, pair, &message, signature.len);
}

fn checkSigLengths(allocator: std.mem.Allocator, name: []const u8, pair: SigPair, message: []const u8, signature: []const u8) !void {
    const sig = pair.sig;
    for ([_]isize{ -1, 1 }) |delta| {
        const pk = try resized(allocator, pair.public_key, delta);
        defer allocator.free(pk);
        const sk = try resized(allocator, pair.secret_key, delta);
        defer wipeFree(allocator, sk);
        try require(name, "verify with a public key of the wrong length", isInvalidKeySize(sig.verify(message, signature, pk)));
        try require(name, "sign with a secret key of the wrong length", isInvalidKeySize(sig.sign(message, sk)));
    }
    const empty: []const u8 = &.{};
    try require(name, "verify with an empty public key", isInvalidKeySize(sig.verify(message, signature, empty)));
    try require(name, "sign with an empty secret key", isInvalidKeySize(sig.sign(message, empty)));
}

fn checkHostileSignatures(allocator: std.mem.Allocator, name: []const u8, random: std.Random, pair: SigPair, message: []const u8, produced: usize) !void {
    const sig = pair.sig;
    const max = sig.lengthSignatureMax();
    const lengths = [_]usize{ max, produced, 1, max / 2, 0, max + 1 };
    const hostile = try allocator.alloc(u8, max + 1);
    defer allocator.free(hostile);
    for (lengths) |len| {
        for (0..3) |pattern| {
            switch (pattern) {
                0 => @memset(hostile, 0x00),
                1 => @memset(hostile, 0xFF),
                else => random.bytes(hostile),
            }
            try require(name, "a hostile signature verified", !try sig.verify(message, hostile[0..len], pair.public_key));
        }
    }
}

// --- Fuzz ----------------------------------------------------------------

fn seedKat(random: std.Random) void {
    var seed: [48]u8 = undefined;
    random.bytes(&seed);
    oqs.testing.seedKat(&seed);
}

/// Flips between one and three distinct bits of `bytes`.
fn flipSome(random: std.Random, bytes: []u8) void {
    const count = 1 + random.uintLessThan(usize, 3);
    var chosen: [3]usize = undefined;
    for (0..count) |i| {
        while (true) {
            const bit = random.uintLessThan(usize, bytes.len * 8);
            if (std.mem.indexOfScalar(usize, chosen[0..i], bit) == null) {
                chosen[i] = bit;
                break;
            }
        }
        flipBit(bytes, chosen[i]);
    }
}

/// Fuzzes one KEM for `rounds` rounds. It seeds the liboqs KAT generator, so a
/// binary that calls it must not need the system random source afterwards.
///
/// False negatives: a key pair made under a random seed and an encapsulation
/// made under another random seed always decapsulate to the same secret.
/// False positives: a ciphertext with one to three bits flipped, a random
/// ciphertext, and a secret key of another pair never give that secret.
pub fn fuzzKem(allocator: std.mem.Allocator, name: [:0]const u8, random: std.Random, rounds: usize) !void {
    var kem = try oqs.Kem.init(allocator, name);
    defer kem.deinit();
    try fuzzKemWith(name, kem, random, rounds);
}

/// `fuzzKem` on a `kem` the caller made, like `checkKemWith`.
pub fn fuzzKemWith(name: []const u8, kem: oqs.Kem, random: std.Random, rounds: usize) !void {
    const allocator = kem.allocator;
    for (0..rounds) |_| {
        seedKat(random);
        const kp = try kem.keypair();
        defer allocator.free(kp.public_key);
        defer wipeFree(allocator, kp.secret_key);
        seedKat(random);
        const other = try kem.keypair();
        defer allocator.free(other.public_key);
        defer wipeFree(allocator, other.secret_key);
        seedKat(random);
        const enc = try kem.encaps(kp.public_key);
        defer allocator.free(enc.ciphertext);
        var encapsulated = oqs.SharedSecret.fromOwned(allocator, enc.shared_secret);
        defer encapsulated.deinit();

        var decapsulated = oqs.SharedSecret.fromOwned(allocator, try kem.decaps(enc.ciphertext, kp.secret_key));
        defer decapsulated.deinit();
        try require(name, "fuzz: a fresh pair did not decapsulate to the encapsulated secret", sameBytes(encapsulated.bytes, decapsulated.bytes));

        const mutated = try allocator.dupe(u8, enc.ciphertext);
        defer allocator.free(mutated);
        flipSome(random, mutated);
        try requireRejected(allocator, name, kem, mutated, kp.secret_key, encapsulated.bytes);
        random.bytes(mutated);
        try requireRejected(allocator, name, kem, mutated, kp.secret_key, encapsulated.bytes);
        // The secret key of another pair.
        try requireRejected(allocator, name, kem, enc.ciphertext, other.secret_key, encapsulated.bytes);
    }
}

/// Fuzzes one signature scheme for `rounds` rounds. It seeds the liboqs KAT
/// generator like `fuzzKem`.
///
/// False negatives: a message of random length and content, signed under a
/// random seed, always verifies.
/// False positives: a message with bits flipped, cut or extended, a
/// signature cut or extended, a random signature, the public key of another
/// pair, and a public key with a bit flipped never verify. A signature with
/// bits flipped never verifies when the scheme claims SUF-CMA.
pub fn fuzzSig(allocator: std.mem.Allocator, name: [:0]const u8, random: std.Random, rounds: usize) !void {
    var sig = try oqs.Sig.init(allocator, name);
    defer sig.deinit();
    try fuzzSigWith(name, sig, random, rounds);
}

/// `fuzzSig` on a `sig` the caller made, like `checkKemWith`.
pub fn fuzzSigWith(name: []const u8, sig: oqs.Sig, random: std.Random, rounds: usize) !void {
    const allocator = sig.allocator;
    const claim = claimsSufCma(name) orelse {
        try require(name, "no SUF-CMA claim is written for this signature family", false);
        unreachable;
    };
    var message_buf: [301]u8 = undefined;
    for (0..rounds) |_| {
        seedKat(random);
        const kp = try sig.keypair();
        defer allocator.free(kp.public_key);
        defer wipeFree(allocator, kp.secret_key);
        seedKat(random);
        const other = try sig.keypair();
        defer allocator.free(other.public_key);
        defer wipeFree(allocator, other.secret_key);

        const message_len = random.uintAtMost(usize, 300);
        const message = message_buf[0..message_len];
        random.bytes(message);
        seedKat(random);
        const signature = try sig.sign(message, kp.secret_key);
        defer allocator.free(signature);
        try require(name, "fuzz: a valid signature was rejected", try sig.verify(message, signature, kp.public_key));

        // Message mutants.
        if (message_len > 0) {
            var mutated: [300]u8 = undefined;
            @memcpy(mutated[0..message_len], message);
            flipSome(random, mutated[0..message_len]);
            try require(name, "fuzz: a message with flipped bits verified", !try sig.verify(mutated[0..message_len], signature, kp.public_key));
            try require(name, "fuzz: a cut message verified", !try sig.verify(message[0..random.uintLessThan(usize, message_len)], signature, kp.public_key));
        }
        message_buf[message_len] = random.int(u8);
        try require(name, "fuzz: an extended message verified", !try sig.verify(message_buf[0 .. message_len + 1], signature, kp.public_key));

        // Signature mutants.
        const bad = try allocator.dupe(u8, signature);
        defer allocator.free(bad);
        if (claim) {
            flipSome(random, bad);
            try require(name, "fuzz: a SUF-CMA scheme verified a signature with flipped bits", !try sig.verify(message, bad, kp.public_key));
        }
        try require(name, "fuzz: a cut signature verified", !try sig.verify(message, signature[0..random.uintLessThan(usize, signature.len)], kp.public_key));
        random.bytes(bad);
        try require(name, "fuzz: a random signature verified", !try sig.verify(message, bad, kp.public_key));

        // Key mutants.
        try require(name, "fuzz: a signature verified under another public key", !try sig.verify(message, signature, other.public_key));
        const bad_key = try allocator.dupe(u8, kp.public_key);
        defer allocator.free(bad_key);
        flipBit(bad_key, random.uintLessThan(usize, bad_key.len * 8));
        try require(name, "fuzz: a signature verified under a public key with a flipped bit", !try sig.verify(message, signature, bad_key));
    }
}

test "flipBit flips exactly the bit asked for and flipping twice restores the byte" {
    var bytes = [_]u8{ 0x00, 0x00, 0xFF };
    flipBit(&bytes, 0);
    flipBit(&bytes, 9);
    flipBit(&bytes, 23);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x7F }, &bytes);
    flipBit(&bytes, 0);
    flipBit(&bytes, 9);
    flipBit(&bytes, 23);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0xFF }, &bytes);
}

test "flipPositions starts with the first, middle and last bit" {
    var prng = std.Random.DefaultPrng.init(1);
    const positions = flipPositions(prng.random(), 80);
    try std.testing.expectEqual(@as(usize, 0), positions[0]);
    try std.testing.expectEqual(@as(usize, 40), positions[1]);
    try std.testing.expectEqual(@as(usize, 79), positions[2]);
    for (positions) |p| try std.testing.expect(p < 80);
}

test "flipSome flips one to three distinct bits" {
    var prng = std.Random.DefaultPrng.init(2);
    for (0..200) |_| {
        var bytes: [4]u8 = @splat(0);
        flipSome(prng.random(), &bytes);
        var ones: usize = 0;
        for (bytes) |b| ones += @popCount(b);
        try std.testing.expect(ones >= 1 and ones <= 3);
    }
}
