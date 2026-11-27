//! Tests for seeded key pair generation and encapsulation, through the runtime
//! core `oqs.Kem` and the typed `oqs.kem.*` wrappers.
//!
//! The seeds are fixed public test bytes. The known-answer tests compare the
//! wrapper output with the raw C API under the same seeds, and with SHA-256
//! digests that were written out by hand. The digests come from the native
//! Rust port, so they check the two ports against each other and not only
//! against the code under test. Secret keys and shared secrets are compared
//! through digests or `std.mem.eql`, and no test prints their bytes.
const std = @import("std");
const oqs = @import("oqs");
const c = @import("c_api");
const build_options = @import("build_options");

const a = std.testing.allocator;

// Key pair seed: bytes 0 to 63. Encapsulation seed: bytes 64 to 95.
fn keySeed() [64]u8 {
    var seed: [64]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i);
    return seed;
}

fn encapsSeed() [32]u8 {
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(64 + i);
    return seed;
}

fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

// Compares two byte strings and prints only their lengths when they differ,
// so a failure never shows key or secret bytes.
fn expectSameBytes(what: []const u8, expected: []const u8, actual: []const u8) !void {
    if (!std.mem.eql(u8, expected, actual)) {
        std.debug.print("{s}: bytes differ (lengths {d} and {d})\n", .{ what, expected.len, actual.len });
        return error.TestUnexpectedResult;
    }
}

fn expectDifferentBytes(what: []const u8, one: []const u8, other: []const u8) !void {
    if (std.mem.eql(u8, one, other)) {
        std.debug.print("{s}: bytes are equal but must differ\n", .{what});
        return error.TestUnexpectedResult;
    }
}

const Output = struct {
    public_key: []u8,
    secret_key: []u8,
    ciphertext: []u8,
    shared_secret: []u8,

    fn deinit(self: Output) void {
        a.free(self.public_key);
        std.crypto.secureZero(u8, self.secret_key);
        a.free(self.secret_key);
        a.free(self.ciphertext);
        std.crypto.secureZero(u8, self.shared_secret);
        a.free(self.shared_secret);
    }
};

// One seeded keypair and one seeded encaps through the raw C API.
fn rawSeeded(name: [:0]const u8, key_seed: []const u8, enc_seed: []const u8) !Output {
    const k = c.OQS_KEM_new(name.ptr) orelse return error.AlgorithmNotAvailable;
    defer c.OQS_KEM_free(k);
    const pk = try a.alloc(u8, k.*.length_public_key);
    errdefer a.free(pk);
    const sk = try a.alloc(u8, k.*.length_secret_key);
    errdefer a.free(sk);
    const ct = try a.alloc(u8, k.*.length_ciphertext);
    errdefer a.free(ct);
    const ss = try a.alloc(u8, k.*.length_shared_secret);
    errdefer a.free(ss);
    try std.testing.expectEqual(c.OQS_SUCCESS, c.OQS_KEM_keypair_derand(k, pk.ptr, sk.ptr, key_seed.ptr));
    try std.testing.expectEqual(c.OQS_SUCCESS, c.OQS_KEM_encaps_derand(k, ct.ptr, ss.ptr, pk.ptr, enc_seed.ptr));
    return .{ .public_key = pk, .secret_key = sk, .ciphertext = ct, .shared_secret = ss };
}

fn coreSeeded(name: [:0]const u8, key_seed: []const u8, enc_seed: []const u8) !Output {
    var kem = try oqs.Kem.init(a, name);
    defer kem.deinit();
    const kp = try kem.keypairFromSeed(key_seed);
    errdefer a.free(kp.public_key);
    errdefer a.free(kp.secret_key);
    const enc = try kem.encapsFromSeed(kp.public_key, enc_seed);
    return .{ .public_key = kp.public_key, .secret_key = kp.secret_key, .ciphertext = enc.ciphertext, .shared_secret = enc.shared_secret };
}

// The typed output is copied out so one `Output` type holds all three layers.
fn typedSeeded(comptime T: type, key_seed: []const u8, enc_seed: []const u8) !Output {
    var kp = try T.generateKeyPairFromSeed(a, key_seed);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var enc = try kp.public_key.encapsulateWithSeed(enc_seed);
    defer enc.deinit();
    return .{
        .public_key = try a.dupe(u8, kp.public_key.bytes),
        .secret_key = try a.dupe(u8, kp.secret_key.bytes),
        .ciphertext = try a.dupe(u8, enc.ciphertext),
        .shared_secret = try a.dupe(u8, enc.shared_secret.bytes),
    };
}

fn expectSameOutput(what: []const u8, expected: Output, actual: Output) !void {
    try expectSameBytes(what, expected.public_key, actual.public_key);
    try expectSameBytes(what, expected.secret_key, actual.secret_key);
    try expectSameBytes(what, expected.ciphertext, actual.ciphertext);
    try expectSameBytes(what, expected.shared_secret, actual.shared_secret);
}

const Expected = struct {
    name: [:0]const u8,
    pk_len: usize,
    sk_len: usize,
    ct_len: usize,
    pk_sha: []const u8,
    sk_sha: []const u8,
    ct_sha: []const u8,
    ss_sha: []const u8,
};

// Digests of the native Rust port output for the same two seeds.
const ml_kem_512 = Expected{
    .name = "ML-KEM-512",
    .pk_len = 800,
    .sk_len = 1632,
    .ct_len = 768,
    .pk_sha = "3ae268dccc5456ac0d0f9b39257dc48fe081383b97c400512d712b739762daee",
    .sk_sha = "17fb29b8c4baf74fb81eea15ffd583b3e37f5a5b8dcf6db96c72c3b3751d6f17",
    .ct_sha = "81efe667826848514dcae46fc10cfd34f7b95ed6900e094f727c9e7cccc34df2",
    .ss_sha = "10f3aedb1a3440f36128242e3f158ea8503f9e3b74e18e253f60c8ad0e20cac8",
};
const ml_kem_768 = Expected{
    .name = "ML-KEM-768",
    .pk_len = 1184,
    .sk_len = 2400,
    .ct_len = 1088,
    .pk_sha = "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9",
    .sk_sha = "dac268bde6a8dd238e9887117d6b664e7a7a9350ad6b7c08a948e504809572a5",
    .ct_sha = "dbf4e9aa48b078ad46ec1c9c47bda8c2d2fec9d0e7a21bd48d2238a2abedb856",
    .ss_sha = "3211693eed5183e918a272986290fdf7419bcae0f2f648533dcfb290ca670c19",
};
const ml_kem_1024 = Expected{
    .name = "ML-KEM-1024",
    .pk_len = 1568,
    .sk_len = 3168,
    .ct_len = 1568,
    .pk_sha = "c7b8fa0aa471d5ae18922d6ccad5b31e1d84f92ae723abfd13747018740a8530",
    .sk_sha = "3a2a676c5a242ee683cb6097c8f3e64fbef4d90267f9250ec2beab8f99621fad",
    .ct_sha = "7c89743960f7c3d17bb69572e49de14fe0990c9113a0706963a8f4c7b39afcdf",
    .ss_sha = "0bf615778a6c71e8915a2ec482a0f5a24dbdcd15ddaa55e3c0d7c5df7a4f3910",
};

fn expectDigests(expected: Expected, out: Output) !void {
    try std.testing.expectEqual(expected.pk_len, out.public_key.len);
    try std.testing.expectEqual(expected.sk_len, out.secret_key.len);
    try std.testing.expectEqual(expected.ct_len, out.ciphertext.len);
    try std.testing.expectEqual(@as(usize, 32), out.shared_secret.len);
    try std.testing.expectEqualStrings(expected.pk_sha, &sha256Hex(out.public_key));
    try std.testing.expectEqualStrings(expected.sk_sha, &sha256Hex(out.secret_key));
    try std.testing.expectEqualStrings(expected.ct_sha, &sha256Hex(out.ciphertext));
    try std.testing.expectEqualStrings(expected.ss_sha, &sha256Hex(out.shared_secret));
}

fn expectKnownAnswers(comptime T: type, expected: Expected) !void {
    const key_seed = keySeed();
    const enc_seed = encapsSeed();

    const raw = try rawSeeded(expected.name, &key_seed, &enc_seed);
    defer raw.deinit();
    try expectDigests(expected, raw);

    const core = try coreSeeded(expected.name, &key_seed, &enc_seed);
    defer core.deinit();
    try expectSameOutput(expected.name, raw, core);
    try expectDigests(expected, core);

    const typed = try typedSeeded(T, &key_seed, &enc_seed);
    defer typed.deinit();
    try expectSameOutput(expected.name, raw, typed);
    try expectDigests(expected, typed);

    // The seeded ciphertext decapsulates, through the normal decaps, to the
    // seeded shared secret, on the core and on the typed key.
    var kem = try oqs.Kem.init(a, expected.name);
    defer kem.deinit();
    const ss = try kem.decaps(core.ciphertext, core.secret_key);
    defer {
        std.crypto.secureZero(u8, ss);
        a.free(ss);
    }
    try expectSameBytes("core decaps", core.shared_secret, ss);

    var typed_sk = try T.SecretKey.fromBytes(a, typed.secret_key);
    defer typed_sk.deinit();
    var typed_ss = try typed_sk.decapsulate(typed.ciphertext);
    defer typed_ss.deinit();
    try expectSameBytes("typed decaps", typed.shared_secret, typed_ss.bytes);
}

// --- Known answers -----------------------------------------------------------

test "ML-KEM-512 seeded core and typed output equals the raw C output and the Rust port digests" {
    try expectKnownAnswers(oqs.kem.MlKem512, ml_kem_512);
}

test "ML-KEM-768 seeded core and typed output equals the raw C output and the Rust port digests" {
    try expectKnownAnswers(oqs.kem.MlKem768, ml_kem_768);
}

test "ML-KEM-1024 seeded core and typed output equals the raw C output and the Rust port digests" {
    try expectKnownAnswers(oqs.kem.MlKem1024, ml_kem_1024);
}

// --- Which mechanisms take a seed -------------------------------------------

test "exactly ML-KEM-512, 768 and 1024 have seeds of 64 and 32 bytes and the other 38 of 41 have none, as written out by hand" {
    const supporting = [_][:0]const u8{ "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };
    var names = oqs.Registry.kemNames();
    var total: usize = 0;
    var seeded: usize = 0;
    while (names.next()) |name| {
        total += 1;
        var is_listed = false;
        for (supporting) |listed| {
            if (std.mem.eql(u8, listed, name)) is_listed = true;
        }
        var kem = try oqs.Kem.init(a, name);
        defer kem.deinit();
        const description = oqs.Registry.kemDescription(name).?;
        const want_key: usize = if (is_listed) 64 else 0;
        const want_enc: usize = if (is_listed) 32 else 0;
        if (kem.lengthKeyPairSeed() != want_key or kem.lengthEncapsulationSeed() != want_enc or
            description.keyPairSeedLength != want_key or description.encapsulationSeedLength != want_enc)
        {
            std.debug.print("{s}: seed lengths {d} and {d}, expected {d} and {d}\n", .{ name, kem.lengthKeyPairSeed(), kem.lengthEncapsulationSeed(), want_key, want_enc });
            return error.TestUnexpectedResult;
        }
        if (is_listed) seeded += 1;
    }
    try std.testing.expectEqual(@as(usize, 41), total);
    try std.testing.expectEqual(@as(usize, 3), seeded);
}

// --- Behaviour ---------------------------------------------------------------

test "the same seed gives the same key pair twice and a different seed gives a different one" {
    var kem = try oqs.Kem.init(a, "ML-KEM-768");
    defer kem.deinit();
    const seed = keySeed();
    // The first 32 bytes of a key pair seed fix the public key and the last 32
    // only add the rejection value in the secret key.
    var other = seed;
    other[0] ^= 1;
    var tail_changed = seed;
    tail_changed[63] ^= 1;

    const first = try kem.keypairFromSeed(&seed);
    defer a.free(first.public_key);
    defer {
        std.crypto.secureZero(u8, first.secret_key);
        a.free(first.secret_key);
    }
    const second = try kem.keypairFromSeed(&seed);
    defer a.free(second.public_key);
    defer {
        std.crypto.secureZero(u8, second.secret_key);
        a.free(second.secret_key);
    }
    const third = try kem.keypairFromSeed(&other);
    defer a.free(third.public_key);
    defer {
        std.crypto.secureZero(u8, third.secret_key);
        a.free(third.secret_key);
    }
    const fourth = try kem.keypairFromSeed(&tail_changed);
    defer a.free(fourth.public_key);
    defer {
        std.crypto.secureZero(u8, fourth.secret_key);
        a.free(fourth.secret_key);
    }
    try expectSameBytes("same seed public key", first.public_key, second.public_key);
    try expectSameBytes("same seed secret key", first.secret_key, second.secret_key);
    try expectDifferentBytes("other seed public key", first.public_key, third.public_key);
    try expectDifferentBytes("other seed secret key", first.secret_key, third.secret_key);
    try expectSameBytes("tail changed public key", first.public_key, fourth.public_key);
    try expectDifferentBytes("tail changed secret key", first.secret_key, fourth.secret_key);
}

test "seeded encapsulation to the same key with the same seed gives the same ciphertext and secret, and another seed gives different ones" {
    var kp = try oqs.kem.MlKem768.generateKeyPairFromSeed(a, &keySeed());
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    const seed = encapsSeed();
    var other = seed;
    other[0] ^= 0x80;

    var first = try kp.public_key.encapsulateWithSeed(&seed);
    defer first.deinit();
    var second = try kp.public_key.encapsulateWithSeed(&seed);
    defer second.deinit();
    var third = try kp.public_key.encapsulateWithSeed(&other);
    defer third.deinit();
    try expectSameBytes("same seed ciphertext", first.ciphertext, second.ciphertext);
    try expectSameBytes("same seed secret", first.shared_secret.bytes, second.shared_secret.bytes);
    try expectDifferentBytes("other seed ciphertext", first.ciphertext, third.ciphertext);
    try expectDifferentBytes("other seed secret", first.shared_secret.bytes, third.shared_secret.bytes);
}

test "a seeded key works with random encapsulation and a random key works with seeded encapsulation" {
    // Seeded key pair, random encapsulation.
    var seeded = try oqs.kem.MlKem768.generateKeyPairFromSeed(a, &keySeed());
    defer seeded.public_key.deinit();
    defer seeded.secret_key.deinit();
    var random_enc = try seeded.public_key.encapsulate();
    defer random_enc.deinit();
    var recovered = try seeded.secret_key.decapsulate(random_enc.ciphertext);
    defer recovered.deinit();
    try expectSameBytes("random encaps to a seeded key", random_enc.shared_secret.bytes, recovered.bytes);

    // Random key pair, seeded encapsulation.
    var random_kp = try oqs.kem.MlKem768.generateKeyPair(a);
    defer random_kp.public_key.deinit();
    defer random_kp.secret_key.deinit();
    var seeded_enc = try random_kp.public_key.encapsulateWithSeed(&encapsSeed());
    defer seeded_enc.deinit();
    var recovered_again = try random_kp.secret_key.decapsulate(seeded_enc.ciphertext);
    defer recovered_again.deinit();
    try expectSameBytes("seeded encaps to a random key", seeded_enc.shared_secret.bytes, recovered_again.bytes);
}

test "the seeded calls leave the caller's seed unchanged" {
    var kem = try oqs.Kem.init(a, "ML-KEM-512");
    defer kem.deinit();
    const key_seed = keySeed();
    var key_copy = key_seed;
    const kp = try kem.keypairFromSeed(&key_copy);
    defer a.free(kp.public_key);
    defer {
        std.crypto.secureZero(u8, kp.secret_key);
        a.free(kp.secret_key);
    }
    try expectSameBytes("key seed", &key_seed, &key_copy);

    const enc_seed = encapsSeed();
    var enc_copy = enc_seed;
    const enc = try kem.encapsFromSeed(kp.public_key, &enc_copy);
    defer a.free(enc.ciphertext);
    defer {
        std.crypto.secureZero(u8, enc.shared_secret);
        a.free(enc.shared_secret);
    }
    try expectSameBytes("encaps seed", &enc_seed, &enc_copy);
}

// --- Errors ------------------------------------------------------------------

const wrong_key_seed_lengths = [_]usize{ 0, 1, 32, 63, 65, 128 };
const wrong_enc_seed_lengths = [_]usize{ 0, 1, 16, 31, 33, 64 };

test "a seed of the wrong length gives InvalidKeySize from the core and the typed layer" {
    var buffer: [128]u8 = @splat(7);
    const seed_names = [_][:0]const u8{ "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };
    for (seed_names) |name| {
        var kem = try oqs.Kem.init(a, name);
        defer kem.deinit();
        const pk = try a.alloc(u8, kem.lengthPublicKey());
        defer a.free(pk);
        @memset(pk, 0);
        for (wrong_key_seed_lengths) |len| {
            try std.testing.expectError(oqs.OqsError.InvalidKeySize, kem.keypairFromSeed(buffer[0..len]));
        }
        for (wrong_enc_seed_lengths) |len| {
            try std.testing.expectError(oqs.OqsError.InvalidKeySize, kem.encapsFromSeed(pk, buffer[0..len]));
        }
    }

    // The typed layer, on one level.
    const T = oqs.kem.MlKem512;
    for (wrong_key_seed_lengths) |len| {
        try std.testing.expectError(oqs.OqsError.InvalidKeySize, T.generateKeyPairFromSeed(a, buffer[0..len]));
    }
    var kp = try T.generateKeyPairFromSeed(a, &keySeed());
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    for (wrong_enc_seed_lengths) |len| {
        try std.testing.expectError(oqs.OqsError.InvalidKeySize, kp.public_key.encapsulateWithSeed(buffer[0..len]));
    }
}

test "a public key of the wrong length on seeded encapsulation gives InvalidKeySize from the core and the typed layer" {
    var kem = try oqs.Kem.init(a, "ML-KEM-768");
    defer kem.deinit();
    const long = try a.alloc(u8, kem.lengthPublicKey() + 1);
    defer a.free(long);
    @memset(long, 0);
    const seed = encapsSeed();
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, kem.encapsFromSeed(long[0..0], &seed));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, kem.encapsFromSeed(long[0 .. long.len - 2], &seed));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, kem.encapsFromSeed(long, &seed));

    // A typed key can only hold a wrong length when built by hand.
    const typed_pk = oqs.kem.MlKem768.PublicKey{ .allocator = a, .bytes = long };
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, typed_pk.encapsulateWithSeed(&seed));
}

test "a wrong seed together with a wrong public key length gives InvalidKeySize and a mechanism without seeds gives SeedNotSupported first" {
    var supported = try oqs.Kem.init(a, "ML-KEM-512");
    defer supported.deinit();
    const wrong_pk: [3]u8 = @splat(0);
    const wrong_seed: [5]u8 = @splat(0);
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, supported.encapsFromSeed(&wrong_pk, &wrong_seed));

    // The support check comes before every length check, as in the Rust port.
    var unsupported = try oqs.Kem.init(a, "Kyber512");
    defer unsupported.deinit();
    try std.testing.expectError(oqs.OqsError.SeedNotSupported, unsupported.keypairFromSeed(&wrong_seed));
    try std.testing.expectError(oqs.OqsError.SeedNotSupported, unsupported.encapsFromSeed(&wrong_pk, &wrong_seed));
    try std.testing.expectError(oqs.OqsError.SeedNotSupported, unsupported.keypairFromSeed(&keySeed()));
    try std.testing.expectError(oqs.OqsError.SeedNotSupported, unsupported.encapsFromSeed(&wrong_pk, &encapsSeed()));
}

// Counts the calls that reach the liboqs derand functions, and records what
// they were given. A call that the wrapper refuses must not reach them.
const DerandRecorder = struct {
    var keypair_calls: usize = 0;
    var encaps_calls: usize = 0;
    var seed_pointer: ?[*c]const u8 = null;
    var public_key_pointer: ?[*c]const u8 = null;
    var status: c.OQS_STATUS = c.OQS_SUCCESS;

    fn reset(next_status: c.OQS_STATUS) void {
        keypair_calls = 0;
        encaps_calls = 0;
        seed_pointer = null;
        public_key_pointer = null;
        status = next_status;
    }

    fn keypair(public_key: [*c]u8, secret_key: [*c]u8, seed: [*c]const u8) callconv(.c) c.OQS_STATUS {
        keypair_calls += 1;
        seed_pointer = seed;
        public_key[0] = 0x5A;
        secret_key[0] = 0x5A;
        return status;
    }

    fn encaps(ciphertext: [*c]u8, shared_secret: [*c]u8, public_key: [*c]const u8, seed: [*c]const u8) callconv(.c) c.OQS_STATUS {
        encaps_calls += 1;
        seed_pointer = seed;
        public_key_pointer = public_key;
        ciphertext[0] = 0x5A;
        shared_secret[0] = 0x5A;
        return status;
    }

    fn install(kem: *oqs.Kem, next_status: c.OQS_STATUS) void {
        kem.handle.keypair_derand = keypair;
        kem.handle.encaps_derand = encaps;
        reset(next_status);
    }
};

test "a mechanism without seeds returns SeedNotSupported from both seeded calls without calling liboqs" {
    const seed_key = keySeed();
    const seed_enc = encapsSeed();
    const pk: [1]u8 = .{0};
    var names = oqs.Registry.kemNames();
    var checked: usize = 0;
    while (names.next()) |name| {
        if (std.mem.startsWith(u8, name, "ML-KEM-")) continue;
        var kem = try oqs.Kem.init(a, name);
        defer kem.deinit();
        DerandRecorder.install(&kem, c.OQS_SUCCESS);
        // A correct-looking seed, a wrong one and an empty one all give the same error.
        try std.testing.expectError(oqs.OqsError.SeedNotSupported, kem.keypairFromSeed(&seed_key));
        try std.testing.expectError(oqs.OqsError.SeedNotSupported, kem.keypairFromSeed(&.{}));
        try std.testing.expectError(oqs.OqsError.SeedNotSupported, kem.encapsFromSeed(&pk, &seed_enc));
        try std.testing.expectError(oqs.OqsError.SeedNotSupported, kem.encapsFromSeed(&.{}, &.{}));
        if (DerandRecorder.keypair_calls != 0 or DerandRecorder.encaps_calls != 0) {
            std.debug.print("{s}: a refused seeded call reached liboqs\n", .{name});
            return error.TestUnexpectedResult;
        }
        checked += 1;
    }
    try std.testing.expectEqual(@as(usize, 38), checked);
}

test "a typed algorithm without seeds returns SeedNotSupported from both seeded calls" {
    const seed_key = keySeed();
    const seed_enc = encapsSeed();
    var small: [4]u8 = @splat(0);
    var checked: usize = 0;
    inline for (@typeInfo(oqs.kem).@"struct".decl_names) |decl| {
        const T = @field(oqs.kem, decl);
        if (comptime !std.mem.startsWith(u8, T.algorithm_name, "ML-KEM-")) {
            try std.testing.expectError(oqs.OqsError.SeedNotSupported, T.generateKeyPairFromSeed(a, &seed_key));
            try std.testing.expectError(oqs.OqsError.SeedNotSupported, T.generateKeyPairFromSeed(a, &.{}));
            // A hand-built key with a short buffer, so no large key is allocated.
            const pk = T.PublicKey{ .allocator = a, .bytes = &small };
            try std.testing.expectError(oqs.OqsError.SeedNotSupported, pk.encapsulateWithSeed(&seed_enc));
            try std.testing.expectError(oqs.OqsError.SeedNotSupported, pk.encapsulateWithSeed(&.{}));
            checked += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 38), checked);
}

test "the seeded calls hand the caller's seed and key to liboqs unchanged and a refused length never reaches it" {
    var kem = try oqs.Kem.init(a, "ML-KEM-512");
    defer kem.deinit();
    DerandRecorder.install(&kem, c.OQS_SUCCESS);
    const key_seed = keySeed();
    const kp = try kem.keypairFromSeed(&key_seed);
    defer a.free(kp.public_key);
    defer {
        std.crypto.secureZero(u8, kp.secret_key);
        a.free(kp.secret_key);
    }
    try std.testing.expectEqual(@as(usize, 1), DerandRecorder.keypair_calls);
    // The very same memory, so the wrapper made no copy of the seed.
    try std.testing.expectEqual(@intFromPtr(&key_seed), @intFromPtr(DerandRecorder.seed_pointer.?));

    const enc_seed = encapsSeed();
    const enc = try kem.encapsFromSeed(kp.public_key, &enc_seed);
    defer a.free(enc.ciphertext);
    defer {
        std.crypto.secureZero(u8, enc.shared_secret);
        a.free(enc.shared_secret);
    }
    try std.testing.expectEqual(@as(usize, 1), DerandRecorder.encaps_calls);
    try std.testing.expectEqual(@intFromPtr(&enc_seed), @intFromPtr(DerandRecorder.seed_pointer.?));
    try std.testing.expectEqual(@intFromPtr(kp.public_key.ptr), @intFromPtr(DerandRecorder.public_key_pointer.?));

    // Refused calls leave both counters where they were.
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, kem.keypairFromSeed(key_seed[1..]));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, kem.encapsFromSeed(kp.public_key, enc_seed[1..]));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, kem.encapsFromSeed(kp.public_key[1..], &enc_seed));
    try std.testing.expectEqual(@as(usize, 1), DerandRecorder.keypair_calls);
    try std.testing.expectEqual(@as(usize, 1), DerandRecorder.encaps_calls);
}

// An allocator that checks every freed block of a given length and records
// whether it was all zero at the moment it reached the allocator. Everything
// else goes to the child allocator.
const WipeRecorder = struct {
    child: std.mem.Allocator,
    watched_len: usize,
    watched_frees: usize = 0,
    all_zero: bool = true,

    fn allocator(self: *WipeRecorder) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *WipeRecorder = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *WipeRecorder = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *WipeRecorder = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(memory, alignment, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *WipeRecorder = @ptrCast(@alignCast(ctx));
        if (memory.len == self.watched_len) {
            self.watched_frees += 1;
            for (memory) |byte| {
                if (byte != 0) self.all_zero = false;
            }
        }
        self.child.rawFree(memory, alignment, ret_addr);
    }
};

test "a liboqs error status gives KeyGenerationFailed and EncapsulationFailed and the secret buffers are zero when they are freed" {
    // The secret key of ML-KEM-512 is 1632 bytes and no other buffer has that length.
    var key_recorder = WipeRecorder{ .child = a, .watched_len = 1632 };
    {
        var kem = try oqs.Kem.init(key_recorder.allocator(), "ML-KEM-512");
        defer kem.deinit();
        DerandRecorder.install(&kem, c.OQS_ERROR);
        try std.testing.expectError(oqs.OqsError.KeyGenerationFailed, kem.keypairFromSeed(&keySeed()));
        try std.testing.expectEqual(@as(usize, 1), DerandRecorder.keypair_calls);
    }
    try std.testing.expectEqual(@as(usize, 1), key_recorder.watched_frees);
    try std.testing.expect(key_recorder.all_zero);

    // The shared secret is 32 bytes and no other buffer here has that length.
    var secret_recorder = WipeRecorder{ .child = a, .watched_len = 32 };
    {
        var kem = try oqs.Kem.init(secret_recorder.allocator(), "ML-KEM-512");
        defer kem.deinit();
        DerandRecorder.install(&kem, c.OQS_ERROR);
        const pk: [800]u8 = @splat(0);
        try std.testing.expectError(oqs.OqsError.EncapsulationFailed, kem.encapsFromSeed(&pk, &encapsSeed()));
        try std.testing.expectEqual(@as(usize, 1), DerandRecorder.encaps_calls);
    }
    try std.testing.expectEqual(@as(usize, 1), secret_recorder.watched_frees);
    try std.testing.expect(secret_recorder.all_zero);
}

// --- Fuzz ---------------------------------------------------------------------

// The seed comes from build.zig (default 0x5717f022, override with
// -Dfuzz-seed=N). The test prints it at the start of a run and again in every
// failure message, so a failure can be run again with the same seed.
// The round count keeps a Debug run to a few seconds.
const fuzz_rounds = 48;

test "fuzz with a seed from the build: seeded keys and encapsulations always agree with raw C and decapsulate, mutated ciphertexts never give the same secret, and wrong seed lengths always give InvalidKeySize" {
    const seed: u64 = build_options.fuzz_seed;
    std.debug.print("fuzz seed 0x{x}\n", .{seed});
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    var kem = try oqs.Kem.init(a, "ML-KEM-512");
    defer kem.deinit();
    const raw_kem = c.OQS_KEM_new("ML-KEM-512") orelse return error.AlgorithmNotAvailable;
    defer c.OQS_KEM_free(raw_kem);

    var previous_seed: [64]u8 = @splat(0);
    var previous_public_key: ?[]u8 = null;
    defer if (previous_public_key) |pk| a.free(pk);

    for (0..fuzz_rounds) |round| {
        var key_seed: [64]u8 = undefined;
        var enc_seed: [32]u8 = undefined;
        random.bytes(&key_seed);
        random.bytes(&enc_seed);
        defer std.crypto.secureZero(u8, &key_seed);
        defer std.crypto.secureZero(u8, &enc_seed);

        // No false negatives: every seed of the right length is accepted and
        // the pair agrees with raw C and with the typed layer.
        const raw = try rawSeeded("ML-KEM-512", &key_seed, &enc_seed);
        defer raw.deinit();
        const core = try coreSeeded("ML-KEM-512", &key_seed, &enc_seed);
        defer core.deinit();
        const typed = try typedSeeded(oqs.kem.MlKem512, &key_seed, &enc_seed);
        defer typed.deinit();
        expectSameOutput("core against raw C", raw, core) catch |err| {
            std.debug.print("round {d}: core differs from raw C (seed 0x{x})\n", .{ round, seed });
            return err;
        };
        expectSameOutput("typed against raw C", raw, typed) catch |err| {
            std.debug.print("round {d}: typed differs from raw C (seed 0x{x})\n", .{ round, seed });
            return err;
        };

        // The seeded ciphertext decapsulates to the seeded secret.
        const ss = try kem.decaps(core.ciphertext, core.secret_key);
        defer {
            std.crypto.secureZero(u8, ss);
            a.free(ss);
        }
        if (!std.mem.eql(u8, ss, core.shared_secret)) {
            std.debug.print("round {d}: decapsulation gave another secret (seed 0x{x})\n", .{ round, seed });
            return error.TestUnexpectedResult;
        }

        // No false positives: a flipped ciphertext bit gives another secret,
        // because decapsulation rejects implicitly with a different key.
        const mutated = try a.dupe(u8, core.ciphertext);
        defer a.free(mutated);
        mutated[random.uintLessThan(usize, mutated.len)] ^= @as(u8, 1) << random.int(u3);
        const bad_ss = try kem.decaps(mutated, core.secret_key);
        defer {
            std.crypto.secureZero(u8, bad_ss);
            a.free(bad_ss);
        }
        if (std.mem.eql(u8, bad_ss, core.shared_secret)) {
            std.debug.print("round {d}: a mutated ciphertext gave the same secret (seed 0x{x})\n", .{ round, seed });
            return error.TestUnexpectedResult;
        }

        // A different seed gives a different public key.
        if (previous_public_key) |pk| {
            if (!std.mem.eql(u8, &previous_seed, &key_seed) and std.mem.eql(u8, pk, core.public_key)) {
                std.debug.print("round {d}: two seeds gave one public key (seed 0x{x})\n", .{ round, seed });
                return error.TestUnexpectedResult;
            }
            a.free(pk);
        }
        previous_public_key = try a.dupe(u8, core.public_key);
        previous_seed = key_seed;

        // Wrong seed lengths always give InvalidKeySize. The first rounds take
        // the edge lengths 63, 65, 31 and 33 and the rest are random.
        var buffer: [200]u8 = @splat(0);
        const key_len: usize = switch (round) {
            0 => 63,
            1 => 65,
            else => wrongLength(random, 64),
        };
        const enc_len: usize = switch (round) {
            0 => 31,
            1 => 33,
            else => wrongLength(random, 32),
        };
        random.bytes(&buffer);
        try std.testing.expectError(oqs.OqsError.InvalidKeySize, kem.keypairFromSeed(buffer[0..key_len]));
        try std.testing.expectError(oqs.OqsError.InvalidKeySize, kem.encapsFromSeed(core.public_key, buffer[0..enc_len]));
        try std.testing.expectError(oqs.OqsError.InvalidKeySize, oqs.kem.MlKem512.generateKeyPairFromSeed(a, buffer[0..key_len]));
        const typed_pk = oqs.kem.MlKem512.PublicKey{ .allocator = a, .bytes = core.public_key };
        try std.testing.expectError(oqs.OqsError.InvalidKeySize, typed_pk.encapsulateWithSeed(buffer[0..enc_len]));
        std.crypto.secureZero(u8, &buffer);
    }
}

// A random length in 0 to 199 that is not `right`.
fn wrongLength(random: std.Random, right: usize) usize {
    while (true) {
        const len = random.uintLessThan(usize, 200);
        if (len != right) return len;
    }
}
