//! Tests for signing and verifying with a context string, through the runtime
//! core `oqs.Sig` and the typed `oqs.sig.*` wrappers.
//!
//! The known-answer tests seed the NIST-KAT RNG and compare the wrapper output
//! with the raw C API under the same seed, so this module has its own binary.
//! Which algorithms take a context, and the digest of one signature, are
//! written out by hand. Test output never includes secret key bytes.
const std = @import("std");
const oqs = @import("oqs");
const c = @import("c_api");
const build_options = @import("build_options");

const message = "the quick brown fox";
const a = std.testing.allocator;

fn seedKat() void {
    var e: [48]u8 = undefined;
    for (&e, 0..) |*b, i| b.* = @intCast(i);
    oqs.testing.seedKat(&e);
}

// --- Which algorithms take a context ----------------------------------------

test "ML-DSA and SLH-DSA take a context and Falcon, MAYO, CROSS, UOV, SNOVA and MQOM do not, as written out by hand" {
    const cases = [_]struct { name: [:0]const u8, supports: bool }{
        .{ .name = "ML-DSA-44", .supports = true },
        .{ .name = "ML-DSA-65", .supports = true },
        .{ .name = "ML-DSA-87", .supports = true },
        .{ .name = "SLH_DSA_PURE_SHA2_128F", .supports = true },
        .{ .name = "SLH_DSA_PURE_SHAKE_256S", .supports = true },
        .{ .name = "SLH_DSA_SHA2_256_PREHASH_SHA2_128F", .supports = true },
        .{ .name = "SLH_DSA_SHAKE_256_PREHASH_SHAKE_256S", .supports = true },
        .{ .name = "Falcon-512", .supports = false },
        .{ .name = "Falcon-padded-1024", .supports = false },
        .{ .name = "MAYO-1", .supports = false },
        .{ .name = "cross-rsdp-128-fast", .supports = false },
        .{ .name = "OV-Is", .supports = false },
        .{ .name = "SNOVA_24_5_4", .supports = false },
        .{ .name = "mqom2_cat1_gf16_fast_r3", .supports = false },
    };
    for (cases) |case| {
        var sig = try oqs.Sig.init(a, case.name);
        defer sig.deinit();
        if (sig.supportsContext() != case.supports) {
            std.debug.print("{s}: supportsContext is {}, expected {}\n", .{ case.name, sig.supportsContext(), case.supports });
            return error.TestUnexpectedResult;
        }
        try std.testing.expectEqual(case.supports, oqs.Registry.sigDescription(case.name).?.supportsContext);
    }
}

test "159 of the 221 enabled signature schemes take a context: 3 ML-DSA and 156 SLH-DSA" {
    var names = oqs.Registry.sigNames();
    var supporting: usize = 0;
    var total: usize = 0;
    while (names.next()) |name| {
        total += 1;
        var sig = try oqs.Sig.init(a, name);
        defer sig.deinit();
        const is_family = std.mem.startsWith(u8, name, "ML-DSA-") or std.mem.startsWith(u8, name, "SLH_DSA_");
        if (sig.supportsContext() != is_family) {
            std.debug.print("{s}: supportsContext is {}\n", .{ name, sig.supportsContext() });
            return error.TestUnexpectedResult;
        }
        if (sig.supportsContext()) supporting += 1;
    }
    try std.testing.expectEqual(@as(usize, 221), total);
    try std.testing.expectEqual(@as(usize, 159), supporting);
}

// --- Agreement with the raw C API under the KAT seed ------------------------

const RawContext = union(enum) {
    // OQS_SIG_sign, with no context argument.
    plain,
    // OQS_SIG_sign_with_ctx_str with a null pointer and length 0.
    null_context,
    // OQS_SIG_sign_with_ctx_str with these bytes.
    bytes: []const u8,
};

const RawOutput = struct {
    public_key: []u8,
    secret_key: []u8,
    signature: []u8,

    fn deinit(self: RawOutput) void {
        a.free(self.public_key);
        std.crypto.secureZero(u8, self.secret_key);
        a.free(self.secret_key);
        a.free(self.signature);
    }
};

// One keygen and one sign through the raw C API, each after a fresh KAT seed.
fn rawKatSign(name: [:0]const u8, context: RawContext) !RawOutput {
    const s = c.OQS_SIG_new(name.ptr) orelse return error.AlgorithmNotAvailable;
    defer c.OQS_SIG_free(s);
    const pk = try a.alloc(u8, s.*.length_public_key);
    errdefer a.free(pk);
    const sk = try a.alloc(u8, s.*.length_secret_key);
    errdefer a.free(sk);
    const buf = try a.alloc(u8, s.*.length_signature);
    defer a.free(buf);
    seedKat();
    try std.testing.expectEqual(c.OQS_SUCCESS, c.OQS_SIG_keypair(s, pk.ptr, sk.ptr));
    seedKat();
    var len: usize = 0;
    const status = switch (context) {
        .plain => c.OQS_SIG_sign(s, buf.ptr, &len, message.ptr, message.len, sk.ptr),
        .null_context => c.OQS_SIG_sign_with_ctx_str(s, buf.ptr, &len, message.ptr, message.len, null, 0, sk.ptr),
        .bytes => |ctx| c.OQS_SIG_sign_with_ctx_str(s, buf.ptr, &len, message.ptr, message.len, ctx.ptr, ctx.len, sk.ptr),
    };
    try std.testing.expectEqual(c.OQS_SUCCESS, status);
    return .{ .public_key = pk, .secret_key = sk, .signature = try a.dupe(u8, buf[0..len]) };
}

// Keygen and signWithContext through the core, each after a fresh KAT seed.
fn coreKatSign(name: [:0]const u8, context: []const u8) !RawOutput {
    var sig = try oqs.Sig.init(a, name);
    defer sig.deinit();
    seedKat();
    const kp = try sig.keypair();
    errdefer a.free(kp.public_key);
    errdefer a.free(kp.secret_key);
    seedKat();
    const signature = try sig.signWithContext(message, context, kp.secret_key);
    return .{ .public_key = kp.public_key, .secret_key = kp.secret_key, .signature = signature };
}

// Keygen and signWithContext through the typed wrapper, each after a fresh KAT seed.
fn typedKatSign(comptime T: type, context: []const u8) !RawOutput {
    seedKat();
    var kp = try T.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    seedKat();
    var s = try kp.secret_key.signWithContext(message, context);
    defer s.deinit();
    return .{
        .public_key = try a.dupe(u8, kp.public_key.bytes),
        // Only the public key and signature are compared, so no secret is copied.
        .secret_key = try a.alloc(u8, 0),
        .signature = try a.dupe(u8, s.bytes),
    };
}

fn expectSamePublicOutput(expected: RawOutput, actual: RawOutput) !void {
    try std.testing.expectEqualSlices(u8, expected.public_key, actual.public_key);
    try std.testing.expectEqualSlices(u8, expected.signature, actual.signature);
}

fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

test "ML-DSA-44 core and typed signatures under the KAT seed with context ctx equal the raw C output and its hand-written digest" {
    const raw = try rawKatSign("ML-DSA-44", .{ .bytes = "ctx" });
    defer raw.deinit();
    // sha256 of the 2420-byte raw C signature, recorded from liboqs 0.16.0.
    try std.testing.expectEqual(@as(usize, 2420), raw.signature.len);
    try std.testing.expectEqualStrings("376684a48ca2d3afdb53aeaddb8f6be2dcdc2764a6de423bc8caab49b26d3a4a", &sha256Hex(raw.signature));

    const core = try coreKatSign("ML-DSA-44", "ctx");
    defer core.deinit();
    try expectSamePublicOutput(raw, core);
    try std.testing.expectEqualSlices(u8, raw.secret_key, core.secret_key);

    const typed = try typedKatSign(oqs.sig.MlDsa44, "ctx");
    defer typed.deinit();
    try expectSamePublicOutput(raw, typed);
}

test "SLH_DSA_PURE_SHA2_128F core and typed signatures under the KAT seed with context ctx equal the raw C output" {
    const raw = try rawKatSign("SLH_DSA_PURE_SHA2_128F", .{ .bytes = "ctx" });
    defer raw.deinit();
    try std.testing.expectEqual(@as(usize, 17088), raw.signature.len);

    const core = try coreKatSign("SLH_DSA_PURE_SHA2_128F", "ctx");
    defer core.deinit();
    try expectSamePublicOutput(raw, core);

    const typed = try typedKatSign(oqs.sig.SlhDsaPureSha2128f, "ctx");
    defer typed.deinit();
    try expectSamePublicOutput(raw, typed);
}

test "Falcon-512 core and typed signatures with an empty context under the KAT seed equal the raw C plain and null-context signatures" {
    const plain = try rawKatSign("Falcon-512", .plain);
    defer plain.deinit();
    const null_context = try rawKatSign("Falcon-512", .null_context);
    defer null_context.deinit();
    try expectSamePublicOutput(plain, null_context);

    const core = try coreKatSign("Falcon-512", "");
    defer core.deinit();
    try expectSamePublicOutput(plain, core);

    const typed = try typedKatSign(oqs.sig.Falcon512, "");
    defer typed.deinit();
    try expectSamePublicOutput(plain, typed);
}

test "ML-DSA-44 signatures with an empty context and with no context are byte-identical under the KAT seed, as in liboqs" {
    const raw_plain = try rawKatSign("ML-DSA-44", .plain);
    defer raw_plain.deinit();
    const raw_empty = try rawKatSign("ML-DSA-44", .null_context);
    defer raw_empty.deinit();
    try expectSamePublicOutput(raw_plain, raw_empty);

    const core = try coreKatSign("ML-DSA-44", "");
    defer core.deinit();
    try expectSamePublicOutput(raw_plain, core);

    // The context changes the signature, so the compare above can fail.
    const raw_ctx = try rawKatSign("ML-DSA-44", .{ .bytes = "ctx" });
    defer raw_ctx.deinit();
    try std.testing.expect(!std.mem.eql(u8, raw_plain.signature, raw_ctx.signature));
}

// --- Behaviour through the core ---------------------------------------------

const Pair = struct {
    sig: oqs.Sig,
    public_key: []u8,
    secret_key: []u8,

    fn init(name: [:0]const u8) !Pair {
        var sig = try oqs.Sig.init(a, name);
        errdefer sig.deinit();
        const kp = try sig.keypair();
        return .{ .sig = sig, .public_key = kp.public_key, .secret_key = kp.secret_key };
    }

    fn deinit(self: *Pair) void {
        a.free(self.public_key);
        std.crypto.secureZero(u8, self.secret_key);
        a.free(self.secret_key);
        self.sig.deinit();
    }
};

test "ML-DSA-44 core: an empty-context signature passes plain verify and a plain signature passes empty-context verify" {
    var p = try Pair.init("ML-DSA-44");
    defer p.deinit();
    const with_empty = try p.sig.signWithContext(message, "", p.secret_key);
    defer a.free(with_empty);
    const plain = try p.sig.sign(message, p.secret_key);
    defer a.free(plain);
    try std.testing.expect(try p.sig.verify(message, with_empty, p.public_key));
    try std.testing.expect(try p.sig.verifyWithContext(message, plain, "", p.public_key));
    try std.testing.expect(try p.sig.verifyWithContext(message, with_empty, "", p.public_key));
}

test "ML-DSA-44 core: a context signature fails under another context, an empty context and plain verify" {
    var p = try Pair.init("ML-DSA-44");
    defer p.deinit();
    const s = try p.sig.signWithContext(message, "ctx", p.secret_key);
    defer a.free(s);
    try std.testing.expect(try p.sig.verifyWithContext(message, s, "ctx", p.public_key));
    try std.testing.expect(!try p.sig.verifyWithContext(message, s, "ctX", p.public_key));
    try std.testing.expect(!try p.sig.verifyWithContext(message, s, "ct", p.public_key));
    try std.testing.expect(!try p.sig.verifyWithContext(message, s, "", p.public_key));
    try std.testing.expect(!try p.sig.verify(message, s, p.public_key));
    try std.testing.expect(!try p.sig.verifyWithContext("the quick brown fax", s, "ctx", p.public_key));

    const plain = try p.sig.sign(message, p.secret_key);
    defer a.free(plain);
    try std.testing.expect(!try p.sig.verifyWithContext(message, plain, "ctx", p.public_key));
}

test "ML-DSA-44 core: a 255-byte context signs and verifies, and a 256-byte one gives ContextTooLong on sign and false on verify" {
    var p = try Pair.init("ML-DSA-44");
    defer p.deinit();
    var long: [256]u8 = undefined;
    for (&long, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    const s = try p.sig.signWithContext(message, long[0..255], p.secret_key);
    defer a.free(s);
    try std.testing.expect(try p.sig.verifyWithContext(message, s, long[0..255], p.public_key));
    try std.testing.expectError(oqs.OqsError.ContextTooLong, p.sig.signWithContext(message, &long, p.secret_key));
    try std.testing.expect(!try p.sig.verifyWithContext(message, s, &long, p.public_key));
}

test "SLH_DSA_PURE_SHA2_128F core: a context signature verifies only under its context, and 256 bytes gives ContextTooLong" {
    var p = try Pair.init("SLH_DSA_PURE_SHA2_128F");
    defer p.deinit();
    const s = try p.sig.signWithContext(message, "ctx", p.secret_key);
    defer a.free(s);
    try std.testing.expect(try p.sig.verifyWithContext(message, s, "ctx", p.public_key));
    try std.testing.expect(!try p.sig.verifyWithContext(message, s, "cty", p.public_key));
    try std.testing.expect(!try p.sig.verify(message, s, p.public_key));
    const long: [256]u8 = @splat(0x41);
    try std.testing.expectError(oqs.OqsError.ContextTooLong, p.sig.signWithContext(message, &long, p.secret_key));
}

test "Falcon-512 and MAYO-1 core: a non-empty context gives ContextNotSupported on sign and false on verify" {
    for ([_][:0]const u8{ "Falcon-512", "MAYO-1" }) |name| {
        var p = try Pair.init(name);
        defer p.deinit();
        try std.testing.expectError(oqs.OqsError.ContextNotSupported, p.sig.signWithContext(message, "c", p.secret_key));
        const s = try p.sig.sign(message, p.secret_key);
        defer a.free(s);
        try std.testing.expect(!try p.sig.verifyWithContext(message, s, "c", p.public_key));
    }
}

test "Falcon-512 and MAYO-1 core: an empty context signs, and the signature passes plain and empty-context verify" {
    for ([_][:0]const u8{ "Falcon-512", "MAYO-1" }) |name| {
        var p = try Pair.init(name);
        defer p.deinit();
        const s = try p.sig.signWithContext(message, "", p.secret_key);
        defer a.free(s);
        try std.testing.expect(try p.sig.verify(message, s, p.public_key));
        try std.testing.expect(try p.sig.verifyWithContext(message, s, "", p.public_key));
        try std.testing.expect(!try p.sig.verifyWithContext("tampered", s, "", p.public_key));
    }
}

test "core sign checks context support, then the secret key length, then the context length, as the Rust port does" {
    var falcon = try Pair.init("Falcon-512");
    defer falcon.deinit();
    const long: [256]u8 = @splat(0x41);
    // No support wins over a context that is too long and over a short key.
    try std.testing.expectError(oqs.OqsError.ContextNotSupported, falcon.sig.signWithContext(message, &long, falcon.secret_key));
    try std.testing.expectError(oqs.OqsError.ContextNotSupported, falcon.sig.signWithContext(message, "c", falcon.secret_key[1..]));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, falcon.sig.signWithContext(message, "", falcon.secret_key[1..]));

    var mldsa = try Pair.init("ML-DSA-44");
    defer mldsa.deinit();
    // The key length is checked before the context length.
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, mldsa.sig.signWithContext(message, &long, mldsa.secret_key[1..]));
}

test "core signWithContext and verifyWithContext return InvalidKeySize for keys of the wrong length" {
    var p = try Pair.init("ML-DSA-44");
    defer p.deinit();
    const s = try p.sig.signWithContext(message, "ctx", p.secret_key);
    defer a.free(s);
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, p.sig.signWithContext(message, "ctx", p.secret_key[1..]));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, p.sig.signWithContext(message, "ctx", p.public_key));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, p.sig.verifyWithContext(message, s, "ctx", p.public_key[1..]));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, p.sig.verifyWithContext(message, s, "ctx", p.secret_key));
}

test "core signWithContext returns OutOfMemory at either allocation and leaks nothing" {
    var p = try Pair.init("ML-DSA-44");
    defer p.deinit();
    for ([_]usize{ 0, 1 }) |fail_index| {
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = fail_index });
        var sig = try oqs.Sig.init(failing.allocator(), "ML-DSA-44");
        defer sig.deinit();
        try std.testing.expectError(oqs.OqsError.OutOfMemory, sig.signWithContext(message, "ctx", p.secret_key));
    }
}

// --- Behaviour through the typed wrappers -----------------------------------

test "typed MlDsa44: a context signature verifies only under its context, and an empty context equals no context" {
    var kp = try oqs.sig.MlDsa44.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var s = try kp.secret_key.signWithContext(message, "ctx");
    defer s.deinit();
    try std.testing.expect(try kp.public_key.isValidSignatureWithContext(message, s.bytes, "ctx"));
    try std.testing.expect(!try kp.public_key.isValidSignatureWithContext(message, s.bytes, "cty"));
    try std.testing.expect(!try kp.public_key.isValidSignatureWithContext(message, s.bytes, ""));
    try std.testing.expect(!try kp.public_key.isValidSignature(message, s.bytes));
    try std.testing.expect(!try kp.public_key.isValidSignatureWithContext("tampered", s.bytes, "ctx"));

    var empty = try kp.secret_key.signWithContext(message, "");
    defer empty.deinit();
    try std.testing.expect(try kp.public_key.isValidSignature(message, empty.bytes));
    var plain = try kp.secret_key.sign(message);
    defer plain.deinit();
    try std.testing.expect(try kp.public_key.isValidSignatureWithContext(message, plain.bytes, ""));
}

test "typed MlDsa44: a 255-byte context works, and a 256-byte one gives ContextTooLong on sign and false on verify" {
    var kp = try oqs.sig.MlDsa44.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    const long: [256]u8 = @splat(0x7E);
    var s = try kp.secret_key.signWithContext(message, long[0..255]);
    defer s.deinit();
    try std.testing.expect(try kp.public_key.isValidSignatureWithContext(message, s.bytes, long[0..255]));
    try std.testing.expectError(oqs.OqsError.ContextTooLong, kp.secret_key.signWithContext(message, &long));
    try std.testing.expect(!try kp.public_key.isValidSignatureWithContext(message, s.bytes, &long));
}

test "typed Falcon512 and Mayo1: a non-empty context gives ContextNotSupported and false, and an empty one signs and verifies" {
    inline for (.{ oqs.sig.Falcon512, oqs.sig.Mayo1 }) |T| {
        var kp = try T.generateKeyPair(a);
        defer kp.public_key.deinit();
        defer kp.secret_key.deinit();
        try std.testing.expectError(oqs.OqsError.ContextNotSupported, kp.secret_key.signWithContext(message, "c"));
        const long: [256]u8 = @splat(0x41);
        try std.testing.expectError(oqs.OqsError.ContextNotSupported, kp.secret_key.signWithContext(message, &long));
        var s = try kp.secret_key.signWithContext(message, "");
        defer s.deinit();
        try std.testing.expect(try kp.public_key.isValidSignature(message, s.bytes));
        try std.testing.expect(try kp.public_key.isValidSignatureWithContext(message, s.bytes, ""));
        try std.testing.expect(!try kp.public_key.isValidSignatureWithContext(message, s.bytes, "c"));
    }
}

test "typed MlDsa44: keys built with bytes of the wrong length give InvalidKeySize on signWithContext and isValidSignatureWithContext" {
    var short: [16]u8 = @splat(0);
    const sk = oqs.sig.MlDsa44.SecretKey{ .allocator = a, .bytes = &short };
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, sk.signWithContext(message, "ctx"));
    const pk = oqs.sig.MlDsa44.PublicKey{ .allocator = a, .bytes = &short };
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, pk.isValidSignatureWithContext(message, "sig", "ctx"));
}

test "typed MlDsa44: signWithContext returns OutOfMemory at either allocation and leaks nothing" {
    var kp = try oqs.sig.MlDsa44.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    for ([_]usize{ 0, 1 }) |fail_index| {
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = fail_index });
        const sk = oqs.sig.MlDsa44.SecretKey{ .allocator = failing.allocator(), .bytes = kp.secret_key.bytes };
        try std.testing.expectError(oqs.OqsError.OutOfMemory, sk.signWithContext(message, "ctx"));
    }
}

// --- Fuzz ---------------------------------------------------------------------

// The seed comes from build.zig (default 0x5717f022, override with
// -Dfuzz-seed=N). The test prints it at the start of a run and again in every
// failure message, so a failure can be run again with the same seed.
// The round count keeps a Debug run to a few seconds.
const fuzz_rounds = 24;

test "fuzz with a seed from the build: contexts of 0 to 255 bytes verify under the same context, mutated ones never do, and longer ones give ContextTooLong" {
    const seed: u64 = build_options.fuzz_seed;
    std.debug.print("fuzz seed 0x{x}\n", .{seed});
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    var p = try Pair.init("ML-DSA-44");
    defer p.deinit();
    var typed_kp = try oqs.sig.MlDsa44.generateKeyPair(a);
    defer typed_kp.public_key.deinit();
    defer typed_kp.secret_key.deinit();
    var falcon = try Pair.init("Falcon-512");
    defer falcon.deinit();

    var context_buf: [1024]u8 = undefined;
    var mutated_buf: [1025]u8 = undefined;
    var message_buf: [65]u8 = undefined;

    for (0..fuzz_rounds) |round| {
        // The first rounds take the two edge lengths, the rest are random.
        const context_len: usize = switch (round) {
            0 => 0,
            1 => 255,
            else => random.uintAtMost(usize, 255),
        };
        const context = context_buf[0..context_len];
        random.bytes(context);
        const message_len = random.uintAtMost(usize, 64);
        const msg = message_buf[0..message_len];
        random.bytes(msg);

        // Even rounds sign through the core, odd rounds through the typed key.
        const use_typed = round % 2 == 1;
        const signature = if (use_typed) blk: {
            var s = try typed_kp.secret_key.signWithContext(msg, context);
            defer s.deinit();
            break :blk try a.dupe(u8, s.bytes);
        } else try p.sig.signWithContext(msg, context, p.secret_key);
        defer a.free(signature);
        const public_key = if (use_typed) typed_kp.public_key.bytes else p.public_key;

        // No false negatives: the same context always verifies, on both layers.
        const core_ok = try p.sig.verifyWithContext(msg, signature, context, public_key);
        const typed_pk = oqs.sig.MlDsa44.PublicKey{ .allocator = a, .bytes = public_key };
        const typed_ok = try typed_pk.isValidSignatureWithContext(msg, signature, context);
        if (!core_ok or !typed_ok) {
            std.debug.print("round {d}: context of {d} bytes was rejected (core {}, typed {}, seed 0x{x})\n", .{ round, context_len, core_ok, typed_ok, seed });
            return error.TestUnexpectedResult;
        }

        // No false positives: a flipped, truncated or extended context fails.
        var mutants: [3]?[]const u8 = .{ null, null, null };
        var flipped: [255]u8 = undefined;
        if (context_len > 0) {
            @memcpy(flipped[0..context_len], context);
            flipped[random.uintLessThan(usize, context_len)] ^= @as(u8, 1) << random.int(u3);
            mutants[0] = flipped[0..context_len];
            mutants[1] = context[0..random.uintLessThan(usize, context_len)];
        }
        @memcpy(mutated_buf[0..context_len], context);
        mutated_buf[context_len] = random.int(u8);
        mutants[2] = mutated_buf[0 .. context_len + 1];
        for (mutants, 0..) |maybe, kind| {
            const bad = maybe orelse continue;
            if (try p.sig.verifyWithContext(msg, signature, bad, public_key) or
                try typed_pk.isValidSignatureWithContext(msg, signature, bad))
            {
                std.debug.print("round {d}: context mutant {d} of {d} bytes was accepted (seed 0x{x})\n", .{ round, kind, bad.len, seed });
                return error.TestUnexpectedResult;
            }
        }

        // A changed message or signature fails under the right context.
        var bad_message: [65]u8 = undefined;
        @memcpy(bad_message[0..message_len], msg);
        bad_message[message_len] = random.int(u8);
        const bad_sig = try a.dupe(u8, signature);
        defer a.free(bad_sig);
        bad_sig[random.uintLessThan(usize, bad_sig.len)] ^= @as(u8, 1) << random.int(u3);
        if (try p.sig.verifyWithContext(bad_message[0 .. message_len + 1], signature, context, public_key) or
            try p.sig.verifyWithContext(msg, bad_sig, context, public_key) or
            try typed_pk.isValidSignatureWithContext(msg, bad_sig, context))
        {
            std.debug.print("round {d}: a changed message or signature was accepted (seed 0x{x})\n", .{ round, seed });
            return error.TestUnexpectedResult;
        }
        if (message_len > 0) {
            var flipped_message: [64]u8 = undefined;
            @memcpy(flipped_message[0..message_len], msg);
            flipped_message[random.uintLessThan(usize, message_len)] ^= 0x80;
            if (try p.sig.verifyWithContext(flipped_message[0..message_len], signature, context, public_key)) {
                std.debug.print("round {d}: a flipped message was accepted (seed 0x{x})\n", .{ round, seed });
                return error.TestUnexpectedResult;
            }
        }

        // Lengths over 255 give ContextTooLong on both layers, and false on
        // verify. The first round takes 256, the shortest length that is too long.
        const too_long_len = if (round == 0) 256 else 256 + random.uintAtMost(usize, context_buf.len - 256);
        const too_long = context_buf[0..too_long_len];
        random.bytes(too_long);
        try std.testing.expectError(oqs.OqsError.ContextTooLong, p.sig.signWithContext(msg, too_long, p.secret_key));
        try std.testing.expectError(oqs.OqsError.ContextTooLong, typed_kp.secret_key.signWithContext(msg, too_long));
        try std.testing.expect(!try p.sig.verifyWithContext(msg, signature, too_long, public_key));

        // Any non-empty context on an algorithm without support is refused.
        const refused = context_buf[0 .. 1 + random.uintLessThan(usize, context_buf.len)];
        try std.testing.expectError(oqs.OqsError.ContextNotSupported, falcon.sig.signWithContext(msg, refused, falcon.secret_key));
    }
}
