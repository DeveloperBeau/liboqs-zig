const std = @import("std");
const c = @import("c.zig").c;
const oqs_init = @import("init.zig");
const OqsError = @import("errors.zig").OqsError;
const SigStflSecretKey = @import("sig_stfl_secret_key.zig").SigStflSecretKey;

/// A stateful hash-based signature algorithm (XMSS, XMSS^MT or LMS), chosen by its liboqs name at run time.
///
/// Each key pair can make a fixed number of signatures. liboqs advances the index
/// inside the secret key state on every signature, so a state must never be copied
/// or restored to an earlier point. A state is not safe to sign with from two
/// threads at once.
pub const SigStfl = struct {
    /// The allocator that owns the public keys and signatures this value returns.
    allocator: std.mem.Allocator,
    /// The liboqs stateful signature object for the chosen algorithm.
    handle: *c.OQS_SIG_STFL,

    /// Creates the algorithm named `name`, or returns `AlgorithmNotAvailable` if this build does not have it.
    pub fn init(allocator: std.mem.Allocator, name: [:0]const u8) OqsError!SigStfl {
        oqs_init.ensure();
        const h = c.OQS_SIG_STFL_new(name.ptr) orelse return OqsError.AlgorithmNotAvailable;
        return .{ .allocator = allocator, .handle = h };
    }

    /// Frees the liboqs algorithm object.
    pub fn deinit(self: *SigStfl) void {
        c.OQS_SIG_STFL_free(self.handle);
        self.* = undefined;
    }

    /// The length of a public key in bytes.
    pub fn lengthPublicKey(self: SigStfl) usize {
        return self.handle.length_public_key;
    }

    /// The length of a serialized secret key in bytes.
    pub fn lengthSecretKey(self: SigStfl) usize {
        return self.handle.length_secret_key;
    }

    /// The length of a signature in bytes, which is the same for every signature of a stateful variant.
    pub fn lengthSignatureMax(self: SigStfl) usize {
        return self.handle.length_signature;
    }

    /// Generates a key pair. The caller owns `public_key` and must `deinit` `secret_key`.
    pub fn keypair(self: SigStfl) OqsError!struct { public_key: []u8, secret_key: SigStflSecretKey } {
        const sk = c.OQS_SIG_STFL_SECRET_KEY_new(self.handle.method_name) orelse
            return OqsError.KeyGenerationFailed;
        errdefer c.OQS_SIG_STFL_SECRET_KEY_free(sk);
        const pk = try self.allocator.alloc(u8, self.lengthPublicKey());
        errdefer self.allocator.free(pk);
        try keypairResult(c.OQS_SIG_STFL_keypair(self.handle, pk.ptr, sk));
        // liboqs refuses to sign until a store callback is set. LMS ignores the
        // callback when the context is null, so the key object is passed as one.
        c.OQS_SIG_STFL_SECRET_KEY_SET_store_cb(sk, keepStateInMemory, sk);
        return .{
            .public_key = pk,
            .secret_key = .{ .handle = sk, .algorithm = self.handle.method_name },
        };
    }

    /// Signs `message` with the next index of `secret_key` and returns an owned signature of exactly the produced length.
    ///
    /// The advanced state stays in memory inside `secret_key`. Nothing is written
    /// to storage. Returns `InvalidKeySize` if `secret_key` belongs to another
    /// algorithm. liboqs decides when a key is used up. As in liboqs, one key
    /// makes `sigsTotal` + 1 signatures, and the last one is made when
    /// `sigsRemaining` is already 0. For XMSS that last signature uses wiped key
    /// material, so it does not verify. After it, the next `sign` returns no
    /// signature. For LMS liboqs reports success with no signature there, and
    /// `sign` returns `KeyExhausted`. For XMSS liboqs reports an error status,
    /// and `sign` returns `SignFailed`. Any error status from liboqs returns
    /// `SignFailed`, even when liboqs wrote a signature into the buffer.
    pub fn sign(self: SigStfl, message: []const u8, secret_key: *SigStflSecretKey) OqsError![]u8 {
        if (!self.owns(secret_key.*)) return OqsError.InvalidKeySize;
        const buf = try self.allocator.alloc(u8, self.lengthSignatureMax());
        defer self.allocator.free(buf);
        // liboqs leaves the length alone when it writes no signature, so it
        // must start at 0.
        var sig_len: usize = 0;
        const status = c.OQS_SIG_STFL_sign(self.handle, buf.ptr, &sig_len, message.ptr, message.len, secret_key.handle);
        const len = try signatureLength(status, sig_len);
        const out = try self.allocator.alloc(u8, len);
        @memcpy(out, buf[0..len]);
        return out;
    }

    /// True if `signature` is a valid signature of `message` under `public_key`.
    ///
    /// liboqs rejects a signature whose length differs from `lengthSignatureMax`.
    pub fn verify(self: SigStfl, message: []const u8, signature: []const u8, public_key: []const u8) OqsError!bool {
        if (public_key.len != self.lengthPublicKey()) return OqsError.InvalidKeySize;
        return c.OQS_SIG_STFL_verify(self.handle, message.ptr, message.len, signature.ptr, signature.len, public_key.ptr) == c.OQS_SUCCESS;
    }

    /// The number of signatures `secret_key` can still make, as liboqs counts it.
    ///
    /// Returns `InvalidKeySize` if `secret_key` belongs to another algorithm or
    /// liboqs cannot read it. After the last signature, liboqs can no longer
    /// read an LMS key, and an XMSS count wraps to the largest u64.
    pub fn sigsRemaining(self: SigStfl, secret_key: SigStflSecretKey) OqsError!u64 {
        if (!self.owns(secret_key)) return OqsError.InvalidKeySize;
        var remaining: c_ulonglong = 0;
        if (c.OQS_SIG_STFL_sigs_remaining(self.handle, &remaining, secret_key.handle) != c.OQS_SUCCESS)
            return OqsError.InvalidKeySize;
        return remaining;
    }

    /// The number of signatures `secret_key` can make over its life, as liboqs counts it.
    ///
    /// Returns `InvalidKeySize` if `secret_key` belongs to another algorithm or
    /// liboqs cannot read it.
    pub fn sigsTotal(self: SigStfl, secret_key: SigStflSecretKey) OqsError!u64 {
        if (!self.owns(secret_key)) return OqsError.InvalidKeySize;
        var total: c_ulonglong = 0;
        if (c.OQS_SIG_STFL_sigs_total(self.handle, &total, secret_key.handle) != c.OQS_SUCCESS)
            return OqsError.InvalidKeySize;
        return total;
    }

    fn owns(self: SigStfl, secret_key: SigStflSecretKey) bool {
        return std.mem.orderZ(u8, self.handle.method_name, secret_key.algorithm) == .eq;
    }
};

// liboqs reports a failed key generation through the status alone.
fn keypairResult(status: c.OQS_STATUS) OqsError!void {
    if (status != c.OQS_SUCCESS) return OqsError.KeyGenerationFailed;
}

// Decides whether a liboqs sign call made a signature, and how long it is.
// An error status means no signature, even with a length. XMSS writes the
// length before it stores the advanced state, so a failed store returns an
// error with a full signature in the buffer. Handing that out would give the
// caller a signature whose state was never stored. A success with no length
// is a used-up LMS key, which writes no signature.
fn signatureLength(status: c.OQS_STATUS, sig_len: usize) OqsError!usize {
    if (status != c.OQS_SUCCESS) return OqsError.SignFailed;
    if (sig_len == 0) return OqsError.KeyExhausted;
    return sig_len;
}

// liboqs hands the advanced state to this callback after each signature and
// zeroes and frees its serialized copy afterwards. The state already lives in
// the secret key object, so there is nothing more to keep.
fn keepStateInMemory(sk_buf: [*c]u8, buf_len: usize, context: ?*anyopaque) callconv(.c) c.OQS_STATUS {
    _ = sk_buf;
    _ = buf_len;
    _ = context;
    return c.OQS_SUCCESS;
}

test "LMS_SHA256_H5_W8 signs and verifies through the core" {
    const a = std.testing.allocator;
    var sig = try SigStfl.init(a, "LMS_SHA256_H5_W8");
    defer sig.deinit();

    var kp = try sig.keypair();
    defer a.free(kp.public_key);
    defer kp.secret_key.deinit();

    const msg = "the quick brown fox";
    const s = try sig.sign(msg, &kp.secret_key);
    defer a.free(s);

    try std.testing.expect(try sig.verify(msg, s, kp.public_key));
    try std.testing.expect(!try sig.verify("tampered", s, kp.public_key));
}

test "an unknown stateful name returns AlgorithmNotAvailable" {
    try std.testing.expectError(OqsError.AlgorithmNotAvailable, SigStfl.init(std.testing.allocator, "LMS_NOT_A_VARIANT"));
}

test "keypairResult accepts only OQS_SUCCESS" {
    try keypairResult(c.OQS_SUCCESS);
    try std.testing.expectError(OqsError.KeyGenerationFailed, keypairResult(c.OQS_ERROR));
    try std.testing.expectError(OqsError.KeyGenerationFailed, keypairResult(c.OQS_EXTERNAL_LIB_ERROR_OPENSSL));
}

test "signatureLength: an error is SignFailed even with a length, success with no length is KeyExhausted, success with a length returns it" {
    try std.testing.expectError(OqsError.SignFailed, signatureLength(c.OQS_ERROR, 2500));
    try std.testing.expectError(OqsError.SignFailed, signatureLength(c.OQS_EXTERNAL_LIB_ERROR_OPENSSL, 1296));
    try std.testing.expectError(OqsError.SignFailed, signatureLength(c.OQS_ERROR, 0));
    try std.testing.expectError(OqsError.SignFailed, signatureLength(c.OQS_EXTERNAL_LIB_ERROR_OPENSSL, 0));
    try std.testing.expectError(OqsError.KeyExhausted, signatureLength(c.OQS_SUCCESS, 0));
    try std.testing.expectEqual(@as(usize, 1296), try signatureLength(c.OQS_SUCCESS, 1296));
    try std.testing.expectEqual(@as(usize, 2500), try signatureLength(c.OQS_SUCCESS, 2500));
}

// Stands in for the liboqs keypair function of one variant and reports a
// failure after writing part of a public key.
fn failingKeypair(public_key: [*c]u8, secret_key: [*c]c.OQS_SIG_STFL_SECRET_KEY) callconv(.c) c.OQS_STATUS {
    _ = secret_key;
    public_key[0] = 0xAB;
    return c.OQS_ERROR;
}

test "keypair returns KeyGenerationFailed and frees the public key when liboqs fails to generate a key" {
    const a = std.testing.allocator;
    var sig = try SigStfl.init(a, "LMS_SHA256_H5_W8");
    defer sig.deinit();
    // A copy of the liboqs method table with only the keypair entry replaced,
    // so the real dispatcher and the real wrapper code run.
    var table = sig.handle.*;
    table.keypair = failingKeypair;
    const broken = SigStfl{ .allocator = a, .handle = &table };
    try std.testing.expectError(OqsError.KeyGenerationFailed, broken.keypair());
}

// Test double for the store callback. It counts calls, reads the remaining
// count from each state liboqs hands it, then returns `status`.
const StoreRecorder = struct {
    sig: *c.OQS_SIG_STFL,
    status: c.OQS_STATUS = c.OQS_SUCCESS,
    calls: u64 = 0,
    stored_remaining: ?u64 = null,

    fn store(sk_buf: [*c]u8, buf_len: usize, context: ?*anyopaque) callconv(.c) c.OQS_STATUS {
        const self: *StoreRecorder = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        self.stored_remaining = remainingIn(self.sig, sk_buf[0..buf_len]);
        return self.status;
    }

    // Loads a stored state into a new liboqs key object and reads its count.
    fn remainingIn(sig: *c.OQS_SIG_STFL, state: []const u8) ?u64 {
        const sk = c.OQS_SIG_STFL_SECRET_KEY_new(sig.method_name) orelse return null;
        defer c.OQS_SIG_STFL_SECRET_KEY_free(sk);
        if (c.OQS_SIG_STFL_SECRET_KEY_deserialize(sk, state.ptr, state.len, null) != c.OQS_SUCCESS) return null;
        var remaining: c_ulonglong = 0;
        if (c.OQS_SIG_STFL_sigs_remaining(sig, &remaining, sk) != c.OQS_SUCCESS) return null;
        return remaining;
    }
};

const StoreCase = struct { name: [:0]const u8, sigs_total: u64, index_offset: usize };
// Hand-written totals: 2^5 - 1 for LMS height 5 and 2^10 - 1 for XMSS height
// 10. The index is a 4-byte big-endian field. An HSS signature puts it after
// the 4-byte level count (RFC 8554). An XMSS signature starts with it (RFC 8391).
const store_cases = [_]StoreCase{
    .{ .name = "LMS_SHA256_H5_W8", .sigs_total = 31, .index_offset = 4 },
    .{ .name = "XMSS-SHA2_10_256", .sigs_total = 1023, .index_offset = 0 },
};

fn signatureIndex(e: StoreCase, signature: []const u8) u32 {
    return std.mem.readInt(u32, signature[e.index_offset..][0..4], .big);
}

test "sign stores the advanced state exactly once per signature, before it returns the signature" {
    const a = std.testing.allocator;
    for (store_cases) |e| {
        var sig = try SigStfl.init(a, e.name);
        defer sig.deinit();
        var kp = try sig.keypair();
        defer a.free(kp.public_key);
        defer kp.secret_key.deinit();
        var recorder = StoreRecorder{ .sig = sig.handle };
        c.OQS_SIG_STFL_SECRET_KEY_SET_store_cb(kp.secret_key.handle, StoreRecorder.store, &recorder);

        var i: u64 = 1;
        while (i <= 3) : (i += 1) {
            const s = try sig.sign("the quick brown fox", &kp.secret_key);
            defer a.free(s);
            // By the time signature i is handed back, the store ran i times and
            // the stored state already counts signature i as used.
            try std.testing.expectEqual(i, recorder.calls);
            try std.testing.expectEqual(e.sigs_total - i, recorder.stored_remaining.?);
            try std.testing.expectEqual(@as(u32, @intCast(i - 1)), signatureIndex(e, s));
            try std.testing.expect(try sig.verify("the quick brown fox", s, kp.public_key));
        }
    }
}

test "a failed store makes sign return SignFailed with no signature, and the used index is not given out again" {
    const a = std.testing.allocator;
    for (store_cases) |e| {
        var sig = try SigStfl.init(a, e.name);
        defer sig.deinit();
        var kp = try sig.keypair();
        defer a.free(kp.public_key);
        defer kp.secret_key.deinit();
        var recorder = StoreRecorder{ .sig = sig.handle, .status = c.OQS_ERROR };
        c.OQS_SIG_STFL_SECRET_KEY_SET_store_cb(kp.secret_key.handle, StoreRecorder.store, &recorder);

        // XMSS returns the error with a full signature in the buffer. LMS
        // wipes it first. Either way no signature reaches the caller, and
        // std.testing.allocator fails the test on a leaked one.
        try std.testing.expectError(OqsError.SignFailed, sig.sign("the quick brown fox", &kp.secret_key));
        try std.testing.expectEqual(@as(u64, 1), recorder.calls);
        // liboqs advanced the index in memory before the store ran.
        try std.testing.expectEqual(e.sigs_total - 1, try sig.sigsRemaining(kp.secret_key));

        recorder.status = c.OQS_SUCCESS;
        const s = try sig.sign("the quick brown fox", &kp.secret_key);
        defer a.free(s);
        try std.testing.expectEqual(@as(u64, 2), recorder.calls);
        try std.testing.expectEqual(e.sigs_total - 2, recorder.stored_remaining.?);
        try std.testing.expectEqual(@as(u32, 1), signatureIndex(e, s));
        try std.testing.expect(try sig.verify("the quick brown fox", s, kp.public_key));
    }
}
