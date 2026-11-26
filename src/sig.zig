const std = @import("std");
const c = @import("c.zig").c;
const oqs_init = @import("init.zig");
const OqsError = @import("errors.zig").OqsError;

pub const Sig = struct {
    allocator: std.mem.Allocator,
    handle: *c.OQS_SIG,

    pub fn init(allocator: std.mem.Allocator, name: [:0]const u8) OqsError!Sig {
        oqs_init.ensure();
        const h = c.OQS_SIG_new(name.ptr) orelse return OqsError.AlgorithmNotAvailable;
        return .{ .allocator = allocator, .handle = h };
    }

    pub fn deinit(self: *Sig) void {
        c.OQS_SIG_free(self.handle);
        self.* = undefined;
    }

    pub fn lengthPublicKey(self: Sig) usize {
        return self.handle.length_public_key;
    }
    pub fn lengthSecretKey(self: Sig) usize {
        return self.handle.length_secret_key;
    }
    pub fn lengthSignatureMax(self: Sig) usize {
        return self.handle.length_signature;
    }

    pub fn keypair(self: Sig) OqsError!struct { public_key: []u8, secret_key: []u8 } {
        const pk = try self.allocator.alloc(u8, self.lengthPublicKey());
        errdefer self.allocator.free(pk);
        const sk = try self.allocator.alloc(u8, self.lengthSecretKey());
        errdefer self.allocator.free(sk);
        if (c.OQS_SIG_keypair(self.handle, pk.ptr, sk.ptr) != c.OQS_SUCCESS)
            return OqsError.KeyGenerationFailed;
        return .{ .public_key = pk, .secret_key = sk };
    }

    /// Returns an owned slice of exactly the produced signature length.
    pub fn sign(self: Sig, message: []const u8, secret_key: []const u8) OqsError![]u8 {
        if (secret_key.len != self.lengthSecretKey()) return OqsError.InvalidKeySize;
        const buf = try self.allocator.alloc(u8, self.lengthSignatureMax());
        defer self.allocator.free(buf);
        var sig_len: usize = 0;
        if (c.OQS_SIG_sign(self.handle, buf.ptr, &sig_len, message.ptr, message.len, secret_key.ptr) != c.OQS_SUCCESS)
            return OqsError.SignFailed;
        const out = try self.allocator.alloc(u8, sig_len);
        @memcpy(out, buf[0..sig_len]);
        return out;
    }

    pub fn verify(self: Sig, message: []const u8, signature: []const u8, public_key: []const u8) OqsError!bool {
        if (public_key.len != self.lengthPublicKey()) return OqsError.InvalidKeySize;
        return c.OQS_SIG_verify(self.handle, message.ptr, message.len, signature.ptr, signature.len, public_key.ptr) == c.OQS_SUCCESS;
    }

    /// True if liboqs can sign and verify with a non-empty context string for this algorithm.
    ///
    /// It is the `sig_with_ctx_support` field of the liboqs object. In liboqs
    /// 0.16.0 that is ML-DSA and SLH-DSA.
    pub fn supportsContext(self: Sig) bool {
        return self.handle.sig_with_ctx_support;
    }

    /// Signs `message` under the context string `context` and returns an owned slice of exactly the produced signature length.
    ///
    /// It calls `OQS_SIG_sign_with_ctx_str`. An empty context goes to liboqs
    /// as a null pointer with length 0. That is the only context an algorithm
    /// without context support takes, and liboqs then gives the plain
    /// signature, so the result verifies with `verify`.
    ///
    /// The checks run before liboqs is called, in the order the Rust port
    /// uses. A non-empty context on an algorithm without context support
    /// returns `ContextNotSupported`. A secret key of the wrong length returns
    /// `InvalidKeySize`. A context over 255 bytes on an algorithm with context
    /// support returns `ContextTooLong`, as FIPS 204 and FIPS 205 set.
    pub fn signWithContext(self: Sig, message: []const u8, context: []const u8, secret_key: []const u8) OqsError![]u8 {
        if (!self.supportsContext() and context.len != 0) return OqsError.ContextNotSupported;
        if (secret_key.len != self.lengthSecretKey()) return OqsError.InvalidKeySize;
        if (context.len > max_context_length) return OqsError.ContextTooLong;
        const buf = try self.allocator.alloc(u8, self.lengthSignatureMax());
        defer self.allocator.free(buf);
        var sig_len: usize = 0;
        if (c.OQS_SIG_sign_with_ctx_str(self.handle, buf.ptr, &sig_len, message.ptr, message.len, contextPointer(context), context.len, secret_key.ptr) != c.OQS_SUCCESS)
            return OqsError.SignFailed;
        const out = try self.allocator.alloc(u8, sig_len);
        @memcpy(out, buf[0..sig_len]);
        return out;
    }

    /// True if `signature` is valid for `message` under `context` and `public_key`.
    ///
    /// It calls `OQS_SIG_verify_with_ctx_str` and returns what liboqs says.
    /// An empty context goes to liboqs as a null pointer with length 0, so it
    /// matches `verify`. A non-empty context on an algorithm without context
    /// support, or a context over 255 bytes, gives false and not an error,
    /// because liboqs rejects those as it rejects a bad signature. A public
    /// key of the wrong length returns `InvalidKeySize`.
    pub fn verifyWithContext(self: Sig, message: []const u8, signature: []const u8, context: []const u8, public_key: []const u8) OqsError!bool {
        if (public_key.len != self.lengthPublicKey()) return OqsError.InvalidKeySize;
        return c.OQS_SIG_verify_with_ctx_str(self.handle, message.ptr, message.len, signature.ptr, signature.len, contextPointer(context), context.len, public_key.ptr) == c.OQS_SUCCESS;
    }
};

// The longest context string FIPS 204 and FIPS 205 allow. ML-DSA and SLH-DSA
// reject a longer one inside liboqs, and they are the only algorithms with
// context support.
const max_context_length = 255;

// The algorithms without context support accept a context only when the
// pointer is null and the length is 0 (for example
// OQS_SIG_falcon_512_sign_with_ctx_str). A Zig empty slice can have a non-null
// pointer, so an empty context is sent as null.
fn contextPointer(context: []const u8) ?[*]const u8 {
    return if (context.len == 0) null else context.ptr;
}

fn roundTrip(name: [:0]const u8) !void {
    const a = std.testing.allocator;
    var sig = try Sig.init(a, name);
    defer sig.deinit();

    const kp = try sig.keypair();
    defer a.free(kp.public_key);
    defer a.free(kp.secret_key);

    const msg = "the quick brown fox";
    const s = try sig.sign(msg, kp.secret_key);
    defer a.free(s);

    try std.testing.expect(try sig.verify(msg, s, kp.public_key));
    try std.testing.expect(!try sig.verify("tampered", s, kp.public_key));
}

test "ML-DSA-65 sign/verify" {
    try roundTrip("ML-DSA-65");
}
test "MAYO-2 sign/verify" {
    try roundTrip("MAYO-2");
}

// Stands in for the sign_with_ctx_str and verify_with_ctx_str function
// pointers of an OQS_SIG, so a test can see what reaches liboqs and choose
// the status liboqs returns.
const ContextRecorder = struct {
    var status: c.OQS_STATUS = c.OQS_SUCCESS;
    var calls: usize = 0;
    var context_was_null: bool = false;
    var context_len: usize = 0;
    var first_context_byte: u8 = 0;

    fn reset(next_status: c.OQS_STATUS) void {
        status = next_status;
        calls = 0;
        context_was_null = false;
        context_len = 0;
        first_context_byte = 0;
    }

    fn record(ctx_str: [*c]const u8, ctx_str_len: usize) void {
        calls += 1;
        context_was_null = ctx_str == null;
        context_len = ctx_str_len;
        if (ctx_str != null and ctx_str_len > 0) first_context_byte = ctx_str[0];
    }

    fn sign(signature: [*c]u8, signature_len: [*c]usize, message: [*c]const u8, message_len: usize, ctx_str: [*c]const u8, ctx_str_len: usize, secret_key: [*c]const u8) callconv(.c) c.OQS_STATUS {
        _ = message;
        _ = message_len;
        _ = secret_key;
        record(ctx_str, ctx_str_len);
        signature[0] = 0x5A;
        signature_len.* = 1;
        return status;
    }

    fn verify(message: [*c]const u8, message_len: usize, signature: [*c]const u8, signature_len: usize, ctx_str: [*c]const u8, ctx_str_len: usize, public_key: [*c]const u8) callconv(.c) c.OQS_STATUS {
        _ = message;
        _ = message_len;
        _ = signature;
        _ = signature_len;
        _ = public_key;
        record(ctx_str, ctx_str_len);
        return status;
    }
};

// A core over ML-DSA-44 whose context functions are the recorder's.
fn recordingSig(next_status: c.OQS_STATUS) !Sig {
    var sig = try Sig.init(std.testing.allocator, "ML-DSA-44");
    sig.handle.sign_with_ctx_str = ContextRecorder.sign;
    sig.handle.verify_with_ctx_str = ContextRecorder.verify;
    ContextRecorder.reset(next_status);
    return sig;
}

test "signWithContext returns SignFailed and no signature when liboqs reports an error status" {
    var sig = try recordingSig(c.OQS_ERROR);
    defer sig.deinit();
    const sk: [2560]u8 = @splat(0);
    try std.testing.expectError(OqsError.SignFailed, sig.signWithContext("m", "ctx", &sk));
    try std.testing.expectEqual(@as(usize, 1), ContextRecorder.calls);
}

test "signWithContext hands liboqs the context bytes and length, and the empty context as a null pointer" {
    var sig = try recordingSig(c.OQS_SUCCESS);
    defer sig.deinit();
    const sk: [2560]u8 = @splat(0);
    const out = try sig.signWithContext("m", "ctx", &sk);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x5A}, out);
    try std.testing.expect(!ContextRecorder.context_was_null);
    try std.testing.expectEqual(@as(usize, 3), ContextRecorder.context_len);
    try std.testing.expectEqual(@as(u8, 'c'), ContextRecorder.first_context_byte);

    // A slice of length 0 that still points at memory.
    const backing = "xyz";
    const out_empty = try sig.signWithContext("m", backing[0..0], &sk);
    defer std.testing.allocator.free(out_empty);
    try std.testing.expect(ContextRecorder.context_was_null);
    try std.testing.expectEqual(@as(usize, 0), ContextRecorder.context_len);
    try std.testing.expectEqual(@as(usize, 2), ContextRecorder.calls);
}

test "verifyWithContext hands liboqs the context and returns its status as a bool" {
    var sig = try recordingSig(c.OQS_SUCCESS);
    defer sig.deinit();
    const pk: [1312]u8 = @splat(0);
    try std.testing.expect(try sig.verifyWithContext("m", "s", "ctx", &pk));
    try std.testing.expect(!ContextRecorder.context_was_null);
    try std.testing.expectEqual(@as(usize, 3), ContextRecorder.context_len);
    try std.testing.expectEqual(@as(u8, 'c'), ContextRecorder.first_context_byte);

    const backing = "xyz";
    ContextRecorder.status = c.OQS_ERROR;
    try std.testing.expect(!try sig.verifyWithContext("m", "s", backing[0..0], &pk));
    try std.testing.expect(ContextRecorder.context_was_null);
    try std.testing.expectEqual(@as(usize, 0), ContextRecorder.context_len);
}

test "signWithContext and verifyWithContext stop before liboqs on a rejected context or key" {
    var sig = try recordingSig(c.OQS_SUCCESS);
    defer sig.deinit();
    const sk: [2560]u8 = @splat(0);
    const pk: [1312]u8 = @splat(0);
    const long: [256]u8 = @splat(1);
    try std.testing.expectError(OqsError.ContextTooLong, sig.signWithContext("m", &long, &sk));
    try std.testing.expectError(OqsError.InvalidKeySize, sig.signWithContext("m", "ctx", sk[1..]));
    try std.testing.expectError(OqsError.InvalidKeySize, sig.verifyWithContext("m", "s", "ctx", pk[1..]));
    try std.testing.expectEqual(@as(usize, 0), ContextRecorder.calls);
}

test "signWithContext returns OutOfMemory when the signature buffer cannot be allocated" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var sig = try Sig.init(failing.allocator(), "ML-DSA-44");
    defer sig.deinit();
    const sk: [2560]u8 = @splat(0);
    try std.testing.expectError(OqsError.OutOfMemory, sig.signWithContext("m", "ctx", &sk));
}
