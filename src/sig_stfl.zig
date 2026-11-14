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
        if (c.OQS_SIG_STFL_keypair(self.handle, pk.ptr, sk) != c.OQS_SUCCESS)
            return OqsError.KeyGenerationFailed;
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
    /// algorithm, and `SignFailed` once `sigsRemaining` is 0. liboqs itself would
    /// still sign at that point (with wiped key material for XMSS), so the count
    /// is checked first.
    pub fn sign(self: SigStfl, message: []const u8, secret_key: *SigStflSecretKey) OqsError![]u8 {
        if (!self.owns(secret_key.*)) return OqsError.InvalidKeySize;
        const remaining = self.sigsRemaining(secret_key.*) catch return OqsError.SignFailed;
        if (remaining == 0) return OqsError.SignFailed;
        const buf = try self.allocator.alloc(u8, self.lengthSignatureMax());
        defer self.allocator.free(buf);
        var sig_len: usize = 0;
        if (c.OQS_SIG_STFL_sign(self.handle, buf.ptr, &sig_len, message.ptr, message.len, secret_key.handle) != c.OQS_SUCCESS)
            return OqsError.SignFailed;
        const out = try self.allocator.alloc(u8, sig_len);
        @memcpy(out, buf[0..sig_len]);
        return out;
    }

    /// True if `signature` is a valid signature of `message` under `public_key`.
    ///
    /// A signature of the wrong length is rejected before it reaches liboqs,
    /// because the XMSS verifier reads a fixed length without checking it.
    pub fn verify(self: SigStfl, message: []const u8, signature: []const u8, public_key: []const u8) OqsError!bool {
        if (public_key.len != self.lengthPublicKey()) return OqsError.InvalidKeySize;
        if (signature.len != self.lengthSignatureMax()) return false;
        return c.OQS_SIG_STFL_verify(self.handle, message.ptr, message.len, signature.ptr, signature.len, public_key.ptr) == c.OQS_SUCCESS;
    }

    /// The number of signatures `secret_key` can still make.
    ///
    /// Returns `InvalidKeySize` if `secret_key` belongs to another algorithm or
    /// liboqs cannot read it.
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
