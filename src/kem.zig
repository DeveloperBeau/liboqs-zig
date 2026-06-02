const std = @import("std");
const c = @import("c.zig").c;
const oqs_init = @import("init.zig");
const OqsError = @import("errors.zig").OqsError;

pub const Kem = struct {
    allocator: std.mem.Allocator,
    handle: *c.OQS_KEM,

    pub fn init(allocator: std.mem.Allocator, name: [:0]const u8) OqsError!Kem {
        oqs_init.ensure();
        const h = c.OQS_KEM_new(name.ptr) orelse return OqsError.AlgorithmNotAvailable;
        return .{ .allocator = allocator, .handle = h };
    }

    pub fn deinit(self: *Kem) void {
        c.OQS_KEM_free(self.handle);
        self.* = undefined;
    }

    pub fn lengthPublicKey(self: Kem) usize {
        return self.handle.length_public_key;
    }
    pub fn lengthSecretKey(self: Kem) usize {
        return self.handle.length_secret_key;
    }
    pub fn lengthCiphertext(self: Kem) usize {
        return self.handle.length_ciphertext;
    }
    pub fn lengthSharedSecret(self: Kem) usize {
        return self.handle.length_shared_secret;
    }

    /// Caller owns both returned slices.
    pub fn keypair(self: Kem) OqsError!struct { public_key: []u8, secret_key: []u8 } {
        const pk = try self.allocator.alloc(u8, self.lengthPublicKey());
        errdefer self.allocator.free(pk);
        const sk = try self.allocator.alloc(u8, self.lengthSecretKey());
        errdefer self.allocator.free(sk);
        if (c.OQS_KEM_keypair(self.handle, pk.ptr, sk.ptr) != c.OQS_SUCCESS)
            return OqsError.KeyGenerationFailed;
        return .{ .public_key = pk, .secret_key = sk };
    }

    /// Caller owns both returned slices.
    pub fn encaps(self: Kem, public_key: []const u8) OqsError!struct { ciphertext: []u8, shared_secret: []u8 } {
        if (public_key.len != self.lengthPublicKey()) return OqsError.InvalidKeySize;
        const ct = try self.allocator.alloc(u8, self.lengthCiphertext());
        errdefer self.allocator.free(ct);
        const ss = try self.allocator.alloc(u8, self.lengthSharedSecret());
        errdefer self.allocator.free(ss);
        if (c.OQS_KEM_encaps(self.handle, ct.ptr, ss.ptr, public_key.ptr) != c.OQS_SUCCESS)
            return OqsError.EncapsulationFailed;
        return .{ .ciphertext = ct, .shared_secret = ss };
    }

    /// Caller owns the returned slice.
    pub fn decaps(self: Kem, ciphertext: []const u8, secret_key: []const u8) OqsError![]u8 {
        if (ciphertext.len != self.lengthCiphertext()) return OqsError.InvalidKeySize;
        if (secret_key.len != self.lengthSecretKey()) return OqsError.InvalidKeySize;
        const ss = try self.allocator.alloc(u8, self.lengthSharedSecret());
        errdefer self.allocator.free(ss);
        if (c.OQS_KEM_decaps(self.handle, ss.ptr, ciphertext.ptr, secret_key.ptr) != c.OQS_SUCCESS)
            return OqsError.DecapsulationFailed;
        return ss;
    }
};

test "ML-KEM-768 round-trip" {
    const a = std.testing.allocator;
    var kem = try Kem.init(a, "ML-KEM-768");
    defer kem.deinit();

    const kp = try kem.keypair();
    defer a.free(kp.public_key);
    defer a.free(kp.secret_key);

    const enc = try kem.encaps(kp.public_key);
    defer a.free(enc.ciphertext);
    defer a.free(enc.shared_secret);

    const ss = try kem.decaps(enc.ciphertext, kp.secret_key);
    defer a.free(ss);

    try std.testing.expectEqualSlices(u8, enc.shared_secret, ss);
}
