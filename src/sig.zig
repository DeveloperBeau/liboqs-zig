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
};

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
