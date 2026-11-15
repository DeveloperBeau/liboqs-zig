const std = @import("std");
const c = @import("c.zig").c;

/// The secret key state of one stateful key pair, owned by the caller and advanced by liboqs on every signature.
///
/// The key material lives inside the liboqs `OQS_SIG_STFL_SECRET_KEY` object and never
/// leaves it through this type. `deinit` releases it with the liboqs free function,
/// which zeroes the key bytes before freeing them.
pub const SigStflSecretKey = struct {
    /// The liboqs secret key object that holds the key bytes and the signature index.
    handle: *c.OQS_SIG_STFL_SECRET_KEY,
    /// The liboqs method name of the algorithm that generated this key.
    algorithm: [*:0]const u8,

    /// Zeroes and frees the secret key state.
    pub fn deinit(self: *SigStflSecretKey) void {
        c.OQS_SIG_STFL_SECRET_KEY_free(self.handle);
        self.* = undefined;
    }
};

// Records each call of the variant free function that
// OQS_SIG_STFL_SECRET_KEY_free runs, then forwards to the real one. The key
// object holds that function in its own method table, so no C code changes.
const FreeKeyRecorder = struct {
    var real: @TypeOf(@as(c.OQS_SIG_STFL_SECRET_KEY, undefined).free_key) = null;
    var calls: usize = 0;
    var freed: ?*c.OQS_SIG_STFL_SECRET_KEY = null;
    var had_key_data = false;

    fn freeKey(sk: [*c]c.OQS_SIG_STFL_SECRET_KEY) callconv(.c) void {
        calls += 1;
        freed = sk;
        had_key_data = sk.*.secret_key_data != null;
        real.?(sk);
    }
};

// The key bytes are wiped inside liboqs, by OQS_MEM_secure_free in the
// variant free function. Zig cannot read them after that without reading
// freed memory, so this test proves the release that does the wipe.
test "deinit releases the liboqs secret key, key data included, exactly once" {
    const SigStfl = @import("sig_stfl.zig").SigStfl;
    const a = std.testing.allocator;
    for ([_][:0]const u8{ "LMS_SHA256_H5_W8", "XMSS-SHA2_10_256" }) |name| {
        var sig = try SigStfl.init(a, name);
        defer sig.deinit();
        const kp = try sig.keypair();
        defer a.free(kp.public_key);
        var sk = kp.secret_key;
        const handle = sk.handle;

        FreeKeyRecorder.real = handle.free_key;
        FreeKeyRecorder.calls = 0;
        FreeKeyRecorder.freed = null;
        FreeKeyRecorder.had_key_data = false;
        handle.free_key = FreeKeyRecorder.freeKey;

        sk.deinit();
        try std.testing.expectEqual(@as(usize, 1), FreeKeyRecorder.calls);
        try std.testing.expect(FreeKeyRecorder.freed == handle);
        try std.testing.expect(FreeKeyRecorder.had_key_data);
    }
}
