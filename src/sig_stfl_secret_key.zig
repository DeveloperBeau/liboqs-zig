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
