//! Compile-time-typed wrappers over the runtime KEM/SIG cores.
//!
//! Each algorithm is a distinct type, so keys of different algorithms cannot be
//! mixed (compile error). Secret material is zeroed on `deinit`.
//!
//! ```zig
//! const oqs = @import("oqs");
//! var kp = try oqs.kem.MlKem768.generateKeyPair(allocator);
//! defer kp.public_key.deinit();
//! defer kp.secret_key.deinit();
//! var enc = try kp.public_key.encapsulate();
//! defer enc.deinit();                 // send enc.ciphertext to the key holder
//! var ss = try kp.secret_key.decapsulate(enc.ciphertext);
//! defer ss.deinit();                  // ss.bytes == enc.shared_secret.bytes
//! ```

const std = @import("std");
const core_kem = @import("kem.zig").Kem;
const core_sig = @import("sig.zig").Sig;
const core_sig_stfl = @import("sig_stfl.zig").SigStfl;
const SigStflSecretKey = @import("sig_stfl_secret_key.zig").SigStflSecretKey;
const keys = @import("keys.zig");
const OqsError = @import("errors.zig").OqsError;

pub const SharedSecret = keys.SharedSecret;

/// Compile-time description of one KEM algorithm (from the generated registry).
pub const KemInfo = struct {
    name: [:0]const u8,
    public_key: usize,
    secret_key: usize,
    ciphertext: usize,
    shared_secret: usize,
};

/// Compile-time description of one signature algorithm.
pub const SigInfo = struct {
    name: [:0]const u8,
    public_key: usize,
    secret_key: usize,
    signature_max: usize,
};

/// Compile-time description of one stateful signature algorithm.
pub const SigStflInfo = struct {
    name: [:0]const u8,
    public_key: usize,
    secret_key: usize,
    signature_max: usize,
};

/// The result of `PublicKey.encapsulate`: the shared secret you keep and the
/// ciphertext you send to the secret-key holder. Caller owns both; `deinit`
/// zeroes the shared secret and frees the ciphertext.
pub fn Encapsulation(comptime SharedSecretType: type) type {
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        ciphertext: []u8,
        shared_secret: SharedSecretType,

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.ciphertext);
            self.shared_secret.deinit();
            self.* = undefined;
        }
    };
}

/// Build the typed namespace for a single KEM algorithm. Each instantiation
/// nests its own `PublicKey`/`SecretKey`, so keys of different algorithms are
/// distinct types and cannot be mixed (compile error), even when sizes match.
pub fn Kem(comptime spec: KemInfo) type {
    return struct {
        pub const algorithm_name = spec.name;
        pub const info = spec; // consumed by the registry gate test
        pub const public_key_length = spec.public_key;
        pub const secret_key_length = spec.secret_key;
        pub const ciphertext_length = spec.ciphertext;
        pub const shared_secret_length = spec.shared_secret;

        pub const KeyPair = struct { public_key: PublicKey, secret_key: SecretKey };

        /// Encapsulation (public) key for this algorithm.
        pub const PublicKey = struct {
            allocator: std.mem.Allocator,
            bytes: []u8,

            /// Import from raw bytes; errors if the length is wrong.
            pub fn fromBytes(allocator: std.mem.Allocator, raw: []const u8) OqsError!PublicKey {
                if (raw.len != spec.public_key) return OqsError.InvalidKeySize;
                const dup = try allocator.dupe(u8, raw);
                return .{ .allocator = allocator, .bytes = dup };
            }

            pub fn deinit(self: *PublicKey) void {
                self.allocator.free(self.bytes);
                self.* = undefined;
            }

            /// Generate a fresh shared secret encapsulated to this key. Owned
            /// memory is allocated with the key's allocator.
            pub fn encapsulate(self: PublicKey) OqsError!Encapsulation(SharedSecret) {
                var k = try core_kem.init(self.allocator, spec.name);
                defer k.deinit();
                const enc = try k.encaps(self.bytes);
                return .{
                    .allocator = self.allocator,
                    .ciphertext = enc.ciphertext,
                    .shared_secret = SharedSecret.fromOwned(self.allocator, enc.shared_secret),
                };
            }
        };

        /// Decapsulation (secret) key for this algorithm. Zeroed on `deinit`.
        pub const SecretKey = struct {
            allocator: std.mem.Allocator,
            bytes: []u8,

            pub fn fromBytes(allocator: std.mem.Allocator, raw: []const u8) OqsError!SecretKey {
                if (raw.len != spec.secret_key) return OqsError.InvalidKeySize;
                const dup = try allocator.dupe(u8, raw);
                return .{ .allocator = allocator, .bytes = dup };
            }

            pub fn deinit(self: *SecretKey) void {
                keys.zeroAndFree(self.allocator, self.bytes);
                self.* = undefined;
            }

            /// Recover the shared secret from a ciphertext. Allocated with the
            /// key's allocator.
            pub fn decapsulate(self: SecretKey, ciphertext: []const u8) OqsError!SharedSecret {
                var k = try core_kem.init(self.allocator, spec.name);
                defer k.deinit();
                const ss = try k.decaps(ciphertext, self.bytes);
                return SharedSecret.fromOwned(self.allocator, ss);
            }
        };

        /// Generate a new random key pair.
        pub fn generateKeyPair(allocator: std.mem.Allocator) OqsError!KeyPair {
            var k = try core_kem.init(allocator, spec.name);
            defer k.deinit();
            const kp = try k.keypair();
            return .{
                .public_key = .{ .allocator = allocator, .bytes = kp.public_key },
                .secret_key = .{ .allocator = allocator, .bytes = kp.secret_key },
            };
        }
    };
}

/// Build the typed namespace for a single signature algorithm. Like `Kem`,
/// each instantiation nests its own key/signature types.
pub fn Sig(comptime spec: SigInfo) type {
    return struct {
        pub const algorithm_name = spec.name;
        pub const info = spec; // consumed by the registry gate test
        pub const public_key_length = spec.public_key;
        pub const secret_key_length = spec.secret_key;
        pub const signature_max_length = spec.signature_max;

        pub const KeyPair = struct { public_key: PublicKey, secret_key: SecretKey };

        /// A produced signature. Owns its bytes (exact produced length).
        pub const Signature = struct {
            allocator: std.mem.Allocator,
            bytes: []u8,

            pub fn deinit(self: *Signature) void {
                self.allocator.free(self.bytes);
                self.* = undefined;
            }
        };

        pub const PublicKey = struct {
            allocator: std.mem.Allocator,
            bytes: []u8,

            pub fn fromBytes(allocator: std.mem.Allocator, raw: []const u8) OqsError!PublicKey {
                if (raw.len != spec.public_key) return OqsError.InvalidKeySize;
                const dup = try allocator.dupe(u8, raw);
                return .{ .allocator = allocator, .bytes = dup };
            }

            pub fn deinit(self: *PublicKey) void {
                self.allocator.free(self.bytes);
                self.* = undefined;
            }

            /// True iff `signature` is valid for `message` under this key.
            pub fn isValidSignature(self: PublicKey, message: []const u8, signature: []const u8) OqsError!bool {
                var s = try core_sig.init(self.allocator, spec.name);
                defer s.deinit();
                return s.verify(message, signature, self.bytes);
            }
        };

        /// Signing (secret) key for this algorithm. Zeroed on `deinit`.
        pub const SecretKey = struct {
            allocator: std.mem.Allocator,
            bytes: []u8,

            pub fn fromBytes(allocator: std.mem.Allocator, raw: []const u8) OqsError!SecretKey {
                if (raw.len != spec.secret_key) return OqsError.InvalidKeySize;
                const dup = try allocator.dupe(u8, raw);
                return .{ .allocator = allocator, .bytes = dup };
            }

            pub fn deinit(self: *SecretKey) void {
                keys.zeroAndFree(self.allocator, self.bytes);
                self.* = undefined;
            }

            /// Sign `message`. Caller owns the returned signature, allocated
            /// with the key's allocator.
            pub fn sign(self: SecretKey, message: []const u8) OqsError!Signature {
                var s = try core_sig.init(self.allocator, spec.name);
                defer s.deinit();
                const bytes = try s.sign(message, self.bytes);
                return .{ .allocator = self.allocator, .bytes = bytes };
            }
        };

        pub fn generateKeyPair(allocator: std.mem.Allocator) OqsError!KeyPair {
            var s = try core_sig.init(allocator, spec.name);
            defer s.deinit();
            const kp = try s.keypair();
            return .{
                .public_key = .{ .allocator = allocator, .bytes = kp.public_key },
                .secret_key = .{ .allocator = allocator, .bytes = kp.secret_key },
            };
        }
    };
}

/// Build the typed namespace for a single stateful signature algorithm (XMSS,
/// XMSS^MT or LMS). Like `Sig`, each instantiation nests its own key and
/// signature types. The secret key is liboqs-owned state that advances on every
/// signature, so it is not a byte slice and has no import or export.
///
/// As in liboqs, one key makes `sigsTotal` + 1 signatures, and the last one is
/// made when `sigsRemaining` is already 0. For XMSS that last signature does
/// not verify. After it, `sign` returns no signature. An LMS key returns
/// `KeyExhausted` and an XMSS key returns `SignFailed`, because liboqs reports
/// success with no signature for LMS and an error status for XMSS.
pub fn SigStfl(comptime spec: SigStflInfo) type {
    return struct {
        pub const algorithm_name = spec.name;
        pub const info = spec; // consumed by the registry gate test
        pub const public_key_length = spec.public_key;
        pub const secret_key_length = spec.secret_key;
        pub const signature_max_length = spec.signature_max;

        pub const KeyPair = struct { public_key: PublicKey, secret_key: SecretKey };

        /// A produced signature. Owns its bytes (exact produced length).
        pub const Signature = struct {
            allocator: std.mem.Allocator,
            bytes: []u8,

            /// Frees the signature bytes.
            pub fn deinit(self: *Signature) void {
                self.allocator.free(self.bytes);
                self.* = undefined;
            }
        };

        /// Verification (public) key for this algorithm.
        pub const PublicKey = struct {
            allocator: std.mem.Allocator,
            bytes: []u8,

            /// Import from raw bytes. Errors if the length is wrong.
            pub fn fromBytes(allocator: std.mem.Allocator, raw: []const u8) OqsError!PublicKey {
                if (raw.len != spec.public_key) return OqsError.InvalidKeySize;
                const dup = try allocator.dupe(u8, raw);
                return .{ .allocator = allocator, .bytes = dup };
            }

            /// Frees the public key bytes.
            pub fn deinit(self: *PublicKey) void {
                self.allocator.free(self.bytes);
                self.* = undefined;
            }

            /// True iff `signature` is valid for `message` under this key.
            pub fn isValidSignature(self: PublicKey, message: []const u8, signature: []const u8) OqsError!bool {
                var s = try core_sig_stfl.init(self.allocator, spec.name);
                defer s.deinit();
                return s.verify(message, signature, self.bytes);
            }
        };

        /// Signing (secret) key for this algorithm. It owns the liboqs key
        /// state, which `deinit` zeroes and frees.
        pub const SecretKey = struct {
            allocator: std.mem.Allocator,
            state: SigStflSecretKey,

            /// Zeroes and frees the key state.
            pub fn deinit(self: *SecretKey) void {
                self.state.deinit();
                self.* = undefined;
            }

            /// Sign `message` with the next index and advance the key state.
            /// Caller owns the returned signature, allocated with the key's
            /// allocator. Once the key is used up it returns `KeyExhausted`
            /// for LMS and `SignFailed` for XMSS, as `oqs.SigStfl.sign` does.
            pub fn sign(self: *SecretKey, message: []const u8) OqsError!Signature {
                var s = try core_sig_stfl.init(self.allocator, spec.name);
                defer s.deinit();
                const bytes = try s.sign(message, &self.state);
                return .{ .allocator = self.allocator, .bytes = bytes };
            }

            /// How many signatures this key can still make, as liboqs counts it.
            pub fn sigsRemaining(self: SecretKey) OqsError!u64 {
                var s = try core_sig_stfl.init(self.allocator, spec.name);
                defer s.deinit();
                return s.sigsRemaining(self.state);
            }

            /// How many signatures this key can make over its life.
            pub fn sigsTotal(self: SecretKey) OqsError!u64 {
                var s = try core_sig_stfl.init(self.allocator, spec.name);
                defer s.deinit();
                return s.sigsTotal(self.state);
            }
        };

        /// Generate a new random key pair.
        pub fn generateKeyPair(allocator: std.mem.Allocator) OqsError!KeyPair {
            var s = try core_sig_stfl.init(allocator, spec.name);
            defer s.deinit();
            const kp = try s.keypair();
            return .{
                .public_key = .{ .allocator = allocator, .bytes = kp.public_key },
                .secret_key = .{ .allocator = allocator, .state = kp.secret_key },
            };
        }
    };
}

// Records each call of the variant free function that
// OQS_SIG_STFL_SECRET_KEY_free runs, then forwards to the real one.
const FreeKeyRecorder = struct {
    var real: @TypeOf(@as(@import("c.zig").c.OQS_SIG_STFL_SECRET_KEY, undefined).free_key) = null;
    var calls: usize = 0;

    fn freeKey(sk: [*c]@import("c.zig").c.OQS_SIG_STFL_SECRET_KEY) callconv(.c) void {
        calls += 1;
        real.?(sk);
    }
};

test "typed stateful SecretKey.deinit releases the liboqs key state exactly once" {
    const T = SigStfl(.{ .name = "LMS_SHA256_H5_W8", .public_key = 60, .secret_key = 64, .signature_max = 1296 });
    const a = std.testing.allocator;
    var kp = try T.generateKeyPair(a);
    defer kp.public_key.deinit();
    const handle = kp.secret_key.state.handle;
    FreeKeyRecorder.real = handle.free_key;
    FreeKeyRecorder.calls = 0;
    handle.free_key = FreeKeyRecorder.freeKey;
    kp.secret_key.deinit();
    try std.testing.expectEqual(@as(usize, 1), FreeKeyRecorder.calls);
}
