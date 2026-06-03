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
