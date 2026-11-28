//! Stand-ins for the liboqs function pointers of an ML-KEM-512 object and an
//! ML-DSA-44 object, so a test can show that the behaviour checks fail when a
//! KEM or signature scheme misbehaves. The objects keep their real lengths. The
//! stubs make no secret of their own: a "secret" is a fixed byte pattern, and
//! no stub touches the random source, so they are safe in the seeded fuzz
//! binary too. Tests run one at a time, so the mode and the counter below are
//! plain globals that `kem`/`sig` reset.
const std = @import("std");
const oqs = @import("oqs");
const c = @import("c_api");

// --- KEM -----------------------------------------------------------------------

/// What the stub decaps does. The ciphertext the stub encaps makes is all
/// `ct_byte`, and the stub key pair numbers its secret keys 1, 2, 3 in the
/// first byte. Distance is the number of bits that differ from that ciphertext.
pub const KemMode = enum {
    /// The real secret for every ciphertext and every key.
    leak_all,
    /// The real secret for the right ciphertext under the first key, and for any ciphertext at most 3 bits away.
    leak_near,
    /// The real secret for the right ciphertext, and for every ciphertext more than 3 bits away.
    leak_far,
    /// The real secret for the right ciphertext under any key.
    leak_other_key,
    /// The real secret for the right ciphertext under the first key and an error for everything else.
    reject_rest,
};

const ct_byte: u8 = 0xA5;
const real_secret: u8 = 0x5A;
const rejection_secret: u8 = 0x11;
var kem_mode: KemMode = .leak_all;
var key_counter: u8 = 0;

fn kemKeypair(public_key: [*c]u8, secret_key: [*c]u8) callconv(.c) c.OQS_STATUS {
    key_counter += 1;
    @memset(public_key[0..800], key_counter);
    @memset(secret_key[0..1632], key_counter);
    return c.OQS_SUCCESS;
}

fn kemEncaps(ciphertext: [*c]u8, shared_secret: [*c]u8, public_key: [*c]const u8) callconv(.c) c.OQS_STATUS {
    _ = public_key;
    @memset(ciphertext[0..768], ct_byte);
    @memset(shared_secret[0..32], real_secret);
    return c.OQS_SUCCESS;
}

fn kemDecaps(shared_secret: [*c]u8, ciphertext: [*c]const u8, secret_key: [*c]const u8) callconv(.c) c.OQS_STATUS {
    var distance: usize = 0;
    for (ciphertext[0..768]) |byte| distance += @popCount(byte ^ ct_byte);
    const own_key = secret_key[0] == 1;
    const exact = distance == 0;
    const real = switch (kem_mode) {
        .leak_all => true,
        .leak_near => distance <= 3 and own_key,
        .leak_far => (exact and own_key) or distance > 3,
        .leak_other_key => exact,
        .reject_rest => exact and own_key,
    };
    if (kem_mode == .reject_rest and !real) return c.OQS_ERROR;
    @memset(shared_secret[0..32], if (real) real_secret else rejection_secret);
    return c.OQS_SUCCESS;
}

/// An ML-KEM-512 object whose key pair, encaps and decaps are the stubs. The caller deinits it.
pub fn kem(allocator: std.mem.Allocator, mode: KemMode) !oqs.Kem {
    var k = try oqs.Kem.init(allocator, "ML-KEM-512");
    k.handle.keypair = kemKeypair;
    k.handle.encaps = kemEncaps;
    k.handle.decaps = kemDecaps;
    kem_mode = mode;
    key_counter = 0;
    return k;
}

// --- Signature -------------------------------------------------------------------

pub const SigMode = enum {
    /// verify says yes to everything.
    accept_all,
    /// verify says no to everything.
    reject_all,
    /// verify says yes to the empty message only, so a valid signature of any other message is rejected.
    only_empty,
    /// verify says yes to the stub signature under the first key for any message as long as the message has the length of the last one signed, so a changed message verifies and everything else is rejected.
    same_length_message,
};

const stub_signature = [_]u8{ 1, 2, 3, 4 };
var sig_mode: SigMode = .accept_all;
var signed_len: usize = 0;

fn sigKeypair(public_key: [*c]u8, secret_key: [*c]u8) callconv(.c) c.OQS_STATUS {
    key_counter += 1;
    @memset(public_key[0..1312], key_counter);
    @memset(secret_key[0..2560], key_counter);
    return c.OQS_SUCCESS;
}

fn sigSign(signature: [*c]u8, signature_len: [*c]usize, message: [*c]const u8, message_len: usize, secret_key: [*c]const u8) callconv(.c) c.OQS_STATUS {
    _ = message;
    _ = secret_key;
    signed_len = message_len;
    @memcpy(signature[0..stub_signature.len], &stub_signature);
    signature_len.* = stub_signature.len;
    return c.OQS_SUCCESS;
}

fn sigVerify(message: [*c]const u8, message_len: usize, signature: [*c]const u8, signature_len: usize, public_key: [*c]const u8) callconv(.c) c.OQS_STATUS {
    _ = message;
    const yes = switch (sig_mode) {
        .accept_all => true,
        .reject_all => false,
        .only_empty => message_len == 0,
        .same_length_message => message_len == signed_len and
            std.mem.eql(u8, signature[0..signature_len], &stub_signature) and
            std.mem.allEqual(u8, public_key[0..1312], 1),
    };
    return if (yes) c.OQS_SUCCESS else c.OQS_ERROR;
}

/// An ML-DSA-44 object whose key pair, sign and verify are the stubs. The caller deinits it.
pub fn sig(allocator: std.mem.Allocator, mode: SigMode) !oqs.Sig {
    var s = try oqs.Sig.init(allocator, "ML-DSA-44");
    s.handle.keypair = sigKeypair;
    s.handle.sign = sigSign;
    s.handle.verify = sigVerify;
    sig_mode = mode;
    key_counter = 0;
    signed_len = 0;
    return s;
}
