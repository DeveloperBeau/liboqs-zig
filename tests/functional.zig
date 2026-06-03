//! Behavioral tests for the typed API under the system RNG. These assert API
//! behavior (round-trip, uniqueness, length validation), not algorithm breadth
//! — the registry gate, smoke, and parity cover breadth. This module must never
//! call seedKat: that flips a process-global DRBG pointer for the whole binary.
const std = @import("std");
const oqs = @import("oqs");

test "KEM: independent key pairs differ" {
    const a = std.testing.allocator;
    var k1 = try oqs.kem.MlKem768.generateKeyPair(a);
    defer k1.public_key.deinit();
    defer k1.secret_key.deinit();
    var k2 = try oqs.kem.MlKem768.generateKeyPair(a);
    defer k2.public_key.deinit();
    defer k2.secret_key.deinit();
    try std.testing.expect(!std.mem.eql(u8, k1.public_key.bytes, k2.public_key.bytes));
}

test "KEM: two encapsulations to the same key differ" {
    const a = std.testing.allocator;
    var kp = try oqs.kem.MlKem768.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var e1 = try kp.public_key.encapsulate();
    defer e1.deinit();
    var e2 = try kp.public_key.encapsulate();
    defer e2.deinit();
    try std.testing.expect(!std.mem.eql(u8, e1.ciphertext, e2.ciphertext));
}

test "KEM: round-trip recovers the shared secret" {
    const a = std.testing.allocator;
    var kp = try oqs.kem.MlKem768.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var enc = try kp.public_key.encapsulate();
    defer enc.deinit();
    var ss = try kp.secret_key.decapsulate(enc.ciphertext);
    defer ss.deinit();
    try std.testing.expectEqualSlices(u8, enc.shared_secret.bytes, ss.bytes);
}

test "KEM: truncated ciphertext is rejected by length check" {
    const a = std.testing.allocator;
    var kp = try oqs.kem.MlKem768.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var enc = try kp.public_key.encapsulate();
    defer enc.deinit();
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, kp.secret_key.decapsulate(enc.ciphertext[0 .. enc.ciphertext.len - 1]));
}

test "SIG: round-trip verifies; tamper fails" {
    const a = std.testing.allocator;
    var kp = try oqs.sig.MlDsa65.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var s = try kp.secret_key.sign("hello world");
    defer s.deinit();
    try std.testing.expect(try kp.public_key.isValidSignature("hello world", s.bytes));
    try std.testing.expect(!try kp.public_key.isValidSignature("hello worle", s.bytes));
}

test "SIG: signature does not verify under a different key pair" {
    const a = std.testing.allocator;
    var k1 = try oqs.sig.MlDsa65.generateKeyPair(a);
    defer k1.public_key.deinit();
    defer k1.secret_key.deinit();
    var k2 = try oqs.sig.MlDsa65.generateKeyPair(a);
    defer k2.public_key.deinit();
    defer k2.secret_key.deinit();
    var s = try k1.secret_key.sign("msg");
    defer s.deinit();
    try std.testing.expect(!try k2.public_key.isValidSignature("msg", s.bytes));
}

test "SIG: empty message round-trips" {
    const a = std.testing.allocator;
    var kp = try oqs.sig.MlDsa65.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var s = try kp.secret_key.sign("");
    defer s.deinit();
    try std.testing.expect(try kp.public_key.isValidSignature("", s.bytes));
}
