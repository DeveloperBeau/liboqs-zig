const std = @import("std");
const oqs = @import("oqs");

// --- Registry gate ---------------------------------------------------------
// Every generated wrapper must name a runtime-enabled algorithm, and the
// wrapper count must equal liboqs' enabled count. Catches a typo'd or
// not-actually-compiled algorithm shipping silently — neither the smoke nor
// parity tests would catch that.

test "every KEM wrapper names a runtime-enabled algorithm" {
    comptime var count: usize = 0;
    inline for (@typeInfo(oqs.kem).@"struct".decls) |d| {
        try std.testing.expect(oqs.isKemEnabled(@field(oqs.kem, d.name).info.name));
        count += 1;
    }
    try std.testing.expectEqual(oqs.enabledKemCount(), count);
}

test "every SIG wrapper names a runtime-enabled algorithm" {
    comptime var count: usize = 0;
    inline for (@typeInfo(oqs.sig).@"struct".decls) |d| {
        try std.testing.expect(oqs.isSigEnabled(@field(oqs.sig, d.name).info.name));
        count += 1;
    }
    try std.testing.expectEqual(oqs.enabledSigCount(), count);
}

// --- Behavior via the public namespaces ------------------------------------

test "namespace round-trip via oqs.kem.MlKem768" {
    const a = std.testing.allocator;
    var kp = try oqs.kem.MlKem768.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var enc = try kp.public_key.encapsulate(a);
    defer enc.deinit();
    var ss = try kp.secret_key.decapsulate(a, enc.ciphertext);
    defer ss.deinit();
    try std.testing.expectEqualSlices(u8, enc.shared_secret.bytes, ss.bytes);
}

test "namespace sign/verify via oqs.sig.MlDsa65" {
    const a = std.testing.allocator;
    var kp = try oqs.sig.MlDsa65.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var s = try kp.secret_key.sign(a, "the quick brown fox");
    defer s.deinit();
    try std.testing.expect(try kp.public_key.isValidSignature("the quick brown fox", s.bytes));
    try std.testing.expect(!try kp.public_key.isValidSignature("tampered", s.bytes));
}

test "public key import round-trip preserves bytes" {
    const a = std.testing.allocator;
    var kp = try oqs.kem.MlKem768.generateKeyPair(a);
    defer kp.public_key.deinit();
    defer kp.secret_key.deinit();
    var imported = try oqs.kem.MlKem768.PublicKey.fromBytes(a, kp.public_key.bytes);
    defer imported.deinit();
    try std.testing.expectEqualSlices(u8, kp.public_key.bytes, imported.bytes);
}

test "import rejects wrong-length bytes" {
    const a = std.testing.allocator;
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, oqs.kem.MlKem768.PublicKey.fromBytes(a, &[_]u8{ 1, 2, 3 }));
    try std.testing.expectError(oqs.OqsError.InvalidKeySize, oqs.sig.MlDsa65.SecretKey.fromBytes(a, &[_]u8{}));
}

test "comptime sizes are exposed" {
    try std.testing.expectEqual(@as(usize, 1184), oqs.kem.MlKem768.public_key_length);
    try std.testing.expectEqual(@as(usize, 32), oqs.kem.MlKem768.shared_secret_length);
    try std.testing.expectEqual(@as(usize, 1952), oqs.sig.MlDsa65.public_key_length);
}

// --- Cross-algorithm type safety -------------------------------------------
// Distinct algorithms produce distinct key types, so a key of one algorithm
// cannot be passed where another's is required (compile error). We can only
// assert the type distinctness at runtime; the compile-time guarantee is the
// real payoff and is verified by the type system itself.

test "distinct algorithms have distinct key types" {
    try std.testing.expect(oqs.kem.MlKem768.PublicKey != oqs.kem.MlKem1024.PublicKey);
    try std.testing.expect(oqs.sig.MlDsa65.SecretKey != oqs.sig.MlDsa87.SecretKey);
}
