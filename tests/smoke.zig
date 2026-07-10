//! Cross-family smoke test: instantiate + round-trip every algorithm we
//! claim to have enabled in build.zig, exercised through the public `oqs`
//! module. Uses std.testing.allocator so leaks fail the test.
const std = @import("std");
const oqs = @import("oqs");

const kem_names = [_][:0]const u8{
    "ML-KEM-768",
    "HQC-1",
    "HQC-3",
    "HQC-5",
    "Classic-McEliece-348864",
    "NTRU-HPS-2048-509",
    "sntrup761",
    "Kyber768",
    "FrodoKEM-640-AES",
    "eFrodoKEM-640-AES",
};

const sig_names = [_][:0]const u8{
    "ML-DSA-65",
    "MAYO-2",
    "Falcon-512",
    "Falcon-1024",
    "Falcon-padded-512",
    "Falcon-padded-1024",
    "cross-rsdp-128-balanced",
    "mqom2_cat1_gf16_fast_r3",
    "SLH_DSA_PURE_SHA2_128F",
    "SNOVA_24_5_4",
};

fn kemRoundTrip(name: [:0]const u8) !void {
    const a = std.testing.allocator;
    var kem = try oqs.Kem.init(a, name);
    defer kem.deinit();

    try std.testing.expect(kem.lengthPublicKey() > 0);
    try std.testing.expect(kem.lengthSecretKey() > 0);
    try std.testing.expect(kem.lengthCiphertext() > 0);
    try std.testing.expect(kem.lengthSharedSecret() > 0);

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

fn sigRoundTrip(name: [:0]const u8) !void {
    const a = std.testing.allocator;
    var sig = try oqs.Sig.init(a, name);
    defer sig.deinit();

    try std.testing.expect(sig.lengthPublicKey() > 0);
    try std.testing.expect(sig.lengthSecretKey() > 0);

    const kp = try sig.keypair();
    defer a.free(kp.public_key);
    defer a.free(kp.secret_key);

    const msg = "the quick brown fox";
    const s = try sig.sign(msg, kp.secret_key);
    defer a.free(s);

    try std.testing.expect(try sig.verify(msg, s, kp.public_key));
    try std.testing.expect(!try sig.verify("tampered", s, kp.public_key));
}

test "KEM smoke across enabled families" {
    for (kem_names) |name| {
        kemRoundTrip(name) catch |err| {
            std.debug.print("KEM smoke failed for {s}: {}\n", .{ name, err });
            return err;
        };
    }
}

test "SIG smoke across enabled families" {
    for (sig_names) |name| {
        sigRoundTrip(name) catch |err| {
            std.debug.print("SIG smoke failed for {s}: {}\n", .{ name, err });
            return err;
        };
    }
}
