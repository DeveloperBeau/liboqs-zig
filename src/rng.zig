const std = @import("std");
const c = @import("c.zig").c;

/// Switch the global liboqs RNG to the deterministic NIST-KAT DRBG and seed it.
/// `entropy` must be exactly 48 bytes. For test/parity use only — the DRBG is
/// global mutable state and is not thread-safe.
pub fn seedKat(entropy: *const [48]u8) void {
    c.OQS_randombytes_custom_algorithm(c.OQS_randombytes_nist_kat);
    c.OQS_randombytes_nist_kat_init_256bit(entropy, null);
}

test "same KAT seed yields identical byte streams" {
    var seed: [48]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i);

    var a: [32]u8 = undefined;
    var bbuf: [32]u8 = undefined;

    seedKat(&seed);
    c.OQS_randombytes(&a, a.len);

    seedKat(&seed);
    c.OQS_randombytes(&bbuf, bbuf.len);

    try std.testing.expectEqualSlices(u8, &a, &bbuf);
}
