//! The algorithms the fuzz tests of `zig build test` run, and which of them
//! are slow in a Debug build. Measured on a Debug build of this repository:
//! the slow ones take several seconds a round, the rest a fraction of one.
//! `zig build behaviour` runs every algorithm.

/// An algorithm name and whether one round of it is slow in a Debug build.
pub const Entry = struct { name: [:0]const u8, slow: bool };

pub const kem = [_]Entry{
    .{ .name = "ML-KEM-512", .slow = false },
    .{ .name = "Kyber512", .slow = false },
    .{ .name = "NTRU-HPS-2048-509", .slow = false },
    .{ .name = "sntrup761", .slow = false },
    .{ .name = "BIKE-L1", .slow = false },
    .{ .name = "HQC-1", .slow = false },
    .{ .name = "FrodoKEM-640-SHAKE", .slow = false },
    .{ .name = "Classic-McEliece-348864", .slow = true },
};

pub const sig = [_]Entry{
    .{ .name = "ML-DSA-44", .slow = false },
    .{ .name = "Falcon-512", .slow = false },
    .{ .name = "Falcon-padded-512", .slow = false },
    .{ .name = "MAYO-1", .slow = false },
    .{ .name = "cross-rsdp-128-small", .slow = true },
    .{ .name = "OV-Is", .slow = false },
    .{ .name = "SNOVA_24_5_4", .slow = false },
    .{ .name = "mqom2_cat1_gf16_fast_r3", .slow = true },
    .{ .name = "SLH_DSA_PURE_SHAKE_128F", .slow = true },
};
