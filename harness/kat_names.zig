//! The names a known-answer run covers, and the fixed set an unfiltered run must check.
//!
//! The run list and the summary both take their names from `enabledNames`, so a
//! name dropped there would drop out of the run and out of the check together.
//! `Expected` is written out by hand, so an unfiltered run can notice that.
const std = @import("std");

/// The run list and the expected set of a known-answer run.
pub const KatNames = struct {
    /// True if `filter` is unset, or if its comma-separated list holds `name`.
    pub fn selected(name: []const u8, filter: ?[]const u8) bool {
        const list = filter orelse return true;
        var it = std.mem.splitScalar(u8, list, ',');
        while (it.next()) |item| {
            if (std.mem.eql(u8, item, name)) return true;
        }
        return false;
    }

    fn NameOf(comptime Iterator: type) type {
        return @typeInfo(@typeInfo(@TypeOf(Iterator.next)).@"fn".return_type.?).optional.child;
    }

    /// The names of `names`, in its order, that `filter` selects. `names` is any
    /// iterator whose `next` returns an optional string, such as `oqs.AlgorithmNames`.
    /// The result is owned by `a` and keeps the string type of `next`, so a sentinel is kept.
    pub fn enabledNames(a: std.mem.Allocator, names: anytype, filter: ?[]const u8) ![]const NameOf(@TypeOf(names)) {
        var it = names;
        var list: std.ArrayList(NameOf(@TypeOf(names))) = .empty;
        errdefer list.deinit(a);
        while (it.next()) |name| {
            if (selected(name, filter)) try list.append(a, name);
        }
        return list.toOwnedSlice(a);
    }

    /// The algorithms an unfiltered run must check: every entry of the `kats.json`
    /// files of liboqs 0.16.0. A vendor bump must update these lists.
    pub const Expected = struct {
        /// The KEM names that an unfiltered run must check, in liboqs order.
        pub const kems = [_][]const u8{
            "BIKE-L1",
            "BIKE-L3",
            "BIKE-L5",
            "Classic-McEliece-348864",
            "Classic-McEliece-348864f",
            "Classic-McEliece-460896",
            "Classic-McEliece-460896f",
            "Classic-McEliece-6688128",
            "Classic-McEliece-6688128f",
            "Classic-McEliece-6960119",
            "Classic-McEliece-6960119f",
            "Classic-McEliece-8192128",
            "Classic-McEliece-8192128f",
            "FrodoKEM-1344-AES",
            "FrodoKEM-1344-SHAKE",
            "FrodoKEM-640-AES",
            "FrodoKEM-640-SHAKE",
            "FrodoKEM-976-AES",
            "FrodoKEM-976-SHAKE",
            "HQC-1",
            "HQC-3",
            "HQC-5",
            "Kyber1024",
            "Kyber512",
            "Kyber768",
            "ML-KEM-1024",
            "ML-KEM-512",
            "ML-KEM-768",
            "NTRU-HPS-2048-509",
            "NTRU-HPS-2048-677",
            "NTRU-HPS-4096-1229",
            "NTRU-HPS-4096-821",
            "NTRU-HRSS-1373",
            "NTRU-HRSS-701",
            "eFrodoKEM-1344-AES",
            "eFrodoKEM-1344-SHAKE",
            "eFrodoKEM-640-AES",
            "eFrodoKEM-640-SHAKE",
            "eFrodoKEM-976-AES",
            "eFrodoKEM-976-SHAKE",
            "sntrup761",
        };

        /// The signature names that an unfiltered run must check, in liboqs order.
        pub const sigs = [_][]const u8{
            "Falcon-1024",
            "Falcon-512",
            "Falcon-padded-1024",
            "Falcon-padded-512",
            "MAYO-1",
            "MAYO-2",
            "MAYO-3",
            "MAYO-5",
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87",
            "OV-III",
            "OV-III-pkc",
            "OV-III-pkc-skc",
            "OV-Ip",
            "OV-Ip-pkc",
            "OV-Ip-pkc-skc",
            "OV-Is",
            "OV-Is-pkc",
            "OV-Is-pkc-skc",
            "OV-V",
            "OV-V-pkc",
            "OV-V-pkc-skc",
            "SNOVA_24_5_4",
            "SNOVA_24_5_4_SHAKE",
            "SNOVA_24_5_4_SHAKE_esk",
            "SNOVA_24_5_4_esk",
            "SNOVA_24_5_5",
            "SNOVA_25_8_3",
            "SNOVA_29_6_5",
            "SNOVA_37_17_2",
            "SNOVA_37_8_4",
            "SNOVA_49_11_3",
            "SNOVA_56_25_2",
            "SNOVA_60_10_4",
            "cross-rsdp-128-balanced",
            "cross-rsdp-128-fast",
            "cross-rsdp-128-small",
            "cross-rsdp-192-balanced",
            "cross-rsdp-192-fast",
            "cross-rsdp-192-small",
            "cross-rsdp-256-balanced",
            "cross-rsdp-256-fast",
            "cross-rsdp-256-small",
            "cross-rsdpg-128-balanced",
            "cross-rsdpg-128-fast",
            "cross-rsdpg-128-small",
            "cross-rsdpg-192-balanced",
            "cross-rsdpg-192-fast",
            "cross-rsdpg-192-small",
            "cross-rsdpg-256-balanced",
            "cross-rsdpg-256-fast",
            "cross-rsdpg-256-small",
            "mqom2_cat1_gf16_fast_r3",
            "mqom2_cat1_gf16_fast_r5",
            "mqom2_cat1_gf16_short_r3",
            "mqom2_cat1_gf16_short_r5",
            "mqom2_cat3_gf16_fast_r3",
            "mqom2_cat3_gf16_fast_r5",
            "mqom2_cat3_gf16_short_r3",
            "mqom2_cat3_gf16_short_r5",
            "mqom2_cat5_gf16_fast_r3",
            "mqom2_cat5_gf16_fast_r5",
            "mqom2_cat5_gf16_short_r3",
            "mqom2_cat5_gf16_short_r5",
        };
    };
};
