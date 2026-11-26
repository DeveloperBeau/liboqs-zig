const std = @import("std");
const c = @import("c.zig").c;
const oqs_init = @import("init.zig");
const AlgorithmNames = @import("algorithm_names.zig").AlgorithmNames;
const KemDescription = @import("kem_description.zig").KemDescription;
const SigDescription = @import("sig_description.zig").SigDescription;
const SigStflDescription = @import("sig_stfl_description.zig").SigStflDescription;

/// The algorithms this build of liboqs enables, with their names and what liboqs reports about each one.
///
/// Every name list comes from the liboqs identifier lists, filtered by the
/// liboqs enabled check, in liboqs order.
///
/// Name matching follows liboqs. liboqs compares names with `strcasecmp`
/// (`_stricmp` on Windows), so case is ignored for the ASCII letters A to Z
/// only. Every other byte must be equal, and the lengths must be equal.
/// So `ml-kem-768` matches `ML-KEM-768`, as it does for `oqs.Kem.init`.
/// A description always carries the liboqs name, such as `ML-KEM-768`, not
/// the name that was passed in.
///
/// A name that holds a zero byte never matches. C would stop reading at that
/// byte, so liboqs would see a shorter name. Here the whole slice is compared,
/// and no liboqs name holds a zero byte. A Zig slice cannot be null, so the
/// liboqs null checks have no match here.
pub const Registry = struct {
    /// The names of the enabled key encapsulation mechanisms, in liboqs order.
    pub fn kemNames() AlgorithmNames {
        return names(kem_kind);
    }

    /// The names of the enabled signature schemes, in liboqs order.
    pub fn sigNames() AlgorithmNames {
        return names(sig_kind);
    }

    /// The names of the enabled stateful signature schemes, in liboqs order.
    pub fn sigStflNames() AlgorithmNames {
        return names(sig_stfl_kind);
    }

    /// The number of key encapsulation mechanisms this build enables.
    pub fn enabledKemCount() usize {
        return count(kem_kind);
    }

    /// The number of signature schemes this build enables.
    pub fn enabledSigCount() usize {
        return count(sig_kind);
    }

    /// The number of stateful signature schemes this build enables.
    pub fn enabledSigStflCount() usize {
        return count(sig_stfl_kind);
    }

    /// True if `name` is the liboqs name of a key encapsulation mechanism this build enables, ignoring ASCII case.
    pub fn isKemEnabled(name: []const u8) bool {
        return enabledIdentifier(kem_kind, name) != null;
    }

    /// True if `name` is the liboqs name of a signature scheme this build enables, ignoring ASCII case.
    pub fn isSigEnabled(name: []const u8) bool {
        return enabledIdentifier(sig_kind, name) != null;
    }

    /// True if `name` is the liboqs name of a stateful signature scheme this build enables, ignoring ASCII case.
    pub fn isSigStflEnabled(name: []const u8) bool {
        return enabledIdentifier(sig_stfl_kind, name) != null;
    }

    /// What liboqs reports about the key encapsulation mechanism named `name`.
    ///
    /// `name` matches ignoring ASCII case, and the description carries the
    /// liboqs name. Returns null when `name` is not the name of an enabled
    /// mechanism, or when liboqs cannot allocate its algorithm object.
    pub fn kemDescription(name: []const u8) ?KemDescription {
        const identifier = enabledIdentifier(kem_kind, name) orelse return null;
        const kem: *c.OQS_KEM = c.OQS_KEM_new(identifier) orelse return null;
        defer c.OQS_KEM_free(kem);
        return .{
            .name = staticString(kem.method_name),
            .algorithmVersion = staticString(kem.alg_version),
            .claimedNistLevel = kem.claimed_nist_level,
            .isIndCcaSecure = kem.ind_cca,
            .publicKeyLength = kem.length_public_key,
            .secretKeyLength = kem.length_secret_key,
            .ciphertextLength = kem.length_ciphertext,
            .sharedSecretLength = kem.length_shared_secret,
            .keyPairSeedLength = kem.length_keypair_seed,
            .encapsulationSeedLength = kem.length_encaps_seed,
        };
    }

    /// What liboqs reports about the signature scheme named `name`.
    ///
    /// `name` matches ignoring ASCII case, and the description carries the
    /// liboqs name. Returns null when `name` is not the name of an enabled
    /// scheme, or when liboqs cannot allocate its algorithm object.
    pub fn sigDescription(name: []const u8) ?SigDescription {
        const identifier = enabledIdentifier(sig_kind, name) orelse return null;
        const sig: *c.OQS_SIG = c.OQS_SIG_new(identifier) orelse return null;
        defer c.OQS_SIG_free(sig);
        return .{
            .name = staticString(sig.method_name),
            .algorithmVersion = staticString(sig.alg_version),
            .claimedNistLevel = sig.claimed_nist_level,
            .isEufCmaSecure = sig.euf_cma,
            .isSufCmaSecure = sig.suf_cma,
            .supportsContext = sig.sig_with_ctx_support,
            .publicKeyLength = sig.length_public_key,
            .secretKeyLength = sig.length_secret_key,
            .signatureLength = sig.length_signature,
        };
    }

    /// What liboqs reports about the stateful signature scheme named `name`.
    ///
    /// `name` matches ignoring ASCII case, and the description carries the
    /// liboqs name. Returns null when `name` is not the name of an enabled
    /// scheme, or when liboqs cannot allocate its algorithm object.
    pub fn sigStflDescription(name: []const u8) ?SigStflDescription {
        const identifier = enabledIdentifier(sig_stfl_kind, name) orelse return null;
        const sig: *c.OQS_SIG_STFL = c.OQS_SIG_STFL_new(identifier) orelse return null;
        defer c.OQS_SIG_STFL_free(sig);
        return .{
            .objectIdentifier = sig.oid,
            .name = staticString(sig.method_name),
            .algorithmVersion = staticString(sig.alg_version),
            .isEufCmaSecure = sig.euf_cma,
            .isSufCmaSecure = sig.suf_cma,
            .publicKeyLength = sig.length_public_key,
            .secretKeyLength = sig.length_secret_key,
            .signatureLength = sig.length_signature,
        };
    }
};

// The three liboqs functions that list and filter the names of one kind.
const Kind = struct {
    count: *const fn () callconv(.c) c_int,
    identifierAt: *const fn (usize) callconv(.c) [*c]const u8,
    isEnabled: *const fn ([*c]const u8) callconv(.c) c_int,
};

const kem_kind = Kind{
    .count = &c.OQS_KEM_alg_count,
    .identifierAt = &c.OQS_KEM_alg_identifier,
    .isEnabled = &c.OQS_KEM_alg_is_enabled,
};
const sig_kind = Kind{
    .count = &c.OQS_SIG_alg_count,
    .identifierAt = &c.OQS_SIG_alg_identifier,
    .isEnabled = &c.OQS_SIG_alg_is_enabled,
};
const sig_stfl_kind = Kind{
    .count = &c.OQS_SIG_STFL_alg_count,
    .identifierAt = &c.OQS_SIG_STFL_alg_identifier,
    .isEnabled = &c.OQS_SIG_STFL_alg_is_enabled,
};

fn names(kind: Kind) AlgorithmNames {
    oqs_init.ensure();
    return .{
        .index = 0,
        .total = @intCast(kind.count()),
        .identifierAt = kind.identifierAt,
        .isEnabled = kind.isEnabled,
    };
}

fn count(kind: Kind) usize {
    var it = names(kind);
    var n: usize = 0;
    while (it.next()) |_| n += 1;
    return n;
}

// The enabled liboqs identifier that equals `name` when ASCII case is
// ignored, as strcasecmp does. The match is done here over the whole slice,
// so a zero byte inside `name` is compared, not taken as the end. The
// identifier is returned, not `name`, so liboqs gets its own string.
fn enabledIdentifier(kind: Kind, name: []const u8) ?[*:0]const u8 {
    var it = names(kind);
    while (it.next()) |candidate| {
        if (std.ascii.eqlIgnoreCase(candidate, name)) return candidate.ptr;
    }
    return null;
}

// liboqs sets method_name and alg_version to string literals in each
// algorithm's constructor (for example `kem->alg_version = "FIPS203"` in
// kem_ml_kem_768.c), so the slice stays valid after the object is freed.
fn staticString(pointer: [*c]const u8) [:0]const u8 {
    return std.mem.span(@as([*:0]const u8, pointer));
}
