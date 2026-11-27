//! The random generators of the liboqs known-answer programs.
//!
//! `tests/test_helpers.c` gives HQC a SHAKE256 generator and every other
//! algorithm the NIST DRBG. The harness replaces the liboqs random source
//! with the chosen generator. It calls liboqs C directly for this, as the
//! library wrapper has no part in choosing a random source.
const std = @import("std");
const oqs = @import("oqs");
const c = @import("c_api");

// The SHAKE256 state of the HQC generator. liboqs keeps the same state as
// file-level data in test_helpers.c, because the random source callback has
// no context argument.
var hqc_state: c.OQS_SHA3_shake256_inc_ctx = .{ .ctx = null };

fn hqcRandomBytes(out: [*c]u8, len: usize) callconv(.c) void {
    c.OQS_SHA3_shake256_inc_squeeze(out, len, &hqc_state);
}

/// A generator of one known-answer run, with room to save and restore its state.
pub const KatGenerator = struct {
    /// Which generator an algorithm uses.
    pub const Kind = enum {
        /// The NIST DRBG, used by every algorithm except HQC.
        nist_drbg,
        /// SHAKE256 of the seed and a zero domain byte, used by HQC.
        hqc_shake256,
    };

    /// The number of counts of the `all` run of most algorithms.
    pub const default_counts: usize = 100;
    /// The number of counts of the `all` run of Classic McEliece.
    pub const mceliece_counts: usize = 10;

    kind: Kind,
    saved_nist: c.OQS_NIST_DRBG_struct = undefined,
    saved_hqc: c.OQS_SHA3_shake256_inc_ctx = .{ .ctx = null },

    /// The generator `name` uses. Only the three HQC names use SHAKE256.
    pub fn kindFor(name: []const u8) Kind {
        const hqc = [_][]const u8{ "HQC-1", "HQC-3", "HQC-5" };
        for (hqc) |hqc_name| {
            if (std.mem.eql(u8, name, hqc_name)) return .hqc_shake256;
        }
        return .nist_drbg;
    }

    /// The number of counts of the `all` run of `name`.
    ///
    /// Classic McEliece keys are large, so its run has 10 counts.
    pub fn countsFor(name: []const u8) usize {
        if (std.mem.startsWith(u8, name, "Classic-McEliece-")) return mceliece_counts;
        return default_counts;
    }

    /// Makes `name`'s generator the liboqs random source. Call `seed` before use.
    pub fn init(name: []const u8) KatGenerator {
        const kind = kindFor(name);
        switch (kind) {
            .nist_drbg => c.OQS_randombytes_custom_algorithm(c.OQS_randombytes_nist_kat),
            .hqc_shake256 => {
                c.OQS_randombytes_custom_algorithm(&hqcRandomBytes);
                c.OQS_SHA3_shake256_inc_init(&hqc_state);
            },
        }
        var generator = KatGenerator{ .kind = kind };
        if (kind == .hqc_shake256) c.OQS_SHA3_shake256_inc_init(&generator.saved_hqc);
        return generator;
    }

    /// Releases the generator state and gives the liboqs random source back to the system.
    pub fn deinit(self: *KatGenerator) void {
        if (self.kind == .hqc_shake256) {
            c.OQS_SHA3_shake256_inc_ctx_release(&self.saved_hqc);
            c.OQS_SHA3_shake256_inc_ctx_release(&hqc_state);
            hqc_state.ctx = null;
        }
        _ = c.OQS_randombytes_switch_algorithm(c.OQS_RAND_alg_system);
        self.* = undefined;
    }

    /// Starts the generator from 48 bytes of entropy, as `OQS_KAT_PRNG_seed` does.
    pub fn seed(self: *KatGenerator, entropy: *const [48]u8) void {
        switch (self.kind) {
            .nist_drbg => oqs.testing.seedKat(entropy),
            .hqc_shake256 => {
                const domain: u8 = 0;
                c.OQS_SHA3_shake256_inc_ctx_reset(&hqc_state);
                c.OQS_SHA3_shake256_inc_absorb(&hqc_state, entropy, 48);
                c.OQS_SHA3_shake256_inc_absorb(&hqc_state, &domain, 1);
                c.OQS_SHA3_shake256_inc_finalize(&hqc_state);
            },
        }
    }

    /// Draws bytes from the generator through the liboqs random source.
    pub fn fill(self: *KatGenerator, out: []u8) void {
        _ = self;
        c.OQS_randombytes(out.ptr, out.len);
    }

    /// Keeps the current state, so `restoreState` can return to it.
    pub fn saveState(self: *KatGenerator) void {
        switch (self.kind) {
            .nist_drbg => c.OQS_randombytes_nist_kat_get_state(&self.saved_nist),
            .hqc_shake256 => c.OQS_SHA3_shake256_inc_ctx_clone(&self.saved_hqc, &hqc_state),
        }
    }

    /// Returns to the state that `saveState` kept.
    pub fn restoreState(self: *KatGenerator) void {
        switch (self.kind) {
            .nist_drbg => c.OQS_randombytes_nist_kat_set_state(&self.saved_nist),
            .hqc_shake256 => c.OQS_SHA3_shake256_inc_ctx_clone(&hqc_state, &self.saved_hqc),
        }
    }
};
