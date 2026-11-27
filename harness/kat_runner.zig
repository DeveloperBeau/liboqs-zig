//! The programs `kat_kem` and `kat_sig` of liboqs, driven through the Zig wrapper.
//!
//! Each run prints the same text as the C program. Key generation,
//! encapsulation, decapsulation, signing and verification go through the
//! runtime cores `oqs.Kem` and `oqs.Sig`. Only the random source is replaced
//! with the known-answer generator.
const std = @import("std");
const oqs = @import("oqs");
const KatText = @import("kat_text.zig").KatText;
const KatGenerator = @import("kat_generator.zig").KatGenerator;
const KatDigests = @import("kat_digests.zig").KatDigests;
const SignedMessageForm = @import("signed_message_form.zig").SignedMessageForm;

/// The runs of the two known-answer programs and their digests.
pub const KatRunner = struct {
    /// Why a run stopped. The wrapper errors pass through unchanged.
    pub const Error = oqs.OqsError || SignedMessageForm.Error || std.Io.Writer.Error || error{
        /// The signature scheme has no `sm` layout, as for SLH-DSA.
        NoSignedMessageForm,
        /// Decapsulation did not give the shared secret of encapsulation.
        SharedSecretsDiffer,
        /// The signature did not verify.
        SignatureRejected,
    };

    /// The message length of count `count`, in bytes: 33 times the number of counts so far.
    pub fn messageLength(count: usize) usize {
        return 33 * (count + 1);
    }

    /// The entropy that seeds the outer generator: the bytes 0 to 47.
    pub fn outerEntropy() [48]u8 {
        var entropy: [48]u8 = undefined;
        for (&entropy, 0..) |*byte, i| byte.* = @intCast(i);
        return entropy;
    }

    /// Writes the output of `kat_kem name` (or `kat_kem name --all`) to `w`.
    pub fn writeKem(allocator: std.mem.Allocator, w: *std.Io.Writer, name: [:0]const u8, mode: KatDigests.Mode) Error!void {
        var generator = KatGenerator.init(name);
        defer generator.deinit();
        var kem = try oqs.Kem.init(allocator, name);
        defer kem.deinit();

        generator.seed(&outerEntropy());
        const max_count: usize = if (mode == .all) KatGenerator.countsFor(name) else 1;
        var seed: [48]u8 = undefined;
        for (0..max_count) |count| {
            try KatText.writeCount(w, count);
            generator.fill(&seed);
            try KatText.writeBstr(w, "seed = ", &seed);

            generator.saveState();
            generator.seed(&seed);

            const pair = try kem.keypair();
            defer wipeAndFree(allocator, pair.secret_key);
            defer allocator.free(pair.public_key);
            try KatText.writeBstr(w, "pk = ", pair.public_key);
            try KatText.writeBstr(w, "sk = ", pair.secret_key);

            const encapsulated = try kem.encaps(pair.public_key);
            defer allocator.free(encapsulated.ciphertext);
            defer wipeAndFree(allocator, encapsulated.shared_secret);
            try KatText.writeBstr(w, "ct = ", encapsulated.ciphertext);
            try KatText.writeBstr(w, "ss = ", encapsulated.shared_secret);

            // The NIST program ends its response file with one newline.
            if (count != max_count - 1) try KatText.writeSeparator(w);

            const decapsulated = try kem.decaps(encapsulated.ciphertext, pair.secret_key);
            defer wipeAndFree(allocator, decapsulated);
            if (!std.mem.eql(u8, encapsulated.shared_secret, decapsulated)) return error.SharedSecretsDiffer;

            generator.restoreState();
        }
    }

    /// Writes the output of `kat_sig name` (or `kat_sig name --all`) to `w`.
    pub fn writeSig(allocator: std.mem.Allocator, w: *std.Io.Writer, name: [:0]const u8, mode: KatDigests.Mode) Error!void {
        var generator = KatGenerator.init(name);
        defer generator.deinit();
        var sig = try oqs.Sig.init(allocator, name);
        defer sig.deinit();
        const form = SignedMessageForm.of(name) orelse return error.NoSignedMessageForm;

        generator.seed(&outerEntropy());
        const max_count: usize = if (mode == .all) KatGenerator.countsFor(name) else 1;
        var seed: [48]u8 = undefined;
        for (0..max_count) |count| {
            try KatText.writeCount(w, count);
            generator.fill(&seed);
            try KatText.writeBstr(w, "seed = ", &seed);

            const message = try allocator.alloc(u8, messageLength(count));
            defer allocator.free(message);
            try KatText.writeLength(w, "mlen", message.len);
            generator.fill(message);
            try KatText.writeBstr(w, "msg = ", message);

            generator.saveState();
            generator.seed(&seed);

            const pair = try sig.keypair();
            defer wipeAndFree(allocator, pair.secret_key);
            defer allocator.free(pair.public_key);
            try KatText.writeBstr(w, "pk = ", pair.public_key);
            try KatText.writeBstr(w, "sk = ", pair.secret_key);

            const signature = try sig.sign(message, pair.secret_key);
            defer allocator.free(signature);
            const signed_message = try form.combine(allocator, message, signature);
            defer allocator.free(signed_message);
            try KatText.writeLength(w, "smlen", signed_message.len);
            try KatText.writeBstr(w, "sm = ", signed_message);

            if (count != max_count - 1) try KatText.writeSeparator(w);

            if (!try sig.verify(message, signature, pair.public_key)) return error.SignatureRejected;

            generator.restoreState();
        }
    }

    /// The SHA-256 of the output of `kat_kem name`.
    pub fn digestKem(allocator: std.mem.Allocator, name: [:0]const u8, mode: KatDigests.Mode) Error![32]u8 {
        var buffer: [4096]u8 = undefined;
        var hashing = std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256).init(&buffer);
        try writeKem(allocator, &hashing.writer, name, mode);
        return finish(&hashing);
    }

    /// The SHA-256 of the output of `kat_sig name`.
    pub fn digestSig(allocator: std.mem.Allocator, name: [:0]const u8, mode: KatDigests.Mode) Error![32]u8 {
        var buffer: [4096]u8 = undefined;
        var hashing = std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256).init(&buffer);
        try writeSig(allocator, &hashing.writer, name, mode);
        return finish(&hashing);
    }

    fn finish(hashing: *std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256)) Error![32]u8 {
        try hashing.writer.flush();
        return hashing.hasher.finalResult();
    }

    // The known-answer keys are public test values, but the harness wipes
    // them anyway, as the C program does with `OQS_MEM_secure_free`.
    fn wipeAndFree(allocator: std.mem.Allocator, bytes: []u8) void {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
};
