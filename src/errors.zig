//! The errors the wrapper returns, and a short text for each one.
//! This file is plain data. It imports only std.
const std = @import("std");

/// Every error a liboqs-zig operation can return.
///
/// Zig errors carry no payload, so `InvalidKeySize` does not hold the expected
/// and actual lengths.
pub const OqsError = error{
    /// The algorithm name is not one this build of liboqs has.
    AlgorithmNotAvailable,
    /// liboqs failed to generate a key pair.
    KeyGenerationFailed,
    /// liboqs failed to encapsulate a shared secret.
    EncapsulationFailed,
    /// liboqs failed to decapsulate a shared secret.
    DecapsulationFailed,
    /// liboqs returned an error status while signing, so no signature is handed back.
    SignFailed,
    /// liboqs failed to verify a signature.
    VerifyFailed,
    /// A key, ciphertext or signature has the wrong length for the algorithm, or belongs to another algorithm.
    InvalidKeySize,
    /// The allocator could not provide the memory an operation needs.
    OutOfMemory,
    /// The algorithm does not take a context string.
    ///
    /// `signWithContext` returns it for a non-empty context on an algorithm
    /// without context support, such as Falcon or MAYO.
    ContextNotSupported,
    /// The context string is longer than the algorithm allows.
    ///
    /// `signWithContext` returns it for a context over 255 bytes on ML-DSA
    /// or SLH-DSA.
    ContextTooLong,
    /// The algorithm has no form of the operation that takes a seed.
    ///
    /// Nothing returns it yet. It is declared so the set stays the same when
    /// seeded operations are added.
    SeedNotSupported,
    /// A stateful secret key has no signature left.
    ///
    /// A stateful `sign` returns it when liboqs reports success but writes no
    /// signature, which is what an LMS key does once it is used up.
    KeyExhausted,
    /// The advanced state of a stateful secret key was not saved, so no signature was handed back.
    ///
    /// Nothing returns it yet. The wrapper keeps the key state in memory and
    /// its store step always succeeds. It is declared so the set stays the
    /// same when a storage step is added.
    PersistenceFailed,
};

/// A short plain text that says what went wrong, for logs and messages.
///
/// The texts follow the Swift and Rust ports where those agree. They hold no
/// key material and no lengths.
pub fn describeError(err: OqsError) []const u8 {
    // No else branch, so a new member fails the build here until it has a text.
    return switch (err) {
        error.AlgorithmNotAvailable => "Algorithm not available",
        error.KeyGenerationFailed => "Key generation failed",
        error.EncapsulationFailed => "KEM encapsulation failed",
        error.DecapsulationFailed => "KEM decapsulation failed",
        error.SignFailed => "Signature generation failed",
        error.VerifyFailed => "Signature verification failed",
        error.InvalidKeySize => "Invalid key size",
        error.OutOfMemory => "Out of memory",
        error.ContextNotSupported => "The algorithm does not take a context string",
        error.ContextTooLong => "The context string is too long",
        error.SeedNotSupported => "The algorithm has no form of the operation that takes a seed",
        error.KeyExhausted => "The secret key has no signature left",
        error.PersistenceFailed => "The advanced secret key was not saved",
    };
}

// Written out by hand, one row per member, so a changed text fails here.
const expected_texts = [_]struct { err: OqsError, text: []const u8 }{
    .{ .err = error.AlgorithmNotAvailable, .text = "Algorithm not available" },
    .{ .err = error.KeyGenerationFailed, .text = "Key generation failed" },
    .{ .err = error.EncapsulationFailed, .text = "KEM encapsulation failed" },
    .{ .err = error.DecapsulationFailed, .text = "KEM decapsulation failed" },
    .{ .err = error.SignFailed, .text = "Signature generation failed" },
    .{ .err = error.VerifyFailed, .text = "Signature verification failed" },
    .{ .err = error.InvalidKeySize, .text = "Invalid key size" },
    .{ .err = error.OutOfMemory, .text = "Out of memory" },
    .{ .err = error.ContextNotSupported, .text = "The algorithm does not take a context string" },
    .{ .err = error.ContextTooLong, .text = "The context string is too long" },
    .{ .err = error.SeedNotSupported, .text = "The algorithm has no form of the operation that takes a seed" },
    .{ .err = error.KeyExhausted, .text = "The secret key has no signature left" },
    .{ .err = error.PersistenceFailed, .text = "The advanced secret key was not saved" },
};

test "OqsError has exactly the 13 hand-listed members" {
    const members = @typeInfo(OqsError).error_set.error_names.?;
    try std.testing.expectEqual(@as(usize, 13), members.len);
    try std.testing.expectEqual(members.len, expected_texts.len);
    for (members) |member| {
        var listed = false;
        for (expected_texts) |row| {
            if (std.mem.eql(u8, member, @errorName(row.err))) listed = true;
        }
        try std.testing.expect(listed);
    }
}

test "describeError gives each member its hand-written text" {
    for (expected_texts) |row| {
        try std.testing.expectEqualStrings(row.text, describeError(row.err));
    }
}

test "describeError gives every member a non-empty text that no other member shares" {
    for (expected_texts, 0..) |a, i| {
        try std.testing.expect(describeError(a.err).len > 0);
        for (expected_texts[i + 1 ..]) |b| {
            try std.testing.expect(!std.mem.eql(u8, describeError(a.err), describeError(b.err)));
        }
    }
}
