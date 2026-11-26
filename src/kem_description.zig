//! Plain data. This file imports only std.

/// What liboqs reports about one key encapsulation mechanism, read from its `OQS_KEM` object.
///
/// The two strings point at static strings inside liboqs, so they live as long
/// as the program and need no freeing.
pub const KemDescription = struct {
    /// The liboqs name of the mechanism, such as `ML-KEM-768`.
    name: [:0]const u8,
    /// The version of the implementation liboqs reports, such as `FIPS203`.
    algorithmVersion: [:0]const u8,
    /// The NIST security level, 1 to 5, that the original submission claims.
    claimedNistLevel: u8,
    /// True if the mechanism is IND-CCA secure, false if it is only IND-CPA secure.
    isIndCcaSecure: bool,
    /// The length of a public key in bytes.
    publicKeyLength: usize,
    /// The length of a secret key in bytes.
    secretKeyLength: usize,
    /// The length of a ciphertext in bytes.
    ciphertextLength: usize,
    /// The length of a shared secret in bytes.
    sharedSecretLength: usize,
    /// The length in bytes of the seed for seeded key pair generation, or 0 when the mechanism has none.
    keyPairSeedLength: usize,
    /// The length in bytes of the seed for seeded encapsulation, or 0 when the mechanism has none.
    encapsulationSeedLength: usize,
};
