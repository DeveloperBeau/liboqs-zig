//! Plain data. This file imports only std.

/// What liboqs reports about one signature scheme, read from its `OQS_SIG` object.
///
/// The two strings point at static strings inside liboqs, so they live as long
/// as the program and need no freeing.
pub const SigDescription = struct {
    /// The liboqs name of the scheme, such as `ML-DSA-65`.
    name: [:0]const u8,
    /// The version of the implementation liboqs reports, such as `FIPS204`.
    algorithmVersion: [:0]const u8,
    /// The NIST security level, 1 to 5, that the original submission claims.
    claimedNistLevel: u8,
    /// True if the scheme is EUF-CMA secure.
    isEufCmaSecure: bool,
    /// True if the scheme is SUF-CMA secure.
    isSufCmaSecure: bool,
    /// True if liboqs can sign and verify with a context string for this scheme.
    supportsContext: bool,
    /// The length of a public key in bytes.
    publicKeyLength: usize,
    /// The length of a secret key in bytes.
    secretKeyLength: usize,
    /// The largest length of a signature in bytes.
    signatureLength: usize,
};
