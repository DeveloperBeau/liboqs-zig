//! Plain data. This file imports only std.

/// What liboqs reports about one stateful signature scheme, read from its `OQS_SIG_STFL` object.
///
/// The two strings point at static strings inside liboqs, so they live as long
/// as the program and need no freeing. liboqs keeps no NIST level for these
/// schemes, so there is none here.
pub const SigStflDescription = struct {
    /// The numeric identifier liboqs gives the parameter set (the XMSS OID or the LMS type code).
    objectIdentifier: u32,
    /// The liboqs name of the scheme, such as `LMS_SHA256_H5_W8`.
    name: [:0]const u8,
    /// The version of the implementation liboqs reports, which for these schemes is the RFC address.
    algorithmVersion: [:0]const u8,
    /// True if the scheme is EUF-CMA secure.
    isEufCmaSecure: bool,
    /// True if the scheme is SUF-CMA secure.
    isSufCmaSecure: bool,
    /// The length of a public key in bytes.
    publicKeyLength: usize,
    /// The length of a serialized secret key in bytes.
    secretKeyLength: usize,
    /// The length of a signature in bytes.
    signatureLength: usize,
};
