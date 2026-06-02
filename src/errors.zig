pub const OqsError = error{
    AlgorithmNotAvailable,
    KeyGenerationFailed,
    EncapsulationFailed,
    DecapsulationFailed,
    SignFailed,
    VerifyFailed,
    InvalidKeySize,
    OutOfMemory,
};
