//! The known-answer harness. The program `kat` and `tests/kat.zig` both
//! import this module, so there is one copy of each rule.
//!
//! The two digest files are the `kats.json` files of the hash-pinned liboqs
//! dependency, embedded at build time, so they cannot drift from `LIBOQS_VERSION`.

/// The text of `tests/KATs/kem/kats.json` in liboqs.
pub const kem_kats_json = @embedFile("kem_kats_json");
/// The text of `tests/KATs/sig/kats.json` in liboqs.
pub const sig_kats_json = @embedFile("sig_kats_json");

/// The line printers of the known-answer text.
pub const KatText = @import("kat_text.zig").KatText;
/// The layout of the signed message `sm` that `kat_sig` prints.
pub const SignedMessageForm = @import("signed_message_form.zig").SignedMessageForm;
/// The random generators of the known-answer programs.
pub const KatGenerator = @import("kat_generator.zig").KatGenerator;
/// The expected digests of a `kats.json` file.
pub const KatDigests = @import("kat_digests.zig").KatDigests;
/// The runs of `kat_kem` and `kat_sig` through the wrapper.
pub const KatRunner = @import("kat_runner.zig").KatRunner;
/// The result lines of a run and the check that reads them back.
pub const KatReport = @import("kat_report.zig").KatReport;
