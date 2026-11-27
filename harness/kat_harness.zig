//! The known-answer harness. The program `kat` and `tests/kat.zig` both
//! import this module, so there is one copy of each rule.
//!
//! The two digest files are the `kats.json` files of the hash-pinned liboqs
//! dependency, embedded at build time, so they cannot drift from `LIBOQS_VERSION`.

/// The text of `tests/KATs/kem/kats.json` in liboqs.
pub const kem_kats_json = @embedFile("kem_kats_json");
/// The text of `tests/KATs/sig/kats.json` in liboqs.
pub const sig_kats_json = @embedFile("sig_kats_json");

pub const KatText = @import("kat_text.zig").KatText;
pub const SignedMessageForm = @import("signed_message_form.zig").SignedMessageForm;
pub const KatGenerator = @import("kat_generator.zig").KatGenerator;
pub const KatDigests = @import("kat_digests.zig").KatDigests;
pub const KatRunner = @import("kat_runner.zig").KatRunner;
pub const KatReport = @import("kat_report.zig").KatReport;
