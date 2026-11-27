//! Tests for the known-answer harness: the text lines, the signed message
//! layouts, the generator choice, the `kats.json` reader, the report and the
//! runs themselves.
//!
//! Every expected value is written out by hand. The known-answer text and the
//! digests come from running the liboqs C programs `kat_kem` and `kat_sig`
//! once, and from `tests/KATs/*/kats.json` of liboqs 0.16.0. The runs seed the
//! KAT RNG, so this module has its own binary. Test output never includes
//! secret key bytes.
const std = @import("std");
const oqs = @import("oqs");
const harness = @import("kat_harness");
const build_options = @import("build_options");

const KatText = harness.KatText;
const SignedMessageForm = harness.SignedMessageForm;
const KatGenerator = harness.KatGenerator;
const KatDigests = harness.KatDigests;
const KatRunner = harness.KatRunner;
const KatReport = harness.KatReport;

const a = std.testing.allocator;

// Hand-copied from liboqs 0.16.0 tests/KATs/kem/kats.json and sig/kats.json.
const ml_kem_512_single = "c70041a761e01cd6426fa60e9fd6a4412c2be817386c8d0f3334898082512782";
const ml_kem_512_all = "74b470e797cbdbd589a31d387d36c72aad5033446ab5159bf4014c24652b1173";
const hqc_1_single = "0f1f4fd014b32492ec6490d2ad9e9f75ccc0c2b27d72f34918c7f73f9698c2e4";
const ml_dsa_44_single = "9a196e7fb32fbc93757dc2d8dc1924460eab66303c0c08aeb8b798fb8d8f8cf3";
const falcon_512_single = "da27fe8a462de7307ddf1f9b00072a457d9c5b14e838c148fbe2662094b9a2ca";
const cross_rsdp_128_fast_single = "0e4818ec4a37211a00b475583d3b3104db68ad59f4434811ce99fdb5aa72a865";

fn hexOf(digest: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(digest, .lower);
}

fn kemText(name: [:0]const u8, mode: KatDigests.Mode) !std.Io.Writer.Allocating {
    var aw: std.Io.Writer.Allocating = .init(a);
    errdefer aw.deinit();
    try KatRunner.writeKem(a, &aw.writer, name, mode);
    return aw;
}

// --- Text lines --------------------------------------------------------------

test "a byte string prints as upper-case hexadecimal after its label, as written out by hand" {
    var buf: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try KatText.writeBstr(&w, "pk = ", &[_]u8{ 0x00, 0x0A, 0xFF, 0xab, 0x5c });
    try std.testing.expectEqualStrings("pk = 000AFFAB5C\n", w.buffered());
}

test "an empty byte string prints as 00, as OQS_fprintBstr does" {
    var buf: [32]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try KatText.writeBstr(&w, "msg = ", "");
    try std.testing.expectEqualStrings("msg = 00\n", w.buffered());
}

test "a byte string longer than the print chunk keeps every byte in order" {
    const bytes = try a.alloc(u8, 600);
    defer a.free(bytes);
    for (bytes, 0..) |*b, i| b.* = @intCast(i % 256);
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    try KatText.writeBstr(&aw.writer, "x = ", bytes);
    const text = aw.written();
    try std.testing.expectEqual(@as(usize, 4 + 1200 + 1), text.len);
    try std.testing.expectEqualStrings("x = 000102030405", text[0..16]);
    // Byte 255 is at hex offset 510 and byte 256 wraps to 00.
    try std.testing.expectEqualStrings("FE" ++ "FF" ++ "00" ++ "01", text[4 + 508 .. 4 + 516]);
    try std.testing.expectEqualStrings("\n", text[text.len - 1 ..]);
}

test "count, length and separator lines match the C program text" {
    var buf: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try KatText.writeCount(&w, 7);
    try KatText.writeLength(&w, "mlen", 66);
    try KatText.writeLength(&w, "smlen", 2453);
    try KatText.writeSeparator(&w);
    try std.testing.expectEqualStrings("count = 7\nmlen = 66\nsmlen = 2453\n\n", w.buffered());
}

// --- Signed message layouts --------------------------------------------------

test "the signed message layout is chosen by scheme name, one scheme of each form as written out by hand" {
    try std.testing.expectEqual(SignedMessageForm.signature_then_message, SignedMessageForm.of("ML-DSA-44").?);
    try std.testing.expectEqual(SignedMessageForm.signature_then_message, SignedMessageForm.of("Falcon-padded-512").?);
    try std.testing.expectEqual(SignedMessageForm.signature_then_message, SignedMessageForm.of("MAYO-1").?);
    try std.testing.expectEqual(SignedMessageForm.signature_then_message, SignedMessageForm.of("SNOVA_24_5_4_SHAKE_esk").?);
    try std.testing.expectEqual(SignedMessageForm.message_then_signature, SignedMessageForm.of("cross-rsdp-128-fast").?);
    try std.testing.expectEqual(SignedMessageForm.message_then_signature, SignedMessageForm.of("cross-rsdpg-256-small").?);
    try std.testing.expectEqual(SignedMessageForm.message_then_signature, SignedMessageForm.of("OV-Is-pkc-skc").?);
    try std.testing.expectEqual(SignedMessageForm.message_then_signature, SignedMessageForm.of("mqom2_cat1_gf16_fast_r3").?);
    try std.testing.expectEqual(SignedMessageForm.falcon_512, SignedMessageForm.of("Falcon-512").?);
    try std.testing.expectEqual(SignedMessageForm.falcon_1024, SignedMessageForm.of("Falcon-1024").?);
}

test "a scheme that kat_sig has no layout for, such as SLH-DSA or an unknown name, has none here" {
    try std.testing.expect(SignedMessageForm.of("SLH_DSA_PURE_SHA2_128F") == null);
    try std.testing.expect(SignedMessageForm.of("SLH_DSA_SHAKE_256_PREHASH_SHAKE_256S") == null);
    try std.testing.expect(SignedMessageForm.of("ML-KEM-512") == null);
    try std.testing.expect(SignedMessageForm.of("") == null);
    // Falcon-512 and Falcon-1024 are exact names, so no other Falcon name takes their layout.
    try std.testing.expect(SignedMessageForm.of("Falcon-5120") == null);
}

test "signature then message puts the signature first, message then signature puts the message first" {
    const sm1 = try SignedMessageForm.signature_then_message.combine(a, "MSG", "SIGNATURE");
    defer a.free(sm1);
    try std.testing.expectEqualStrings("SIGNATUREMSG", sm1);
    const sm2 = try SignedMessageForm.message_then_signature.combine(a, "MSG", "SIGNATURE");
    defer a.free(sm2);
    try std.testing.expectEqualStrings("MSGSIGNATURE", sm2);
}

test "the Falcon-512 layout is length, salt, message, 0x29 and the rest, as written out by hand" {
    // Header byte 0x39, a 40-byte salt of 0x11 and a 3-byte rest.
    var signature: [44]u8 = undefined;
    signature[0] = 0x39;
    @memset(signature[1..41], 0x11);
    signature[41..44].* = .{ 0xA1, 0xA2, 0xA3 };
    const sm = try SignedMessageForm.falcon_512.combine(a, "hi", &signature);
    defer a.free(sm);
    // 2 + 40 + 2 + 1 + 3 = 48 bytes. The length is 44 - 40 = 4.
    var expected: [48]u8 = undefined;
    expected[0..2].* = .{ 0x00, 0x04 };
    @memset(expected[2..42], 0x11);
    expected[42..44].* = .{ 'h', 'i' };
    expected[44] = 0x29;
    expected[45..48].* = .{ 0xA1, 0xA2, 0xA3 };
    try std.testing.expectEqualSlices(u8, &expected, sm);
}

test "the Falcon-1024 layout differs from Falcon-512 only in the tag byte 0x2A" {
    var signature: [41]u8 = undefined;
    signature[0] = 0x3A;
    @memset(signature[1..41], 0x22);
    const sm = try SignedMessageForm.falcon_1024.combine(a, "m", &signature);
    defer a.free(sm);
    // A signature of 41 bytes has an empty rest and a length of 1.
    var expected: [2 + 40 + 1 + 1]u8 = undefined;
    expected[0..2].* = .{ 0x00, 0x01 };
    @memset(expected[2..42], 0x22);
    expected[42] = 'm';
    expected[43] = 0x2A;
    try std.testing.expectEqualSlices(u8, &expected, sm);
}

test "a Falcon signature shorter than its header and salt is refused, not read past its end" {
    const short: [40]u8 = @splat(0);
    try std.testing.expectError(error.SignatureTooShort, SignedMessageForm.falcon_512.combine(a, "m", &short));
    try std.testing.expectError(error.SignatureTooShort, SignedMessageForm.falcon_1024.combine(a, "m", &short));
}

// --- Generator choice --------------------------------------------------------

test "HQC uses the SHAKE256 generator and every other algorithm the NIST DRBG, as written out by hand" {
    try std.testing.expectEqual(KatGenerator.Kind.hqc_shake256, KatGenerator.kindFor("HQC-1"));
    try std.testing.expectEqual(KatGenerator.Kind.hqc_shake256, KatGenerator.kindFor("HQC-3"));
    try std.testing.expectEqual(KatGenerator.Kind.hqc_shake256, KatGenerator.kindFor("HQC-5"));
    try std.testing.expectEqual(KatGenerator.Kind.nist_drbg, KatGenerator.kindFor("ML-KEM-512"));
    try std.testing.expectEqual(KatGenerator.Kind.nist_drbg, KatGenerator.kindFor("BIKE-L1"));
    try std.testing.expectEqual(KatGenerator.Kind.nist_drbg, KatGenerator.kindFor("Classic-McEliece-348864"));
    try std.testing.expectEqual(KatGenerator.Kind.nist_drbg, KatGenerator.kindFor("ML-DSA-44"));
    try std.testing.expectEqual(KatGenerator.Kind.nist_drbg, KatGenerator.kindFor("hqc-1"));
}

test "exactly the three enabled HQC names pick the SHAKE256 generator" {
    var names = oqs.Registry.kemNames();
    var shake: usize = 0;
    while (names.next()) |name| {
        const is_hqc = std.mem.startsWith(u8, name, "HQC");
        try std.testing.expectEqual(is_hqc, KatGenerator.kindFor(name) == .hqc_shake256);
        if (is_hqc) shake += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), shake);
}

test "Classic McEliece has 10 counts and every other algorithm 100, as written out by hand" {
    const mceliece = [_][]const u8{
        "Classic-McEliece-348864",  "Classic-McEliece-348864f",
        "Classic-McEliece-460896",  "Classic-McEliece-460896f",
        "Classic-McEliece-6688128", "Classic-McEliece-6688128f",
        "Classic-McEliece-6960119", "Classic-McEliece-6960119f",
        "Classic-McEliece-8192128", "Classic-McEliece-8192128f",
    };
    for (mceliece) |name| try std.testing.expectEqual(@as(usize, 10), KatGenerator.countsFor(name));
    try std.testing.expectEqual(@as(usize, 100), KatGenerator.countsFor("ML-KEM-512"));
    try std.testing.expectEqual(@as(usize, 100), KatGenerator.countsFor("HQC-1"));
    try std.testing.expectEqual(@as(usize, 100), KatGenerator.countsFor("ML-DSA-44"));
    // The enabled McEliece names are exactly those ten.
    var names = oqs.Registry.kemNames();
    var found: usize = 0;
    while (names.next()) |name| {
        if (KatGenerator.countsFor(name) == 10) found += 1;
    }
    try std.testing.expectEqual(@as(usize, 10), found);
}

fn expectBytes(expected_hex: []const u8, actual: []const u8) !void {
    var want: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, expected_hex);
    try std.testing.expectEqualSlices(u8, want[0..actual.len], actual);
}

test "the NIST DRBG seeded with the bytes 0 to 47 gives the first KAT seed of the NIST files" {
    var generator = KatGenerator.init("ML-KEM-512");
    defer generator.deinit();
    generator.seed(&KatRunner.outerEntropy());
    var out: [48]u8 = undefined;
    generator.fill(&out);
    try expectBytes("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", &out);
}

test "the HQC generator seeded with the bytes 0 to 47 gives the first HQC seed, which differs from the NIST DRBG" {
    var generator = KatGenerator.init("HQC-1");
    defer generator.deinit();
    generator.seed(&KatRunner.outerEntropy());
    var out: [48]u8 = undefined;
    generator.fill(&out);
    try expectBytes("9EF877FDDBE8891C6E4E79EAF022E563DEFACA6B152161B9A423E8FE96A403E774B2D352CF74C934069C9DE74757F505", &out);
}

test "restoring a saved state repeats the bytes drawn after it, for both generators" {
    for ([_][]const u8{ "ML-KEM-512", "HQC-1" }) |name| {
        var generator = KatGenerator.init(name);
        defer generator.deinit();
        generator.seed(&KatRunner.outerEntropy());
        var first: [16]u8 = undefined;
        generator.fill(&first);
        generator.saveState();
        var second: [16]u8 = undefined;
        generator.fill(&second);
        generator.restoreState();
        var again: [16]u8 = undefined;
        generator.fill(&again);
        try std.testing.expectEqualSlices(u8, &second, &again);
        try std.testing.expect(!std.mem.eql(u8, &first, &second));
    }
}

// --- kats.json reader --------------------------------------------------------

const digest_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
// A 64-character digest text of one repeated character.
fn filled(comptime ch: u8) *const [64]u8 {
    const out: [64]u8 = @splat(ch);
    return &out;
}

const zero_digest = filled('0');
const upper_digest = filled('A');
const non_hex_digest = filled('g');
const digest_b = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

test "the reader returns the two digests of each named entry" {
    var digests = try KatDigests.parse(a,
        \\{ "X-1": { "all": "
    ++ digest_a ++
        \\", "single": "
    ++ digest_b ++
        \\" },
        \\  "Y-2": { "single": "
    ++ digest_a ++
        \\", "all": "
    ++ digest_b ++
        \\" } }
    );
    defer digests.deinit();
    try std.testing.expectEqual(@as(usize, 2), digests.count());
    try std.testing.expectEqualStrings("X-1", digests.nameAt(0));
    try std.testing.expectEqualStrings(digest_a, &digests.find("X-1").?.all);
    try std.testing.expectEqualStrings(digest_b, &digests.find("X-1").?.single);
    try std.testing.expectEqualStrings(digest_a, &digests.find("Y-2").?.single);
    try std.testing.expectEqualStrings(digest_b, &digests.find("Y-2").?.all);
    try std.testing.expect(digests.find("x-1") == null);
    try std.testing.expect(digests.find("X-") == null);
    try std.testing.expect(digests.find("") == null);
}

fn parseFails(expected: KatDigests.ParseError, text: []const u8) !void {
    try std.testing.expectError(expected, KatDigests.parse(a, text));
}

test "the reader refuses bad JSON, wrong shapes, bad digests and repeated names" {
    const good = "\"all\":\"" ++ digest_a ++ "\",\"single\":\"" ++ digest_b ++ "\"";
    try parseFails(error.SyntaxError, "");
    try parseFails(error.SyntaxError, "{");
    try parseFails(error.SyntaxError, "{\"X\":{" ++ good);
    try parseFails(error.UnexpectedShape, "[]");
    try parseFails(error.UnexpectedShape, "{\"X\":1}");
    try parseFails(error.UnexpectedShape, "{\"X\":{\"single\":\"" ++ digest_b ++ "\"}}");
    try parseFails(error.UnexpectedShape, "{\"X\":{" ++ good ++ ",\"extra\":\"" ++ digest_a ++ "\"}}");
    try parseFails(error.UnexpectedShape, "{\"X\":{\"all\":1,\"single\":\"" ++ digest_b ++ "\"}}");
    try parseFails(error.InvalidDigest, "{\"X\":{\"all\":\"" ++ digest_a[1..] ++ "\",\"single\":\"" ++ digest_b ++ "\"}}");
    try parseFails(error.InvalidDigest, "{\"X\":{\"all\":\"" ++ upper_digest ++ "\",\"single\":\"" ++ digest_b ++ "\"}}");
    try parseFails(error.InvalidDigest, "{\"X\":{\"all\":\"" ++ non_hex_digest ++ "\",\"single\":\"" ++ digest_b ++ "\"}}");
    try parseFails(error.DuplicateName, "{\"X\":{" ++ good ++ "},\"X\":{" ++ good ++ "}}");
    try parseFails(error.DuplicateName, "{\"X\":{\"all\":\"" ++ digest_a ++ "\",\"all\":\"" ++ digest_a ++ "\"}}");
}

test "an entry matches only the digest it holds for the chosen mode" {
    var single: [32]u8 = undefined;
    var all: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&single, digest_b);
    _ = try std.fmt.hexToBytes(&all, digest_a);
    const entry = KatDigests.Entry{ .single = digest_b.*, .all = digest_a.* };
    try std.testing.expect(entry.matches(.single, single));
    try std.testing.expect(entry.matches(.all, all));
    try std.testing.expect(!entry.matches(.single, all));
    try std.testing.expect(!entry.matches(.all, single));
    var flipped = single;
    flipped[31] ^= 1;
    try std.testing.expect(!entry.matches(.single, flipped));
}

test "OQS_KAT_ALL picks the all digests only when it is exactly 1" {
    try std.testing.expectEqual(KatDigests.Mode.single, KatDigests.Mode.fromFlag(null));
    try std.testing.expectEqual(KatDigests.Mode.single, KatDigests.Mode.fromFlag(""));
    try std.testing.expectEqual(KatDigests.Mode.single, KatDigests.Mode.fromFlag("0"));
    try std.testing.expectEqual(KatDigests.Mode.single, KatDigests.Mode.fromFlag("11"));
    try std.testing.expectEqual(KatDigests.Mode.all, KatDigests.Mode.fromFlag("1"));
}

test "the upstream files hold 41 KEM entries and 65 signature entries, as written out by hand" {
    var kem = try KatDigests.parse(a, harness.kem_kats_json);
    defer kem.deinit();
    var sig = try KatDigests.parse(a, harness.sig_kats_json);
    defer sig.deinit();
    try std.testing.expectEqual(@as(usize, 41), kem.count());
    try std.testing.expectEqual(@as(usize, 65), sig.count());
    try std.testing.expectEqualStrings(ml_kem_512_single, &kem.find("ML-KEM-512").?.single);
    try std.testing.expectEqualStrings(ml_kem_512_all, &kem.find("ML-KEM-512").?.all);
    try std.testing.expectEqualStrings(hqc_1_single, &kem.find("HQC-1").?.single);
    try std.testing.expectEqualStrings(ml_dsa_44_single, &sig.find("ML-DSA-44").?.single);
    try std.testing.expectEqualStrings(falcon_512_single, &sig.find("Falcon-512").?.single);
    try std.testing.expectEqualStrings(cross_rsdp_128_fast_single, &sig.find("cross-rsdp-128-fast").?.single);
}

// --- Which enabled algorithms have an entry ----------------------------------

test "every enabled KEM has an entry and every enabled signature has one except the 156 SLH-DSA schemes, as written out by hand" {
    var kem = try KatDigests.parse(a, harness.kem_kats_json);
    defer kem.deinit();
    var sig = try KatDigests.parse(a, harness.sig_kats_json);
    defer sig.deinit();

    var kems = oqs.Registry.kemNames();
    var kems_with: usize = 0;
    var kems_without: usize = 0;
    while (kems.next()) |name| {
        if (kem.find(name) != null) kems_with += 1 else kems_without += 1;
    }
    try std.testing.expectEqual(@as(usize, 41), kems_with);
    try std.testing.expectEqual(@as(usize, 0), kems_without);

    var sigs = oqs.Registry.sigNames();
    var sigs_with: usize = 0;
    var sigs_without: usize = 0;
    while (sigs.next()) |name| {
        if (sig.find(name) != null) {
            sigs_with += 1;
            // An entry always comes with a layout.
            try std.testing.expect(SignedMessageForm.of(name) != null);
        } else {
            sigs_without += 1;
            // The schemes without an entry are the SLH-DSA schemes, which liboqs tests with ACVP vectors.
            try std.testing.expect(std.mem.startsWith(u8, name, "SLH_DSA_"));
            try std.testing.expect(SignedMessageForm.of(name) == null);
        }
    }
    try std.testing.expectEqual(@as(usize, 65), sigs_with);
    try std.testing.expectEqual(@as(usize, 156), sigs_without);

    // No entry of either file names an algorithm this build leaves out.
    for (0..kem.count()) |i| try std.testing.expect(oqs.Registry.isKemEnabled(kem.nameAt(i)));
    for (0..sig.count()) |i| try std.testing.expect(oqs.Registry.isSigEnabled(sig.nameAt(i)));
}

// --- Known-answer text -------------------------------------------------------

test "ML-KEM-512 count 0 starts with the count, the NIST seed and the first public key bytes, as printed by kat_kem" {
    var text = try kemText("ML-KEM-512", .single);
    defer text.deinit();
    try std.testing.expect(std.mem.startsWith(u8, text.written(), "count = 0\n" ++
        "seed = 061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1\n" ++
        "pk = 400865ED10B619AA5811139BC086825782B2B7124F757C83AE794444BC78A4789"));
    // The five fields end with the shared secret and a single newline, with no blank line.
    try std.testing.expect(std.mem.endsWith(u8, text.written(), "\nss = B4C8E3C4115F9511F2FDDB288C4B78C5CD7C89D2D4D321F46B4EDC54DDF0EB36\n"));
    try std.testing.expect(!std.mem.endsWith(u8, text.written(), "\n\n"));
}

test "HQC-1 count 0 starts with the SHAKE256 seed, not the NIST seed" {
    var text = try kemText("HQC-1", .single);
    defer text.deinit();
    try std.testing.expect(std.mem.startsWith(u8, text.written(), "count = 0\n" ++
        "seed = 9EF877FDDBE8891C6E4E79EAF022E563DEFACA6B152161B9A423E8FE96A403E774B2D352CF74C934069C9DE74757F505\n" ++
        "pk = 4053237912EA281C51C4456A5096589EC9D20219651E00F9704178F0CF84F9AE0"));
}

test "ML-DSA-44 count 0 starts with the seed, a 33-byte message and ends with the message, as printed by kat_sig" {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    try KatRunner.writeSig(a, &aw.writer, "ML-DSA-44", .single);
    const text = aw.written();
    try std.testing.expect(std.mem.startsWith(u8, text, "count = 0\n" ++
        "seed = 061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1\n" ++
        "mlen = 33\n" ++
        "msg = D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8\n" ++
        "pk = DC7BC9A2E0B6DC66823AE4FBDE971C0CFC46F9D96BBFBEEBB3470AE0A5A0139FDD6A6CE5BC7"));
    // The signature is 2420 bytes and the message 33, so smlen is 2453 and sm ends with the message.
    try std.testing.expect(std.mem.indexOf(u8, text, "\nsmlen = 2453\nsm = ") != null);
    try std.testing.expect(std.mem.endsWith(u8, text, "D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8\n"));
}

test "the all mode of ML-KEM-512 prints 100 counts with a blank line between them and none at the end" {
    var text = try kemText("ML-KEM-512", .all);
    defer text.deinit();
    const out = text.written();
    try std.testing.expect(std.mem.startsWith(u8, out, "count = 0\n"));
    try std.testing.expectEqual(@as(usize, 100), std.mem.count(u8, out, "count = "));
    try std.testing.expectEqual(@as(usize, 99), std.mem.count(u8, out, "\n\n"));
    try std.testing.expect(std.mem.indexOf(u8, out, "\n\ncount = 99\n") != null);
    try std.testing.expect(!std.mem.endsWith(u8, out, "\n\n"));
}

// --- Digests against liboqs --------------------------------------------------

fn expectDigest(expected: []const u8, digest: [32]u8) !void {
    const hex = hexOf(digest);
    try std.testing.expectEqualStrings(expected, &hex);
}

test "ML-KEM-512 single digest equals the kats.json value, through the NIST DRBG" {
    try expectDigest(ml_kem_512_single, try KatRunner.digestKem(a, "ML-KEM-512", .single));
}

test "ML-KEM-512 all digest equals the kats.json value, 100 counts with the inner generator re-seeded for each" {
    try expectDigest(ml_kem_512_all, try KatRunner.digestKem(a, "ML-KEM-512", .all));
}

test "HQC-1 single digest equals the kats.json value, through the SHAKE256 generator" {
    try expectDigest(hqc_1_single, try KatRunner.digestKem(a, "HQC-1", .single));
}

test "ML-DSA-44 single digest equals the kats.json value, with the signature first in the signed message" {
    try expectDigest(ml_dsa_44_single, try KatRunner.digestSig(a, "ML-DSA-44", .single));
}

test "cross-rsdp-128-fast single digest equals the kats.json value, with the message first in the signed message" {
    try expectDigest(cross_rsdp_128_fast_single, try KatRunner.digestSig(a, "cross-rsdp-128-fast", .single));
}

test "Falcon-512 single digest equals the kats.json value, with the Falcon signed message layout" {
    try expectDigest(falcon_512_single, try KatRunner.digestSig(a, "Falcon-512", .single));
}

test "a signature scheme with no signed message layout is an error, not an empty digest" {
    try std.testing.expectError(error.NoSignedMessageForm, KatRunner.digestSig(a, "SLH_DSA_PURE_SHA2_128F", .single));
}

test "an algorithm that is not enabled is an error from the wrapper" {
    try std.testing.expectError(oqs.OqsError.AlgorithmNotAvailable, KatRunner.digestKem(a, "NoSuchKem", .single));
}

test "a wrong expected digest is rejected and the true one accepted, with the output of the C program for ML-KEM-512" {
    var kem = try KatDigests.parse(a, harness.kem_kats_json);
    defer kem.deinit();
    const entry = kem.find("ML-KEM-512").?;
    const digest = try KatRunner.digestKem(a, "ML-KEM-512", .single);
    try std.testing.expect(entry.matches(.single, digest));
    // The all digest belongs to another output.
    try std.testing.expect(!entry.matches(.all, digest));
    // A digest with one flipped bit never matches.
    for (0..256) |bit| {
        var flipped = digest;
        flipped[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        try std.testing.expect(!entry.matches(.single, flipped));
    }
}

test "one changed byte anywhere in the ML-KEM-512 text changes the digest, so it never matches" {
    var text = try kemText("ML-KEM-512", .single);
    defer text.deinit();
    const out = text.written();
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, ml_kem_512_single);
    // The true text hashes to the expected digest.
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(out, &sha, .{});
    try std.testing.expectEqualSlices(u8, &want, &sha);
    const copy = try a.dupe(u8, out);
    defer a.free(copy);
    var prng = std.Random.DefaultPrng.init(build_options.fuzz_seed);
    for (0..200) |_| {
        const at = prng.random().uintLessThan(usize, copy.len);
        const old = copy[at];
        copy[at] = old ^ (1 + prng.random().uintLessThan(u8, 255));
        std.crypto.hash.sha2.Sha256.hash(copy, &sha, .{});
        try std.testing.expect(!std.mem.eql(u8, &want, &sha));
        copy[at] = old;
    }
    // Dropping the last byte, the newline, also changes it.
    std.crypto.hash.sha2.Sha256.hash(out[0 .. out.len - 1], &sha, .{});
    try std.testing.expect(!std.mem.eql(u8, &want, &sha));
}

// --- Report ------------------------------------------------------------------

const sample_kem_json = "{\"K-1\":{\"all\":\"" ++ digest_a ++ "\",\"single\":\"" ++ digest_b ++ "\"}," ++
    "\"K-2\":{\"all\":\"" ++ digest_b ++ "\",\"single\":\"" ++ digest_a ++ "\"}}";
const sample_sig_json = "{\"S-1\":{\"all\":\"" ++ digest_a ++ "\",\"single\":\"" ++ digest_b ++ "\"}}";

const ReportRun = struct {
    summary: KatReport.Summary,
    text: []u8,

    fn deinit(self: ReportRun) void {
        a.free(self.text);
    }
};

fn report(lines: []const u8, kems: []const []const u8, sigs: []const []const u8, mode: KatDigests.Mode, filtered: bool) !ReportRun {
    var kem = try KatDigests.parse(a, sample_kem_json);
    defer kem.deinit();
    var sig = try KatDigests.parse(a, sample_sig_json);
    defer sig.deinit();
    var aw: std.Io.Writer.Allocating = .init(a);
    errdefer aw.deinit();
    const summary = try KatReport.summarize(a, &aw.writer, .{
        .kem_names = kems,
        .sig_names = sigs,
        .kem_digests = &kem,
        .sig_digests = &sig,
        .mode = mode,
        .lines = lines,
        .filtered = filtered,
        .version = "9.9.9",
    });
    return .{ .summary = summary, .text = try aw.toOwnedSlice() };
}

test "a report with every digest right and one SLH-style name without an entry says KAT OK with the counts" {
    const lines = "kem K-1 digest " ++ digest_b ++ "\n" ++
        "kem K-2 digest " ++ digest_a ++ "\n" ++
        "sig S-1 digest " ++ digest_b ++ "\n" ++
        "sig S-2 noentry\n";
    const run = try report(lines, &.{ "K-1", "K-2" }, &.{ "S-1", "S-2" }, .single, false);
    defer run.deinit();
    try std.testing.expectEqual(@as(usize, 0), run.summary.problems);
    try std.testing.expectEqual(@as(usize, 2), run.summary.kems_checked);
    try std.testing.expectEqual(@as(usize, 1), run.summary.sigs_checked);
    try std.testing.expectEqual(@as(usize, 1), run.summary.sigs_without_entry);
    try std.testing.expect(std.mem.indexOf(u8, run.text, "2 KEMs checked, 1 signatures checked, 0 enabled KEMs and 1 enabled signatures without an entry") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.text, "enabled signatures without an entry:\n      S-2\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, run.text, "KAT OK: 2 KEMs and 1 signatures match liboqs 9.9.9 kats.json (single)\n"));
}

test "the all mode compares the all digest" {
    const lines = "kem K-1 digest " ++ digest_a ++ "\n";
    const run = try report(lines, &.{"K-1"}, &.{}, .all, true);
    defer run.deinit();
    try std.testing.expectEqual(@as(usize, 0), run.summary.problems);
    try std.testing.expect(std.mem.endsWith(u8, run.text, "KAT OK: 1 KEMs and 0 signatures match liboqs 9.9.9 kats.json (all)\n"));
    const wrong = try report("kem K-1 digest " ++ digest_b ++ "\n", &.{"K-1"}, &.{}, .all, true);
    defer wrong.deinit();
    try std.testing.expectEqual(@as(usize, 1), wrong.summary.problems);
}

test "a wrong digest prints the name, the expected and the actual digest, and fails" {
    const wrong = zero_digest;
    const lines = "kem K-1 digest " ++ wrong ++ "\nkem K-2 digest " ++ digest_a ++ "\n";
    const run = try report(lines, &.{ "K-1", "K-2" }, &.{}, .single, false);
    defer run.deinit();
    try std.testing.expectEqual(@as(usize, 1), run.summary.problems);
    try std.testing.expectEqual(@as(usize, 1), run.summary.kems_checked);
    try std.testing.expect(std.mem.indexOf(u8, run.text, "MISMATCH kem K-1 (single)") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.text, "expected " ++ digest_b) != null);
    try std.testing.expect(std.mem.indexOf(u8, run.text, "actual   " ++ wrong) != null);
    try std.testing.expect(std.mem.endsWith(u8, run.text, "KAT FAILED: 1 problems\n"));
    try std.testing.expect(std.mem.indexOf(u8, run.text, "KAT OK") == null);
}

test "an enabled algorithm with an entry that no line reports is a failure, not a skip" {
    const lines = "kem K-1 digest " ++ digest_b ++ "\n";
    const run = try report(lines, &.{ "K-1", "K-2" }, &.{"S-1"}, .single, false);
    defer run.deinit();
    try std.testing.expectEqual(@as(usize, 2), run.summary.problems);
    try std.testing.expect(std.mem.indexOf(u8, run.text, "NOT REPORTED kem K-2") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.text, "NOT REPORTED sig S-1") != null);
}

test "a noentry line for an algorithm that has an entry is a failure" {
    const run = try report("kem K-1 noentry\n", &.{"K-1"}, &.{}, .single, true);
    defer run.deinit();
    try std.testing.expectEqual(@as(usize, 1), run.summary.problems);
    try std.testing.expectEqual(@as(usize, 0), run.summary.kems_without_entry);
}

test "a digest line for an algorithm that has no entry is a failure" {
    const run = try report("sig S-2 digest " ++ digest_b ++ "\n", &.{}, &.{"S-2"}, .single, true);
    defer run.deinit();
    try std.testing.expectEqual(@as(usize, 1), run.summary.problems);
}

test "duplicate, unexpected and malformed lines are failures" {
    const lines = "kem K-1 digest " ++ digest_b ++ "\n" ++
        "kem K-1 digest " ++ digest_b ++ "\n" ++
        "kem K-9 digest " ++ digest_b ++ "\n" ++
        "kem K-2 digest zz\n" ++
        "foo K-2 digest " ++ digest_a ++ "\n" ++
        "sig S-1 digest " ++ digest_b ++ "\n";
    const run = try report(lines, &.{ "K-1", "K-2" }, &.{"S-1"}, .single, false);
    defer run.deinit();
    // Duplicate K-1, unexpected K-9, malformed K-2 digest, malformed kind.
    try std.testing.expectEqual(@as(usize, 4), run.summary.problems);
    try std.testing.expectEqual(@as(usize, 1), run.summary.kems_checked);
    try std.testing.expectEqual(@as(usize, 1), run.summary.sigs_checked);
}

test "entries that the build does not enable are counted, and only when the run is not filtered" {
    const lines = "kem K-1 digest " ++ digest_b ++ "\nsig S-1 digest " ++ digest_b ++ "\n";
    const run = try report(lines, &.{"K-1"}, &.{"S-1"}, .single, false);
    defer run.deinit();
    try std.testing.expectEqual(@as(usize, 1), run.summary.kem_entries_not_enabled);
    try std.testing.expectEqual(@as(usize, 0), run.summary.sig_entries_not_enabled);
    try std.testing.expect(std.mem.indexOf(u8, run.text, "entries not enabled in this build: 1 KEMs, 0 signatures") != null);
    const filtered = try report(lines, &.{"K-1"}, &.{"S-1"}, .single, true);
    defer filtered.deinit();
    try std.testing.expectEqual(@as(usize, 0), filtered.summary.kem_entries_not_enabled);
}

test "result lines print as kind, name and digest, or kind, name and noentry" {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    var digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&digest, digest_b);
    try KatReport.writeDigest(&w, .kem, "K-1", digest);
    try KatReport.writeNoEntry(&w, .sig, "S-2");
    try std.testing.expectEqualStrings("kem K-1 digest " ++ digest_b ++ "\nsig S-2 noentry\n", w.buffered());
}

// --- Fuzz --------------------------------------------------------------------

const FuzzFile = struct {
    text: []u8,
    names: [][]u8,
    singles: [][64]u8,
    alls: [][64]u8,
    starts: []usize,
    ends: []usize,

    fn deinit(self: FuzzFile) void {
        a.free(self.text);
        for (self.names) |n| a.free(n);
        a.free(self.names);
        a.free(self.singles);
        a.free(self.alls);
        a.free(self.starts);
        a.free(self.ends);
    }
};

fn randomHex(random: std.Random, out: *[64]u8) void {
    const digits = "0123456789abcdef";
    for (out) |*ch| ch.* = digits[random.uintLessThan(usize, 16)];
}

// A random kats.json text with 1 to 12 distinct names and random white space.
// It records where each entry starts and ends in the text.
fn randomFile(random: std.Random) !FuzzFile {
    const count = 1 + random.uintLessThan(usize, 12);
    const names = try a.alloc([]u8, count);
    const singles = try a.alloc([64]u8, count);
    const alls = try a.alloc([64]u8, count);
    const starts = try a.alloc(usize, count);
    const ends = try a.alloc(usize, count);
    var made: usize = 0;
    errdefer {
        for (names[0..made]) |n| a.free(n);
        a.free(names);
        a.free(singles);
        a.free(alls);
        a.free(starts);
        a.free(ends);
    }
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    while (made < count) {
        const len = 3 + random.uintLessThan(usize, 10);
        const name = try a.alloc(u8, len);
        for (name) |*ch| ch.* = alphabet[random.uintLessThan(usize, alphabet.len)];
        var clash = false;
        for (names[0..made]) |other| {
            if (std.mem.eql(u8, other, name)) clash = true;
        }
        if (clash) {
            a.free(name);
            continue;
        }
        names[made] = name;
        randomHex(random, &singles[made]);
        randomHex(random, &alls[made]);
        made += 1;
    }
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(a);
    const gaps = [_][]const u8{ "", " ", "\n", "\n  ", "\t" };
    try text.appendSlice(a, "{");
    for (0..count) |i| {
        if (i > 0) try text.appendSlice(a, ",");
        try text.appendSlice(a, gaps[random.uintLessThan(usize, gaps.len)]);
        starts[i] = text.items.len;
        try text.appendSlice(a, "\"");
        try text.appendSlice(a, names[i]);
        try text.appendSlice(a, "\":");
        try text.appendSlice(a, gaps[random.uintLessThan(usize, gaps.len)]);
        const all_first = random.boolean();
        try text.appendSlice(a, "{");
        const first = if (all_first) "all" else "single";
        const second = if (all_first) "single" else "all";
        const first_digest = if (all_first) &alls[i] else &singles[i];
        const second_digest = if (all_first) &singles[i] else &alls[i];
        try text.appendSlice(a, gaps[random.uintLessThan(usize, gaps.len)]);
        try text.print(a, "\"{s}\":\"{s}\",\"{s}\":\"{s}\"", .{ first, first_digest, second, second_digest });
        try text.appendSlice(a, gaps[random.uintLessThan(usize, gaps.len)]);
        try text.appendSlice(a, "}");
        ends[i] = text.items.len;
    }
    try text.appendSlice(a, "}");
    return .{ .text = try text.toOwnedSlice(a), .names = names, .singles = singles, .alls = alls, .starts = starts, .ends = ends };
}

test "fuzz: a generated kats.json always parses to exactly its entries (no false negatives)" {
    errdefer std.debug.print("fuzz seed 0x{x}\n", .{build_options.fuzz_seed});
    var prng = std.Random.DefaultPrng.init(build_options.fuzz_seed);
    const random = prng.random();
    for (0..300) |_| {
        const file = try randomFile(random);
        defer file.deinit();
        var digests = try KatDigests.parse(a, file.text);
        defer digests.deinit();
        try std.testing.expectEqual(file.names.len, digests.count());
        for (file.names, 0..) |name, i| {
            const entry = digests.find(name).?;
            try std.testing.expectEqualSlices(u8, &file.singles[i], &entry.single);
            try std.testing.expectEqualSlices(u8, &file.alls[i], &entry.all);
        }
    }
}

test "fuzz: one changed byte never changes an entry it did not touch and never adds or drops an entry (no false positives)" {
    errdefer std.debug.print("fuzz seed 0x{x}\n", .{build_options.fuzz_seed});
    var prng = std.Random.DefaultPrng.init(build_options.fuzz_seed +% 1);
    const random = prng.random();
    const replacements = "{}[]\",: \n0123456789abcdefghijklmnopqrstuvwxyzXYZ-_\\";
    var parsed: usize = 0;
    var refused: usize = 0;
    for (0..1500) |_| {
        const file = try randomFile(random);
        defer file.deinit();
        const at = random.uintLessThan(usize, file.text.len);
        const old = file.text[at];
        var new = replacements[random.uintLessThan(usize, replacements.len)];
        if (new == old) new = if (old == 'x') 'y' else 'x';
        file.text[at] = new;
        var digests = KatDigests.parse(a, file.text) catch {
            refused += 1;
            continue;
        };
        defer digests.deinit();
        parsed += 1;
        try std.testing.expectEqual(file.names.len, digests.count());
        for (file.names, 0..) |name, i| {
            if (at >= file.starts[i] and at < file.ends[i]) continue;
            const entry = digests.find(name) orelse return error.TestUnexpectedResult;
            try std.testing.expectEqualSlices(u8, &file.singles[i], &entry.single);
            try std.testing.expectEqualSlices(u8, &file.alls[i], &entry.all);
        }
    }
    // Both outcomes happen, so the checks above ran.
    try std.testing.expect(parsed > 0);
    try std.testing.expect(refused > 0);
}

test "fuzz: a kats.json cut short is always refused" {
    errdefer std.debug.print("fuzz seed 0x{x}\n", .{build_options.fuzz_seed});
    var prng = std.Random.DefaultPrng.init(build_options.fuzz_seed +% 2);
    const random = prng.random();
    for (0..300) |_| {
        const file = try randomFile(random);
        defer file.deinit();
        const cut = random.uintLessThan(usize, file.text.len);
        try std.testing.expect(std.meta.isError(KatDigests.parse(a, file.text[0..cut])));
    }
}

test "fuzz: a random digest matches its own entry and no other, and one changed digit or bit never matches" {
    errdefer std.debug.print("fuzz seed 0x{x}\n", .{build_options.fuzz_seed});
    var prng = std.Random.DefaultPrng.init(build_options.fuzz_seed +% 3);
    const random = prng.random();
    for (0..2000) |_| {
        var digest: [32]u8 = undefined;
        random.bytes(&digest);
        var other: [32]u8 = undefined;
        random.bytes(&other);
        const entry = KatDigests.Entry{ .single = hexOf(digest), .all = hexOf(other) };
        try std.testing.expect(entry.matches(.single, digest));
        try std.testing.expect(entry.matches(.all, other));
        try std.testing.expect(!entry.matches(.single, other));
        try std.testing.expect(!entry.matches(.all, digest));

        var flipped = digest;
        const bit = random.uintLessThan(usize, 256);
        flipped[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        try std.testing.expect(!entry.matches(.single, flipped));

        var changed = entry;
        const at = random.uintLessThan(usize, 64);
        const old = changed.single[at];
        changed.single[at] = if (old == '0') '1' else '0';
        try std.testing.expect(!changed.matches(.single, digest));
    }
}
