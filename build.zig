const std = @import("std");
const manifest = @import("build/manifest.zig");

// Single source of truth for which liboqs families are compiled and exposed.
// The same list scopes include/oqs/oqsconfig.h via tools/gen-manifest.sh.
// @embedFile (not a configure-time read) so editing the txt forces a rebuild.
const enabled_families = parseFamilies(@embedFile("build/enabled-families.txt"));

/// Parse the enabled-families manifest at comptime: one family per line,
/// trimmed, skipping blank lines and `#` comments.
fn parseFamilies(comptime raw: []const u8) []const []const u8 {
    @setEvalBranchQuota(10000);
    comptime {
        var families: []const []const u8 = &.{};
        var it = std.mem.tokenizeScalar(u8, raw, '\n');
        while (it.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;
            families = families ++ .{trimmed};
        }
        return families;
    }
}

/// Look up a family's kind ("kem"/"sig") from the manifest. Panics if the
/// family has no manifest entry (i.e. enabled-families.txt names something the
/// generator does not know about).
fn familyKind(comptime family: []const u8) []const u8 {
    comptime {
        @setEvalBranchQuota(10000);
        for (manifest.algorithms) |entry| {
            if (std.mem.eql(u8, entry.family, family)) {
                return switch (entry.kind) {
                    .kem => "kem",
                    .sig => "sig",
                };
            }
        }
        @compileError("enabled-families.txt names '" ++ family ++ "' which has no entry in build/manifest.zig");
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ------------------------------------------------------------------
    // Static C library: cliboqs (portable-only slice of liboqs 0.15.0).
    // ------------------------------------------------------------------
    const cliboqs_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const cliboqs = b.addLibrary(.{
        .name = "cliboqs",
        .linkage = .static,
        .root_module = cliboqs_mod,
    });

    // liboqs C source comes from a hash-pinned dependency (build.zig.zon),
    // fetched by `zig fetch`. The tarball unpacks to a tree whose source
    // root is `src/` (same relative layout as the old vendored slice).
    const liboqs = b.dependency("liboqs", .{});

    // Root for all relative C source paths below.
    const vendor_src = liboqs.path("src");

    // Assemble the public `oqs/` umbrella include directory at build time:
    // copy each required upstream header to `oqs/<basename>`, plus our
    // in-repo (hand-maintained) oqsconfig.h. The result is a generated
    // LazyPath consumed as an include dir by every group below.
    const hdrs = b.addWriteFiles();
    _ = hdrs.addCopyFile(b.path("include/oqs/oqsconfig.h"), "oqs/oqsconfig.h");
    const umbrella_headers = [_]struct { []const u8, []const u8 }{
        .{ "src/oqs.h", "oqs/oqs.h" },
        .{ "src/common/common.h", "oqs/common.h" },
        .{ "src/common/rand/rand.h", "oqs/rand.h" },
        .{ "src/common/rand/rand_nist.h", "oqs/rand_nist.h" },
        .{ "src/common/aes/aes_ops.h", "oqs/aes_ops.h" },
        .{ "src/common/aes/aes.h", "oqs/aes.h" },
        .{ "src/common/sha2/sha2_ops.h", "oqs/sha2_ops.h" },
        .{ "src/common/sha2/sha2.h", "oqs/sha2.h" },
        .{ "src/common/sha3/sha3_ops.h", "oqs/sha3_ops.h" },
        .{ "src/common/sha3/sha3.h", "oqs/sha3.h" },
        .{ "src/common/sha3/sha3x4_ops.h", "oqs/sha3x4_ops.h" },
        .{ "src/common/sha3/sha3x4.h", "oqs/sha3x4.h" },
        .{ "src/kem/kem.h", "oqs/kem.h" },
        .{ "src/sig/sig.h", "oqs/sig.h" },
        .{ "src/sig_stfl/sig_stfl.h", "oqs/sig_stfl.h" },
        .{ "src/sig_stfl/xmss/sig_stfl_xmss.h", "oqs/sig_stfl_xmss.h" },
        .{ "src/sig_stfl/lms/sig_stfl_lms.h", "oqs/sig_stfl_lms.h" },
    };
    for (umbrella_headers) |h| {
        _ = hdrs.addCopyFile(liboqs.path(h[0]), h[1]);
    }

    // Per-family umbrella headers, derived from enabled_families. Each family's
    // umbrella is oqs/<kind>_<family>.h (kem_<f>.h for KEMs, sig_<f>.h for SIGs);
    // its kind comes from the manifest. kem.h/sig.h #include these under the
    // family-level OQS_ENABLE_* guards, so the enabled set must match oqsconfig.h.
    inline for (enabled_families) |fam| {
        const sub = comptime familyKind(fam); // "kem" or "sig"
        const rel = b.fmt("src/{s}/{s}/{s}_{s}.h", .{ sub, fam, sub, fam });
        const dst = b.fmt("oqs/{s}_{s}.h", .{ sub, fam });
        _ = hdrs.addCopyFile(liboqs.path(rel), dst);
    }
    const oqs_include = hdrs.getDirectory();

    // Library-global include paths (order matters: pqclean_shims must
    // resolve before the internal sha2/sha3 headers). The assembled
    // umbrella dir replaces the old vendored `include/`.
    cliboqs_mod.addIncludePath(oqs_include);
    const include_dirs = [_][]const u8{
        "src",
        "src/common",
        "src/common/pqclean_shims",
        "src/common/aes",
        "src/common/sha2",
        "src/common/sha3",
        "src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits",
        "src/common/sha3/xkcp_low/KeccakP-1600times4/serial",
        "src/common/rand",
    };
    for (include_dirs) |dir| {
        cliboqs_mod.addIncludePath(liboqs.path(dir));
    }

    // Base flags applied to every cliboqs C group.
    // -fno-sanitize=alignment is library-wide: several PQClean impls do
    // unaligned casts (e.g. uchar[] -> uint64_t* for GF arithmetic), safe on
    // little-endian targets that tolerate unaligned loads but flagged by UBSan.
    const base_flags = [_][]const u8{
        "-std=c11",
        "-DOQS_DIST_BUILD=1",
        "-fno-sanitize=alignment",
    };

    // --- common (portable, OpenSSL OFF) + dispatchers -----------------
    cliboqs_mod.addCSourceFiles(.{
        .root = vendor_src,
        .flags = &base_flags,
        .files = &.{
            // common: aes
            "common/aes/aes_impl.c",
            "common/aes/aes_c.c",
            "common/aes/aes.c",
            // common: sha2
            "common/sha2/sha2_impl.c",
            "common/sha2/sha2_c.c",
            "common/sha2/sha2.c",
            // common: sha3
            "common/sha3/xkcp_sha3.c",
            "common/sha3/xkcp_sha3x4.c",
            "common/sha3/sha3.c",
            "common/sha3/sha3x4.c",
            // common: Keccak low-level (portable)
            "common/sha3/xkcp_low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c",
            "common/sha3/xkcp_low/KeccakP-1600times4/serial/KeccakP-1600-times4-on1.c",
            // common: misc
            "common/common.c",
            "common/pqclean_shims/fips202.c",
            "common/pqclean_shims/fips202x4.c",
            "common/rand/rand.c",
            "common/rand/rand_nist.c",
            // dispatchers
            "kem/kem.c",
            "sig/sig.c",
        },
    });

    // --- per-algorithm groups, driven by build/manifest.zig -----------
    // Each manifest entry whose family is enabled becomes one
    // addCSourceFiles group. Families come online incrementally via this
    // enable list. Enabling a family compiles ALL its variants (this is how
    // upstream builds; PQClean/mlkem-native namespace per-variant so there
    // are no symbol clashes).
    const is_macos = target.result.os.tag == .macos;

    for (manifest.algorithms) |entry| {
        var enabled = false;
        for (enabled_families) |fam| {
            if (std.mem.eql(u8, fam, entry.family)) {
                enabled = true;
                break;
            }
        }
        if (!enabled) continue;

        // Build a fresh flag slice per entry on the build arena.
        var flags: std.ArrayList([]const u8) = .empty;
        flags.appendSlice(b.allocator, &base_flags) catch @panic("OOM");
        for (entry.flags) |flag| {
            if (flag.macos_only and !is_macos) continue;
            flags.append(b.allocator, flag.text) catch @panic("OOM");
        }
        for (entry.includes) |inc| {
            const abs = liboqs.path(b.fmt("src/{s}", .{inc})).getPath(b);
            flags.append(b.allocator, b.fmt("-I{s}", .{abs})) catch @panic("OOM");
        }

        cliboqs_mod.addCSourceFiles(.{
            .root = vendor_src,
            .flags = flags.toOwnedSlice(b.allocator) catch @panic("OOM"),
            .files = entry.files,
        });
    }

    b.installArtifact(cliboqs);

    // ------------------------------------------------------------------
    // Zig module `oqs` + test step.
    // ------------------------------------------------------------------
    const oqs_mod = b.addModule("oqs", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    oqs_mod.linkLibrary(cliboqs);
    oqs_mod.addIncludePath(oqs_include);

    const mod_tests = b.addTest(.{ .root_module = oqs_mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_mod_tests.step);

    // Smoke test: instantiate + round-trip across the enabled families.
    const smoke_mod = b.createModule(.{
        .root_source_file = b.path("tests/smoke.zig"),
        .target = target,
        .optimize = optimize,
    });
    smoke_mod.addImport("oqs", oqs_mod);
    const smoke_tests = b.addTest(.{ .root_module = smoke_mod });
    const run_smoke_tests = b.addRunArtifact(smoke_tests);
    test_step.dependOn(&run_smoke_tests.step);

    // Typed-API tests: registry gate + namespace round-trips + type safety.
    const typed_mod = b.createModule(.{
        .root_source_file = b.path("tests/typed.zig"),
        .target = target,
        .optimize = optimize,
    });
    typed_mod.addImport("oqs", oqs_mod);
    const typed_tests = b.addTest(.{ .root_module = typed_mod });
    const run_typed_tests = b.addRunArtifact(typed_tests);
    test_step.dependOn(&run_typed_tests.step);

    // ------------------------------------------------------------------
    // C reference harness: cref
    // ------------------------------------------------------------------
    const cref_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const cref = b.addExecutable(.{
        .name = "cref",
        .root_module = cref_mod,
    });
    cref_mod.addCSourceFile(.{ .file = b.path("harness/cref.c"), .flags = &.{"-std=c11"} });
    cref_mod.addIncludePath(oqs_include);
    cref_mod.linkLibrary(cliboqs);
    b.installArtifact(cref);

    // ------------------------------------------------------------------
    // Zig wrapper harness: zref
    // ------------------------------------------------------------------
    const zref_mod = b.createModule(.{
        .root_source_file = b.path("harness/zref.zig"),
        .target = target,
        .optimize = optimize,
    });
    zref_mod.addImport("oqs", oqs_mod);
    const zref = b.addExecutable(.{
        .name = "zref",
        .root_module = zref_mod,
    });
    b.installArtifact(zref);

    // ------------------------------------------------------------------
    // Parity gate: diff cref vs zref output
    // ------------------------------------------------------------------
    const parity_mod = b.createModule(.{
        .root_source_file = b.path("tests/parity.zig"),
        .target = target,
        .optimize = optimize,
    });
    const parity = b.addTest(.{ .root_module = parity_mod });
    const run_parity = b.addRunArtifact(parity);
    run_parity.step.dependOn(b.getInstallStep());
    const parity_step = b.step("parity", "Diff C reference vs Zig wrapper output");
    parity_step.dependOn(&run_parity.step);
}
