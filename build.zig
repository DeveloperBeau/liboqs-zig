const std = @import("std");

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

    // Root for all relative C source paths below.
    const vendor_src = b.path("vendor/liboqs/src");

    // Library-global include paths (order matters: pqclean_shims must
    // resolve before the internal sha2/sha3 headers).
    const include_dirs = [_][]const u8{
        "vendor/liboqs/include",
        "vendor/liboqs/src",
        "vendor/liboqs/src/common",
        "vendor/liboqs/src/common/pqclean_shims",
        "vendor/liboqs/src/common/aes",
        "vendor/liboqs/src/common/sha2",
        "vendor/liboqs/src/common/sha3",
        "vendor/liboqs/src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits",
        "vendor/liboqs/src/common/sha3/xkcp_low/KeccakP-1600times4/serial",
        "vendor/liboqs/src/common/rand",
    };
    for (include_dirs) |dir| {
        cliboqs_mod.addIncludePath(b.path(dir));
    }

    // Base flags applied to every group.
    const base_flags = [_][]const u8{
        "-std=c11",
        "-DOQS_DIST_BUILD=1",
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

    // --- ML-KEM-768 ---------------------------------------------------
    // MLK_CONFIG_FILE expands inside a #include directive, so it must
    // carry literal embedded quotes. The path is relative to the
    // including file (mlkem/src/params.h), independent of CWD.
    const mlkem_flags = base_flags ++ [_][]const u8{
        "-DMLK_CONFIG_PARAMETER_SET=768",
        "-DMLK_CONFIG_FILE=\"../../integration/liboqs/config_c.h\"",
        b.fmt("-I{s}", .{b.pathFromRoot("vendor/liboqs/src/kem/ml_kem/mlkem-native_ml-kem-768_ref")}),
        b.fmt("-I{s}", .{b.pathFromRoot("vendor/liboqs/src/common/pqclean_shims")}),
    };
    cliboqs_mod.addCSourceFiles(.{
        .root = vendor_src,
        .flags = &mlkem_flags,
        .files = &.{
            "kem/ml_kem/kem_ml_kem_768.c",
            "kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/compress.c",
            "kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/debug.c",
            "kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/indcpa.c",
            "kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/kem.c",
            "kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/poly.c",
            "kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/poly_k.c",
            "kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/sampling.c",
            "kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/verify.c",
        },
    });

    // --- ML-DSA-65 ----------------------------------------------------
    const mldsa_flags = base_flags ++ [_][]const u8{
        "-DDILITHIUM_MODE=3",
        b.fmt("-I{s}", .{b.pathFromRoot("vendor/liboqs/src/sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_ref")}),
        b.fmt("-I{s}", .{b.pathFromRoot("vendor/liboqs/src/common/pqclean_shims")}),
    };
    cliboqs_mod.addCSourceFiles(.{
        .root = vendor_src,
        .flags = &mldsa_flags,
        .files = &.{
            "sig/ml_dsa/sig_ml_dsa_65.c",
            "sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_ref/ntt.c",
            "sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_ref/packing.c",
            "sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_ref/poly.c",
            "sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_ref/polyvec.c",
            "sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_ref/reduce.c",
            "sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_ref/rounding.c",
            "sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_ref/sign.c",
            "sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_ref/symmetric-shake.c",
        },
    });

    // --- MAYO-2 -------------------------------------------------------
    // -fno-sanitize=alignment: the MAYO-2 opt implementation casts an
    // unsigned char[] stack buffer to uint64_t* for SIMD-style GF(16)
    // arithmetic. The cast is safe on little-endian targets that tolerate
    // unaligned 64-bit loads (all current macOS/Linux x86-64 and ARM64),
    // but UBSan flags it. Suppress alignment sanitization for these files.
    const mayo_flags = base_flags ++ [_][]const u8{
        "-DMAYO_VARIANT=MAYO_2",
        "-DMAYO_BUILD_TYPE_OPT",
        "-DHAVE_RANDOMBYTES_NORETVAL",
        b.fmt("-I{s}", .{b.pathFromRoot("vendor/liboqs/src/sig/mayo/pqmayo_mayo-2_opt")}),
        "-fno-sanitize=alignment",
    };
    cliboqs_mod.addCSourceFiles(.{
        .root = vendor_src,
        .flags = &mayo_flags,
        .files = &.{
            "sig/mayo/sig_mayo_2.c",
            "sig/mayo/pqmayo_mayo-2_opt/api.c",
            "sig/mayo/pqmayo_mayo-2_opt/arithmetic.c",
            "sig/mayo/pqmayo_mayo-2_opt/mayo.c",
            "sig/mayo/pqmayo_mayo-2_opt/params.c",
        },
    });

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
    oqs_mod.addIncludePath(b.path("vendor/liboqs/include"));

    const mod_tests = b.addTest(.{ .root_module = oqs_mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_mod_tests.step);
}
