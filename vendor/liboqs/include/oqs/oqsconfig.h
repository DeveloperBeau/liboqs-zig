// SPDX-License-Identifier: MIT
// Minimal hand-maintained liboqs 0.15.0 build configuration for ZigOQS.
// Portable-only build: no platform-specific optimized variants.
// Enabled algorithms: ML-KEM-768, ML-DSA-65, MAYO-2.

#ifndef OQS_OQSCONFIG_H
#define OQS_OQSCONFIG_H

// --- Version ---
#define OQS_VERSION_TEXT "0.15.0"
#define OQS_VERSION_MAJOR 0
#define OQS_VERSION_MINOR 15
#define OQS_VERSION_PATCH 0

// --- Build target / system ---
#define OQS_COMPILE_BUILD_TARGET "generic"
#define OQS_DIST_BUILD 1
#define OQS_BUILD_ONLY_LIB 1

// --- System feature flags ---
#define OQS_HAVE_POSIX_MEMALIGN 1

// --- No GPU/CUPQC/ICICLE/libjade ---
#define OQS_USE_CUPQC 0
#define OQS_USE_ICICLE 0
#define OQS_LIBJADE_BUILD 0

// --- KEM: ML-KEM-768 only ---
// Family umbrella (required by kem.h dispatcher)
#define OQS_ENABLE_KEM_ML_KEM 1
// Variant: 768 only; 512 and 1024 are intentionally absent
#define OQS_ENABLE_KEM_ml_kem_768 1
// No optimized backends (x86_64, aarch64, cuda, icicle_cuda) for ml_kem_768

// --- SIG: ML-DSA-65 only ---
// Family umbrella (required by sig.h dispatcher)
#define OQS_ENABLE_SIG_ML_DSA 1
// Variant: 65 only; 44 and 87 are intentionally absent
#define OQS_ENABLE_SIG_ml_dsa_65 1
// No optimized backends (avx2) for ml_dsa_65

// --- SIG: MAYO-2 only ---
// Family umbrella (required by sig.h dispatcher)
#define OQS_ENABLE_SIG_MAYO 1
// Variant: mayo_2 only; mayo_1, mayo_3, mayo_5 are intentionally absent
#define OQS_ENABLE_SIG_mayo_2 1
// No optimized backends (avx2, neon) for mayo_2

// All other KEMs and SIGs (BIKE, FrodoKEM, NTRU, NTRUPRIME, Classic McEliece,
// HQC, Kyber, ml_kem_512, ml_kem_1024, Falcon, SPHINCS+, SLH-DSA, CROSS,
// UOV, SNOVA, ML-DSA-44, ML-DSA-87, MAYO-1/3/5, stateful sigs) are
// intentionally left undefined / not enabled.

#endif // OQS_OQSCONFIG_H
