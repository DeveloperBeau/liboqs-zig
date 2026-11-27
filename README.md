# liboqs-zig

A safe Zig wrapper over [liboqs](https://github.com/open-quantum-safe/liboqs), the Open Quantum Safe library of post-quantum KEMs and signature schemes.

`build.zig` fetches liboqs as a hash-pinned `build.zig.zon` dependency and compiles it, so you only run `zig build`. The repository carries no vendored C, and you install no system liboqs.

## Requirements

- Zig 0.17.1
- A C toolchain (Zig ships one; nothing else needed)

## Add to your project

Fetch the release and let Zig pin the hash:

```sh
zig fetch --save https://github.com/DeveloperBeau/liboqs-zig/archive/refs/tags/v0.16.0.tar.gz
```

That writes a `.liboqs_zig` entry into your `build.zig.zon`. Wire the `oqs` module into your build graph:

```zig
// build.zig
const dep = b.dependency("liboqs_zig", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("oqs", dep.module("oqs"));
```

Now `@import("oqs")` works from your code. The module brings the compiled liboqs and its headers with it, so there is nothing else to install. The first build compiles the liboqs C slice (18 algorithm families), which takes a minute or two. Later builds are cached.

Wrapped liboqs version: 0.16.0. Note two upstream changes in that release: the `FrodoKEM-*` names now refer to the salted FrodoKEM variants (the 0.15 algorithms live on as `eFrodoKEM-*`, and ciphertext sizes differ between the two), and HQC was updated to the 2025-08-22 specification under new names (`HQC-1/3/5` replacing `HQC-128/192/256`). Ciphertexts and keys produced by 0.15-era builds do not interoperate across those changes.

If you fetched an earlier, broken tag and now see a hash mismatch, delete the `.liboqs_zig` `.hash` line and re-run the `zig fetch --save` command above.

## Usage

The typed API gives each algorithm its own type, so a key from one algorithm cannot be passed where another's is expected. Secret keys and shared secrets zero their bytes on `deinit`.

```zig
const oqs = @import("oqs");

// Key encapsulation
var kp = try oqs.kem.MlKem768.generateKeyPair(allocator);
defer kp.public_key.deinit();
defer kp.secret_key.deinit();

var enc = try kp.public_key.encapsulate();   // send enc.ciphertext to the holder
defer enc.deinit();
var ss = try kp.secret_key.decapsulate(enc.ciphertext);
defer ss.deinit();                            // ss.bytes == enc.shared_secret.bytes

// Signatures
var sk = try oqs.sig.MlDsa65.generateKeyPair(allocator);
defer sk.public_key.deinit();
defer sk.secret_key.deinit();
var sig = try sk.secret_key.sign("message");
defer sig.deinit();
const ok = try sk.public_key.isValidSignature("message", sig.bytes);
```

The wrappers (`oqs.kem.*`, `oqs.sig.*`) are generated from liboqs' own headers for every enabled algorithm: 41 KEMs and 221 signature variants, including the full SLH-DSA matrix. A runtime, name-based API (`oqs.Kem`, `oqs.Sig`) is also available.

## Algorithm names and metadata

`oqs.Registry` lists the algorithms this build enables, in liboqs order, and reports what liboqs knows about each one. The lists come from liboqs itself and allocate nothing.

```zig
var names = oqs.Registry.kemNames();
while (names.next()) |name| {
    const d = oqs.Registry.kemDescription(name).?;
    std.debug.print("{s}: level {d}, public key {d} bytes\n", .{ d.name, d.claimedNistLevel, d.publicKeyLength });
}

if (oqs.Registry.sigDescription("ML-DSA-65")) |d| {
    std.debug.print("{s} takes a context string: {}\n", .{ d.name, d.supportsContext });
}
const n = oqs.Registry.enabledSigCount();      // 221
const on = oqs.Registry.isKemEnabled("ML-KEM-768");
```

`kemDescription`, `sigDescription` and `sigStflDescription` return a `KemDescription`, `SigDescription` or `SigStflDescription`, or null when the name is not enabled. Name matching follows liboqs, which compares names with `strcasecmp`. Case is ignored for the ASCII letters only, and every other byte must match, so `ml-kem-768` finds `ML-KEM-768` here and in `oqs.Kem.init`. A description always carries the liboqs name, such as `ML-KEM-768`, whatever case was passed in. A name that holds a zero byte never matches, even though C would stop reading at that byte. The name and version strings in a description point at static liboqs strings and need no freeing.

## Context strings

ML-DSA and SLH-DSA can sign under a context string of up to 255 bytes, as FIPS 204 and FIPS 205 set. A signature made under one context verifies only under the same context. The calls go through `OQS_SIG_sign_with_ctx_str` and `OQS_SIG_verify_with_ctx_str`.

```zig
var kp = try oqs.sig.MlDsa44.generateKeyPair(allocator);
defer kp.public_key.deinit();
defer kp.secret_key.deinit();
var sig = try kp.secret_key.signWithContext("message", "my protocol v1");
defer sig.deinit();
const ok = try kp.public_key.isValidSignatureWithContext("message", sig.bytes, "my protocol v1");
```

The runtime core has the same pair, `oqs.Sig.signWithContext` and `oqs.Sig.verifyWithContext`, and `oqs.Sig.supportsContext` reports what liboqs says about the algorithm. `oqs.Registry.sigDescription(name).?.supportsContext` gives the same answer by name.

The rules follow liboqs:

- An empty context is the same as no context. A signature made with an empty context verifies with `isValidSignature`, and a plain signature verifies with an empty context.
- An algorithm without context support, such as Falcon or MAYO, signs only with an empty context and then gives its plain signature. Any other context returns `error.ContextNotSupported`.
- A context over 255 bytes returns `error.ContextTooLong` from signing.
- Signing checks run before liboqs is called, in this order: context support, then the secret key length, then the context length.
- Verifying never returns a context error. A context the algorithm cannot take, or one over 255 bytes, gives false, as liboqs does. A public key of the wrong length still returns `error.InvalidKeySize`.

Stateful signatures (XMSS, XMSS^MT and LMS) have no context strings in liboqs, so they have none here.

## Seeded key generation

ML-KEM-512, ML-KEM-768 and ML-KEM-1024 can make a key pair and an encapsulation from a seed, so the same seed always gives the same output. The calls go through `OQS_KEM_keypair_derand` and `OQS_KEM_encaps_derand`. The key pair seed is 64 bytes and the encapsulation seed is 32 bytes.

```zig
const key_seed: [64]u8 = ...; // from your own secure source
var kp = try oqs.kem.MlKem768.generateKeyPairFromSeed(allocator, &key_seed);
defer kp.public_key.deinit();
defer kp.secret_key.deinit();
const message_seed: [32]u8 = ...;
var enc = try kp.public_key.encapsulateWithSeed(&message_seed);
defer enc.deinit();
```

The runtime core has `oqs.Kem.keypairFromSeed` and `oqs.Kem.encapsFromSeed`. `oqs.Kem.lengthKeyPairSeed` and `oqs.Kem.lengthEncapsulationSeed` report the seed lengths liboqs gives, and `oqs.Registry.kemDescription(name).?.keyPairSeedLength` gives the same by name.

- A seed is secret. Anyone with a key pair seed can rebuild the secret key. Keep it as private as the key, and wipe it yourself when done, for example with `std.crypto.secureZero`. The wrapper keeps no copy.
- Every other key encapsulation mechanism has a seed length of 0 in liboqs, so both seeded calls return `error.SeedNotSupported`. liboqs has no seeded signature key generation, so there is none here.
- Checks run before liboqs is called, in this order: seed support, then the seed length, then for encapsulation the public key length. A wrong length returns `error.InvalidKeySize`.
- The seeded calls return the same key and ciphertext types as the random ones, and decapsulation is the usual one.

## Errors

Every operation returns `oqs.OqsError`. `oqs.describeError(err)` gives a short plain text for each member. `PersistenceFailed` is part of the set, but nothing returns it yet. Zig errors carry no payload, so `InvalidKeySize` does not say which length was expected.

## Stateful signatures

The build includes the stateful hash-based signature families from liboqs: 21 XMSS, 16 XMSS^MT and 33 LMS variants, 70 in all. Each key pair can sign only a fixed number of times. `oqs.SigStfl` is the runtime, name-based core for them. `sign` takes the secret key state, and liboqs advances the signature index inside it.

```zig
var alg = try oqs.SigStfl.init(allocator, "LMS_SHA256_H5_W8");
defer alg.deinit();
var kp = try alg.keypair();
defer allocator.free(kp.public_key);
defer kp.secret_key.deinit();                 // zeroes the key state

const sig = try alg.sign("message", &kp.secret_key);
defer allocator.free(sig);
const ok = try alg.verify("message", sig, kp.public_key);
const left = try alg.sigsRemaining(kp.secret_key);
```

For a tree of height h, liboqs reports `sigsTotal` as 2^h - 1. As in liboqs, a key makes `sigsTotal` + 1 signatures, and the last one is made when `sigsRemaining` already reads 0. For XMSS that last signature uses wiped key material and does not verify. After it, `sign` returns no signature. For LMS liboqs reports success with no signature, and `sign` returns `error.KeyExhausted`. For XMSS and XMSS^MT liboqs reports an error, and `sign` returns `error.SignFailed`. `sign` returns `error.SignFailed` whenever liboqs reports an error, and never hands back a signature in that case. `oqs.Registry.isSigStflEnabled(name)` and `oqs.Registry.enabledSigStflCount()` report what is compiled in.

The core keeps the key state in memory only and writes nothing to storage, so a key pair cannot sign again after the process exits. A `SigStflSecretKey` value points at one liboqs key state. A copy of the value shares that state, so signing through either copy takes the next index. Call `deinit` on one copy only.

Each stateful variant also has a typed wrapper under `oqs.sig_stfl`, named like the other typed namespaces (`oqs.sig_stfl.LmsSha256H5W8`, `oqs.sig_stfl.XmssSha256H10`, `oqs.sig_stfl.XmssmtSha256H204`). The generator emits them from the pinned liboqs headers, so the 70 wrappers match what is compiled in. A key of one variant cannot be passed to another, and the signing key is the same in-memory state as in the core.

```zig
var kp = try oqs.sig_stfl.LmsSha256H5W8.generateKeyPair(allocator);
defer kp.public_key.deinit();
defer kp.secret_key.deinit();                 // zeroes the key state

var sig = try kp.secret_key.sign("message");  // takes *SecretKey, the index advances
defer sig.deinit();
const ok = try kp.public_key.isValidSignature("message", sig.bytes);
const left = try kp.secret_key.sigsRemaining();
```

The typed secret key has no import or export, because the core cannot save or restore key state. The exhaustion rules above apply to the typed `sign` as well.

## Build and test

```sh
zig build              # build the static C library and the oqs module
zig build test         # unit, smoke, typed-API, registry, context string, functional, concurrency, and stateful tests
zig build parity       # every algorithm: C reference vs Zig wrapper, byte-identical
zig build snapshot     # wrapper output vs the frozen liboqs reference digests
zig build kat          # known-answer digests of liboqs kats.json, through the wrapper
```

The stateful fuzz test signs several seeded messages per family, then checks that each valid pair verifies and that mutated or swapped pairs do not. The registry fuzz test looks up every listed name, then mutated names and names of the wrong kind, and checks that only listed names are found. The context string fuzz test signs ML-DSA-44 messages under seeded contexts of 0 to 255 bytes and checks that each verifies under its own context, that flipped, cut or extended contexts and changed messages or signatures do not, and that longer contexts give `error.ContextTooLong`. They all use a fixed seed. `zig build test --summary all` shows it in the names of the test steps, and `-Dfuzz-seed=N` runs them with another seed.

`parity` also checks the stateful signature families (XMSS, XMSS^MT and LMS) through the typed `oqs.sig_stfl` API against the raw C API, after the main compare. For each algorithm it does one keygen and one sign under the shared seed and message, and compares the public key, the signature and the signature counts. This check is separate from the frozen snapshot, which has no stateful lines. By default only parameter sets with a total tree height of 16 or less run, which is 29 of the 70, and each skipped name is printed. Set `OQS_STATEFUL_ALL=1` to run all 70. The stateful harnesses are always built in ReleaseFast.

`parity` runs the full algorithm set, so it is slow (Classic McEliece keygen and SLH-DSA signing dominate). It shards across CPU cores and prints each algorithm as it goes, finishing with an OK or FAILED summary.

## Known-answer tests

`zig build kat` runs the liboqs programs `kat_kem` and `kat_sig` through the Zig wrapper. Key generation, encapsulation, decapsulation, signing and verification go through `oqs.Kem` and `oqs.Sig`. Only the liboqs random source is replaced by the known-answer generators of liboqs: the NIST DRBG for every algorithm except HQC, which uses its SHAKE256 generator. The harness prints the same text as the C programs, takes its SHA-256 and compares it with the `single` digest in `tests/KATs/kem/kats.json` or `tests/KATs/sig/kats.json` of the pinned liboqs. Those files are embedded from the hash-pinned dependency at build time, so they cannot drift from `LIBOQS_VERSION`.

Every enabled KEM and signature scheme that has an entry is checked, and one that is missing from the run is a failure, not a skip. Run output counts the algorithms that are enabled but have no entry. With the default build that is the 156 SLH-DSA schemes, which liboqs tests with ACVP vectors instead. A mismatch prints the algorithm name with the expected and the actual digest and exits non-zero. A passing run ends with `KAT OK: 41 KEMs and 65 signatures match liboqs 0.16.0 kats.json (single)`. A run without `OQS_KAT_FILTER` must check exactly that fixed set of 41 KEMs and 65 signatures, listed in `harness/kat_names.zig`. A missing or an extra name is a failure, so dropping one algorithm from the run list cannot pass. A vendor bump must update that list.

The run splits over four processes, because the liboqs random source is global. `OQS_SHARDS` sets the number. `OQS_KAT_ALL=1` compares the `all` digests (100 counts, 10 for Classic McEliece) instead. `OQS_KAT_FILTER=ML-KEM-768,ML-DSA-44` covers only the named algorithms. The harness is built in the optimize mode you choose, as `parity` is. Do not use `-Doptimize=ReleaseFast` for it yet: SNOVA_25_8_3 gives a stable wrong known-answer digest when the liboqs C is built that way for an AVX-512 native target, from a miscompile in LLVM 22 x86 instruction selection (the C compiler bundled with zig 0.17.1). The same wrong digest shows up through the C built by zig.

The stateful signatures (XMSS, XMSS^MT and LMS) are not covered. `kat_sig_stfl` loads the secret key from a response file, and the typed stateful API has no secret key import. The harness code is in `harness/kat*.zig` and its tests are in `tests/kat.zig`.

## Which algorithms are built

`build/enabled-families.txt` is the single source of truth for the algorithm families compiled and exposed. `tools/gen-manifest.sh` reads it and the pinned liboqs headers to generate `build/manifest.zig` (the C build recipe), `include/oqs/oqsconfig.h` (the C config), and `src/algorithms.zig` (the typed wrappers). The three stay in lockstep with that list.

BIKE is supported upstream only on 64-bit little-endian platforms (arm64/x86_64 macOS and Linux are fine; Windows, 32-bit, and big-endian targets are not).

## Updating liboqs

The pinned version lives in `LIBOQS_VERSION` and in the `.liboqs` entry of `build.zig.zon`.

A weekly workflow (`.github/workflows/update-liboqs.yml`, also runnable on demand) compares the latest liboqs release tag to `LIBOQS_VERSION`. On a newer tag it bumps the pin, regenerates the manifest, config, registry, and reference snapshot, runs every gate, and opens a pull request. A maintainer reviews that PR against its checklist before merging.

To bump by hand:

```sh
echo <new-version> > LIBOQS_VERSION
zig fetch --save=liboqs https://github.com/open-quantum-safe/liboqs/archive/refs/tags/<new-version>.tar.gz
bash tools/gen-manifest.sh        # regenerate manifest, oqsconfig.h, algorithms.zig
bash tools/freeze-snapshots.sh    # regenerate tests/snapshots/<new-version>.txt
zig build && zig build test && zig build parity && zig build snapshot && zig build kat
```

The reference snapshot is frozen on macOS (arm64). Parity is self-consistent on any platform; the snapshot is a drift tripwire on that one reference platform, so CI runs it only there.

## Continuous integration

`.github/workflows/ci.yml` runs on pull requests: build, `zig fmt --check`, and `zig build test` on macOS and Linux, plus parity on Linux. `.github/workflows/main.yml` runs on pushes to `main`: the same build/test on both systems, full parity on both, and the snapshot on macOS. It also runs on a monthly schedule as an idle-repo safety net, which skips itself when `main` saw a commit in the past week (the push run already covered it). Splitting by event keeps the heavier main-only jobs off the PR checklist.

## License

MIT
