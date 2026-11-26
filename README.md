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

## Errors

Every operation returns `oqs.OqsError`. `oqs.describeError(err)` gives a short plain text for each member. `ContextNotSupported`, `ContextTooLong`, `SeedNotSupported` and `PersistenceFailed` are part of the set, but nothing returns them yet. Zig errors carry no payload, so `InvalidKeySize` does not say which length was expected.

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
zig build test         # unit, smoke, typed-API, registry, functional, concurrency, and stateful tests
zig build parity       # every algorithm: C reference vs Zig wrapper, byte-identical
zig build snapshot     # wrapper output vs the frozen liboqs reference digests
```

The stateful fuzz test signs several seeded messages per family, then checks that each valid pair verifies and that mutated or swapped pairs do not. The registry fuzz test looks up every listed name, then mutated names and names of the wrong kind, and checks that only listed names are found. Both use a fixed seed. `zig build test --summary all` shows it in the names of the test steps, and `-Dfuzz-seed=N` runs them with another seed.

`parity` also checks the stateful signature families (XMSS, XMSS^MT and LMS) through the typed `oqs.sig_stfl` API against the raw C API, after the main compare. For each algorithm it does one keygen and one sign under the shared seed and message, and compares the public key, the signature and the signature counts. This check is separate from the frozen snapshot, which has no stateful lines. By default only parameter sets with a total tree height of 16 or less run, which is 29 of the 70, and each skipped name is printed. Set `OQS_STATEFUL_ALL=1` to run all 70. The stateful harnesses are always built in ReleaseFast.

`parity` runs the full algorithm set, so it is slow (Classic McEliece keygen and SLH-DSA signing dominate). It shards across CPU cores and prints each algorithm as it goes, finishing with an OK or FAILED summary.

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
zig build && zig build test && zig build parity && zig build snapshot
```

The reference snapshot is frozen on macOS (arm64). Parity is self-consistent on any platform; the snapshot is a drift tripwire on that one reference platform, so CI runs it only there.

## Continuous integration

`.github/workflows/ci.yml` runs on pull requests: build, `zig fmt --check`, and `zig build test` on macOS and Linux, plus parity on Linux. `.github/workflows/main.yml` runs on pushes to `main`: the same build/test on both systems, full parity on both, and the snapshot on macOS. It also runs on a monthly schedule as an idle-repo safety net, which skips itself when `main` saw a commit in the past week (the push run already covered it). Splitting by event keeps the heavier main-only jobs off the PR checklist.

## License

MIT
