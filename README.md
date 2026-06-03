# liboqs-zig

A safe Zig wrapper over [liboqs](https://github.com/open-quantum-safe/liboqs), the Open Quantum Safe library of post-quantum KEMs and signature schemes.

liboqs is pulled in as a hash-pinned `build.zig.zon` dependency and compiled by `build.zig`, so a consumer only runs `zig build`. There is no vendored C in the repository and no system liboqs to install.

## Requirements

- Zig 0.16.0
- A C toolchain (Zig ships one; nothing else needed)

## Usage

Add this repository as a dependency, then import the `oqs` module. The typed API gives each algorithm its own type, so a key from one algorithm cannot be passed where another's is expected. Secret keys and shared secrets zero their bytes on `deinit`.

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

The wrappers (`oqs.kem.*`, `oqs.sig.*`) are generated from liboqs' own headers for every enabled algorithm: 32 KEMs and 209 signature variants, including the full SLH-DSA matrix. A runtime, name-based API (`oqs.Kem`, `oqs.Sig`) is also available.

## Build and test

```sh
zig build              # build the static C library and the oqs module
zig build test         # unit, smoke, typed-API, functional, and concurrency tests
zig build parity       # every algorithm: C reference vs Zig wrapper, byte-identical
zig build snapshot     # wrapper output vs the frozen liboqs reference digests
```

`parity` runs the full algorithm set, so it is slow (Classic McEliece keygen and SPHINCS+/SLH-DSA signing dominate). It shards across CPU cores and prints each algorithm as it goes, finishing with an OK or FAILED summary.

## Which algorithms are built

`build/enabled-families.txt` is the single source of truth for the algorithm families compiled and exposed. `tools/gen-manifest.sh` reads it and the pinned liboqs headers to generate `build/manifest.zig` (the C build recipe), `include/oqs/oqsconfig.h` (the C config), and `src/algorithms.zig` (the typed wrappers). The three stay in lockstep with that list.

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
