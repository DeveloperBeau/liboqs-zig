#!/usr/bin/env bash
# Regenerate build/manifest.zig and include/oqs/oqsconfig.h from the liboqs
# CMake metadata for the version pinned in LIBOQS_VERSION.
#
# This is a regen-time tool: it downloads the upstream liboqs tarball into a
# temp dir (independent of zig's package cache), parses each family's
# CMakeLists.txt for its PORTABLE OBJECT targets, and emits a checked-in Zig
# manifest plus a maximal oqsconfig.h. It is idempotent: re-running produces
# byte-identical output.
#
# Usage: bash tools/gen-manifest.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(cat "$ROOT/LIBOQS_VERSION")"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading liboqs $VERSION ..." >&2
curl -sL "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$VERSION.tar.gz" \
  | tar -xz -C "$TMP"
SRC="$TMP/liboqs-$VERSION/src"
[ -d "$SRC" ] || { echo "error: $SRC not found after extraction" >&2; exit 1; }

mkdir -p "$ROOT/build"

VERSION="$VERSION" SRC="$SRC" ROOT="$ROOT" python3 - <<'PY'
import os, re, sys

VERSION = os.environ["VERSION"]
SRC = os.environ["SRC"]
ROOT = os.environ["ROOT"]

PORTABLE_SUFFIXES = ("_clean", "_ref", "_opt")
# Optimized backends / non-portable target suffixes that must be skipped.
OPT_SUFFIXES = ("_avx2", "_avx512", "_neon", "_aarch64", "_x86_64",
                "_cuda", "_icicle_cuda", "_icicle")
ASM_EXT = (".S", ".s", ".asm")

# FrodoKEM files that are textually #include'd into the per-variant glue and
# must never be compiled standalone.
FRODO_EXCLUDE = re.compile(r"(frodo_macrify_.*\.c$)|(external/(noise|util|kem)\.c$)")


def read(path):
    with open(path, "r") as f:
        return f.read()


def alg_name_table(header, prefix):
    """Map variant id -> algorithm name string from kem.h / sig.h."""
    table = {}
    for m in re.finditer(r'#define\s+%s([A-Za-z0-9_]+)\s+"([^"]*)"' % prefix,
                         read(header)):
        table[m.group(1)] = m.group(2)
    return table


def balanced_paren(text, start):
    """Given index of '(' return (inner_text, index_after_close)."""
    depth = 0
    i = start
    while i < len(text):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:i], i + 1
        i += 1
    raise ValueError("unbalanced parentheses")


def resolve_include(raw, family_rel):
    """Resolve a CMake include dir token to a path relative to src/."""
    t = raw.strip()
    t = t.replace("${CMAKE_CURRENT_LIST_DIR}", family_rel)
    t = t.replace("${PROJECT_SOURCE_DIR}/src", "")
    t = t.lstrip("/")
    # Collapse a possible "family_rel/" with no subdir.
    return t


def split_if_blocks(text):
    """Yield (guard_expr, body_text) for each top-level if(...) ... endif()."""
    # We scan line by line, tracking depth of if/endif. We only need the
    # OUTERMOST blocks (depth 1) and we keep their full body (including any
    # nested if(Darwin) ...).
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = re.match(r"\s*if\s*\((.*)$", line)
        if m and not re.match(r"\s*if\s*\(.*\)\s*$", line) or m:
            # Found an if(. Collect the guard expression (may span lines) and
            # then the body until the matching endif().
            # Reconstruct guard up to its closing paren.
            guard, body_start_line, body_start_col = collect_guard(lines, i)
            body, end_i = collect_body(lines, body_start_line, body_start_col)
            yield guard, body
            i = end_i + 1
        else:
            i += 1


def collect_guard(lines, start_i):
    depth = 0
    buf = []
    i = start_i
    started = False
    while i < len(lines):
        line = lines[i]
        j = 0
        while j < len(line):
            c = line[j]
            if c == "(":
                depth += 1
                started = True
                if depth == 1:
                    j += 1
                    continue
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return "".join(buf).strip(), i, j + 1
            if started and depth >= 1:
                buf.append(c)
            j += 1
        buf.append(" ")
        i += 1
    raise ValueError("guard never closed")


def collect_body(lines, start_i, start_col):
    """Collect text from (start_i,start_col) until the matching endif()."""
    depth = 1
    out = []
    i = start_i
    col = start_col
    while i < len(lines):
        line = lines[i]
        rest = line[col:]
        # Detect if(/endif at statement granularity.
        for m in re.finditer(r"\b(if|endif)\s*\(", rest):
            pass
        # Simpler: count if(/endif tokens on this slice.
        for tok in re.finditer(r"\b(if|endif)\b\s*\(", rest):
            if tok.group(1) == "if":
                depth += 1
            else:
                depth -= 1
                if depth == 0:
                    # body ends just before this endif
                    end_col = col + tok.start()
                    out.append(line[col:end_col])
                    return "\n".join(out), i
        out.append(rest)
        col = 0
        i += 1
    raise ValueError("endif never found")


def parse_add_library(body):
    """Return (target, [files]) or None."""
    m = re.search(r"add_library\s*\(", body)
    if not m:
        return None
    inner, _ = balanced_paren(body, m.end() - 1)
    toks = inner.split()
    if len(toks) < 2 or toks[1] != "OBJECT":
        # snova/frodo use OBJECT as 2nd token; all portable do.
        if "OBJECT" not in toks:
            return None
    target = toks[0]
    try:
        oidx = toks.index("OBJECT")
    except ValueError:
        return None
    files = [t for t in toks[oidx + 1:] if t.endswith(".c")]
    return target, files


def collect_flags_includes(body, family_rel):
    """Return (flags, includes) where flags is list of (text, macos_only)."""
    flags = []
    includes = []
    seen_flag = set()
    seen_inc = set()

    # Identify the Darwin-only region(s): everything inside
    #   if (CMAKE_SYSTEM_NAME STREQUAL "Darwin") ... endif()
    darwin_spans = []
    for m in re.finditer(r'if\s*\([^)]*CMAKE_SYSTEM_NAME\s+STREQUAL\s+"Darwin"[^)]*\)',
                         body):
        # find matching endif from m.end()
        depth = 1
        idx = m.end()
        for tok in re.finditer(r"\b(if|endif)\b\s*\(", body[idx:]):
            if tok.group(1) == "if":
                depth += 1
            else:
                depth -= 1
                if depth == 0:
                    darwin_spans.append((m.start(), idx + tok.end()))
                    break

    def is_darwin(pos):
        return any(s <= pos < e for s, e in darwin_spans)

    def add_flag(text, macos_only):
        key = (text, macos_only)
        if key in seen_flag:
            return
        # If a token already present as non-macos, don't also add as macos.
        if (text, not macos_only) in seen_flag:
            return
        seen_flag.add(key)
        flags.append((text, macos_only))

    # target_compile_options: tokens are already -D.../-O...; keep verbatim.
    for m in re.finditer(r"target_compile_options\s*\(", body):
        inner, _ = balanced_paren(body, m.end() - 1)
        toks = inner.split()
        # drop target name + visibility keyword
        rest = [t for t in toks[1:] if t not in ("PRIVATE", "PUBLIC", "INTERFACE")]
        macos = is_darwin(m.start())
        for t in rest:
            if t.startswith("-m") or t.startswith("$<"):
                # arch/codegen flags belong to optimized backends; skip.
                continue
            add_flag(t, macos)

    # target_compile_definitions: bare tokens -> prefix with -D.
    for m in re.finditer(r"target_compile_definitions\s*\(", body):
        inner, _ = balanced_paren(body, m.end() - 1)
        toks = inner.split()
        rest = [t for t in toks[1:] if t not in ("PRIVATE", "PUBLIC", "INTERFACE")]
        macos = is_darwin(m.start())
        for t in rest:
            if t.startswith("${"):
                continue
            text = t if t.startswith("-D") else "-D" + t
            add_flag(text, macos)

    for m in re.finditer(r"target_include_directories\s*\(", body):
        inner, _ = balanced_paren(body, m.end() - 1)
        toks = inner.split()
        rest = [t for t in toks[1:] if t not in ("PRIVATE", "PUBLIC", "INTERFACE")]
        for t in rest:
            inc = resolve_include(t, family_rel)
            if inc not in seen_inc:
                seen_inc.add(inc)
                includes.append(inc)

    return flags, includes


class Algo:
    def __init__(self, family, variant, kind, alg_name, files, flags, includes):
        self.family = family
        self.variant = variant
        self.kind = kind
        self.alg_name = alg_name
        self.files = files
        self.flags = flags
        self.includes = includes


SKIP_FAMILIES = {"uov"}
# Families with non-PQClean shapes handled by dedicated logic.
SPECIAL = {"frodokem", "slh_dsa", "bike"}

warnings = []
algos = []


def parse_regular(kind, family, header_table):
    fam_dir = os.path.join(SRC, kind, family)
    cml = os.path.join(fam_dir, "CMakeLists.txt")
    if not os.path.exists(cml):
        return
    family_rel = "%s/%s" % (kind, family)
    text = read(cml)
    found = 0
    for guard, body in split_if_blocks(text):
        gm = re.match(r"OQS_ENABLE_(KEM|SIG)_([A-Za-z0-9_]+)\s*$", guard.strip())
        if not gm:
            continue
        variant = gm.group(2)
        if any(variant.endswith(s) for s in OPT_SUFFIXES):
            continue
        al = parse_add_library(body)
        if not al:
            continue
        target, files = al
        if not any(target.endswith(s) for s in PORTABLE_SUFFIXES):
            continue
        files = [f for f in files if not f.endswith(ASM_EXT)]
        flags, includes = collect_flags_includes(body, family_rel)
        files = ["%s/%s" % (family_rel, f) for f in files]
        alg_name = header_table.get(variant)
        if alg_name is None:
            warnings.append("no alg_name for %s/%s" % (family, variant))
            alg_name = variant
        algos.append(Algo(family, variant, kind, alg_name, files, flags, includes))
        found += 1
    if found == 0:
        warnings.append("DRIFT: family %s/%s yielded 0 portable targets" % (kind, family))


def parse_frodokem(kem_table):
    family = "frodokem"
    fam_dir = os.path.join(SRC, "kem", family)
    text = read(os.path.join(fam_dir, "CMakeLists.txt"))
    family_rel = "kem/frodokem"
    # Each variant is its own if(OQS_ENABLE_KEM_frodokem_*) set(SRCS ...) block.
    for guard, body in split_if_blocks(text):
        gm = re.match(r"OQS_ENABLE_KEM_(frodokem_[A-Za-z0-9_]+)\s*$", guard.strip())
        if not gm:
            continue
        variant = gm.group(1)
        sm = re.search(r"set\s*\(\s*SRCS\b(.*?)\)", body, re.S)
        if not sm:
            continue
        raw = sm.group(1)
        files = [t for t in raw.split()
                 if t.endswith(".c") and not t.startswith("${")]
        files = [f for f in files if not FRODO_EXCLUDE.search(f)]
        files = ["%s/%s" % (family_rel, f) for f in files]
        includes = ["common/pqclean_shims"]
        alg_name = kem_table.get(variant, variant)
        algos.append(Algo(family, variant, "kem", alg_name, files, [], includes))


def parse_slh_dsa(sig_table):
    family = "slh_dsa"
    fam_dir = os.path.join(SRC, "sig", family)
    text = read(os.path.join(fam_dir, "CMakeLists.txt"))
    family_rel = "sig/slh_dsa"
    for guard, body in split_if_blocks(text):
        if guard.strip() != "OQS_ENABLE_SIG_SLH_DSA":
            continue
        al = parse_add_library(body)
        if not al:
            continue
        target, files = al
        files = [f for f in files if not f.endswith(ASM_EXT)]
        files = ["%s/%s" % (family_rel, f) for f in files]
        _, includes = collect_flags_includes(body, family_rel)
        # Single compile unit; schema's single alg_name cannot hold the ~156
        # algorithm names this target provides. Use a sentinel.
        algos.append(Algo(family, "slh_dsa", "sig",
                          "(multi: see oqsconfig OQS_ENABLE_SIG_slh_dsa_*)",
                          files, [], includes))
        return
    warnings.append("DRIFT: slh_dsa OQS_ENABLE_SIG_SLH_DSA block not found")


def parse_bike(kem_table):
    family = "bike"
    fam_dir = os.path.join(SRC, "kem", family)
    text = read(os.path.join(fam_dir, "CMakeLists.txt"))
    family_rel = "kem/bike"
    # Shared portable base sources from set(SRCS_R3 ...). Take only the first
    # (unconditional) assignment; later set() calls append AVX2/AVX512/pclmul.
    sm = re.search(r"set\s*\(\s*SRCS_R3\b(.*?)\)", text, re.S)
    base = []
    if sm:
        base = [t for t in sm.group(1).split()
                if t.endswith(".c") and not t.startswith("${")]
    # kem_bike.c is a shared glue unit (like the kem.c/sig.c dispatchers): it
    # self-gates all three levels via #ifdef OQS_ENABLE_KEM_bike_lN and uses
    # neither LEVEL nor FUNC_PREFIX. The CMake builds it as its own
    # add_library(kem_bike OBJECT kem_bike.c) BEFORE the per-level
    # add_compile_options(-include functions_renaming.h), so it gets none of
    # the per-level flags. Emit it once as variant "bike" with base flags
    # only; it must NOT be duplicated into the per-level entries.
    algos.append(Algo(family, "bike", "kem",
                      "(shared bike glue; algs are bike_l1/l3/l5)",
                      ["kem/bike/kem_bike.c"], [], ["common/pqclean_shims"]))
    # The renamed crypto cores (additional_r4/*.c) ARE compiled once per level
    # with distinct LEVEL/FUNC_PREFIX and the -include rename header.
    for level in ("bike_l1", "bike_l3", "bike_l5"):
        gm = re.search(r"if\s*\(\s*OQS_ENABLE_KEM_%s\s*\)" % level, text)
        if not gm:
            continue
        files = ["%s/%s" % (family_rel, f) for f in base]
        n = level[-1]
        flags = [
            ("-DLEVEL=%s" % n, False),
            ("-DFUNC_PREFIX=OQS_KEM_%s" % level, False),
            ("-DDISABLE_VPCLMUL", False),
            ("-include kem/bike/functions_renaming.h", False),
        ]
        includes = ["kem/bike/additional_r4", "common/pqclean_shims"]
        alg_name = kem_table.get(level, level)
        algos.append(Algo(family, level, "kem", alg_name, files, flags, includes))
    warnings.append("BIKE: kem_bike.c is emitted once as variant \"bike\" "
                    "(shared glue, base flags only); the additional_r4 cores "
                    "are per-level with LEVEL/FUNC_PREFIX. X86_64/ARCH_X86_64/"
                    "try_compile(VPCLMUL) branches and the top-level "
                    "-Wno-missing-braces/-Wno-missing-field-initializers "
                    "suppressions are not modeled; emitted DISABLE_VPCLMUL. "
                    "BIKE may be x86-only; next task's smoke test will confirm.")


kem_table = alg_name_table(os.path.join(SRC, "kem", "kem.h"), "OQS_KEM_alg_")
sig_table = alg_name_table(os.path.join(SRC, "sig", "sig.h"), "OQS_SIG_alg_")

kem_families = sorted(d for d in os.listdir(os.path.join(SRC, "kem"))
                      if os.path.isdir(os.path.join(SRC, "kem", d)))
sig_families = sorted(d for d in os.listdir(os.path.join(SRC, "sig"))
                      if os.path.isdir(os.path.join(SRC, "sig", d)))

for fam in kem_families:
    if fam in SKIP_FAMILIES:
        continue
    if fam == "frodokem":
        parse_frodokem(kem_table)
    elif fam == "bike":
        parse_bike(kem_table)
    elif fam in SPECIAL:
        continue
    else:
        parse_regular("kem", fam, kem_table)

for fam in sig_families:
    if fam in SKIP_FAMILIES:
        continue
    if fam == "slh_dsa":
        parse_slh_dsa(sig_table)
    elif fam in SPECIAL:
        continue
    else:
        parse_regular("sig", fam, sig_table)

# Deterministic ordering: by (kind, family, variant).
algos.sort(key=lambda a: (a.kind, a.family, a.variant))


def zstr(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


out = []
out.append("// GENERATED by tools/gen-manifest.sh from liboqs %s CMake metadata. Do not edit by hand." % VERSION)
out.append("pub const Kind = enum { kem, sig };")
out.append("pub const Flag = struct { text: []const u8, macos_only: bool = false };")
out.append("pub const Algo = struct {")
out.append("    family: []const u8,")
out.append("    variant: []const u8,")
out.append("    kind: Kind,")
out.append("    alg_name: [:0]const u8,")
out.append("    files: []const []const u8, // relative to src/")
out.append("    flags: []const Flag, // verbatim per-variant compile flags")
out.append("    includes: []const []const u8, // relative to src/")
out.append("};")
out.append("pub const algorithms = [_]Algo{")
for a in algos:
    out.append("    .{")
    out.append("        .family = %s," % zstr(a.family))
    out.append("        .variant = %s," % zstr(a.variant))
    out.append("        .kind = .%s," % a.kind)
    out.append("        .alg_name = %s," % zstr(a.alg_name))
    if a.files:
        out.append("        .files = &.{")
        for f in a.files:
            out.append("            %s," % zstr(f))
        out.append("        },")
    else:
        out.append("        .files = &.{},")
    if a.flags:
        out.append("        .flags = &.{")
        for text, mac in a.flags:
            if mac:
                out.append("            .{ .text = %s, .macos_only = true }," % zstr(text))
            else:
                out.append("            .{ .text = %s }," % zstr(text))
        out.append("        },")
    else:
        out.append("        .flags = &.{},")
    if a.includes:
        out.append("        .includes = &.{")
        for inc in a.includes:
            out.append("            %s," % zstr(inc))
        out.append("        },")
    else:
        out.append("        .includes = &.{},")
    out.append("    },")
out.append("};")
out.append("")

with open(os.path.join(ROOT, "build", "manifest.zig"), "w") as f:
    f.write("\n".join(out))

# -------------------------------------------------------------------------
# Scoped oqsconfig.h. Enable list is derived from the C-preprocessor guards
# in the dispatchers/headers (ground truth), NOT from the manifest variants,
# then SCOPED to the families listed in build/enabled-families.txt -- the
# single source of truth shared with build.zig. Enabling a family here that
# build.zig does not compile (or vice versa) breaks the link, so the two MUST
# derive from the same list.
# -------------------------------------------------------------------------
FAMILIES_TXT = os.path.join(ROOT, "build", "enabled-families.txt")
DEFAULT_FAMILIES = ["ml_kem", "ml_dsa", "mayo", "hqc", "falcon"]


def read_enabled_families():
    """Parse build/enabled-families.txt -> list of family names. Falls back to
    the current 5 if the file is missing (never silently emits maximal)."""
    if not os.path.exists(FAMILIES_TXT):
        warnings.append("enabled-families.txt missing; defaulting to %s"
                        % ", ".join(DEFAULT_FAMILIES))
        return list(DEFAULT_FAMILIES)
    fams = []
    for line in read(FAMILIES_TXT).splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        fams.append(s)
    if not fams:
        warnings.append("enabled-families.txt empty; defaulting to %s"
                        % ", ".join(DEFAULT_FAMILIES))
        return list(DEFAULT_FAMILIES)
    return fams


enabled_families = read_enabled_families()

guard_files = [
    os.path.join(SRC, "kem", "kem.c"), os.path.join(SRC, "kem", "kem.h"),
    os.path.join(SRC, "sig", "sig.c"), os.path.join(SRC, "sig", "sig.h"),
]
enables = set()
for gf in guard_files:
    for m in re.finditer(r"OQS_ENABLE_(KEM|SIG)_[A-Za-z0-9_]+", read(gf)):
        enables.add(m.group(0))


def keep(macro):
    low = macro.lower()
    if "uov" in low:
        return False
    if "_stfl_" in low or "xmss" in low or "lms" in low:
        return False
    # strip OQS_ENABLE_KEM_ / OQS_ENABLE_SIG_
    tail = re.sub(r"^OQS_ENABLE_(KEM|SIG)_", "", macro)
    tail_low = tail.lower()
    # Scope to enabled families: keep the family umbrella macro (uppercase
    # family name) and per-variant macros (family + "_" prefix). The "_"
    # guard prevents a family from matching a longer family's prefix.
    if not any(tail_low == fam or tail_low.startswith(fam + "_")
               for fam in enabled_families):
        return False
    # Umbrella macros are all-uppercase family names: keep.
    if tail == tail.upper():
        return True
    # Per-variant: drop optimized backends.
    if any(tail.endswith(s) for s in OPT_SUFFIXES):
        return False
    return True


kept = sorted(m for m in enables if keep(m))
kem_macros = [m for m in kept if m.startswith("OQS_ENABLE_KEM_")]
sig_macros = [m for m in kept if m.startswith("OQS_ENABLE_SIG_")]

cfg = []
cfg.append("// SPDX-License-Identifier: MIT")
cfg.append("// GENERATED by tools/gen-manifest.sh from liboqs %s. Do not edit by hand." % VERSION)
cfg.append("// Portable-only build configuration for ZigOQS, scoped to the families that")
cfg.append("// build.zig currently compiles (build/enabled-families.txt, the single source")
cfg.append("// of truth this generator reads). This MUST stay in sync with that list: the")
cfg.append("// kem/sig dispatchers (kem.c/sig.c) reference OQS_*_<alg>_new() under these")
cfg.append("// OQS_ENABLE_* guards, and kem.h/sig.h #include the per-family umbrella headers")
cfg.append("// under the family-level guards. Enabling a family here without compiling it")
cfg.append("// (or vice versa) breaks the build.")
cfg.append("// UOV (needs OpenSSL), stateful signatures, and optimized backends excluded.")
cfg.append("")
cfg.append("#ifndef OQS_OQSCONFIG_H")
cfg.append("#define OQS_OQSCONFIG_H")
cfg.append("")
maj, minr, pat = VERSION.split(".")
cfg.append("// --- Version ---")
cfg.append('#define OQS_VERSION_TEXT "%s"' % VERSION)
cfg.append("#define OQS_VERSION_MAJOR %s" % maj)
cfg.append("#define OQS_VERSION_MINOR %s" % minr)
cfg.append("#define OQS_VERSION_PATCH %s" % pat)
cfg.append("")
cfg.append("// --- Build target / system ---")
cfg.append('#define OQS_COMPILE_BUILD_TARGET "generic"')
cfg.append("#define OQS_DIST_BUILD 1")
cfg.append("#define OQS_BUILD_ONLY_LIB 1")
cfg.append("")
cfg.append("// --- System feature flags ---")
cfg.append("#define OQS_HAVE_POSIX_MEMALIGN 1")
cfg.append("")
cfg.append("// --- No GPU/CUPQC/ICICLE/libjade ---")
cfg.append("#define OQS_USE_CUPQC 0")
cfg.append("#define OQS_USE_ICICLE 0")
cfg.append("#define OQS_LIBJADE_BUILD 0")
cfg.append("")
cfg.append("// --- KEMs ---")
for m in kem_macros:
    cfg.append("#define %s 1" % m)
cfg.append("")
cfg.append("// --- SIGs ---")
for m in sig_macros:
    cfg.append("#define %s 1" % m)
cfg.append("")
cfg.append("// Families not listed in build/enabled-families.txt, plus UOV (requires")
cfg.append("// OpenSSL) and stateful signatures (XMSS/LMS), are intentionally left")
cfg.append("// undefined until they are compiled.")
cfg.append("")
cfg.append("#endif // OQS_OQSCONFIG_H")
cfg.append("")

with open(os.path.join(ROOT, "include", "oqs", "oqsconfig.h"), "w") as f:
    f.write("\n".join(cfg))

# -------------------------------------------------------------------------
# Report to stderr.
# -------------------------------------------------------------------------
from collections import Counter
fam_counts = Counter("%s/%s" % (a.kind, a.family) for a in algos)
print("manifest: %d algorithm entries" % len(algos), file=sys.stderr)
for fam in sorted(fam_counts):
    print("  %-24s %d" % (fam, fam_counts[fam]), file=sys.stderr)
print("oqsconfig: %d KEM macros, %d SIG macros" % (len(kem_macros), len(sig_macros)), file=sys.stderr)
if warnings:
    print("warnings:", file=sys.stderr)
    for w in warnings:
        print("  - " + w, file=sys.stderr)
PY

echo "Done. Wrote build/manifest.zig and include/oqs/oqsconfig.h" >&2
