#include <oqs/oqs.h>
#include <oqs/rand_nist.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Raw C side of the stateful parity check. Each algorithm gets one keygen and
 * one sign under the NIST-KAT seed, and the harness prints the public key, the
 * signature and the signature counts after that one sign. The secret key is
 * never printed. This stays out of cref.c so the frozen snapshot, which
 * tools/snapshot.sh builds from the zig side alone, has no stateful lines.
 *
 * Only parameter sets with a total tree height of 16 or less run, unless
 * OQS_STATEFUL_ALL=1. The same rule lives in harness/stfl_filter.zig. With
 * --list the harness prints "run NAME HEIGHT" or "skip NAME HEIGHT" for every
 * enabled name and does nothing else. */

#define MAX_DEFAULT_HEIGHT 16

static void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p) { fprintf(stderr, "out of memory (%zu bytes)\n", n); exit(1); }
    return p;
}

static void seed(void) {
    uint8_t e[48];
    for (int i = 0; i < 48; i++) e[i] = (uint8_t)i;
    OQS_randombytes_custom_algorithm(&OQS_randombytes_nist_kat);
    OQS_randombytes_nist_kat_init_256bit(e, NULL);
}

static void emit(const char *algo, const char *field, const uint8_t *buf, size_t n) {
    printf("%s %s ", algo, field);
    for (size_t i = 0; i < n; i++) printf("%02x", buf[i]);
    printf("\n");
}

/* A count is printed as 8 bytes, big-endian, in hex. */
static void emit_count(const char *algo, const char *field, unsigned long long v) {
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (56 - 8 * i));
    emit(algo, field, b, 8);
}

/* Total height from a liboqs name: XMSS-SHA2_10_256 is 10, XMSSMT-SHA2_20/2_256
 * is 20 and LMS_SHA256_H10_W4_H5_W8 is 10 + 5. An unreadable name counts as
 * too tall, so it only runs with OQS_STATEFUL_ALL=1. */
static long total_height(const char *name) {
    if (strncmp(name, "LMS_", 4) == 0) {
        long sum = 0;
        const char *p = name;
        while ((p = strchr(p, '_')) != NULL) {
            p++;
            if (*p == 'H') sum += atol(p + 1);
        }
        return sum;
    }
    const char *u = strchr(name, '_');
    if (!u) return 1000;
    long h = atol(u + 1);
    return h > 0 ? h : 1000;
}

static int store_ok(uint8_t *sk_buf, size_t len, void *ctx) {
    (void)sk_buf; (void)len; (void)ctx;
    return OQS_SUCCESS;
}

static void run_one(const char *algo) {
    OQS_SIG_STFL *s = OQS_SIG_STFL_new(algo);
    if (!s) { fprintf(stderr, "no stateful sig %s\n", algo); exit(1); }
    OQS_SIG_STFL_SECRET_KEY *key = OQS_SIG_STFL_SECRET_KEY_new(algo);
    if (!key) { fprintf(stderr, "no secret key for %s\n", algo); exit(1); }
    /* liboqs calls the store callback after keygen and sign. This one keeps
     * nothing and reports success. The context must be non-NULL, because LMS
     * drops a callback registered with a NULL context. */
    OQS_SIG_STFL_SECRET_KEY_SET_store_cb(key, store_ok, key);
    uint8_t *pk = xmalloc(s->length_public_key);
    uint8_t *sig = xmalloc(s->length_signature);
    const uint8_t msg[] = "the quick brown fox";
    size_t msglen = sizeof(msg) - 1; /* drop trailing NUL: 19 bytes */
    size_t siglen = 0;
    unsigned long long remaining = 0, total = 0;
    seed();
    if (OQS_SIG_STFL_keypair(s, pk, key) != OQS_SUCCESS) { fprintf(stderr, "keygen failed %s\n", algo); exit(1); }
    seed();
    if (OQS_SIG_STFL_sign(s, sig, &siglen, msg, msglen, key) != OQS_SUCCESS) { fprintf(stderr, "sign failed %s\n", algo); exit(1); }
    if (OQS_SIG_STFL_sigs_remaining(s, &remaining, key) != OQS_SUCCESS) { fprintf(stderr, "remaining failed %s\n", algo); exit(1); }
    if (OQS_SIG_STFL_sigs_total(s, &total, key) != OQS_SUCCESS) { fprintf(stderr, "total failed %s\n", algo); exit(1); }
    emit(algo, "pk", pk, s->length_public_key);
    emit(algo, "sig", sig, siglen);
    emit_count(algo, "remaining", remaining);
    emit_count(algo, "total", total);
    free(pk); free(sig);
    OQS_SIG_STFL_SECRET_KEY_free(key);
    OQS_SIG_STFL_free(s);
}

int main(int argc, char **argv) {
    int list = argc > 1 && strcmp(argv[1], "--list") == 0;
    const char *a = getenv("OQS_STATEFUL_ALL");
    int all = a && strcmp(a, "1") == 0;
    const char *sh = getenv("OQS_SHARD"), *t = getenv("OQS_TOTAL");
    long shard = sh ? atol(sh) : 0;
    long total = t ? atol(t) : 1;
    if (total < 1) total = 1;
    OQS_init();
    long idx = 0;
    for (size_t i = 0; i < (size_t)OQS_SIG_STFL_alg_count(); i++) {
        const char *name = OQS_SIG_STFL_alg_identifier(i);
        if (!OQS_SIG_STFL_alg_is_enabled(name)) continue;
        long h = total_height(name);
        int run = all || h <= MAX_DEFAULT_HEIGHT;
        if (list) { printf("%s %s %ld\n", run ? "run" : "skip", name, h); continue; }
        if (!run) continue;
        if (idx++ % total == shard) {
            fprintf(stderr, "  stfl_cref[%ld] %s\n", shard, name);
            run_one(name);
        }
    }
    return 0;
}
