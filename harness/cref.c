#include <oqs/oqs.h>
#include <oqs/rand_nist.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

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

static void run_kem(const char *algo) {
    OQS_KEM *k = OQS_KEM_new(algo);
    if (!k) { fprintf(stderr, "no kem %s\n", algo); exit(1); }
    uint8_t *pk = malloc(k->length_public_key), *sk = malloc(k->length_secret_key);
    uint8_t *ct = malloc(k->length_ciphertext), *ss = malloc(k->length_shared_secret);
    uint8_t *ss2 = malloc(k->length_shared_secret);
    seed(); OQS_KEM_keypair(k, pk, sk);
    seed(); OQS_KEM_encaps(k, ct, ss, pk);
    OQS_KEM_decaps(k, ss2, ct, sk);
    emit(algo, "pk", pk, k->length_public_key);
    emit(algo, "sk", sk, k->length_secret_key);
    emit(algo, "ct", ct, k->length_ciphertext);
    emit(algo, "ss", ss, k->length_shared_secret);
    emit(algo, "ss2", ss2, k->length_shared_secret);
    free(pk); free(sk); free(ct); free(ss); free(ss2); OQS_KEM_free(k);
}

static void run_sig(const char *algo) {
    OQS_SIG *s = OQS_SIG_new(algo);
    if (!s) { fprintf(stderr, "no sig %s\n", algo); exit(1); }
    uint8_t *pk = malloc(s->length_public_key), *sk = malloc(s->length_secret_key);
    uint8_t *sig = malloc(s->length_signature);
    const uint8_t msg[] = "the quick brown fox";
    size_t msglen = sizeof(msg) - 1; /* drop trailing NUL: 19 bytes */
    size_t siglen = 0;
    seed(); OQS_SIG_keypair(s, pk, sk);
    seed(); OQS_SIG_sign(s, sig, &siglen, msg, msglen, sk);
    emit(algo, "pk", pk, s->length_public_key);
    emit(algo, "sk", sk, s->length_secret_key);
    emit(algo, "sig", sig, siglen);
    free(pk); free(sk); free(sig); OQS_SIG_free(s);
}

int main(void) {
    OQS_init();
    run_kem("ML-KEM-768");
    run_sig("ML-DSA-65");
    run_sig("MAYO-2");
    return 0;
}
