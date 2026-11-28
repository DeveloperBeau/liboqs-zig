// The liboqs C API that the known-answer harness calls directly: the random
// source, the NIST DRBG state and the SHAKE256 state of the HQC generator.
#include <oqs/oqs.h>
#include <oqs/rand_nist.h>
#include <oqs/sha3.h>
