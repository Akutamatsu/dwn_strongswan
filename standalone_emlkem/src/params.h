#ifndef PARAMS_H
#define PARAMS_H

#ifndef KYBER_K
#define KYBER_K 3	/* Change this for different security strengths */
#endif

#ifndef CCA_MODE
#define CPAF_MODE
#endif

#ifdef CPAF_MODE
#if   (KYBER_K == 2)
#define CRYPTO_ALGNAME "eMLKEM-512"
#elif (KYBER_K == 3)
#define CRYPTO_ALGNAME "eMLKEM-768"
#elif (KYBER_K == 4)
#define CRYPTO_ALGNAME "eMLKEM-1024"
#endif
# else
#if   (KYBER_K == 2)
#define CRYPTO_ALGNAME "MLKEM-512"
#elif (KYBER_K == 3)
#define CRYPTO_ALGNAME "MLKEM-768"
#elif (KYBER_K == 4)
#define CRYPTO_ALGNAME "MLKEM-1024"
#endif
#endif

/* Don't change parameters below this line */
#if   (KYBER_K == 2)
#define KYBER_NAMESPACE(s) pqcrystals_kyber512_ref_##s
#elif (KYBER_K == 3)
#define KYBER_NAMESPACE(s) pqcrystals_kyber768_ref_##s
#elif (KYBER_K == 4)
#define KYBER_NAMESPACE(s) pqcrystals_kyber1024_ref_##s
#else
#error "KYBER_K must be in {2,3,4}"
#endif

#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

#define KYBER_POLYBYTES		384
#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)

/* Switch between CCA/CPAF params */
# ifdef CPAF_MODE
#define PK_COMPRESS
#define CONF_LEN 32
// New Compress Params
#if KYBER_K == 2
#define KYBER_ETA1 3
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 256)
#define KYBER_PK_POLYVECBYTES        (KYBER_K * 256)
#elif KYBER_K == 3
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 256)
#define KYBER_PK_POLYVECBYTES        (KYBER_K * 256)
#elif KYBER_K == 4
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    96
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 256)
#define KYBER_PK_POLYVECBYTES        (KYBER_K * 288)
#endif

# else
// Origninal params
 #if KYBER_K == 2
 #define KYBER_ETA1 3
 #define KYBER_POLYCOMPRESSEDBYTES    128
 #define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
 #elif KYBER_K == 3
 #define KYBER_ETA1 2
 #define KYBER_POLYCOMPRESSEDBYTES    128
 #define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
 #elif KYBER_K == 4
 #define KYBER_ETA1 2
 #define KYBER_POLYCOMPRESSEDBYTES    160
 #define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
 #endif
#define KYBER_PK_POLYVECBYTES KYBER_POLYVECBYTES

# endif // END CPAF_MODE

#define KYBER_ETA2 2

#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_PK_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
#ifdef CPAF_MODE
/* No need in sk to store implicit rejection seed z */
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES)
#define KYBER_CIPHERTEXTBYTES  (KYBER_INDCPA_BYTES + CONF_LEN)

#else // CCA_MODE
/* 32 bytes to save H(pk) & 32 bytes to save implicit rejection seed z */
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)
#endif

#endif
