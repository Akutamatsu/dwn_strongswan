#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
//#include "../kem.h"
#include "../api.h"
#include "../params.h"
#include "../indcpa.h"
#include "../polyvec.h"
#include "../poly.h"
#include "../randombytes.h"
#include "cpucycles.h"
#include "speed_print.h"

#define NTESTS 100000

uint64_t t[NTESTS];
uint8_t seed[KYBER_SYMBYTES] = {0};

#if   (KYBER_K == 2)
#define crypto_kem_keypair_derand pqcrystals_kyber512_ref_keypair_derand
#define crypto_kem_keypair        pqcrystals_kyber512_ref_keypair
#define crypto_kem_enc_derand     pqcrystals_kyber512_ref_enc_derand
#define crypto_kem_enc            pqcrystals_kyber512_ref_enc
#define crypto_kem_dec            pqcrystals_kyber512_ref_dec

#define CRYPTO_SECRETKEYBYTES   pqcrystals_kyber512_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES   pqcrystals_kyber512_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES  pqcrystals_kyber512_CIPHERTEXTBYTES
#define KEYPAIRCOINBYTES        pqcrystals_kyber512_KEYPAIRCOINBYTES
#define ENCCOINBYTES            pqcrystals_kyber512_ENCCOINBYTES
#define CRYPTO_BYTES            pqcrystals_kyber512_BYTES

#elif (KYBER_K == 3)
#define crypto_kem_keypair_derand pqcrystals_kyber768_ref_keypair_derand
#define crypto_kem_keypair        pqcrystals_kyber768_ref_keypair
#define crypto_kem_enc_derand     pqcrystals_kyber768_ref_enc_derand
#define crypto_kem_enc            pqcrystals_kyber768_ref_enc
#define crypto_kem_dec            pqcrystals_kyber768_ref_dec

#define CRYPTO_SECRETKEYBYTES   pqcrystals_kyber768_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES   pqcrystals_kyber768_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES  pqcrystals_kyber768_CIPHERTEXTBYTES
#define KEYPAIRCOINBYTES        pqcrystals_kyber768_KEYPAIRCOINBYTES
#define ENCCOINBYTES            pqcrystals_kyber768_ENCCOINBYTES
#define CRYPTO_BYTES            pqcrystals_kyber768_BYTES

#elif (KYBER_K == 4)
#define crypto_kem_keypair_derand pqcrystals_kyber1024_ref_keypair_derand
#define crypto_kem_keypair        pqcrystals_kyber1024_ref_keypair
#define crypto_kem_enc_derand     pqcrystals_kyber1024_ref_enc_derand
#define crypto_kem_enc            pqcrystals_kyber1024_ref_enc
#define crypto_kem_dec            pqcrystals_kyber1024_ref_dec

#define CRYPTO_SECRETKEYBYTES   pqcrystals_kyber1024_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES   pqcrystals_kyber1024_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES  pqcrystals_kyber1024_CIPHERTEXTBYTES
#define KEYPAIRCOINBYTES        pqcrystals_kyber1024_KEYPAIRCOINBYTES
#define ENCCOINBYTES            pqcrystals_kyber1024_ENCCOINBYTES
#define CRYPTO_BYTES            pqcrystals_kyber1024_BYTES
#endif

int main(void)
{
  unsigned int i;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key[CRYPTO_BYTES];
  uint8_t coins32[ENCCOINBYTES];
  uint8_t coins64[KEYPAIRCOINBYTES];
  polyvec matrix[KYBER_K];
  poly ap;

  printf("\n=== [Test] %s start ===\n\n", CRYPTO_ALGNAME);

  randombytes(coins32, ENCCOINBYTES);
  randombytes(coins64, KEYPAIRCOINBYTES);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_keypair_derand(pk, sk, coins64);
  }
  print_results("kyber_keypair_derand: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_keypair(pk, sk);
  }
  print_results("kyber_keypair: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_enc_derand(ct, key, pk, coins32);
  }
  print_results("kyber_encaps_derand: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_enc(ct, key, pk);
  }
  print_results("kyber_encaps: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_dec(key, ct, sk);
  }
  print_results("kyber_decaps: ", t, NTESTS);
  
  printf("=== [Test] %s End (iteration: %d) ===\n\n", CRYPTO_ALGNAME, NTESTS);

  return 0;
}
