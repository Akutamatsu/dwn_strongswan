#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "kem.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "randombytes.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>

static void prf_hmac_sha256(unsigned char out[CONF_LEN], const unsigned char* key, int keylen,
    const unsigned char *input, int inlen)
{
    unsigned int out_len = 0;
    HMAC(EVP_sha3_256(), key, keylen, (unsigned char*)input, inlen, out, &out_len);
}

/*************************************************
* Name:        crypto_kem_keypair_derand
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*              - uint8_t *coins: pointer to input randomness
*                (an already allocated array filled with KYBER_SYMBYTES random bytes)
**
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair_derand(uint8_t *pk,
                              uint8_t *sk,
                              const uint8_t *coins)
{
  indcpa_keypair_derand(pk, sk, coins);
  /* No need for implicit rejection seed 'z' any more */
  return 0;
}

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(uint8_t *pk,
                       uint8_t *sk)
{
  uint8_t coins[KYBER_SYMBYTES];
  randombytes(coins, KYBER_SYMBYTES);
  crypto_kem_keypair_derand(pk, sk, coins);
  return 0;
}

/*************************************************
* Name:        crypto_kem_enc_derand
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - const uint8_t *coins: pointer to input randomness
*                (an already allocated array filled with KYBER_SYMBYTES random bytes)
**
* Returns 0 (success)
**************************************************/
int crypto_kem_enc_derand(uint8_t *ct,
                          uint8_t *ss,
                          const uint8_t *pk,
                          const uint8_t *coins)
{
  uint8_t buf[2*KYBER_SYMBYTES];
  uint8_t *mac_tag = ct + KYBER_CIPHERTEXTBYTES - CONF_LEN;

  memcpy(buf, coins, 2* KYBER_SYMBYTES); // needs double length coins. (without using hash(pk))
  
  /* coins are in buf+KYBER_SYMBYTES */
  indcpa_enc(ct, buf, pk, buf + KYBER_SYMBYTES);

  /* append ct' with conf = PRF(mu, ct) to  (ct' || conf) */
  prf_hmac_sha256(mac_tag, buf, CRYPTO_BYTES, ct, KYBER_CIPHERTEXTBYTES - CONF_LEN);
  
  hash_h(ss, buf, KYBER_SYMBYTES); /* output k: = hash_h(mu) */
  return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk)
{
  uint8_t coins[2*KYBER_SYMBYTES];
  randombytes(coins, 2*KYBER_SYMBYTES);
  crypto_kem_enc_derand(ct, ss, pk, coins);
  return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *ct: pointer to input cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk)
{
  int fail;
  uint8_t buf[CRYPTO_BYTES];
  uint8_t cmp[CONF_LEN] = { 0 };

  /* decrypt mu' from c in ct=(c,conf) */
  indcpa_dec(buf, ct, sk);

  /* Compute PRF(mu', hct) and compare with conf */
  prf_hmac_sha256(cmp, buf, CRYPTO_BYTES, ct, KYBER_CIPHERTEXTBYTES - CONF_LEN);
  fail = verify(cmp, ct + KYBER_CIPHERTEXTBYTES - CONF_LEN, CONF_LEN);

  /* hash pre-key mu' to get true key K' */
  hash_h(buf, buf, KYBER_SYMBYTES);

  /* Copy true key to return buffer if fail is false */
  cmov(ss, buf, KYBER_SYMBYTES, !fail);

  return fail;
}
