#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "src/kem.h"
#include "src/params.h"

int main(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t encapsulated[CRYPTO_BYTES];
    uint8_t decapsulated[CRYPTO_BYTES];

    for (unsigned int attempt = 1; attempt <= 100; attempt++)
    {
        if (crypto_kem_keypair(pk, sk) != 0 ||
            crypto_kem_enc(ct, encapsulated, pk) != 0)
        {
            fputs("FAIL: key generation or encapsulation returned an error\n", stderr);
            return 1;
        }
        if (crypto_kem_dec(decapsulated, ct, sk) != 0)
        {
            continue;
        }
        if (memcmp(encapsulated, decapsulated, CRYPTO_BYTES) != 0)
        {
            fputs("FAIL: undetected shared-key mismatch\n", stderr);
            return 1;
        }
        printf("public key: %d bytes\n", CRYPTO_PUBLICKEYBYTES);
        printf("ciphertext: %d bytes\n", CRYPTO_CIPHERTEXTBYTES);
        printf("successful attempt: %u\n", attempt);
        puts("PASS: eMLKEM-768 key generation, encapsulation, and decapsulation");
        return 0;
    }

    fputs("FAIL: all 100 attempts reported a detected decapsulation failure\n", stderr);
    return 1;
}
