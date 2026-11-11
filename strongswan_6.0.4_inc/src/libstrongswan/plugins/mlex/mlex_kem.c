/*
 * Copyright (C) 2024 Tobias Brunner
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "mlex_bitpacker.h"
#include "mlex_kem.h"
#include "mlex_params.h"
#include "mlex_poly.h"
#include "mlex_utils.h"

typedef struct private_key_exchange_t private_key_exchange_t;

/**
 * Private data.
 */
struct private_key_exchange_t {

	/**
	 * Public interface.
	 */
	key_exchange_t public;

	/**
	 * Key exchange method.
	 */
	key_exchange_method_t method;

	/**
	 * Parameter set.
	 */
	const mlex_kem_params_t *params;

	/**
	 * Decryption/private key as initiator (array of k polynomials).
	 */
	chunk_t private_key;

	/**
	 * Encryption/public key and matrix A as initiator (array of k polynomials,
	 * followed by a matrix of k*k polynomials).
	 */
	chunk_t public_key;

	/**
	 * Additional key data as initiator (hash of encoded public key,
	 * rejection seed z).
	 */
	// chunk_t key_data;

	/**
	 * Ciphertext as responder.
	 */
	chunk_t ciphertext;

	/**
	 * Shared secret.
	 */
	chunk_t shared_secret;

	/**
	 * SHAKE-128 instance used as XOF when generating matrix A.
	 */
	xof_t *shake128;

	/**
	 * SHAKE-256 instance used as PRF and hash function J.
	 */
	xof_t *shake256;

	/**
	 * Hash function G (SHA3-512) used throughout the algorithms.
	 */
	hasher_t *G;

	/**
	 * Hash function H (SHA3-256) used throughout the algorithms.
	 */
	hasher_t *H;

#ifdef TESTABLE_KE
	/**
	 * DRBG used during testing.
	 */
	drbg_t *drbg;
#endif
};

/**
 * Get random bytes either from a DRBG during testing or from an RNG.
 */
static bool get_random(private_key_exchange_t *this, size_t len, uint8_t *out)
{
	rng_t *rng;

#ifdef TESTABLE_KE
	if (this->drbg)
	{
		return this->drbg->generate(this->drbg, len, out);
	}
#endif

	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!rng || !rng->get_bytes(rng, len, out))
	{
		DESTROY_IF(rng);
		return FALSE;
	}
	rng->destroy(rng);
	return TRUE;
}

/**
 * Generate a pseudorandom element of T_q using the given XOF.
 *
 * Algorithm 7 in FIPS 203.
 */
static bool sample_ntt(private_key_exchange_t *this, mlex_poly_t *ahat)
{
	uint8_t C[3];
	uint16_t d1, d2;
	int j = 0;

	while (j < ML_KEM_N)
	{
		if (!this->shake128->get_bytes(this->shake128, sizeof(C), C))
		{
			return FALSE;
		}
		d1 = C[0] + ((C[1] & 0xf) << 8);
		d2 = (C[1] >> 4) + (C[2] << 4);
		if (d1 < ML_KEM_Q)
		{
			ahat->f[j++] = d1;
		}
		if (d2 < ML_KEM_Q && j < ML_KEM_N)
		{
			ahat->f[j++] = d2;
		}
	}
	return TRUE;
}

/**
 * Generate pseudorandom matrix A or its transposed version A^T.
 */
static bool generate_a(private_key_exchange_t *this, mlex_poly_t *a,
					   uint8_t *rho)
{
	const uint8_t k = this->params->k;

	chunk_t B = chunk_alloca(ML_KEM_SEED_LEN + 2);
	int i, j;

	memcpy(B.ptr, rho, ML_KEM_SEED_LEN);
	for (i = 0; i < k; i++)
	{
		for (j = 0; j < k; j++)
		{
			B.ptr[ML_KEM_SEED_LEN] = j;
			B.ptr[ML_KEM_SEED_LEN + 1] = i;
			if (!this->shake128->set_seed(this->shake128, B) ||
				!sample_ntt(this, &a[i*k + j]))
			{
				return FALSE;
			}
		}
	}
	return TRUE;
}

/**
 * Derives a seed via PRF_eta(s, N) = SHAKE256(s||N, 64 * eta) from the given
 * random 32-byte seed and nonce N and outputs a pseudorandom polynomial sampled
 * from the distribution D_eta(R_q) of polynomials in R_q with small
 * coefficients, with each coefficient sampled independently from a certain
 * centered binomial distribution (CBD) on Z_q.
 *
 * Algorithm 8 in FIPS 203.
 */
static void sample_poly_cbd(private_key_exchange_t *this, uint8_t eta,
							uint8_t *s, uint8_t N, mlex_poly_t *p)
{
	/* this uses an optimization from the reference implementation. since eta
	 * can only take two values for the current parameter sets (it's actually 2
	 * for all but ML-KEM-512 that uses 3 for eta1), we can optimize this and
	 * either add together 16*2 or 8*3 bits concurrently and then split the
	 * result into 8 or 4 coefficients, respectively */
	const int coeffs = (eta == 2) ? 8 : 4;
	const int fetch = 2 * coeffs * eta / 8;
	/* every second or third bit is set in these masks */
	const uint32_t add_mask = (eta == 2) ? 0x55555555 : 0x00249249;
	const uint32_t mask = (eta == 2) ? 0x3 : 0x7;
	const int len = 64 * eta;

	chunk_t seed = chunk_alloca(ML_KEM_SEED_LEN+1);
	uint8_t sample_seed[len];
	uint32_t t, b;
	uint16_t x, y;
	int i, j;

	memcpy(seed.ptr, s, ML_KEM_SEED_LEN);
	seed.ptr[ML_KEM_SEED_LEN] = N;

	ignore_result(this->shake256->set_seed(this->shake256, seed) &&
				  this->shake256->get_bytes(this->shake256, len, sample_seed));

	for (i = 0; i < ML_KEM_N/coeffs; i++)
	{
		/* get a bit stream from the seed */
		t = mlex_read_bytes_le(sample_seed + fetch*i, fetch);

		/* add together eta consecutive bits */
		b = t & add_mask;
		b += (t >> 1) & add_mask;
		if (eta == 3)
		{
			b += (t >> 2) & add_mask;
		}

		for (j = 0; j < coeffs; j++)
		{
			x = (b >> (2*j*eta)) & mask;
			y = (b >> (2*j*eta + eta)) & mask;
			p->f[coeffs*i + j] = mlex_reduce_modq(x - y + ML_KEM_Q);
		}
	}

	memwipe(seed.ptr, seed.len);
	memwipe(sample_seed, sizeof(sample_seed));
}

/**
 * Multiply the given two (reduced) numbers, followed by a Barrett reduction to
 * get a*b mod q so i.e. a*b - [a*b*m/R]*q (where m is [R/q], R is 2^40 and
 * rounded against zero).  Note that m/2^40 is close enough to 1/q that no
 * fixup is necessary after the final subtraction.
 */
static uint16_t mul_modq(uint16_t a, uint16_t b)
{
	const uint64_t m = (1ULL << 40) / ML_KEM_Q;
	const uint32_t prod = (uint32_t)a * b;

	uint32_t t;

	t = (prod * m) >> 40;
	return prod - t * ML_KEM_Q;
}

/**
 * Computes the number-theoretic transform (NTT) representation of the given
 * polynomial p in place.
 *
 * Algorithm 9 in FIPS 203.
 */
static void ntt(private_key_exchange_t *this, mlex_poly_t *p)
{
	int len, start, i = 1, j;
	uint16_t zeta, t;

	for (len = ML_KEM_N / 2; len >= 2; len /= 2)
	{
		for (start = 0; start < ML_KEM_N; start += 2 * len)
		{
			zeta = mlex_kem_zetas[i++];
			for (j = start; j < start + len; j++)
			{
				t = mul_modq(zeta, p->f[j + len]);
				p->f[j + len] = mlex_reduce_modq(p->f[j] - t + ML_KEM_Q);
				p->f[j] = mlex_reduce_modq(p->f[j] + t);
			}
		}
	}
}

/**
 * Computes the polynomial p that corresponds to the given number-theoretic
 * transform (NTT) representation of it in place.
 *
 * Algorithm 10 in FIPS 203.
 */
static void ntt_inv(private_key_exchange_t *this, mlex_poly_t *p)
{
	const uint16_t f = 3303;

	int len, start, i = 127, j;
	uint16_t zeta, t;

	for (len = 2; len <= 128; len *= 2)
	{
		for (start = 0; start < ML_KEM_N; start += 2 * len)
		{
			zeta = mlex_kem_zetas[i--];
			for (j = start; j < start + len; j++)
			{
				t = p->f[j];
				p->f[j] = mlex_reduce_modq(t + p->f[j + len]);
				p->f[j + len] = mul_modq(zeta, p->f[j + len] - t + ML_KEM_Q);
			}
		}
	}
	for (i = 0; i < ML_KEM_N; i++)
	{
		p->f[i] = mul_modq(p->f[i], f);
	}
}

/**
 * Multiply the two degree-one polynomials a (= a[0] + a[1]*X) and b with
 * respect to a quadratic modulus (X^2-gamma) and put the result in c.
 *
 * Algorithm 12 in FIPS 203.
 */
static void base_case_multiply(uint16_t *a, uint16_t *b, uint16_t *c,
							   uint16_t gamma)
{
	c[0] = mul_modq(a[1], b[1]);
	c[0] = mlex_reduce_modq(mul_modq(c[0], gamma) + mul_modq(a[0], b[0]));
	c[1] = mlex_reduce_modq(mul_modq(a[0], b[1])  + mul_modq(a[1], b[0]));
}

/**
 * Multiply two polynomials a and b in NTT domain and put them into c.
 *
 * Algorithm 11 in FIPS 203.
 */
static void multiply_poly(mlex_poly_t *a, mlex_poly_t *b, mlex_poly_t *c)
{
	int i;

	/* since the Zeta^(2BitRev_7(i)+1) mod q values required here can be found
	 * in the second half of the table for Zeta^BitRev_7(i) mod q, we reuse them
	 * and directly handle four coefficients per iteration instead of two */
	for (i = 0; i < ML_KEM_N/4; i++)
	{
		base_case_multiply(&a->f[4*i], &b->f[4*i], &c->f[4*i],
						   mlex_kem_zetas[i+64]);
		base_case_multiply(&a->f[4*i+2], &b->f[4*i+2], &c->f[4*i+2],
						   ML_KEM_Q - mlex_kem_zetas[i+64]);
	}
}

/**
 * Multiply the k polynomials in a with those in b and accumulate them into c.
 *
 * If transposed is TRUE, a is assumed to be a k*k matrix where polynomials from
 * a column are used (not a sequential row).
 *
 * See the note regarding the result of multiply_poly().
 */
static void multiply_poly_arr(uint8_t k, mlex_poly_t *a, mlex_poly_t *b,
							  mlex_poly_t *c, bool transposed)
{
	mlex_poly_t t;
	int i, f = transposed ? k : 1;

	multiply_poly(&a[0], &b[0], c);
	for (i = 1; i < k; i++)
	{
		multiply_poly(&a[i*f], &b[i], &t);
		mlex_poly_add(c, &t, c);
	}
}
#if 0 // old codes:
/**
 * Encode k polynomials to a byte array (12-bit version that packs 2
 * coefficients into 3 bytes, not using mlex_bitpacker_t for performance reasons).
 *
 * Algorithm 5 in FIPS 203.
 */
static void encode_poly_arr(uint8_t k, mlex_poly_t *a, uint8_t *out)
{
	uint16_t f0, f1;
	int i, j;

	for (i = 0; i < k; i++)
	{
		for (j = 0; j < ML_KEM_N / 2; j++)
		{
			f0 = a[i].f[2*j];
			f1 = a[i].f[2*j + 1];
			out[3*j]   = (uint8_t)f0;
			out[3*j+1] = (uint8_t)((f0 >> 8) | (f1 << 4));
			out[3*j+2] = (uint8_t)(f1 >> 4);
		}
		out += ML_KEM_POLY_LEN;
	}
}

/**
 * Decode k polynomials from a byte array (12-bit version that unpacks 2
 * coefficients from 3 bytes, not using mlex_bitpacker_t for performance reasons).
 *
 * Algorithm 6 in FIPS 203.
 */
static void decode_poly_arr(uint8_t k, uint8_t *in, mlex_poly_t *a)
{
	int i, j;

	for (i = 0; i < k; i++)
	{
		for (j = 0; j < ML_KEM_N / 2; j++)
		{
			a[i].f[2*j]   =  (in[3*j]         | ((uint16_t)in[3*j+1] << 8)) & 0xfff;
			a[i].f[2*j+1] = ((in[3*j+1] >> 4) | ((uint16_t)in[3*j+2] << 4)) & 0xfff;
		}
		in += ML_KEM_POLY_LEN;
	}
}
#endif
/**
 * Compress the k 12-bit polynomials in a to d bits and encode the result as
 * bytes in out.
 */
static void compress_polys_arr(uint8_t k, uint8_t d, mlex_poly_t *a, uint8_t *out)
{
	/* avoid division by replacing 2^d/q with [m/2^p] where m is [2^(p+d)/q] */
	const int p = 63 - d;
	const uint64_t m = ((1ULL << (p+d)) + ML_KEM_Q/2) / ML_KEM_Q;
	const uint64_t mask = (1 << d) - 1;

	mlex_bitpacker_t *packer;
	uint64_t f;
	int i, j;

	packer = mlex_bitpacker_create(chunk_create(out, k * d * ML_KEM_N / 8));
	for (i = 0; i < k; i++)
	{
		for (j = 0; j < ML_KEM_N; j++)
		{
			f = a[i].f[j];
			/* calculate the compression [f * 2^d/q mod 2^d] without division */
			f = ((f * m + (1ULL << (p - 1))) >> p) & mask;
			packer->write_bits(packer, f, d);
		}
	}
	packer->destroy(packer);
}

/**
 * Decompress the k 12-bit polynomials in a from a stream of d-bit chunks.
 */
static void decompress_poly_arr(uint8_t k, uint8_t d, uint8_t *in, mlex_poly_t *a)
{
	const uint16_t rounding = 1 << (d - 1);

	mlex_bitpacker_t *packer;
	uint32_t f;
	int i, j;

	packer = mlex_bitpacker_create_from_data(chunk_create(in, k * d * ML_KEM_N / 8));
	for (i = 0; i < k; i++)
	{
		for (j = 0; j < ML_KEM_N; j++)
		{
			/* calculate the decompression [f * q / 2^d] */
			packer->read_bits(packer, &f, d);
			a[i].f[j] = (f * ML_KEM_Q + rounding) >> d;
		}
	}
	packer->destroy(packer);
}

/**
 * Calculates Decompress_1(ByteDecode_1()) for the given message m of length
 * ML_KEM_SEED_LEN and puts the result into p.
 */
static void message_to_poly(uint8_t *m, mlex_poly_t *p)
{
	int i, j;

	for (i = 0; i < ML_KEM_SEED_LEN; i++)
	{
		for (j = 0; j < 8; j++)
		{
			/* can't use
			 *   p->f[8 * i + j] = (ML_KEM_Q + 1) / 2 * (m[i] >> j & 0x1);
			 * or some manual masking here because after recognizing that this
			 * is either 0 or a constant, some versions of clang apparently
			 * optimize this with a branching instruction to just skip over the
			 * assignment, creating a possible side-channel */
			p->f[8 * i + j] = 0;
			mlex_assign_cond_int16(&p->f[8 * i + j], (ML_KEM_Q + 1) / 2,
								 (m[i] >> j) & 0x1);
		}
	}
}

/**
 * Calculates ByteEncode_1(Compress_1()) for the given polynomial p to decode
 * message m of length ML_KEM_SEED_LEN.
 */
static void poly_to_message(mlex_poly_t *p, uint8_t *m)
{
	/* avoid division by replacing 2/q with [n/2^k] where n is [2^(k+1)/q] */
	const int k = 30;
	const uint32_t n = ((1 << (k+1)) + ML_KEM_Q/2) / ML_KEM_Q;

	uint32_t f;
	int i, j;

	for (i = 0; i < ML_KEM_SEED_LEN; i++)
	{
		m[i] = 0;
		for (j = 0; j < 8; j++)
		{
			f = p->f[8 * i + j];
			/* calculate the compression [f * 2/q mod 2] without division */
			f = ((f * n + (1 << (k-1))) >> k) & 0x1;
			m[i] |= f << j;
		}
	}
}

/**
 * Generate a key pair from the given random seed d.  Returns the encoded public
 * key.
 *
 * Algorithm 13 in FIPS 203.
 */
static bool pke_keygen(private_key_exchange_t *this, chunk_t d, chunk_t *ek)
{
	const uint8_t k = this->params->k;
	const uint8_t eta1 = this->params->eta1;
#if 1 // new codes:
	const uint8_t dt = this->params->dt;
#endif
	uint8_t seeds[2 * ML_KEM_SEED_LEN];
	uint8_t *rho = seeds;
	uint8_t *sigma = seeds + ML_KEM_SEED_LEN;
	uint8_t N = 0;
	mlex_poly_t *a, *s, e[k], *t;
	int i;
	bool success = FALSE;

	/* derive seeds for private and public key from randomness d and domain
	 * parameter k */
	if (!this->G->get_hash(this->G, d, NULL) ||
		!this->G->get_hash(this->G, chunk_from_thing(k), seeds))
	{
		goto err;
	}

	this->public_key = chunk_alloc((k+1) * k * sizeof(mlex_poly_t));
	t = (mlex_poly_t*)this->public_key.ptr;
	a = (mlex_poly_t*)this->public_key.ptr + k;

	/* generate matrix A */
	if (!generate_a(this, a, rho))
	{
		goto err;
	}

	this->private_key = chunk_alloc(k * sizeof(mlex_poly_t));
	s = (mlex_poly_t*)this->private_key.ptr;

	/* sample s from CBD using noise seed sigma and nonce N as input */
	for (i = 0; i < k; i++)
	{
		sample_poly_cbd(this, eta1, sigma, N++, &s[i]);
	}

	/* sample e from CBD using noise seed sigma and nonce N as input */
	for (i = 0; i < k; i++)
	{
		sample_poly_cbd(this, eta1, sigma, N++, &e[i]);
	}

	/* calculate s = NTT(s) */
	for (i = 0; i < k; i++)
	{
		ntt(this, &s[i]);
	}

#if 0 // old codes:
	/* calculate e = NTT(e) */
	for (i = 0; i < k; i++)
	{
		ntt(this, &e[i]);
	}

	/* calculate t = A * s + e to get the public key */
	for (i = 0; i < k; i++)
	{
		multiply_poly_arr(k, &a[i*k], s, &t[i], FALSE);
	}
	mlex_poly_add_arr(k, t, e, t);
	/* pack public key and rho */
	*ek = chunk_alloc(k * ML_KEM_POLY_LEN + ML_KEM_SEED_LEN);
	encode_poly_arr(k, t, ek->ptr);
	memcpy(ek->ptr + k * ML_KEM_POLY_LEN, rho, ML_KEM_SEED_LEN);

#else // new codes:
	/* calculate t = invNTT(A * s) + e to get the public key */
	for (i = 0; i < k; i++)
	{
		multiply_poly_arr(k, &a[i*k], s, &t[i], FALSE);
	}
	/* calculate t = invNTT(A * s) */
	for (i = 0; i < k; i++)
	{
		ntt_inv(this, &t[i]);
	}
	mlex_poly_add_arr(k, t, e, t);
	/* pack public key and rho */
	*ek = chunk_alloc(k * dt * ML_KEM_N / 8 + ML_KEM_SEED_LEN);
	compress_polys_arr(k, dt, t, ek->ptr);
	memcpy(ek->ptr + k * dt * ML_KEM_N / 8, rho, ML_KEM_SEED_LEN);

	/* overwrite/store t into this->public_key.ptr */
	decompress_poly_arr(k, dt, ek->ptr, t);
#endif
	success = TRUE;

err:
	memwipe(seeds, sizeof(seeds));
	memwipe(sigma, ML_KEM_SEED_LEN);
	memwipe(e, sizeof(e));
	return success;
}

/**
 * Encrypt randomness m using the given public key and randomness r that's
 * derived from both.
 *
 * Algorithm 14 in FIPS 203.
 */
static bool pke_encrypt(private_key_exchange_t *this, chunk_t ek, uint8_t *m,
						uint8_t *r, chunk_t ciphertext)
{
	const uint8_t k = this->params->k;
	const uint8_t eta1 = this->params->eta1;
	const uint8_t eta2 = this->params->eta2;
	const uint8_t du = this->params->du;
	const uint8_t dv = this->params->dv;
#if 1 // new codes:
	const uint8_t dt = this->params->dt;
#endif

	uint8_t rho[ML_KEM_SEED_LEN];
	uint8_t N = 0;
	mlex_poly_t a_gen[k*k], *a = a_gen, t_dec[k], *t = t_dec;
	mlex_poly_t y[k], e1[k], e2, u[k], mu, v;
	int i;
	bool success = FALSE;

	if (!this->public_key.ptr)
	{
		/* decode polynomial t and extract seed rho from the public key */
#if 0 // old codes:
		decode_poly_arr(k, ek.ptr, t);
		memcpy(rho, ek.ptr + k * ML_KEM_POLY_LEN, ML_KEM_SEED_LEN);
#else // new codes:
		decompress_poly_arr(k, dt, ek.ptr, t);
		memcpy(rho, ek.ptr + k * dt * ML_KEM_N / 8, ML_KEM_SEED_LEN);
		/* calculate t = NTT(t) */
		for (i = 0; i < k; i++)
		{
			ntt(this, &t[i]);
		}
#endif
		/* generate matrix A */
		if (!generate_a(this, a, rho))
		{
			goto err;
		}
	}
	else
	{
		/* as initiator, we already have the decoded polynomial and matrix A */
		t = (mlex_poly_t*)this->public_key.ptr;
		a = (mlex_poly_t*)this->public_key.ptr + k;
		/* calculate t = NTT(t) */
		for (i = 0; i < k; i++)
		{
			ntt(this, &t[i]);
		}
	}

	/* sample y from CBD using noise seed r and nonce N as input */
	for (i = 0; i < k; i++)
	{
		sample_poly_cbd(this, eta1, r, N++, &y[i]);
	}

	/* sample e_1 from CBD using noise seed r and nonce N as input */
	for (i = 0; i < k; i++)
	{
		sample_poly_cbd(this, eta2, r, N++, &e1[i]);
	}

	/* sample e_2 from CBD using noise seed r and nonce N as input */
	sample_poly_cbd(this, eta2, r, N++, &e2);

	/* calculate y = NTT(y) */
	for (i = 0; i < k; i++)
	{
		ntt(this, &y[i]);
	}

	/* calculate u = NTT^-1(A^T * y) + e_1 */
	for (i = 0; i < k; i++)
	{
		multiply_poly_arr(k, &a[i], y, &u[i], TRUE);
	}
	for (i = 0; i < k; i++)
	{
		ntt_inv(this, &u[i]);
	}
	mlex_poly_add_arr(k, u, e1, u);

	/* prepare plaintext message m */
	message_to_poly(m, &mu);

	/* calculate v = NTT^-1(t^T * y) + e_2 + mu to encrypt the plaintext */
	multiply_poly_arr(k, t, y, &v, FALSE);
	ntt_inv(this, &v);
	mlex_poly_add(&v, &e2, &v);
	mlex_poly_add(&v, &mu, &v);

	/* encode u as c1 and v as c2, the two parts of the ciphertext */
	compress_polys_arr(k, du, u, ciphertext.ptr);
	compress_polys_arr(1, dv, &v, ciphertext.ptr + k * du * ML_KEM_N / 8);
	success = TRUE;

err:
	memwipe(y, sizeof(y));
	memwipe(e1, sizeof(e1));
	memwipe(&e2, sizeof(e2));
	memwipe(&mu, sizeof(mu));
	return success;
}

/**
 * Compute HMAC-SHA3-256 over data using a key.
 * HMAC(K, msg) = H((K XOR opad) || H((K XOR ipad) || msg))
 *
 * @param hasher	SHA3-256 hasher instance
 * @param key		HMAC key
 * @param data		data to authenticate
 * @param mac		output buffer for MAC (must be 32 bytes)
 * @return			TRUE if MAC computed successfully
 */
static bool compute_hmac_sha3_256(hasher_t *hasher, chunk_t key, 
					   chunk_t data, chunk_t mac)
{
	const uint8_t ipad = 0x36;
	const uint8_t opad = 0x5c;
	size_t hash_len = 32; /* SHA3-256 output is 32 bytes */
	size_t block_len = 136; /* SHA3-256 block size (1088 bits / 8) */
	uint8_t ipad_key[136];
	uint8_t opad_key[136];
	uint8_t inner_hash[32];
	size_t i;

	/* Initialize ipad and opad buffers */
	memset(ipad_key, ipad, block_len);
	memset(opad_key, opad, block_len);

	/* XOR key with ipad and opad (pad key to block size if needed) */
	for (i = 0; i < key.len && i < block_len; i++)
	{
		ipad_key[i] ^= key.ptr[i];
		opad_key[i] ^= key.ptr[i];
	}

	/* Compute inner hash: H(ipad_key || data) */
	if (!hasher->reset(hasher))
	{
		return FALSE;
	}
	if (!hasher->get_hash(hasher, chunk_create(ipad_key, block_len), NULL))
	{
		return FALSE;
	}
	if (!hasher->get_hash(hasher, data, inner_hash))
	{
		return FALSE;
	}

	/* Compute outer hash: H(opad_key || inner_hash) */
	if (!hasher->reset(hasher))
	{
		return FALSE;
	}
	if (!hasher->get_hash(hasher, chunk_create(opad_key, block_len), NULL))
	{
		return FALSE;
	}
	if (!hasher->get_hash(hasher, chunk_create(inner_hash, hash_len), mac.ptr))
	{
		return FALSE;
	}

	memwipe(ipad_key, sizeof(ipad_key));
	memwipe(opad_key, sizeof(opad_key));
	memwipe(inner_hash, sizeof(inner_hash));
	return TRUE;
}

/**
 * Decrypt message m using the stored private key and given ciphertext.
 *
 * Algorithm 14 in FIPS 203.
 */
static bool pke_decrypt(private_key_exchange_t *this, chunk_t ciphertext,
						uint8_t *m)
{
	const uint8_t k = this->params->k;
	const uint8_t du = this->params->du;
	const uint8_t dv = this->params->dv;

	mlex_poly_t *s, u[k], v, w;
	int i;

	/* decode u and v from c1 and c2, the two parts of the ciphertext */
	decompress_poly_arr(k, du, ciphertext.ptr, u);
	decompress_poly_arr(1, dv, ciphertext.ptr + k * du * ML_KEM_N / 8, &v);

	/* we already have private key s stored */
	s = (mlex_poly_t*)this->private_key.ptr;

	/* calculate w = v - NTT^-1(s * NTT(u)) */
	for (i = 0; i < k; i++)
	{
		ntt(this, &u[i]);
	}
	multiply_poly_arr(k, s, u, &w, FALSE);
	ntt_inv(this, &w);
	mlex_poly_sub(&v, &w, &w);

	/* decode plaintext message m from polynomial w */
	poly_to_message(&w, m);
	return TRUE;
}

/**
 * Get random seeds and generate a key pair.
 *
 * removing implicit rejection seed 'z' in sk
 */
static bool generate_keypair(private_key_exchange_t *this, chunk_t *ek)
{
	chunk_t d = chunk_alloca(ML_KEM_SEED_LEN);
	bool success = FALSE;

	/* get random seeds d */
	if (!get_random(this, d.len, d.ptr))
	{
		return FALSE;
	}

	/* generate a key pair */
	if (pke_keygen(this, d, ek))
	{
		success = TRUE;
	}

	memwipe(d.ptr, d.len);
	return success;
}

METHOD(key_exchange_t, get_public_key, bool,
	private_key_exchange_t *this, chunk_t *value)
{
	/* as responder, this method is called after set_public_key(), which
	 * encapsulated the secret to produce this ciphertext */
	if (this->ciphertext.ptr)
	{
		*value = chunk_clone(this->ciphertext);
		return TRUE;
	}

	/* as initiator, we generate a key pair and return the public key */
	return generate_keypair(this, value);
}

/**
 * Decapsulate a generated shared secret from the given ciphertext using our
 * private key.
 *
 * Algorithm 18 in FIPS 203.
 */
static bool decaps_shared_secret(private_key_exchange_t *this, chunk_t ciphertext)
{
	chunk_t m = chunk_alloca(ML_KEM_SEED_LEN);
	chunk_t tag_computed = chunk_alloca(ML_KEM_TAG_LEN);
	chunk_t pke_ciphertext, tag_received;
	uint32_t pke_ct_len;
	bool success = FALSE;

	/* verify received ciphertext length matches expected (ct_len = pke_ct + mac) */
	if (ciphertext.len != this->params->ct_len)
	{
		DBG1(DBG_LIB, "ciphertext length mismatch: got %u bytes, expected %u bytes",
			 ciphertext.len, this->params->ct_len);
		goto err;
	}

	/* calculate actual PKE ciphertext size */
	pke_ct_len = this->params->ct_len - ML_KEM_TAG_LEN;

	/* get ciphertext and mac tag */
	chunk_split(ciphertext, "mm",
				pke_ct_len, &pke_ciphertext,
				ML_KEM_TAG_LEN, &tag_received);

	/* decrypt message m using only the PKE ciphertext */
	if (!pke_decrypt(this, pke_ciphertext, m.ptr))
	{
		goto err;
	}

	/* compute HMAC-SHA3-256 over PKE ciphertext with encrypted value */
	if (!compute_hmac_sha3_256(this->H,
							   m,
							   pke_ciphertext,
							   tag_computed))
	{
		goto err;
	}

	this->shared_secret = chunk_alloc(ML_KEM_SEED_LEN);
	if (!this->shared_secret.ptr)
	{
		DBG1(DBG_LIB, "failed to allocate shared secret");
		goto err;
	}

	/* replace the rejection seed with real decrypted message based on whether re-computed MAC tag matches the received one, using a constant-time conditional copy to avoid side-channels */
	success = chunk_equals_const(tag_received, tag_computed); // explicit rejection
    if (!success)
    {
        DBG1(DBG_LIB, "MAC tag mismatch: ciphertext rejected");
        goto err;
    }

	/* derive K = H(m) */
	if (!this->H->get_hash(this->H, m, this->shared_secret.ptr))
	{
		success = FALSE;
		goto err;
	}

err:
	memwipe(m.ptr, m.len);
	return success;
}

/**
 * Encapsulate a generated shared secret using the given public key.
 *
 * Algorithm 17 in FIPS 203.
 */
static bool encaps_shared_secret(private_key_exchange_t *this, chunk_t public)
{
	chunk_t mr = chunk_alloca(2*ML_KEM_SEED_LEN);
	chunk_t m, r, pke_ciphertext, mac_tag;
	uint32_t pke_ct_len;
	bool success = FALSE;

	/* get a random message (m, r) */
	if (!get_random(this, 2*ML_KEM_SEED_LEN, mr.ptr))
	{
		goto err;
	}

	/* allocate full buffer (ct_len already includes MAC size) */
	this->ciphertext = chunk_alloc(this->params->ct_len);
	if (!this->ciphertext.ptr)
	{
		goto err;
	}

	/* calculate actual PKE ciphertext size */
	pke_ct_len = this->params->ct_len - ML_KEM_TAG_LEN;

	/* split the buffer into ciphertext and tag */
	chunk_split(this->ciphertext, "mm",
				pke_ct_len, &pke_ciphertext,
				ML_KEM_TAG_LEN, &mac_tag);

	/* split the buffer into msg and random coins */
	chunk_split(mr, "mm",
				ML_KEM_SEED_LEN, &m,
				ML_KEM_SEED_LEN, &r);

	/* encrypt the message using random r */
	if (!pke_encrypt(this, public, m.ptr, r.ptr, pke_ciphertext))
	{
		goto err;
	}

	/* compute HMAC-SHA3-256 authentication tag over ciphertext part */
	if (!compute_hmac_sha3_256(this->H, 
						   m,
						   pke_ciphertext, 
						   mac_tag))
	{
		goto err;
	}

	this->shared_secret = chunk_alloc(ML_KEM_SEED_LEN);
	if (!this->shared_secret.ptr)
	{
		DBG1(DBG_LIB, "failed to allocate shared secret");
		goto err;
	}
	/* derive K = H(m) */
	if (!this->H->get_hash(this->H, m, this->shared_secret.ptr))
	{
		goto err;
	}
	success = TRUE;

err:
	memwipe(mr.ptr, 2*ML_KEM_SEED_LEN);
	return success;
}

/**
 * Perform a modulus check as required by section 7.2 of FIPS 203.
 */
static bool validate_public_key(private_key_exchange_t *this, chunk_t public)
{
	const uint8_t k = this->params->k;

	mlex_poly_t p[k];
#if 0 // old codes:
	uint8_t ek[k * ML_KEM_POLY_LEN];
	decode_poly_arr(k, public.ptr, p);
	encode_poly_arr(k, p, ek);
#else // new codes:
	const uint8_t dt = this->params->dt;
	uint8_t ek[k * dt * ML_KEM_N / 8];
	decompress_poly_arr(k, dt, public.ptr, p);
	compress_polys_arr(k, dt, p, ek);
#endif
	return memeq_const(public.ptr, ek, sizeof(ek));
}

METHOD(key_exchange_t, set_public_key, bool,
	private_key_exchange_t *this, chunk_t value)
{
	/* as initiator, we decapsulate the secret from the given ciphertext */
	if (this->private_key.ptr)
	{
		if (value.len != this->params->ct_len)
		{
			DBG1(DBG_LIB, "wrong %N ciphertext size of %u bytes, %u bytes expected",
				 key_exchange_method_names, this->method, value.len,
				 this->params->ct_len);
			return FALSE;
		}
		return decaps_shared_secret(this, value);
	}

	/* as responder, we generate a secret and encapsulate it */
	if (value.len != this->params->pk_len)
	{
		DBG1(DBG_LIB, "wrong %N public key size of %u bytes, %u bytes expected",
			 key_exchange_method_names, this->method, value.len,
			 this->params->pk_len);
		return FALSE;
	}
	else if (!validate_public_key(this, value))
	{
		DBG1(DBG_LIB, "%N public key encoding invalid",
			 key_exchange_method_names, this->method);
		return FALSE;
	}
	return encaps_shared_secret(this, value);
}

METHOD(key_exchange_t, get_method, key_exchange_method_t,
	private_key_exchange_t *this)
{
	return this->method;
}

METHOD(key_exchange_t, get_shared_secret, bool,
	private_key_exchange_t *this, chunk_t *secret)
{
	*secret = chunk_clone(this->shared_secret);
	return TRUE;
}

#ifdef TESTABLE_KE

METHOD(key_exchange_t, set_seed, bool,
	private_key_exchange_t *this, chunk_t value, drbg_t *drbg)
{
	DESTROY_IF(this->drbg);
	this->drbg = drbg->get_ref(drbg);
	return TRUE;
}

#endif /* TESTABLE_KE */

METHOD(key_exchange_t, destroy, void,
	private_key_exchange_t *this)
{
	chunk_clear(&this->private_key);
	// chunk_clear(&this->key_data);
	chunk_clear(&this->shared_secret);
	chunk_free(&this->public_key);
	chunk_free(&this->ciphertext);
#ifdef TESTABLE_KE
	DESTROY_IF(this->drbg);
#endif
	DESTROY_IF(this->shake128);
	DESTROY_IF(this->shake256);
	DESTROY_IF(this->G);
	DESTROY_IF(this->H);
	free(this);
}

/*
 * Described in header
 */
key_exchange_t *mlex_kem_create(key_exchange_method_t method)
{
	private_key_exchange_t *this;
	const mlex_kem_params_t *params;

	params = mlex_kem_params_get(method);
	if (!params)
	{
		return NULL;
	}

	INIT(this,
		.public = {
			.get_method = _get_method,
			.get_public_key = _get_public_key,
			.set_public_key = _set_public_key,
			.get_shared_secret = _get_shared_secret,
			.destroy = _destroy,
		},
		.method = method,
		.params = params,
		.shake128 = lib->crypto->create_xof(lib->crypto, XOF_SHAKE_128),
		.shake256 = lib->crypto->create_xof(lib->crypto, XOF_SHAKE_256),
		.G = lib->crypto->create_hasher(lib->crypto, HASH_SHA3_512),
		.H = lib->crypto->create_hasher(lib->crypto, HASH_SHA3_256),
	);

#ifdef TESTABLE_KE
	this->public.set_seed = _set_seed;
#endif

	if (!this->shake128 || !this->shake256 || !this->G || !this->H)
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}

