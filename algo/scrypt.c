/*
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2011-2014 pooler
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#include "miner.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

static const uint32_t keypad[12] = {
	0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000280
};
static const uint32_t innerpad[11] = {
	0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x000004a0
};
static const uint32_t outerpad[8] = {
	0x80000000, 0, 0, 0, 0, 0, 0, 0x00000300
};
static const uint32_t finalblk[16] = {
	0x00000001, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000620
};

static inline void HMAC_SHA256_80_init(const uint32_t *key,
	uint32_t *tstate, uint32_t *ostate)
{
	uint32_t ihash[8];
	uint32_t pad[16];
	int i;

	/* tstate is assumed to contain the midstate of key */
	memcpy(pad, key + 16, 16);
	memcpy(pad + 4, keypad, 48);
	sha256_transform(tstate, pad, 0);
	memcpy(ihash, tstate, 32);

	sha256_init(ostate);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for (; i < 16; i++)
		pad[i] = 0x5c5c5c5c;
	sha256_transform(ostate, pad, 0);

	sha256_init(tstate);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x36363636;
	for (; i < 16; i++)
		pad[i] = 0x36363636;
	sha256_transform(tstate, pad, 0);
}

static inline void PBKDF2_SHA256_80_128(const uint32_t *tstate,
	const uint32_t *ostate, const uint32_t *salt, uint32_t *output)
{
	uint32_t istate[8], ostate2[8];
	uint32_t ibuf[16], obuf[16];
	int i, j;

	memcpy(istate, tstate, 32);
	sha256_transform(istate, salt, 0);
	
	memcpy(ibuf, salt + 16, 16);
	memcpy(ibuf + 5, innerpad, 44);
	memcpy(obuf + 8, outerpad, 32);

	for (i = 0; i < 4; i++) {
		memcpy(obuf, istate, 32);
		ibuf[4] = i + 1;
		sha256_transform(obuf, ibuf, 0);

		memcpy(ostate2, ostate, 32);
		sha256_transform(ostate2, obuf, 0);
		for (j = 0; j < 8; j++)
			output[8 * i + j] = swab32(ostate2[j]);
	}
}

static inline void PBKDF2_SHA256_128_32(uint32_t *tstate, uint32_t *ostate,
	const uint32_t *salt, uint32_t *output)
{
	uint32_t buf[16];
	int i;
	
	sha256_transform(tstate, salt, 1);
	sha256_transform(tstate, salt + 16, 1);
	sha256_transform(tstate, finalblk, 0);
	memcpy(buf, tstate, 32);
	memcpy(buf + 8, outerpad, 32);

	sha256_transform(ostate, buf, 0);
	for (i = 0; i < 8; i++)
		output[i] = swab32(ostate[i]);
}


#ifdef HAVE_SHA256_4WAY

static const uint32_t keypad_4way[4 * 12] = {
	0x80000000, 0x80000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000280, 0x00000280, 0x00000280, 0x00000280
};
static const uint32_t innerpad_4way[4 * 11] = {
	0x80000000, 0x80000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x000004a0, 0x000004a0, 0x000004a0, 0x000004a0
};
static const uint32_t outerpad_4way[4 * 8] = {
	0x80000000, 0x80000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000300, 0x00000300, 0x00000300, 0x00000300
};
static const uint32_t _ALIGN(16) finalblk_4way[4 * 16] = {
	0x00000001, 0x00000001, 0x00000001, 0x00000001,
	0x80000000, 0x80000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000620, 0x00000620, 0x00000620, 0x00000620
};

static inline void HMAC_SHA256_80_init_4way(const uint32_t *key,
	uint32_t *tstate, uint32_t *ostate)
{
	uint32_t _ALIGN(16) ihash[4 * 8];
	uint32_t _ALIGN(16) pad[4 * 16];
	int i;

	/* tstate is assumed to contain the midstate of key */
	memcpy(pad, key + 4 * 16, 4 * 16);
	memcpy(pad + 4 * 4, keypad_4way, 4 * 48);
	sha256_transform_4way(tstate, pad, 0);
	memcpy(ihash, tstate, 4 * 32);

	sha256_init_4way(ostate);
	for (i = 0; i < 4 * 8; i++)
		pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for (; i < 4 * 16; i++)
		pad[i] = 0x5c5c5c5c;
	sha256_transform_4way(ostate, pad, 0);

	sha256_init_4way(tstate);
	for (i = 0; i < 4 * 8; i++)
		pad[i] = ihash[i] ^ 0x36363636;
	for (; i < 4 * 16; i++)
		pad[i] = 0x36363636;
	sha256_transform_4way(tstate, pad, 0);
}

static inline void PBKDF2_SHA256_80_128_4way(const uint32_t *tstate,
	const uint32_t *ostate, const uint32_t *salt, uint32_t *output)
{
	uint32_t _ALIGN(16) istate[4 * 8];
	uint32_t _ALIGN(16) ostate2[4 * 8];
	uint32_t _ALIGN(16) ibuf[4 * 16];
	uint32_t _ALIGN(16) obuf[4 * 16];
	int i, j;

	memcpy(istate, tstate, 4 * 32);
	sha256_transform_4way(istate, salt, 0);
	
	memcpy(ibuf, salt + 4 * 16, 4 * 16);
	memcpy(ibuf + 4 * 5, innerpad_4way, 4 * 44);
	memcpy(obuf + 4 * 8, outerpad_4way, 4 * 32);

	for (i = 0; i < 4; i++) {
		memcpy(obuf, istate, 4 * 32);
		ibuf[4 * 4 + 0] = i + 1;
		ibuf[4 * 4 + 1] = i + 1;
		ibuf[4 * 4 + 2] = i + 1;
		ibuf[4 * 4 + 3] = i + 1;
		sha256_transform_4way(obuf, ibuf, 0);

		memcpy(ostate2, ostate, 4 * 32);
		sha256_transform_4way(ostate2, obuf, 0);
		for (j = 0; j < 4 * 8; j++)
			output[4 * 8 * i + j] = swab32(ostate2[j]);
	}
}

static inline void PBKDF2_SHA256_128_32_4way(uint32_t *tstate,
	uint32_t *ostate, const uint32_t *salt, uint32_t *output)
{
	uint32_t _ALIGN(16) buf[4 * 16];
	int i;
	
	sha256_transform_4way(tstate, salt, 1);
	sha256_transform_4way(tstate, salt + 4 * 16, 1);
	sha256_transform_4way(tstate, finalblk_4way, 0);
	memcpy(buf, tstate, 4 * 32);
	memcpy(buf + 4 * 8, outerpad_4way, 4 * 32);

	sha256_transform_4way(ostate, buf, 0);
	for (i = 0; i < 4 * 8; i++)
		output[i] = swab32(ostate[i]);
}

#endif /* HAVE_SHA256_4WAY */


#ifdef HAVE_SHA256_8WAY

static const uint32_t _ALIGN(32) finalblk_8way[8 * 16] = {
	0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001,
	0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000620, 0x00000620, 0x00000620, 0x00000620, 0x00000620, 0x00000620, 0x00000620, 0x00000620
};

static inline void HMAC_SHA256_80_init_8way(const uint32_t *key,
	uint32_t *tstate, uint32_t *ostate)
{
	uint32_t _ALIGN(32) ihash[8 * 8];
	uint32_t _ALIGN(32)  pad[8 * 16];
	int i;
	
	/* tstate is assumed to contain the midstate of key */
	memcpy(pad, key + 8 * 16, 8 * 16);
	for (i = 0; i < 8; i++)
		pad[8 * 4 + i] = 0x80000000;
	memset(pad + 8 * 5, 0x00, 8 * 40);
	for (i = 0; i < 8; i++)
		pad[8 * 15 + i] = 0x00000280;
	sha256_transform_8way(tstate, pad, 0);
	memcpy(ihash, tstate, 8 * 32);
	
	sha256_init_8way(ostate);
	for (i = 0; i < 8 * 8; i++)
		pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for (; i < 8 * 16; i++)
		pad[i] = 0x5c5c5c5c;
	sha256_transform_8way(ostate, pad, 0);
	
	sha256_init_8way(tstate);
	for (i = 0; i < 8 * 8; i++)
		pad[i] = ihash[i] ^ 0x36363636;
	for (; i < 8 * 16; i++)
		pad[i] = 0x36363636;
	sha256_transform_8way(tstate, pad, 0);
}

static inline void PBKDF2_SHA256_80_128_8way(const uint32_t *tstate,
	const uint32_t *ostate, const uint32_t *salt, uint32_t *output)
{
	uint32_t _ALIGN(32) istate[8 * 8];
	uint32_t _ALIGN(32) ostate2[8 * 8];
	uint32_t _ALIGN(32) ibuf[8 * 16];
	uint32_t _ALIGN(32) obuf[8 * 16];
	int i, j;
	
	memcpy(istate, tstate, 8 * 32);
	sha256_transform_8way(istate, salt, 0);
	
	memcpy(ibuf, salt + 8 * 16, 8 * 16);
	for (i = 0; i < 8; i++)
		ibuf[8 * 5 + i] = 0x80000000;
	memset(ibuf + 8 * 6, 0x00, 8 * 36);
	for (i = 0; i < 8; i++)
		ibuf[8 * 15 + i] = 0x000004a0;
	
	for (i = 0; i < 8; i++)
		obuf[8 * 8 + i] = 0x80000000;
	memset(obuf + 8 * 9, 0x00, 8 * 24);
	for (i = 0; i < 8; i++)
		obuf[8 * 15 + i] = 0x00000300;
	
	for (i = 0; i < 4; i++) {
		memcpy(obuf, istate, 8 * 32);
		ibuf[8 * 4 + 0] = i + 1;
		ibuf[8 * 4 + 1] = i + 1;
		ibuf[8 * 4 + 2] = i + 1;
		ibuf[8 * 4 + 3] = i + 1;
		ibuf[8 * 4 + 4] = i + 1;
		ibuf[8 * 4 + 5] = i + 1;
		ibuf[8 * 4 + 6] = i + 1;
		ibuf[8 * 4 + 7] = i + 1;
		sha256_transform_8way(obuf, ibuf, 0);
		
		memcpy(ostate2, ostate, 8 * 32);
		sha256_transform_8way(ostate2, obuf, 0);
		for (j = 0; j < 8 * 8; j++)
			output[8 * 8 * i + j] = swab32(ostate2[j]);
	}
}

static inline void PBKDF2_SHA256_128_32_8way(uint32_t *tstate,
	uint32_t *ostate, const uint32_t *salt, uint32_t *output)
{
	uint32_t _ALIGN(32) buf[8 * 16];
	int i;
	
	sha256_transform_8way(tstate, salt, 1);
	sha256_transform_8way(tstate, salt + 8 * 16, 1);
	sha256_transform_8way(tstate, finalblk_8way, 0);
	
	memcpy(buf, tstate, 8 * 32);
	for (i = 0; i < 8; i++)
		buf[8 * 8 + i] = 0x80000000;
	memset(buf + 8 * 9, 0x00, 8 * 24);
	for (i = 0; i < 8; i++)
		buf[8 * 15 + i] = 0x00000300;
	sha256_transform_8way(ostate, buf, 0);
	
	for (i = 0; i < 8 * 8; i++)
		output[i] = swab32(ostate[i]);
}

#endif /* HAVE_SHA256_8WAY */


#if defined(USE_ASM) && defined(__x86_64__)

#define SCRYPT_MAX_WAYS 12
#define HAVE_SCRYPT_3WAY 1
int scrypt_best_throughput();
void scrypt_core(uint32_t *X, uint32_t *V, int N);
void scrypt_core_3way(uint32_t *X, uint32_t *V, int N);
#if defined(USE_AVX2)
#undef SCRYPT_MAX_WAYS
#define SCRYPT_MAX_WAYS 24
#define HAVE_SCRYPT_6WAY 1
void scrypt_core_6way(uint32_t *X, uint32_t *V, int N);
#endif

#elif defined(USE_ASM) && defined(__i386__)

#define SCRYPT_MAX_WAYS 4
#define scrypt_best_throughput() 1
void scrypt_core(uint32_t *X, uint32_t *V, int N);

#elif defined(USE_ASM) && defined(__arm__) && defined(__APCS_32__)

void scrypt_core(uint32_t *X, uint32_t *V, int N);
#if defined(__ARM_NEON__)
#undef HAVE_SHA256_4WAY
#define SCRYPT_MAX_WAYS 3
#define HAVE_SCRYPT_3WAY 1
#define scrypt_best_throughput() 3
void scrypt_core_3way(uint32_t *X, uint32_t *V, int N);
#endif

#elif defined(__aarch64__)
#include <arm_neon.h>

#undef HAVE_SHA256_4WAY
#define SCRYPT_MAX_WAYS 3
#define HAVE_SCRYPT_3WAY 1
#define scrypt_best_throughput() 3

static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16])
{
	uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
	int i;

	x00 = (B[ 0] ^= Bx[ 0]);
	x01 = (B[ 1] ^= Bx[ 1]);
	x02 = (B[ 2] ^= Bx[ 2]);
	x03 = (B[ 3] ^= Bx[ 3]);
	x04 = (B[ 4] ^= Bx[ 4]);
	x05 = (B[ 5] ^= Bx[ 5]);
	x06 = (B[ 6] ^= Bx[ 6]);
	x07 = (B[ 7] ^= Bx[ 7]);
	x08 = (B[ 8] ^= Bx[ 8]);
	x09 = (B[ 9] ^= Bx[ 9]);
	x10 = (B[10] ^= Bx[10]);
	x11 = (B[11] ^= Bx[11]);
	x12 = (B[12] ^= Bx[12]);
	x13 = (B[13] ^= Bx[13]);
	x14 = (B[14] ^= Bx[14]);
	x15 = (B[15] ^= Bx[15]);
	for (i = 0; i < 8; i += 2) {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns. */
		x04 ^= R(x00+x12, 7);	x09 ^= R(x05+x01, 7);
		x14 ^= R(x10+x06, 7);	x03 ^= R(x15+x11, 7);
		
		x08 ^= R(x04+x00, 9);	x13 ^= R(x09+x05, 9);
		x02 ^= R(x14+x10, 9);	x07 ^= R(x03+x15, 9);
		
		x12 ^= R(x08+x04,13);	x01 ^= R(x13+x09,13);
		x06 ^= R(x02+x14,13);	x11 ^= R(x07+x03,13);
		
		x00 ^= R(x12+x08,18);	x05 ^= R(x01+x13,18);
		x10 ^= R(x06+x02,18);	x15 ^= R(x11+x07,18);
		
		/* Operate on rows. */
		x01 ^= R(x00+x03, 7);	x06 ^= R(x05+x04, 7);
		x11 ^= R(x10+x09, 7);	x12 ^= R(x15+x14, 7);
		
		x02 ^= R(x01+x00, 9);	x07 ^= R(x06+x05, 9);
		x08 ^= R(x11+x10, 9);	x13 ^= R(x12+x15, 9);
		
		x03 ^= R(x02+x01,13);	x04 ^= R(x07+x06,13);
		x09 ^= R(x08+x11,13);	x14 ^= R(x13+x12,13);
		
		x00 ^= R(x03+x02,18);	x05 ^= R(x04+x07,18);
		x10 ^= R(x09+x08,18);	x15 ^= R(x14+x13,18);
#undef R
	}
	B[ 0] += x00;
	B[ 1] += x01;
	B[ 2] += x02;
	B[ 3] += x03;
	B[ 4] += x04;
	B[ 5] += x05;
	B[ 6] += x06;
	B[ 7] += x07;
	B[ 8] += x08;
	B[ 9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}


static inline void xor_salsa8_prefetch(uint32_t B[16], const uint32_t Bx[16], uint32_t* V, uint32_t N)
{
	uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
	int i;

	x00 = (B[ 0] ^= Bx[ 0]);
	x01 = (B[ 1] ^= Bx[ 1]);
	x02 = (B[ 2] ^= Bx[ 2]);
	x03 = (B[ 3] ^= Bx[ 3]);
	x04 = (B[ 4] ^= Bx[ 4]);
	x05 = (B[ 5] ^= Bx[ 5]);
	x06 = (B[ 6] ^= Bx[ 6]);
	x07 = (B[ 7] ^= Bx[ 7]);
	x08 = (B[ 8] ^= Bx[ 8]);
	x09 = (B[ 9] ^= Bx[ 9]);
	x10 = (B[10] ^= Bx[10]);
	x11 = (B[11] ^= Bx[11]);
	x12 = (B[12] ^= Bx[12]);
	x13 = (B[13] ^= Bx[13]);
	x14 = (B[14] ^= Bx[14]);
	x15 = (B[15] ^= Bx[15]);
	for (i = 0; i < 8; i += 2) {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns. */
		x04 ^= R(x00+x12, 7);	x09 ^= R(x05+x01, 7);
		x14 ^= R(x10+x06, 7);	x03 ^= R(x15+x11, 7);
		
		x08 ^= R(x04+x00, 9);	x13 ^= R(x09+x05, 9);
		x02 ^= R(x14+x10, 9);	x07 ^= R(x03+x15, 9);
		
		x12 ^= R(x08+x04,13);	x01 ^= R(x13+x09,13);
		x06 ^= R(x02+x14,13);	x11 ^= R(x07+x03,13);
		
		x00 ^= R(x12+x08,18);	x05 ^= R(x01+x13,18);
		x10 ^= R(x06+x02,18);	x15 ^= R(x11+x07,18);
		
		/* Operate on rows. */
		x01 ^= R(x00+x03, 7);	x06 ^= R(x05+x04, 7);
		x11 ^= R(x10+x09, 7);	x12 ^= R(x15+x14, 7);
		
		x02 ^= R(x01+x00, 9);	x07 ^= R(x06+x05, 9);
		x08 ^= R(x11+x10, 9);	x13 ^= R(x12+x15, 9);
		
		x03 ^= R(x02+x01,13);	x04 ^= R(x07+x06,13);
		x09 ^= R(x08+x11,13);	x14 ^= R(x13+x12,13);
		
		x00 ^= R(x03+x02,18);	x05 ^= R(x04+x07,18);
		x10 ^= R(x09+x08,18);	x15 ^= R(x14+x13,18);
#undef R
	}
	B[ 0] += x00;
	uint32_t one = 32 * (B[0] & (N - 1));
	__builtin_prefetch(&V[one + 0]);
	__builtin_prefetch(&V[one + 8]);
	__builtin_prefetch(&V[one + 16]);
	__builtin_prefetch(&V[one + 24]);
	asm("":::"memory");
	B[ 1] += x01;
	B[ 2] += x02;
	B[ 3] += x03;
	B[ 4] += x04;
	B[ 5] += x05;
	B[ 6] += x06;
	B[ 7] += x07;
	B[ 8] += x08;
	B[ 9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}

static inline void scrypt_core(uint32_t *X, uint32_t *V, int N)
{
	int i;

	for (i = 0; i < N; i++) {
		memcpy(&V[i * 32], X, 128);
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}
	for (i = 0; i < N; i++) {
		uint32_t j = 32 * (X[16] & (N - 1));
		for (uint8_t k = 0; k < 32; k++)
			X[k] ^= V[j + k];
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8_prefetch(&X[16], &X[0], V, N);
	}
}


static inline void scrypt_shuffle(uint32_t B[16])
{
	uint32_t x0 = 	B[0]; 
	uint32_t x1 = 	B[1]; 
	uint32_t x2 = 	B[2];
	uint32_t x3 = 	B[3]; 
	uint32_t x4 = 	B[4];
	uint32_t x5 = 	B[5]; 
	uint32_t x6 = 	B[6]; 
	uint32_t x7 = 	B[7]; 
	uint32_t x8 = 	B[8]; 
	uint32_t x9 = 	B[9]; 
	uint32_t x10 = B[10]; 
	uint32_t x11 = B[11]; 
	uint32_t x12 = B[12];
	uint32_t x13 = B[13]; 
	uint32_t x14 = B[14]; 
	uint32_t x15 = B[15]; 

	B[0] = x0;  B[1] = x5;  B[2] = x10;  B[3] = x15;
	B[4] = x12; B[5] = x1;  B[6] = x6;   B[7] = x11;
	B[8] = x8;  B[9] = x13; B[10] = x2;  B[11] = x7;
	B[12] = x4; B[13] = x9; B[14] = x14; B[15] = x3;
}

static inline void scrypt_core_3way(uint32_t B[32 * 3], uint32_t *V, uint32_t N)
{
	uint32_t* W = V;

	scrypt_shuffle(&B[0  + 0]);
	scrypt_shuffle(&B[16 + 0]);
	scrypt_shuffle(&B[0 + 32]);
	scrypt_shuffle(&B[16 + 32]);
	scrypt_shuffle(&B[0 + 64]);
	scrypt_shuffle(&B[16 + 64]);

	uint32x4x4_t q_a, q_b, q_c, q_tmp;
	uint32x4x4_t ba_a, bb_a, bc_a, ba_b, bb_b, bc_b;

	ba_a.val[0] = vld1q_u32(&B[( 0) / 4]);
	ba_a.val[1] = vld1q_u32(&B[(16) / 4]);
	ba_a.val[2] = vld1q_u32(&B[(32) / 4]);
	ba_a.val[3] = vld1q_u32(&B[(48) / 4]);
	ba_b.val[0] = vld1q_u32(&B[(0 + 64 + 0) / 4]);
	ba_b.val[1] = vld1q_u32(&B[(0 + 64 + 16) / 4]);
	ba_b.val[2] = vld1q_u32(&B[(0 + 64 + 32) / 4]);
	ba_b.val[3] = vld1q_u32(&B[(0 + 64 + 48) / 4]);

	bb_a.val[0] = vld1q_u32(&B[(128 +  0) / 4]);
	bb_a.val[1] = vld1q_u32(&B[(128 + 16) / 4]);
	bb_a.val[2] = vld1q_u32(&B[(128 + 32) / 4]);
	bb_a.val[3] = vld1q_u32(&B[(128 + 48) / 4]);
	bb_b.val[0] = vld1q_u32(&B[(128 + 64 + 0) / 4]);
	bb_b.val[1] = vld1q_u32(&B[(128 + 64 + 16) / 4]);
	bb_b.val[2] = vld1q_u32(&B[(128 + 64 + 32) / 4]);
	bb_b.val[3] = vld1q_u32(&B[(128 + 64 + 48) / 4]);
	
	bc_a.val[0] = vld1q_u32(&B[(256 + 0) / 4]);
	bc_a.val[1] = vld1q_u32(&B[(256 + 16) / 4]);
	bc_a.val[2] = vld1q_u32(&B[(256 + 32) / 4]);
	bc_a.val[3] = vld1q_u32(&B[(256 + 48) / 4]);
	bc_b.val[0] = vld1q_u32(&B[(256 + 64 + 0) / 4]);
	bc_b.val[1] = vld1q_u32(&B[(256 + 64 + 16) / 4]);
	bc_b.val[2] = vld1q_u32(&B[(256 + 64 + 32) / 4]);
	bc_b.val[3] = vld1q_u32(&B[(256 + 64 + 48) / 4]);

	// prep

	vst1q_u32(&V[( 0) / 4], ba_a.val[0]);
	vst1q_u32(&V[(16) / 4], ba_a.val[1]);
	vst1q_u32(&V[(32) / 4], ba_a.val[2]);
	vst1q_u32(&V[(48) / 4], ba_a.val[3]);
	vst1q_u32(&V[(64) / 4],  ba_b.val[0]);
	vst1q_u32(&V[(80) / 4],  ba_b.val[1]);
	vst1q_u32(&V[(96) / 4],  ba_b.val[2]);
	vst1q_u32(&V[(112) / 4], ba_b.val[3]);

	vst1q_u32(&V[(128 +  0) / 4], bb_a.val[0]);
	vst1q_u32(&V[(128 + 16) / 4], bb_a.val[1]);
	vst1q_u32(&V[(128 + 32) / 4], bb_a.val[2]);
	vst1q_u32(&V[(128 + 48) / 4], bb_a.val[3]);
	vst1q_u32(&V[(128 + 64) / 4],  bb_b.val[0]);
	vst1q_u32(&V[(128 + 80) / 4],  bb_b.val[1]);
	vst1q_u32(&V[(128 + 96) / 4],  bb_b.val[2]);
	vst1q_u32(&V[(128 + 112) / 4], bb_b.val[3]);

	vst1q_u32(&V[(256 +  0) / 4], bc_a.val[0]);
	vst1q_u32(&V[(256 + 16) / 4], bc_a.val[1]);
	vst1q_u32(&V[(256 + 32) / 4], bc_a.val[2]);
	vst1q_u32(&V[(256 + 48) / 4], bc_a.val[3]);
	vst1q_u32(&V[(256 + 64) / 4], bc_b.val[0]);
	vst1q_u32(&V[(256 + 80) / 4], bc_b.val[1]);
	vst1q_u32(&V[(256 + 96) / 4], bc_b.val[2]);
	vst1q_u32(&V[(256 + 112) / 4],bc_b.val[3]);

	V += 96;

	for (int n = 0; n < N; n++)
	{
		// loop 1 part a
		q_a.val[0] = veorq_u32(ba_b.val[0], ba_a.val[0]);
		q_a.val[1] = veorq_u32(ba_b.val[1], ba_a.val[1]);
		q_a.val[2] = veorq_u32(ba_b.val[2], ba_a.val[2]);
		q_a.val[3] = veorq_u32(ba_b.val[3], ba_a.val[3]);

		q_b.val[0] = veorq_u32(bb_b.val[0], bb_a.val[0]);
		q_b.val[1] = veorq_u32(bb_b.val[1], bb_a.val[1]);
		q_b.val[2] = veorq_u32(bb_b.val[2], bb_a.val[2]);
		q_b.val[3] = veorq_u32(bb_b.val[3], bb_a.val[3]);

		q_c.val[0] = veorq_u32(bc_b.val[0], bc_a.val[0]);
		q_c.val[1] = veorq_u32(bc_b.val[1], bc_a.val[1]);
		q_c.val[2] = veorq_u32(bc_b.val[2], bc_a.val[2]);
		q_c.val[3] = veorq_u32(bc_b.val[3], bc_a.val[3]);

		ba_a = q_a;
		bb_a = q_b;
		bc_a = q_c;

		for (int i = 0; i < 4; i ++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[1]); 
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7); 				
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);				
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 3);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
			
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 1);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 3);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 1);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
		}
		ba_a.val[0] = vaddq_u32(ba_a.val[0], q_a.val[0]);
		ba_a.val[1] = vaddq_u32(ba_a.val[1], q_a.val[1]);
		ba_a.val[2] = vaddq_u32(ba_a.val[2], q_a.val[2]);
		ba_a.val[3] = vaddq_u32(ba_a.val[3], q_a.val[3]);

		q_a = ba_a;

		bb_a.val[0] = vaddq_u32(bb_a.val[0], q_b.val[0]);
		bb_a.val[1] = vaddq_u32(bb_a.val[1], q_b.val[1]);
		bb_a.val[2] = vaddq_u32(bb_a.val[2], q_b.val[2]);
		bb_a.val[3] = vaddq_u32(bb_a.val[3], q_b.val[3]);

		q_b = bb_a;

		bc_a.val[0] = vaddq_u32(bc_a.val[0], q_c.val[0]);
		bc_a.val[1] = vaddq_u32(bc_a.val[1], q_c.val[1]);
		bc_a.val[2] = vaddq_u32(bc_a.val[2], q_c.val[2]);
		bc_a.val[3] = vaddq_u32(bc_a.val[3], q_c.val[3]);

		q_c = bc_a;
		
		for (int i = 0; i < 4; i++)
		{
			vst1q_u32(&V[      (i * 4) ], ba_a.val[i]);
			vst1q_u32(&V[(32 + (i * 4))], bb_a.val[i]);
			vst1q_u32(&V[(64 + (i * 4))], bc_a.val[i]);
		}

		// loop 1 part b

		q_a.val[0] = veorq_u32(ba_b.val[0], q_a.val[0]);
		q_a.val[1] = veorq_u32(ba_b.val[1], q_a.val[1]);
		q_a.val[2] = veorq_u32(ba_b.val[2], q_a.val[2]);
		q_a.val[3] = veorq_u32(ba_b.val[3], q_a.val[3]);
		ba_b = q_a;

		q_b.val[0] = veorq_u32(bb_b.val[0], q_b.val[0]);
		q_b.val[1] = veorq_u32(bb_b.val[1], q_b.val[1]);
		q_b.val[2] = veorq_u32(bb_b.val[2], q_b.val[2]);
		q_b.val[3] = veorq_u32(bb_b.val[3], q_b.val[3]);
		bb_b = q_b;

		q_c.val[0] = veorq_u32(bc_b.val[0], q_c.val[0]);
		q_c.val[1] = veorq_u32(bc_b.val[1], q_c.val[1]);
		q_c.val[2] = veorq_u32(bc_b.val[2], q_c.val[2]);
		q_c.val[3] = veorq_u32(bc_b.val[3], q_c.val[3]);
		bc_b = q_c;


		for (int i = 0; i < 4; i ++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[1]); 
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7); 				
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);				
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 3);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
			
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 1);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 3);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 1);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
		}

		ba_b.val[0] = vaddq_u32(q_a.val[0], ba_b.val[0]);
		ba_b.val[1] = vaddq_u32(q_a.val[1], ba_b.val[1]);
		ba_b.val[2] = vaddq_u32(q_a.val[2], ba_b.val[2]);
		ba_b.val[3] = vaddq_u32(q_a.val[3], ba_b.val[3]);
		bb_b.val[0] = vaddq_u32(q_b.val[0], bb_b.val[0]);
		bb_b.val[1] = vaddq_u32(q_b.val[1], bb_b.val[1]);
		bb_b.val[2] = vaddq_u32(q_b.val[2], bb_b.val[2]);
		bb_b.val[3] = vaddq_u32(q_b.val[3], bb_b.val[3]);
		bc_b.val[0] = vaddq_u32(q_c.val[0], bc_b.val[0]);
		bc_b.val[1] = vaddq_u32(q_c.val[1], bc_b.val[1]);
		bc_b.val[2] = vaddq_u32(q_c.val[2], bc_b.val[2]);
		bc_b.val[3] = vaddq_u32(q_c.val[3], bc_b.val[3]);
		for (int i = 0; i < 4; i++)
		{
			vst1q_u32(&V[(     16 + (i * 4))], ba_b.val[i]);
			vst1q_u32(&V[(32 + 16 + (i * 4))], bb_b.val[i]);
			vst1q_u32(&V[(64 + 16 + (i * 4))], bc_b.val[i]);
		}
		V += 96;
	}
	V = W;

    // loop 2

	uint32x4x4_t x;

	uint32_t one =   32 * (3 * (ba_b.val[0][0] & (N - 1)) + 0);
	uint32_t two =   32 * (3 * (bb_b.val[0][0] & (N - 1)) + 1);
	uint32_t three = 32 * (3 * (bc_b.val[0][0] & (N - 1)) + 2);
	x.val[0] = vld1q_u32(&W[one +  0]);
	x.val[1] = vld1q_u32(&W[one +  4]);
	x.val[2] = vld1q_u32(&W[one +  8]);
	x.val[3] = vld1q_u32(&W[one + 12]);

	for (int n = 0; n < N; n++)
	{
		// loop 2 part a

		ba_a.val[0] = veorq_u32(ba_a.val[0], x.val[0]);
			x.val[0] = vld1q_u32(&W[one + 16 +  0]);
		ba_a.val[1] = veorq_u32(ba_a.val[1], x.val[1]);
			x.val[1] = vld1q_u32(&W[one + 16 +  4]);
		ba_a.val[2] = veorq_u32(ba_a.val[2], x.val[2]);
			x.val[2] = vld1q_u32(&W[one + 16 +  8]);
		ba_a.val[3] = veorq_u32(ba_a.val[3], x.val[3]);

			ba_b.val[0] = veorq_u32(ba_b.val[0], x.val[0]);
			ba_b.val[1] = veorq_u32(ba_b.val[1], x.val[1]);
			x.val[3] = vld1q_u32(&W[one + 16 + 12]);
			ba_b.val[2] = veorq_u32(ba_b.val[2], x.val[2]);
			ba_b.val[3] = veorq_u32(ba_b.val[3], x.val[3]);
		x.val[0] = vld1q_u32(&W[two +  0]);
				q_a.val[0] = veorq_u32(ba_b.val[0], ba_a.val[0]);
				q_a.val[1] = veorq_u32(ba_b.val[1], ba_a.val[1]);
		x.val[1] = vld1q_u32(&W[two +  4]);
				q_a.val[2] = veorq_u32(ba_b.val[2], ba_a.val[2]);
				q_a.val[3] = veorq_u32(ba_b.val[3], ba_a.val[3]);
		x.val[2] = vld1q_u32(&W[two +  8]);
		ba_a = q_a;

		x.val[3] = vld1q_u32(&W[two + 12]);

		bb_a.val[0] = veorq_u32(bb_a.val[0], x.val[0]);
			x.val[0] = vld1q_u32(&W[two + 16 +  0]);
		bb_a.val[1] = veorq_u32(bb_a.val[1], x.val[1]);
			x.val[1] = vld1q_u32(&W[two + 16 +  4]);
		bb_a.val[2] = veorq_u32(bb_a.val[2], x.val[2]);
			x.val[2] = vld1q_u32(&W[two + 16 +  8]);
		bb_a.val[3] = veorq_u32(bb_a.val[3], x.val[3]);
			bb_b.val[0] = veorq_u32(bb_b.val[0], x.val[0]);
			x.val[3] = vld1q_u32(&W[two + 16 + 12]);
			bb_b.val[1] = veorq_u32(bb_b.val[1], x.val[1]);
		x.val[0] = vld1q_u32(&W[three +  0]);
			bb_b.val[2] = veorq_u32(bb_b.val[2], x.val[2]);
			bb_b.val[3] = veorq_u32(bb_b.val[3], x.val[3]);
		x.val[1] = vld1q_u32(&W[three +  4]);
				q_b.val[0] = veorq_u32(bb_b.val[0], bb_a.val[0]);
				q_b.val[1] = veorq_u32(bb_b.val[1], bb_a.val[1]);
		x.val[2] = vld1q_u32(&W[three +  8]);
				q_b.val[2] = veorq_u32(bb_b.val[2], bb_a.val[2]);
				q_b.val[3] = veorq_u32(bb_b.val[3], bb_a.val[3]);
		x.val[3] = vld1q_u32(&W[three + 12]);
		bb_a = q_b;

		bc_a.val[0] = veorq_u32(bc_a.val[0], x.val[0]);
			x.val[0] = vld1q_u32(&W[three + 16 +  0]);
		bc_a.val[1] = veorq_u32(bc_a.val[1], x.val[1]);
			x.val[1] = vld1q_u32(&W[three + 16 +  4]);
		bc_a.val[2] = veorq_u32(bc_a.val[2], x.val[2]);
			x.val[2] = vld1q_u32(&W[three + 16 +  8]);
		bc_a.val[3] = veorq_u32(bc_a.val[3], x.val[3]);
			bc_b.val[0] = veorq_u32(bc_b.val[0], x.val[0]);
			x.val[3] = vld1q_u32(&W[three + 16 + 12]);
			bc_b.val[1] = veorq_u32(bc_b.val[1], x.val[1]);
			bc_b.val[2] = veorq_u32(bc_b.val[2], x.val[2]);
			bc_b.val[3] = veorq_u32(bc_b.val[3], x.val[3]);
				q_c.val[0] = veorq_u32(bc_b.val[0], bc_a.val[0]);
				q_c.val[1] = veorq_u32(bc_b.val[1], bc_a.val[1]);
				q_c.val[2] = veorq_u32(bc_b.val[2], bc_a.val[2]);
				q_c.val[3] = veorq_u32(bc_b.val[3], bc_a.val[3]);
		bc_a = q_c;

		for (int i = 0; i < 4; i++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[1]); 
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7); 				
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);				
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 3);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
			
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 1);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 3);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 1);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
		}
		ba_a.val[0] = vaddq_u32(ba_a.val[0], q_a.val[0]);
		ba_a.val[1] = vaddq_u32(ba_a.val[1], q_a.val[1]);
		ba_a.val[2] = vaddq_u32(ba_a.val[2], q_a.val[2]);
		ba_a.val[3] = vaddq_u32(ba_a.val[3], q_a.val[3]);

		q_a = ba_a;

		bb_a.val[0] = vaddq_u32(bb_a.val[0], q_b.val[0]);
		bb_a.val[1] = vaddq_u32(bb_a.val[1], q_b.val[1]);
		bb_a.val[2] = vaddq_u32(bb_a.val[2], q_b.val[2]);
		bb_a.val[3] = vaddq_u32(bb_a.val[3], q_b.val[3]);
		q_b = bb_a;

		bc_a.val[0] = vaddq_u32(bc_a.val[0], q_c.val[0]);
		bc_a.val[1] = vaddq_u32(bc_a.val[1], q_c.val[1]);
		bc_a.val[2] = vaddq_u32(bc_a.val[2], q_c.val[2]);
		bc_a.val[3] = vaddq_u32(bc_a.val[3], q_c.val[3]);
		q_c = bc_a;

		// loop 2 b

		q_a.val[0] = veorq_u32(ba_b.val[0], q_a.val[0]);
		q_a.val[1] = veorq_u32(ba_b.val[1], q_a.val[1]);
		q_a.val[2] = veorq_u32(ba_b.val[2], q_a.val[2]);
		q_a.val[3] = veorq_u32(ba_b.val[3], q_a.val[3]);
		ba_b = q_a;

		q_b.val[0] = veorq_u32(bb_b.val[0], q_b.val[0]);
		q_b.val[1] = veorq_u32(bb_b.val[1], q_b.val[1]);
		q_b.val[2] = veorq_u32(bb_b.val[2], q_b.val[2]);
		q_b.val[3] = veorq_u32(bb_b.val[3], q_b.val[3]);
		bb_b = q_b;

		q_c.val[0] = veorq_u32(bc_b.val[0], q_c.val[0]);
		q_c.val[1] = veorq_u32(bc_b.val[1], q_c.val[1]);
		q_c.val[2] = veorq_u32(bc_b.val[2], q_c.val[2]);
		q_c.val[3] = veorq_u32(bc_b.val[3], q_c.val[3]);
		bc_b = q_c;


		for (int i = 0; i < 3; i++)
		{
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[1]); 
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7); 				
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);				
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 3);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
			
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 1);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);

			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);

			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 3);

			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 1);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
		}
		{
			//1
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[1]);  	
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);	
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[1]);  	
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[1]); 
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7); 				
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);				
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
			//2
			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);
			//3
			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 3);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 3);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 3);
			//4
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
			
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			//5
			q_tmp.val[0] = vaddq_u32(q_a.val[0], q_a.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 7);
			q_tmp.val[2] = vaddq_u32(q_b.val[0], q_b.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 25);
			q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 1);
			q_a.val[1] = veorq_u32(q_tmp.val[1], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 7);
			q_tmp.val[3] = vaddq_u32(q_c.val[0], q_c.val[3]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 25);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 1);
			q_b.val[1] = veorq_u32(q_tmp.val[1], q_b.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 7);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 25);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 1);
			q_c.val[1] = veorq_u32(q_tmp.val[1], q_c.val[1]);
			//6
			q_tmp.val[0] = vaddq_u32(q_a.val[1], q_a.val[0]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 9);
			q_tmp.val[2] = vaddq_u32(q_b.val[1], q_b.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 23);
			q_a.val[2] = veorq_u32(q_tmp.val[1], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 9);
			q_tmp.val[3] = vaddq_u32(q_c.val[1], q_c.val[0]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 23);
			q_b.val[2] = veorq_u32(q_tmp.val[1], q_b.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 9);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 23);
			q_c.val[2] = veorq_u32(q_tmp.val[1], q_c.val[2]);
			//7
			q_tmp.val[0] = vaddq_u32(q_a.val[2], q_a.val[1]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 13);
			q_tmp.val[2] = vaddq_u32(q_b.val[2], q_b.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 19);
			q_a.val[3] = veorq_u32(q_tmp.val[1], q_a.val[3]);
				q_a.val[1] = vextq_u32(q_a.val[1], q_a.val[1], 3);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 13);
			q_tmp.val[3] = vaddq_u32(q_c.val[2], q_c.val[1]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 19);
			q_b.val[3] = veorq_u32(q_tmp.val[1], q_b.val[3]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 13);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 19);
			q_c.val[3] = veorq_u32(q_tmp.val[1], q_c.val[3]);
			q_b.val[1] = vextq_u32(q_b.val[1], q_b.val[1], 3);
			q_c.val[1] = vextq_u32(q_c.val[1], q_c.val[1], 3);

			//8
			q_tmp.val[0] = vaddq_u32(q_a.val[3], q_a.val[2]);
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[0], 18);
			q_tmp.val[2] = vaddq_u32(q_b.val[3], q_b.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[0], 14);
			q_a.val[0] = veorq_u32(q_tmp.val[1], q_a.val[0]);
				ba_b.val[0] = vaddq_u32(q_a.val[0], ba_b.val[0]);
					one =	32 * (3 * (ba_b.val[0][0] & (N - 1)) + 0);
					__builtin_prefetch(&W[one + 0]);
					__builtin_prefetch(&W[one + 8]);
					__builtin_prefetch(&W[one + 16]);
					__builtin_prefetch(&W[one + 24]);
			
			q_a.val[2] = vextq_u32(q_a.val[2], q_a.val[2], 2);
			q_b.val[2] = vextq_u32(q_b.val[2], q_b.val[2], 2);
			
			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[2], 18);
			q_tmp.val[3] = vaddq_u32(q_c.val[3], q_c.val[2]);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[2], 14);
			q_c.val[2] = vextq_u32(q_c.val[2], q_c.val[2], 2);
			q_b.val[3] = vextq_u32(q_b.val[3], q_b.val[3], 1);
			q_b.val[0] = veorq_u32(q_tmp.val[1], q_b.val[0]);
				bb_b.val[0] = vaddq_u32(q_b.val[0], bb_b.val[0]);
					two =	32 * (3 * (bb_b.val[0][0] & (N - 1)) + 1);
					__builtin_prefetch(&W[two + 0]);
					__builtin_prefetch(&W[two + 8]);
					__builtin_prefetch(&W[two + 16]);
					__builtin_prefetch(&W[two + 24]);

			q_tmp.val[1] = vshlq_n_u32(q_tmp.val[3], 18);
			q_tmp.val[1] = vsriq_n_u32(q_tmp.val[1], q_tmp.val[3], 14);
			q_a.val[3] = vextq_u32(q_a.val[3], q_a.val[3], 1);
			q_c.val[3] = vextq_u32(q_c.val[3], q_c.val[3], 1);
			q_c.val[0] = veorq_u32(q_tmp.val[1], q_c.val[0]);
				bc_b.val[0] = vaddq_u32(q_c.val[0], bc_b.val[0]);
					three = 32 * (3 * (bc_b.val[0][0] & (N - 1)) + 2);
					__builtin_prefetch(&W[three + 0]);
					__builtin_prefetch(&W[three + 8]);
					__builtin_prefetch(&W[three + 16]);
					__builtin_prefetch(&W[three + 24]);
		}

		x.val[0] = vld1q_u32(&W[one +  0]);
		ba_b.val[1] = vaddq_u32(q_a.val[1], ba_b.val[1]);
		ba_b.val[2] = vaddq_u32(q_a.val[2], ba_b.val[2]);
		ba_b.val[3] = vaddq_u32(q_a.val[3], ba_b.val[3]);
		x.val[1] = vld1q_u32(&W[one +  4]);
		bb_b.val[1] = vaddq_u32(q_b.val[1], bb_b.val[1]);
		bb_b.val[2] = vaddq_u32(q_b.val[2], bb_b.val[2]);
		bb_b.val[3] = vaddq_u32(q_b.val[3], bb_b.val[3]);
		x.val[2] = vld1q_u32(&W[one +  8]);
		bc_b.val[1] = vaddq_u32(q_c.val[1], bc_b.val[1]);
		bc_b.val[2] = vaddq_u32(q_c.val[2], bc_b.val[2]);
		bc_b.val[3] = vaddq_u32(q_c.val[3], bc_b.val[3]);
		x.val[3] = vld1q_u32(&W[one + 12]);
	}

	vst1q_u32(&B[0],       ba_a.val[0]);
	vst1q_u32(&B[4],       ba_a.val[1]);
	vst1q_u32(&B[8],       ba_a.val[2]);
	vst1q_u32(&B[12],      ba_a.val[3]);
	vst1q_u32(&B[16 + 0],  ba_b.val[0]);
	vst1q_u32(&B[16 + 4],  ba_b.val[1]);
	vst1q_u32(&B[16 + 8],  ba_b.val[2]);
	vst1q_u32(&B[16 + 12], ba_b.val[3]);

	vst1q_u32(&B[32 + 0],  		bb_a.val[0]);
	vst1q_u32(&B[32 + 4],  		bb_a.val[1]);
	vst1q_u32(&B[32 + 8],  		bb_a.val[2]);
	vst1q_u32(&B[32 + 12], 		bb_a.val[3]);
	vst1q_u32(&B[32 + 16 + 0],  bb_b.val[0]);
	vst1q_u32(&B[32 + 16 + 4],  bb_b.val[1]);
	vst1q_u32(&B[32 + 16 + 8],  bb_b.val[2]);
	vst1q_u32(&B[32 + 16 + 12], bb_b.val[3]);

	vst1q_u32(&B[64 + 0],  		bc_a.val[0]);
	vst1q_u32(&B[64 + 4],  		bc_a.val[1]);
	vst1q_u32(&B[64 + 8],  		bc_a.val[2]);
	vst1q_u32(&B[64 + 12], 		bc_a.val[3]);
	vst1q_u32(&B[64 + 16 + 0],  bc_b.val[0]);
	vst1q_u32(&B[64 + 16 + 4],  bc_b.val[1]);
	vst1q_u32(&B[64 + 16 + 8],  bc_b.val[2]);
	vst1q_u32(&B[64 + 16 + 12], bc_b.val[3]);

	scrypt_shuffle(&B[0  + 0]);
	scrypt_shuffle(&B[16 + 0]);
	scrypt_shuffle(&B[0 + 32]);
	scrypt_shuffle(&B[16 + 32]);
	scrypt_shuffle(&B[0 + 64]);
	scrypt_shuffle(&B[16 + 64]);
}
#else
static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16])
{
	uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
	int i;

	x00 = (B[ 0] ^= Bx[ 0]);
	x01 = (B[ 1] ^= Bx[ 1]);
	x02 = (B[ 2] ^= Bx[ 2]);
	x03 = (B[ 3] ^= Bx[ 3]);
	x04 = (B[ 4] ^= Bx[ 4]);
	x05 = (B[ 5] ^= Bx[ 5]);
	x06 = (B[ 6] ^= Bx[ 6]);
	x07 = (B[ 7] ^= Bx[ 7]);
	x08 = (B[ 8] ^= Bx[ 8]);
	x09 = (B[ 9] ^= Bx[ 9]);
	x10 = (B[10] ^= Bx[10]);
	x11 = (B[11] ^= Bx[11]);
	x12 = (B[12] ^= Bx[12]);
	x13 = (B[13] ^= Bx[13]);
	x14 = (B[14] ^= Bx[14]);
	x15 = (B[15] ^= Bx[15]);
	for (i = 0; i < 8; i += 2) {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns. */
		x04 ^= R(x00+x12, 7);	x09 ^= R(x05+x01, 7);
		x14 ^= R(x10+x06, 7);	x03 ^= R(x15+x11, 7);
		
		x08 ^= R(x04+x00, 9);	x13 ^= R(x09+x05, 9);
		x02 ^= R(x14+x10, 9);	x07 ^= R(x03+x15, 9);
		
		x12 ^= R(x08+x04,13);	x01 ^= R(x13+x09,13);
		x06 ^= R(x02+x14,13);	x11 ^= R(x07+x03,13);
		
		x00 ^= R(x12+x08,18);	x05 ^= R(x01+x13,18);
		x10 ^= R(x06+x02,18);	x15 ^= R(x11+x07,18);
		
		/* Operate on rows. */
		x01 ^= R(x00+x03, 7);	x06 ^= R(x05+x04, 7);
		x11 ^= R(x10+x09, 7);	x12 ^= R(x15+x14, 7);
		
		x02 ^= R(x01+x00, 9);	x07 ^= R(x06+x05, 9);
		x08 ^= R(x11+x10, 9);	x13 ^= R(x12+x15, 9);
		
		x03 ^= R(x02+x01,13);	x04 ^= R(x07+x06,13);
		x09 ^= R(x08+x11,13);	x14 ^= R(x13+x12,13);
		
		x00 ^= R(x03+x02,18);	x05 ^= R(x04+x07,18);
		x10 ^= R(x09+x08,18);	x15 ^= R(x14+x13,18);
#undef R
	}
	B[ 0] += x00;
	B[ 1] += x01;
	B[ 2] += x02;
	B[ 3] += x03;
	B[ 4] += x04;
	B[ 5] += x05;
	B[ 6] += x06;
	B[ 7] += x07;
	B[ 8] += x08;
	B[ 9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}

static inline void scrypt_core(uint32_t *X, uint32_t *V, int N)
{
	int i;

	for (i = 0; i < N; i++) {
		memcpy(&V[i * 32], X, 128);
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}
	for (i = 0; i < N; i++) {
		uint32_t j = 32 * (X[16] & (N - 1));
		for (uint8_t k = 0; k < 32; k++)
			X[k] ^= V[j + k];
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}
}

#endif

#ifndef SCRYPT_MAX_WAYS
#define SCRYPT_MAX_WAYS 1
#define scrypt_best_throughput() 1
#endif

unsigned char *scrypt_buffer_alloc(int N)
{
	return (uchar*) malloc((size_t)N * SCRYPT_MAX_WAYS * 128 + 63);
}

static void scrypt_1024_1_1_256(const uint32_t *input, uint32_t *output,
	uint32_t *midstate, unsigned char *scratchpad, int N)
{
	uint32_t tstate[8], ostate[8];
	uint32_t X[32];
	uint32_t *V;
	
	V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

	memcpy(tstate, midstate, 32);
	HMAC_SHA256_80_init(input, tstate, ostate);
	PBKDF2_SHA256_80_128(tstate, ostate, input, X);

	scrypt_core(X, V, N);

	PBKDF2_SHA256_128_32(tstate, ostate, X, output);
}

#ifdef HAVE_SHA256_4WAY
static void scrypt_1024_1_1_256_4way(const uint32_t *input,
	uint32_t *output, uint32_t *midstate, unsigned char *scratchpad, int N)
{
	uint32_t _ALIGN(128) tstate[4 * 8];
	uint32_t _ALIGN(128) ostate[4 * 8];
	uint32_t _ALIGN(128) W[4 * 32];
	uint32_t _ALIGN(128) X[4 * 32];
	uint32_t *V;
	int i, k;
	
	V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

	for (i = 0; i < 20; i++)
		for (k = 0; k < 4; k++)
			W[4 * i + k] = input[k * 20 + i];
	for (i = 0; i < 8; i++)
		for (k = 0; k < 4; k++)
			tstate[4 * i + k] = midstate[i];
	HMAC_SHA256_80_init_4way(W, tstate, ostate);
	PBKDF2_SHA256_80_128_4way(tstate, ostate, W, W);
	for (i = 0; i < 32; i++)
		for (k = 0; k < 4; k++)
			X[k * 32 + i] = W[4 * i + k];
	scrypt_core(X + 0 * 32, V, N);
	scrypt_core(X + 1 * 32, V, N);
	scrypt_core(X + 2 * 32, V, N);
	scrypt_core(X + 3 * 32, V, N);
	for (i = 0; i < 32; i++)
		for (k = 0; k < 4; k++)
			W[4 * i + k] = X[k * 32 + i];
	PBKDF2_SHA256_128_32_4way(tstate, ostate, W, W);
	for (i = 0; i < 8; i++)
		for (k = 0; k < 4; k++)
			output[k * 8 + i] = W[4 * i + k];
}
#endif /* HAVE_SHA256_4WAY */

#ifdef HAVE_SCRYPT_3WAY

static void scrypt_1024_1_1_256_3way(const uint32_t *input,
	uint32_t *output, uint32_t *midstate, unsigned char *scratchpad, int N)
{
	uint32_t _ALIGN(64) tstate[3 * 8], ostate[3 * 8];
	uint32_t _ALIGN(64) X[3 * 32];
	uint32_t *V;
	
	V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

	memcpy(tstate +  0, midstate, 32);
	memcpy(tstate +  8, midstate, 32);
	memcpy(tstate + 16, midstate, 32);
	HMAC_SHA256_80_init(input +  0, tstate +  0, ostate +  0);
	HMAC_SHA256_80_init(input + 20, tstate +  8, ostate +  8);
	HMAC_SHA256_80_init(input + 40, tstate + 16, ostate + 16);
	PBKDF2_SHA256_80_128(tstate +  0, ostate +  0, input +  0, X +  0);
	PBKDF2_SHA256_80_128(tstate +  8, ostate +  8, input + 20, X + 32);
	PBKDF2_SHA256_80_128(tstate + 16, ostate + 16, input + 40, X + 64);

	scrypt_core_3way(X, V, N);

	PBKDF2_SHA256_128_32(tstate +  0, ostate +  0, X +  0, output +  0);
	PBKDF2_SHA256_128_32(tstate +  8, ostate +  8, X + 32, output +  8);
	PBKDF2_SHA256_128_32(tstate + 16, ostate + 16, X + 64, output + 16);
}

#ifdef HAVE_SHA256_4WAY
static void scrypt_1024_1_1_256_12way(const uint32_t *input,
	uint32_t *output, uint32_t *midstate, unsigned char *scratchpad, int N)
{
	uint32_t _ALIGN(128) tstate[12 * 8];
	uint32_t _ALIGN(128) ostate[12 * 8];
	uint32_t _ALIGN(128) W[12 * 32];
	uint32_t _ALIGN(128) X[12 * 32];
	uint32_t *V;
	int i, j, k;
	
	V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

	for (j = 0; j < 3; j++)
		for (i = 0; i < 20; i++)
			for (k = 0; k < 4; k++)
				W[128 * j + 4 * i + k] = input[80 * j + k * 20 + i];
	for (j = 0; j < 3; j++)
		for (i = 0; i < 8; i++)
			for (k = 0; k < 4; k++)
				tstate[32 * j + 4 * i + k] = midstate[i];
	HMAC_SHA256_80_init_4way(W +   0, tstate +  0, ostate +  0);
	HMAC_SHA256_80_init_4way(W + 128, tstate + 32, ostate + 32);
	HMAC_SHA256_80_init_4way(W + 256, tstate + 64, ostate + 64);
	PBKDF2_SHA256_80_128_4way(tstate +  0, ostate +  0, W +   0, W +   0);
	PBKDF2_SHA256_80_128_4way(tstate + 32, ostate + 32, W + 128, W + 128);
	PBKDF2_SHA256_80_128_4way(tstate + 64, ostate + 64, W + 256, W + 256);
	for (j = 0; j < 3; j++)
		for (i = 0; i < 32; i++)
			for (k = 0; k < 4; k++)
				X[128 * j + k * 32 + i] = W[128 * j + 4 * i + k];
	scrypt_core_3way(X + 0 * 96, V, N);
	scrypt_core_3way(X + 1 * 96, V, N);
	scrypt_core_3way(X + 2 * 96, V, N);
	scrypt_core_3way(X + 3 * 96, V, N);
	for (j = 0; j < 3; j++)
		for (i = 0; i < 32; i++)
			for (k = 0; k < 4; k++)
				W[128 * j + 4 * i + k] = X[128 * j + k * 32 + i];
	PBKDF2_SHA256_128_32_4way(tstate +  0, ostate +  0, W +   0, W +   0);
	PBKDF2_SHA256_128_32_4way(tstate + 32, ostate + 32, W + 128, W + 128);
	PBKDF2_SHA256_128_32_4way(tstate + 64, ostate + 64, W + 256, W + 256);
	for (j = 0; j < 3; j++)
		for (i = 0; i < 8; i++)
			for (k = 0; k < 4; k++)
				output[32 * j + k * 8 + i] = W[128 * j + 4 * i + k];
}
#endif /* HAVE_SHA256_4WAY */

#endif /* HAVE_SCRYPT_3WAY */

#ifdef HAVE_SCRYPT_6WAY
static void scrypt_1024_1_1_256_24way(const uint32_t *input,
	uint32_t *output, uint32_t *midstate, unsigned char *scratchpad, int N)
{
	uint32_t _ALIGN(128) tstate[24 * 8];
	uint32_t _ALIGN(128) ostate[24 * 8];
	uint32_t _ALIGN(128) W[24 * 32];
	uint32_t _ALIGN(128) X[24 * 32];
	uint32_t *V;
	int i, j, k;
	
	V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));
	
	for (j = 0; j < 3; j++) 
		for (i = 0; i < 20; i++)
			for (k = 0; k < 8; k++)
				W[8 * 32 * j + 8 * i + k] = input[8 * 20 * j + k * 20 + i];
	for (j = 0; j < 3; j++)
		for (i = 0; i < 8; i++)
			for (k = 0; k < 8; k++)
				tstate[8 * 8 * j + 8 * i + k] = midstate[i];
	HMAC_SHA256_80_init_8way(W +   0, tstate +   0, ostate +   0);
	HMAC_SHA256_80_init_8way(W + 256, tstate +  64, ostate +  64);
	HMAC_SHA256_80_init_8way(W + 512, tstate + 128, ostate + 128);
	PBKDF2_SHA256_80_128_8way(tstate +   0, ostate +   0, W +   0, W +   0);
	PBKDF2_SHA256_80_128_8way(tstate +  64, ostate +  64, W + 256, W + 256);
	PBKDF2_SHA256_80_128_8way(tstate + 128, ostate + 128, W + 512, W + 512);
	for (j = 0; j < 3; j++)
		for (i = 0; i < 32; i++)
			for (k = 0; k < 8; k++)
				X[8 * 32 * j + k * 32 + i] = W[8 * 32 * j + 8 * i + k];
	scrypt_core_6way(X + 0 * 32, V, N);
	scrypt_core_6way(X + 6 * 32, V, N);
	scrypt_core_6way(X + 12 * 32, V, N);
	scrypt_core_6way(X + 18 * 32, V, N);
	for (j = 0; j < 3; j++)
		for (i = 0; i < 32; i++)
			for (k = 0; k < 8; k++)
				W[8 * 32 * j + 8 * i + k] = X[8 * 32 * j + k * 32 + i];
	PBKDF2_SHA256_128_32_8way(tstate +   0, ostate +   0, W +   0, W +   0);
	PBKDF2_SHA256_128_32_8way(tstate +  64, ostate +  64, W + 256, W + 256);
	PBKDF2_SHA256_128_32_8way(tstate + 128, ostate + 128, W + 512, W + 512);
	for (j = 0; j < 3; j++)
		for (i = 0; i < 8; i++)
			for (k = 0; k < 8; k++)
				output[8 * 8 * j + k * 8 + i] = W[8 * 32 * j + 8 * i + k];
}
#endif /* HAVE_SCRYPT_6WAY */

extern int scanhash_scrypt(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
	unsigned char *scratchbuf, uint32_t N)
{
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	uint32_t data[SCRYPT_MAX_WAYS * 20], hash[SCRYPT_MAX_WAYS * 8];
	uint32_t midstate[8];
	uint32_t n = pdata[19] - 1;
	const uint32_t Htarg = ptarget[7];
	int throughput = scrypt_best_throughput();
	int i;
	
#ifdef HAVE_SHA256_4WAY
	if (sha256_use_4way())
		throughput *= 4;
#endif
	
	for (i = 0; i < throughput; i++)
		memcpy(data + i * 20, pdata, 80);
	
	sha256_init(midstate);
	sha256_transform(midstate, data, 0);
	
	do {
		for (i = 0; i < throughput; i++)
			data[i * 20 + 19] = ++n;
		
#if defined(HAVE_SHA256_4WAY)
		if (throughput == 4)
			scrypt_1024_1_1_256_4way(data, hash, midstate, scratchbuf, N);
		else
#endif
#if defined(HAVE_SCRYPT_3WAY) && defined(HAVE_SHA256_4WAY)
		if (throughput == 12)
			scrypt_1024_1_1_256_12way(data, hash, midstate, scratchbuf, N);
		else
#endif
#if defined(HAVE_SCRYPT_6WAY)
		if (throughput == 24)
			scrypt_1024_1_1_256_24way(data, hash, midstate, scratchbuf, N);
		else
#endif
#if defined(HAVE_SCRYPT_3WAY)
		if (throughput == 3)
			scrypt_1024_1_1_256_3way(data, hash, midstate, scratchbuf, N);
		else
#endif
		scrypt_1024_1_1_256(data, hash, midstate, scratchbuf, N);
		
		for (i = 0; i < throughput; i++) {
			if (unlikely(hash[i * 8 + 7] <= Htarg && fulltest(hash + i * 8, ptarget))) {
				work_set_target_ratio(work, hash + i * 8);
				*hashes_done = n - pdata[19] + 1;
				pdata[19] = data[i * 20 + 19];
				return 1;
			}
		}
	} while (likely(n < max_nonce && !work_restart[thr_id].restart));
	
	*hashes_done = n - pdata[19] + 1;
	pdata[19] = n;
	return 0;
}

/* simple cpu test (util.c) */
void scrypthash(void *output, const void *input, uint32_t N)
{
	uint32_t midstate[8];
	char *scratchbuf = scrypt_buffer_alloc(N);

	memset(output, 0, 32);
	if (!scratchbuf)
		return;

	sha256_init(midstate);
	sha256_transform(midstate, input, 0);

	scrypt_1024_1_1_256((uint32_t*)input, (uint32_t*)output, midstate, scratchbuf, N);

	free(scratchbuf);
}
