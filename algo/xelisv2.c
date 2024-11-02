#include "miner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_sha2.h"
#include "crypto/blake3.h"
#include "crypto/chacha20.h"
#if defined(_M_X64) || defined(__x86_64__)
#include <wmmintrin.h>
#endif
#if defined(__ARM_NEON)
  #include <arm_neon.h>
#endif


#define INPUT_LEN (112)
#define MEMSIZE (429 * 128)
#define ITERS (3)
#define HASHSIZE (32)

static inline void blake3(const uint8_t *input, int len, uint8_t *output)
{
	blake3_hasher hasher;
	blake3_hasher_init(&hasher);
	blake3_hasher_update(&hasher, input, len);
	blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
}

#define HASH_SIZE (32)
#define CHUNK_SIZE (32)
#define NONCE_SIZE (12)
#define OUTPUT_SIZE (MEMSIZE * 8)
#define CHUNKS (4)


void xel_stage_1(const uint8_t *input, size_t input_len, uint8_t scratch_pad[OUTPUT_SIZE])
{
	uint8_t key[CHUNK_SIZE * CHUNKS] = {0};
	uint8_t input_hash[HASH_SIZE];
	uint8_t buffer[CHUNK_SIZE * 2];
	memcpy(key, input, INPUT_LEN);
	// memcpy(key, input, sizeof(input));
	blake3(input, input_len, buffer);

	uint8_t *t = scratch_pad;

	memcpy(buffer + CHUNK_SIZE, key + 0 * CHUNK_SIZE, CHUNK_SIZE);
	blake3(buffer, CHUNK_SIZE * 2, input_hash);
	chacha_encrypt(input_hash, buffer, NULL, t, OUTPUT_SIZE / CHUNKS, 8);

	t += OUTPUT_SIZE / CHUNKS;
	memcpy(buffer, input_hash, CHUNK_SIZE);
	memcpy(buffer + CHUNK_SIZE, key + 1 * CHUNK_SIZE, CHUNK_SIZE);
	blake3(buffer, CHUNK_SIZE * 2, input_hash);
	chacha_encrypt(input_hash, t - NONCE_SIZE, NULL, t, OUTPUT_SIZE / CHUNKS, 8);

	t += OUTPUT_SIZE / CHUNKS;
	memcpy(buffer, input_hash, CHUNK_SIZE);
	memcpy(buffer + CHUNK_SIZE, key + 2 * CHUNK_SIZE, CHUNK_SIZE);
	blake3(buffer, CHUNK_SIZE * 2, input_hash);
	chacha_encrypt(input_hash, t - NONCE_SIZE, NULL, t, OUTPUT_SIZE / CHUNKS, 8);

	t += OUTPUT_SIZE / CHUNKS;
	memcpy(buffer, input_hash, CHUNK_SIZE);
	memcpy(buffer + CHUNK_SIZE, key + 3 * CHUNK_SIZE, CHUNK_SIZE);
	blake3(buffer, CHUNK_SIZE * 2, input_hash);
	chacha_encrypt(input_hash, t - NONCE_SIZE, NULL, t, OUTPUT_SIZE / CHUNKS, 8);
}


#define KEY "xelishash-pow-v2"
#define BUFSIZE (MEMSIZE / 2)

// https://danlark.org/2020/06/14/128-bit-division
#if defined(USE_ASM) && defined(x86_64)
static inline uint64_t Divide128Div64To64(uint64_t high, uint64_t low, uint64_t divisor, uint64_t *remainder)
{
	uint64_t result;
	__asm__("divq %[v]"
			: "=a"(result), "=d"(*remainder) // Output parametrs, =a for rax, =d for rdx, [v] is an
			// alias for divisor, input paramters "a" and "d" for low and high.
			: [v] "r"(divisor), "a"(low), "d"(high));
	return result;
}

static inline uint64_t udiv(uint64_t high, uint64_t low, uint64_t divisor)
{
	uint64_t remainder;

	if (high < divisor)
	{
		return Divide128Div64To64(high, low, divisor, &remainder);
	}
	else
	{
		uint64_t qhi = Divide128Div64To64(0, high, divisor, &high);
		return Divide128Div64To64(high, low, divisor, &remainder);
	}
}

static inline uint64_t ROTR(uint64_t x, uint32_t r)
{
	asm("rorq %%cl, %0" : "+r"(x) : "c"(r));
	return x;
}

static inline uint64_t ROTL(uint64_t x, uint32_t r)
{
	asm("rolq %%cl, %0" : "+r"(x) : "c"(r));
	return x;
}
#else // Use ASM
static inline uint64_t Divide128Div64To64(uint64_t high, uint64_t low, uint64_t divisor, uint64_t *remainder)
{
    // Combine high and low into a 128-bit dividend
    __uint128_t dividend = ((__uint128_t)high << 64) | low;

    // Perform division using built-in compiler functions
    *remainder = dividend % divisor;
    return dividend / divisor;
}

static inline uint64_t ROTR(uint64_t x, uint32_t r)
{
    r %= 64;  // Ensure r is within the range [0, 63] for a 64-bit rotate
    return (x >> r) | (x << (64 - r));
}

static inline uint64_t ROTL(uint64_t x, uint32_t r)
{
    r %= 64;  // Ensure r is within the range [0, 63] for a 64-bit rotate
    return (x << r) | (x >> (64 - r));
}
#endif

static inline uint64_t udiv(uint64_t high, uint64_t low, uint64_t divisor)
{
    uint64_t remainder;

    if (high < divisor)
    {
        return Divide128Div64To64(high, low, divisor, &remainder);
    }
    else
    {
        uint64_t qhi = Divide128Div64To64(0, high, divisor, &high);
        return Divide128Div64To64(high, low, divisor, &remainder);
    }
}


static inline __uint128_t combine_uint64(uint64_t high, uint64_t low)
{
	return ((__uint128_t)high << 64) | low;
}

/*
uint64_t isqrt(uint64_t n) {
	if (n < 2)
		return n;

	uint64_t x = n;
	uint64_t y = (x + 1) >> 1;

	while (y < x) {
		x = y;
		y = (x + n / x) >> 1;
	}

	return x;
}
*/

uint64_t isqrt(uint64_t n)
{
	if (n < 2)
		return n;

	uint64_t x = n;
	uint64_t result = 0;
	uint64_t bit = (uint64_t)1 << 62; // The second-to-top bit is set

	// "bit" starts at the highest power of four <= the argument.
	while (bit > x)
		bit >>= 2;

	while (bit != 0)
	{
		if (x >= result + bit)
		{
			x -= result + bit;
			result = (result >> 1) + bit;
		}
		else
		{
			result >>= 1;
		}
		bit >>= 2;
	}

	return result;
}

void static inline uint64_to_le_bytes(uint64_t value, uint8_t *bytes)
{
	for (int i = 0; i < 8; i++)
	{
		bytes[i] = value & 0xFF;
		value >>= 8;
	}
}

uint64_t static inline le_bytes_to_uint64(const uint8_t *bytes)
{
	uint64_t value = 0;
	for (int i = 7; i >= 0; i--)
		value = (value << 8) | bytes[i];
	return value;
}

// AES S-box
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xFA, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Helper function to perform GF(2^8) multiplication
static uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00);
}

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) {
            result ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    return result;
}


// AES SubBytes transformation
static void sub_bytes(uint8_t *state) {
    for (int i = 0; i < 16; ++i) {
        state[i] = sbox[state[i]];
    }
}


// AES ShiftRows transformation
static void shift_rows(uint8_t *state) {
    uint8_t temp[16];
    temp[0]  = state[0];
    temp[1]  = state[5];
    temp[2]  = state[10];
    temp[3]  = state[15];
    temp[4]  = state[4];
    temp[5]  = state[9];
    temp[6]  = state[14];
    temp[7]  = state[3];
    temp[8]  = state[8];
    temp[9]  = state[13];
    temp[10] = state[2];
    temp[11] = state[7];
    temp[12] = state[12];
    temp[13] = state[1];
    temp[14] = state[6];
    temp[15] = state[11];
    memcpy(state, temp, 16);
}
// AES MixColumns transformation
static void mix_columns(uint8_t *state) {
    uint8_t temp[16];
    for (int i = 0; i < 4; ++i) {
        temp[i * 4 + 0] = gmul(0x02, state[i * 4 + 0]) ^ gmul(0x03, state[i * 4 + 1]) ^ gmul(0x01, state[i * 4 + 2]) ^ gmul(0x01, state[i * 4 + 3]);
        temp[i * 4 + 1] = gmul(0x01, state[i * 4 + 0]) ^ gmul(0x02, state[i * 4 + 1]) ^ gmul(0x03, state[i * 4 + 2]) ^ gmul(0x01, state[i * 4 + 3]);
        temp[i * 4 + 2] = gmul(0x01, state[i * 4 + 0]) ^ gmul(0x01, state[i * 4 + 1]) ^ gmul(0x02, state[i * 4 + 2]) ^ gmul(0x03, state[i * 4 + 3]);
        temp[i * 4 + 3] = gmul(0x03, state[i * 4 + 0]) ^ gmul(0x01, state[i * 4 + 1]) ^ gmul(0x01, state[i * 4 + 2]) ^ gmul(0x02, state[i * 4 + 3]);
    }
    memcpy(state, temp, 16);
}

// AES AddRoundKey transformation
static void add_round_key(uint8_t *state, const uint8_t *round_key) {
    for (int i = 0; i < 16; ++i) {
        state[i] ^= round_key[i];
    }
}


void aes_single_round_no_intrinsics(uint8_t *state, const uint8_t *round_key) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, round_key);
}

void static inline aes_single_round(uint8_t *block, const uint8_t *key)
{
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
  #if defined(_M_X64) || defined(__x86_64__)

	__m128i block_vec = _mm_loadu_si128((const __m128i *)block);
	__m128i key_vec = _mm_loadu_si128((const __m128i *)key);

	// Perform single AES encryption round
	block_vec = _mm_aesenc_si128(block_vec, key_vec);

	_mm_storeu_si128((__m128i *)block, block_vec);
  #elif defined(__ARM_FEATURE_AES)
    uint8x16_t blck = vld1q_u8(block);
    uint8x16_t ky = vld1q_u8(key);
    // This magic sauce is from here: https://blog.michaelbrase.com/2018/06/04/optimizing-x86-aes-intrinsics-on-armv8-a/
    uint8x16_t rslt = vaesmcq_u8(vaeseq_u8(blck, (uint8x16_t){})) ^ ky;
    vst1q_u8(block, rslt);
  #endif
#else
   aes_single_round_no_intrinsics(block, key);
#endif
}

void xel_stage_3(uint64_t *scratch)
{
	uint64_t *mem_buffer_a = scratch;
	uint64_t *mem_buffer_b = &scratch[BUFSIZE];

	uint64_t addr_a = mem_buffer_b[BUFSIZE - 1];
	uint64_t addr_b = mem_buffer_a[BUFSIZE - 1] >> 32;
	uint32_t r = 0;

	for (uint32_t i = 0; i < ITERS; i++)
	{
		uint64_t mem_a = mem_buffer_a[addr_a % BUFSIZE];
		uint64_t mem_b = mem_buffer_b[addr_b % BUFSIZE];

		uint8_t block[16];
		uint64_to_le_bytes(mem_b, block);
		uint64_to_le_bytes(mem_a, block + 8);
		aes_single_round(block, KEY);

		uint64_t hash1 = le_bytes_to_uint64(block);
		uint64_t hash2 = mem_a ^ mem_b;
		uint64_t result = ~(hash1 ^ hash2);

		for (uint32_t j = 0; j < BUFSIZE; j++)
		{
			uint64_t a = mem_buffer_a[result % BUFSIZE];
			uint64_t b = mem_buffer_b[~ROTR(result, r) % BUFSIZE];
			uint64_t c = (r < BUFSIZE) ? mem_buffer_a[r] : mem_buffer_b[r - BUFSIZE];
			r = (r < MEMSIZE - 1) ? r + 1 : 0;

			uint64_t v;
			__uint128_t t1, t2;
			switch (ROTL(result, (uint32_t)c) & 0xf)
			{
			case 0:
				v = ROTL(c, i * j) ^ b;
				break;
			case 1:
				v = ROTR(c, i * j) ^ a;
				break;
			case 2:
				v = a ^ b ^ c;
				break;
			case 3:
				v = ((a + b) * c);
				break;
			case 4:
				v = ((b - c) * a);
				break;
			case 5:
				v = (c - a + b);
				break;
			case 6:
				v = (a - b + c);
				break;
			case 7:
				v = (b * c + a);
				break;
			case 8:
				v = (c * a + b);
				break;
			case 9:
				v = (a * b * c);
				break;
			case 10:
			{
				t1 = combine_uint64(a, b);
				uint64_t t2 = c | 1;
				v = t1 % t2;
			}
			break;
			case 11:
			{
				t1 = combine_uint64(b, c);
				t2 = combine_uint64(ROTL(result, r), a | 2);
				v = (t2 > t1) ? c : t1 % t2;
			}
			break;
			case 12:
				v = udiv(c, a, b | 4);
				break;
			case 13:
			{
				t1 = combine_uint64(ROTL(result, r), b);
				t2 = combine_uint64(a, c | 8);
				v = (t1 > t2) ? t1 / t2 : a ^ b;
			}
			break;
			case 14:
			{
				t1 = combine_uint64(b, a);
				uint64_t t2 = c;
				v = (t1 * t2) >> 64;
			}
			break;
			case 15:
			{
				t1 = combine_uint64(a, c);
				t2 = combine_uint64(ROTR(result, r), b);
				v = (t1 * t2) >> 64;
			}
			break;
			}
			result = ROTL(result ^ v, 1);

			uint64_t t = mem_buffer_a[BUFSIZE - j - 1] ^ result;
			mem_buffer_a[BUFSIZE - j - 1] = t;
			mem_buffer_b[j] ^= ROTR(t, result);
		}
		addr_a = result;
		addr_b = isqrt(result);
	}
}

#define XEL_INPUT_LEN (112)
void xelisv2_hash(const uint32_t* input, uint32_t* output, uint8_t* xel_input, uint64_t* scratch)
{

        uint8_t *scratch_uint8 = (uint8_t *)scratch;
	  uint8_t hash[HASHSIZE];  // See Below
	int len=80; // #FixMe

			memcpy(xel_input, input, len);  // Ensure we have correct hash input only with trailing 0 as needed
                        xel_stage_1(xel_input, XEL_INPUT_LEN, scratch_uint8);
                        xel_stage_3(scratch);
                        // blake3(scratch_uint8, OUTPUT_SIZE, output);

                         blake3(scratch_uint8, OUTPUT_SIZE, hash); // This appears to be uncessary, but the compiler complains...
			 memcpy(output,hash,HASHSIZE*sizeof(uint8_t)); // See above ^^^^^^^
                        return;
}

int scanhash_xelisv2(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
        uint32_t _ALIGN(128) hash[8];
        uint32_t _ALIGN(128) endiandata[20];
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

        const uint32_t Htarg = ptarget[7];
        const uint32_t first_nonce = pdata[19];
        uint32_t nonce = first_nonce;
        volatile uint8_t *restart = &(work_restart[thr_id].restart);


	uint8_t *xel_input = (uint8_t *)calloc(INPUT_LEN, sizeof(uint8_t));
        uint64_t *scratch = (uint64_t *)calloc(MEMSIZE, sizeof(uint64_t));

        if (opt_benchmark)
                ptarget[7] = 0x0cff;

        for (int k=0; k < 19; k++)
                be32enc(&endiandata[k], pdata[k]);

        do {
                be32enc(&endiandata[19], nonce);
                xelisv2_hash(endiandata, hash, xel_input, scratch);

                if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
                        work_set_target_ratio(work, hash);
                        pdata[19] = nonce;
                        *hashes_done = pdata[19] - first_nonce;
		        free(scratch);	
		        free(xel_input);	
                        return 1;
                }
                nonce++;

        } while (nonce < max_nonce && !(*restart));

        pdata[19] = nonce;
        *hashes_done = pdata[19] - first_nonce + 1;
        free(scratch);	
        free(xel_input);	
        return 0;
}
