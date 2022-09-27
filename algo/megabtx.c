#include "miner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_FUNC_BASE_TIMESTAMP_1 1492973331 // Bitcore  Genesis
#define HASH_FUNC_COUNT_1 8
#define HASH_FUNC_COUNT_2 8
#define HASH_FUNC_COUNT_3 7
#define HASH_FUNC_VAR_1 3333
#define HASH_FUNC_VAR_2 2100
#define HASH_FUNC_COUNT_PERMUTATIONS_7 5040
#define HASH_FUNC_COUNT_PERMUTATIONS 40320

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_shabal.h"
#include "sha3/sph_whirlpool.h"
#include "sha3/gost_streebog.h"
#include "sha3/sph_haval.h"
#include "sha3/sph_sha2.h"


#define _ALIGN(x) __attribute__ ((aligned(x)))

// helpers
inline void swap(int *a, int *b) {
	int c = *a;
	*a = *b;
	*b = c;
}

static void reverse(int *pbegin, int *pend) {
	while ( (pbegin != pend) && (pbegin != --pend) )
		swap(pbegin++, pend);
}

static void next_permutation(int *pbegin, int *pend) {
	if (pbegin == pend)
		return;

	int *i = pbegin;
	++i;
	if (i == pend)
		return;

	i = pend;
	--i;

	while (1) {
		int *j = i;
		--i;

		if (*i < *j) {
			int *k = pend;

			while (!(*i < *--k))
				/* pass */;

			swap(i, k);
			reverse(j, pend);
			return; // true
		}

		if (i == pbegin) {
			reverse(pbegin, pend);
			return; // false
		}
	}
}

void megabtx_hash(const char* input, char* output, uint32_t len)
{
	uint32_t _ALIGN(64) hash[23];
	uint32_t *work_data = (uint32_t *)input;
	const uint32_t timestamp = work_data[17];

	sph_blake512_context     ctx_blake;
	sph_bmw512_context       ctx_bmw;
	sph_groestl512_context   ctx_groestl;
	sph_jh512_context        ctx_jh;
	sph_keccak512_context    ctx_keccak;
	sph_skein512_context     ctx_skein;
	sph_luffa512_context     ctx_luffa;
	sph_cubehash512_context  ctx_cubehash;
	sph_shavite512_context   ctx_shavite;
	sph_simd512_context      ctx_simd;
	sph_echo512_context      ctx_echo;
	sph_hamsi512_context     ctx_hamsi;
	sph_fugue512_context     ctx_fugue;	
	sph_shabal512_context    ctx_shabal;
	sph_whirlpool_context    ctx_whirlpool;
	sph_sha512_context       ctx_sha512;
	sph_gost512_context      ctx_gost;	
	sph_haval256_5_context   ctx_haval;

    uint32_t permutation_1[HASH_FUNC_COUNT_1];
	uint32_t permutation_2[HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1];
	uint32_t permutation_3[HASH_FUNC_COUNT_3 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1];

    //Init1
	for (uint32_t i = 1; i < HASH_FUNC_COUNT_1; i++) {
		permutation_1[i] = i;
        }

 //Init2
	for (uint32_t i = HASH_FUNC_COUNT_1; i < HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1; i++) {
    permutation_2[i] = i;
    }

    //Init3
     for (uint32_t i = HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2; i < HASH_FUNC_COUNT_3 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1; i++) {
         permutation_3[i] = i;
    }

            uint32_t steps_1 = (timestamp - HASH_FUNC_BASE_TIMESTAMP_1) % HASH_FUNC_COUNT_PERMUTATIONS_7;
            for (uint32_t i = 0; i < steps_1; i++) {
                next_permutation(permutation_1, permutation_1 + HASH_FUNC_COUNT_1);
            }

            uint32_t steps_2 = (timestamp+ HASH_FUNC_VAR_1 - HASH_FUNC_BASE_TIMESTAMP_1) % HASH_FUNC_COUNT_PERMUTATIONS;
            for (uint32_t i = 0; i < steps_2; i++) {
                next_permutation(permutation_2 + HASH_FUNC_COUNT_1, permutation_2 + HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2);
            }

            uint32_t steps_3 = (timestamp+ HASH_FUNC_VAR_2 - HASH_FUNC_BASE_TIMESTAMP_1) % HASH_FUNC_COUNT_PERMUTATIONS_7;
            for (uint32_t i = 0; i < steps_3; i++) {
                next_permutation(permutation_3 + HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2, permutation_3 + HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_3);
            }

	int lenToHash = 64;
	
	sph_blake512_init(&ctx_blake);
	sph_blake512 (&ctx_blake, input, len);
	sph_blake512_close(&ctx_blake, hash);
	
	for (int i = 1; i < HASH_FUNC_COUNT_1; i++) {
		switch (permutation_1[i]) {
                case 1:
                    // 3000 + 700
                    sph_echo512_init(&ctx_echo);
                    sph_echo512(&ctx_echo, hash, lenToHash );
                    sph_echo512_close(&ctx_echo, hash);

                    sph_blake512_init(&ctx_blake);
                    sph_blake512(&ctx_blake, hash, 64);
                    sph_blake512_close(&ctx_blake, hash);
                    break;
                case 2:
                    // 700 +3500
                    sph_simd512_init(&ctx_simd);
                    sph_simd512(&ctx_simd, hash, lenToHash);
                    sph_simd512_close(&ctx_simd, hash);

                    sph_bmw512_init(&ctx_bmw);
                    sph_bmw512(&ctx_bmw, hash, 64);
                    sph_bmw512_close(&ctx_bmw, hash);
                    break;
                case 3:
                    // 4000
                    sph_groestl512_init(&ctx_groestl);
                    sph_groestl512(&ctx_groestl, hash, lenToHash);
                    sph_groestl512_close(&ctx_groestl, hash);
                    break;
                case 4:
                    // 2000 + 2100
                    sph_whirlpool_init(&ctx_whirlpool);
                    sph_whirlpool(&ctx_whirlpool, hash, lenToHash);
                    sph_whirlpool_close(&ctx_whirlpool, hash);

                    sph_jh512_init(&ctx_jh);
                    sph_jh512(&ctx_jh, hash, 64);
                    sph_jh512_close(&ctx_jh, hash);
                    break;
                case 5:
                    // 1000 + 700
                    sph_gost512_init(&ctx_gost);
                    sph_gost512 (&ctx_gost, hash, lenToHash);;
                    sph_gost512_close(&ctx_gost, hash);

                    sph_keccak512_init(&ctx_keccak);
                    sph_keccak512(&ctx_keccak, hash, 64);
                    sph_keccak512_close(&ctx_keccak, hash);
                    break;
                case 6:
                    // 1000 + 4000
                    sph_fugue512_init(&ctx_fugue);
                    sph_fugue512(&ctx_fugue, hash, lenToHash);
                    sph_fugue512_close(&ctx_fugue, hash);

                    sph_skein512_init(&ctx_skein);
                    sph_skein512(&ctx_skein, hash, 64);
                    sph_skein512_close(&ctx_skein, hash);
                    break;
                case 7:
                    // 1800 + 2000
                    sph_shavite512_init(&ctx_shavite);
                    sph_shavite512(&ctx_shavite, hash, lenToHash);
                    sph_shavite512_close(&ctx_shavite, hash);

                    sph_luffa512_init(&ctx_luffa);
                    sph_luffa512(&ctx_luffa, hash, 64);
                    sph_luffa512_close(&ctx_luffa, hash);
                    break;
                }
            }
            	for (int i = HASH_FUNC_COUNT_1; i < HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2; i++) {
            	switch (permutation_2[i]) {
                case 8:
                    // 2100 +2000
                    sph_whirlpool_init(&ctx_whirlpool);
                    sph_whirlpool(&ctx_whirlpool, hash, lenToHash);
                    sph_whirlpool_close(&ctx_whirlpool, hash);

                    sph_cubehash512_init(&ctx_cubehash);
                    sph_cubehash512(&ctx_cubehash, hash, 64);
                    sph_cubehash512_close(&ctx_cubehash, hash);
                    break;
                case 9:
                    // 1800 + 2100
                    sph_jh512_init(&ctx_jh);
                    sph_jh512(&ctx_jh, hash, lenToHash);
                    sph_jh512_close(&ctx_jh, hash);

                    sph_shavite512_init(&ctx_shavite);
                    sph_shavite512(&ctx_shavite, hash, 64);
                    sph_shavite512_close(&ctx_shavite, hash);
                    break;
                case 10:
                    // 3500 + 700
                    sph_blake512_init(&ctx_blake);
                    sph_blake512(&ctx_blake, hash, lenToHash);
                    sph_blake512_close(&ctx_blake, hash);

                    sph_simd512_init(&ctx_simd);
                    sph_simd512(&ctx_simd, hash, 64);
                    sph_simd512_close(&ctx_simd, hash);
                    break;
                case 11:
                    // 3000 + 1000
                    sph_shabal512_init(&ctx_shabal);
                    sph_shabal512(&ctx_shabal, hash, lenToHash);
                    sph_shabal512_close(&ctx_shabal, hash);

                    sph_echo512_init(&ctx_echo);
                    sph_echo512(&ctx_echo, hash, 64);
                    sph_echo512_close(&ctx_echo, hash);
                    break;
                case 12:
                    // 5000
                    sph_hamsi512_init(&ctx_hamsi);
                    sph_hamsi512(&ctx_hamsi, hash, lenToHash);
                    sph_hamsi512_close(&ctx_hamsi, hash);
                    break;
                case 13:
                    // 4000 + 700
                    sph_bmw512_init(&ctx_bmw);
                    sph_bmw512(&ctx_bmw,  hash, lenToHash);
                    sph_bmw512_close(&ctx_bmw, hash);

                    sph_fugue512_init(&ctx_fugue);
                    sph_fugue512(&ctx_fugue, hash, 64);
                    sph_fugue512_close(&ctx_fugue, hash);
                    break;
                case 14:
                    // 1000 +1000
                    sph_keccak512_init(&ctx_keccak);
                    sph_keccak512(&ctx_keccak, hash, lenToHash);;
                    sph_keccak512_close(&ctx_keccak, hash);

                    sph_shabal512_init(&ctx_shabal);
                    sph_shabal512(&ctx_shabal, hash, 64);
                    sph_shabal512_close(&ctx_shabal, hash);
                    break;
                case 15:
                    // 2000 + 2000
                    sph_luffa512_init(&ctx_luffa);
                    sph_luffa512(&ctx_luffa,  hash, lenToHash);
                    sph_luffa512_close(&ctx_luffa, hash);

                    sph_whirlpool_init(&ctx_whirlpool);
                    sph_whirlpool(&ctx_whirlpool, hash, 64);
                    sph_whirlpool_close(&ctx_whirlpool, hash);
                    break;
                }
            }
            	for (int i = HASH_FUNC_COUNT_2; i < HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_3; i++) {
		switch (permutation_3[i]) {
                case 16:
                    // 700 + 2000
                    sph_sha512_init(&ctx_sha512);
                    sph_sha512(&ctx_sha512,  hash, lenToHash);
                    sph_sha512_close(&ctx_sha512, hash);

                    sph_haval256_5_init(&ctx_haval);
                    sph_haval256_5 (&ctx_haval, hash, 64);
                    sph_haval256_5_close(&ctx_haval, hash);
                    break;
                case 17:
                    // 4000 + 700
                    sph_skein512_init(&ctx_skein);
                    sph_skein512(&ctx_skein, hash, lenToHash);
                    sph_skein512_close(&ctx_skein, hash);

                    sph_groestl512_init(&ctx_groestl);
                    sph_groestl512(&ctx_groestl, hash, 64);
                    sph_groestl512_close(&ctx_groestl, hash);
                    break;
                case 18:
                    // 700 + 5000
                    sph_simd512_init(&ctx_simd);
                    sph_simd512(&ctx_simd, hash, lenToHash);
                    sph_simd512_close(&ctx_simd, hash);

                    sph_hamsi512_init(&ctx_hamsi);
                    sph_hamsi512(&ctx_hamsi, hash, 64);
                    sph_hamsi512_close(&ctx_hamsi, hash);
                    break;
                case 19:
                    // 1000 + 2000
                    sph_gost512_init(&ctx_gost);
                    sph_gost512 (&ctx_gost, hash, lenToHash);;
                    sph_gost512_close(&ctx_gost, hash);

                    sph_haval256_5_init(&ctx_haval);
                    sph_haval256_5 (&ctx_haval, hash, 64);
                    sph_haval256_5_close(&ctx_haval, hash);
                    break;
                case 20:
                    // 2100 + 700
                    sph_cubehash512_init(&ctx_cubehash);
                    sph_cubehash512(&ctx_cubehash, hash, lenToHash);
                    sph_cubehash512_close(&ctx_cubehash, hash);

                    sph_sha512_init(&ctx_sha512);
                    sph_sha512(&ctx_sha512, hash, 64);
                    sph_sha512_close(&ctx_sha512, hash);
                    break;
                case 21:
                    // 1800 + 3000
                    sph_echo512_init(&ctx_echo);
                    sph_echo512(&ctx_echo, hash, lenToHash);
                    sph_echo512_close(&ctx_echo, hash);

                    sph_shavite512_init(&ctx_shavite);
                    sph_shavite512(&ctx_shavite, hash, 64);
                    sph_shavite512_close(&ctx_shavite, hash);
                    break;
                case 22:
                    // 2000 + 1000
                    sph_luffa512_init(&ctx_luffa);
                    sph_luffa512(&ctx_luffa, hash, lenToHash);
                    sph_luffa512_close(&ctx_luffa, hash);

                    sph_shabal512_init(&ctx_shabal);
                    sph_shabal512(&ctx_shabal, hash, 64);
                    sph_shabal512_close(&ctx_shabal, hash);;
                    break;
                }

            }

	memcpy(output, hash, 32);
}

int scanhash_megabtx(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
        uint32_t _ALIGN(64) vhash[8];
        uint32_t _ALIGN(64) endiandata[20];
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

        const uint32_t Htarg = ptarget[7];
        const uint32_t first_nonce = pdata[19];
        uint32_t n = first_nonce;

        for (int k = 0; k < 19; k++)
                be32enc(&endiandata[k], pdata[k]);

        do {
                be32enc(&endiandata[19], n);
                megabtx_hash((char*) endiandata, (char*) vhash, 80);
                if (vhash[7] < Htarg && fulltest(vhash, ptarget)) {
                        work_set_target_ratio( work, vhash );
                        *hashes_done = n - first_nonce + 1;
                        pdata[19] = n;
                        return true;
                }
                n++;
        } while (n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;

        return 0;
}
