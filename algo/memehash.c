#include "miner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_sha2.h"

void meme_hash(const char* input, char* output, uint32_t len)
{
	sph_blake512_context     ctx_blake;
	sph_cubehash512_context  ctx_cubehash1;
	sph_shavite512_context   ctx_shavite1;
	sph_simd512_context      ctx_simd1;
	sph_echo512_context      ctx_echo1;
    sph_sha256_context       ctx_sha;

    uint32_t hash[16];
    uint32_t hashA[16];

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, len);
    sph_blake512_close (&ctx_blake, hash);
	
    sph_simd512_init (&ctx_simd1);
    sph_simd512 (&ctx_simd1, hash, 64);
    sph_simd512_close(&ctx_simd1, hash);

    sph_echo512_init (&ctx_echo1);
    sph_echo512 (&ctx_echo1, hash, 64);
    sph_echo512_close(&ctx_echo1, hash);

    sph_cubehash512_init (&ctx_cubehash1);
    sph_cubehash512 (&ctx_cubehash1, hash, 64);
    sph_cubehash512_close(&ctx_cubehash1, hash);

    sph_shavite512_init (&ctx_shavite1);
    sph_shavite512 (&ctx_shavite1, hash, 64);
    sph_shavite512_close(&ctx_shavite1, hash);

    sph_sha256_init(&ctx_sha);
    sph_sha256 (&ctx_sha, hash, 64);
    sph_sha256_close(&ctx_sha, hashA);

    for (int i=8;i<16;i++)
        hashA[i]=0;
	
    sph_sha256_init(&ctx_sha);
    sph_sha256 (&ctx_sha, hashA, 64);
    sph_sha256_close(&ctx_sha, hashA);

    for (int i=8;i<16;i++)
        hashA[i]=0;	

    sph_sha256_init(&ctx_sha);
    sph_sha256 (&ctx_sha, hashA, 64);
    sph_sha256_close(&ctx_sha, hash);	

    memcpy(output, hash, 32);
}

int scanhash_meme(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
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
                meme_hash((char*) endiandata, (char*) vhash, 80);
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
