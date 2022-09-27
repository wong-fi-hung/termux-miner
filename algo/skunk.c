#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_skein.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_fugue.h"
#include "sha3/gost_streebog.h"

void skunk_hash(const char *input, char* output, uint32_t len)
{
        uint32_t _ALIGN(64) hash[16];

        sph_skein512_context ctx_skein;
        sph_cubehash512_context ctx_cube;
        sph_fugue512_context ctx_fugue;
        sph_gost512_context ctx_gost;

        sph_skein512_init(&ctx_skein);
        sph_skein512(&ctx_skein, input, 80);
        sph_skein512_close(&ctx_skein, (void*) hash);

        sph_cubehash512_init(&ctx_cube);
        sph_cubehash512(&ctx_cube, hash, 64);
        sph_cubehash512_close(&ctx_cube, hash);

        sph_fugue512_init (&ctx_fugue);
        sph_fugue512(&ctx_fugue, hash, 64);
        sph_fugue512_close(&ctx_fugue, hash);

        sph_gost512_init(&ctx_gost);
        sph_gost512(&ctx_gost, (const void*) hash, 64);
        sph_gost512_close(&ctx_gost, (void*) hash);

        memcpy(output, hash, 32);
}

int scanhash_skunk(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
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
                skunk_hash((char*) endiandata, (char*) vhash, 80);
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
