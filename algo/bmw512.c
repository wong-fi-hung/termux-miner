/**
* bmw512 algorithm implementation
* by maribun20@github
*/

#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sha3/sph_bmw.h"

void bmw512_hash(void *output, const void *input)
{
	uint32_t hash[32];
	sph_bmw512_context ctx;

	sph_bmw512_init(&ctx);
	sph_bmw512(&ctx, input, 80);
	sph_bmw512_close(&ctx, hash);

	memcpy(output, hash, 32);
}

int scanhash_bmw512(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash64[8];
	uint32_t _ALIGN(128) endiandata[32];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	};

	do {
		pdata[19] = ++n;
		be32enc(&endiandata[19], n);
		bmw512_hash(hash64, endiandata);
		if (((hash64[7]&0xFFFFFF00)==0) && fulltest(hash64, ptarget)) {
			work_set_target_ratio(work, hash64);
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return 1;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}
