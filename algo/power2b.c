#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1-power2b/yespower-p2b.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

void power2b_hash( const char *input, char *output, uint32_t len )
{
    static const yespower_params_t v1 = {YESPOWER_1_0, 2048, 8, NULL, 0};
    yespower_tls_p2b( (yespower_binary_t_p2b*)input, len, &v1, (yespower_binary_t_p2b*)output );
    static yespower_params_t params = {
        .version = YESPOWER_1_0_BLAKE2B,
        .N = 2048,
        .r = 32,
        .pers = (const uint8_t *)"Now I am become Death, the destroyer of worlds",
        .perslen = 46
    };
    yespower_tls_p2b( (yespower_binary_t_p2b*)input, len, &params, (yespower_binary_t_p2b*)output );
}

int scanhash_power2b( int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done )
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
                power2b_hash((char*) endiandata, (char*) vhash, 80);
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
