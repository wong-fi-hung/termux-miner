/*
 * Copyright 2011 ArtForz, 2011-2014 pooler
 * 2018 The Resistance developers
 * 2020 The Sugarchain Yumekawa developers
 * 2020 - 2022 The termux-miner developers
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
 * This file is loosly based on a tiny portion of pooler's cpuminer scrypt.c.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/* ALGO LISTS */

void yespower_hash( const char *input, char *output, uint32_t len )
{
   {
        static const yespower_params_t v1 = {YESPOWER_1_0, 2048, 8, NULL, 0};
        yespower_tls( (yespower_binary_t*)input, len, &v1, (yespower_binary_t*)output );
        }
}

/* yespower default */

int scanhash_yespower(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	static const yespower_params_t params = {
		.version = YESPOWER_1_0,
		.N = 2048,
		.r = 32,
		.pers = NULL,
		.perslen = 0
	};

	uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
        const uint32_t Htarg = ptarget[7];
        const uint32_t first_nonce = pdata[19] - 1;
        uint32_t n = first_nonce;

	union {
		uint8_t u8[8];
		uint32_t u32[20];
	} data;
	union {
		yespower_binary_t yb;
		uint32_t u32[7];
	} hash;

	int i;

	for (i = 0; i < 19; i++)
		be32enc(&data.u32[i], pdata[i]);

	do {
		be32enc(&data.u32[19], ++n);

		if (yespower_tls(data.u8, 80, &params, &hash.yb))
			abort();

		if (le32dec(&hash.u32[7]) <= Htarg) {
			for (i = 0; i < 7; i++)
				hash.u32[i] = le32dec(&hash.u32[i]);
			if (Htarg && fulltest(hash.u32, ptarget)) {
				*hashes_done = n - pdata[19] + 1;
				pdata[19] = n;
				return 1;
			}
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - pdata[19] + 1;
	pdata[19] = n;
	return 0;
}

/* yespowerIC */

int scanhash_yespowerIC(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
        static const yespower_params_t params = {
                .version = YESPOWER_1_0,
                .N = 2048,
                .r = 32,
                .pers = (const uint8_t *)"IsotopeC",
                .perslen = 8
        };

        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
        const uint32_t Htarg = ptarget[7];
        const uint32_t first_nonce = pdata[19] - 1;
        uint32_t n = first_nonce;

        union {
                uint8_t u8[8];
                uint32_t u32[20];
        } data;
        union {
                yespower_binary_t yb;
                uint32_t u32[7];
        } hash;

        int i;

        for (i = 0; i < 19; i++)
                be32enc(&data.u32[i], pdata[i]);

        do {
                be32enc(&data.u32[19], ++n);

                if (yespower_tls(data.u8, 80, &params, &hash.yb))
                        abort();

                if (le32dec(&hash.u32[7]) <= Htarg) {
                        for (i = 0; i < 7; i++)
                                hash.u32[i] = le32dec(&hash.u32[i]);
                        if (Htarg && fulltest(hash.u32, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                pdata[19] = n;
                                return 1;
                        }
                }
        } while (n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}

/* yespowerIOTS */

int scanhash_yespowerIOTS(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
        static const yespower_params_t params = {
                .version = YESPOWER_1_0,
                .N = 2048,
                .r = 32,
                .pers = (const uint8_t *)"Iots is committed to the development of IOT",
                .perslen = 43
        };

        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
        const uint32_t Htarg = ptarget[7];
        const uint32_t first_nonce = pdata[19] - 1;
        uint32_t n = first_nonce;

        union {
                uint8_t u8[8];
                uint32_t u32[20];
        } data;
        union {
                yespower_binary_t yb;
                uint32_t u32[7];
        } hash;

        int i;

        for (i = 0; i < 19; i++)
                be32enc(&data.u32[i], pdata[i]);

        do {
                be32enc(&data.u32[19], ++n);

                if (yespower_tls(data.u8, 80, &params, &hash.yb))
                        abort();

                if (le32dec(&hash.u32[7]) <= Htarg) {
                        for (i = 0; i < 7; i++)
                                hash.u32[i] = le32dec(&hash.u32[i]);
                        if (Htarg && fulltest(hash.u32, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                pdata[19] = n;
                                return 1;
                        }
                }
        } while (n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}

/* yespowerITC*/

int scanhash_yespowerITC(int thr_id, struct work * work, uint32_t max_nonce, uint64_t *hashes_done)
{
        static const yespower_params_t params = {
                .version = YESPOWER_1_0,
                .N = 2048,
                .r = 32,
                .pers = (const uint8_t *)"InterITC",
                .perslen = 8
        };

        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
        const uint32_t Htarg = ptarget[7];
        const uint32_t first_nonce = pdata[19] - 1;
        uint32_t n = first_nonce;

        union {
                uint8_t u8[8];
                uint32_t u32[20];
        } data;
        union {
                yespower_binary_t yb;
                uint32_t u32[7];
        } hash;

        int i;

        for (i = 0; i < 19; i++)
                be32enc(&data.u32[i], pdata[i]);

        do {
                be32enc(&data.u32[19], ++n);

                if (yespower_tls(data.u8, 80, &params, &hash.yb))
                        abort();

                if (le32dec(&hash.u32[7]) <= Htarg) {
                        for (i = 0; i < 7; i++)
                                hash.u32[i] = le32dec(&hash.u32[i]);
                        if (Htarg && fulltest(hash.u32, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                pdata[19] = n;
                                return 1;
                        }
                }
        } while (n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}

/* yespowerLITB */

int scanhash_yespowerLITB(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
        static const yespower_params_t params = {
                .version = YESPOWER_1_0,
                .N = 2048,
                .r = 32,
                .pers = (const uint8_t *)"LITBpower: The number of LITB working or available for proof-of-work mining",
                .perslen = 73
        };

        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
        const uint32_t Htarg = ptarget[7];
        const uint32_t first_nonce = pdata[19] - 1;
        uint32_t n = first_nonce;

        union {
                uint8_t u8[8];
                uint32_t u32[20];
        } data;
        union {
                yespower_binary_t yb;
                uint32_t u32[7];
        } hash;

        int i;

        for (i = 0; i < 19; i++)
                be32enc(&data.u32[i], pdata[i]);

        do {
                be32enc(&data.u32[19], ++n);

                if (yespower_tls(data.u8, 80, &params, &hash.yb))
                        abort();

                if (le32dec(&hash.u32[7]) <= Htarg) {
                        for (i = 0; i < 7; i++)
                                hash.u32[i] = le32dec(&hash.u32[i]);
                        if (Htarg && fulltest(hash.u32, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                pdata[19] = n;
                                return 1;
                        }
                }
        } while (n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}

/* yespowerLNC */

int scanhash_yespowerLNC(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
        static const yespower_params_t params = {
                .version = YESPOWER_1_0,
                .N = 2048,
                .r = 32,
                .pers = "LTNCGYES",
                .perslen = 8
        };

        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
        const uint32_t Htarg = ptarget[7];
        const uint32_t first_nonce = pdata[19] - 1;
        uint32_t n = first_nonce;

        union {
                uint8_t u8[8];
                uint32_t u32[20];
        } data;
        union {
                yespower_binary_t yb;
                uint32_t u32[7];
        } hash;

        int i;

        for (i = 0; i < 19; i++)
                be32enc(&data.u32[i], pdata[i]);

        do {
                be32enc(&data.u32[19], ++n);

                if (yespower_tls(data.u8, 80, &params, &hash.yb))
                        abort();

                if (le32dec(&hash.u32[7]) <= Htarg) {
                        for (i = 0; i < 7; i++)
                                hash.u32[i] = le32dec(&hash.u32[i]);
                        if (Htarg && fulltest(hash.u32, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                pdata[19] = n;
                                return 1;
                        }
                }
        } while (n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}

/* yespowerMGPC */

enum YespowerParamsType {
        YESPOWER_PARAMS_MAGPIECOIN,
};

enum YespowerParamsType paramsType = YESPOWER_PARAMS_MAGPIECOIN;

 void yespowerMGPC_hash( const char *input, char *output, uint32_t len )
{


        static const yespower_params_t v1 = {YESPOWER_1_0, 2048, 8, NULL, 0};
        yespower_tls( (yespower_binary_t*)input, len, &v1, (yespower_binary_t*)output );

    static yespower_params_t params = {
        .version = YESPOWER_1_0,
        .N = 2048,
        .r = 32,
        .pers = "Magpies are birds of the Corvidae family.",
        .perslen = 41
    };

    switch (paramsType) {
        case YESPOWER_PARAMS_MAGPIECOIN:
            break;
         default:
            break;
    }
    yespower_tls( (yespower_binary_t*)input, len, &params, (yespower_binary_t*)output );
}

int scanhash_yespowerMGPC( int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done )
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
                yespowerMGPC_hash((char*) endiandata, (char*) vhash, 80);
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

/* yespowerR16 */

int scanhash_yespowerR16(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
        static const yespower_params_t params = {
                .version = YESPOWER_1_0,
                .N = 4096,
                .r = 16,
                .pers = NULL,
                .perslen = 0
        };

        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
        const uint32_t Htarg = ptarget[7];
        const uint32_t first_nonce = pdata[19] - 1;
        uint32_t n = first_nonce;

        union {
                uint8_t u8[8];
                uint32_t u32[20];
        } data;
        union {
                yespower_binary_t yb;
                uint32_t u32[7];
        } hash;

        int i;

        for (i = 0; i < 19; i++)
                be32enc(&data.u32[i], pdata[i]);

        do {
                be32enc(&data.u32[19], ++n);

                if (yespower_tls(data.u8, 80, &params, &hash.yb))
                        abort();

                if (le32dec(&hash.u32[7]) <= Htarg) {
                        for (i = 0; i < 7; i++)
                                hash.u32[i] = le32dec(&hash.u32[i]);
                        if (Htarg && fulltest(hash.u32, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                pdata[19] = n;
                                return 1;
                        }
                }
        } while (n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}

/* yespowerSUGAR */

int scanhash_yespowerSUGAR(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
        static const yespower_params_t params = {
                .version = YESPOWER_1_0,
                .N = 2048,
                .r = 32,
                .pers = (const uint8_t *)"Satoshi Nakamoto 31/Oct/2008 Proof-of-work is essentially one-CPU-one-vote",
                .perslen = 74
        };

        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
        const uint32_t Htarg = ptarget[7];
        const uint32_t first_nonce = pdata[19] - 1;
        uint32_t n = first_nonce;

        union {
                uint8_t u8[8];
                uint32_t u32[20];
        } data;
        union {
                yespower_binary_t yb;
                uint32_t u32[7];
        } hash;

        int i;

        for (i = 0; i < 19; i++)
                be32enc(&data.u32[i], pdata[i]);

        do {
                be32enc(&data.u32[19], ++n);

                if (yespower_tls(data.u8, 80, &params, &hash.yb))
                        abort();

                if (le32dec(&hash.u32[7]) <= Htarg) {
                        for (i = 0; i < 7; i++)
                                hash.u32[i] = le32dec(&hash.u32[i]);
                        if (Htarg && fulltest(hash.u32, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                pdata[19] = n;
                                return 1;
                        }
                }
        } while (n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}

/* yespowerTIDE */

int scanhash_yespowerTIDE(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done )
{
        static const yespower_params_t params = {
                .version = YESPOWER_1_0,
                .N = 2048,
                .r = 8,
                .pers = (const uint8_t *)"Tidecoin: Post Quantum Security.",
                .perslen = 32
        };

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
                yespower_hash((char*) endiandata, (char*) vhash, 80);
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

/* yespowerURX */

int scanhash_yespowerURX(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
        static const yespower_params_t params = {
                .version = YESPOWER_1_0,
                .N = 2048,
                .r = 32,
                .pers = (const uint8_t *)"UraniumX",
                .perslen = 8
        };

        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
        const uint32_t Htarg = ptarget[7];
        const uint32_t first_nonce = pdata[19] - 1;
        uint32_t n = first_nonce;

        union {
                uint8_t u8[8];
                uint32_t u32[20];
        } data;
        union {
                yespower_binary_t yb;
                uint32_t u32[7];
        } hash;

        int i;

        for (i = 0; i < 19; i++)
                be32enc(&data.u32[i], pdata[i]);

        do {
                be32enc(&data.u32[19], ++n);

                if (yespower_tls(data.u8, 80, &params, &hash.yb))
                        abort();

                if (le32dec(&hash.u32[7]) <= Htarg) {
                        for (i = 0; i < 7; i++)
                                hash.u32[i] = le32dec(&hash.u32[i]);
                        if (Htarg && fulltest(hash.u32, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                pdata[19] = n;
                                return 1;
                        }
                }
        } while (n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}
