#include "chacha20.h"
#if (defined(_M_X64) || defined(__x86_64__)) && defined(__SSE2__)
#include <immintrin.h>
#include <memory.h>

static inline void PartialXor(const __m128i val, uint8_t *Src, uint8_t *Dest, uint64_t Size)
{
	_Alignas(16) uint8_t BuffForPartialOp[16];
	memcpy(BuffForPartialOp, Src, Size);
	_mm_storeu_si128((__m128i *)(BuffForPartialOp), _mm_xor_si128(val, _mm_loadu_si128((const __m128i *)BuffForPartialOp)));
	memcpy(Dest, BuffForPartialOp, Size);
}
static inline void PartialStore(const __m128i val, uint8_t *Dest, uint64_t Size)
{
	_Alignas(16) uint8_t BuffForPartialOp[16];
	_mm_storeu_si128((__m128i *)(BuffForPartialOp), val);
	memcpy(Dest, BuffForPartialOp, Size);
}

static inline __m128i RotateLeft7(const __m128i val)
{
	return _mm_or_si128(_mm_slli_epi32(val, 7), _mm_srli_epi32(val, 32 - 7));
}

static inline __m128i RotateLeft8(const __m128i val)
{
	return _mm_or_si128(_mm_slli_epi32(val, 8), _mm_srli_epi32(val, 32 - 8));
}

static inline __m128i RotateLeft12(const __m128i val)
{
	return _mm_or_si128(_mm_slli_epi32(val, 12), _mm_srli_epi32(val, 32 - 12));
}

static inline __m128i RotateLeft16(const __m128i val)
{
	return _mm_or_si128(_mm_slli_epi32(val, 16), _mm_srli_epi32(val, 32 - 16));
}

static void ChaCha20EncryptBytes(uint8_t *state, uint8_t *In, uint8_t *Out, size_t Size, uint32_t rounds)
{

	uint8_t *CurrentIn = In;
	uint8_t *CurrentOut = Out;

	uint64_t FullBlocksCount = Size / 256;
	uint64_t RemainingBytes = Size % 256;

	const __m128i state0 = _mm_set_epi32(1797285236, 2036477234, 857760878, 1634760805); //"expand 32-byte k"
	const __m128i state1 = _mm_loadu_si128((const __m128i *)(state));
	const __m128i state2 = _mm_loadu_si128((const __m128i *)((state) + 16));

	for (int64_t n = 0; n < FullBlocksCount; n++)
	{

		const __m128i state3 = _mm_loadu_si128((const __m128i *)((state) + 32));

		__m128i r0_0 = state0;
		__m128i r0_1 = state1;
		__m128i r0_2 = state2;
		__m128i r0_3 = state3;

		__m128i r1_0 = state0;
		__m128i r1_1 = state1;
		__m128i r1_2 = state2;
		__m128i r1_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 1));

		__m128i r2_0 = state0;
		__m128i r2_1 = state1;
		__m128i r2_2 = state2;
		__m128i r2_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 2));

		__m128i r3_0 = state0;
		__m128i r3_1 = state1;
		__m128i r3_2 = state2;
		__m128i r3_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 3));

		for (int i = rounds; i > 0; i -= 2)
		{
			r0_0 = _mm_add_epi32(r0_0, r0_1);
			r1_0 = _mm_add_epi32(r1_0, r1_1);
			r2_0 = _mm_add_epi32(r2_0, r2_1);
			r3_0 = _mm_add_epi32(r3_0, r3_1);

			r0_3 = _mm_xor_si128(r0_3, r0_0);
			r1_3 = _mm_xor_si128(r1_3, r1_0);
			r2_3 = _mm_xor_si128(r2_3, r2_0);
			r3_3 = _mm_xor_si128(r3_3, r3_0);

			r0_3 = RotateLeft16(r0_3);
			r1_3 = RotateLeft16(r1_3);
			r2_3 = RotateLeft16(r2_3);
			r3_3 = RotateLeft16(r3_3);

			r0_2 = _mm_add_epi32(r0_2, r0_3);
			r1_2 = _mm_add_epi32(r1_2, r1_3);
			r2_2 = _mm_add_epi32(r2_2, r2_3);
			r3_2 = _mm_add_epi32(r3_2, r3_3);

			r0_1 = _mm_xor_si128(r0_1, r0_2);
			r1_1 = _mm_xor_si128(r1_1, r1_2);
			r2_1 = _mm_xor_si128(r2_1, r2_2);
			r3_1 = _mm_xor_si128(r3_1, r3_2);

			r0_1 = RotateLeft12(r0_1);
			r1_1 = RotateLeft12(r1_1);
			r2_1 = RotateLeft12(r2_1);
			r3_1 = RotateLeft12(r3_1);

			r0_0 = _mm_add_epi32(r0_0, r0_1);
			r1_0 = _mm_add_epi32(r1_0, r1_1);
			r2_0 = _mm_add_epi32(r2_0, r2_1);
			r3_0 = _mm_add_epi32(r3_0, r3_1);

			r0_3 = _mm_xor_si128(r0_3, r0_0);
			r1_3 = _mm_xor_si128(r1_3, r1_0);
			r2_3 = _mm_xor_si128(r2_3, r2_0);
			r3_3 = _mm_xor_si128(r3_3, r3_0);

			r0_3 = RotateLeft8(r0_3);
			r1_3 = RotateLeft8(r1_3);
			r2_3 = RotateLeft8(r2_3);
			r3_3 = RotateLeft8(r3_3);

			r0_2 = _mm_add_epi32(r0_2, r0_3);
			r1_2 = _mm_add_epi32(r1_2, r1_3);
			r2_2 = _mm_add_epi32(r2_2, r2_3);
			r3_2 = _mm_add_epi32(r3_2, r3_3);

			r0_1 = _mm_xor_si128(r0_1, r0_2);
			r1_1 = _mm_xor_si128(r1_1, r1_2);
			r2_1 = _mm_xor_si128(r2_1, r2_2);
			r3_1 = _mm_xor_si128(r3_1, r3_2);

			r0_1 = RotateLeft7(r0_1);
			r1_1 = RotateLeft7(r1_1);
			r2_1 = RotateLeft7(r2_1);
			r3_1 = RotateLeft7(r3_1);

			r0_1 = _mm_shuffle_epi32(r0_1, _MM_SHUFFLE(0, 3, 2, 1));
			r0_2 = _mm_shuffle_epi32(r0_2, _MM_SHUFFLE(1, 0, 3, 2));
			r0_3 = _mm_shuffle_epi32(r0_3, _MM_SHUFFLE(2, 1, 0, 3));

			r1_1 = _mm_shuffle_epi32(r1_1, _MM_SHUFFLE(0, 3, 2, 1));
			r1_2 = _mm_shuffle_epi32(r1_2, _MM_SHUFFLE(1, 0, 3, 2));
			r1_3 = _mm_shuffle_epi32(r1_3, _MM_SHUFFLE(2, 1, 0, 3));

			r2_1 = _mm_shuffle_epi32(r2_1, _MM_SHUFFLE(0, 3, 2, 1));
			r2_2 = _mm_shuffle_epi32(r2_2, _MM_SHUFFLE(1, 0, 3, 2));
			r2_3 = _mm_shuffle_epi32(r2_3, _MM_SHUFFLE(2, 1, 0, 3));

			r3_1 = _mm_shuffle_epi32(r3_1, _MM_SHUFFLE(0, 3, 2, 1));
			r3_2 = _mm_shuffle_epi32(r3_2, _MM_SHUFFLE(1, 0, 3, 2));
			r3_3 = _mm_shuffle_epi32(r3_3, _MM_SHUFFLE(2, 1, 0, 3));

			r0_0 = _mm_add_epi32(r0_0, r0_1);
			r1_0 = _mm_add_epi32(r1_0, r1_1);
			r2_0 = _mm_add_epi32(r2_0, r2_1);
			r3_0 = _mm_add_epi32(r3_0, r3_1);

			r0_3 = _mm_xor_si128(r0_3, r0_0);
			r1_3 = _mm_xor_si128(r1_3, r1_0);
			r2_3 = _mm_xor_si128(r2_3, r2_0);
			r3_3 = _mm_xor_si128(r3_3, r3_0);

			r0_3 = RotateLeft16(r0_3);
			r1_3 = RotateLeft16(r1_3);
			r2_3 = RotateLeft16(r2_3);
			r3_3 = RotateLeft16(r3_3);

			r0_2 = _mm_add_epi32(r0_2, r0_3);
			r1_2 = _mm_add_epi32(r1_2, r1_3);
			r2_2 = _mm_add_epi32(r2_2, r2_3);
			r3_2 = _mm_add_epi32(r3_2, r3_3);

			r0_1 = _mm_xor_si128(r0_1, r0_2);
			r1_1 = _mm_xor_si128(r1_1, r1_2);
			r2_1 = _mm_xor_si128(r2_1, r2_2);
			r3_1 = _mm_xor_si128(r3_1, r3_2);

			r0_1 = RotateLeft12(r0_1);
			r1_1 = RotateLeft12(r1_1);
			r2_1 = RotateLeft12(r2_1);
			r3_1 = RotateLeft12(r3_1);

			r0_0 = _mm_add_epi32(r0_0, r0_1);
			r1_0 = _mm_add_epi32(r1_0, r1_1);
			r2_0 = _mm_add_epi32(r2_0, r2_1);
			r3_0 = _mm_add_epi32(r3_0, r3_1);

			r0_3 = _mm_xor_si128(r0_3, r0_0);
			r1_3 = _mm_xor_si128(r1_3, r1_0);
			r2_3 = _mm_xor_si128(r2_3, r2_0);
			r3_3 = _mm_xor_si128(r3_3, r3_0);

			r0_3 = RotateLeft8(r0_3);
			r1_3 = RotateLeft8(r1_3);
			r2_3 = RotateLeft8(r2_3);
			r3_3 = RotateLeft8(r3_3);

			r0_2 = _mm_add_epi32(r0_2, r0_3);
			r1_2 = _mm_add_epi32(r1_2, r1_3);
			r2_2 = _mm_add_epi32(r2_2, r2_3);
			r3_2 = _mm_add_epi32(r3_2, r3_3);

			r0_1 = _mm_xor_si128(r0_1, r0_2);
			r1_1 = _mm_xor_si128(r1_1, r1_2);
			r2_1 = _mm_xor_si128(r2_1, r2_2);
			r3_1 = _mm_xor_si128(r3_1, r3_2);

			r0_1 = RotateLeft7(r0_1);
			r1_1 = RotateLeft7(r1_1);
			r2_1 = RotateLeft7(r2_1);
			r3_1 = RotateLeft7(r3_1);

			r0_1 = _mm_shuffle_epi32(r0_1, _MM_SHUFFLE(2, 1, 0, 3));
			r0_2 = _mm_shuffle_epi32(r0_2, _MM_SHUFFLE(1, 0, 3, 2));
			r0_3 = _mm_shuffle_epi32(r0_3, _MM_SHUFFLE(0, 3, 2, 1));

			r1_1 = _mm_shuffle_epi32(r1_1, _MM_SHUFFLE(2, 1, 0, 3));
			r1_2 = _mm_shuffle_epi32(r1_2, _MM_SHUFFLE(1, 0, 3, 2));
			r1_3 = _mm_shuffle_epi32(r1_3, _MM_SHUFFLE(0, 3, 2, 1));

			r2_1 = _mm_shuffle_epi32(r2_1, _MM_SHUFFLE(2, 1, 0, 3));
			r2_2 = _mm_shuffle_epi32(r2_2, _MM_SHUFFLE(1, 0, 3, 2));
			r2_3 = _mm_shuffle_epi32(r2_3, _MM_SHUFFLE(0, 3, 2, 1));

			r3_1 = _mm_shuffle_epi32(r3_1, _MM_SHUFFLE(2, 1, 0, 3));
			r3_2 = _mm_shuffle_epi32(r3_2, _MM_SHUFFLE(1, 0, 3, 2));
			r3_3 = _mm_shuffle_epi32(r3_3, _MM_SHUFFLE(0, 3, 2, 1));
		}

		r0_0 = _mm_add_epi32(r0_0, state0);
		r0_1 = _mm_add_epi32(r0_1, state1);
		r0_2 = _mm_add_epi32(r0_2, state2);
		r0_3 = _mm_add_epi32(r0_3, state3);

		r1_0 = _mm_add_epi32(r1_0, state0);
		r1_1 = _mm_add_epi32(r1_1, state1);
		r1_2 = _mm_add_epi32(r1_2, state2);
		r1_3 = _mm_add_epi32(r1_3, state3);
		r1_3 = _mm_add_epi64(r1_3, _mm_set_epi32(0, 0, 0, 1));

		r2_0 = _mm_add_epi32(r2_0, state0);
		r2_1 = _mm_add_epi32(r2_1, state1);
		r2_2 = _mm_add_epi32(r2_2, state2);
		r2_3 = _mm_add_epi32(r2_3, state3);
		r2_3 = _mm_add_epi64(r2_3, _mm_set_epi32(0, 0, 0, 2));

		r3_0 = _mm_add_epi32(r3_0, state0);
		r3_1 = _mm_add_epi32(r3_1, state1);
		r3_2 = _mm_add_epi32(r3_2, state2);
		r3_3 = _mm_add_epi32(r3_3, state3);
		r3_3 = _mm_add_epi64(r3_3, _mm_set_epi32(0, 0, 0, 3));

		if (In)
		{
			_mm_storeu_si128((__m128i *)(CurrentOut + 0 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 0 * 16)), r0_0));
			_mm_storeu_si128((__m128i *)(CurrentOut + 1 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 1 * 16)), r0_1));
			_mm_storeu_si128((__m128i *)(CurrentOut + 2 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 2 * 16)), r0_2));
			_mm_storeu_si128((__m128i *)(CurrentOut + 3 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 3 * 16)), r0_3));

			_mm_storeu_si128((__m128i *)(CurrentOut + 4 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 4 * 16)), r1_0));
			_mm_storeu_si128((__m128i *)(CurrentOut + 5 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 5 * 16)), r1_1));
			_mm_storeu_si128((__m128i *)(CurrentOut + 6 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 6 * 16)), r1_2));
			_mm_storeu_si128((__m128i *)(CurrentOut + 7 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 7 * 16)), r1_3));

			_mm_storeu_si128((__m128i *)(CurrentOut + 8 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 8 * 16)), r2_0));
			_mm_storeu_si128((__m128i *)(CurrentOut + 9 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 9 * 16)), r2_1));
			_mm_storeu_si128((__m128i *)(CurrentOut + 10 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 10 * 16)), r2_2));
			_mm_storeu_si128((__m128i *)(CurrentOut + 11 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 11 * 16)), r2_3));

			_mm_storeu_si128((__m128i *)(CurrentOut + 12 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 12 * 16)), r3_0));
			_mm_storeu_si128((__m128i *)(CurrentOut + 13 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 13 * 16)), r3_1));
			_mm_storeu_si128((__m128i *)(CurrentOut + 14 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 14 * 16)), r3_2));
			_mm_storeu_si128((__m128i *)(CurrentOut + 15 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 15 * 16)), r3_3));
			CurrentIn += 256;
		}
		else
		{
			_mm_storeu_si128((__m128i *)(CurrentOut + 0 * 16), r0_0);
			_mm_storeu_si128((__m128i *)(CurrentOut + 1 * 16), r0_1);
			_mm_storeu_si128((__m128i *)(CurrentOut + 2 * 16), r0_2);
			_mm_storeu_si128((__m128i *)(CurrentOut + 3 * 16), r0_3);

			_mm_storeu_si128((__m128i *)(CurrentOut + 4 * 16), r1_0);
			_mm_storeu_si128((__m128i *)(CurrentOut + 5 * 16), r1_1);
			_mm_storeu_si128((__m128i *)(CurrentOut + 6 * 16), r1_2);
			_mm_storeu_si128((__m128i *)(CurrentOut + 7 * 16), r1_3);

			_mm_storeu_si128((__m128i *)(CurrentOut + 8 * 16), r2_0);
			_mm_storeu_si128((__m128i *)(CurrentOut + 9 * 16), r2_1);
			_mm_storeu_si128((__m128i *)(CurrentOut + 10 * 16), r2_2);
			_mm_storeu_si128((__m128i *)(CurrentOut + 11 * 16), r2_3);

			_mm_storeu_si128((__m128i *)(CurrentOut + 12 * 16), r3_0);
			_mm_storeu_si128((__m128i *)(CurrentOut + 13 * 16), r3_1);
			_mm_storeu_si128((__m128i *)(CurrentOut + 14 * 16), r3_2);
			_mm_storeu_si128((__m128i *)(CurrentOut + 15 * 16), r3_3);
		}

		CurrentOut += 256;

		ChaCha20AddCounter(state, 4);
	}

	if (RemainingBytes == 0)
		return;

	while (1)
	{
		const __m128i state3 = _mm_loadu_si128((const __m128i *)((state) + 32));

		__m128i r0_0 = state0;
		__m128i r0_1 = state1;
		__m128i r0_2 = state2;
		__m128i r0_3 = state3;

		for (int i = rounds; i > 0; i -= 2)
		{
			r0_0 = _mm_add_epi32(r0_0, r0_1);

			r0_3 = _mm_xor_si128(r0_3, r0_0);

			r0_3 = RotateLeft16(r0_3);

			r0_2 = _mm_add_epi32(r0_2, r0_3);

			r0_1 = _mm_xor_si128(r0_1, r0_2);

			r0_1 = RotateLeft12(r0_1);

			r0_0 = _mm_add_epi32(r0_0, r0_1);

			r0_3 = _mm_xor_si128(r0_3, r0_0);

			r0_3 = RotateLeft8(r0_3);

			r0_2 = _mm_add_epi32(r0_2, r0_3);

			r0_1 = _mm_xor_si128(r0_1, r0_2);

			r0_1 = RotateLeft7(r0_1);

			r0_1 = _mm_shuffle_epi32(r0_1, _MM_SHUFFLE(0, 3, 2, 1));
			r0_2 = _mm_shuffle_epi32(r0_2, _MM_SHUFFLE(1, 0, 3, 2));
			r0_3 = _mm_shuffle_epi32(r0_3, _MM_SHUFFLE(2, 1, 0, 3));

			r0_0 = _mm_add_epi32(r0_0, r0_1);

			r0_3 = _mm_xor_si128(r0_3, r0_0);

			r0_3 = RotateLeft16(r0_3);

			r0_2 = _mm_add_epi32(r0_2, r0_3);

			r0_1 = _mm_xor_si128(r0_1, r0_2);

			r0_1 = RotateLeft12(r0_1);

			r0_0 = _mm_add_epi32(r0_0, r0_1);

			r0_3 = _mm_xor_si128(r0_3, r0_0);

			r0_3 = RotateLeft8(r0_3);

			r0_2 = _mm_add_epi32(r0_2, r0_3);

			r0_1 = _mm_xor_si128(r0_1, r0_2);

			r0_1 = RotateLeft7(r0_1);

			r0_1 = _mm_shuffle_epi32(r0_1, _MM_SHUFFLE(2, 1, 0, 3));
			r0_2 = _mm_shuffle_epi32(r0_2, _MM_SHUFFLE(1, 0, 3, 2));
			r0_3 = _mm_shuffle_epi32(r0_3, _MM_SHUFFLE(0, 3, 2, 1));
		}

		r0_0 = _mm_add_epi32(r0_0, state0);
		r0_1 = _mm_add_epi32(r0_1, state1);
		r0_2 = _mm_add_epi32(r0_2, state2);
		r0_3 = _mm_add_epi32(r0_3, state3);

		if (RemainingBytes >= 64)
		{

			if (In)
			{
				_mm_storeu_si128((__m128i *)(CurrentOut + 0 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 0 * 16)), r0_0));
				_mm_storeu_si128((__m128i *)(CurrentOut + 1 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 1 * 16)), r0_1));
				_mm_storeu_si128((__m128i *)(CurrentOut + 2 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 2 * 16)), r0_2));
				_mm_storeu_si128((__m128i *)(CurrentOut + 3 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(CurrentIn + 3 * 16)), r0_3));
				CurrentIn += 64;
			}
			else
			{
				_mm_storeu_si128((__m128i *)(CurrentOut + 0 * 16), r0_0);
				_mm_storeu_si128((__m128i *)(CurrentOut + 1 * 16), r0_1);
				_mm_storeu_si128((__m128i *)(CurrentOut + 2 * 16), r0_2);
				_mm_storeu_si128((__m128i *)(CurrentOut + 3 * 16), r0_3);
			}
			CurrentOut += 64;
			ChaCha20AddCounter(state, 1);
			RemainingBytes -= 64;
			if (RemainingBytes == 0)
				return;
			continue;
		}
		else
		{
			_Alignas(16) uint8_t TmpBuf[64];
			if (In)
			{
				memcpy(TmpBuf, CurrentIn, RemainingBytes);
				_mm_storeu_si128((__m128i *)(TmpBuf + 0 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(TmpBuf + 0 * 16)), r0_0));
				_mm_storeu_si128((__m128i *)(TmpBuf + 1 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(TmpBuf + 1 * 16)), r0_1));
				_mm_storeu_si128((__m128i *)(TmpBuf + 2 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(TmpBuf + 2 * 16)), r0_2));
				_mm_storeu_si128((__m128i *)(TmpBuf + 3 * 16), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(TmpBuf + 3 * 16)), r0_3));
			}
			else
			{
				_mm_storeu_si128((__m128i *)(TmpBuf + 0 * 16), r0_0);
				_mm_storeu_si128((__m128i *)(TmpBuf + 1 * 16), r0_1);
				_mm_storeu_si128((__m128i *)(TmpBuf + 2 * 16), r0_2);
				_mm_storeu_si128((__m128i *)(TmpBuf + 3 * 16), r0_3);
			}
			memcpy(CurrentOut, TmpBuf, RemainingBytes);
			ChaCha20AddCounter(state, 1);
			return;
		}
	}
}

void chacha_encrypt_sse2(uint8_t *key, uint8_t *nonce, uint8_t *in, uint8_t *out, size_t bytes, uint32_t rounds)
{
	uint8_t state[48] = {0};
	ChaCha20SetKey(state, key);
	ChaCha20SetNonce(state, nonce);
	ChaCha20EncryptBytes(state, in, out, bytes, rounds);
}
#endif
