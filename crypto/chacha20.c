#include "chacha20.h"
#include <memory.h>

static const int32_t KeyDataSize = 48;
static const int32_t rounds = 20;

static const uint32_t ConstState[4] = {1634760805, 857760878, 2036477234, 1797285236}; //"expand 32-byte k";;

void ChaCha20SetKey(uint8_t *state, const uint8_t *Key)
{
	memcpy(state, Key, 32);
}

void ChaCha20SetNonce(uint8_t *state, const uint8_t *Nonce)
{
	memcpy(state + 36, Nonce, 12);
}

void ChaCha20SetCtr(uint8_t *state, const uint8_t *Ctr)
{
	memcpy(state + 32, Ctr, 4);
}

void ChaCha20IncrementNonce(uint8_t *state)
{
	uint32_t *State32bits = (uint32_t *)state;
	State32bits[8] = 0; // reset counter
	++State32bits[9];
	if (State32bits[9] == 0)
	{
		++State32bits[10];
		if (State32bits[10] == 0)
			++State32bits[11];
	}
}

void ChaCha20AddCounter(uint8_t *ChaCha, const uint32_t value_to_add)
{
	uint32_t *State32bits = (uint32_t *)ChaCha;
	State32bits[8] += value_to_add;
}
void ChaCha20EncryptBytes(uint8_t *state, uint8_t *In, uint8_t *Out, size_t Size, uint32_t rounds)
{

	// portable chacha, no simd
	uint8_t *CurrentIn = In;
	uint8_t *CurrentOut = Out;
	uint64_t RemainingBytes = Size;
	uint32_t *state_dwords = (uint32_t *)state;
	uint32_t b[16];
	while (1)
	{
		b[0] = ConstState[0];
		b[1] = ConstState[1];
		b[2] = ConstState[2];
		b[3] = ConstState[3];
		memcpy(((uint8_t *)b) + 16, state, 48);

		for (int i = rounds; i > 0; i -= 2)
		{
			b[0] = b[0] + b[4];
			b[12] = (b[12] ^ b[0]) << 16 | (b[12] ^ b[0]) >> 16;
			b[8] = b[8] + b[12];
			b[4] = (b[4] ^ b[8]) << 12 | (b[4] ^ b[8]) >> 20;
			b[0] = b[0] + b[4];
			b[12] = (b[12] ^ b[0]) << 8 | (b[12] ^ b[0]) >> 24;
			b[8] = b[8] + b[12];
			b[4] = (b[4] ^ b[8]) << 7 | (b[4] ^ b[8]) >> 25;
			b[1] = b[1] + b[5];
			b[13] = (b[13] ^ b[1]) << 16 | (b[13] ^ b[1]) >> 16;
			b[9] = b[9] + b[13];
			b[5] = (b[5] ^ b[9]) << 12 | (b[5] ^ b[9]) >> 20;
			b[1] = b[1] + b[5];
			b[13] = (b[13] ^ b[1]) << 8 | (b[13] ^ b[1]) >> 24;
			b[9] = b[9] + b[13];
			b[5] = (b[5] ^ b[9]) << 7 | (b[5] ^ b[9]) >> 25;
			b[2] = b[2] + b[6];
			b[14] = (b[14] ^ b[2]) << 16 | (b[14] ^ b[2]) >> 16;
			b[10] = b[10] + b[14];
			b[6] = (b[6] ^ b[10]) << 12 | (b[6] ^ b[10]) >> 20;
			b[2] = b[2] + b[6];
			b[14] = (b[14] ^ b[2]) << 8 | (b[14] ^ b[2]) >> 24;
			b[10] = b[10] + b[14];
			b[6] = (b[6] ^ b[10]) << 7 | (b[6] ^ b[10]) >> 25;
			b[3] = b[3] + b[7];
			b[15] = (b[15] ^ b[3]) << 16 | (b[15] ^ b[3]) >> 16;
			b[11] = b[11] + b[15];
			b[7] = (b[7] ^ b[11]) << 12 | (b[7] ^ b[11]) >> 20;
			b[3] = b[3] + b[7];
			b[15] = (b[15] ^ b[3]) << 8 | (b[15] ^ b[3]) >> 24;
			b[11] = b[11] + b[15];
			b[7] = (b[7] ^ b[11]) << 7 | (b[7] ^ b[11]) >> 25;
			b[0] = b[0] + b[5];
			b[15] = (b[15] ^ b[0]) << 16 | (b[15] ^ b[0]) >> 16;
			b[10] = b[10] + b[15];
			b[5] = (b[5] ^ b[10]) << 12 | (b[5] ^ b[10]) >> 20;
			b[0] = b[0] + b[5];
			b[15] = (b[15] ^ b[0]) << 8 | (b[15] ^ b[0]) >> 24;
			b[10] = b[10] + b[15];
			b[5] = (b[5] ^ b[10]) << 7 | (b[5] ^ b[10]) >> 25;
			b[1] = b[1] + b[6];
			b[12] = (b[12] ^ b[1]) << 16 | (b[12] ^ b[1]) >> 16;
			b[11] = b[11] + b[12];
			b[6] = (b[6] ^ b[11]) << 12 | (b[6] ^ b[11]) >> 20;
			b[1] = b[1] + b[6];
			b[12] = (b[12] ^ b[1]) << 8 | (b[12] ^ b[1]) >> 24;
			b[11] = b[11] + b[12];
			b[6] = (b[6] ^ b[11]) << 7 | (b[6] ^ b[11]) >> 25;
			b[2] = b[2] + b[7];
			b[13] = (b[13] ^ b[2]) << 16 | (b[13] ^ b[2]) >> 16;
			b[8] = b[8] + b[13];
			b[7] = (b[7] ^ b[8]) << 12 | (b[7] ^ b[8]) >> 20;
			b[2] = b[2] + b[7];
			b[13] = (b[13] ^ b[2]) << 8 | (b[13] ^ b[2]) >> 24;
			b[8] = b[8] + b[13];
			b[7] = (b[7] ^ b[8]) << 7 | (b[7] ^ b[8]) >> 25;
			b[3] = b[3] + b[4];
			b[14] = (b[14] ^ b[3]) << 16 | (b[14] ^ b[3]) >> 16;
			b[9] = b[9] + b[14];
			b[4] = (b[4] ^ b[9]) << 12 | (b[4] ^ b[9]) >> 20;
			b[3] = b[3] + b[4];
			b[14] = (b[14] ^ b[3]) << 8 | (b[14] ^ b[3]) >> 24;
			b[9] = b[9] + b[14];
			b[4] = (b[4] ^ b[9]) << 7 | (b[4] ^ b[9]) >> 25;
		}

		for (uint32_t i = 0; i < 4; ++i)
		{
			b[i] += ConstState[i];
		}
		for (uint32_t i = 0; i < 12; ++i)
		{
			b[i + 4] += state_dwords[i];
		}

		++state_dwords[8]; // counter

		if (RemainingBytes >= 64)
		{
			if (In)
			{
				uint32_t *In32bits = (uint32_t *)CurrentIn;
				uint32_t *Out32bits = (uint32_t *)CurrentOut;
				for (uint32_t i = 0; i < 16; i++)
				{
					Out32bits[i] = In32bits[i] ^ b[i];
				}
			}
			else
				memcpy(CurrentOut, b, 64);

			if (In)
				CurrentIn += 64;
			CurrentOut += 64;
			RemainingBytes -= 64;
			if (RemainingBytes == 0)
				return;
			continue;
		}
		else
		{
			if (In)
			{
				for (int32_t i = 0; i < RemainingBytes; i++)
					CurrentOut[i] = CurrentIn[i] ^ ((uint8_t *)b)[i];
			}
			else
				memcpy(CurrentOut, b, RemainingBytes);
			return;
		}
	}
}

void chacha_encrypt_portable(uint8_t *key, uint8_t *nonce, uint8_t *in, uint8_t *out, size_t bytes, uint32_t rounds)
{
	uint8_t state[48] = {0};
	ChaCha20SetKey(state, key);
	ChaCha20SetNonce(state, nonce);
	ChaCha20EncryptBytes(state, in, out, bytes, rounds);
}
