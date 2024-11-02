
#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

#define ChaCha20StateSizeBytes 48;
#define ChaCha20KeySizeByte 32
#define ChaCha20NonceSizeByte 12
#define ChaCha20CounterSizeByte 4

#ifdef __cplusplus
extern "C"
{
#endif

	void ChaCha20SetKey(uint8_t *state, const uint8_t *Key);
	void ChaCha20SetNonce(uint8_t *state, const uint8_t *Nonce);
	// void ChaCha20SetCtr(uint8_t *state, const uint8_t *Ctr);
	// void ChaCha20EncryptBytes(uint8_t *state, uint8_t *In, uint8_t *Out, size_t Size, uint32_t rounds); // if In=nullptr - just fill Out
	void ChaCha20IncrementNonce(uint8_t *state);
	void ChaCha20AddCounter(uint8_t *ChaCha, const uint32_t value_to_add);

	void chacha_encrypt_portable(uint8_t *key, uint8_t *nonce, uint8_t *in, uint8_t *out, size_t bytes, uint32_t rounds);
	void chacha_encrypt_sse2(uint8_t *key, uint8_t *nonce, uint8_t *in, uint8_t *out, size_t bytes, uint32_t rounds);
	void chacha_encrypt_avx2(uint8_t *key, uint8_t *nonce, uint8_t *in, uint8_t *out, size_t bytes, uint32_t rounds);
	void chacha_encrypt(uint8_t *key, uint8_t *nonce, uint8_t *in, uint8_t *out, size_t bytes, uint32_t rounds);

#ifdef __cplusplus
}
#endif

#endif // CHACHA20_H
