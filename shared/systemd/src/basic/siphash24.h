#pragma once

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#if 0 /* NM_IGNORED */
struct siphash {
        uint64_t v0;
        uint64_t v1;
        uint64_t v2;
        uint64_t v3;
        uint64_t padding;
        size_t inlen;
};
#else /* NM_IGNORED */
struct siphash {
	CSipHash _csiphash;
};

static inline void
siphash24_init (struct siphash *state, const uint8_t k[16])
{
	c_siphash_init ((CSipHash *) state, k);
}

static inline void
siphash24_compress (const void *in, size_t inlen, struct siphash *state)
{
	c_siphash_append ((CSipHash *) state, in, inlen);
}

static inline uint64_t
siphash24_finalize (struct siphash *state)
{
	return c_siphash_finalize ((CSipHash *) state);
}

static inline uint64_t
siphash24 (const void *in, size_t inlen, const uint8_t k[16])
{
	return c_siphash_hash (k, in, inlen);
}
#endif /* NM_IGNORED */

void siphash24_init(struct siphash *state, const uint8_t k[static 16]);
void siphash24_compress(const void *in, size_t inlen, struct siphash *state);
void siphash24_compress_boolean(bool in, struct siphash *state);
#define siphash24_compress_byte(byte, state) siphash24_compress((const uint8_t[]) { (byte) }, 1, (state))

uint64_t siphash24_finalize(struct siphash *state);

uint64_t siphash24(const void *in, size_t inlen, const uint8_t k[static 16]);

static inline uint64_t siphash24_string(const char *s, const uint8_t k[static 16]) {
        return siphash24(s, strlen(s) + 1, k);
}
