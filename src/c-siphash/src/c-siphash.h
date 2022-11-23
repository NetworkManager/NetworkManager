#pragma once

/**
 * Streaming-capable SipHash Implementation
 *
 * This library provides a SipHash API, that is fully implemented in ISO-C11
 * and has no external dependencies. The library performs no memory allocation,
 * and provides a streaming API where data to be hashed can be appended
 * piecemeal.
 *
 * A streaming-capable hash state is represented by the "CSipHash" structure,
 * which should be initialized with a unique seed before use. If streaming
 * capabilities are not required, c_siphash_hash() provides a simple one-shot
 * API.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct CSipHash CSipHash;

/**
 * struct CSipHash - SipHash state object
 * @v0-@v3:             internal state
 * @padding:            pending bytes that were not a multiple of 8
 * @n_bytes:            number of hashed bytes
 *
 * The state of an inflight hash is represenetd by a CSipHash object. Before
 * hashing, it must be initialized with c_siphash_init(), providing a unique
 * random hash seed. Data is hashed by appending it to the state object, using
 * c_siphash_append(). Finally, the hash is read out by calling
 * c_siphash_finalize().
 *
 * This state object has no allocated resources. It is safe to release its
 * backing memory without any further action.
 */
struct CSipHash {
        uint64_t v0;
        uint64_t v1;
        uint64_t v2;
        uint64_t v3;
        uint64_t padding;
        size_t n_bytes;
};

#define C_SIPHASH_NULL {0}

void c_siphash_init(CSipHash *state, const uint8_t seed[16]);

/* siphash-2-4 (default for historical reasons) */

void c_siphash_append(CSipHash *state, const uint8_t *bytes, size_t n_bytes);
uint64_t c_siphash_finalize(CSipHash *state);
uint64_t c_siphash_hash(const uint8_t seed[16], const uint8_t *bytes, size_t n_bytes);

/* siphash-1-3 */

void c_siphash_append_13(CSipHash *state, const uint8_t *bytes, size_t n_bytes);
uint64_t c_siphash_finalize_13(CSipHash *state);
uint64_t c_siphash_hash_13(const uint8_t seed[16], const uint8_t *bytes, size_t n_bytes);

/* inline helpers */

static inline void c_siphash_append_24(CSipHash *state, const uint8_t *bytes, size_t n_bytes) {
        c_siphash_append(state, bytes, n_bytes);
}

static inline uint64_t c_siphash_finalize_24(CSipHash *state) {
        return c_siphash_finalize(state);
}

static inline uint64_t c_siphash_hash_24(const uint8_t seed[16], const uint8_t *bytes, size_t n_bytes) {
        return c_siphash_hash(seed, bytes, n_bytes);
}

#ifdef __cplusplus
}
#endif
