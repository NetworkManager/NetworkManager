/*
 * Tests for Basic Hash Operations
 * This test does some basic hash operations and verifies their correctness. It
 * breaks up the data to be hashed in various ways to make sure it is stable.
 */

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c-siphash.h"

/* See https://131002.net/siphash/siphash.pdf, Appendix A. */
static void do_reference_test(const uint8_t *in, size_t len, const uint8_t *key) {
        CSipHash state = {};
        uint64_t out;
        unsigned i, j;

        /* verify the internal state as given in the above paper */
        c_siphash_init(&state, key);
        assert(state.v0 == 0x7469686173716475);
        assert(state.v1 == 0x6b617f6d656e6665);
        assert(state.v2 == 0x6b7f62616d677361);
        assert(state.v3 == 0x7b6b696e727e6c7b);
        c_siphash_append(&state, in, len);
        assert(state.v0 == 0x4a017198de0a59e0);
        assert(state.v1 == 0x0d52f6f62a4f59a4);
        assert(state.v2 == 0x634cb3577b01fd3d);
        assert(state.v3 == 0xa5224d6f55c7d9c8);
        out = c_siphash_finalize(&state);
        assert(out == 0xa129ca6149be45e5);
        assert(state.v0 == 0xf6bcd53893fecff1);
        assert(state.v1 == 0x54b9964c7ea0d937);
        assert(state.v2 == 0x1b38329c099bb55a);
        assert(state.v3 == 0x1814bb89ad7be679);

        /* verify that decomposing the input in three chunks gives the
           same result */
        for (i = 0; i < len; i++) {
                for (j = i; j < len; j++) {
                        c_siphash_init(&state, key);
                        c_siphash_append(&state, in, i);
                        c_siphash_append(&state, &in[i], j - i);
                        c_siphash_append(&state, &in[j], len - j);
                        out = c_siphash_finalize(&state);
                        assert(out == 0xa129ca6149be45e5);
                }
        }

        /* verify c_siphash_hash() produces the same result */
        assert(out == c_siphash_hash(key, in, len));
}

static void test_reference(void) {

        const uint8_t in[15]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e };
        const uint8_t key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        uint8_t in_buf[20];

        /* Test with same input but different alignments. */
        memcpy(in_buf, in, sizeof(in));
        do_reference_test(in_buf, sizeof(in), key);
        memcpy(in_buf + 1, in, sizeof(in));
        do_reference_test(in_buf + 1, sizeof(in), key);
        memcpy(in_buf + 2, in, sizeof(in));
        do_reference_test(in_buf + 2, sizeof(in), key);
        memcpy(in_buf + 4, in, sizeof(in));
        do_reference_test(in_buf + 4, sizeof(in), key);
}

static void test_short_hashes(void) {
        const uint8_t one[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
        const uint8_t  key[16] = { 0x22, 0x24, 0x41, 0x22, 0x55, 0x77, 0x88, 0x07,
                                   0x23, 0x09, 0x23, 0x14, 0x0c, 0x33, 0x0e, 0x0f};
        uint8_t two[sizeof one] = {};

        CSipHash state1 = {}, state2 = {};
        unsigned i, j;

        c_siphash_init(&state1, key);
        c_siphash_init(&state2, key);

        /* hashing 1, 2, 3, 4, 5, ..., 16 bytes, with the byte after the buffer different */
        for (i = 1; i <= sizeof one; i++) {
                c_siphash_append(&state1, one, i);

                two[i-1] = one[i-1];
                c_siphash_append(&state2, two, i);

                assert(memcmp(&state1, &state2, sizeof state1) == 0);
        }

        /* hashing n and 1, n and 2, n and 3, ..., n-1 and 1, n-2 and 2, ... */
        for (i = sizeof one; i > 0; i--) {
                memset(two, 0, sizeof(two));

                for (j = 1; j <= sizeof one; j++) {
                        c_siphash_append(&state1, one, i);
                        c_siphash_append(&state1, one, j);

                        c_siphash_append(&state2, one, i);
                        two[j-1] = one[j-1];
                        c_siphash_append(&state2, two, j);

                        assert(memcmp(&state1, &state2, sizeof state1) == 0);
                }
        }
}

int main(int argc, char *argv[]) {
        test_reference();
        test_short_hashes();

        return 0;
}
