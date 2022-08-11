/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nm-sd-adapt-shared.h"

#include <string.h>

#include "hash-funcs.h"
#include "path-util.h"
#include "strv.h"

void string_hash_func(const char *p, struct siphash *state) {
        siphash24_compress(p, strlen(p) + 1, state);
}

DEFINE_HASH_OPS(string_hash_ops, char, string_hash_func, string_compare_func);
DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(string_hash_ops_free,
                                    char, string_hash_func, string_compare_func, free);
DEFINE_HASH_OPS_FULL(string_hash_ops_free_free,
                     char, string_hash_func, string_compare_func, free,
                     void, free);
DEFINE_HASH_OPS_FULL(string_hash_ops_free_strv_free,
                     char, string_hash_func, string_compare_func, free,
                     char*, strv_free);

#if 0 /* NM_IGNORED */
void path_hash_func(const char *q, struct siphash *state) {
        bool add_slash = false;

        assert(q);
        assert(state);

        /* Calculates a hash for a path in a way this duplicate inner slashes don't make a differences, and also
         * whether there's a trailing slash or not. This fits well with the semantics of path_compare(), which does
         * similar checks and also doesn't care for trailing slashes. Note that relative and absolute paths (i.e. those
         * which begin in a slash or not) will hash differently though. */

        /* if path is absolute, add one "/" to the hash. */
        if (path_is_absolute(q))
                siphash24_compress("/", 1, state);

        for (;;) {
                const char *e;
                int r;

                r = path_find_first_component(&q, true, &e);
                if (r == 0)
                        return;

                if (add_slash)
                        siphash24_compress_byte('/', state);

                if (r < 0) {
                        /* if a component is invalid, then add remaining part as a string. */
                        string_hash_func(q, state);
                        return;
                }

                /* Add this component to the hash. */
                siphash24_compress(e, r, state);

                add_slash = true;
        }
}

DEFINE_HASH_OPS(path_hash_ops, char, path_hash_func, path_compare);
DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(path_hash_ops_free,
                                    char, path_hash_func, path_compare, free);
DEFINE_HASH_OPS_FULL(path_hash_ops_free_free,
                     char, path_hash_func, path_compare, free,
                     void, free);
#endif /* NM_IGNORED */

void trivial_hash_func(const void *p, struct siphash *state) {
        siphash24_compress(&p, sizeof(p), state);
}

int trivial_compare_func(const void *a, const void *b) {
        return CMP(a, b);
}

const struct hash_ops trivial_hash_ops = {
        .hash = trivial_hash_func,
        .compare = trivial_compare_func,
};

const struct hash_ops trivial_hash_ops_free = {
        .hash = trivial_hash_func,
        .compare = trivial_compare_func,
        .free_key = free,
};

const struct hash_ops trivial_hash_ops_free_free = {
        .hash = trivial_hash_func,
        .compare = trivial_compare_func,
        .free_key = free,
        .free_value = free,
};

void uint64_hash_func(const uint64_t *p, struct siphash *state) {
        siphash24_compress(p, sizeof(uint64_t), state);
}

int uint64_compare_func(const uint64_t *a, const uint64_t *b) {
        return CMP(*a, *b);
}

DEFINE_HASH_OPS(uint64_hash_ops, uint64_t, uint64_hash_func, uint64_compare_func);

#if 0 /* NM_IGNORED */
#if SIZEOF_DEV_T != 8
void devt_hash_func(const dev_t *p, struct siphash *state) {
        siphash24_compress(p, sizeof(dev_t), state);
}
#endif

int devt_compare_func(const dev_t *a, const dev_t *b) {
        int r;

        r = CMP(major(*a), major(*b));
        if (r != 0)
                return r;

        return CMP(minor(*a), minor(*b));
}

DEFINE_HASH_OPS(devt_hash_ops, dev_t, devt_hash_func, devt_compare_func);
#endif /* NM_IGNORED */
