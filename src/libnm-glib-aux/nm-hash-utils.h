/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_HASH_UTILS_H__
#define __NM_HASH_UTILS_H__

#include "c-siphash/src/c-siphash.h"
#include "nm-macros-internal.h"

/*****************************************************************************/

#define NM_HASH_SEED_16(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, aa, ab, ac, ad, ae, af) \
    ((const guint8[16]) {a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, aa, ab, ac, ad, ae, af})

struct _nm_packed _nm_hash_seed_16_u64_data {
    guint64 s1;
    guint64 s2;
};

G_STATIC_ASSERT(sizeof(struct _nm_hash_seed_16_u64_data) == 16);
G_STATIC_ASSERT(sizeof(struct _nm_hash_seed_16_u64_data) == sizeof(guint64) * 2);

/* c_siphash_init() has a seed of 16 bytes (NM_HASH_SEED_16()). That is
 * cumbersome to use, because we usually just hardcode an arbitrarily chosen,
 * fixed number.
 *
 * This macro takes a u64 (in host-endianness) and returns a 16 byte seed
 * buffer. The number will be big endian encoded, to be architecture
 * independent. */
#define NM_HASH_SEED_16_U64(u64)                               \
    ((const guint8 *) ((gpointer)                              \
                       & ((struct _nm_hash_seed_16_u64_data) { \
                           .s1 = htobe64((u64)),               \
                           .s2 = 0,                            \
                       })))

/*****************************************************************************/

void nm_hash_siphash42_init(CSipHash *h, guint static_seed);

/* Siphash24 of binary buffer @arr and @len, using the randomized seed from
 * other NMHash functions.
 *
 * Note, that this is guaranteed to use siphash42 under the hood (contrary to
 * all other NMHash API, which leave this undefined). That matters at the point,
 * where the caller needs to be sure that a reasonably strong hashing algorithm
 * is used.  (Yes, NMHash is all about siphash42, but otherwise that is not promised
 * anywhere).
 *
 * Another difference is, that this returns guint64 (not guint like other NMHash functions).
 *
 * Another difference is, that this may also return zero (not like nm_hash_complete()).
 *
 * Then, why not use c_siphash_hash() directly? Because this also uses the randomized,
 * per-run hash-seed like nm_hash_init(). So, you get siphash24 with a random
 * seed (which is cached for the current run of the program).
 *
 * WARNING: the static_seed gets randomized like with nm_hash*(). If you want a reproducible
 *   siphash42, use instead `c_siphash_hash(NM_HASH_SEED_16_U64(number), ptr, len)`.
 */
static inline guint64
nm_hash_siphash42(guint static_seed, const void *ptr, gsize n)
{
    CSipHash h;

    nm_hash_siphash42_init(&h, static_seed);
    c_siphash_append(&h, ptr, n);
    return c_siphash_finalize(&h);
}

/*****************************************************************************/

struct _NMHashState {
    CSipHash _state;
};

typedef struct _NMHashState NMHashState;

guint nm_hash_static(guint static_seed);

static inline void
nm_hash_init(NMHashState *state, guint static_seed)
{
    nm_assert(state);

    nm_hash_siphash42_init(&state->_state, static_seed);
}

static inline guint64
nm_hash_complete_u64(NMHashState *state)
{
    nm_assert(state);

    /* this returns the native u64 hash value. Note that this differs
     * from nm_hash_complete() in two ways:
     *
     * - the type, guint64 vs. guint.
     * - nm_hash_complete() never returns zero.
     *
     * In practice, nm_hash*() API is implemented via siphash24, so this returns
     * the siphash24 value. But that is not guaranteed by the API, and if you need
     * siphash24 directly, use c_siphash_*() and nm_hash_siphash42*() API. */
    return c_siphash_finalize(&state->_state);
}

static inline guint
nm_hash_complete(NMHashState *state)
{
    guint64 h;

    h = nm_hash_complete_u64(state);

    /* we don't ever want to return a zero hash.
     *
     * NMPObject requires that in _idx_obj_part(), and it's just a good idea. */
    return (((guint) (h >> 32)) ^ ((guint) h)) ?: 1396707757u;
}

static inline void
nm_hash_update(NMHashState *state, const void *ptr, gsize n)
{
    nm_assert(state);
    nm_assert(n == 0 || ptr);

    /* Note: the data passed in here might be sensitive data (secrets),
     * that we should nm_explicit_bzero() afterwards. However, since
     * we are using siphash24 with a random key, that is not really
     * necessary. Something to keep in mind, if we ever move away from
     * this hash implementation. */
    c_siphash_append(&state->_state, ptr, n);
}

#define _NM_HASH_COMBINE_VALS_TYPE_OP(x, idx, op_arg) typeof(x) _v##idx;
#define _NM_HASH_COMBINE_VALS_INIT_OP(x, idx, op_arg) ._v##idx = (x),

/* NM_HASH_COMBINE_VALS() is faster then nm_hash_update_val() as it combines multiple
 * calls to nm_hash_update() using a packed structure. */
#define NM_HASH_COMBINE_VALS(var, ...)                                         \
    const struct _nm_packed {                                                  \
        NM_VA_ARGS_FOREACH(, , , _NM_HASH_COMBINE_VALS_TYPE_OP, , __VA_ARGS__) \
    } var _nm_alignas(max_align_t) = {                                         \
        NM_VA_ARGS_FOREACH(, , , _NM_HASH_COMBINE_VALS_INIT_OP, , __VA_ARGS__)}

/* nm_hash_update_vals() is faster then nm_hash_update_val() as it combines multiple
 * calls to nm_hash_update() using a packed structure. */
#define nm_hash_update_vals(state, ...)               \
    G_STMT_START                                      \
    {                                                 \
        NM_HASH_COMBINE_VALS(_val, __VA_ARGS__);      \
                                                      \
        nm_hash_update((state), &_val, sizeof(_val)); \
    }                                                 \
    G_STMT_END

#define nm_hash_update_val(state, val) nm_hash_update_vals((state), (val))

#define nm_hash_update_valp(state, val) nm_hash_update((state), (val), sizeof(*(val)))

static inline void
nm_hash_update_bool(NMHashState *state, bool val)
{
    nm_hash_update(state, &val, sizeof(val));
}

#define _NM_HASH_COMBINE_BOOLS_OP(x, n, op_arg) ((x) ? NM_BIT((n)) : 0ull)

#define NM_HASH_COMBINE_BOOLS(type, ...)                                                 \
    ((type) (NM_STATIC_ASSERT_EXPR_1(NM_NARG(__VA_ARGS__) <= 8 * sizeof(type))           \
                 ? (NM_VA_ARGS_FOREACH(, , |, _NM_HASH_COMBINE_BOOLS_OP, , __VA_ARGS__)) \
                 : 0ull))

#define nm_hash_update_bools(state, ...) \
    nm_hash_update_val(state, NM_HASH_COMBINE_BOOLS(guint8, __VA_ARGS__))

static inline void
nm_hash_update_mem(NMHashState *state, const void *ptr, gsize n)
{
    /* This also hashes the length of the data. That means,
     * hashing two consecutive binary fields (of arbitrary
     * length), will hash differently. That is,
     * [[1,1], []] differs from [[1],[1]].
     *
     * If you have a constant length (sizeof), use nm_hash_update()
     * instead. */
    nm_hash_update(state, &n, sizeof(n));
    if (n > 0)
        nm_hash_update(state, ptr, n);
}

static inline void
nm_hash_update_str0(NMHashState *state, const char *str)
{
    if (str)
        nm_hash_update_mem(state, str, strlen(str));
    else {
        gsize n = G_MAXSIZE;

        nm_hash_update(state, &n, sizeof(n));
    }
}

static inline void
nm_hash_update_str(NMHashState *state, const char *str)
{
    nm_assert(str);
    nm_hash_update(state, str, strlen(str) + 1);
}

#if _NM_CC_SUPPORT_GENERIC
/* Like nm_hash_update_str(), but restricted to arrays only. nm_hash_update_str() only works
 * with a @str argument that cannot be NULL. If you have a string pointer, that is never NULL, use
 * nm_hash_update() instead. */
#define nm_hash_update_strarr(state, str)                                 \
    (_Generic(&(str),                                                     \
         const char (*)[sizeof(str)]: nm_hash_update_str((state), (str)), \
         char (*)[sizeof(str)]: nm_hash_update_str((state), (str))))
#else
#define nm_hash_update_strarr(state, str) nm_hash_update_str((state), (str))
#endif

guint nm_hash_ptr(gconstpointer ptr);
#define nm_direct_hash nm_hash_ptr

guint nm_hash_str(const char *str);
#define nm_str_hash ((guint (*)(gconstpointer str)) nm_hash_str)

#define nm_hash_vals(static_seed, ...)         \
    ({                                         \
        NMHashState _h;                        \
                                               \
        nm_hash_init(&_h, (static_seed));      \
        nm_hash_update_vals(&_h, __VA_ARGS__); \
        nm_hash_complete(&_h);                 \
    })

#define nm_hash_val(static_seed, val) nm_hash_vals((static_seed), (val))

static inline guint
nm_hash_mem(guint static_seed, const void *ptr, gsize n)
{
    NMHashState h;

    if (n == 0)
        return nm_hash_static(static_seed);
    nm_hash_init(&h, static_seed);
    nm_hash_update(&h, ptr, n);
    return nm_hash_complete(&h);
}

/*****************************************************************************/

/* nm_pstr_*() are for hashing keys that are pointers to strings,
 * that is, "const char *const*" types, using strcmp(). */

guint nm_pstr_hash(gconstpointer p);

gboolean nm_pstr_equal(gconstpointer a, gconstpointer b);

/*****************************************************************************/

/* nm_pint_*() are for hashing keys that are pointers to int values,
 * that is, "const int *" types. */

guint    nm_pint_hash(gconstpointer p);
gboolean nm_pint_equal(gconstpointer a, gconstpointer b);

guint    nm_puint64_hash(gconstpointer p);
gboolean nm_puint64_equal(gconstpointer a, gconstpointer b);

G_STATIC_ASSERT(sizeof(int) == sizeof(guint32));
#define nm_puint32_hash  nm_pint_hash
#define nm_puint32_equal nm_pint_equal

/*****************************************************************************/

/* this hashes/compares the pointer value that we point to. Basically,
 * (*((const void *const*) a) == *((const void *const*) b)). */

guint nm_pdirect_hash(gconstpointer p);

gboolean nm_pdirect_equal(gconstpointer a, gconstpointer b);

/* this hashes/compares the direct pointer value by following pointers to
 * pointers 2 times.
 * (**((const void *const*const*) a) == **((const void *const*const*) b)). */

guint nm_ppdirect_hash(gconstpointer p);

gboolean nm_ppdirect_equal(gconstpointer a, gconstpointer b);

/*****************************************************************************/

guint nm_g_bytes_hash(gconstpointer p);
#define nm_g_bytes_equal g_bytes_equal

guint    nm_pg_bytes_hash(gconstpointer p);
gboolean nm_pg_bytes_equal(gconstpointer a, gconstpointer b);

/*****************************************************************************/

#define NM_HASH_OBFUSCATE_PTR_FMT "%016" G_GINT64_MODIFIER "x"

/* sometimes we want to log a pointer directly, for providing context/information about
 * the message that get logged. Logging pointer values directly defeats ASLR, so we should
 * not do that. This returns a "unsigned long long" value that can be used
 * instead.
 *
 * Note that there is a chance that two different pointer values hash to the same obfuscated
 * value. So beware of that when reviewing logs. However, such a collision is very unlikely. */
guint64 nm_hash_obfuscate_ptr(guint static_seed, gconstpointer val);

/* if you want to log obfuscated pointer for a certain context (like, NMPRuleManager
 * logging user-tags), then you are advised to use nm_hash_obfuscate_ptr() with your
 * own, unique static-seed.
 *
 * However, for example the singleton constructors log the obfuscated pointer values
 * for all singletons, so they must all be obfuscated with the same seed. So, this
 * macro uses a particular static seed that should be used by when comparing pointer
 * values in a global context. */
#define NM_HASH_OBFUSCATE_PTR(ptr) (nm_hash_obfuscate_ptr(1678382159u, ptr))

/* NM_HASH_OBFUSCATE_PTR_STR needs a buffer of at least this many bytes. */
#define NM_HASH_OBFUSCATE_PTR_STR_BUF_SIZE 19

#define NM_HASH_OBFUSCATE_PTR_STR(ptr, buf)                                                        \
    ({                                                                                             \
        gconstpointer _ptr = (ptr);                                                                \
                                                                                                   \
        _ptr ? nm_sprintf_buf(buf, "[" NM_HASH_OBFUSCATE_PTR_FMT "]", NM_HASH_OBFUSCATE_PTR(_ptr)) \
             : "(null)";                                                                           \
    })

static inline const char *
nm_hash_obfuscated_ptr_str(gconstpointer ptr, char buf[static 17])
{
    int l;

    nm_assert(buf);
    l = g_snprintf(buf, 17, NM_HASH_OBFUSCATE_PTR_FMT, NM_HASH_OBFUSCATE_PTR(ptr));
    nm_assert(l < 17);
    return buf;
}

#define nm_hash_obfuscated_ptr_str_a(ptr) (nm_hash_obfuscated_ptr_str((ptr), g_alloca(17)))

/*****************************************************************************/

#endif /* __NM_HASH_UTILS_H__ */
