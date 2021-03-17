/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_REF_STRING_H__
#define __NM_REF_STRING_H__

/*****************************************************************************/

typedef struct _NMRefString {
    const gsize len;
    union {
        struct {
            volatile int _ref_count;
            const char   str[];
        };
        struct {
            /* This union field is only used during lookup by external string.
             * In that case, len will be set to G_MAXSIZE, and the actual len/str values
             * are set in _priv_lookup. */
            gsize       l_len;
            const char *l_str;
        } _priv_lookup;
    };
} NMRefString;

/*****************************************************************************/

void _nm_assert_nm_ref_string(NMRefString *rstr);

static inline void
nm_assert_nm_ref_string(NMRefString *rstr)
{
#if NM_MORE_ASSERTS
    _nm_assert_nm_ref_string(rstr);
#endif
}

/*****************************************************************************/

NMRefString *nm_ref_string_new_len(const char *cstr, gsize len);

static inline NMRefString *
nm_ref_string_new(const char *cstr)
{
    return cstr ? nm_ref_string_new_len(cstr, strlen(cstr)) : NULL;
}

/*****************************************************************************/

static inline NMRefString *
nm_ref_string_ref(NMRefString *rstr)
{
    if (rstr) {
        nm_assert_nm_ref_string(rstr);
        g_atomic_int_inc(&rstr->_ref_count);
    }
    return rstr;
}

void _nm_ref_string_unref_slow_path(NMRefString *rstr);

static inline void
nm_ref_string_unref(NMRefString *rstr)
{
    int r;

    if (!rstr)
        return;

    nm_assert_nm_ref_string(rstr);

    /* fast-path: first try to decrement the ref-count without bringing it
     * to zero. */
    r = rstr->_ref_count;
    if (G_LIKELY(r > 1 && g_atomic_int_compare_and_exchange(&rstr->_ref_count, r, r - 1)))
        return;

    _nm_ref_string_unref_slow_path(rstr);
}

NM_AUTO_DEFINE_FCN_VOID(NMRefString *, _nm_auto_ref_string, nm_ref_string_unref);
#define nm_auto_ref_string nm_auto(_nm_auto_ref_string)

/*****************************************************************************/

static inline const char *
nm_ref_string_get_str(NMRefString *rstr)
{
    return rstr ? rstr->str : NULL;
}

static inline gsize
nm_ref_string_get_len(NMRefString *rstr)
{
    return rstr ? rstr->len : 0u;
}

static inline gboolean
nm_ref_string_equals_str(NMRefString *rstr, const char *s)
{
    /* Note that rstr->len might be greater than strlen(rstr->str). This function does
     * not cover that and would ignore everything after the first NUL byte. If you need
     * that distinction, this function is not for you. */

    return rstr ? (s && nm_streq(rstr->str, s)) : (s == NULL);
}

static inline gboolean
NM_IS_REF_STRING(NMRefString *rstr)
{
#if NM_MORE_ASSERTS > 10
    if (rstr) {
        nm_auto_ref_string NMRefString *r2 = NULL;

        r2 = nm_ref_string_new_len(rstr->str, rstr->len);
        nm_assert(rstr == r2);
    }
#endif

    /* Technically, %NULL is also a valid NMRefString (according to nm_ref_string_new(),
     * nm_ref_string_get_str() and nm_ref_string_unref()). However, NM_IS_REF_STRING()
     * does not think so. If callers want to allow %NULL, they need to check
     * separately. */
    return !!rstr;
}

#endif /* __NM_REF_STRING_H__ */
