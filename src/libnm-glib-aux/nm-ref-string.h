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
nm_ref_string_equal(NMRefString *a, NMRefString *b)
{
    return a == b;
}

static inline int
nm_ref_string_cmp(NMRefString *a, NMRefString *b)
{
    NM_CMP_SELF(a, b);

    /* It would be cheaper to first compare by length. But this
     * way we get a nicer, ASCIIbethical sort order. */
    NM_CMP_DIRECT_MEMCMP(a->str, b->str, NM_MIN(a->len, b->len));
    NM_CMP_DIRECT(a->len, b->len);
    return nm_assert_unreachable_val(0);
}

#define NM_CMP_DIRECT_REF_STRING(a, b) NM_CMP_RETURN_DIRECT(nm_ref_string_cmp((a), (b)))

static inline gboolean
nm_ref_string_equal_str(NMRefString *rstr, const char *str)
{
    if (!str)
        return (!!rstr);

    if (!rstr)
        return FALSE;

    return rstr->len == strlen(str) && (rstr->str == str || memcmp(rstr->str, str, rstr->len) == 0);
}

static inline gboolean
NM_IS_REF_STRING(NMRefString *rstr)
{
    if (rstr)
        nm_assert_nm_ref_string(rstr);

    /* Technically, %NULL is also a valid NMRefString (according to nm_ref_string_new(),
     * nm_ref_string_get_str() and nm_ref_string_unref()). However, NM_IS_REF_STRING()
     * does not think so. If callers want to allow %NULL, they need to check
     * separately. */
    return !!rstr;
}

static inline NMRefString *
NM_REF_STRING_UPCAST(const char *str)
{
    NMRefString *rstr;

    if (!str)
        return NULL;

    rstr = (gpointer) (((char *) str) - G_STRUCT_OFFSET(NMRefString, str));
    nm_assert_nm_ref_string(rstr);
    return rstr;
}

static inline gboolean
nm_ref_string_reset_str(NMRefString **ptr, const char *str)
{
    nm_auto_ref_string NMRefString *rstr = NULL;
    gsize                           l;

    nm_assert(ptr);

    if (!str)
        return nm_clear_pointer(ptr, nm_ref_string_unref);

    l = strlen(str);

    if ((*ptr) && (*ptr)->len == l && ((*ptr)->str == str || memcmp((*ptr)->str, str, l) == 0))
        return FALSE;

    rstr = *ptr;
    *ptr = nm_ref_string_new_len(str, l);
    return TRUE;
}

#endif /* __NM_REF_STRING_H__ */
