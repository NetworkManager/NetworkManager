/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-ref-string.h"

/*****************************************************************************/

G_LOCK_DEFINE_STATIC(gl_lock);
static GHashTable *gl_hash;

/*****************************************************************************/

static void
_ref_string_get(const NMRefString *rstr, const char **out_str, gsize *out_len)
{
    if (rstr->len == G_MAXSIZE) {
        *out_len = rstr->_priv_lookup.l_len;
        *out_str = rstr->_priv_lookup.l_str;
    } else {
        *out_len = rstr->len;
        *out_str = rstr->str;
    }
}

static guint
_ref_string_hash(gconstpointer ptr)
{
    const char *cstr;
    gsize       len;

    _ref_string_get(ptr, &cstr, &len);
    return nm_hash_mem(1463435489u, cstr, len);
}

static gboolean
_ref_string_equal(gconstpointer ptr_a, gconstpointer ptr_b)
{
    const char *cstr_a;
    const char *cstr_b;
    gsize       len_a;
    gsize       len_b;

    _ref_string_get(ptr_a, &cstr_a, &len_a);
    _ref_string_get(ptr_b, &cstr_b, &len_b);

    /* memcmp() accepts "n=0" argument, but it's not clear whether in that case
     * all pointers must still be valid. The input pointer might be provided by
     * the user via nm_ref_string_new_len(), and for len=0 we want to allow
     * also invalid pointers. Hence, this extra "len_a==0" check. */
    return len_a == len_b && (len_a == 0 || (memcmp(cstr_a, cstr_b, len_a) == 0));
}

/*****************************************************************************/

void
_nm_assert_nm_ref_string(NMRefString *rstr)
{
    int r;

    nm_assert(rstr);

    if (NM_MORE_ASSERTS > 0) {
        r = g_atomic_int_get(&rstr->_ref_count);
        nm_assert(r > 0);
        nm_assert(r < G_MAXINT);
    }

    nm_assert(rstr->str[rstr->len] == '\0');

    if (NM_MORE_ASSERTS > 10) {
        G_LOCK(gl_lock);
        r = g_atomic_int_get(&rstr->_ref_count);
        nm_assert(r > 0);
        nm_assert(r < G_MAXINT);

        nm_assert(rstr == g_hash_table_lookup(gl_hash, rstr));
        G_UNLOCK(gl_lock);
    }
}

/**
 * nm_ref_string_new_len:
 * @cstr: the string to intern. Must contain @len bytes.
 *   If @len is zero, @cstr may be %NULL. Note that it is
 *   acceptable that the string contains a NUL character
 *   within the first @len bytes. That is, the string is
 *   not treated as a NUL terminated string, but as binary.
 *   Also, contrary to strncpy(), this will read all the
 *   first @len bytes. It won't stop at the first NUL.
 * @len: the length of the string (usually there is no NUL character
 *   within the first @len bytes, but that would be acceptable as well
 *   to add binary data).
 *
 * Note that the resulting NMRefString instance will always be NUL terminated
 * (at position @len).
 *
 * Note that NMRefString are always interned/deduplicated. If such a string
 * already exists, the existing instance will be referred and returned.
 *
 *
 * Since all NMRefString are shared and interned, you may use
 * pointer equality to compare them. Note that if a NMRefString contains
 * a NUL character (meaning, if
 *
 *    strlen (nm_ref_string_get_str (str)) != nm_ref_string_get_len (str)
 *
 * ), then pointer in-equality does not mean that the NUL terminated strings
 * are also unequal. In other words, for strings that contain NUL characters,
 *
 *    if (str1 != str2)
 *       assert (!nm_streq0 (nm_ref_string_get_str (str1), nm_ref_string_get_str (str2)));
 *
 * might not hold!
 *
 *
 * NMRefString is thread-safe.
 *
 * Returns: (transfer full): the interned string. This is
 *   never %NULL, but note that %NULL is also a valid NMRefString.
 *   The result must be unrefed with nm_ref_string_unref().
 */
NMRefString *
nm_ref_string_new_len(const char *cstr, gsize len)
{
    NMRefString *rstr;

    /* @len cannot be close to G_MAXSIZE. For one, that would mean our call
     * to malloc() below overflows. Also, we use G_MAXSIZE as special length
     * to indicate using _priv_lookup. */
    nm_assert(len < G_MAXSIZE - G_STRUCT_OFFSET(NMRefString, str) - 1u);

    G_LOCK(gl_lock);

    if (G_UNLIKELY(!gl_hash)) {
        gl_hash = g_hash_table_new_full(_ref_string_hash, _ref_string_equal, g_free, NULL);
        rstr    = NULL;
    } else {
        NMRefString rr_lookup = {
            .len = G_MAXSIZE,
            ._priv_lookup =
                {
                    .l_len = len,
                    .l_str = cstr,
                },
        };

        rstr = g_hash_table_lookup(gl_hash, &rr_lookup);
    }

    if (rstr) {
        nm_assert(({
            int r = g_atomic_int_get(&rstr->_ref_count);

            (r >= 0 && r < G_MAXINT);
        }));
        g_atomic_int_inc(&rstr->_ref_count);
    } else {
        rstr = g_malloc((G_STRUCT_OFFSET(NMRefString, str) + 1u) + len);
        if (len > 0)
            memcpy((char *) rstr->str, cstr, len);
        ((char *) rstr->str)[len] = '\0';
        *((gsize *) &rstr->len)   = len;
        rstr->_ref_count          = 1;

        if (!g_hash_table_add(gl_hash, rstr))
            nm_assert_not_reached();
    }

    G_UNLOCK(gl_lock);

    return rstr;
}

void
_nm_ref_string_unref_slow_path(NMRefString *rstr)
{
    G_LOCK(gl_lock);

    nm_assert(g_hash_table_lookup(gl_hash, rstr) == rstr);

    if (G_LIKELY(g_atomic_int_dec_and_test(&rstr->_ref_count))) {
        if (!g_hash_table_remove(gl_hash, rstr))
            nm_assert_not_reached();
    }

    G_UNLOCK(gl_lock);
}

/*****************************************************************************/
