/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_STR_BUF_H__
#define __NM_STR_BUF_H__

#include "nm-shared-utils.h"
#include "nm-secret-utils.h"

/*****************************************************************************/

/* NMStrBuf is not unlike GString. The main difference is that it can use
 * nm_explicit_bzero() when growing the buffer. */
typedef struct _NMStrBuf {
    char *_priv_str;

    /* The unions only exist because we allow/encourage read-only access
     * to the "len" and "allocated" fields, but modifying the fields is
     * only allowed to the NMStrBuf implementation itself. */
    union {
        /*const*/ gsize len;
        gsize           _priv_len;
    };
    union {
        /*const*/ gsize allocated;
        gsize           _priv_allocated;
    };

    bool _priv_do_bzero_mem;
} NMStrBuf;

/*****************************************************************************/

static inline void
_nm_str_buf_assert(const NMStrBuf *strbuf)
{
    nm_assert(strbuf);
    nm_assert((!!strbuf->_priv_str) == (strbuf->_priv_allocated > 0));
    nm_assert(strbuf->_priv_len <= strbuf->_priv_allocated);
}

static inline NMStrBuf
NM_STR_BUF_INIT(gsize allocated, gboolean do_bzero_mem)
{
    NMStrBuf strbuf = {
        ._priv_str          = allocated ? g_malloc(allocated) : NULL,
        ._priv_allocated    = allocated,
        ._priv_len          = 0,
        ._priv_do_bzero_mem = do_bzero_mem,
    };

    return strbuf;
}

static inline void
nm_str_buf_init(NMStrBuf *strbuf, gsize len, bool do_bzero_mem)
{
    nm_assert(strbuf);
    *strbuf = NM_STR_BUF_INIT(len, do_bzero_mem);
    _nm_str_buf_assert(strbuf);
}

void _nm_str_buf_ensure_size(NMStrBuf *strbuf, gsize new_size, gboolean reserve_exact);

static inline void
nm_str_buf_maybe_expand(NMStrBuf *strbuf, gsize reserve, gboolean reserve_exact)
{
    _nm_str_buf_assert(strbuf);
    nm_assert(strbuf->_priv_len < G_MAXSIZE - reserve);

    /* @reserve is the extra space that we require. */
    if (G_UNLIKELY(reserve > strbuf->_priv_allocated - strbuf->_priv_len))
        _nm_str_buf_ensure_size(strbuf, strbuf->_priv_len + reserve, reserve_exact);
}

/*****************************************************************************/

/**
 * nm_str_buf_set_size:
 * @strbuf: the initialized #NMStrBuf
 * @new_len: the new length
 * @honor_do_bzero_mem: if %TRUE, the shrunk memory will be cleared, if
 *   do_bzero_mem is set. This should be usually set to %TRUE, unless
 *   you know that the shrunk memory does not contain data that requires to be
 *   cleared. When growing the size, this value has no effect.
 * @reserve_exact: when growing the buffer, reserve the exact amount of bytes.
 *   If %FALSE, the buffer may allocate more memory than requested to grow
 *   exponentially.
 *
 * This is like g_string_set_size(). If new_len is smaller than the
 * current length, the string gets truncated (excess memory will be cleared).
 *
 * When extending the length, the added bytes are undefined (like with
 * g_string_set_size(). Likewise, if you first pre-allocate a buffer with
 * nm_str_buf_maybe_expand(), then write to the bytes, and finally set
 * the appropriate size, then that works as expected (by not clearing the
 * pre-existing, grown buffer).
 */
static inline void
nm_str_buf_set_size(NMStrBuf *strbuf,
                    gsize     new_len,
                    gboolean  honor_do_bzero_mem,
                    gboolean  reserve_exact)
{
    _nm_str_buf_assert(strbuf);

    if (new_len < strbuf->_priv_len) {
        if (honor_do_bzero_mem && strbuf->_priv_do_bzero_mem) {
            /* we only clear the memory that we wrote to. */
            nm_explicit_bzero(&strbuf->_priv_str[new_len], strbuf->_priv_len - new_len);
        }
    } else if (new_len > strbuf->_priv_len) {
        nm_str_buf_maybe_expand(strbuf,
                                new_len - strbuf->_priv_len + (reserve_exact ? 0u : 1u),
                                reserve_exact);
    } else
        return;

    strbuf->_priv_len = new_len;
}

/*****************************************************************************/

static inline void
nm_str_buf_erase(NMStrBuf *strbuf, gsize pos, gssize len, gboolean honor_do_bzero_mem)
{
    gsize new_len;

    _nm_str_buf_assert(strbuf);

    nm_assert(pos <= strbuf->_priv_len);

    if (len == 0)
        return;

    if (len < 0) {
        /* truncate the string before pos */
        nm_assert(len == -1);
        new_len = pos;
    } else {
        gsize l = len;

        nm_assert(l <= strbuf->_priv_len - pos);

        new_len = strbuf->_priv_len - l;
        if (pos + l < strbuf->_priv_len) {
            memmove(&strbuf->_priv_str[pos],
                    &strbuf->_priv_str[pos + l],
                    strbuf->_priv_len - (pos + l));
        }
    }

    nm_assert(new_len <= strbuf->_priv_len);
    nm_str_buf_set_size(strbuf, new_len, honor_do_bzero_mem, TRUE);
}

/*****************************************************************************/

static inline void
nm_str_buf_append_c_repeated(NMStrBuf *strbuf, char ch, guint len)
{
    if (len > 0) {
        nm_str_buf_maybe_expand(strbuf, len + 1, FALSE);
        do {
            strbuf->_priv_str[strbuf->_priv_len++] = ch;
        } while (--len > 0);
    }
}

static inline void
nm_str_buf_append_c(NMStrBuf *strbuf, char ch)
{
    nm_str_buf_maybe_expand(strbuf, 2, FALSE);
    strbuf->_priv_str[strbuf->_priv_len++] = ch;
}

static inline void
nm_str_buf_append_c2(NMStrBuf *strbuf, char ch0, char ch1)
{
    nm_str_buf_maybe_expand(strbuf, 3, FALSE);
    strbuf->_priv_str[strbuf->_priv_len++] = ch0;
    strbuf->_priv_str[strbuf->_priv_len++] = ch1;
}

static inline void
nm_str_buf_append_c4(NMStrBuf *strbuf, char ch0, char ch1, char ch2, char ch3)
{
    nm_str_buf_maybe_expand(strbuf, 5, FALSE);
    strbuf->_priv_str[strbuf->_priv_len++] = ch0;
    strbuf->_priv_str[strbuf->_priv_len++] = ch1;
    strbuf->_priv_str[strbuf->_priv_len++] = ch2;
    strbuf->_priv_str[strbuf->_priv_len++] = ch3;
}

static inline void
nm_str_buf_append_c_hex(NMStrBuf *strbuf, char ch, gboolean upper_case)
{
    nm_str_buf_maybe_expand(strbuf, 3, FALSE);
    strbuf->_priv_str[strbuf->_priv_len++] = nm_hexchar(((guchar) ch) >> 4, upper_case);
    strbuf->_priv_str[strbuf->_priv_len++] = nm_hexchar((guchar) ch, upper_case);
}

static inline void
nm_str_buf_append_len(NMStrBuf *strbuf, const char *str, gsize len)
{
    _nm_str_buf_assert(strbuf);

    if (len > 0) {
        nm_str_buf_maybe_expand(strbuf, len + 1, FALSE);
        memcpy(&strbuf->_priv_str[strbuf->_priv_len], str, len);
        strbuf->_priv_len += len;
    }
}

static inline char *
nm_str_buf_append_len0(NMStrBuf *strbuf, const char *str, gsize len)
{
    _nm_str_buf_assert(strbuf);

    /* this is basically like nm_str_buf_append_len() and
     * nm_str_buf_get_str() in one. */

    nm_str_buf_maybe_expand(strbuf, len + 1u, FALSE);
    if (len > 0) {
        memcpy(&strbuf->_priv_str[strbuf->_priv_len], str, len);
        strbuf->_priv_len += len;
    }
    strbuf->_priv_str[strbuf->_priv_len] = '\0';
    return strbuf->_priv_str;
}

static inline void
nm_str_buf_append(NMStrBuf *strbuf, const char *str)
{
    nm_assert(str);

    nm_str_buf_append_len(strbuf, str, strlen(str));
}

static inline char *
nm_str_buf_append0(NMStrBuf *strbuf, const char *str)
{
    nm_assert(str);

    return nm_str_buf_append_len0(strbuf, str, strlen(str));
}

void nm_str_buf_append_printf(NMStrBuf *strbuf, const char *format, ...) _nm_printf(2, 3);

static inline void
nm_str_buf_ensure_trailing_c(NMStrBuf *strbuf, char ch)
{
    _nm_str_buf_assert(strbuf);

    if (strbuf->_priv_len == 0 || strbuf->_priv_str[strbuf->_priv_len - 1] != ch)
        nm_str_buf_append_c(strbuf, ch);
}

static inline NMStrBuf *
nm_str_buf_append_required_delimiter(NMStrBuf *strbuf, char delimiter)
{
    _nm_str_buf_assert(strbuf);

    /* appends the @delimiter if it is required (that is, if the
     * string is not empty). */
    if (strbuf->len > 0)
        nm_str_buf_append_c(strbuf, delimiter);
    return strbuf;
}

static inline void
nm_str_buf_append_dirty(NMStrBuf *strbuf, gsize len)
{
    _nm_str_buf_assert(strbuf);

    /* this append @len bytes to the buffer, but it does not
     * initialize them! */
    if (len > 0) {
        nm_str_buf_maybe_expand(strbuf, len, FALSE);
        strbuf->_priv_len += len;
    }
}

static inline void
nm_str_buf_append_c_len(NMStrBuf *strbuf, char ch, gsize len)
{
    _nm_str_buf_assert(strbuf);

    if (len > 0) {
        nm_str_buf_maybe_expand(strbuf, len, FALSE);
        memset(&strbuf->_priv_str[strbuf->_priv_len], ch, len);
        strbuf->_priv_len += len;
    }
}

/*****************************************************************************/

static inline NMStrBuf *
nm_str_buf_reset(NMStrBuf *strbuf)
{
    _nm_str_buf_assert(strbuf);

    if (strbuf->_priv_len > 0) {
        if (strbuf->_priv_do_bzero_mem) {
            /* we only clear the memory that we wrote to. */
            nm_explicit_bzero(strbuf->_priv_str, strbuf->_priv_len);
        }
        strbuf->_priv_len = 0;
    }

    return strbuf;
}

/*****************************************************************************/

/* Calls nm_utils_escaped_tokens_escape() on @str and appends the
 * result to @strbuf. */
static inline void
nm_utils_escaped_tokens_escape_strbuf(const char *str, const char *delimiters, NMStrBuf *strbuf)
{
    gs_free char *str_to_free = NULL;

    nm_assert(str);

    nm_str_buf_append(strbuf, nm_utils_escaped_tokens_escape(str, delimiters, &str_to_free));
}

/* Calls nm_utils_escaped_tokens_escape_unnecessary() on @str and appends the
 * string to @strbuf. */
static inline void
nm_utils_escaped_tokens_escape_strbuf_assert(const char *str,
                                             const char *delimiters,
                                             NMStrBuf *  strbuf)
{
    nm_str_buf_append(strbuf, nm_utils_escaped_tokens_escape_unnecessary(str, delimiters));
}

/*****************************************************************************/

static inline gboolean
nm_str_buf_is_initalized(NMStrBuf *strbuf)
{
    nm_assert(strbuf);
#if NM_MORE_ASSERTS
    if (strbuf->_priv_str)
        _nm_str_buf_assert(strbuf);
#endif
    return !!strbuf->_priv_str;
}

/**
 * nm_str_buf_get_str:
 * @strbuf: the #NMStrBuf instance
 *
 * Returns the NUL terminated internal string.
 *
 * While constructing the string, the intermediate buffer
 * is not NUL terminated (this makes it different from GString).
 * Usually, one would build the string and retrieve it at the
 * end with nm_str_buf_finalize(). This returns the NUL terminated
 * buffer that was appended so far. Contrary to nm_str_buf_finalize(), you
 * can still append more data to the buffer and this does not transfer ownership
 * of the string.
 *
 * Returns: (transfer none): the internal string. The string
 *   is of length "strbuf->len", which may be larger if the
 *   returned string contains NUL characters (binary). The terminating
 *   NUL character is always present after "strbuf->len" characters.
 *   If currently no buffer is allocated, this will return %NULL.
 */
static inline char *
nm_str_buf_get_str(NMStrBuf *strbuf)
{
    _nm_str_buf_assert(strbuf);

    if (!strbuf->_priv_str)
        return NULL;

    nm_str_buf_maybe_expand(strbuf, 1, FALSE);
    strbuf->_priv_str[strbuf->_priv_len] = '\0';
    return strbuf->_priv_str;
}

static inline char *
nm_str_buf_get_str_unsafe(NMStrBuf *strbuf)
{
    _nm_str_buf_assert(strbuf);
    return strbuf->_priv_str;
}

static inline char *
nm_str_buf_get_str_at_unsafe(NMStrBuf *strbuf, gsize index)
{
    _nm_str_buf_assert(strbuf);

    /* it is acceptable to ask for a pointer at the end of the buffer -- even
     * if there is no data there. The caller is anyway required to take care
     * of the length (that's the "unsafe" part), and in that case, the length
     * is merely zero. */
    nm_assert(index <= strbuf->allocated);

    if (!strbuf->_priv_str)
        return NULL;

    return &strbuf->_priv_str[index];
}

static inline char
nm_str_buf_get_char(const NMStrBuf *strbuf, gsize index)
{
    _nm_str_buf_assert(strbuf);
    nm_assert(index < strbuf->allocated);
    return strbuf->_priv_str[index];
}

/**
 * nm_str_buf_finalize:
 * @strbuf: an initilized #NMStrBuf
 * @out_len: (out): (allow-none): optional output
 *   argument with the length of the returned string.
 *
 * Returns: (transfer full): the string of the buffer
 *   which must be freed by the caller. The @strbuf
 *   is afterwards in undefined state, though it can be
 *   reused after nm_str_buf_init().
 *   Note that if no string is allocated yet (after nm_str_buf_init() with
 *   length zero), this will return %NULL. */
static inline char *
nm_str_buf_finalize(NMStrBuf *strbuf, gsize *out_len)
{
    _nm_str_buf_assert(strbuf);

    NM_SET_OUT(out_len, strbuf->_priv_len);

    if (!strbuf->_priv_str)
        return NULL;

    nm_str_buf_maybe_expand(strbuf, 1, TRUE);
    strbuf->_priv_str[strbuf->_priv_len] = '\0';

    /* the buffer is in invalid state afterwards, however, we clear it
     * so far, that nm_auto_str_buf and nm_str_buf_destroy() is happy.  */
    return g_steal_pointer(&strbuf->_priv_str);
}

static inline GBytes *
nm_str_buf_finalize_to_gbytes(NMStrBuf *strbuf)
{
    char *s;
    gsize l;

    /* this always returns a non-NULL, newly allocated GBytes instance.
     * The data buffer always has an additional NUL character after
     * the data, and the data is allocated with malloc.
     *
     * That means, the caller who takes ownership of the GBytes can
     * safely modify the content of the buffer (including the additional
     * NUL sentinel). */
    s = nm_str_buf_finalize(strbuf, &l);
    return g_bytes_new_take(s ?: g_new0(char, 1), l);
}

/**
 * nm_str_buf_destroy:
 * @strbuf: an initialized #NMStrBuf
 *
 * Frees the associated memory of @strbuf. The buffer
 * afterwards is in undefined state, but can be re-initialized
 * with nm_str_buf_init().
 */
static inline void
nm_str_buf_destroy(NMStrBuf *strbuf)
{
    if (!strbuf->_priv_str)
        return;
    _nm_str_buf_assert(strbuf);
    if (strbuf->_priv_do_bzero_mem)
        nm_explicit_bzero(strbuf->_priv_str, strbuf->_priv_len);
    g_free(strbuf->_priv_str);

    /* the buffer is in invalid state afterwards, however, we clear it
     * so far, that nm_auto_str_buf is happy when calling
     * nm_str_buf_destroy() again.  */
    strbuf->_priv_str = NULL;
}

#define nm_auto_str_buf nm_auto(nm_str_buf_destroy)

#endif /* __NM_STR_BUF_H__ */
