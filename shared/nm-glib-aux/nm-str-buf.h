// SPDX-License-Identifier: LGPL-2.1+

#ifndef __NM_STR_BUF_H__
#define __NM_STR_BUF_H__

#include "nm-shared-utils.h"
#include "nm-secret-utils.h"

/*****************************************************************************/

/* NMStrBuf is not unlike GString. The main difference is that it can use
 * nm_explicit_bzero() when growing the buffer. */
typedef struct _NMStrBuf {
	char *_str;
	union {
		/*const*/ gsize len;
		gsize _len;
	};
	union {
		/*const*/ gsize allocated;
		gsize _allocated;
	};
	bool _do_bzero_mem;
} NMStrBuf;

/*****************************************************************************/

static inline void
_nm_str_buf_assert (NMStrBuf *strbuf)
{
	nm_assert (strbuf);
	nm_assert (strbuf->_str);
	nm_assert (strbuf->_allocated > 0);
	nm_assert (strbuf->_len <= strbuf->_allocated);
}

static inline void
nm_str_buf_init (NMStrBuf *strbuf,
                 gsize len,
                 bool do_bzero_mem)
{
	nm_assert (strbuf);
	nm_assert (len > 0);

	strbuf->_do_bzero_mem = do_bzero_mem;
	strbuf->_allocated    = len;
	strbuf->_str          = g_malloc (len);
	strbuf->_len          = 0;

	_nm_str_buf_assert (strbuf);
}

void _nm_str_buf_ensure_size (NMStrBuf *strbuf,
                              gsize new_size,
                              gboolean reserve_exact);

static inline void
nm_str_buf_maybe_expand (NMStrBuf *strbuf,
                         gsize reserve,
                         gboolean reserve_exact)
{
	_nm_str_buf_assert (strbuf);

	/* currently we always require to reserve a non-zero number of bytes. */
	nm_assert (reserve > 0);
	nm_assert (strbuf->_len < G_MAXSIZE - reserve);

	/* @reserve is the extra space that we require. */
	if (G_UNLIKELY (reserve > strbuf->_allocated - strbuf->_len))
		_nm_str_buf_ensure_size (strbuf, strbuf->_len + reserve, reserve_exact);
}

/*****************************************************************************/

/**
 * nm_str_buf_set_size:
 * @strbuf: the initialized #NMStrBuf
 * @new_len: the new length
 * @honor_do_bzero_mem: if %TRUE, the shrinked memory will be cleared, if
 *   do_bzero_mem is set. This should be usually set to %TRUE, unless
 *   you know that the shrinked memory does not contain data that requires to be
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
nm_str_buf_set_size (NMStrBuf *strbuf,
                     gsize new_len,
                     gboolean honor_do_bzero_mem,
                     gboolean reserve_exact)
{
	_nm_str_buf_assert (strbuf);

	if (new_len < strbuf->len) {
		if (   honor_do_bzero_mem
		    && strbuf->_do_bzero_mem) {
			/* we only clear the memory that we wrote to. */
			nm_explicit_bzero (&strbuf->_str[new_len], strbuf->_len - new_len);
		}
	} else if (new_len > strbuf->len) {
		nm_str_buf_maybe_expand (strbuf,
		                         new_len - strbuf->len + (reserve_exact ? 0u : 1u),
		                         reserve_exact);
	} else
		return;

	strbuf->_len = new_len;
}

/*****************************************************************************/

static inline void
nm_str_buf_append_c (NMStrBuf *strbuf,
                     char ch)
{
	nm_str_buf_maybe_expand (strbuf, 2, FALSE);
	strbuf->_str[strbuf->_len++] = ch;
}

static inline void
nm_str_buf_append_c2 (NMStrBuf *strbuf,
                      char ch0,
                      char ch1)
{
	nm_str_buf_maybe_expand (strbuf, 3, FALSE);
	strbuf->_str[strbuf->_len++] = ch0;
	strbuf->_str[strbuf->_len++] = ch1;
}

static inline void
nm_str_buf_append_c4 (NMStrBuf *strbuf,
                      char ch0,
                      char ch1,
                      char ch2,
                      char ch3)
{
	nm_str_buf_maybe_expand (strbuf, 5, FALSE);
	strbuf->_str[strbuf->_len++] = ch0;
	strbuf->_str[strbuf->_len++] = ch1;
	strbuf->_str[strbuf->_len++] = ch2;
	strbuf->_str[strbuf->_len++] = ch3;
}

static inline void
nm_str_buf_append_len (NMStrBuf *strbuf,
                       const char *str,
                       gsize len)
{
	_nm_str_buf_assert (strbuf);

	if (len > 0) {
		nm_str_buf_maybe_expand (strbuf, len + 1, FALSE);
		memcpy (&strbuf->_str[strbuf->_len], str, len);
		strbuf->_len += len;
	}
}

static inline void
nm_str_buf_append (NMStrBuf *strbuf,
                   const char *str)
{
	nm_assert (str);

	nm_str_buf_append_len (strbuf, str, strlen (str));
}

void nm_str_buf_append_printf (NMStrBuf *strbuf,
                               const char *format,
                               ...) _nm_printf (2, 3);

static inline void
nm_str_buf_ensure_trailing_c (NMStrBuf *strbuf, char ch)
{
	_nm_str_buf_assert (strbuf);

	if (   strbuf->len == 0
	    || strbuf->_str[strbuf->len - 1] != ch)
		nm_str_buf_append_c (strbuf, ch);
}

/*****************************************************************************/

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
 */
static inline const char *
nm_str_buf_get_str (NMStrBuf *strbuf)
{
	nm_str_buf_maybe_expand (strbuf, 1, FALSE);
	strbuf->_str[strbuf->_len] = '\0';
	return strbuf->_str;
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
 *   reused after nm_str_buf_init(). */
static inline char *
nm_str_buf_finalize (NMStrBuf *strbuf,
                     gsize *out_len)
{
	nm_str_buf_maybe_expand (strbuf, 1, TRUE);
	strbuf->_str[strbuf->_len] = '\0';

	NM_SET_OUT (out_len, strbuf->_len);

	/* the buffer is in invalid state afterwards, however, we clear it
	 * so far, that nm_auto_str_buf and nm_str_buf_destroy() is happy.  */
	return g_steal_pointer (&strbuf->_str);
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
nm_str_buf_destroy (NMStrBuf *strbuf)
{
	if (!strbuf->_str)
		return;
	_nm_str_buf_assert (strbuf);
	if (strbuf->_do_bzero_mem)
		nm_explicit_bzero (strbuf->_str, strbuf->_len);
	g_free (strbuf->_str);

	/* the buffer is in invalid state afterwards, however, we clear it
	 * so far, that nm_auto_str_buf is happy when calling
	 * nm_str_buf_destroy() again.  */
	strbuf->_str = NULL;
}

#define nm_auto_str_buf    nm_auto (nm_str_buf_destroy)

#endif /* __NM_STR_BUF_H__ */
