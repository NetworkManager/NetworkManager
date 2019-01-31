/* NetworkManager -- Network link manager
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-errno.h"

#include <pthread.h>

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (_geterror,
#if 0
	enum _NMErrno,
#else
	int,
#endif
	NM_UTILS_LOOKUP_DEFAULT (NULL),

	NM_UTILS_LOOKUP_STR_ITEM (NME_ERRNO_SUCCESS,      "NME_ERRNO_SUCCESS"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_ERRNO_OUT_OF_RANGE, "NME_ERRNO_OUT_OF_RANGE"),

	NM_UTILS_LOOKUP_STR_ITEM (NME_UNSPEC,             "NME_UNSPEC"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_BUG,                "NME_BUG"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_NATIVE_ERRNO,       "NME_NATIVE_ERRNO"),

	NM_UTILS_LOOKUP_STR_ITEM (NME_NL_ATTRSIZE,        "NME_NL_ATTRSIZE"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_NL_BAD_SOCK,        "NME_NL_BAD_SOCK"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_NL_DUMP_INTR,       "NME_NL_DUMP_INTR"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_NL_MSG_OVERFLOW,    "NME_NL_MSG_OVERFLOW"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_NL_MSG_TOOSHORT,    "NME_NL_MSG_TOOSHORT"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_NL_MSG_TRUNC,       "NME_NL_MSG_TRUNC"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_NL_SEQ_MISMATCH,    "NME_NL_SEQ_MISMATCH"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_NL_NOADDR,          "NME_NL_NOADDR"),

	NM_UTILS_LOOKUP_STR_ITEM (NME_PL_NOT_FOUND,       "not-found"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_PL_EXISTS,          "exists"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_PL_WRONG_TYPE,      "wrong-type"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_PL_NOT_SLAVE,       "not-slave"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_PL_NO_FIRMWARE,     "no-firmware"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_PL_OPNOTSUPP,       "not-supported"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_PL_NETLINK,         "netlink"),
	NM_UTILS_LOOKUP_STR_ITEM (NME_PL_CANT_SET_MTU,    "cant-set-mtu"),

	NM_UTILS_LOOKUP_ITEM_IGNORE (_NM_ERRNO_MININT),
	NM_UTILS_LOOKUP_ITEM_IGNORE (_NM_ERRNO_RESERVED_LAST_PLUS_1),
);

/**
 * nm_strerror():
 * @nmerr: the NetworkManager specific errno to be converted
 *   to string.
 *
 * NetworkManager specific error numbers reserve a range in "errno.h" with
 * our own defines. For numbers that don't fall into this range, the numbers
 * are identical to the common error numbers.
 *
 * Idential to strerror(), g_strerror(), nm_strerror_native() for error numbers
 * that are not in the reserved range of NetworkManager specific errors.
 *
 * Returns: (transfer none): the string representation of the error number.
 */
const char *
nm_strerror (int nmerr)
{
	const char *s;

	nmerr = nm_errno (nmerr);

	if (nmerr >= _NM_ERRNO_RESERVED_FIRST) {
		s = _geterror (nmerr);
		if (s)
			return s;
	}
	return nm_strerror_native (nmerr);
}

/*****************************************************************************/

/**
 * nm_strerror_native_r:
 * @errsv: the errno to convert to string.
 * @buf: the output buffer where to write the string to.
 * @buf_size: the length of buffer.
 *
 * This is like strerror_r(), with one difference: depending on the
 * locale, the returned string is guaranteed to be valid UTF-8.
 * Also, there is some confusion as to whether to use glibc's
 * strerror_r() or the POXIX/XSI variant. This is abstracted
 * by the function.
 *
 * Note that the returned buffer may also be a statically allocated
 * buffer, and not the input buffer @buf. Consequently, the returned
 * string may be longer than @buf_size.
 *
 * Returns: (transfer none): a NUL terminated error message. This is either a static
 *   string (that is never freed), or the provided @buf argumnt.
 */
const char *
nm_strerror_native_r (int errsv, char *buf, gsize buf_size)
{
	char *buf2;

	nm_assert (buf);
	nm_assert (buf_size > 0);

#if (_POSIX_C_SOURCE >= 200112L) && !  _GNU_SOURCE
	/* XSI-compliant */
	{
		int errno_saved = errno;

		if (strerror_r (errsv, buf, buf_size) != 0) {
			g_snprintf (buf, buf_size, "Unspecified errno %d", errsv);
			errno = errno_saved;
		}
		buf2 = buf;
	}
#else
	/* GNU-specific */
	buf2 = strerror_r (errsv, buf, buf_size);
#endif

	/* like g_strerror(), ensure that the error message is UTF-8. */
	if (   !g_get_charset (NULL)
	    && !g_utf8_validate (buf2, -1, NULL)) {
		gs_free char *msg = NULL;

		msg = g_locale_to_utf8 (buf2, -1, NULL, NULL, NULL);
		if (msg) {
			g_strlcpy (buf, msg, buf_size);
			buf2 = buf;
		}
	}

	return buf2;
}

/**
 * nm_strerror_native:
 * @errsv: the errno integer from <errno.h>
 *
 * Like strerror(), but strerror() is not thread-safe and not guaranteed
 * to be UTF-8.
 *
 * g_strerror() is a thread-safe variant of strerror(), however it caches
 * all returned strings in a dictionary. That means, using this on untrusted
 * error numbers can result in this cache to grow without limits.
 *
 * Instead, return a tread-local buffer. This way, it's thread-safe.
 *
 * There is a downside to this: subsequent calls of nm_strerror_native()
 * overwrite the error message.
 *
 * Returns: (transfer none): the text representation of the error number.
 */
const char *
nm_strerror_native (int errsv)
{
	static _nm_thread_local char *buf_static = NULL;
	char *buf;

	buf = buf_static;
	if (G_UNLIKELY (!buf)) {
		int errno_saved = errno;
		pthread_key_t key;

		buf = g_malloc (NM_STRERROR_BUFSIZE);
		buf_static = buf;

		if (   pthread_key_create (&key, g_free) != 0
		    || pthread_setspecific (key, buf) != 0) {
			/* Failure. We will leak the buffer when the thread exits.
			 *
			 * Nothing we can do about it really. For Debug builds we fail with an assertion. */
			nm_assert_not_reached ();
		}
		errno = errno_saved;
	}

	return nm_strerror_native_r (errsv, buf, NM_STRERROR_BUFSIZE);
}
