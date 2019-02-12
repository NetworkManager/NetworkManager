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

#ifndef __NM_ERRNO_H__
#define __NM_ERRNO_H__

#include <errno.h>

/*****************************************************************************/

enum _NMErrno {
	_NM_ERRNO_MININT         = G_MININT,
	_NM_ERRNO_MAXINT         = G_MAXINT,
	_NM_ERRNO_RESERVED_FIRST = 100000,


	/* when we cannot represent a number as positive number, we resort to this
	 * number. Basically, the values G_MININT, -NME_ERRNO_SUCCESS, NME_ERRNO_SUCCESS
	 * and G_MAXINT all map to the same value. */
	NME_ERRNO_OUT_OF_RANGE   = G_MAXINT,

	/* Indicate that the original errno was zero. Zero denotes *no error*, but we know something
	 * went wrong and we want to report some error. This is a placeholder to mean, something
	 * was wrong, but errno was zero. */
	NME_ERRNO_SUCCESS        = G_MAXINT - 1,


	/* an unspecified error. */
	NME_UNSPEC = _NM_ERRNO_RESERVED_FIRST,

	/* A bug, for example when an assertion failed.
	 * Should never happen. */
	NME_BUG,

	/* a native error number (from <errno.h>) cannot be mapped as
	 * an nm-error, because it is in the range [_NM_ERRNO_RESERVED_FIRST,
	 * _NM_ERRNO_RESERVED_LAST]. */
	NME_NATIVE_ERRNO,

	/* netlink errors. */
	NME_NL_SEQ_MISMATCH,
	NME_NL_MSG_TRUNC,
	NME_NL_MSG_TOOSHORT,
	NME_NL_DUMP_INTR,
	NME_NL_ATTRSIZE,
	NME_NL_BAD_SOCK,
	NME_NL_NOADDR,
	NME_NL_MSG_OVERFLOW,

	/* platform errors. */
	NME_PL_NOT_FOUND,
	NME_PL_EXISTS,
	NME_PL_WRONG_TYPE,
	NME_PL_NOT_SLAVE,
	NME_PL_NO_FIRMWARE,
	NME_PL_OPNOTSUPP,
	NME_PL_NETLINK,
	NME_PL_CANT_SET_MTU,

	_NM_ERRNO_RESERVED_LAST_PLUS_1,
	_NM_ERRNO_RESERVED_LAST = _NM_ERRNO_RESERVED_LAST_PLUS_1 - 1,
};

/*****************************************************************************/

/* When we receive an errno from a system function, we can safely assume
 * that the error number is not negative. We rely on that, and possibly just
 * "return -errsv;" to signal an error. We also rely on that, because libc
 * is our trusted base: meaning, if it cannot even succeed at setting errno
 * according to specification, all bets are off.
 *
 * This macro returns the input argument, and asserts that the error variable
 * is positive.
 *
 * In a sense, the macro is related to nm_errno_native() function, but the difference
 * is that this macro asserts that @errsv is positive, while nm_errno_native() coerces
 * negative values to be non-negative. */
#define NM_ERRNO_NATIVE(errsv) \
	({ \
		const int _errsv_x = (errsv); \
		\
		nm_assert (_errsv_x > 0); \
		_errsv_x; \
	})

/* Normalize native errno.
 *
 * Our API may return native error codes (<errno.h>) as negative values. This function
 * takes such an errno, and normalizes it to their positive value.
 *
 * The special values G_MININT and zero are coerced to NME_ERRNO_OUT_OF_RANGE and NME_ERRNO_SUCCESS
 * respectively.
 * Other values are coerced to their inverse.
 * Other positive values are returned unchanged.
 *
 * Basically, this normalizes errsv to be positive (taking care of two pathological cases).
 */
static inline int
nm_errno_native (int errsv)
{
	switch (errsv) {
	case 0:                  return NME_ERRNO_SUCCESS;
	case G_MININT:           return NME_ERRNO_OUT_OF_RANGE;
	default:
		return errsv >= 0 ? errsv : -errsv;
	}
}

/* Normalizes an nm-error to be positive.
 *
 * Various API returns negative error codes, and this function converts the negative
 * value to its positive.
 *
 * Note that @nmerr is on the domain of NetworkManager specific error numbers,
 * which is not the same as the native error numbers (errsv from <errno.h>). But
 * as far as normalizing goes, nm_errno() does exactly the same remapping as
 * nm_errno_native(). */
static inline int
nm_errno (int nmerr)
{
	return nm_errno_native (nmerr);
}

/* this maps a native errno to a (always non-negative) nm-error number.
 *
 * Note that nm-error numbers are embedded into the range of regular
 * errno. The only difference is, that nm-error numbers reserve a
 * range (_NM_ERRNO_RESERVED_FIRST, _NM_ERRNO_RESERVED_LAST) for their
 * own purpose.
 *
 * That means, converting an errno to nm-error number means in
 * most cases just returning itself.
 * Only pathological cases need special handling:
 *
 *  - 0 is mapped to NME_ERRNO_SUCCESS;
 *  - G_MININT is mapped to NME_ERRNO_OUT_OF_RANGE;
 *  - values in the range of (+/-) [_NM_ERRNO_RESERVED_FIRST, _NM_ERRNO_RESERVED_LAST]
 *    are mapped to NME_NATIVE_ERRNO
 *  - all other values are their (positive) absolute value.
 */
static inline int
nm_errno_from_native (int errsv)
{
	switch (errsv) {
	case 0:                  return NME_ERRNO_SUCCESS;
	case G_MININT:           return NME_ERRNO_OUT_OF_RANGE;
	default:
		if (errsv < 0)
			errsv = -errsv;
		return   G_UNLIKELY (   errsv >= _NM_ERRNO_RESERVED_FIRST
		                     && errsv <= _NM_ERRNO_RESERVED_LAST)
		       ? NME_NATIVE_ERRNO
		       : errsv;
	}
}

const char *nm_strerror (int nmerr);

/*****************************************************************************/

#define NM_STRERROR_BUFSIZE 1024

const char *nm_strerror_native_r (int errsv, char *buf, gsize buf_size);
const char *nm_strerror_native (int errsv);

/*****************************************************************************/

#endif /* __NM_ERRNO_H__ */
