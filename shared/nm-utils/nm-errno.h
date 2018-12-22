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

enum {
	_NM_ERRNO_MININT         = G_MININT,
	_NM_ERRNO_MAXINT         = G_MAXINT,
	_NM_ERRNO_RESERVED_FIRST = 100000,

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

static inline int
nm_errno_native (int errsv)
{
	/* several API returns negative errno values as errors. Normalize
	 * negative values to positive values.
	 *
	 * As a special case, map G_MININT to G_MAXINT. If you care about the
	 * distinction, then check for G_MININT before.
	 *
	 * Basically, this normalizes a plain errno to be non-negative. */
	return errsv >= 0
	       ? errsv
	       : ((errsv == G_MININT) ? G_MAXINT : -errsv);
}

static inline int
nm_errno (int nmerr)
{
	/* Normalizes an nm-error to be positive. Various API returns negative
	 * error codes, and this function converts the negative value to its
	 * positive.
	 *
	 * It's very similar to nm_errno_native(), but not exactly. The difference is that
	 * nm_errno_native() is for plain errno, while nm_errno() is for nm-error numbers.
	 * Yes, nm-error number are ~almost~ the same as errno, except that a particular
	 * range (_NM_ERRNO_RESERVED_FIRST, _NM_ERRNO_RESERVED_LAST) is reserved. The difference
	 * between the two functions is only how G_MININT is mapped.
	 *
	 * See also nm_errno_from_native() below. */
	return nmerr >= 0
	       ? nmerr
	       : ((nmerr == G_MININT) ? NME_BUG : -nmerr);
}

static inline int
nm_errno_from_native (int errsv)
{
	/* this maps a native errno to a (always non-negative) nm-error number.
	 *
	 * Note that nm-error numbers are embedded into the range of regular
	 * errno. The only difference is, that nm-error numbers reserve a
	 * range (_NM_ERRNO_RESERVED_FIRST, _NM_ERRNO_RESERVED_LAST) for their
	 * own purpose.
	 *
	 * That means, converting an errno to nm-error number means in
	 * most cases just returning itself (negative values are normalized
	 * to be positive). Only values G_MININT and [_NM_ERRNO_RESERVED_FIRST, _NM_ERRNO_RESERVED_LAST]
	 * are coerced to the special value NME_NATIVE_ERRNO, as they cannot
	 * otherwise be represented in nm-error number domain. */
	if (errsv < 0) {
		return   G_UNLIKELY (errsv == G_MININT)
		       ? NME_NATIVE_ERRNO
		       : -errsv;
	}
	return   G_UNLIKELY (   errsv >= _NM_ERRNO_RESERVED_FIRST
	                     && errsv <= _NM_ERRNO_RESERVED_LAST)
	       ? NME_NATIVE_ERRNO
	       : errsv;
}

const char *nm_strerror (int nmerr);

/*****************************************************************************/

#endif /* __NM_ERRNO_H__ */
