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

#define _NLE_BASE               100000
#define NLE_UNSPEC              (_NLE_BASE +  0)
#define NLE_BUG                 (_NLE_BASE +  1)
#define NLE_NATIVE_ERRNO        (_NLE_BASE +  2)
#define NLE_SEQ_MISMATCH        (_NLE_BASE +  3)
#define NLE_MSG_TRUNC           (_NLE_BASE +  4)
#define NLE_MSG_TOOSHORT        (_NLE_BASE +  5)
#define NLE_DUMP_INTR           (_NLE_BASE +  6)
#define NLE_ATTRSIZE            (_NLE_BASE +  7)
#define NLE_BAD_SOCK            (_NLE_BASE +  8)
#define NLE_NOADDR              (_NLE_BASE +  9)
#define NLE_MSG_OVERFLOW        (_NLE_BASE + 10)

#define _NLE_BASE_END           (_NLE_BASE + 11)

/*****************************************************************************/

static inline int
nl_errno (int nlerr)
{
	/* Normalizes an netlink error to be positive. Various API returns negative
	 * error codes, and this function converts the negative value to its
	 * positive.
	 *
	 * It's very similar to nm_errno(), but not exactly. The difference is that
	 * nm_errno() is for plain errno, while nl_errno() is for netlink error numbers.
	 * Yes, netlink error number are ~almost~ the same as errno, except that a particular
	 * range (_NLE_BASE, _NLE_BASE_END) is reserved. The difference between the two
	 * functions is only how G_MININT is mapped.
	 *
	 * See also nl_syserr2nlerr() below. */
	return nlerr >= 0
	       ? nlerr
	       : ((nlerr == G_MININT) ? NLE_BUG : -nlerr);
}

static inline int
nl_syserr2nlerr (int errsv)
{
	/* this maps a native errno to a (always non-negative) netlink error number.
	 *
	 * Note that netlink error numbers are embedded into the range of regular
	 * errno. The only difference is, that netlink error numbers reserve a
	 * range (_NLE_BASE, _NLE_BASE_END) for their own purpose.
	 *
	 * That means, converting an errno to netlink error number means in
	 * most cases just returning itself (negative values are normalized
	 * to be positive). Only values G_MININT and [_NLE_BASE, _NLE_BASE_END]
	 * are coerced to the special value NLE_NATIVE_ERRNO, as they cannot
	 * otherwise be represented in netlink error number domain. */
	if (errsv == G_MININT)
		return NLE_NATIVE_ERRNO;
	if (errsv < 0)
		errsv = -errsv;
	return (errsv >= _NLE_BASE && errsv < _NLE_BASE_END)
	       ? NLE_NATIVE_ERRNO
	       : errsv;
}

const char *nl_geterror (int nlerr);

/*****************************************************************************/

#endif /* __NM_ERRNO_H__ */
