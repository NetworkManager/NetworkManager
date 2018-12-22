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

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (_geterror, int,
	NM_UTILS_LOOKUP_DEFAULT (NULL),
	NM_UTILS_LOOKUP_ITEM (NLE_UNSPEC,          "NLE_UNSPEC"),
	NM_UTILS_LOOKUP_ITEM (NLE_BUG,             "NLE_BUG"),
	NM_UTILS_LOOKUP_ITEM (NLE_NATIVE_ERRNO,    "NLE_NATIVE_ERRNO"),

	NM_UTILS_LOOKUP_ITEM (NLE_ATTRSIZE,        "NLE_ATTRSIZE"),
	NM_UTILS_LOOKUP_ITEM (NLE_BAD_SOCK,        "NLE_BAD_SOCK"),
	NM_UTILS_LOOKUP_ITEM (NLE_DUMP_INTR,       "NLE_DUMP_INTR"),
	NM_UTILS_LOOKUP_ITEM (NLE_MSG_OVERFLOW,    "NLE_MSG_OVERFLOW"),
	NM_UTILS_LOOKUP_ITEM (NLE_MSG_TOOSHORT,    "NLE_MSG_TOOSHORT"),
	NM_UTILS_LOOKUP_ITEM (NLE_MSG_TRUNC,       "NLE_MSG_TRUNC"),
	NM_UTILS_LOOKUP_ITEM (NLE_SEQ_MISMATCH,    "NLE_SEQ_MISMATCH"),
)

const char *
nl_geterror (int nlerr)
{
	const char *s;

	nlerr = nl_errno (nlerr);

	if (nlerr >= _NLE_BASE) {
		s = _geterror (nlerr);
		if (s)
			return s;
	}
	return g_strerror (nlerr);
}
