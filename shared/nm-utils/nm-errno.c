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

	NM_UTILS_LOOKUP_ITEM (NME_UNSPEC,          "NME_UNSPEC"),
	NM_UTILS_LOOKUP_ITEM (NME_BUG,             "NME_BUG"),
	NM_UTILS_LOOKUP_ITEM (NME_NATIVE_ERRNO,    "NME_NATIVE_ERRNO"),

	NM_UTILS_LOOKUP_ITEM (NME_NL_ATTRSIZE,     "NME_NL_ATTRSIZE"),
	NM_UTILS_LOOKUP_ITEM (NME_NL_BAD_SOCK,     "NME_NL_BAD_SOCK"),
	NM_UTILS_LOOKUP_ITEM (NME_NL_DUMP_INTR,    "NME_NL_DUMP_INTR"),
	NM_UTILS_LOOKUP_ITEM (NME_NL_MSG_OVERFLOW, "NME_NL_MSG_OVERFLOW"),
	NM_UTILS_LOOKUP_ITEM (NME_NL_MSG_TOOSHORT, "NME_NL_MSG_TOOSHORT"),
	NM_UTILS_LOOKUP_ITEM (NME_NL_MSG_TRUNC,    "NME_NL_MSG_TRUNC"),
	NM_UTILS_LOOKUP_ITEM (NME_NL_SEQ_MISMATCH, "NME_NL_SEQ_MISMATCH"),
)

const char *
nm_strerror (int nmerr)
{
	const char *s;

	nmerr = nl_errno (nmerr);

	if (nmerr >= _NLE_BASE) {
		s = _geterror (nmerr);
		if (s)
			return s;
	}
	return g_strerror (nmerr);
}
