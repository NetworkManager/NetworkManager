/* This library is free software; you can redistribute it and/or
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
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-sd-utils-shared.h"

#include "nm-sd-adapt-shared.h"

#include "path-util.h"
#include "hexdecoct.h"

/*****************************************************************************/

gboolean
nm_sd_utils_path_equal (const char *a, const char *b)
{
	return path_equal (a, b);
}

char *
nm_sd_utils_path_simplify (char *path, gboolean kill_dots)
{
	return path_simplify (path, kill_dots);
}

const char *
nm_sd_utils_path_startswith (const char *path, const char *prefix)
{
	return path_startswith (path, prefix);
}

/*****************************************************************************/

gboolean
nm_sd_utils_unbase64char (char ch, gboolean accept_padding_equal)
{
	if (   ch == '='
	    && accept_padding_equal)
		return G_MAXINT;
	return unbase64char (ch);
}

/**
 * nm_sd_utils_unbase64mem:
 * @p: a valid base64 string. Whitespace is ignored, but invalid encodings
 *   will cause the function to fail.
 * @l: the length of @p. @p is not treated as NUL terminated string but
 *   merely as a buffer of ascii characters.
 * @secure: whether the temporary memory will be cleared to avoid leaving
 *   secrets in memory (see also nm_explict_bzero()).
 * @mem: (transfer full): the decoded buffer on success.
 * @len: the length of @mem on success.
 *
 * glib provides g_base64_decode(), but that does not report any errors
 * from invalid encodings. Expose systemd's implementation which does
 * reject invalid inputs.
 *
 * Returns: a non-negative code on success. Invalid encoding let the
 *   function fail.
 */
int
nm_sd_utils_unbase64mem (const char *p,
                         size_t l,
                         gboolean secure,
                         guint8 **mem,
                         size_t *len)
{
	return unbase64mem_full (p, l, secure, (void **) mem, len);
}
