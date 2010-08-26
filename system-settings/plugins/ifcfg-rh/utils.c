/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2008 - 2009 Red Hat, Inc.
 */

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "shvar.h"

/*
 * utils_bin2hexstr
 *
 * Convert a byte-array into a hexadecimal string.
 *
 * Code originally by Alex Larsson <alexl@redhat.com> and
 *  copyright Red Hat, Inc. under terms of the LGPL.
 *
 */
char *
utils_bin2hexstr (const char *bytes, int len, int final_len)
{
	static char hex_digits[] = "0123456789abcdef";
	char *result;
	int i;
	gsize buflen = (len * 2) + 1;

	g_return_val_if_fail (bytes != NULL, NULL);
	g_return_val_if_fail (len > 0, NULL);
	g_return_val_if_fail (len < 4096, NULL);   /* Arbitrary limit */
	if (final_len > -1)
		g_return_val_if_fail (final_len < buflen, NULL);

	result = g_malloc0 (buflen);
	for (i = 0; i < len; i++)
	{
		result[2*i] = hex_digits[(bytes[i] >> 4) & 0xf];
		result[2*i+1] = hex_digits[bytes[i] & 0xf];
	}
	/* Cut converted key off at the correct length for this cipher type */
	if (final_len > -1)
		result[final_len] = '\0';
	else
		result[buflen - 1] = '\0';

	return result;
}

/* From hostap, Copyright (c) 2002-2005, Jouni Malinen <jkmaline@cc.hut.fi> */

static int hex2num (char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int hex2byte (const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

char *
utils_hexstr2bin (const char *hex, size_t len)
{
	size_t       i;
	int          a;
	const char * ipos = hex;
	char *       buf = NULL;
	char *       opos;

	/* Length must be a multiple of 2 */
	if ((len % 2) != 0)
		return NULL;

	opos = buf = g_malloc0 ((len / 2) + 1);
	for (i = 0; i < len; i += 2) {
		a = hex2byte (ipos);
		if (a < 0) {
			g_free (buf);
			return NULL;
		}
		*opos++ = a;
		ipos += 2;
	}
	return buf;
}

/* End from hostap */

static gboolean
check_suffix (const char *base, const char *tag)
{
	int len, tag_len;

	g_return_val_if_fail (base != NULL, TRUE);
	g_return_val_if_fail (tag != NULL, TRUE);

	len = strlen (base);
	tag_len = strlen (tag);
	if ((len > tag_len) && !strcasecmp (base + len - tag_len, tag))
		return TRUE;
	return FALSE;
}

gboolean
utils_should_ignore_file (const char *filename, gboolean only_ifcfg)
{
	char *base;
	gboolean ignore = TRUE;
	gboolean is_ifcfg = FALSE;
	gboolean is_other = FALSE;

	g_return_val_if_fail (filename != NULL, TRUE);

	base = g_path_get_basename (filename);
	g_return_val_if_fail (base != NULL, TRUE);

	/* Only handle ifcfg, keys, and routes files */
	if (!strncmp (base, IFCFG_TAG, strlen (IFCFG_TAG)))
		is_ifcfg = TRUE;

	if (only_ifcfg == FALSE) {
		if (   !strncmp (base, KEYS_TAG, strlen (KEYS_TAG))
		    || !strncmp (base, ROUTE_TAG, strlen (ROUTE_TAG))
		    || !strncmp (base, ROUTE6_TAG, strlen (ROUTE6_TAG)))
				is_other = TRUE;
	}

	/* But not those that have certain suffixes */
	if (   (is_ifcfg || is_other)
	    && !check_suffix (base, BAK_TAG)
	    && !check_suffix (base, TILDE_TAG)
	    && !check_suffix (base, ORIG_TAG)
	    && !check_suffix (base, REJ_TAG)
	    && !check_suffix (base, RPMNEW_TAG)
	    && !check_suffix (base, AUGNEW_TAG)
	    && !check_suffix (base, AUGTMP_TAG))
		ignore = FALSE;

	g_free (base);
	return ignore;
}

char *
utils_cert_path (const char *parent, const char *suffix)
{
	const char *name;
	char *dir, *path;

	g_return_val_if_fail (parent != NULL, NULL);
	g_return_val_if_fail (suffix != NULL, NULL);

	name = utils_get_ifcfg_name (parent, FALSE);
	dir = g_path_get_dirname (parent);
	path = g_strdup_printf ("%s/%s-%s", dir, name, suffix);
	g_free (dir);
	return path;
}

const char *
utils_get_ifcfg_name (const char *file, gboolean only_ifcfg)
{
	const char *name = NULL, *start = NULL;
	char *base;

	g_return_val_if_fail (file != NULL, NULL);

	base = g_path_get_basename (file);
	if (!base)
		return NULL;

	/* Find the point in 'file' where 'base' starts.  We use 'file' since it's
	 * const and thus will survive after we free 'base'.
	 */
	start = file + strlen (file) - strlen (base);
	g_assert (strcmp (start, base) == 0);
	g_free (base);

	if (!strncmp (start, IFCFG_TAG, strlen (IFCFG_TAG)))
		name = start + strlen (IFCFG_TAG);
	else if (only_ifcfg == FALSE)  {
		if (!strncmp (start, KEYS_TAG, strlen (KEYS_TAG)))
			name = start + strlen (KEYS_TAG);
		else if (!strncmp (start, ROUTE_TAG, strlen (ROUTE_TAG)))
			name = start + strlen (ROUTE_TAG);
		else if (!strncmp (start, ROUTE6_TAG, strlen (ROUTE6_TAG)))
			name = start + strlen (ROUTE6_TAG);
	}

	return name;
}

/* Used to get any ifcfg/extra file path from any other ifcfg/extra path
 * in the form <tag><name>.
 */
static char *
utils_get_extra_path (const char *parent, const char *tag)
{
	char *item_path = NULL, *dirname;
	const char *name;

	g_return_val_if_fail (parent != NULL, NULL);
	g_return_val_if_fail (tag != NULL, NULL);

	dirname = g_path_get_dirname (parent);
	if (!dirname)
		return NULL;

	name = utils_get_ifcfg_name (parent, FALSE);
	if (name) {
		if (!strcmp (dirname, "."))
			item_path = g_strdup_printf ("%s%s", tag, name);
		else
			item_path = g_strdup_printf ("%s/%s%s", dirname, tag, name);
	}
	g_free (dirname);

	return item_path;
}

char *
utils_get_ifcfg_path (const char *parent)
{
	return utils_get_extra_path (parent, IFCFG_TAG);
}

char *
utils_get_keys_path (const char *parent)
{
	return utils_get_extra_path (parent, KEYS_TAG);
}

char *
utils_get_route_path (const char *parent)
{
	return utils_get_extra_path (parent, ROUTE_TAG);
}

char *
utils_get_route6_path (const char *parent)
{
	return utils_get_extra_path (parent, ROUTE6_TAG);
}

shvarFile *
utils_get_extra_ifcfg (const char *parent, const char *tag, gboolean should_create)
{
	shvarFile *ifcfg = NULL;
	char *path;

	path = utils_get_extra_path (parent, tag);
	if (!path)
		return NULL;

	if (should_create && !g_file_test (path, G_FILE_TEST_EXISTS))
		ifcfg = svCreateFile (path);

	if (!ifcfg)
		ifcfg = svNewFile (path);

	g_free (path);
	return ifcfg;
}

shvarFile *
utils_get_keys_ifcfg (const char *parent, gboolean should_create)
{
	return utils_get_extra_ifcfg (parent, KEYS_TAG, should_create);
}

shvarFile *
utils_get_route_ifcfg (const char *parent, gboolean should_create)
{
	return utils_get_extra_ifcfg (parent, ROUTE_TAG, should_create);
}

shvarFile *
utils_get_route6_ifcfg (const char *parent, gboolean should_create)
{
	return utils_get_extra_ifcfg (parent, ROUTE6_TAG, should_create);
}

/* Finds out if route file has new or older format
 * Returns TRUE  - new syntax (ADDRESS<n>=a.b.c.d ...), error opening file or empty
 *         FALSE - older syntax, i.e. argument to 'ip route add' (1.2.3.0/24 via 11.22.33.44)
 */
gboolean
utils_has_route_file_new_syntax (const char *filename)
{
	char *contents = NULL;
	gsize len = 0;
	gboolean ret = FALSE;
	const char *pattern = "^[[:space:]]*ADDRESS[0-9]+=";

	g_return_val_if_fail (filename != NULL, TRUE);

	if (!g_file_get_contents (filename, &contents, &len, NULL))
		return TRUE;

	if (len <= 0) {
		ret = TRUE;
		goto gone;
	}

	if (g_regex_match_simple (pattern, contents, G_REGEX_MULTILINE, 0))
		ret = TRUE;

gone:
	g_free (contents);
	return ret;
}

