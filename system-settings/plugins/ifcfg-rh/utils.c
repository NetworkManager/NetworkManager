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
#include "sha1.h"
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

char *
utils_hash_byte_array (const GByteArray *data)
{
	unsigned char buf[SHA1_MAC_LEN];
	static const char *key = "0123456789abcdefghijklmnopqrstuvwxyz";

	memset (buf, 0, sizeof (buf));
	sha1_mac ((const unsigned char *) key, strlen (key), (const u_int8_t *) data->data, data->len, &buf[0]);
	return utils_bin2hexstr ((const char *) &buf[0], SHA1_MAC_LEN, SHA1_MAC_LEN * 2);
}

char *
utils_cert_path (const char *parent, const char *suffix)
{
	char *name, *dir, *path;

	name = utils_get_ifcfg_name (parent);
	dir = g_path_get_dirname (parent);
	path = g_strdup_printf ("%s/%s-%s", dir, name, suffix);
	g_free (dir);
	g_free (name);
	return path;
}

char *
utils_get_ifcfg_name (const char *file)
{
	char *ifcfg_name;
	char *basename;

	basename = g_path_get_basename (file);
	if (!basename)
		return NULL;

	ifcfg_name = g_strdup (basename + strlen (IFCFG_TAG));
	g_free (basename);
	return ifcfg_name;
}

char *
utils_get_keys_path (const char *parent)
{
	char *ifcfg_name;
	char *keys_file = NULL;
	char *tmp = NULL;

	ifcfg_name = utils_get_ifcfg_name (parent);
	if (!ifcfg_name)
		return NULL;

	tmp = g_path_get_dirname (parent);
	if (!tmp)
		goto out;

	keys_file = g_strdup_printf ("%s/" KEYS_TAG "%s", tmp, ifcfg_name);

out:
	g_free (tmp);
	g_free (ifcfg_name);
	return keys_file;
}

shvarFile *
utils_get_keys_ifcfg (const char *parent, gboolean should_create)
{
	shvarFile *ifcfg = NULL;
	char *path;

	path = utils_get_keys_path (parent);
	if (!path)
		return NULL;

	if (should_create && !g_file_test (path, G_FILE_TEST_EXISTS))
		ifcfg = svCreateFile (path);

	if (!ifcfg)
		ifcfg = svNewFile (path);

	g_free (path);
	return ifcfg;
}

