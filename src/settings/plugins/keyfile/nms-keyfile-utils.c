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
 * (C) Copyright 2010 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nms-keyfile-utils.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-config.h"

#define NM_CONFIG_KEYFILE_PATH_DEFAULT NMCONFDIR "/system-connections"

/*****************************************************************************/

static const char temp_letters[] =
"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/*
 * Check '.[a-zA-Z0-9]{6}' file suffix used for temporary files by g_file_set_contents() (mkstemp()).
 */
static gboolean
check_mkstemp_suffix (const char *path)
{
	const char *ptr;

	g_return_val_if_fail (path != NULL, FALSE);

	/* Matches *.[a-zA-Z0-9]{6} suffix of mkstemp()'s temporary files */
	ptr = strrchr (path, '.');
	if (ptr && (strspn (ptr + 1, temp_letters) == 6) && (! ptr[7]))
		return TRUE;
	return FALSE;
}

static gboolean
check_prefix_dot (const char *base)
{
	nm_assert (base && base[0]);

	return base[0] == '.';
}

static gboolean
check_suffix (const char *base, const char *tag)
{
	int len, tag_len;

	g_return_val_if_fail (base != NULL, TRUE);
	g_return_val_if_fail (tag != NULL, TRUE);

	len = strlen (base);
	tag_len = strlen (tag);
	if ((len > tag_len) && !g_ascii_strcasecmp (base + len - tag_len, tag))
		return TRUE;
	return FALSE;
}

#define SWP_TAG ".swp"
#define SWPX_TAG ".swpx"
#define PEM_TAG ".pem"
#define DER_TAG ".der"

gboolean
nms_keyfile_utils_should_ignore_file (const char *filename, gboolean require_extension)
{
	gs_free char *base = NULL;

	g_return_val_if_fail (filename != NULL, TRUE);

	base = g_path_get_basename (filename);
	g_return_val_if_fail (base != NULL, TRUE);

	/* Ignore hidden and backup files */
	/* should_ignore_file() must mirror escape_filename() */
	if (check_prefix_dot (base) || check_suffix (base, "~"))
		return TRUE;
	/* Ignore temporary files */
	if (check_mkstemp_suffix (base))
		return TRUE;
	/* Ignore 802.1x certificates and keys */
	if (check_suffix (base, PEM_TAG) || check_suffix (base, DER_TAG))
		return TRUE;

	if (require_extension) {
		gsize l = strlen (base);

		if (   l <= NM_STRLEN (NMS_KEYFILE_PATH_SUFFIX_NMCONNECTION)
		    || !g_str_has_suffix (base, NMS_KEYFILE_PATH_SUFFIX_NMCONNECTION))
			return TRUE;
	}

	return FALSE;
}

/*****************************************************************************/

gboolean
nms_keyfile_utils_check_file_permissions_stat (const struct stat *st,
                                               GError **error)
{
	g_return_val_if_fail (st, FALSE);

	if (!S_ISREG (st->st_mode)) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "file is not a regular file");
		return FALSE;
	}

	if (!NM_FLAGS_HAS (nm_utils_get_testing (), NM_UTILS_TEST_NO_KEYFILE_OWNER_CHECK)) {
		if (st->st_uid != 0) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "File owner (%lld) is insecure",
			             (long long) st->st_uid);
			return FALSE;
		}

		if (st->st_mode & 0077) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "File permissions (%03o) are insecure",
			             st->st_mode);
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
nms_keyfile_utils_check_file_permissions (const char *filename,
                                          struct stat *out_st,
                                          GError **error)
{
	struct stat st;
	int errsv;

	g_return_val_if_fail (filename && filename[0] == '/', FALSE);

	if (stat (filename, &st) != 0) {
		errsv = errno;
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "cannot access file: %s", g_strerror (errsv));
		return FALSE;
	}

	if (!nms_keyfile_utils_check_file_permissions_stat (&st, error))
		return FALSE;

	NM_SET_OUT (out_st, st);
	return TRUE;
}

/*****************************************************************************/

char *
nms_keyfile_utils_escape_filename (const char *filename,
                                   gboolean with_extension)
{
	GString *str;
	const char *f = filename;
	/* keyfile used to escape with '*', do not change that behavior.
	 *
	 * But for newly added escapings, use '_' instead.
	 * Also, @with_extension is new-style. */
	const char ESCAPE_CHAR = with_extension ? '_' : '*';
	const char ESCAPE_CHAR2 = '_';

	g_return_val_if_fail (filename && filename[0], NULL);

	str = g_string_sized_new (60);

	/* Convert '/' to ESCAPE_CHAR */
	for (f = filename; f[0]; f++) {
		if (f[0] == '/')
			g_string_append_c (str, ESCAPE_CHAR);
		else
			g_string_append_c (str, f[0]);
	}

	/* escape_filename() must avoid anything that should_ignore_file() would reject.
	 * We can escape here more aggressivly then what we would read back. */
	if (check_prefix_dot (str->str))
		str->str[0] = ESCAPE_CHAR2;
	if (check_suffix (str->str, "~"))
		str->str[str->len - 1] = ESCAPE_CHAR2;
	if (   check_mkstemp_suffix (str->str)
	    || check_suffix (str->str, PEM_TAG)
	    || check_suffix (str->str, DER_TAG))
		g_string_append_c (str, ESCAPE_CHAR2);

	if (with_extension)
		g_string_append (str, NMS_KEYFILE_PATH_SUFFIX_NMCONNECTION);

	return g_string_free (str, FALSE);;
}

/*****************************************************************************/

const char *
nms_keyfile_utils_get_path (void)
{
	static char *path = NULL;

	if (G_UNLIKELY (!path)) {
		path = nm_config_data_get_value (NM_CONFIG_GET_DATA_ORIG,
		                                 NM_CONFIG_KEYFILE_GROUP_KEYFILE,
		                                 NM_CONFIG_KEYFILE_KEY_KEYFILE_PATH,
		                                 NM_CONFIG_GET_VALUE_STRIP | NM_CONFIG_GET_VALUE_NO_EMPTY);
		if (!path)
			path = g_strdup (""NM_CONFIG_KEYFILE_PATH_DEFAULT"");
	}
	return path;
}

