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
#include <sys/stat.h>

#include "nm-keyfile-internal.h"
#include "nm-utils.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-config.h"

/*****************************************************************************/

char *
nms_keyfile_loaded_uuid_filename (const char *dirname,
                                  const char *uuid,
                                  gboolean temporary)
{
	char filename[250];

	nm_assert (dirname && dirname[0] == '/');
	nm_assert (uuid && nm_utils_is_uuid (uuid) && !strchr (uuid, '/'));

	if (g_snprintf (filename,
	                sizeof (filename),
	                "%s%s%s%s",
	                NM_KEYFILE_PATH_PREFIX_NMLOADED,
	                uuid,
	                NM_KEYFILE_PATH_SUFFIX_NMCONNECTION,
	                temporary ? "~" : "") >= sizeof (filename)) {
		/* valid uuids are limited in length. The buffer should always be large
		 * enough. */
		nm_assert_not_reached ();
		return NULL;
	}

	return g_build_filename (dirname, filename, NULL);
}

gboolean
nms_keyfile_loaded_uuid_read (const char *dirname,
                              const char *filename,
                              char **out_full_filename,
                              char **out_uuid,
                              char **out_loaded_path)
{
	const char *uuid;
	const char *tmp;
	gsize len;
	gs_free char *full_filename = NULL;
	gs_free char *ln = NULL;

	nm_assert (dirname && dirname[0] == '/');
	nm_assert (filename && filename[0] && !strchr (filename, '/'));

	if (filename[0] != '.') {
		/* the hidden-uuid filename must start with '.'. That is,
		 * so that it does not conflict with regular keyfiles according
		 * to nm_keyfile_utils_ignore_filename(). */
		return FALSE;
	}

	len = strlen (filename);
	if (   len <= NM_STRLEN (NM_KEYFILE_PATH_PREFIX_NMLOADED)
	    || memcmp (filename, NM_KEYFILE_PATH_PREFIX_NMLOADED, NM_STRLEN (NM_KEYFILE_PATH_PREFIX_NMLOADED)) != 0) {
		/* the filename does not have the right prefix. */
		return FALSE;
	}

	tmp = &filename[NM_STRLEN (NM_KEYFILE_PATH_PREFIX_NMLOADED)];
	len -= NM_STRLEN (NM_KEYFILE_PATH_PREFIX_NMLOADED);

	if (   len <= NM_STRLEN (NM_KEYFILE_PATH_SUFFIX_NMCONNECTION)
	    || memcmp (&tmp[len - NM_STRLEN (NM_KEYFILE_PATH_SUFFIX_NMCONNECTION)],
	               NM_KEYFILE_PATH_SUFFIX_NMCONNECTION,
	               NM_STRLEN (NM_KEYFILE_PATH_SUFFIX_NMCONNECTION)) != 0) {
		/* the file does not have the right suffix. */
		return FALSE;
	}
	len -= NM_STRLEN (NM_KEYFILE_PATH_SUFFIX_NMCONNECTION);

	if (!NM_IN_SET (len, 36, 40)) {
		/* the remaining part of the filename has not the right length to
		 * contain a UUID (according to nm_utils_is_uuid()). */
		return FALSE;
	}

	uuid = nm_strndup_a (100, tmp, len, NULL);
	if (!nm_utils_is_uuid (uuid))
		return FALSE;

	full_filename = g_build_filename (dirname, filename, NULL);

	if (!nms_keyfile_utils_check_file_permissions (NMS_KEYFILE_FILETYPE_NMLOADED,
	                                               full_filename,
	                                               NULL,
	                                               NULL))
		return FALSE;

	ln = nm_utils_read_link_absolute (full_filename, NULL);
	if (!ln)
		return FALSE;

	NM_SET_OUT (out_uuid, g_strdup (uuid));
	NM_SET_OUT (out_full_filename, g_steal_pointer (&full_filename));
	NM_SET_OUT (out_loaded_path, g_steal_pointer (&ln));
	return TRUE;
}

gboolean
nms_keyfile_loaded_uuid_read_from_file (const char *full_filename,
                                        char **out_dirname,
                                        char **out_filename,
                                        char **out_uuid,
                                        char **out_loaded_path)
{
	gs_free char *dirname = NULL;
	gs_free char *filename = NULL;

	nm_assert (full_filename && full_filename[0] == '/');

	filename = g_path_get_basename (full_filename);
	dirname = g_path_get_dirname (full_filename);

	if (!nms_keyfile_loaded_uuid_read (dirname,
	                                   filename,
	                                   NULL,
	                                   out_uuid,
	                                   out_loaded_path))
		return FALSE;

	NM_SET_OUT (out_dirname, g_steal_pointer (&dirname));
	NM_SET_OUT (out_filename, g_steal_pointer (&filename));
	return TRUE;
}

gboolean
nms_keyfile_loaded_uuid_write (const char *dirname,
                               const char *uuid,
                               const char *loaded_path,
                               gboolean allow_relative,
                               char **out_full_filename)
{
	gs_free char *full_filename_tmp = NULL;
	gs_free char *full_filename = NULL;

	nm_assert (dirname && dirname[0] == '/');
	nm_assert (uuid && nm_utils_is_uuid (uuid) && !strchr (uuid, '/'));
	nm_assert (!loaded_path || loaded_path[0] == '/');

	full_filename_tmp = nms_keyfile_loaded_uuid_filename (dirname, uuid, TRUE);

	nm_assert (g_str_has_suffix (full_filename_tmp, "~"));
	nm_assert (nm_utils_file_is_in_path (full_filename_tmp, dirname));

	(void) unlink (full_filename_tmp);

	if (!loaded_path) {
		gboolean success = TRUE;

		full_filename_tmp[strlen (full_filename_tmp) - 1] = '\0';
		if (unlink (full_filename_tmp) != 0)
			success = NM_IN_SET (errno, ENOENT);
		NM_SET_OUT (out_full_filename, g_steal_pointer (&full_filename_tmp));
		return success;
	}

	if (allow_relative) {
		const char *f;

		f = nm_utils_file_is_in_path (loaded_path, dirname);
		if (f) {
			/* @loaded_path points to a file directly in @dirname.
			 * Don't use absolute paths. */
			loaded_path = f;
		}
	}

	if (symlink (loaded_path, full_filename_tmp) != 0) {
		full_filename_tmp[strlen (full_filename_tmp) - 1] = '\0';
		NM_SET_OUT (out_full_filename, g_steal_pointer (&full_filename_tmp));
		return FALSE;
	}

	full_filename = g_strdup (full_filename_tmp);
	full_filename[strlen (full_filename) - 1] = '\0';
	if (rename (full_filename_tmp, full_filename) != 0) {
		(void) unlink (full_filename_tmp);
		NM_SET_OUT (out_full_filename, g_steal_pointer (&full_filename));
		return FALSE;
	}

	NM_SET_OUT (out_full_filename, g_steal_pointer (&full_filename));
	return TRUE;
}

/*****************************************************************************/

gboolean
nms_keyfile_utils_check_file_permissions_stat (NMSKeyfileFiletype filetype,
                                               const struct stat *st,
                                               GError **error)
{
	g_return_val_if_fail (st, FALSE);

	if (filetype == NMS_KEYFILE_FILETYPE_KEYFILE) {
		if (!S_ISREG (st->st_mode)) {
			g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			                     "file is not a regular file");
			return FALSE;
		}
	} else if (filetype == NMS_KEYFILE_FILETYPE_NMLOADED) {
		if (!S_ISLNK (st->st_mode)) {
			g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			                     "file is not a slink");
			return FALSE;
		}
	} else
		g_return_val_if_reached (FALSE);

	if (!NM_FLAGS_HAS (nm_utils_get_testing (), NM_UTILS_TEST_NO_KEYFILE_OWNER_CHECK)) {
		if (st->st_uid != 0) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "File owner (%lld) is insecure",
			             (long long) st->st_uid);
			return FALSE;
		}

		if (   filetype == NMS_KEYFILE_FILETYPE_KEYFILE
		    && (st->st_mode & 0077)) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "File permissions (%03o) are insecure",
			             st->st_mode);
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
nms_keyfile_utils_check_file_permissions (NMSKeyfileFiletype filetype,
                                          const char *filename,
                                          struct stat *out_st,
                                          GError **error)
{
	struct stat st;
	int errsv;

	g_return_val_if_fail (filename && filename[0] == '/', FALSE);

	if (filetype == NMS_KEYFILE_FILETYPE_KEYFILE) {
		if (stat (filename, &st) != 0) {
			errsv = errno;
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "cannot access file: %s", nm_strerror_native (errsv));
			return FALSE;
		}
	} else if (filetype == NMS_KEYFILE_FILETYPE_NMLOADED) {
		if (lstat (filename, &st) != 0) {
			errsv = errno;
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "cannot access file: %s", nm_strerror_native (errsv));
			return FALSE;
		}
	} else
		g_return_val_if_reached (FALSE);

	if (!nms_keyfile_utils_check_file_permissions_stat (filetype, &st, error))
		return FALSE;

	NM_SET_OUT (out_st, st);
	return TRUE;
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
			path = g_strdup (""NM_KEYFILE_PATH_NAME_ETC_DEFAULT"");
	}
	return path;
}

