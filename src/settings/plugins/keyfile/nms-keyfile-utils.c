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

#include "nm-keyfile-internal.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-config.h"

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

