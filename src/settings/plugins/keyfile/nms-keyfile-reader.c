/* NetworkManager system settings service - keyfile plugin
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
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nms-keyfile-reader.h"

#include <sys/stat.h>

#include "nm-keyfile-internal.h"

#include "NetworkManagerUtils.h"
#include "nms-keyfile-utils.h"

/*****************************************************************************/

static const char *
_fmt_warn (const char *group, NMSetting *setting, const char *property_name, const char *message, char **out_message)
{
	const char *setting_name = setting ? nm_setting_get_name (setting) : NULL;

	if (group) {
		char *res;

		if (setting_name) {
			if (property_name && !strcmp (group, setting_name))
				res = g_strdup_printf ("%s.%s: %s", group, property_name, message);
			else if (property_name)
				res = g_strdup_printf ("%s/%s.%s: %s", group, setting_name, property_name, message);
			else if (!strcmp (group, setting_name))
				res = g_strdup_printf ("%s: %s", group, message);
			else
				res = g_strdup_printf ("%s/%s: %s", group, setting_name, message);
		} else
			res = g_strdup_printf ("%s: %s", group, message);
		*out_message = res;
		return res;
	} else
		return message;
}

typedef struct {
	bool verbose;
} HandlerReadData;

static gboolean
_handler_read (GKeyFile *keyfile,
               NMConnection *connection,
               NMKeyfileReadType type,
               void *type_data,
               void *user_data,
               GError **error)
{
	const HandlerReadData *handler_data = user_data;

	if (type == NM_KEYFILE_READ_TYPE_WARN) {
		NMKeyfileReadTypeDataWarn *warn_data = type_data;
		NMLogLevel level;
		char *message_free = NULL;

		if (!handler_data->verbose)
			return TRUE;

		if (warn_data->severity > NM_KEYFILE_WARN_SEVERITY_WARN)
			level = LOGL_ERR;
		else if (warn_data->severity >= NM_KEYFILE_WARN_SEVERITY_WARN)
			level = LOGL_WARN;
		else if (warn_data->severity == NM_KEYFILE_WARN_SEVERITY_INFO_MISSING_FILE)
			level = LOGL_WARN;
		else
			level = LOGL_INFO;

		nm_log (level, LOGD_SETTINGS, NULL,
		        nm_connection_get_uuid (connection),
		        "keyfile: %s",
		        _fmt_warn (warn_data->group, warn_data->setting,
		                   warn_data->property_name, warn_data->message,
		                   &message_free));
		g_free (message_free);
		return TRUE;
	}
	return FALSE;
}

NMConnection *
nms_keyfile_reader_from_keyfile (GKeyFile *key_file,
                                 const char *filename,
                                 const char *base_dir,
                                 const char *profile_dir,
                                 gboolean verbose,
                                 GError **error)
{
	NMConnection *connection;
	HandlerReadData data = {
		.verbose = verbose,
	};
	gs_free char *base_dir_free = NULL;
	gs_free char *profile_filename_free = NULL;
	gs_free char *filename_id = NULL;
	const char *profile_filename = NULL;

	nm_assert (filename && filename[0]);
	nm_assert (!base_dir || base_dir[0] == '/');
	nm_assert (!profile_dir || profile_dir[0] == '/');

	if (base_dir)
		nm_assert (!strchr (filename, '/'));
	else {
		const char *s;

		nm_assert (filename[0] == '/');

		/* @base_dir may be NULL, in which case @filename must be an absolute path,
		 * and the directory is taken as the @base_dir. */
		s = strrchr (filename, '/');
		base_dir = nm_strndup_a (255, filename, s - filename, &base_dir_free);
		if (   !profile_dir
		    || nm_streq (base_dir, profile_dir))
			profile_filename = filename;
		filename = &s[1];
	}

	connection = nm_keyfile_read (key_file, base_dir, _handler_read, &data, error);
	if (!connection)
		return NULL;

	if (g_str_has_suffix (filename, NM_KEYFILE_PATH_SUFFIX_NMCONNECTION)) {
		gsize l = strlen (filename);

		if (l > NM_STRLEN (NM_KEYFILE_PATH_SUFFIX_NMCONNECTION))
			filename_id = g_strndup (filename, l - NM_STRLEN (NM_KEYFILE_PATH_SUFFIX_NMCONNECTION));
	}

	nm_keyfile_read_ensure_id (connection, filename_id ?: filename);

	if (!profile_filename) {
		profile_filename_free = g_build_filename (profile_dir ?: base_dir, filename, NULL);
		profile_filename = profile_filename_free;
	}
	nm_keyfile_read_ensure_uuid (connection, profile_filename);

	return connection;
}

NMConnection *
nms_keyfile_reader_from_file (const char *full_filename,
                              const char *profile_dir,
                              struct stat *out_stat,
                              NMTernary *out_is_nm_generated,
                              NMTernary *out_is_volatile,
                              char **out_shadowed_storage,
                              NMTernary *out_shadowed_owned,
                              GError **error)
{
	gs_unref_keyfile GKeyFile *key_file = NULL;
	NMConnection *connection = NULL;
	GError *verify_error = NULL;

	nm_assert (full_filename && full_filename[0] == '/');
	nm_assert (!profile_dir || profile_dir[0] == '/');

	NM_SET_OUT (out_is_nm_generated, NM_TERNARY_DEFAULT);
	NM_SET_OUT (out_is_volatile, NM_TERNARY_DEFAULT);

	if (!nms_keyfile_utils_check_file_permissions (NMS_KEYFILE_FILETYPE_KEYFILE,
	                                               full_filename,
	                                               out_stat,
	                                               error))
		return NULL;

	key_file = g_key_file_new ();
	if (!g_key_file_load_from_file (key_file, full_filename, G_KEY_FILE_NONE, error))
		return NULL;

	connection = nms_keyfile_reader_from_keyfile (key_file, full_filename, NULL, profile_dir, TRUE, error);
	if (!connection)
		return NULL;

	/* Normalize and verify the connection */
	if (!nm_connection_normalize (connection, NULL, NULL, &verify_error)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "invalid connection: %s",
		             verify_error->message);
		g_clear_error (&verify_error);
		g_object_unref (connection);
		connection = NULL;
	}

	NM_SET_OUT (out_is_nm_generated, nm_key_file_get_boolean (key_file,
	                                                          NM_KEYFILE_GROUP_NMMETA,
	                                                          NM_KEYFILE_KEY_NMMETA_NM_GENERATED,
	                                                          NM_TERNARY_DEFAULT));

	NM_SET_OUT (out_is_volatile, nm_key_file_get_boolean (key_file,
	                                                      NM_KEYFILE_GROUP_NMMETA,
	                                                      NM_KEYFILE_KEY_NMMETA_VOLATILE,
	                                                      NM_TERNARY_DEFAULT));

	NM_SET_OUT (out_shadowed_storage, g_key_file_get_string (key_file,
	                                                         NM_KEYFILE_GROUP_NMMETA,
	                                                         NM_KEYFILE_KEY_NMMETA_SHADOWED_STORAGE,
	                                                         NULL));

	NM_SET_OUT (out_shadowed_owned, nm_key_file_get_boolean (key_file,
	                                                         NM_KEYFILE_GROUP_NMMETA,
	                                                         NM_KEYFILE_KEY_NMMETA_SHADOWED_OWNED,
	                                                         NM_TERNARY_DEFAULT));

	return connection;
}

