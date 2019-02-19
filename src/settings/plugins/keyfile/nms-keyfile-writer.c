/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nms-keyfile-writer.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nm-keyfile-internal.h"

#include "nms-keyfile-utils.h"
#include "nms-keyfile-reader.h"

#include "nm-utils/nm-io-utils.h"

/*****************************************************************************/

typedef struct {
	const char *keyfile_dir;
} WriteInfo;

static void
cert_writer (NMConnection *connection,
             GKeyFile *file,
             NMKeyfileWriteTypeDataCert *cert_data,
             WriteInfo *info,
             GError **error)
{
	const char *setting_name = nm_setting_get_name (NM_SETTING (cert_data->setting));
	NMSetting8021xCKScheme scheme;
	NMSetting8021xCKFormat format;
	const char *path = NULL, *ext = "pem";

	scheme = cert_data->vtable->scheme_func (cert_data->setting);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		char *tmp = NULL;
		const char *accepted_path = NULL;

		path = cert_data->vtable->path_func (cert_data->setting);
		g_assert (path);

		if (g_str_has_prefix (path, info->keyfile_dir)) {
			const char *p = path + strlen (info->keyfile_dir);

			/* If the path is rooted in the keyfile directory, just use a
			 * relative path instead of an absolute one.
			 */
			if (*p == '/') {
				while (*p == '/')
					p++;
				if (p[0]) {
					/* If @p looks like an integer list, the following detection will fail too and
					 * we will file:// qualify the path below. We thus avoid writing a path string
					 * that would be interpreted as legacy binary format by reader. */
					tmp = nm_keyfile_detect_unqualified_path_scheme (info->keyfile_dir, p, -1, FALSE, NULL);
					if (tmp) {
						g_clear_pointer (&tmp, g_free);
						accepted_path = p;
					}
				}
			}
		}
		if (!accepted_path) {
			/* What we are about to write, must also be understood by the reader.
			 * Otherwise, add a file:// prefix */
			tmp = nm_keyfile_detect_unqualified_path_scheme (info->keyfile_dir, path, -1, FALSE, NULL);
			if (tmp) {
				g_clear_pointer (&tmp, g_free);
				accepted_path = path;
			}
		}

		if (!accepted_path)
			accepted_path = tmp = g_strconcat (NM_KEYFILE_CERT_SCHEME_PREFIX_PATH, path, NULL);
		nm_keyfile_plugin_kf_set_string (file, setting_name, cert_data->vtable->setting_key, accepted_path);
		g_free (tmp);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PKCS11) {
		nm_keyfile_plugin_kf_set_string (file, setting_name, cert_data->vtable->setting_key,
		                                 cert_data->vtable->uri_func (cert_data->setting));
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		GBytes *blob;
		const guint8 *blob_data;
		gsize blob_len;
		gboolean success;
		GError *local = NULL;
		char *new_path;

		blob = cert_data->vtable->blob_func (cert_data->setting);
		g_assert (blob);
		blob_data = g_bytes_get_data (blob, &blob_len);

		if (cert_data->vtable->format_func) {
			/* Get the extension for a private key */
			format = cert_data->vtable->format_func (cert_data->setting);
			if (format == NM_SETTING_802_1X_CK_FORMAT_PKCS12)
				ext = "p12";
		} else {
			/* DER or PEM format certificate? */
			if (blob_len > 2 && blob_data[0] == 0x30 && blob_data[1] == 0x82)
				ext = "der";
		}

		/* Write the raw data out to the standard file so that we can use paths
		 * from now on instead of pushing around the certificate data.
		 */
		new_path = g_strdup_printf ("%s/%s-%s.%s", info->keyfile_dir, nm_connection_get_uuid (connection),
		                            cert_data->vtable->file_suffix, ext);

		success = nm_utils_file_set_contents (new_path, (const char *) blob_data,
		                                      blob_len, 0600, &local);
		if (success) {
			/* Write the path value to the keyfile.
			 * We know, that basename(new_path) starts with a UUID, hence no conflict with "data:;base64,"  */
			nm_keyfile_plugin_kf_set_string (file, setting_name, cert_data->vtable->setting_key, strrchr (new_path, '/') + 1);
		} else {
			nm_log_warn (LOGD_SETTINGS, "keyfile: %s.%s: failed to write certificate to file %s: %s",
			             setting_name, cert_data->vtable->setting_key, new_path, local->message);
			g_error_free (local);
		}
		g_free (new_path);
	} else {
		/* scheme_func() returns UNKNOWN in all other cases. The only valid case
		 * where a scheme is allowed to be UNKNOWN, is unsetting the value. In this
		 * case, we don't expect the writer to be called, because the default value
		 * will not be serialized.
		 * The only other reason for the scheme to be UNKNOWN is an invalid cert.
		 * But our connection verifies, so that cannot happen either. */
		g_return_if_reached ();
	}
}

static gboolean
_handler_write (NMConnection *connection,
                GKeyFile *keyfile,
                NMKeyfileWriteType type,
                void *type_data,
                void *user_data,
                GError **error)
{
	if (type == NM_KEYFILE_WRITE_TYPE_CERT) {
		cert_writer (connection, keyfile,
		             (NMKeyfileWriteTypeDataCert *) type_data,
		             (WriteInfo *) user_data, error);
		return TRUE;
	}
	return FALSE;
}

static gboolean
_internal_write_connection (NMConnection *connection,
                            const char *keyfile_dir,
                            const char *profile_dir,
                            gboolean with_extension,
                            uid_t owner_uid,
                            pid_t owner_grp,
                            const char *existing_path,
                            gboolean existing_path_read_only,
                            gboolean force_rename,
                            char **out_path,
                            NMConnection **out_reread,
                            gboolean *out_reread_same,
                            GError **error)
{
	gs_unref_keyfile GKeyFile *kf_file = NULL;
	gs_free char *kf_content_buf = NULL;
	gsize kf_content_len;
	gs_free char *path = NULL;
	const char *id;
	WriteInfo info = { 0 };
	GError *local_err = NULL;
	int errsv;
	gboolean rename;

	g_return_val_if_fail (!out_path || !*out_path, FALSE);
	g_return_val_if_fail (keyfile_dir && keyfile_dir[0] == '/', FALSE);

	rename =    force_rename
	         || existing_path_read_only
	         || (   existing_path
	             && !nm_utils_file_is_in_path (existing_path, keyfile_dir));

	switch (_nm_connection_verify (connection, error)) {
	case NM_SETTING_VERIFY_NORMALIZABLE:
		nm_assert_not_reached ();
		/* fall-through */
	case NM_SETTING_VERIFY_SUCCESS:
		break;
	default:
		g_return_val_if_reached (FALSE);
	}

	id = nm_connection_get_id (connection);
	g_assert (id && *id);

	info.keyfile_dir = keyfile_dir;

	kf_file = nm_keyfile_write (connection, _handler_write, &info, error);
	if (!kf_file)
		return FALSE;
	kf_content_buf = g_key_file_to_data (kf_file, &kf_content_len, error);
	if (!kf_content_buf)
		return FALSE;

	if (!g_file_test (keyfile_dir, G_FILE_TEST_IS_DIR))
		(void) g_mkdir_with_parents (keyfile_dir, 0755);

	/* If we have existing file path, use it. Else generate one from
	 * connection's ID.
	 */
	if (   existing_path
	    && !rename)
		path = g_strdup (existing_path);
	else {
		gs_free char *filename_escaped = NULL;

		filename_escaped = nm_keyfile_utils_create_filename (id, with_extension);
		path = g_build_filename (keyfile_dir, filename_escaped, NULL);
	}

	/* If a file with this path already exists (but isn't the existing path
	 * of the connection) then we need another name.  Multiple connections
	 * can have the same ID (ie if two connections with the same ID are visible
	 * to different users) but of course can't have the same path.  Yeah,
	 * there's a race here, but there's not a lot we can do about it, and
	 * we shouldn't get more than one connection with the same UUID either.
	 */
	if (   !nm_streq0 (path, existing_path)
	    && g_file_test (path, G_FILE_TEST_EXISTS)) {
		guint i;
		gboolean name_found = FALSE;

		/* A keyfile with this connection's ID already exists. Pick another name. */
		for (i = 0; i < 100; i++) {
			gs_free char *filename_escaped = NULL;
			gs_free char *filename = NULL;

			if (i == 0)
				filename = g_strdup_printf ("%s-%s", id, nm_connection_get_uuid (connection));
			else
				filename = g_strdup_printf ("%s-%s-%u", id, nm_connection_get_uuid (connection), i);

			filename_escaped = nm_keyfile_utils_create_filename (filename, with_extension);

			g_free (path);
			path = g_strdup_printf ("%s/%s", keyfile_dir, filename_escaped);

			if (   nm_streq0 (path, existing_path)
			    || !g_file_test (path, G_FILE_TEST_EXISTS)) {
				name_found = TRUE;
				break;
			}
		}
		if (!name_found) {
			if (existing_path_read_only || !existing_path) {
				/* this really should not happen, we tried hard to find an unused name... bail out. */
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
				                    "could not find suitable keyfile file name (%s already used)", path);
				return FALSE;
			}
			/* Both our preferred path based on connection id and id-uuid are taken.
			 * Fallback to @existing_path */
			g_free (path);
			path = g_strdup (existing_path);
		}
	}

	nm_utils_file_set_contents (path, kf_content_buf, kf_content_len, 0600, &local_err);
	if (local_err) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "error writing to file '%s': %s",
		             path, local_err->message);
		g_error_free (local_err);
		return FALSE;
	}

	if (chown (path, owner_uid, owner_grp) < 0) {
		errsv = errno;
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "error chowning '%s': %s (%d)",
		             path, nm_strerror_native (errsv), errsv);
		unlink (path);
		return FALSE;
	}

	/* In case of updating the connection and changing the file path,
	 * we need to remove the old one, not to end up with two connections.
	 */
	if (   existing_path
	    && !existing_path_read_only
	    && !nm_streq (path, existing_path))
		unlink (existing_path);

	if (out_reread || out_reread_same) {
		gs_unref_object NMConnection *reread = NULL;
		gboolean reread_same = FALSE;

		reread = nms_keyfile_reader_from_keyfile (kf_file, path, NULL, profile_dir, FALSE, NULL);

		nm_assert (NM_IS_CONNECTION (reread));

		if (   reread
		    && !nm_connection_normalize (reread, NULL, NULL, NULL)) {
			nm_assert_not_reached ();
			g_clear_object (&reread);
		}

		if (reread && out_reread_same) {
			reread_same = !!nm_connection_compare (reread, connection, NM_SETTING_COMPARE_FLAG_EXACT);

			nm_assert (reread_same == nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));
			nm_assert (reread_same == ({
			                                gs_unref_hashtable GHashTable *_settings = NULL;

			                                (   nm_connection_diff (reread, connection, NM_SETTING_COMPARE_FLAG_EXACT, &_settings)
			                                 && !_settings);
			                           }));
		}

		NM_SET_OUT (out_reread, g_steal_pointer (&reread));
		NM_SET_OUT (out_reread_same, reread_same);
	}

	NM_SET_OUT (out_path, g_steal_pointer (&path));

	return TRUE;
}

gboolean
nms_keyfile_writer_connection (NMConnection *connection,
                               gboolean save_to_disk,
                               const char *existing_path,
                               gboolean force_rename,
                               char **out_path,
                               NMConnection **out_reread,
                               gboolean *out_reread_same,
                               GError **error)
{
	const char *keyfile_dir;

	if (save_to_disk)
		keyfile_dir = nms_keyfile_utils_get_path ();
	else
		keyfile_dir = NM_KEYFILE_PATH_NAME_RUN;

	return _internal_write_connection (connection,
	                                   keyfile_dir,
	                                   nms_keyfile_utils_get_path (),
	                                   TRUE,
	                                   0,
	                                   0,
	                                   existing_path,
	                                   FALSE,
	                                   force_rename,
	                                   out_path,
	                                   out_reread,
	                                   out_reread_same,
	                                   error);
}

gboolean
nms_keyfile_writer_test_connection (NMConnection *connection,
                                    const char *keyfile_dir,
                                    uid_t owner_uid,
                                    pid_t owner_grp,
                                    char **out_path,
                                    NMConnection **out_reread,
                                    gboolean *out_reread_same,
                                    GError **error)
{
	return _internal_write_connection (connection,
	                                   keyfile_dir,
	                                   keyfile_dir,
	                                   FALSE,
	                                   owner_uid,
	                                   owner_grp,
	                                   NULL,
	                                   FALSE,
	                                   FALSE,
	                                   out_path,
	                                   out_reread,
	                                   out_reread_same,
	                                   error);
}

