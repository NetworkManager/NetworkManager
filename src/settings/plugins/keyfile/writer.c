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

#include "config.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "nm-glib-compat.h"

#include "nm-logging.h"
#include "writer.h"
#include "common.h"
#include "utils.h"
#include "nm-keyfile-internal.h"
#include "gsystem-local-alloc.h"


typedef struct {
	const char *keyfile_dir;
} WriteInfo;


static gboolean
write_cert_key_file (const char *path,
                     const guint8 *data,
                     gsize data_len,
                     GError **error)
{
	char *tmppath;
	int fd = -1, written;
	gboolean success = FALSE;

	tmppath = g_malloc0 (strlen (path) + 10);
	g_assert (tmppath);
	memcpy (tmppath, path, strlen (path));
	strcat (tmppath, ".XXXXXX");

	errno = 0;
	fd = mkstemp (tmppath);
	if (fd < 0) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not create temporary file for '%s': %d",
		             path, errno);
		goto out;
	}

	/* Only readable by root */
	errno = 0;
	if (fchmod (fd, S_IRUSR | S_IWUSR) != 0) {
		close (fd);
		unlink (tmppath);
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not set permissions for temporary file '%s': %d",
		             path, errno);
		goto out;
	}

	errno = 0;
	written = write (fd, data, data_len);
	if (written != data_len) {
		close (fd);
		unlink (tmppath);
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not write temporary file for '%s': %d",
		             path, errno);
		goto out;
	}
	close (fd);

	/* Try to rename */
	errno = 0;
	if (rename (tmppath, path) == 0)
		success = TRUE;
	else {
		unlink (tmppath);
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not rename temporary file to '%s': %d",
		             path, errno);
	}

out:
	g_free (tmppath);
	return success;
}

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

	scheme = cert_data->scheme_func (cert_data->setting);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		char *tmp = NULL;
		const char *accepted_path = NULL;

		path = cert_data->path_func (cert_data->setting);
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
		nm_keyfile_plugin_kf_set_string (file, setting_name, cert_data->property_name, accepted_path);
		g_free (tmp);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		GBytes *blob;
		const guint8 *blob_data;
		gsize blob_len;
		gboolean success;
		GError *local = NULL;
		char *new_path;

		blob = cert_data->blob_func (cert_data->setting);
		g_assert (blob);
		blob_data = g_bytes_get_data (blob, &blob_len);

		if (cert_data->format_func) {
			/* Get the extension for a private key */
			format = cert_data->format_func (cert_data->setting);
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
		                            cert_data->suffix, ext);

		success = write_cert_key_file (new_path, blob_data, blob_len, &local);
		if (success) {
			/* Write the path value to the keyfile.
			 * We know, that basename(new_path) starts with a UUID, hence no conflict with "data:;base64,"  */
			nm_keyfile_plugin_kf_set_string (file, setting_name, cert_data->property_name, strrchr (new_path, '/') + 1);
		} else {
			nm_log_warn (LOGD_SETTINGS, "keyfile: %s.%s: failed to write certificate to file %s: %s",
			             setting_name, cert_data->property_name, new_path, local->message);
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
                            uid_t owner_uid,
                            pid_t owner_grp,
                            const char *existing_path,
                            gboolean force_rename,
                            char **out_path,
                            GError **error)
{
	GKeyFile *key_file;
	gs_free char *data = NULL;
	gsize len;
	gs_free char *path = NULL;
	const char *id;
	WriteInfo info = { 0 };
	GError *local_err = NULL;
	int errsv;

	g_return_val_if_fail (!out_path || !*out_path, FALSE);
	g_return_val_if_fail (keyfile_dir && keyfile_dir[0] == '/', FALSE);

	if (!nm_connection_verify (connection, error))
		g_return_val_if_reached (FALSE);

	id = nm_connection_get_id (connection);
	g_assert (id && *id);

	info.keyfile_dir = keyfile_dir;

	key_file = nm_keyfile_write (connection, _handler_write, &info, error);
	if (!key_file)
		return FALSE;
	data = g_key_file_to_data (key_file, &len, error);
	g_key_file_unref (key_file);
	if (!data)
		return FALSE;

	/* If we have existing file path, use it. Else generate one from
	 * connection's ID.
	 */
	if (existing_path != NULL && !force_rename) {
		path = g_strdup (existing_path);
	} else {
		char *filename_escaped = nm_keyfile_plugin_utils_escape_filename (id);

		path = g_build_filename (keyfile_dir, filename_escaped, NULL);
		g_free (filename_escaped);
	}

	/* If a file with this path already exists (but isn't the existing path
	 * of the connection) then we need another name.  Multiple connections
	 * can have the same ID (ie if two connections with the same ID are visible
	 * to different users) but of course can't have the same path.  Yeah,
	 * there's a race here, but there's not a lot we can do about it, and
	 * we shouldn't get more than one connection with the same UUID either.
	 */
	if (g_strcmp0 (path, existing_path) != 0 && g_file_test (path, G_FILE_TEST_EXISTS)) {
		guint i;
		gboolean name_found = FALSE;

		/* A keyfile with this connection's ID already exists. Pick another name. */
		for (i = 0; i < 100; i++) {
			char *filename, *filename_escaped;

			if (i == 0)
				filename = g_strdup_printf ("%s-%s", id, nm_connection_get_uuid (connection));
			else
				filename = g_strdup_printf ("%s-%s-%u", id, nm_connection_get_uuid (connection), i);

			filename_escaped = nm_keyfile_plugin_utils_escape_filename (filename);

			g_free (path);
			path = g_strdup_printf ("%s/%s", keyfile_dir, filename_escaped);
			g_free (filename);
			g_free (filename_escaped);
			if (g_strcmp0 (path, existing_path) == 0 || !g_file_test (path, G_FILE_TEST_EXISTS)) {
				name_found = TRUE;
				break;
			}
		}
		if (!name_found) {
			if (existing_path == NULL) {
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

	/* In case of updating the connection and changing the file path,
	 * we need to remove the old one, not to end up with two connections.
	 */
	if (existing_path != NULL && strcmp (path, existing_path) != 0)
		unlink (existing_path);

	g_file_set_contents (path, data, len, &local_err);
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
		             path, g_strerror (errsv), errsv);
		unlink (path);
		return FALSE;
	}

	if (chmod (path, S_IRUSR | S_IWUSR) < 0) {
		errsv = errno;
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "error setting permissions on '%s': %s (%d)",
		             path, g_strerror (errsv), errsv);
		unlink (path);
		return FALSE;
	}

	if (out_path && g_strcmp0 (existing_path, path)) {
		*out_path = path;  /* pass path out to caller */
		path = NULL;
	}
	return TRUE;
}

gboolean
nm_keyfile_plugin_write_connection (NMConnection *connection,
                                    const char *existing_path,
                                    gboolean force_rename,
                                    char **out_path,
                                    GError **error)
{
	return _internal_write_connection (connection,
	                                   KEYFILE_DIR,
	                                   0, 0,
	                                   existing_path,
	                                   force_rename,
	                                   out_path,
	                                   error);
}

gboolean
nm_keyfile_plugin_write_test_connection (NMConnection *connection,
                                         const char *keyfile_dir,
                                         uid_t owner_uid,
                                         pid_t owner_grp,
                                         char **out_path,
                                         GError **error)
{
	return _internal_write_connection (connection,
	                                   keyfile_dir,
	                                   owner_uid, owner_grp,
	                                   NULL,
	                                   FALSE,
	                                   out_path,
	                                   error);
}

