// SPDX-License-Identifier: GPL-2.0+
/*
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

#include "nm-glib-aux/nm-io-utils.h"

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

		/* FIXME(keyfile-parse-in-memory): writer must not access/write to the file system before
		 * being sure that the entire profile can be written and all circumstances are good to
		 * proceed. That means, while writing we must only collect the blogs in-memory, and write
		 * them all in the end together (or not at all). */
		success = nm_utils_file_set_contents (new_path,
		                                      (const char *) blob_data,
		                                      blob_len,
		                                      0600,
		                                      NULL,
		                                      &local);
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
                            gboolean is_nm_generated,
                            gboolean is_volatile,
                            const char *shadowed_storage,
                            gboolean shadowed_owned,
                            const char *keyfile_dir,
                            const char *profile_dir,
                            gboolean with_extension,
                            uid_t owner_uid,
                            pid_t owner_grp,
                            const char *existing_path,
                            gboolean existing_path_read_only,
                            gboolean force_rename,
                            NMSKeyfileWriterAllowFilenameCb allow_filename_cb,
                            gpointer allow_filename_user_data,
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
	gs_free_error GError *local_err = NULL;
	int errsv;
	gboolean rename;
	int i_path;
	gs_unref_object NMConnection *reread = NULL;
	gboolean reread_same = FALSE;

	g_return_val_if_fail (!out_path || !*out_path, FALSE);
	g_return_val_if_fail (keyfile_dir && keyfile_dir[0] == '/', FALSE);

	nm_assert (_nm_connection_verify (connection, NULL) == NM_SETTING_VERIFY_SUCCESS);

	nm_assert (!shadowed_owned || shadowed_storage);

	rename =    force_rename
	         || existing_path_read_only
	         || (   existing_path
	             && !nm_utils_file_is_in_path (existing_path, keyfile_dir));

	id = nm_connection_get_id (connection);
	nm_assert (id && *id);

	info.keyfile_dir = keyfile_dir;

	kf_file = nm_keyfile_write (connection, _handler_write, &info, error);
	if (!kf_file)
		return FALSE;

	if (is_nm_generated) {
		g_key_file_set_boolean (kf_file,
		                        NM_KEYFILE_GROUP_NMMETA,
		                        NM_KEYFILE_KEY_NMMETA_NM_GENERATED,
		                        TRUE);
	}

	if (is_volatile) {
		g_key_file_set_boolean (kf_file,
		                        NM_KEYFILE_GROUP_NMMETA,
		                        NM_KEYFILE_KEY_NMMETA_VOLATILE,
		                        TRUE);
	}

	if (shadowed_storage) {
		g_key_file_set_string (kf_file,
		                       NM_KEYFILE_GROUP_NMMETA,
		                       NM_KEYFILE_KEY_NMMETA_SHADOWED_STORAGE,
		                       shadowed_storage);
	}

	if (shadowed_owned) {
		g_key_file_set_boolean (kf_file,
		                        NM_KEYFILE_GROUP_NMMETA,
		                        NM_KEYFILE_KEY_NMMETA_SHADOWED_OWNED,
		                        TRUE);
	}

	kf_content_buf = g_key_file_to_data (kf_file, &kf_content_len, error);
	if (!kf_content_buf)
		return FALSE;

	if (!g_file_test (keyfile_dir, G_FILE_TEST_IS_DIR))
		(void) g_mkdir_with_parents (keyfile_dir, 0755);

	for (i_path = -2; i_path < 10000; i_path++) {
		gs_free char *path_candidate = NULL;
		gboolean is_existing_path;

		if (i_path == -2) {
			if (   !existing_path
			    || rename)
				continue;
			path_candidate = g_strdup (existing_path);
		} else if (i_path == -1) {
			gs_free char *filename_escaped = NULL;

			filename_escaped = nm_keyfile_utils_create_filename (id, with_extension);
			path_candidate = g_build_filename (keyfile_dir, filename_escaped, NULL);
		} else {
			gs_free char *filename_escaped = NULL;
			gs_free char *filename = NULL;

			if (i_path == 0)
				filename = g_strdup_printf ("%s-%s", id, nm_connection_get_uuid (connection));
			else
				filename = g_strdup_printf ("%s-%s-%d", id, nm_connection_get_uuid (connection), i_path);

			filename_escaped = nm_keyfile_utils_create_filename (filename, with_extension);

			path_candidate = g_strdup_printf ("%s/%s", keyfile_dir, filename_escaped);
		}

		is_existing_path =    existing_path
		                   && nm_streq (existing_path, path_candidate);

		if (   is_existing_path
		    && rename)
			continue;

		if (   allow_filename_cb
		    && !allow_filename_cb (path_candidate, allow_filename_user_data))
			continue;

		if (!is_existing_path) {
			if (g_file_test (path_candidate, G_FILE_TEST_EXISTS))
				continue;
		}

		path = g_steal_pointer (&path_candidate);
		break;
	}

	if (!path) {
		/* this really should not happen, we tried hard to find an unused name... bail out. */
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		                    "could not find suitable keyfile file name (%s already used)", path);
		return FALSE;
	}

	if (   out_reread
	    || out_reread_same) {
		gs_free_error GError *reread_error = NULL;

		reread = nms_keyfile_reader_from_keyfile (kf_file, path, NULL, profile_dir, FALSE, &reread_error);

		if (   !reread
		    || !nm_connection_normalize (reread, NULL, NULL, &reread_error)) {
			nm_log_err (LOGD_SETTINGS, "BUG: the profile cannot be stored in keyfile format without becoming unusable: %s", reread_error->message);
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "keyfile writer produces an invalid connection: %s",
			             reread_error->message);
			nm_assert_not_reached ();
			return FALSE;
		}

		if (out_reread_same) {
			reread_same = !!nm_connection_compare (reread, connection, NM_SETTING_COMPARE_FLAG_EXACT);

			nm_assert (reread_same == nm_connection_compare (connection, reread, NM_SETTING_COMPARE_FLAG_EXACT));
			nm_assert (reread_same == ({
			                                gs_unref_hashtable GHashTable *_settings = NULL;

			                                (   nm_connection_diff (reread, connection, NM_SETTING_COMPARE_FLAG_EXACT, &_settings)
			                                 && !_settings);
			                           }));
		}
	}

	nm_utils_file_set_contents (path,
	                            kf_content_buf,
	                            kf_content_len,
	                            0600,
	                            NULL,
	                            &local_err);
	if (local_err) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "error writing to file '%s': %s",
		             path, local_err->message);
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

	NM_SET_OUT (out_reread, g_steal_pointer (&reread));
	NM_SET_OUT (out_reread_same, reread_same);
	NM_SET_OUT (out_path, g_steal_pointer (&path));

	return TRUE;
}

gboolean
nms_keyfile_writer_connection (NMConnection *connection,
                               gboolean is_nm_generated,
                               gboolean is_volatile,
                               const char *shadowed_storage,
                               gboolean shadowed_owned,
                               const char *keyfile_dir,
                               const char *profile_dir,
                               const char *existing_path,
                               gboolean existing_path_read_only,
                               gboolean force_rename,
                               NMSKeyfileWriterAllowFilenameCb allow_filename_cb,
                               gpointer allow_filename_user_data,
                               char **out_path,
                               NMConnection **out_reread,
                               gboolean *out_reread_same,
                               GError **error)
{
	return _internal_write_connection (connection,
	                                   is_nm_generated,
	                                   is_volatile,
	                                   shadowed_storage,
	                                   shadowed_owned,
	                                   keyfile_dir,
	                                   profile_dir,
	                                   TRUE,
	                                   0,
	                                   0,
	                                   existing_path,
	                                   existing_path_read_only,
	                                   force_rename,
	                                   allow_filename_cb,
	                                   allow_filename_user_data,
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
	                                   FALSE,
	                                   FALSE,
	                                   NULL,
	                                   FALSE,
	                                   keyfile_dir,
	                                   keyfile_dir,
	                                   FALSE,
	                                   owner_uid,
	                                   owner_grp,
	                                   NULL,
	                                   FALSE,
	                                   FALSE,
	                                   NULL,
	                                   NULL,
	                                   out_path,
	                                   out_reread,
	                                   out_reread_same,
	                                   error);
}
