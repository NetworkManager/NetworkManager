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
 * Copyright (C) 2008 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nms-keyfile-plugin.h"

#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>

#include "nm-std-aux/c-list-util.h"
#include "nm-glib-aux/nm-c-list.h"
#include "nm-glib-aux/nm-io-utils.h"

#include "nm-connection.h"
#include "nm-setting.h"
#include "nm-setting-connection.h"
#include "nm-utils.h"
#include "nm-config.h"
#include "nm-core-internal.h"
#include "nm-keyfile-internal.h"

#include "systemd/nm-sd-utils-shared.h"

#include "settings/nm-settings-plugin.h"
#include "settings/nm-settings-storage.h"
#include "settings/nm-settings-utils.h"

#include "nms-keyfile-storage.h"
#include "nms-keyfile-writer.h"
#include "nms-keyfile-reader.h"
#include "nms-keyfile-utils.h"

/*****************************************************************************/

typedef struct {

	NMConfig *config;

	/* there can/could be multiple read-only directories. For example, one
	 * could set dirname_libs to
	 *   - /usr/lib/NetworkManager/profiles/
	 *   - /etc/NetworkManager/system-connections
	 * and leave dirname_etc unset. In this case, there would be multiple
	 * read-only directories.
	 *
	 * Directories that come later have higher priority and shadow profiles
	 * from earlier directories.
	 *
	 * Currently, this is only an array with zero or one elements. It could be
	 * easily extended to support multiple read-only directories.
	 */
	char *dirname_libs[2];
	char *dirname_etc;
	char *dirname_run;

	NMSettUtilStorages storages;

} NMSKeyfilePluginPrivate;

struct _NMSKeyfilePlugin {
	NMSettingsPlugin parent;
	NMSKeyfilePluginPrivate _priv;
};

struct _NMSKeyfilePluginClass {
	NMSettingsPluginClass parent;
};

G_DEFINE_TYPE (NMSKeyfilePlugin, nms_keyfile_plugin, NM_TYPE_SETTINGS_PLUGIN)

#define NMS_KEYFILE_PLUGIN_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMSKeyfilePlugin, NMS_IS_KEYFILE_PLUGIN, NMSettingsPlugin)

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME      "keyfile"
#define _NMLOG_DOMAIN           LOGD_SETTINGS
#define _NMLOG(level, ...) \
    nm_log ((level), _NMLOG_DOMAIN, NULL, NULL, \
            "%s" _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
            _NMLOG_PREFIX_NAME": " \
            _NM_UTILS_MACRO_REST (__VA_ARGS__))

/*****************************************************************************/

static const char *
_extra_flags_to_string (char *str, gsize str_len, gboolean is_nm_generated, gboolean is_volatile)
{
	const char *str0 = str;

	if (   !is_nm_generated
	    && !is_volatile)
		nm_utils_strbuf_append_str (&str, &str_len, "");
	else {
		nm_utils_strbuf_append_str (&str, &str_len, " (");
		if (is_nm_generated) {
			nm_utils_strbuf_append_str (&str, &str_len, "nm-generated");
			if (is_volatile)
				nm_utils_strbuf_append_c (&str, &str_len, ',');
		}
		if (is_volatile)
			nm_utils_strbuf_append_str (&str, &str_len, "volatile");
		nm_utils_strbuf_append_c (&str, &str_len, ')');
	}

	return str0;
}

static gboolean
_ignore_filename (NMSKeyfileStorageType storage_type,
                  const char *filename)
{
	/* for backward-compatibility, we don't require an extension for
	 * files under "/etc/...". */
	return nm_keyfile_utils_ignore_filename (filename,
	                                         (storage_type != NMS_KEYFILE_STORAGE_TYPE_ETC));
}

static const char *
_get_plugin_dir (NMSKeyfilePluginPrivate *priv)
{
	/* the plugin dir is only needed to generate connection.uuid value via
	 * nm_keyfile_read_ensure_uuid(). This is either the configured /etc
	 * directory, of the compile-time default (in case the /etc directory
	 * is disabled). */
	return priv->dirname_etc ?: NM_KEYFILE_PATH_NAME_ETC_DEFAULT;
}

static gboolean
_path_detect_storage_type (const char *full_filename,
                           const char *const*dirname_libs,
                           const char *dirname_etc,
                           const char *dirname_run,
                           NMSKeyfileStorageType *out_storage_type,
                           const char **out_dirname,
                           const char **out_filename,
                           gboolean *out_is_nmmeta_file,
                           gboolean *out_failed_due_to_invalid_filename)
{
	NMSKeyfileStorageType storage_type;
	const char *filename = NULL;
	const char *dirname = NULL;
	guint i;
	gboolean is_nmmeta_file = FALSE;

	NM_SET_OUT (out_failed_due_to_invalid_filename, FALSE);

	if (full_filename[0] != '/')
		return FALSE;

	if (   dirname_run
	    && (filename = nm_utils_file_is_in_path (full_filename, dirname_run))) {
		storage_type = NMS_KEYFILE_STORAGE_TYPE_RUN;
		dirname = dirname_run;
	} else if (   dirname_etc
	           && (filename = nm_utils_file_is_in_path (full_filename, dirname_etc))) {
		storage_type = NMS_KEYFILE_STORAGE_TYPE_ETC;
		dirname = dirname_etc;
	} else {
		for (i = 0; dirname_libs && dirname_libs[i]; i++) {
			if ((filename = nm_utils_file_is_in_path (full_filename, dirname_libs[i]))) {
				storage_type = NMS_KEYFILE_STORAGE_TYPE_LIB (i);
				dirname = dirname_libs[i];
				break;
			}
		}
		if (!dirname)
			return FALSE;
	}

	if (_ignore_filename (storage_type, filename)) {

		/* we accept nmmeta files, but only in /etc and /run directories. */

		if (   !NM_IN_SET (storage_type, NMS_KEYFILE_STORAGE_TYPE_RUN,
		                                 NMS_KEYFILE_STORAGE_TYPE_ETC)
		    || !nms_keyfile_nmmeta_check_filename (filename, NULL)) {
			NM_SET_OUT (out_failed_due_to_invalid_filename, TRUE);
			return FALSE;
		}

		is_nmmeta_file = TRUE;
	}

	NM_SET_OUT (out_storage_type, storage_type);
	NM_SET_OUT (out_dirname, dirname);
	NM_SET_OUT (out_filename, filename);
	NM_SET_OUT (out_is_nmmeta_file, is_nmmeta_file);
	return TRUE;
}

/*****************************************************************************/

static NMConnection *
_read_from_file (const char *full_filename,
                 const char *plugin_dir,
                 struct stat *out_stat,
                 NMTernary *out_is_nm_generated,
                 NMTernary *out_is_volatile,
                 char **out_shadowed_storage,
                 NMTernary *out_shadowed_owned,
                 GError **error)
{
	NMConnection *connection;

	nm_assert (full_filename && full_filename[0] == '/');

	connection = nms_keyfile_reader_from_file (full_filename,
	                                           plugin_dir,
	                                           out_stat,
	                                           out_is_nm_generated,
	                                           out_is_volatile,
	                                           out_shadowed_storage,
	                                           out_shadowed_owned,
	                                           error);

	nm_assert (!connection || (_nm_connection_verify (connection, NULL) == NM_SETTING_VERIFY_SUCCESS));
	nm_assert (!connection || nm_utils_is_uuid (nm_connection_get_uuid (connection)));

	return connection;
}

/*****************************************************************************/

static void
_nm_assert_storage (gpointer plugin  /* NMSKeyfilePlugin  */,
                    gpointer storage /* NMSKeyfileStorage */,
                    gboolean tracked)
{
#if NM_MORE_ASSERTS
	NMSettUtilStorageByUuidHead *sbuh;
	const char *uuid;

	nm_assert (!plugin || NMS_IS_KEYFILE_PLUGIN (plugin));
	nm_assert (NMS_IS_KEYFILE_STORAGE (storage));
	nm_assert (!plugin || plugin == nm_settings_storage_get_plugin (storage));

	nm_assert (({
	                const char *f = nms_keyfile_storage_get_filename (storage);
	                f && f[0] == '/';
	            }));

	uuid = nms_keyfile_storage_get_uuid (storage);

	nm_assert (nm_utils_is_uuid (uuid));

	nm_assert (   ((NMSKeyfileStorage *) storage)->is_meta_data
	           || !(((NMSKeyfileStorage *) storage)->u.conn_data.connection)
	           || (   NM_IS_CONNECTION ((((NMSKeyfileStorage *) storage)->u.conn_data.connection))
	               && nm_streq0 (uuid, nm_connection_get_uuid ((((NMSKeyfileStorage *) storage)->u.conn_data.connection)))));

	nm_assert (   !tracked
	           || !plugin
	           || c_list_contains (&NMS_KEYFILE_PLUGIN_GET_PRIVATE (plugin)->storages._storage_lst_head,
	                               &NMS_KEYFILE_STORAGE (storage)->parent._storage_lst));

	nm_assert (   !tracked
	           || !plugin
	           || storage == g_hash_table_lookup (NMS_KEYFILE_PLUGIN_GET_PRIVATE (plugin)->storages.idx_by_filename,
	                                              nms_keyfile_storage_get_filename (storage)));

	if (   tracked
	    && plugin) {
		sbuh = g_hash_table_lookup (NMS_KEYFILE_PLUGIN_GET_PRIVATE (plugin)->storages.idx_by_uuid, &uuid);
		nm_assert (sbuh);
		nm_assert (c_list_contains (&sbuh->_storage_by_uuid_lst_head, &((NMSKeyfileStorage *) storage)->parent._storage_by_uuid_lst));
	}
#endif
}

/*****************************************************************************/

static NMSKeyfileStorage *
_load_file (NMSKeyfilePlugin *self,
            const char *dirname,
            const char *filename,
            NMSKeyfileStorageType storage_type,
            GError **error)
{
	NMSKeyfilePluginPrivate *priv;
	gs_unref_object NMConnection *connection = NULL;
	NMTernary is_volatile_opt;
	NMTernary is_nm_generated_opt;
	NMTernary shadowed_owned_opt;
	gs_free char *shadowed_storage = NULL;
	gs_free_error GError *local = NULL;
	gs_free char *full_filename = NULL;
	struct stat st;

	if (_ignore_filename (storage_type, filename)) {
		gs_free char *nmmeta = NULL;
		gs_free char *loaded_path = NULL;
		gs_free char *shadowed_storage_filename = NULL;

		if (!nms_keyfile_nmmeta_check_filename (filename, NULL)) {
			if (error)
				nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN, "skip due to invalid filename");
			else
				_LOGT ("load: \"%s/%s\": skip file due to invalid filename", dirname, filename);
			return NULL;
		}
		if (!nms_keyfile_nmmeta_read (dirname,
		                              filename,
		                              &full_filename,
		                              &nmmeta,
		                              &loaded_path,
		                              &shadowed_storage_filename,
		                              NULL)) {
			if (error)
				nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN, "skip unreadable nmmeta file");
			else
				_LOGT ("load: \"%s/%s\": skip unreadable nmmeta file", dirname, filename);
			return NULL;
		}
		nm_assert (loaded_path);
		if (!NM_IN_SET (storage_type, NMS_KEYFILE_STORAGE_TYPE_RUN,
		                              NMS_KEYFILE_STORAGE_TYPE_ETC)) {
			if (error)
				nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN, "skip nmmeta file from read-only directory");
			else
				_LOGT ("load: \"%s/%s\": skip nmmeta file from read-only directory", dirname, filename);
			return NULL;
		}
		if (!nm_streq (loaded_path, NM_KEYFILE_PATH_NMMETA_SYMLINK_NULL)) {
			if (error)
				nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN, "skip nmmeta file not symlinking %s", NM_KEYFILE_PATH_NMMETA_SYMLINK_NULL);
			else
				_LOGT ("load: \"%s/%s\": skip nmmeta file not symlinking to %s", dirname, filename, NM_KEYFILE_PATH_NMMETA_SYMLINK_NULL);
			return NULL;
		}

		return nms_keyfile_storage_new_tombstone (self,
		                                          nmmeta,
		                                          full_filename,
		                                          storage_type,
		                                          shadowed_storage_filename);
	}

	full_filename = g_build_filename (dirname, filename, NULL);

	priv = NMS_KEYFILE_PLUGIN_GET_PRIVATE (self);

	connection = _read_from_file (full_filename,
	                              _get_plugin_dir (priv),
	                              &st,
	                              &is_nm_generated_opt,
	                              &is_volatile_opt,
	                              &shadowed_storage,
	                              &shadowed_owned_opt,
	                              &local);
	if (!connection) {
		if (error)
			g_propagate_error (error, local);
		else
			_LOGW ("load: \"%s\": failed to load connection: %s", full_filename, local->message);
		return NULL;
	}

	return nms_keyfile_storage_new_connection (self,
	                                           g_steal_pointer (&connection),
	                                           full_filename,
	                                           storage_type,
	                                           is_nm_generated_opt,
	                                           is_volatile_opt,
	                                           shadowed_storage,
	                                           shadowed_owned_opt,
	                                           &st.st_mtim);
}

static NMSKeyfileStorage *
_load_file_from_path (NMSKeyfilePlugin *self,
                      const char *full_filename,
                      NMSKeyfileStorageType storage_type,
                      GError **error)
{
	gs_free char *f_dirname_free = NULL;
	const char *f_filename;
	const char *f_dirname;

	nm_assert (full_filename && full_filename[0] == '/');

	f_filename = strrchr (full_filename, '/');
	f_dirname = nm_strndup_a (300, full_filename, f_filename - full_filename, &f_dirname_free);
	f_filename++;
	return _load_file (self,
	                   f_dirname,
	                   f_filename,
	                   storage_type,
	                   error);
}

static void
_load_dir (NMSKeyfilePlugin *self,
           NMSKeyfileStorageType storage_type,
           const char *dirname,
           NMSettUtilStorages *storages)
{
	const char *filename;
	GDir *dir;
	gs_unref_hashtable GHashTable *dupl_filenames = NULL;

	dir = g_dir_open (dirname, 0, NULL);
	if (!dir)
		return;

	dupl_filenames = g_hash_table_new_full (nm_str_hash, g_str_equal, NULL, g_free);

	while ((filename = g_dir_read_name (dir))) {
		gs_unref_object NMSKeyfileStorage *storage = NULL;

		filename = g_strdup (filename);
		if (!g_hash_table_add (dupl_filenames, (char *) filename))
			continue;

		storage = _load_file (self,
		                      dirname,
		                      filename,
		                      storage_type,
		                      NULL);
		if (!storage)
			continue;

		nm_sett_util_storages_add_take (storages, g_steal_pointer (&storage));
	}

	g_dir_close (dir);

#if NM_MORE_ASSERTS
	{
		NMSKeyfileStorage *storage;

		c_list_for_each_entry (storage, &storages->_storage_lst_head, parent._storage_lst)
			nm_assert (NMS_IS_KEYFILE_STORAGE (storage));
	}
#endif
}

/*****************************************************************************/

static void
_storages_consolidate (NMSKeyfilePlugin *self,
                       NMSettUtilStorages *storages_new,
                       gboolean replace_all,
                       GHashTable *storages_replaced,
                       NMSettingsPluginConnectionLoadCallback callback,
                       gpointer user_data)
{
	NMSKeyfilePluginPrivate *priv = NMS_KEYFILE_PLUGIN_GET_PRIVATE (self);
	CList lst_conn_info_deleted = C_LIST_INIT (lst_conn_info_deleted);
	gs_unref_ptrarray GPtrArray *storages_modified = NULL;
	CList storages_deleted;
	NMSKeyfileStorage *storage_safe;
	NMSKeyfileStorage *storage_new;
	NMSKeyfileStorage *storage_old;
	NMSKeyfileStorage *storage;
	guint i;

	storages_modified = g_ptr_array_new_with_free_func (g_object_unref);
	c_list_init (&storages_deleted);

	c_list_for_each_entry (storage_old, &priv->storages._storage_lst_head, parent._storage_lst)
		storage_old->is_dirty = TRUE;

	c_list_for_each_entry_safe (storage_new, storage_safe, &storages_new->_storage_lst_head, parent._storage_lst) {
		storage_old = nm_sett_util_storages_lookup_by_filename (&priv->storages, nms_keyfile_storage_get_filename (storage_new));

		nm_sett_util_storages_steal (storages_new, storage_new);

		if (   !storage_old
		    || !nm_streq (nms_keyfile_storage_get_uuid (storage_new), nms_keyfile_storage_get_uuid (storage_old))) {
			if (storage_old) {
				nm_sett_util_storages_steal (&priv->storages, storage_old);
				c_list_link_tail (&storages_deleted, &storage_old->parent._storage_by_uuid_lst);
			}
			storage_new->is_dirty = FALSE;
			nm_sett_util_storages_add_take (&priv->storages, storage_new);
			g_ptr_array_add (storages_modified, g_object_ref (storage_new));
			continue;
		}

		storage_old->is_dirty = FALSE;
		nms_keyfile_storage_copy_content (storage_old, storage_new);
		nms_keyfile_storage_destroy (storage_new);
		g_ptr_array_add (storages_modified, g_object_ref (storage_old));
	}

	c_list_for_each_entry_safe (storage_old, storage_safe, &priv->storages._storage_lst_head, parent._storage_lst) {
		if (!storage_old->is_dirty)
			continue;
		if (   replace_all
		    || (   storages_replaced
		        && g_hash_table_contains (storages_replaced, storage_old))) {
			nm_sett_util_storages_steal (&priv->storages, storage_old);
			c_list_link_tail (&storages_deleted, &storage_old->parent._storage_by_uuid_lst);
		}
	}

	/* raise events. */

	for (i = 0; i < storages_modified->len; i++) {
		storage = storages_modified->pdata[i];
		storage->is_dirty = TRUE;
	}

	for (i = 0; i < storages_modified->len; i++) {
		gs_unref_object NMConnection *connection = NULL;

		storage = storages_modified->pdata[i];

		if (!storage->is_dirty) {
			/* the entry is no longer is_dirty. In the meantime we already emited
			 * another signal for it. */
			continue;
		}
		storage->is_dirty = FALSE;

		if (c_list_is_empty (&storage->parent._storage_lst)) {
			/* hm? The profile was deleted in the meantime? That is only possible
			 * if the signal handler called again into the plugin. In any case, the event
			 * was already emitted. Skip. */
			continue;
		}

		nm_assert (storage == nm_sett_util_storages_lookup_by_filename (&priv->storages, nms_keyfile_storage_get_filename (storage)));

		connection = nms_keyfile_storage_steal_connection (storage);

		callback (NM_SETTINGS_PLUGIN (self),
		          NM_SETTINGS_STORAGE (storage),
		          connection,
		          user_data);
	}

	while ((storage = c_list_first_entry (&storages_deleted, NMSKeyfileStorage, parent._storage_by_uuid_lst))) {
		c_list_unlink (&storage->parent._storage_by_uuid_lst);
		callback (NM_SETTINGS_PLUGIN (self),
		          NM_SETTINGS_STORAGE (storage),
		          NULL,
		          user_data);
		nms_keyfile_storage_destroy (storage);
	}
}

static void
reload_connections (NMSettingsPlugin *plugin,
                    NMSettingsPluginConnectionLoadCallback callback,
                    gpointer user_data)
{
	NMSKeyfilePlugin *self = NMS_KEYFILE_PLUGIN (plugin);
	NMSKeyfilePluginPrivate *priv = NMS_KEYFILE_PLUGIN_GET_PRIVATE (self);
	nm_auto_clear_sett_util_storages NMSettUtilStorages storages_new = NM_SETT_UTIL_STORAGES_INIT (storages_new, nms_keyfile_storage_destroy);
	int i;

	_load_dir (self, NMS_KEYFILE_STORAGE_TYPE_RUN, priv->dirname_run, &storages_new);
	if (priv->dirname_etc)
		_load_dir (self, NMS_KEYFILE_STORAGE_TYPE_ETC, priv->dirname_etc, &storages_new);
	for (i = 0; priv->dirname_libs[i]; i++)
		_load_dir (self, NMS_KEYFILE_STORAGE_TYPE_LIB (i), priv->dirname_libs[i], &storages_new);

	_storages_consolidate (self,
	                       &storages_new,
	                       TRUE,
	                       NULL,
	                       callback,
	                       user_data);
}

static void
load_connections (NMSettingsPlugin *plugin,
                  NMSettingsPluginConnectionLoadEntry *entries,
                  gsize n_entries,
                  NMSettingsPluginConnectionLoadCallback callback,
                  gpointer user_data)
{
	NMSKeyfilePlugin *self = NMS_KEYFILE_PLUGIN (plugin);
	NMSKeyfilePluginPrivate *priv = NMS_KEYFILE_PLUGIN_GET_PRIVATE (self);
	nm_auto_clear_sett_util_storages NMSettUtilStorages storages_new = NM_SETT_UTIL_STORAGES_INIT (storages_new, nms_keyfile_storage_destroy);
	gs_unref_hashtable GHashTable *dupl_filenames = NULL;
	gs_unref_hashtable GHashTable *storages_replaced = NULL;
	gs_unref_hashtable GHashTable *loaded_uuids = NULL;
	const char *loaded_uuid;
	GHashTableIter h_iter;
	gsize i;

	if (n_entries == 0)
		return;

	dupl_filenames = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, NULL);

	loaded_uuids = g_hash_table_new (nm_str_hash, g_str_equal);

	storages_replaced = g_hash_table_new_full (nm_direct_hash, NULL, g_object_unref, NULL);

	for (i = 0; i < n_entries; i++) {
		NMSettingsPluginConnectionLoadEntry *const entry = &entries[i];
		NMSKeyfileStorageType storage_type;
		gs_free_error GError *local = NULL;
		const char *f_filename;
		const char *f_dirname;
		const char *full_filename;
		gs_free char *full_filename_keep = NULL;
		gboolean is_nmmeta_file;
		NMSettingsPluginConnectionLoadEntry *dupl_content_entry;
		gboolean failed_due_to_invalid_filename;
		gs_unref_object NMSKeyfileStorage *storage = NULL;

		if (entry->handled)
			continue;

		if (!_path_detect_storage_type (entry->filename,
		                                (const char *const*) priv->dirname_libs,
		                                priv->dirname_etc,
		                                priv->dirname_run,
		                                &storage_type,
		                                &f_dirname,
		                                &f_filename,
		                                &is_nmmeta_file,
		                                &failed_due_to_invalid_filename)) {
			if (failed_due_to_invalid_filename) {
				entry->handled = TRUE;
				nm_utils_error_set (&entry->error, NM_UTILS_ERROR_UNKNOWN, "filename is not valid for a keyfile");
			}
			continue;
		}

		full_filename_keep = g_build_filename (f_dirname, f_filename, NULL);

		if ((dupl_content_entry = g_hash_table_lookup (dupl_filenames, full_filename_keep))) {
			/* we already visited this file. */
			entry->handled = dupl_content_entry->handled;
			if (dupl_content_entry->error) {
				g_set_error_literal (&entry->error,
				                     dupl_content_entry->error->domain,
				                     dupl_content_entry->error->code,
				                     dupl_content_entry->error->message);
			}
			continue;
		}

		entry->handled = TRUE;

		full_filename = full_filename_keep;
		if (!g_hash_table_insert (dupl_filenames, g_steal_pointer (&full_filename_keep), entry))
			nm_assert_not_reached ();

		storage = _load_file (self,
		                      f_dirname,
		                      f_filename,
		                      storage_type,
		                      &local);
		if (!storage) {
			if (nm_utils_file_stat (full_filename, NULL) == -ENOENT) {
				NMSKeyfileStorage *storage2;

				/* the file does not exist. We take that as indication to unload the file
				 * that was previously loaded... */
				storage2 = nm_sett_util_storages_lookup_by_filename (&priv->storages, full_filename);
				if (storage2)
					g_hash_table_add (storages_replaced, g_object_ref (storage2));
				continue;
			}
			g_propagate_error (&entry->error, g_steal_pointer (&local));
			continue;
		}

		g_hash_table_add (loaded_uuids, (char *) nms_keyfile_storage_get_uuid (storage));

		nm_sett_util_storages_add_take (&storages_new, g_steal_pointer (&storage));
	}

	/* now we visit all UUIDs that are about to change... */
	g_hash_table_iter_init (&h_iter, loaded_uuids);
	while (g_hash_table_iter_next (&h_iter, (gpointer *) &loaded_uuid, NULL)) {
		NMSKeyfileStorage *storage;
		NMSettUtilStorageByUuidHead *sbuh;

		sbuh = nm_sett_util_storages_lookup_by_uuid (&priv->storages, loaded_uuid);
		if (!sbuh)
			continue;

		c_list_for_each_entry (storage, &sbuh->_storage_by_uuid_lst_head, parent._storage_by_uuid_lst) {
			const char *full_filename = nms_keyfile_storage_get_filename (storage);
			gs_unref_object NMSKeyfileStorage *storage_new = NULL;
			gs_free_error GError *local = NULL;

			if (g_hash_table_contains (dupl_filenames, full_filename)) {
				/* already re-loaded. */
				continue;
			}

			/* @storage has a UUID that was just loaded from disk, but we have an entry in cache.
			 * Reload that file too despite not being told to do so. The reason is to get
			 * the latest file timestamp so that we get the priorities right. */

			storage_new = _load_file_from_path (self,
			                                    full_filename,
			                                    storage->storage_type,
			                                    &local);
			if (   storage_new
			    && !nm_streq (loaded_uuid, nms_keyfile_storage_get_uuid (storage_new))) {
				/* the file now references a different UUID. We are not told to reload
				 * that file, so this means the existing storage (with the previous
				 * filename and UUID tuple) is no longer valid. */
				g_clear_object (&storage_new);
			}

			g_hash_table_add (storages_replaced, g_object_ref (storage));
			if (storage_new)
				nm_sett_util_storages_add_take (&storages_new, g_steal_pointer (&storage_new));
		}
	}

	nm_clear_pointer (&loaded_uuids, g_hash_table_destroy);
	nm_clear_pointer (&dupl_filenames, g_hash_table_destroy);

	_storages_consolidate (self,
	                       &storages_new,
	                       FALSE,
	                       storages_replaced,
	                       callback,
	                       user_data);
}

gboolean
nms_keyfile_plugin_add_connection (NMSKeyfilePlugin *self,
                                   NMConnection *connection,
                                   gboolean in_memory,
                                   gboolean is_nm_generated,
                                   gboolean is_volatile,
                                   const char *shadowed_storage,
                                   gboolean shadowed_owned,
                                   NMSettingsStorage **out_storage,
                                   NMConnection **out_connection,
                                   GError **error)
{
	NMSKeyfilePluginPrivate *priv = NMS_KEYFILE_PLUGIN_GET_PRIVATE (self);
	gs_unref_object NMConnection *reread = NULL;
	gs_free char *full_filename = NULL;
	NMSKeyfileStorageType storage_type;
	gs_unref_object NMSKeyfileStorage *storage = NULL;
	GError *local = NULL;
	const char *uuid;
	gboolean reread_same;
	struct timespec mtime;
	char strbuf[100];

	nm_assert (NM_IS_CONNECTION (connection));
	nm_assert (out_storage && !*out_storage);
	nm_assert (out_connection && !*out_connection);

	nm_assert (   in_memory
	           || (   !is_nm_generated
	               && !is_volatile
	               && !shadowed_storage
	               && !shadowed_owned));

	uuid = nm_connection_get_uuid (connection);

	/* Note that even if the caller requests persistent storage, we may switch to in-memory, if
	 * no /etc directory is configured. */
	storage_type =   !in_memory && priv->dirname_etc
	               ? NMS_KEYFILE_STORAGE_TYPE_ETC
	               : NMS_KEYFILE_STORAGE_TYPE_RUN;

	if (!nms_keyfile_writer_connection (connection,
	                                    is_nm_generated,
	                                    is_volatile,
	                                    shadowed_storage,
	                                    shadowed_owned,
	                                      storage_type == NMS_KEYFILE_STORAGE_TYPE_ETC
	                                    ? priv->dirname_etc
	                                    : priv->dirname_run,
	                                    _get_plugin_dir (priv),
	                                    NULL,
	                                    FALSE,
	                                    FALSE,
	                                    nm_sett_util_allow_filename_cb,
	                                    NM_SETT_UTIL_ALLOW_FILENAME_DATA (&priv->storages, NULL),
	                                    &full_filename,
	                                    &reread,
	                                    &reread_same,
	                                    &local)) {
		_LOGT ("commit: %s (%s) failed to add: %s",
		       nm_connection_get_uuid (connection),
		       nm_connection_get_id (connection),
		       local->message);
		g_propagate_error (error, local);
		return FALSE;
	}

	if (   !reread
	    || reread_same)
		nm_g_object_ref_set (&reread, connection);

	nm_assert (_nm_connection_verify (reread, NULL) == NM_SETTING_VERIFY_SUCCESS);
	nm_assert (nm_streq0 (nm_connection_get_uuid (connection), nm_connection_get_uuid (reread)));

	nm_assert (full_filename && full_filename[0] == '/');
	nm_assert (!nm_sett_util_storages_lookup_by_filename (&priv->storages, full_filename));

	_LOGT ("commit: %s (%s) added as \"%s\"%s%s%s%s",
	       uuid,
	       nm_connection_get_id (connection),
	       full_filename,
	       _extra_flags_to_string (strbuf, sizeof (strbuf), is_nm_generated, is_volatile),
	       NM_PRINT_FMT_QUOTED (shadowed_storage, " (shadows \"", shadowed_storage, shadowed_owned ? "\", owned)" : "\")", ""));

	storage = nms_keyfile_storage_new_connection (self,
	                                              g_steal_pointer (&reread),
	                                              full_filename,
	                                              storage_type,
	                                              is_nm_generated ? NM_TERNARY_TRUE : NM_TERNARY_FALSE,
	                                              is_volatile ? NM_TERNARY_TRUE : NM_TERNARY_FALSE,
	                                              shadowed_storage,
	                                              shadowed_owned ? NM_TERNARY_TRUE : NM_TERNARY_FALSE,
	                                              nm_sett_util_stat_mtime (full_filename, FALSE, &mtime));

	nm_sett_util_storages_add_take (&priv->storages, g_object_ref (storage));

	*out_connection = nms_keyfile_storage_steal_connection (storage);
	*out_storage = NM_SETTINGS_STORAGE (g_steal_pointer (&storage));

	return TRUE;
}

static gboolean
add_connection (NMSettingsPlugin *plugin,
                NMConnection *connection,
                NMSettingsStorage **out_storage,
                NMConnection **out_connection,
                GError **error)
{
	return nms_keyfile_plugin_add_connection (NMS_KEYFILE_PLUGIN (plugin),
	                                          connection,
	                                          FALSE,
	                                          FALSE,
	                                          FALSE,
	                                          NULL,
	                                          FALSE,
	                                          out_storage,
	                                          out_connection,
	                                          error);
}

gboolean
nms_keyfile_plugin_update_connection (NMSKeyfilePlugin *self,
                                      NMSettingsStorage *storage_x,
                                      NMConnection *connection,
                                      gboolean is_nm_generated,
                                      gboolean is_volatile,
                                      const char *shadowed_storage,
                                      gboolean shadowed_owned,
                                      gboolean force_rename,
                                      NMSettingsStorage **out_storage,
                                      NMConnection **out_connection,
                                      GError **error)
{
	NMSKeyfilePluginPrivate *priv = NMS_KEYFILE_PLUGIN_GET_PRIVATE (self);
	NMSKeyfileStorage *storage = NMS_KEYFILE_STORAGE (storage_x);
	gs_unref_object NMConnection *connection_clone = NULL;
	gs_unref_object NMConnection *reread = NULL;
	gs_free char *full_filename = NULL;
	gs_free_error GError *local = NULL;
	struct timespec mtime;
	const char *previous_filename;
	gboolean reread_same;
	const char *uuid;
	char strbuf[100];

	_nm_assert_storage (self, storage, TRUE);
	nm_assert (NM_IS_CONNECTION (connection));
	nm_assert (_nm_connection_verify (connection, NULL) == NM_SETTING_VERIFY_SUCCESS);
	nm_assert (nm_streq (nms_keyfile_storage_get_uuid (storage), nm_connection_get_uuid (connection)));
	nm_assert (!error || !*error);
	nm_assert (NM_IN_SET (storage->storage_type, NMS_KEYFILE_STORAGE_TYPE_ETC,
	                                             NMS_KEYFILE_STORAGE_TYPE_RUN));
	nm_assert (!storage->is_meta_data);
	nm_assert (   storage->storage_type == NMS_KEYFILE_STORAGE_TYPE_RUN
	           || (   !is_nm_generated
	               && !is_volatile
	               && !shadowed_storage
	               && !shadowed_owned));
	nm_assert (!shadowed_owned || shadowed_storage);
	nm_assert  (   priv->dirname_etc
	            || storage->storage_type != NMS_KEYFILE_STORAGE_TYPE_ETC);

	previous_filename = nms_keyfile_storage_get_filename (storage);
	uuid = nms_keyfile_storage_get_uuid (storage);

	if (!nms_keyfile_writer_connection (connection,
	                                    is_nm_generated,
	                                    is_volatile,
	                                    shadowed_storage,
	                                    shadowed_owned,
	                                      storage->storage_type == NMS_KEYFILE_STORAGE_TYPE_ETC
	                                    ? priv->dirname_etc
	                                    : priv->dirname_run,
	                                    _get_plugin_dir (priv),
	                                    previous_filename,
	                                    FALSE,
	                                    FALSE,
	                                    nm_sett_util_allow_filename_cb,
	                                    NM_SETT_UTIL_ALLOW_FILENAME_DATA (&priv->storages, previous_filename),
	                                    &full_filename,
	                                    &reread,
	                                    &reread_same,
	                                    &local)) {
		_LOGW ("commit: failure to write %s (%s) to \"%s\": %s",
		       uuid,
		       nm_connection_get_id (connection_clone),
		       previous_filename,
		       local->message);
		g_propagate_error (error, g_steal_pointer (&local));
		return FALSE;
	}

	nm_assert (   full_filename
	           && nm_streq (full_filename, previous_filename));

	if (   !reread
	    || reread_same)
		nm_g_object_ref_set (&reread, connection);

	nm_assert (_nm_connection_verify (reread, NULL) == NM_SETTING_VERIFY_SUCCESS);
	nm_assert (nm_streq (nm_connection_get_uuid (reread), uuid));

	_LOGT ("commit: \"%s\": profile %s (%s) written%s%s%s%s",
	       full_filename,
	       uuid,
	       nm_connection_get_id (connection),
	       _extra_flags_to_string (strbuf, sizeof (strbuf), is_nm_generated, is_volatile),
	       NM_PRINT_FMT_QUOTED (shadowed_storage, shadowed_owned ? " (owns \"" : " (shadows \"", shadowed_storage, "\")", ""));

	storage->u.conn_data.is_nm_generated = is_nm_generated;
	storage->u.conn_data.is_volatile     = is_volatile;
	storage->u.conn_data.stat_mtime      = *nm_sett_util_stat_mtime (full_filename, FALSE, &mtime);
	storage->u.conn_data.shadowed_owned  = shadowed_owned;

	*out_storage = g_object_ref (NM_SETTINGS_STORAGE (storage));
	*out_connection = g_steal_pointer (&reread);
	return TRUE;
}

static gboolean
update_connection (NMSettingsPlugin *plugin,
                   NMSettingsStorage *storage,
                   NMConnection *connection,
                   NMSettingsStorage **out_storage,
                   NMConnection **out_connection,
                   GError **error)
{
	return nms_keyfile_plugin_update_connection (NMS_KEYFILE_PLUGIN (plugin),
	                                             storage,
	                                             connection,
	                                             FALSE,
	                                             FALSE,
	                                             NULL,
	                                             FALSE,
	                                             FALSE,
	                                             out_storage,
	                                             out_connection,
	                                             error);
}

static gboolean
delete_connection (NMSettingsPlugin *plugin,
                   NMSettingsStorage *storage_x,
                   GError **error)
{
	NMSKeyfilePlugin *self = NMS_KEYFILE_PLUGIN (plugin);
	NMSKeyfilePluginPrivate *priv = NMS_KEYFILE_PLUGIN_GET_PRIVATE (self);
	gs_unref_object NMSKeyfileStorage *storage = g_object_ref (NMS_KEYFILE_STORAGE (storage_x));
	const char *remove_from_disk_errmsg = NULL;
	const char *operation_message;
	const char *previous_filename;
	const char *uuid;
	gboolean success = TRUE;

	_nm_assert_storage (self, storage, TRUE);
	nm_assert (!error || !*error);

	previous_filename = nms_keyfile_storage_get_filename (storage);
	uuid = nms_keyfile_storage_get_uuid (storage);

	if (!NM_IN_SET (storage->storage_type, NMS_KEYFILE_STORAGE_TYPE_ETC,
	                                       NMS_KEYFILE_STORAGE_TYPE_RUN)) {
		nm_utils_error_set (error,
		                    NM_UTILS_ERROR_UNKNOWN,
		                    "profile in read-only storage cannot be deleted");
		success = FALSE;
		operation_message = "dropped readonly file from memory";
	} else if (unlink (previous_filename) != 0) {
		int errsv;

		errsv = errno;
		if (errsv != ENOENT) {
			remove_from_disk_errmsg = nm_strerror_native (errsv);
			operation_message = "failed to delete from disk";
			success = FALSE;
			nm_utils_error_set_errno (error,
			                          errsv,
			                          "failure to delete \"%s\": %s",
			                          previous_filename);
		} else
			operation_message = "does not exist on disk";
	} else
		operation_message = "deleted from disk";

	_LOGT ("commit: deleted \"%s\", %s %s (%s%s%s%s)",
	       previous_filename,
	       storage->is_meta_data ? "meta-data" : "profile",
	       uuid,
	       operation_message,
	       NM_PRINT_FMT_QUOTED (remove_from_disk_errmsg, ": ", remove_from_disk_errmsg, "", ""));

	if (success) {
		nm_sett_util_storages_steal (&priv->storages, storage);
		nms_keyfile_storage_destroy (storage);
	}

	return success;
}

/**
 * nms_keyfile_plugin_set_nmmeta_tombstone:
 * @self: the #NMSKeyfilePlugin instance
 * @simulate: if %TRUE, don't do anything on the filename but just pretend
 *   that the loaded UUID file gets tracked/untracked. In this mode, the function
 *   cannot fail (except on hard-failure, see below).
 *   The idea is that you first try without simulate to write to disk.
 *   If that fails, you might still want to forcefully pretend (in-memory
 *   only) that this uuid is marked as tombstone (or not), as desired.
 *   So you repeate the call with @simulate %TRUE.
 * @uuid: the UUID for which to write/delete the nmmeta file
 * @in_memory: the storage type, either /etc or /run. Note that if @self
 *   has no /etc directory configured, this results in a hard failure.
 * @set: if %TRUE, write the symlink to point to /dev/null. If %FALSE,
 *   delete the nmmeta file (if it exists).
 * @shadowed_storage: a tombstone can also shadow an existing storage.
 *   In combination with @set and @in_memory, this is allowed to store
 *   the shadowed storage filename.
 * @out_storage: (transfer full) (allow-none): the storage element that changes, or
 *   NULL if nothing changed. Note that the file on disk is already as
 *   we want to write it, then this still counts as a change. No change only
 *   means if we try to delete a storage (@set %FALSE) that did not
 *   exist previously.
 * @out_hard_failure: (allow-none): on failure, indicate that this is a hard failure.
 *
 * The function writes or deletes nmmeta files to/from filesystem. In this case,
 * the nmmeta files can only be symlinks to /dev/null (to indicate tombstones).
 *
 * A hard failure can only happen if @self has no /etc directory configured
 * and @in_memory is FALSE. In such case even @simulate call fails (which
 * otherwise would always succeed).
 * Also, if you get a hard-failure (with @simulate %FALSE) there is no point
 * in retrying with @simulate %TRUE (contrary to all other cases!).
 *
 * Returns: %TRUE on success.
 */
gboolean
nms_keyfile_plugin_set_nmmeta_tombstone (NMSKeyfilePlugin *self,
                                         gboolean simulate,
                                         const char *uuid,
                                         gboolean in_memory,
                                         gboolean set,
                                         const char *shadowed_storage,
                                         NMSettingsStorage **out_storage,
                                         gboolean *out_hard_failure)
{
	NMSKeyfilePluginPrivate *priv;
	gboolean hard_failure = FALSE;
	NMSKeyfileStorage *storage;
	gs_unref_object NMSKeyfileStorage *storage_result = NULL;
	gboolean nmmeta_success = FALSE;
	gs_free char *nmmeta_filename = NULL;
	NMSKeyfileStorageType storage_type;
	const char *loaded_path;
	const char *dirname;

	nm_assert (NMS_IS_KEYFILE_PLUGIN (self));
	nm_assert (nm_utils_is_uuid (uuid));
	nm_assert (!out_storage || !*out_storage);
	nm_assert (!shadowed_storage || (set && in_memory));

	priv = NMS_KEYFILE_PLUGIN_GET_PRIVATE (self);

	loaded_path =   set
	              ? NM_KEYFILE_PATH_NMMETA_SYMLINK_NULL
	              : NULL;

	if (in_memory) {
		storage_type = NMS_KEYFILE_STORAGE_TYPE_RUN;
		dirname = priv->dirname_run;
	} else {
		if (!priv->dirname_etc) {
			_LOGT ("commit: cannot %s%s nmmeta file for %s as there is no /etc directory",
			       simulate ? "simulate " : "",
			       loaded_path ? "write" : "delete",
			       uuid);
			hard_failure = TRUE;
			goto out;
		}
		storage_type = NMS_KEYFILE_STORAGE_TYPE_ETC;
		dirname = priv->dirname_etc;
	}

	if (simulate) {
		nmmeta_success = TRUE;
		nmmeta_filename = nms_keyfile_nmmeta_filename (dirname, uuid, FALSE);
	} else {
		nmmeta_success = nms_keyfile_nmmeta_write (dirname,
		                                           uuid,
		                                           loaded_path,
		                                           FALSE,
		                                           shadowed_storage,
		                                           &nmmeta_filename);
	}

	_LOGT ("commit: %s nmmeta file \"%s\"%s%s%s%s%s%s %s",
	       loaded_path ? "writing" : "deleting",
	       nmmeta_filename,
	       NM_PRINT_FMT_QUOTED (loaded_path, " (pointing to \"", loaded_path, "\")", ""),
	       NM_PRINT_FMT_QUOTED (shadowed_storage, " (shadows \"", shadowed_storage, "\")", ""),
	       simulate
	       ? "simulated"
	       : (  nmmeta_success
	          ? "succeeded"
	          : "failed"));

	if (!nmmeta_success)
		goto out;

	storage = nm_sett_util_storages_lookup_by_filename (&priv->storages, nmmeta_filename);

	nm_assert (   !storage
	           || (   storage->is_meta_data
	               && storage->storage_type == storage_type
	               && nm_streq (nms_keyfile_storage_get_uuid (storage), uuid)));

	if (loaded_path) {

		if (!storage) {
			storage = nms_keyfile_storage_new_tombstone (self,
			                                             uuid,
			                                             nmmeta_filename,
			                                             storage_type,
			                                             shadowed_storage);
			nm_sett_util_storages_add_take (&priv->storages, storage);
		} else {
			g_free (storage->u.meta_data.shadowed_storage);
			storage->u.meta_data.shadowed_storage = g_strdup (shadowed_storage);
		}

		storage_result = g_object_ref (storage);
	} else {
		if (storage)
			storage_result = nm_sett_util_storages_steal (&priv->storages, storage);
	}

out:
	nm_assert (!nmmeta_success || !hard_failure);
	nm_assert (nmmeta_success  || !storage_result);

	NM_SET_OUT (out_hard_failure, hard_failure);
	NM_SET_OUT (out_storage, (NMSettingsStorage *) g_steal_pointer (&storage_result));
	return nmmeta_success;
}

/*****************************************************************************/

static void
config_changed_cb (NMConfig *config,
                   NMConfigData *config_data,
                   NMConfigChangeFlags changes,
                   NMConfigData *old_data,
                   NMSKeyfilePlugin *self)
{
	gs_free char *old_value = NULL;
	gs_free char *new_value = NULL;

	old_value = nm_config_data_get_value (old_data,    NM_CONFIG_KEYFILE_GROUP_KEYFILE, NM_CONFIG_KEYFILE_KEY_KEYFILE_UNMANAGED_DEVICES, NM_CONFIG_GET_VALUE_TYPE_SPEC);
	new_value = nm_config_data_get_value (config_data, NM_CONFIG_KEYFILE_GROUP_KEYFILE, NM_CONFIG_KEYFILE_KEY_KEYFILE_UNMANAGED_DEVICES, NM_CONFIG_GET_VALUE_TYPE_SPEC);

	if (!nm_streq0 (old_value, new_value))
		_nm_settings_plugin_emit_signal_unmanaged_specs_changed (NM_SETTINGS_PLUGIN (self));
}

static GSList *
get_unmanaged_specs (NMSettingsPlugin *config)
{
	NMSKeyfilePluginPrivate *priv = NMS_KEYFILE_PLUGIN_GET_PRIVATE (config);
	gs_free char *value = NULL;

	value = nm_config_data_get_value (nm_config_get_data (priv->config),
	                                  NM_CONFIG_KEYFILE_GROUP_KEYFILE,
	                                  NM_CONFIG_KEYFILE_KEY_KEYFILE_UNMANAGED_DEVICES,
	                                  NM_CONFIG_GET_VALUE_TYPE_SPEC);
	return nm_match_spec_split (value);
}

/*****************************************************************************/

static void
nms_keyfile_plugin_init (NMSKeyfilePlugin *plugin)
{
	NMSKeyfilePluginPrivate *priv = NMS_KEYFILE_PLUGIN_GET_PRIVATE (plugin);

	priv->config = g_object_ref (nm_config_get ());

	priv->storages = (NMSettUtilStorages) NM_SETT_UTIL_STORAGES_INIT (priv->storages, nms_keyfile_storage_destroy);

	/* dirname_libs are a set of read-only directories with lower priority than /etc or /run.
	 * There is nothing complicated about having multiple of such directories, so dirname_libs
	 * is a list (which currently only has at most one directory). */
	priv->dirname_libs[0] = nm_sd_utils_path_simplify (g_strdup (NM_KEYFILE_PATH_NAME_LIB), FALSE);
	priv->dirname_libs[1] = NULL;
	priv->dirname_run = nm_sd_utils_path_simplify (g_strdup (NM_KEYFILE_PATH_NAME_RUN), FALSE);
	priv->dirname_etc = nm_config_data_get_value (NM_CONFIG_GET_DATA_ORIG,
	                                              NM_CONFIG_KEYFILE_GROUP_KEYFILE,
	                                              NM_CONFIG_KEYFILE_KEY_KEYFILE_PATH,
	                                              NM_CONFIG_GET_VALUE_STRIP);
	if (priv->dirname_etc && priv->dirname_etc[0] == '\0') {
		/* special case: configure an empty keyfile path so that NM has no writable keyfile
		 * directory. In this case, NM will only honor dirname_libs and dirname_run, meaning
		 * it cannot persist profile to non-volatile memory. */
		nm_clear_g_free (&priv->dirname_etc);
	} else if (!priv->dirname_etc || priv->dirname_etc[0] != '/') {
		/* either invalid path or unspecified. Use the default. */
		g_free (priv->dirname_etc);
		priv->dirname_etc = nm_sd_utils_path_simplify (g_strdup (NM_KEYFILE_PATH_NAME_ETC_DEFAULT), FALSE);
	} else
		nm_sd_utils_path_simplify (priv->dirname_etc, FALSE);

	/* no duplicates */
	if (NM_IN_STRSET (priv->dirname_libs[0], priv->dirname_etc,
	                                         priv->dirname_run))
		nm_clear_g_free (&priv->dirname_libs[0]);
	if (NM_IN_STRSET (priv->dirname_etc, priv->dirname_run))
		nm_clear_g_free (&priv->dirname_etc);

	nm_assert (!priv->dirname_libs[0] || priv->dirname_libs[0][0] == '/');
	nm_assert (!priv->dirname_etc     || priv->dirname_etc[0]     == '/');
	nm_assert ( priv->dirname_run     && priv->dirname_run[0]     == '/');
}

static void
constructed (GObject *object)
{
	NMSKeyfilePlugin *self = NMS_KEYFILE_PLUGIN (object);
	NMSKeyfilePluginPrivate *priv = NMS_KEYFILE_PLUGIN_GET_PRIVATE (self);

	G_OBJECT_CLASS (nms_keyfile_plugin_parent_class)->constructed (object);

	if (nm_config_data_has_value (nm_config_get_data_orig (priv->config),
	                              NM_CONFIG_KEYFILE_GROUP_KEYFILE,
	                              NM_CONFIG_KEYFILE_KEY_KEYFILE_HOSTNAME,
	                              NM_CONFIG_GET_VALUE_RAW))
		_LOGW ("'hostname' option is deprecated and has no effect");

	if (nm_config_data_has_value (nm_config_get_data_orig (priv->config),
	                              NM_CONFIG_KEYFILE_GROUP_MAIN,
	                              NM_CONFIG_KEYFILE_KEY_MAIN_MONITOR_CONNECTION_FILES,
	                              NM_CONFIG_GET_VALUE_RAW))
		_LOGW ("'monitor-connection-files' option is deprecated and has no effect");

	g_signal_connect (G_OBJECT (priv->config),
	                  NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_CALLBACK (config_changed_cb),
	                  self);
}

NMSKeyfilePlugin *
nms_keyfile_plugin_new (void)
{
	return g_object_new (NMS_TYPE_KEYFILE_PLUGIN, NULL);
}

static void
dispose (GObject *object)
{
	NMSKeyfilePlugin *self = NMS_KEYFILE_PLUGIN (object);
	NMSKeyfilePluginPrivate *priv = NMS_KEYFILE_PLUGIN_GET_PRIVATE (self);

	if (priv->config)
		g_signal_handlers_disconnect_by_func (priv->config, config_changed_cb, object);

	nm_sett_util_storages_clear (&priv->storages);

	nm_clear_g_free (&priv->dirname_libs[0]);
	nm_clear_g_free (&priv->dirname_etc);
	nm_clear_g_free (&priv->dirname_run);

	g_clear_object (&priv->config);

	G_OBJECT_CLASS (nms_keyfile_plugin_parent_class)->dispose (object);
}

static void
nms_keyfile_plugin_class_init (NMSKeyfilePluginClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingsPluginClass *plugin_class = NM_SETTINGS_PLUGIN_CLASS (klass);

	object_class->constructed = constructed;
	object_class->dispose     = dispose;

	plugin_class->plugin_name         = "keyfile";
	plugin_class->get_unmanaged_specs = get_unmanaged_specs;
	plugin_class->reload_connections  = reload_connections;
	plugin_class->load_connections    = load_connections;
	plugin_class->add_connection      = add_connection;
	plugin_class->update_connection   = update_connection;
	plugin_class->delete_connection   = delete_connection;
}
