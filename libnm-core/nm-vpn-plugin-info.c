/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2015 Red Hat, Inc.
 */

#include "config.h"

#include "nm-vpn-plugin-info.h"

#include <gio/gio.h>
#include <glib/gi18n-lib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include "gsystem-local-alloc.h"
#include "nm-errors.h"
#include "nm-macros-internal.h"
#include "nm-core-internal.h"

#define DEFAULT_DIR_ETC     NMCONFDIR"/VPN"
#define DEFAULT_DIR_LIB     NMLIBDIR"/VPN"

enum {
	PROP_0,
	PROP_NAME,
	PROP_FILENAME,
	PROP_KEYFILE,

	LAST_PROP,
};

typedef struct {
	char *filename;
	char *name;
	char *service;
	GKeyFile *keyfile;

	/* It is convenient for nm_vpn_plugin_info_lookup_property() to return a const char *,
	 * contrary to what g_key_file_get_string() does. Hence we must cache the returned
	 * value somewhere... let's put it in an internal hash table.
	 * This contains a clone of all the strings in keyfile. */
	GHashTable *keys;

	gboolean editor_plugin_loaded;
	NMVpnEditorPlugin *editor_plugin;
} NMVpnPluginInfoPrivate;

static void nm_vpn_plugin_info_initable_iface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (NMVpnPluginInfo, nm_vpn_plugin_info, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_vpn_plugin_info_initable_iface_init);
                         )

#define NM_VPN_PLUGIN_INFO_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_PLUGIN_INFO, NMVpnPluginInfoPrivate))

/*********************************************************************/

/**
 * nm_vpn_plugin_info_validate_filename:
 * @filename: the filename to check
 *
 * Regular name files have a certain pattern. That basically means
 * they have the file extension "name". Check if @filename
 * is valid according to that pattern.
 *
 * Since: 1.2
 */
gboolean
nm_vpn_plugin_info_validate_filename (const char *filename)
{
	if (!filename || !g_str_has_suffix (filename, ".name"))
		return FALSE;

	/* originally, we didn't do further checks... but here we go. */
	if (filename[0] == '.') {
		/* this also rejects name ".name" alone. */
		return FALSE;
	}
	return TRUE;
}

static gboolean
nm_vpn_plugin_info_check_file_full (const char *filename,
                                    gboolean check_absolute,
                                    gboolean do_validate_filename,
                                    gint64 check_owner,
                                    NMUtilsCheckFilePredicate check_file,
                                    gpointer user_data,
                                    struct stat *out_st,
                                    GError **error)
{
	if (!filename || !*filename) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_FAILED,
		             _("missing filename"));
		return FALSE;
	}

	if (check_absolute && !g_path_is_absolute (filename)) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_FAILED,
		             _("filename must be an absolute path (%s)"), filename);
		return FALSE;
	}

	if (   do_validate_filename
	    && !nm_vpn_plugin_info_validate_filename (filename)) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_FAILED,
		             _("filename has invalid format (%s)"), filename);
		return FALSE;
	}

	return _nm_utils_check_file (filename,
	                             check_owner,
	                             check_file,
	                             user_data,
	                             out_st,
	                             error);
}

/**
 * _nm_vpn_plugin_info_check_file:
 * @filename:
 * @check_absolute: if %TRUE, only allow absolute path names.
 * @do_validate_filename: if %TRUE, only accept the filename if
 *   nm_vpn_plugin_info_validate_filename() succeeds.
 * @check_owner: if non-negative, only accept the file if the
 *   owner UID is equal to @check_owner or if the owner is 0.
 *   In this case, also check that the file is not writable by
 *   other users.
 * @check_file: pass a callback to do your own validation.
 * @user_data: user data for @check_file.
 * @error: (allow-none): (out): the error reason if the check fails.
 *
 * Check whether the file exists and is a valid name file (in keyfile format).
 * Additionally, also check for file permissions.
 *
 * Returns: %TRUE if a file @filename exists and has valid permissions.
 *
 * Since: 1.2
 */
gboolean
_nm_vpn_plugin_info_check_file (const char *filename,
                                gboolean check_absolute,
                                gboolean do_validate_filename,
                                gint64 check_owner,
                                NMUtilsCheckFilePredicate check_file,
                                gpointer user_data,
                                GError **error)
{
	return nm_vpn_plugin_info_check_file_full (filename, check_absolute, do_validate_filename, check_owner, check_file, user_data, NULL, error);
}

typedef struct {
	NMVpnPluginInfo *plugin_info;
	struct stat stat;
} LoadDirInfo;

static int
_sort_files (LoadDirInfo *a, LoadDirInfo *b)
{
	time_t ta, tb;

	ta = MAX (a->stat.st_mtime, a->stat.st_ctime);
	tb = MAX (b->stat.st_mtime, b->stat.st_ctime);
	if (ta < tb)
		return 1;
	if (ta > tb)
		return -1;
	return g_strcmp0 (nm_vpn_plugin_info_get_filename (a->plugin_info),
	                  nm_vpn_plugin_info_get_filename (b->plugin_info));
}

/**
 * _nm_vpn_plugin_info_get_default_dir_etc:
 *
 * Returns: (transfer-none): compile time constant of the default
 *   VPN plugin directory.
 */
const char *
_nm_vpn_plugin_info_get_default_dir_etc ()
{
	return DEFAULT_DIR_ETC;
}

/**
 * _nm_vpn_plugin_info_get_default_dir_lib:
 *
 * Returns: (transfer-none): compile time constant of the default
 *   VPN plugin directory.
 */
const char *
_nm_vpn_plugin_info_get_default_dir_lib ()
{
	return DEFAULT_DIR_LIB;
}

/**
 * _nm_vpn_plugin_info_get_default_dir_user:
 *
 * Returns: The user can specify a different directory for VPN plugins
 * by setting NM_VPN_PLUGIN_DIR environment variable. Return
 * that directory.
 */
const char *
_nm_vpn_plugin_info_get_default_dir_user ()
{
	return g_getenv ("NM_VPN_PLUGIN_DIR");
}

/**
 * _nm_vpn_plugin_info_list_load_dir:
 * @dirname: the name of the directory to load.
 * @do_validate_filename: only consider filenames that have a certain
 *   pattern (i.e. end with ".name").
 * @check_owner: if set to a non-negative number, check that the file
 *   owner is either the same uid or 0. In that case, also check
 *   that the file is not writable by group or other.
 * @check_file: (allow-none): callback to check whether the file is valid.
 * @user_data: data for @check_file
 *
 * Iterate over the content of @dirname and load name files.
 *
 * Returns: (transfer-full): list of loaded plugin infos.
 */
GSList *
_nm_vpn_plugin_info_list_load_dir (const char *dirname,
                                   gboolean do_validate_filename,
                                   gint64 check_owner,
                                   NMUtilsCheckFilePredicate check_file,
                                   gpointer user_data)
{
	GDir *dir;
	const char *fn;
	GArray *array;
	GSList *res = NULL;
	guint i;

	g_return_val_if_fail (dirname && dirname[0], NULL);

	dir = g_dir_open (dirname, 0, NULL);
	if (!dir)
		return NULL;

	array = g_array_new (FALSE, FALSE, sizeof (LoadDirInfo));

	while ((fn = g_dir_read_name (dir))) {
		gs_free char *filename = NULL;
		LoadDirInfo info = { 0 };

		filename = g_build_filename (dirname, fn, NULL);
		if (nm_vpn_plugin_info_check_file_full (filename,
		                                        FALSE,
		                                        do_validate_filename,
		                                        check_owner,
		                                        check_file,
		                                        user_data,
		                                        &info.stat,
		                                        NULL)) {
			info.plugin_info = nm_vpn_plugin_info_new_from_file (filename, NULL);
			if (info.plugin_info) {
				g_array_append_val (array, info);
				continue;
			}
		}
	}
	g_dir_close (dir);

	/* sort the files so that we have a stable behavior. The directory might contain
	 * duplicate VPNs, so while nm_vpn_plugin_info_list_load() would load them all, the
	 * caller probably wants to reject duplicates. Having a stable order means we always
	 * reject the same files in face of duplicates. */
	g_array_sort (array, (GCompareFunc) _sort_files);

	for (i = 0; i < array->len; i++)
		res = g_slist_prepend (res, g_array_index (array, LoadDirInfo, i).plugin_info);

	g_array_unref (array);

	return g_slist_reverse (res);
}

/**
 * nm_vpn_plugin_info_list_load:
 *
 * Returns: (tranfer-full): list of plugins loaded from the default
 * directories rejecting duplicates.
 *
 * Since: 1.2
 */
GSList *
nm_vpn_plugin_info_list_load ()
{
	int i;
	gint64 uid;
	GSList *list = NULL;
	GSList *infos, *info;
	const char *dir[] = {
		/* We load plugins from NM_VPN_PLUGIN_DIR *and* DEFAULT_DIR*, with
		 * preference to the former.
		 *
		 * load user directory with highest priority. */
		_nm_vpn_plugin_info_get_default_dir_user (),

		/* lib directory has higher priority then etc. The reason is that
		 * etc is deprecated and used by old plugins. We expect newer plugins
		 * to install their file in lib, where they have higher priority.
		 *
		 * Optimally, there are no duplicates anyway, so it doesn't really matter. */
		_nm_vpn_plugin_info_get_default_dir_lib (),
		_nm_vpn_plugin_info_get_default_dir_etc (),
	};

	uid = getuid ();

	for (i = 0; i < G_N_ELEMENTS (dir); i++) {
		if (   !dir[i]
		    || _nm_utils_strv_find_first ((char **) dir, i, dir[i]) >= 0)
			continue;

		infos = _nm_vpn_plugin_info_list_load_dir (dir[i], TRUE, uid, NULL, NULL);

		for (info = infos; info; info = info->next)
			nm_vpn_plugin_info_list_add (&list, info->data, NULL);

		g_slist_free_full (infos, g_object_unref);
	}
	return list;
}

/*********************************************************************/

static gboolean
_check_no_conflict (NMVpnPluginInfo *i1, NMVpnPluginInfo *i2, GError **error)
{
	NMVpnPluginInfoPrivate *priv1, *priv2;
	uint i;
	struct {
		const char *group;
		const char *key;
	} check_list[] = {
		{ NM_VPN_PLUGIN_INFO_KF_GROUP_CONNECTION, "service" },
		{ NM_VPN_PLUGIN_INFO_KF_GROUP_LIBNM,      "plugin" },
		{ NM_VPN_PLUGIN_INFO_KF_GROUP_GNOME,      "properties" },
	};

	priv1 = NM_VPN_PLUGIN_INFO_GET_PRIVATE (i1);
	priv2 = NM_VPN_PLUGIN_INFO_GET_PRIVATE (i2);

	for (i = 0; i < G_N_ELEMENTS (check_list); i++) {
		gs_free NMUtilsStrStrDictKey *k = NULL;
		const char *s1, *s2;

		k = _nm_utils_strstrdictkey_create (check_list[i].group, check_list[i].key);
		s1 = g_hash_table_lookup (priv1->keys, k);
		if (!s1)
			continue;
		s2 = g_hash_table_lookup (priv2->keys, k);
		if (!s2)
			continue;

		if (strcmp (s1, s2) == 0) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_FAILED,
			             _("there exists a conflicting plugin (%s) that has the same %s.%s value"),
			             priv2->name,
			             check_list[i].group, check_list[i].key);
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * nm_vpn_plugin_info_list_add:
 * @list: list of plugins
 * @plugin_info: instance to add
 * @error: failure reason
 *
 * Returns: %TRUE if the plugin was added to @list. This will fail
 * to add duplicate plugins.
 *
 * Since: 1.2
 */
gboolean
nm_vpn_plugin_info_list_add (GSList **list, NMVpnPluginInfo *plugin_info, GError **error)
{
	GSList *iter;
	const char *name;

	g_return_val_if_fail (list, FALSE);
	g_return_val_if_fail (NM_IS_VPN_PLUGIN_INFO (plugin_info), FALSE);

	name = nm_vpn_plugin_info_get_name (plugin_info);
	for (iter = *list; iter; iter = iter->next) {
		if (iter->data == plugin_info)
			return TRUE;

		if (strcmp (nm_vpn_plugin_info_get_name (iter->data), name) == 0) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_FAILED,
			             _("there exists a conflicting plugin with the same name (%s)"),
			             name);
			return FALSE;
		}

		/* the plugin must have unique values for certain properties. E.g. two different
		 * plugins cannot share the same D-Bus service name. */
		if (!_check_no_conflict (plugin_info, iter->data, error))
			return FALSE;
	}

	*list = g_slist_append (*list, g_object_ref (plugin_info));
	return TRUE;
}

/**
 * nm_vpn_plugin_info_list_remove:
 * @list: list of plugins
 * @plugin_info: instance
 *
 * Remove @plugin_info from @list.
 *
 * Returns: %TRUE if @plugin_info was in @list and successfully removed.
 *
 * Since: 1.2
 */
gboolean
nm_vpn_plugin_info_list_remove (GSList **list, NMVpnPluginInfo *plugin_info)
{
	if (!plugin_info)
		return FALSE;

	g_return_val_if_fail (list, FALSE);
	g_return_val_if_fail (NM_IS_VPN_PLUGIN_INFO (plugin_info), FALSE);

	if (!g_slist_find (*list, plugin_info))
		return FALSE;

	*list = g_slist_remove (*list, plugin_info);
	g_object_unref (plugin_info);
	return TRUE;
}

/**
 * nm_vpn_plugin_info_list_find_by_name:
 * @list: list of plugins
 * @name: name to search
 *
 * Returns: the first plugin with a matching @name (or %NULL).
 *
 * Since: 1.2
 */
NMVpnPluginInfo *
nm_vpn_plugin_info_list_find_by_name (GSList *list, const char *name)
{
	GSList *iter;

	if (!name)
		g_return_val_if_reached (NULL);

	for (iter = list; iter; iter = iter->next) {
		if (strcmp (nm_vpn_plugin_info_get_name (iter->data), name) == 0)
			return iter->data;
	}
	return NULL;
}

/**
 * nm_vpn_plugin_info_list_find_by_filename:
 * @list: list of plugins
 * @filename: filename to search
 *
 * Returns: the first plugin with a matching @filename (or %NULL).
 *
 * Since: 1.2
 */
NMVpnPluginInfo *
nm_vpn_plugin_info_list_find_by_filename (GSList *list, const char *filename)
{
	GSList *iter;

	if (!filename)
		g_return_val_if_reached (NULL);

	for (iter = list; iter; iter = iter->next) {
		if (g_strcmp0 (nm_vpn_plugin_info_get_filename (iter->data), filename) == 0)
			return iter->data;
	}
	return NULL;
}

/**
 * nm_vpn_plugin_info_list_find_by_service:
 * @list: list of plugins
 * @service: service to search
 *
 * Returns: the first plugin with a matching @service (or %NULL).
 *
 * Since: 1.2
 */
NMVpnPluginInfo *
nm_vpn_plugin_info_list_find_by_service (GSList *list, const char *service)
{
	GSList *iter;

	if (!service)
		g_return_val_if_reached (NULL);

	for (iter = list; iter; iter = iter->next) {
		if (strcmp (nm_vpn_plugin_info_get_service (iter->data), service) == 0)
			return iter->data;
	}
	return NULL;
}

/*********************************************************************/

/**
 * nm_vpn_plugin_info_get_filename:
 * @self: plugin info instance
 *
 * Returns: (transfer-none): the filename. Can be %NULL.
 *
 * Since: 1.2
 */
const char *
nm_vpn_plugin_info_get_filename (NMVpnPluginInfo *self)
{
	g_return_val_if_fail (NM_IS_VPN_PLUGIN_INFO (self), NULL);

	return NM_VPN_PLUGIN_INFO_GET_PRIVATE (self)->filename;
}

/**
 * nm_vpn_plugin_info_get_name:
 * @self: plugin info instance
 *
 * Returns: (transfer-none): the name. Cannot be %NULL.
 *
 * Since: 1.2
 */
const char *
nm_vpn_plugin_info_get_name (NMVpnPluginInfo *self)
{
	g_return_val_if_fail (NM_IS_VPN_PLUGIN_INFO (self), NULL);

	return NM_VPN_PLUGIN_INFO_GET_PRIVATE (self)->name;
}

/**
 * nm_vpn_plugin_info_get_service:
 * @self: plugin info instance
 *
 * Returns: (transfer-none): the service. Cannot be %NULL.
 *
 * Since: 1.2
 */
const char *
nm_vpn_plugin_info_get_service (NMVpnPluginInfo *self)
{
	g_return_val_if_fail (NM_IS_VPN_PLUGIN_INFO (self), NULL);

	return NM_VPN_PLUGIN_INFO_GET_PRIVATE (self)->service;
}

/**
 * nm_vpn_plugin_info_get_plugin:
 * @self: plugin info instance
 *
 * Returns: (transfer-none): the plugin. Can be %NULL.
 *
 * Since: 1.2
 */
const char *
nm_vpn_plugin_info_get_plugin (NMVpnPluginInfo *self)
{
	g_return_val_if_fail (NM_IS_VPN_PLUGIN_INFO (self), NULL);

	return g_hash_table_lookup (NM_VPN_PLUGIN_INFO_GET_PRIVATE (self)->keys,
	                            _nm_utils_strstrdictkey_static (NM_VPN_PLUGIN_INFO_KF_GROUP_LIBNM, "plugin"));
}

/**
 * nm_vpn_plugin_info_get_program:
 * @self: plugin info instance
 *
 * Returns: (transfer-none): the program. Can be %NULL.
 *
 * Since: 1.2
 */
const char *
nm_vpn_plugin_info_get_program (NMVpnPluginInfo *self)
{
	g_return_val_if_fail (NM_IS_VPN_PLUGIN_INFO (self), NULL);

	return g_hash_table_lookup (NM_VPN_PLUGIN_INFO_GET_PRIVATE (self)->keys,
	                            _nm_utils_strstrdictkey_static (NM_VPN_PLUGIN_INFO_KF_GROUP_CONNECTION, "program"));
}

/**
 * nm_vpn_plugin_info_lookup_property:
 * @self: plugin info instance
 * @group: group name
 * @key: name of the property
 *
 * Returns: (transfer-none): #NMVpnPluginInfo is internally a #GKeyFile. Returns the matching
 * property.
 *
 * Since: 1.2
 */
const char *
nm_vpn_plugin_info_lookup_property (NMVpnPluginInfo *self, const char *group, const char *key)
{
	NMVpnPluginInfoPrivate *priv;
	gs_free NMUtilsStrStrDictKey *k = NULL;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN_INFO (self), NULL);
	g_return_val_if_fail (group, NULL);
	g_return_val_if_fail (key, NULL);

	priv = NM_VPN_PLUGIN_INFO_GET_PRIVATE (self);

	k = _nm_utils_strstrdictkey_create (group, key);
	return g_hash_table_lookup (priv->keys, k);
}

/*********************************************************************/

/**
 * nm_vpn_plugin_info_get_editor_plugin:
 * @self: plugin info instance
 *
 * Returns: the cached #NMVpnEditorPlugin instance.
 *
 * Since: 1.2
 */
NMVpnEditorPlugin *
nm_vpn_plugin_info_get_editor_plugin (NMVpnPluginInfo *self)
{
	g_return_val_if_fail (NM_IS_VPN_PLUGIN_INFO (self), NULL);

	return NM_VPN_PLUGIN_INFO_GET_PRIVATE (self)->editor_plugin;
}

/**
 * nm_vpn_plugin_info_set_editor_plugin:
 * @self: plugin info instance
 * @plugin: (allow-none): plugin instance
 *
 * Set the internal plugin instance. If %NULL, only clear the previous instance.
 *
 * Since: 1.2
 */
void
nm_vpn_plugin_info_set_editor_plugin (NMVpnPluginInfo *self, NMVpnEditorPlugin *plugin)
{
	NMVpnPluginInfoPrivate *priv;
	NMVpnEditorPlugin *old;

	g_return_if_fail (NM_IS_VPN_PLUGIN_INFO (self));
	g_return_if_fail (!plugin || G_IS_OBJECT (plugin));

	priv = NM_VPN_PLUGIN_INFO_GET_PRIVATE (self);

	if (!plugin) {
		priv->editor_plugin_loaded = FALSE;
		g_clear_object (&priv->editor_plugin);
	} else {
		old = priv->editor_plugin;
		priv->editor_plugin = g_object_ref (plugin);
		priv->editor_plugin_loaded = TRUE;
		if (old)
			g_object_unref (old);
	}
}

/**
 * nm_vpn_plugin_info_load_editor_plugin:
 * @self: plugin info instance
 * @error: error reason on failure
 *
 * Returns: loads the plugin and returns the newly created instance.
 *   The plugin is owned by @self and can be later retrieved again
 *   via nm_vpn_plugin_info_get_editor_plugin(). You can load the
 *   plugin only once, unless you reset the state via
 *   nm_vpn_plugin_info_set_editor_plugin().
 *
 * Since: 1.2
 */
NMVpnEditorPlugin *
nm_vpn_plugin_info_load_editor_plugin (NMVpnPluginInfo *self, GError **error)
{
	NMVpnPluginInfoPrivate *priv;
	const char *plugin_filename;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN_INFO (self), NULL);

	priv = NM_VPN_PLUGIN_INFO_GET_PRIVATE (self);

	if (priv->editor_plugin)
		return priv->editor_plugin;

	plugin_filename = nm_vpn_plugin_info_get_plugin (self);
	if (!plugin_filename || !*plugin_filename) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_FAILED,
		             _("missing \"plugin\" setting"));
		return NULL;
	}

	/* We only try once to load the plugin. If we previously tried and it was
	 * unsuccessful, error out immediately. */
	if (priv->editor_plugin_loaded) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_FAILED,
		             _("%s: don't retry loading plugin which already failed previously"), priv->name);
		return NULL;
	}

	priv->editor_plugin_loaded = TRUE;
	priv->editor_plugin = nm_vpn_editor_plugin_load_from_file (plugin_filename,
	                                                           priv->name,
	                                                           nm_vpn_plugin_info_get_service (self),
	                                                           getuid (),
	                                                           NULL,
	                                                           NULL,
	                                                           error);
	return priv->editor_plugin;
}

/*********************************************************************/

/**
 * nm_vpn_plugin_info_new_from_file:
 * @filename: filename to read.
 * @error: on failure, the error reason.
 *
 * Read the plugin info from file @filename. Does not do
 * any further verification on the file. You might want to check
 * file permissions and ownership of the file.
 *
 * Returns: %NULL if there is any error or a newly created
 * #NMVpnPluginInfo instance.
 *
 * Since: 1.2
 */
NMVpnPluginInfo *
nm_vpn_plugin_info_new_from_file (const char *filename,
                                  GError **error)
{
	g_return_val_if_fail (filename, NULL);

	return NM_VPN_PLUGIN_INFO (g_initable_new (NM_TYPE_VPN_PLUGIN_INFO,
	                                           NULL,
	                                           error,
	                                           NM_VPN_PLUGIN_INFO_FILENAME, filename,
	                                           NULL));
}

/**
 * nm_vpn_plugin_info_new_with_data:
 * @filename: optional filename.
 * @keyfile: inject data for the plugin info instance.
 * @error: construction may fail if the keyfile lacks mandatory fields.
 *   In this case, return the error reason.
 *
 * This constructor does not read any data from file but
 * takes instead a @keyfile argument.
 *
 * Returns: new plugin info instance.
 *
 * Since: 1.2
 */
NMVpnPluginInfo *
nm_vpn_plugin_info_new_with_data (const char *filename,
                                  GKeyFile *keyfile,
                                  GError **error)
{
	g_return_val_if_fail (keyfile, NULL);

	return NM_VPN_PLUGIN_INFO (g_initable_new (NM_TYPE_VPN_PLUGIN_INFO,
	                                           NULL,
	                                           error,
	                                           NM_VPN_PLUGIN_INFO_FILENAME, filename,
	                                           NM_VPN_PLUGIN_INFO_KEYFILE, keyfile,
	                                           NULL));
}

/*********************************************************************/

static void
nm_vpn_plugin_info_init (NMVpnPluginInfo *plugin)
{
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMVpnPluginInfo *self = NM_VPN_PLUGIN_INFO (initable);
	NMVpnPluginInfoPrivate *priv = NM_VPN_PLUGIN_INFO_GET_PRIVATE (self);
	gs_strfreev char **groups = NULL;
	guint i, j;

	if (!priv->keyfile) {
		if (!priv->filename) {
			g_set_error_literal (error,
			                     NM_VPN_PLUGIN_ERROR,
			                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			                     _("missing filename to load VPN plugin info"));
			return FALSE;
		}
		priv->keyfile = g_key_file_new ();
		if (!g_key_file_load_from_file (priv->keyfile, priv->filename, G_KEY_FILE_NONE, error))
			return FALSE;
	}

	/* we reqire at least a "name" */
	priv->name = g_key_file_get_string (priv->keyfile, NM_VPN_PLUGIN_INFO_KF_GROUP_CONNECTION, "name", NULL);
	if (!priv->name || !priv->name[0]) {
		g_set_error_literal (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                     _("missing name for VPN plugin info"));
		return FALSE;
	}

	/* we also require "service", because that how we associate NMSettingVpn:service-type with the
	 * NMVpnPluginInfo. */
	priv->service = g_key_file_get_string (priv->keyfile, NM_VPN_PLUGIN_INFO_KF_GROUP_CONNECTION, "service", NULL);
	if (!priv->service || !*priv->service) {
		g_set_error_literal (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                     _("missing service for VPN plugin info"));
		return FALSE;
	}

	priv->keys = g_hash_table_new_full (_nm_utils_strstrdictkey_hash,
	                                    _nm_utils_strstrdictkey_equal,
	                                    g_free, g_free);
	groups = g_key_file_get_groups (priv->keyfile, NULL);
	for (i = 0; groups && groups[i]; i++) {
		gs_strfreev char **keys = NULL;

		keys = g_key_file_get_keys (priv->keyfile, groups[i], NULL, NULL);
		for (j = 0; keys && keys[j]; j++) {
			char *s;

			/* Lookup the value via get_string(). We want that behavior.
			 * You could still lookup the original values via g_key_file_get_value()
			 * based on priv->keyfile. */
			s = g_key_file_get_string (priv->keyfile, groups[i], keys[j], NULL);
			if (s)
				g_hash_table_insert (priv->keys, _nm_utils_strstrdictkey_create (groups[i], keys[j]), s);
		}
	}

	return TRUE;
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMVpnPluginInfoPrivate *priv = NM_VPN_PLUGIN_INFO_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_FILENAME:
		priv->filename = g_value_dup_string (value);
		break;
	case PROP_KEYFILE:
		priv->keyfile = g_value_dup_boxed (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMVpnPluginInfoPrivate *priv = NM_VPN_PLUGIN_INFO_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, priv->name);
		break;
	case PROP_FILENAME:
		g_value_set_string (value, priv->filename);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMVpnPluginInfo *self = NM_VPN_PLUGIN_INFO (object);
	NMVpnPluginInfoPrivate *priv = NM_VPN_PLUGIN_INFO_GET_PRIVATE (self);

	g_clear_object (&priv->editor_plugin);

	G_OBJECT_CLASS (nm_vpn_plugin_info_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMVpnPluginInfo *self = NM_VPN_PLUGIN_INFO (object);
	NMVpnPluginInfoPrivate *priv = NM_VPN_PLUGIN_INFO_GET_PRIVATE (self);

	g_free (priv->name);
	g_free (priv->service);
	g_free (priv->filename);
	g_key_file_unref (priv->keyfile);
	g_hash_table_unref (priv->keys);

	G_OBJECT_CLASS (nm_vpn_plugin_info_parent_class)->finalize (object);
}

static void
nm_vpn_plugin_info_class_init (NMVpnPluginInfoClass *plugin_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (plugin_class);

	g_type_class_add_private (object_class, sizeof (NMVpnPluginInfoPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose      = dispose;
	object_class->finalize     = finalize;

	/* properties */

	/**
	 * NMVpnPluginInfo:name:
	 *
	 * The name of the VPN plugin.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
	    (object_class, PROP_NAME,
	     g_param_spec_string (NM_VPN_PLUGIN_INFO_NAME, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS));

	/**
	 * NMVpnPluginInfo:filename:
	 *
	 * The filename from which the info was loaded.
	 * Can be %NULL if the instance was not loaded from
	 * a file (i.e. the keyfile instance was passed to the
	 * constructor).
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
	    (object_class, PROP_FILENAME,
	     g_param_spec_string (NM_VPN_PLUGIN_INFO_FILENAME, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	/**
	 * NMVpnPluginInfo:keyfile:
	 *
	 * Initalize the instance with a different keyfile instance.
	 * When passing a keyfile instance, the constructor will not
	 * try to read from filename.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
	    (object_class, PROP_KEYFILE,
	     g_param_spec_boxed (NM_VPN_PLUGIN_INFO_KEYFILE, "", "",
	                         G_TYPE_KEY_FILE,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS));
}

static void
nm_vpn_plugin_info_initable_iface_init (GInitableIface *iface)
{
	iface->init = init_sync;
}

