/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager
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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

#include <gmodule.h>

#include "nm-device-factory.h"
#include "nm-logging.h"
#include "nm-platform.h"

const NMLinkType _nm_device_factory_no_default_links[] = { NM_LINK_TYPE_NONE };
const char *_nm_device_factory_no_default_settings[] = { NULL };

enum {
	DEVICE_ADDED,
	COMPONENT_ADDED,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

gboolean
nm_device_factory_emit_component_added (NMDeviceFactory *factory, GObject *component)
{
	gboolean consumed = FALSE;

	g_signal_emit (factory, signals[COMPONENT_ADDED], 0, component, &consumed);
	return consumed;
}

static void
interface_init (gpointer g_iface)
{
	GType iface_type = G_TYPE_FROM_INTERFACE (g_iface);
	static gboolean initialized = FALSE;

	if (G_LIKELY (initialized))
		return;

	/* Signals */
	signals[DEVICE_ADDED] = g_signal_new (NM_DEVICE_FACTORY_DEVICE_ADDED,
	                                      iface_type,
	                                      G_SIGNAL_RUN_FIRST,
	                                      G_STRUCT_OFFSET (NMDeviceFactory, device_added),
	                                      NULL, NULL, NULL,
	                                      G_TYPE_NONE, 1, NM_TYPE_DEVICE);

	signals[COMPONENT_ADDED] = g_signal_new (NM_DEVICE_FACTORY_COMPONENT_ADDED,
	                                         iface_type,
	                                         G_SIGNAL_RUN_LAST,
	                                         G_STRUCT_OFFSET (NMDeviceFactory, component_added),
	                                         g_signal_accumulator_true_handled, NULL, NULL,
	                                         G_TYPE_BOOLEAN, 1, G_TYPE_OBJECT);

	initialized = TRUE;
}

GType
nm_device_factory_get_type (void)
{
	static GType device_factory_type = 0;

	if (!device_factory_type) {
		const GTypeInfo device_factory_info = {
			sizeof (NMDeviceFactory), /* class_size */
			interface_init,           /* base_init */
			NULL,                     /* base_finalize */
			NULL,
			NULL,                     /* class_finalize */
			NULL,                     /* class_data */
			0,
			0,                        /* n_preallocs */
			NULL
		};

		device_factory_type = g_type_register_static (G_TYPE_INTERFACE,
		                                              "NMDeviceFactory",
		                                              &device_factory_info,
		                                              0);
		g_type_interface_add_prerequisite (device_factory_type, G_TYPE_OBJECT);
	}

	return device_factory_type;
}

void
nm_device_factory_get_supported_types (NMDeviceFactory *factory,
                                       const NMLinkType **out_link_types,
                                       const char ***out_setting_types)
{
	const NMLinkType *link_types_fallback;
	const char **setting_types_fallback;

	g_return_if_fail (factory != NULL);

	if (!out_link_types)
		out_link_types = &link_types_fallback;
	if (!out_setting_types)
		out_setting_types = &setting_types_fallback;

	NM_DEVICE_FACTORY_GET_INTERFACE (factory)->get_supported_types (factory,
	                                                                out_link_types,
	                                                                out_setting_types);
}

void
nm_device_factory_start (NMDeviceFactory *factory)
{
	g_return_if_fail (factory != NULL);

	if (NM_DEVICE_FACTORY_GET_INTERFACE (factory)->start)
		NM_DEVICE_FACTORY_GET_INTERFACE (factory)->start (factory);
}

NMDevice *
nm_device_factory_new_link (NMDeviceFactory *factory,
                            NMPlatformLink *plink,
                            GError **error)
{
	NMDeviceFactory *interface;
	const NMLinkType *link_types = NULL;
	const char **setting_types = NULL;
	int i;

	g_return_val_if_fail (factory != NULL, NULL);
	g_return_val_if_fail (plink != NULL, NULL);

	/* Ensure the factory can create interfaces for this connection */
	nm_device_factory_get_supported_types (factory, &link_types, &setting_types);
	for (i = 0; link_types[i] > NM_LINK_TYPE_UNKNOWN; i++) {
		if (plink->type == link_types[i])
			break;
	}

	if (link_types[i] == NM_LINK_TYPE_UNKNOWN) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Device factory %s does not support link type %s (%d)",
		             G_OBJECT_TYPE_NAME (factory),
		             plink->kind, plink->type);
		return NULL;
	}

	interface = NM_DEVICE_FACTORY_GET_INTERFACE (factory);
	if (!interface->new_link) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		             "Device factory %s cannot manage new devices",
		             G_OBJECT_TYPE_NAME (factory));
		return NULL;
	}

	return interface->new_link (factory, plink, error);
}

NMDevice *
nm_device_factory_create_virtual_device_for_connection (NMDeviceFactory *factory,
                                                        NMConnection *connection,
                                                        NMDevice *parent,
                                                        GError **error)
{
	NMDeviceFactory *interface;
	const char **setting_types = NULL;
	gboolean found = FALSE;
	int i;

	g_return_val_if_fail (factory, NULL);
	g_return_val_if_fail (connection, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	/* Ensure the factory can create interfaces for this connection */
	nm_device_factory_get_supported_types (factory, NULL, &setting_types);
	for (i = 0; setting_types && setting_types[i]; i++) {
		if (nm_connection_is_type (connection, setting_types[i])) {
			found = TRUE;
			break;
		}
	}

	if (!found) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		             "Device factory %s does not support connection type %s",
		             G_OBJECT_TYPE_NAME (factory),
		             nm_connection_get_connection_type (connection));
		return NULL;
	}

	interface = NM_DEVICE_FACTORY_GET_INTERFACE (factory);
	if (!interface->create_virtual_device_for_connection) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		             "Device factory %s cannot create virtual devices",
		             G_OBJECT_TYPE_NAME (factory));
		return NULL;
	}

	return interface->create_virtual_device_for_connection (factory, connection, parent, error);
}

/*******************************************************************/

static GSList *internal_types = NULL;
static GHashTable *factories_by_link = NULL;
static GHashTable *factories_by_setting = NULL;

void
_nm_device_factory_internal_register_type (GType factory_type)
{
	g_return_if_fail (g_slist_find (internal_types, GUINT_TO_POINTER (factory_type)) == NULL);
	internal_types = g_slist_prepend (internal_types, GUINT_TO_POINTER (factory_type));
}

static void __attribute__((destructor))
_cleanup (void)
{
	g_clear_pointer (&internal_types, g_slist_free);
	g_clear_pointer (&factories_by_link, g_hash_table_unref);
	g_clear_pointer (&factories_by_setting, g_hash_table_unref);
}

static NMDeviceFactory *
find_factory (const NMLinkType *needle_link_types,
              const char **needle_setting_types)
{
	NMDeviceFactory *found;
	guint i;

	g_return_val_if_fail (factories_by_link, NULL);
	g_return_val_if_fail (factories_by_setting, NULL);

	/* NMLinkType search */
	for (i = 0; needle_link_types && needle_link_types[i] > NM_LINK_TYPE_UNKNOWN; i++) {
		found = g_hash_table_lookup (factories_by_link, GUINT_TO_POINTER (needle_link_types[i]));
		if (found)
			return found;
	}

	/* NMSetting name search */
	for (i = 0; needle_setting_types && needle_setting_types[i]; i++) {
		found = g_hash_table_lookup (factories_by_setting, needle_setting_types[i]);
		if (found)
			return found;
	}

	return NULL;
}

NMDeviceFactory *
nm_device_factory_manager_find_factory_for_link_type (NMLinkType link_type)
{
	const NMLinkType ltypes[2] = { link_type, NM_LINK_TYPE_NONE };

	g_assert (ltypes[0] > NM_LINK_TYPE_UNKNOWN);
	return find_factory (ltypes, NULL);
}

NMDeviceFactory *
nm_device_factory_manager_find_factory_for_connection (NMConnection *connection)
{
	const char *stypes[2] = { nm_connection_get_connection_type (connection), NULL };

	g_assert (stypes[0]);
	return find_factory (NULL, stypes);
}

void
nm_device_factory_manager_for_each_factory (NMDeviceFactoryManagerFactoryFunc callback,
                                            gpointer user_data)
{
	GHashTableIter iter;
	NMDeviceFactory *factory;
	GSList *list_iter, *list = NULL;

	g_return_if_fail (factories_by_link);
	g_return_if_fail (factories_by_setting);

	g_hash_table_iter_init (&iter, factories_by_link);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &factory)) {
		if (!g_slist_find (list, factory))
			list = g_slist_prepend (list, factory);
	}

	g_hash_table_iter_init (&iter, factories_by_setting);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &factory)) {
		if (!g_slist_find (list, factory))
			list = g_slist_prepend (list, factory);
	}

	for (list_iter = list; list_iter; list_iter = list_iter->next)
		callback (list_iter->data, user_data);

	g_slist_free (list);
}

#define PLUGIN_PREFIX "libnm-device-plugin-"
#define PLUGIN_PATH_TAG "NMManager-plugin-path"

struct read_device_factory_paths_data {
	char *path;
	struct stat st;
};

static gint
read_device_factory_paths_sort_fcn (gconstpointer a, gconstpointer b)
{
	const struct read_device_factory_paths_data *da = a;
	const struct read_device_factory_paths_data *db = b;
	time_t ta, tb;

	ta = MAX (da->st.st_mtime, da->st.st_ctime);
	tb = MAX (db->st.st_mtime, db->st.st_ctime);

	if (ta < tb)
		return 1;
	if (ta > tb)
		return -1;
	return 0;
}

static char**
read_device_factory_paths (void)
{
	GDir *dir;
	GError *error = NULL;
	const char *item;
	GArray *paths;
	char **result;
	guint i;

	dir = g_dir_open (NMPLUGINDIR, 0, &error);
	if (!dir) {
		nm_log_warn (LOGD_HW, "device plugin: failed to open directory %s: %s",
		             NMPLUGINDIR,
		             (error && error->message) ? error->message : "(unknown)");
		g_clear_error (&error);
		return NULL;
	}

	paths = g_array_new (FALSE, FALSE, sizeof (struct read_device_factory_paths_data));

	while ((item = g_dir_read_name (dir))) {
		int errsv;
		struct read_device_factory_paths_data data;

		if (!g_str_has_prefix (item, PLUGIN_PREFIX))
			continue;
		if (g_str_has_suffix (item, ".la"))
			continue;

		data.path = g_build_filename (NMPLUGINDIR, item, NULL);

		if (stat (data.path, &data.st) != 0) {
			errsv = errno;
			nm_log_warn (LOGD_HW, "device plugin: skip invalid file %s (error during stat: %s)", data.path, strerror (errsv));
			goto NEXT;
		}
		if (!S_ISREG (data.st.st_mode))
			goto NEXT;
		if (data.st.st_uid != 0) {
			nm_log_warn (LOGD_HW, "device plugin: skip invalid file %s (file must be owned by root)", data.path);
			goto NEXT;
		}
		if (data.st.st_mode & (S_IWGRP | S_IWOTH | S_ISUID)) {
			nm_log_warn (LOGD_HW, "device plugin: skip invalid file %s (invalid file permissions)", data.path);
			goto NEXT;
		}

		g_array_append_val (paths, data);
		continue;
NEXT:
		g_free (data.path);
	}
	g_dir_close (dir);

	/* sort filenames by modification time. */
	g_array_sort (paths, read_device_factory_paths_sort_fcn);

	result = g_new (char *, paths->len + 1);
	for (i = 0; i < paths->len; i++)
		result[i] = g_array_index (paths, struct read_device_factory_paths_data, i).path;
	result[i] = NULL;

	g_array_free (paths, TRUE);
	return result;
}

static gboolean
_add_factory (NMDeviceFactory *factory,
              gboolean check_duplicates,
              const char *path,
              NMDeviceFactoryManagerFactoryFunc callback,
              gpointer user_data)
{
	NMDeviceFactory *found = NULL;
	const NMLinkType *link_types = NULL;
	const char **setting_types = NULL;
	int i;

	g_return_val_if_fail (factories_by_link, FALSE);
	g_return_val_if_fail (factories_by_setting, FALSE);

	nm_device_factory_get_supported_types (factory, &link_types, &setting_types);
	if (check_duplicates) {
		found = find_factory (link_types, setting_types);
		if (found) {
			nm_log_warn (LOGD_HW, "Loading device plugin failed: multiple plugins "
			             "for same type (using '%s' instead of '%s')",
			             (char *) g_object_get_data (G_OBJECT (found), PLUGIN_PATH_TAG),
			             path);
			return FALSE;
		}
	}

	g_object_set_data_full (G_OBJECT (factory), PLUGIN_PATH_TAG, g_strdup (path), g_free);
	for (i = 0; link_types && link_types[i] > NM_LINK_TYPE_UNKNOWN; i++)
		g_hash_table_insert (factories_by_link, GUINT_TO_POINTER (link_types[i]), g_object_ref (factory));
	for (i = 0; setting_types && setting_types[i]; i++)
		g_hash_table_insert (factories_by_setting, (char *) setting_types[i], g_object_ref (factory));

	callback (factory, user_data);

	nm_log_info (LOGD_HW, "Loaded device plugin: %s (%s)", G_OBJECT_TYPE_NAME (factory), path);
	return TRUE;
}

void
nm_device_factory_manager_load_factories (NMDeviceFactoryManagerFactoryFunc callback,
                                          gpointer user_data)
{
	NMDeviceFactory *factory;
	const GSList *iter;
	GError *error = NULL;
	char **path, **paths;

	g_return_if_fail (factories_by_link == NULL);
	g_return_if_fail (factories_by_setting == NULL);

	factories_by_link = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_object_unref);
	factories_by_setting = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);

	/* Register internal factories first */
	for (iter = internal_types; iter; iter = iter->next) {
		GType ftype = (GType) GPOINTER_TO_SIZE (iter->data);

		factory = (NMDeviceFactory *) g_object_new (ftype, NULL);
		g_assert (factory);
		_add_factory (factory, FALSE, "internal", callback, user_data);
	}

	paths = read_device_factory_paths ();
	if (!paths)
		return;

	for (path = paths; *path; path++) {
		GModule *plugin;
		NMDeviceFactoryCreateFunc create_func;
		const char *item;

		item = strrchr (*path, '/');
		g_assert (item);

		plugin = g_module_open (*path, G_MODULE_BIND_LOCAL);

		if (!plugin) {
			nm_log_warn (LOGD_HW, "(%s): failed to load plugin: %s", item, g_module_error ());
			continue;
		}

		if (!g_module_symbol (plugin, "nm_device_factory_create", (gpointer) &create_func)) {
			nm_log_warn (LOGD_HW, "(%s): failed to find device factory creator: %s", item, g_module_error ());
			g_module_close (plugin);
			continue;
		}

		factory = create_func (&error);
		if (!factory) {
			nm_log_warn (LOGD_HW, "(%s): failed to initialize device factory: %s",
			             item, error ? error->message : "unknown");
			g_clear_error (&error);
			g_module_close (plugin);
			continue;
		}
		g_clear_error (&error);

		if (_add_factory (factory, TRUE, g_module_name (plugin), callback, user_data))
			g_module_make_resident (plugin);
		else
			g_module_close (plugin);

		g_object_unref (factory);
	}
	g_strfreev (paths);
}

