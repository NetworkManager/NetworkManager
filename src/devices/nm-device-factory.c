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

#include "nm-default.h"

#include "nm-device-factory.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <gmodule.h>

#include "platform/nm-platform.h"
#include "nm-utils.h"
#include "nm-core-internal.h"
#include "nm-setting-bluetooth.h"

#define PLUGIN_PREFIX "libnm-device-plugin-"

/*****************************************************************************/

enum {
	DEVICE_ADDED,
	COMPONENT_ADDED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_ABSTRACT_TYPE (NMDeviceFactory, nm_device_factory, G_TYPE_OBJECT)

/*****************************************************************************/

gboolean
nm_device_factory_emit_component_added (NMDeviceFactory *factory, GObject *component)
{
	gboolean consumed = FALSE;

	g_return_val_if_fail (NM_IS_DEVICE_FACTORY (factory), FALSE);

	g_signal_emit (factory, signals[COMPONENT_ADDED], 0, component, &consumed);
	return consumed;
}

static void
nm_device_factory_get_supported_types (NMDeviceFactory *factory,
                                       const NMLinkType **out_link_types,
                                       const char *const**out_setting_types)
{
	g_return_if_fail (NM_IS_DEVICE_FACTORY (factory));

	NM_DEVICE_FACTORY_GET_CLASS (factory)->get_supported_types (factory,
	                                                            out_link_types,
	                                                            out_setting_types);
}

void
nm_device_factory_start (NMDeviceFactory *factory)
{
	g_return_if_fail (factory != NULL);

	if (NM_DEVICE_FACTORY_GET_CLASS (factory)->start)
		NM_DEVICE_FACTORY_GET_CLASS (factory)->start (factory);
}

NMDevice *
nm_device_factory_create_device (NMDeviceFactory *factory,
                                 const char *iface,
                                 const NMPlatformLink *plink,
                                 NMConnection *connection,
                                 gboolean *out_ignore,
                                 GError **error)
{
	NMDeviceFactoryClass *klass;
	NMDevice *device;
	gboolean ignore = FALSE;

	g_return_val_if_fail (factory, NULL);
	g_return_val_if_fail (iface && *iface, NULL);
	if (plink) {
		g_return_val_if_fail (!connection, NULL);
		g_return_val_if_fail (strcmp (iface, plink->name) == 0, NULL);
		nm_assert (factory == nm_device_factory_manager_find_factory_for_link_type (plink->type));
	} else if (connection)
		nm_assert (factory == nm_device_factory_manager_find_factory_for_connection (connection));
	else
		g_return_val_if_reached (NULL);

	klass = NM_DEVICE_FACTORY_GET_CLASS (factory);
	if (!klass->create_device) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		             "Device factory %s cannot manage new devices",
		             G_OBJECT_TYPE_NAME (factory));
		NM_SET_OUT (out_ignore, FALSE);
		return NULL;
	}

	device = klass->create_device (factory, iface, plink, connection, &ignore);
	NM_SET_OUT (out_ignore, ignore);
	if (!device) {
		if (ignore) {
			g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
			             "Device factory %s ignores device %s",
			             G_OBJECT_TYPE_NAME (factory), iface);
		} else {
			g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
			             "Device factory %s failed to create device %s",
			             G_OBJECT_TYPE_NAME (factory), iface);
		}
	}
	return device;
}

const char *
nm_device_factory_get_connection_parent (NMDeviceFactory *factory,
                                         NMConnection *connection)
{
	g_return_val_if_fail (factory != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);

	if (!nm_connection_is_virtual (connection))
		return NULL;

	if (NM_DEVICE_FACTORY_GET_CLASS (factory)->get_connection_parent)
		return NM_DEVICE_FACTORY_GET_CLASS (factory)->get_connection_parent (factory, connection);
	return NULL;
}

char *
nm_device_factory_get_connection_iface (NMDeviceFactory *factory,
                                        NMConnection *connection,
                                        const char *parent_iface,
                                        GError **error)
{
	NMDeviceFactoryClass *klass;
	char *ifname;

	g_return_val_if_fail (factory != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	klass = NM_DEVICE_FACTORY_GET_CLASS (factory);

	ifname = g_strdup (nm_connection_get_interface_name (connection));
	if (!ifname && klass->get_connection_iface)
		ifname = klass->get_connection_iface (factory, connection, parent_iface);

	if (!ifname) {
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_FAILED,
		             "failed to determine interface name: error determine name for %s",
		             nm_connection_get_connection_type (connection));
		return NULL;
	}

	if (!nm_utils_is_valid_iface_name (ifname, error)) {
		g_prefix_error (error,
		                "failed to determine interface name: name \"%s\" is invalid",
		                ifname);
		g_free (ifname);
		return NULL;
	}

	return ifname;
}

/*****************************************************************************/

static void
nm_device_factory_init (NMDeviceFactory *self)
{
}

static void
nm_device_factory_class_init (NMDeviceFactoryClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	signals[DEVICE_ADDED] = g_signal_new (NM_DEVICE_FACTORY_DEVICE_ADDED,
	                                      G_OBJECT_CLASS_TYPE (object_class),
	                                      G_SIGNAL_RUN_FIRST,
	                                      G_STRUCT_OFFSET (NMDeviceFactoryClass, device_added),
	                                      NULL, NULL, NULL,
	                                      G_TYPE_NONE, 1, NM_TYPE_DEVICE);

	signals[COMPONENT_ADDED] = g_signal_new (NM_DEVICE_FACTORY_COMPONENT_ADDED,
	                                         G_OBJECT_CLASS_TYPE (object_class),
	                                         G_SIGNAL_RUN_LAST,
	                                         G_STRUCT_OFFSET (NMDeviceFactoryClass, component_added),
	                                         g_signal_accumulator_true_handled, NULL, NULL,
	                                         G_TYPE_BOOLEAN, 1, G_TYPE_OBJECT);
}

/*****************************************************************************/

static GHashTable *factories_by_link = NULL;
static GHashTable *factories_by_setting = NULL;

static void __attribute__((destructor))
_cleanup (void)
{
	g_clear_pointer (&factories_by_link, g_hash_table_unref);
	g_clear_pointer (&factories_by_setting, g_hash_table_unref);
}

NMDeviceFactory *
nm_device_factory_manager_find_factory_for_link_type (NMLinkType link_type)
{
	g_return_val_if_fail (factories_by_link, NULL);

	return g_hash_table_lookup (factories_by_link, GUINT_TO_POINTER (link_type));
}

NMDeviceFactory *
nm_device_factory_manager_find_factory_for_connection (NMConnection *connection)
{
	NMDeviceFactoryClass *klass;
	NMDeviceFactory *factory;
	const char *type;
	GSList *list;

	g_return_val_if_fail (factories_by_setting, NULL);

	type = nm_connection_get_connection_type (connection);
	list = g_hash_table_lookup (factories_by_setting, type);

	for (; list; list = g_slist_next (list)) {
		factory = list->data;
		klass = NM_DEVICE_FACTORY_GET_CLASS (factory);
		if (!klass->match_connection || klass->match_connection (factory, connection))
			return factory;
	}

	return NULL;
}

void
nm_device_factory_manager_for_each_factory (NMDeviceFactoryManagerFactoryFunc callback,
                                            gpointer user_data)
{
	GHashTableIter iter;
	NMDeviceFactory *factory;
	GSList *list_iter, *list = NULL;

	if (factories_by_link) {
		g_hash_table_iter_init (&iter, factories_by_link);
		while (g_hash_table_iter_next (&iter, NULL, (gpointer) &factory)) {
			if (!g_slist_find (list, factory))
				list = g_slist_prepend (list, factory);
		}
	}

	if (factories_by_setting) {
		g_hash_table_iter_init (&iter, factories_by_setting);
		while (g_hash_table_iter_next (&iter, NULL, (gpointer) &list_iter)) {
			for (; list_iter; list_iter = g_slist_next (list_iter)) {
				if (!g_slist_find (list, list_iter->data))
					list = g_slist_prepend (list, list_iter->data);
			}
		}
	}

	for (list_iter = list; list_iter; list_iter = list_iter->next)
		callback (list_iter->data, user_data);

	g_slist_free (list);
}

static gboolean
_add_factory (NMDeviceFactory *factory,
              const char *path,
              NMDeviceFactoryManagerFactoryFunc callback,
              gpointer user_data)
{
	const NMLinkType *link_types = NULL;
	const char *const*setting_types = NULL;
	GSList *list, *list2;
	int i;

	g_return_val_if_fail (factories_by_link, FALSE);
	g_return_val_if_fail (factories_by_setting, FALSE);

	nm_device_factory_get_supported_types (factory, &link_types, &setting_types);

	g_return_val_if_fail (   (link_types && link_types[0] > NM_LINK_TYPE_UNKNOWN)
	                      || (setting_types && setting_types[0]),
	                      FALSE);

	for (i = 0; link_types && link_types[i] > NM_LINK_TYPE_UNKNOWN; i++)
		g_hash_table_insert (factories_by_link, GUINT_TO_POINTER (link_types[i]), g_object_ref (factory));
	for (i = 0; setting_types && setting_types[i]; i++) {
		list = g_hash_table_lookup (factories_by_setting, (char *) setting_types[i]);
		if (list) {
			list2 = g_slist_append (list, g_object_ref (factory));
			nm_assert (list == list2);
		} else {
			list = g_slist_append (list, g_object_ref (factory));
			g_hash_table_insert (factories_by_setting, (char *) setting_types[i], list);
		}
	}

	callback (factory, user_data);

	nm_log (path ? LOGL_INFO : LOGL_DEBUG,
	        LOGD_PLATFORM,
	        NULL, NULL,
	        "Loaded device plugin: %s (%s)",
	        G_OBJECT_TYPE_NAME (factory),
	        path ?: "internal");
	return TRUE;
}

static void
_load_internal_factory (GType factory_gtype,
                        NMDeviceFactoryManagerFactoryFunc callback,
                        gpointer user_data)
{
	gs_unref_object NMDeviceFactory *factory = NULL;

	factory = (NMDeviceFactory *) g_object_new (factory_gtype, NULL);
	_add_factory (factory, NULL, callback, user_data);
}

static void
factories_list_unref (GSList *list)
{
	g_slist_free_full (list, g_object_unref);
}

static void
load_factories_from_dir (const char *dirname,
                         NMDeviceFactoryManagerFactoryFunc callback,
                         gpointer user_data)
{
	NMDeviceFactory *factory;
	GError *error = NULL;
	char **path, **paths;

	paths = nm_utils_read_plugin_paths (dirname, PLUGIN_PREFIX);
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
			nm_log_warn (LOGD_PLATFORM, "(%s): failed to load plugin: %s", item, g_module_error ());
			continue;
		}

		if (!g_module_symbol (plugin, "nm_device_factory_create", (gpointer) &create_func)) {
			nm_log_warn (LOGD_PLATFORM, "(%s): failed to find device factory creator: %s", item, g_module_error ());
			g_module_close (plugin);
			continue;
		}

		/* after loading glib types from the plugin, we cannot unload the library anymore.
		 * Make it resident. */
		g_module_make_resident (plugin);

		factory = create_func (&error);
		if (!factory) {
			nm_log_warn (LOGD_PLATFORM, "(%s): failed to initialize device factory: %s",
			             item, NM_G_ERROR_MSG (error));
			g_clear_error (&error);
			continue;
		}
		g_clear_error (&error);

		_add_factory (factory, g_module_name (plugin), callback, user_data);

		g_object_unref (factory);
	}
	g_strfreev (paths);
}

void
nm_device_factory_manager_load_factories (NMDeviceFactoryManagerFactoryFunc callback,
                                          gpointer user_data)
{
	g_return_if_fail (factories_by_link == NULL);
	g_return_if_fail (factories_by_setting == NULL);

	factories_by_link = g_hash_table_new_full (nm_direct_hash, NULL, NULL, g_object_unref);
	factories_by_setting = g_hash_table_new_full (nm_str_hash, g_str_equal, NULL, (GDestroyNotify) factories_list_unref);

#define _ADD_INTERNAL(get_type_fcn) \
	G_STMT_START { \
		GType get_type_fcn (void); \
		_load_internal_factory (get_type_fcn (), \
		                        callback, user_data); \
	} G_STMT_END

	_ADD_INTERNAL (nm_bond_device_factory_get_type);
	_ADD_INTERNAL (nm_bridge_device_factory_get_type);
	_ADD_INTERNAL (nm_dummy_device_factory_get_type);
	_ADD_INTERNAL (nm_ethernet_device_factory_get_type);
	_ADD_INTERNAL (nm_infiniband_device_factory_get_type);
	_ADD_INTERNAL (nm_ip_tunnel_device_factory_get_type);
	_ADD_INTERNAL (nm_macsec_device_factory_get_type);
	_ADD_INTERNAL (nm_macvlan_device_factory_get_type);
	_ADD_INTERNAL (nm_ppp_device_factory_get_type);
	_ADD_INTERNAL (nm_tun_device_factory_get_type);
	_ADD_INTERNAL (nm_veth_device_factory_get_type);
	_ADD_INTERNAL (nm_vlan_device_factory_get_type);
	_ADD_INTERNAL (nm_vxlan_device_factory_get_type);

	load_factories_from_dir (NMPLUGINDIR, callback, user_data);
}
