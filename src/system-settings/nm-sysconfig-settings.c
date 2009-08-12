/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
 *
 * Søren Sandmann <sandmann@daimi.au.dk>
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
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
 * (C) Copyright 2007 - 2008 Red Hat, Inc.
 * (C) Copyright 2008 Novell, Inc.
 */

#include <unistd.h>
#include <string.h>
#include <gmodule.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#include <NetworkManager.h>
#include <nm-connection.h>
#include <dbus/dbus.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-pppoe.h>

#include "../nm-device-ethernet.h"
#include "nm-dbus-glib-types.h"
#include "nm-sysconfig-settings.h"
#include "nm-sysconfig-connection.h"
#include "nm-dbus-manager.h"
#include "nm-polkit-helpers.h"
#include "nm-system-config-error.h"
#include "nm-utils.h"
#include "nm-default-wired-connection.h"

#define CONFIG_KEY_NO_AUTO_DEFAULT "no-auto-default"

/* LINKER CRACKROCK */
#define EXPORT(sym) void * __export_##sym = &sym;

#include "nm-inotify-helper.h"
EXPORT(nm_inotify_helper_get_type)
EXPORT(nm_inotify_helper_get)
EXPORT(nm_inotify_helper_add_watch)
EXPORT(nm_inotify_helper_remove_watch)

EXPORT(nm_sysconfig_connection_get_type)
/* END LINKER CRACKROCK */


static gboolean
impl_settings_add_connection (NMSysconfigSettings *self, GHashTable *hash, DBusGMethodInvocation *context);

static gboolean
impl_settings_save_hostname (NMSysconfigSettings *self, const char *hostname, DBusGMethodInvocation *context);

#include "nm-settings-system-glue.h"

static void unmanaged_devices_changed (NMSystemConfigInterface *config, gpointer user_data);

typedef struct {
	NMDBusManager *dbus_mgr;
	PolKitContext *pol_ctx;
	char *config_file;

	GSList *plugins;
	gboolean connections_loaded;
	GHashTable *connections;
	GSList *unmanaged_specs;
	char *orig_hostname;
} NMSysconfigSettingsPrivate;

G_DEFINE_TYPE (NMSysconfigSettings, nm_sysconfig_settings, NM_TYPE_SETTINGS);

#define NM_SYSCONFIG_SETTINGS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SYSCONFIG_SETTINGS, NMSysconfigSettingsPrivate))

enum {
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_UNMANAGED_SPECS,
	PROP_HOSTNAME,
	PROP_CAN_MODIFY,

	LAST_PROP
};

static void
load_connections (NMSysconfigSettings *self)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	if (priv->connections_loaded)
		return;

	for (iter = priv->plugins; iter; iter = g_slist_next (iter)) {
		NMSystemConfigInterface *plugin = NM_SYSTEM_CONFIG_INTERFACE (iter->data);
		GSList *plugin_connections;
		GSList *elt;

		plugin_connections = nm_system_config_interface_get_connections (plugin);

		// FIXME: ensure connections from plugins loaded with a lower priority
		// get rejected when they conflict with connections from a higher
		// priority plugin.

		for (elt = plugin_connections; elt; elt = g_slist_next (elt))
			nm_sysconfig_settings_add_connection (self, NM_EXPORTED_CONNECTION (elt->data), TRUE);

		g_slist_free (plugin_connections);
	}

	priv->connections_loaded = TRUE;

	/* FIXME: Bad hack */
	unmanaged_devices_changed (NULL, self);
}

static void
hash_keys_to_slist (gpointer key, gpointer val, gpointer user_data)
{
	GSList **list = (GSList **) user_data;

	*list = g_slist_prepend (*list, key);
}

GSList *
nm_sysconfig_settings_list_connections (NMSysconfigSettings *self)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GSList *list = NULL;

	load_connections (self);

	g_hash_table_foreach (priv->connections, hash_keys_to_slist, &list);

	return list;
}

static GSList *
list_connections (NMSettings *settings)
{
	return nm_sysconfig_settings_list_connections (NM_SYSCONFIG_SETTINGS (settings));
}

typedef struct {
	const char *path;
	NMSysconfigConnection *found;
} FindConnectionInfo;

static void
find_by_path (gpointer key, gpointer data, gpointer user_data)
{
	FindConnectionInfo *info = user_data;
	NMSysconfigConnection *exported = NM_SYSCONFIG_CONNECTION (key);
	const char *path;

	if (!info->found) {
		NMConnection *connection;

		connection = nm_exported_connection_get_connection (NM_EXPORTED_CONNECTION (exported));
		g_assert (connection);
		path = nm_connection_get_path (connection);
		g_assert (path);
		if (!strcmp (path, info->path))
			info->found = exported;
	}
}

NMSysconfigConnection *
nm_sysconfig_settings_get_connection_by_path (NMSysconfigSettings *self,
                                              const char *path)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	FindConnectionInfo info;

	info.path = path;
	info.found = NULL;
	g_hash_table_foreach (priv->connections, find_by_path, &info);
	return info.found;
}

static void
clear_unmanaged_specs (NMSysconfigSettings *self)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	g_slist_foreach (priv->unmanaged_specs, (GFunc) g_free, NULL);
	g_slist_free (priv->unmanaged_specs);
	priv->unmanaged_specs = NULL;
}

static void
finalize (GObject *object)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (object);
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	g_hash_table_destroy (priv->connections);

	clear_unmanaged_specs (self);

	g_slist_foreach (priv->plugins, (GFunc) g_object_unref, NULL);
	g_slist_free (priv->plugins);

	if (priv->pol_ctx)
		polkit_context_unref (priv->pol_ctx);

	g_object_unref (priv->dbus_mgr);

	g_free (priv->orig_hostname);
	g_free (priv->config_file);

	G_OBJECT_CLASS (nm_sysconfig_settings_parent_class)->finalize (object);
}

static char*
uscore_to_wincaps (const char *uscore)
{
	const char *p;
	GString *str;
	gboolean last_was_uscore;

	last_was_uscore = TRUE;
  
	str = g_string_new (NULL);
	p = uscore;
	while (p && *p) {
		if (*p == '-' || *p == '_')
			last_was_uscore = TRUE;
		else {
			if (last_was_uscore) {
				g_string_append_c (str, g_ascii_toupper (*p));
				last_was_uscore = FALSE;
			} else
				g_string_append_c (str, *p);
		}
		++p;
	}

	return g_string_free (str, FALSE);
}

static void
notify (GObject *object, GParamSpec *pspec)
{
	GValue *value;
	GHashTable *hash;

	value = g_slice_new0 (GValue);
	hash = g_hash_table_new_full (g_str_hash, g_str_equal, (GDestroyNotify) g_free, NULL);

	g_value_init (value, pspec->value_type);
	g_object_get_property (object, pspec->name, value);
	g_hash_table_insert (hash, uscore_to_wincaps (pspec->name), value);
	g_signal_emit (object, signals[PROPERTIES_CHANGED], 0, hash);
	g_hash_table_destroy (hash);
	g_value_unset (value);
	g_slice_free (GValue, value);
}

const GSList *
nm_sysconfig_settings_get_unmanaged_specs (NMSysconfigSettings *self)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	load_connections (self);
	return priv->unmanaged_specs;
}

NMSystemConfigInterface *
nm_sysconfig_settings_get_plugin (NMSysconfigSettings *self,
                                  guint32 capability)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	g_return_val_if_fail (self != NULL, NULL);

	/* Do any of the plugins support setting the hostname? */
	for (iter = priv->plugins; iter; iter = iter->next) {
		NMSystemConfigInterfaceCapabilities caps = NM_SYSTEM_CONFIG_INTERFACE_CAP_NONE;

		g_object_get (G_OBJECT (iter->data), NM_SYSTEM_CONFIG_INTERFACE_CAPABILITIES, &caps, NULL);
		if (caps & capability)
			return NM_SYSTEM_CONFIG_INTERFACE (iter->data);
	}

	return NULL;
}

char *
nm_sysconfig_settings_get_hostname (NMSysconfigSettings *self)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GSList *iter;
	char *hostname = NULL;

	/* Hostname returned is the hostname returned from the first plugin
	 * that provides one.
	 */
	for (iter = priv->plugins; iter; iter = iter->next) {
		NMSystemConfigInterfaceCapabilities caps = NM_SYSTEM_CONFIG_INTERFACE_CAP_NONE;

		g_object_get (G_OBJECT (iter->data), NM_SYSTEM_CONFIG_INTERFACE_CAPABILITIES, &caps, NULL);
		if (caps & NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME) {
			g_object_get (G_OBJECT (iter->data), NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME, &hostname, NULL);
			if (hostname && strlen (hostname))
				return hostname;
			g_free (hostname);
		}
	}

	/* If no plugin provided a hostname, try the original hostname of the machine */
	if (priv->orig_hostname)
		hostname = g_strdup (priv->orig_hostname);

	return hostname;
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (object);
	const GSList *specs, *iter;
	GSList *copy = NULL;

	switch (prop_id) {
	case PROP_UNMANAGED_SPECS:
		specs = nm_sysconfig_settings_get_unmanaged_specs (self);
		for (iter = specs; iter; iter = g_slist_next (iter))
			copy = g_slist_append (copy, g_strdup (iter->data));
		g_value_take_boxed (value, copy);
		break;
	case PROP_HOSTNAME:
		g_value_take_string (value, nm_sysconfig_settings_get_hostname (self));

		/* Don't ever pass NULL through D-Bus */
		if (!g_value_get_string (value))
			g_value_set_static_string (value, "");
		break;
	case PROP_CAN_MODIFY:
		g_value_set_boolean (value, !!nm_sysconfig_settings_get_plugin (self, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_sysconfig_settings_class_init (NMSysconfigSettingsClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);	
	NMSettingsClass *settings_class = NM_SETTINGS_CLASS (class);
	
	g_type_class_add_private (class, sizeof (NMSysconfigSettingsPrivate));

	/* virtual methods */
	object_class->notify = notify;
	object_class->get_property = get_property;
	object_class->finalize = finalize;
	settings_class->list_connections = list_connections;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_UNMANAGED_SPECS,
		 g_param_spec_boxed (NM_SYSCONFIG_SETTINGS_UNMANAGED_SPECS,
							 "Unamanged device specs",
							 "Unmanaged device specs",
							 DBUS_TYPE_G_LIST_OF_STRING,
							 G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_HOSTNAME,
		 g_param_spec_string (NM_SYSCONFIG_SETTINGS_HOSTNAME,
							 "Hostname",
							 "Hostname",
							 NULL,
							 G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_CAN_MODIFY,
		 g_param_spec_boolean (NM_SYSCONFIG_SETTINGS_CAN_MODIFY,
							 "CanModify",
							 "Can modify",
							 FALSE,
							 G_PARAM_READABLE));

	/* signals */
	signals[PROPERTIES_CHANGED] = 
	                g_signal_new ("properties-changed",
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST,
	                              G_STRUCT_OFFSET (NMSysconfigSettingsClass, properties_changed),
	                              NULL, NULL,
	                              g_cclosure_marshal_VOID__BOXED,
	                              G_TYPE_NONE, 1, DBUS_TYPE_G_MAP_OF_VARIANT);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (settings_class),
	                                 &dbus_glib_nm_settings_system_object_info);

	dbus_g_error_domain_register (NM_SYSCONFIG_SETTINGS_ERROR,
	                              NM_DBUS_IFACE_SETTINGS_SYSTEM,
	                              NM_TYPE_SYSCONFIG_SETTINGS_ERROR);
}

static void
nm_sysconfig_settings_init (NMSysconfigSettings *self)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	char hostname[HOST_NAME_MAX + 2];
	GError *error = NULL;

	priv->connections = g_hash_table_new_full (g_direct_hash, g_direct_equal, g_object_unref, NULL);

	priv->pol_ctx = create_polkit_context (&error);
	if (!priv->pol_ctx) {
		g_warning ("%s: failed to create PolicyKit context: %s",
		           __func__,
		           (error && error->message) ? error->message : "(unknown)");
	}

	/* Grab hostname on startup and use that if no plugins provide one */
	memset (hostname, 0, sizeof (hostname));
	if (gethostname (&hostname[0], HOST_NAME_MAX) == 0) {
		/* only cache it if it's a valid hostname */
		if (strlen (hostname) && strcmp (hostname, "localhost") && strcmp (hostname, "localhost.localdomain"))
			priv->orig_hostname = g_strdup (hostname);
	}
}

static void
plugin_connection_added (NMSystemConfigInterface *config,
                         NMExportedConnection *connection,
                         gpointer user_data)
{
	nm_sysconfig_settings_add_connection (NM_SYSCONFIG_SETTINGS (user_data), connection, TRUE);
}

static gboolean
find_unmanaged_device (NMSysconfigSettings *self, const char *needle)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->unmanaged_specs; iter; iter = g_slist_next (iter)) {
		if (!strcmp ((const char *) iter->data, needle))
			return TRUE;
	}
	return FALSE;
}

static void
unmanaged_devices_changed (NMSystemConfigInterface *config,
                           gpointer user_data)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (user_data);
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	clear_unmanaged_specs (self);

	/* Ask all the plugins for their unmanaged devices */
	for (iter = priv->plugins; iter; iter = g_slist_next (iter)) {
		GSList *specs, *specs_iter;

		specs = nm_system_config_interface_get_unmanaged_specs (NM_SYSTEM_CONFIG_INTERFACE (iter->data));
		for (specs_iter = specs; specs_iter; specs_iter = specs_iter->next) {
			if (!find_unmanaged_device (self, (const char *) specs_iter->data)) {
				priv->unmanaged_specs = g_slist_prepend (priv->unmanaged_specs, specs_iter->data);
			} else
				g_free (specs_iter->data);
		}

		g_slist_free (specs);
	}

	g_object_notify (G_OBJECT (self), NM_SYSCONFIG_SETTINGS_UNMANAGED_SPECS);
}

static void
hostname_changed (NMSystemConfigInterface *config,
                  GParamSpec *pspec,
                  gpointer user_data)
{
	g_object_notify (G_OBJECT (user_data), NM_SYSCONFIG_SETTINGS_HOSTNAME);
}

static void
add_plugin (NMSysconfigSettings *self, NMSystemConfigInterface *plugin)
{
	NMSysconfigSettingsPrivate *priv;
	char *pname = NULL;
	char *pinfo = NULL;

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (self));
	g_return_if_fail (NM_IS_SYSTEM_CONFIG_INTERFACE (plugin));

	priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	priv->plugins = g_slist_append (priv->plugins, g_object_ref (plugin));

	g_signal_connect (plugin, "connection-added", G_CALLBACK (plugin_connection_added), self);
	g_signal_connect (plugin, "unmanaged-devices-changed", G_CALLBACK (unmanaged_devices_changed), self);
	g_signal_connect (plugin, "notify::hostname", G_CALLBACK (hostname_changed), self);

	nm_system_config_interface_init (plugin, NULL);

	g_object_get (G_OBJECT (plugin),
	              NM_SYSTEM_CONFIG_INTERFACE_NAME, &pname,
	              NM_SYSTEM_CONFIG_INTERFACE_INFO, &pinfo,
	              NULL);

	g_message ("Loaded plugin %s: %s", pname, pinfo);
	g_free (pname);
	g_free (pinfo);
}

static GObject *
find_plugin (GSList *list, const char *pname)
{
	GSList *iter;
	GObject *obj = NULL;

	g_return_val_if_fail (pname != NULL, FALSE);

	for (iter = list; iter && !obj; iter = g_slist_next (iter)) {
		NMSystemConfigInterface *plugin = NM_SYSTEM_CONFIG_INTERFACE (iter->data);
		char *list_pname = NULL;

		g_object_get (G_OBJECT (plugin),
		              NM_SYSTEM_CONFIG_INTERFACE_NAME,
		              &list_pname,
		              NULL);
		if (list_pname && !strcmp (pname, list_pname))
			obj = G_OBJECT (plugin);

		g_free (list_pname);
	}

	return obj;
}

static gboolean
load_plugins (NMSysconfigSettings *self, const char *plugins, GError **error)
{
	GSList *list = NULL;
	char **plist;
	char **iter;
	gboolean success = TRUE;

	plist = g_strsplit (plugins, ",", 0);
	if (!plist)
		return FALSE;

	for (iter = plist; *iter; iter++) {
		GModule *plugin;
		char *full_name, *path;
		const char *pname = *iter;
		GObject *obj;
		GObject * (*factory_func) (void);

		/* ifcfg-fedora was renamed ifcfg-rh; handle old configs here */
		if (!strcmp (pname, "ifcfg-fedora"))
			pname = "ifcfg-rh";

		obj = find_plugin (list, pname);
		if (obj)
			continue;

		full_name = g_strdup_printf ("nm-settings-plugin-%s", pname);
		path = g_module_build_path (PLUGINDIR, full_name);

		plugin = g_module_open (path, G_MODULE_BIND_LOCAL);
		if (!plugin) {
			g_set_error (error, 0, 0,
			             "Could not load plugin '%s': %s",
			             pname, g_module_error ());
			g_free (full_name);
			g_free (path);
			success = FALSE;
			break;
		}

		g_free (full_name);
		g_free (path);

		if (!g_module_symbol (plugin, "nm_system_config_factory", (gpointer) (&factory_func))) {
			g_set_error (error, 0, 0,
			             "Could not find plugin '%s' factory function.",
			             pname);
			success = FALSE;
			break;
		}

		obj = (*factory_func) ();
		if (!obj || !NM_IS_SYSTEM_CONFIG_INTERFACE (obj)) {
			g_set_error (error, 0, 0,
			             "Plugin '%s' returned invalid system config object.",
			             pname);
			success = FALSE;
			break;
		}

		g_module_make_resident (plugin);
		g_object_weak_ref (obj, (GWeakNotify) g_module_close, plugin);
		add_plugin (self, NM_SYSTEM_CONFIG_INTERFACE (obj));
		list = g_slist_append (list, obj);
	}

	g_strfreev (plist);

	g_slist_foreach (list, (GFunc) g_object_unref, NULL);
	g_slist_free (list);

	return success;
}

static void
connection_removed (NMExportedConnection *connection,
				gpointer user_data)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (user_data);

	g_hash_table_remove (priv->connections, connection);
}

void
nm_sysconfig_settings_add_connection (NMSysconfigSettings *self,
                                      NMExportedConnection *connection,
                                      gboolean do_export)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (self));
	g_return_if_fail (NM_IS_EXPORTED_CONNECTION (connection));

	if (g_hash_table_lookup (priv->connections, connection))
		/* A plugin is lying to us. */
		return;

	g_hash_table_insert (priv->connections, g_object_ref (connection), GINT_TO_POINTER (1));
	g_signal_connect (connection, "removed", G_CALLBACK (connection_removed), self);

	if (do_export) {
		DBusGConnection *g_connection;

		g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
		nm_exported_connection_register_object (connection, NM_CONNECTION_SCOPE_SYSTEM, g_connection);
		nm_settings_signal_new_connection (NM_SETTINGS (self), connection);
	}
}

void
nm_sysconfig_settings_remove_connection (NMSysconfigSettings *self,
                                         NMExportedConnection *connection,
                                         gboolean do_signal)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (self));
	g_return_if_fail (NM_IS_EXPORTED_CONNECTION (connection));

	if (g_hash_table_lookup (priv->connections, connection)) {
		nm_exported_connection_signal_removed (connection);
		g_hash_table_remove (priv->connections, connection);
	}
}

gboolean
nm_sysconfig_settings_add_new_connection (NMSysconfigSettings *self,
                                          GHashTable *hash,
                                          GError **error)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	NMConnection *connection;
	GError *tmp_error = NULL, *last_error = NULL;
	GSList *iter;
	gboolean success = FALSE;

	connection = nm_connection_new_from_hash (hash, &tmp_error);
	if (!connection) {
		/* Invalid connection hash */
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Invalid connection: '%s' / '%s' invalid: %d",
		             tmp_error ? g_type_name (nm_connection_lookup_setting_type_by_quark (tmp_error->domain)) : "(unknown)",
		             tmp_error ? tmp_error->message : "(unknown)", tmp_error ? tmp_error->code : -1);
		g_clear_error (&tmp_error);
		return FALSE;
	}

	/* Here's how it works:
	   1) plugin writes a connection.
	   2) plugin notices that a new connection is available for reading.
	   3) plugin reads the new connection (the one it wrote in 1) and emits 'connection-added' signal.
	   4) NMSysconfigSettings receives the signal and adds it to it's connection list.
	*/

	for (iter = priv->plugins; iter && !success; iter = iter->next) {
		success = nm_system_config_interface_add_connection (NM_SYSTEM_CONFIG_INTERFACE (iter->data),
		                                                     connection, &tmp_error);
		g_clear_error (&last_error);
		if (!success)
			last_error = tmp_error;
	}

	g_object_unref (connection);

	if (!success) {
		g_set_error (error, NM_SYSCONFIG_SETTINGS_ERROR,
		             NM_SYSCONFIG_SETTINGS_ERROR_ADD_FAILED,
		             "Saving connection failed: (%d) %s",
		             last_error ? last_error->code : -1,
		             last_error && last_error->message ? last_error->message : "(unknown)");
		g_clear_error (&last_error);
	}

	return success;
}

static gboolean
impl_settings_add_connection (NMSysconfigSettings *self,
                              GHashTable *hash,
                              DBusGMethodInvocation *context)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	DBusGConnection *g_connection;
	GError *err = NULL;

	/* Do any of the plugins support adding? */
	if (!nm_sysconfig_settings_get_plugin (self, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS)) {
		err = g_error_new (NM_SYSCONFIG_SETTINGS_ERROR,
					    NM_SYSCONFIG_SETTINGS_ERROR_ADD_NOT_SUPPORTED,
					    "%s", "None of the registered plugins support add.");
		goto out;
	}

	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	if (!check_polkit_privileges (g_connection, priv->pol_ctx, context, &err))
		goto out;

	nm_sysconfig_settings_add_new_connection (self, hash, &err);

 out:
	if (err) {
		dbus_g_method_return_error (context, err);
		g_error_free (err);
		return FALSE;
	} else {
		dbus_g_method_return (context);
		return TRUE;
	}
}

static gboolean
impl_settings_save_hostname (NMSysconfigSettings *self,
                             const char *hostname,
                             DBusGMethodInvocation *context)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GError *err = NULL;
	GSList *iter;
	gboolean success = FALSE;
	DBusGConnection *g_connection;

	/* Do any of the plugins support setting the hostname? */
	if (!nm_sysconfig_settings_get_plugin (self, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME)) {
		err = g_error_new (NM_SYSCONFIG_SETTINGS_ERROR,
		                   NM_SYSCONFIG_SETTINGS_ERROR_SAVE_HOSTNAME_NOT_SUPPORTED,
		                   "%s", "None of the registered plugins support setting the hostname.");
		goto out;
	}

	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	if (!check_polkit_privileges (g_connection, priv->pol_ctx, context, &err))
		goto out;

	/* Set the hostname in all plugins */
	for (iter = priv->plugins; iter; iter = iter->next) {
		NMSystemConfigInterfaceCapabilities caps = NM_SYSTEM_CONFIG_INTERFACE_CAP_NONE;

		g_object_get (G_OBJECT (iter->data), NM_SYSTEM_CONFIG_INTERFACE_CAPABILITIES, &caps, NULL);
		if (caps & NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME) {
			g_object_set (G_OBJECT (iter->data), NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME, hostname, NULL);
			success = TRUE;
		}
	}

	if (!success) {
		err = g_error_new (NM_SYSCONFIG_SETTINGS_ERROR,
		                   NM_SYSCONFIG_SETTINGS_ERROR_SAVE_HOSTNAME_FAILED,
		                   "%s", "Saving the hostname failed.");
	}

 out:
	if (err) {
		dbus_g_method_return_error (context, err);
		g_error_free (err);
		return FALSE;
	} else {
		dbus_g_method_return (context);
		return TRUE;
	}
}

static gboolean
have_connection_for_device (NMSysconfigSettings *self, GByteArray *mac)
{
	GSList *list, *iter;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	const GByteArray *setting_mac;
	gboolean ret = FALSE;

	g_return_val_if_fail (NM_IS_SYSCONFIG_SETTINGS (self), FALSE);
	g_return_val_if_fail (mac != NULL, FALSE);

	/* Find a wired connection locked to the given MAC address, if any */
	list = nm_settings_list_connections (NM_SETTINGS (self));
	for (iter = list; iter; iter = g_slist_next (iter)) {
		NMExportedConnection *exported = NM_EXPORTED_CONNECTION (iter->data);
		NMConnection *connection;
		const char *connection_type;

		connection = nm_exported_connection_get_connection (exported);
		if (!connection)
			continue;

		s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
		connection_type = nm_setting_connection_get_connection_type (s_con);

		if (   strcmp (connection_type, NM_SETTING_WIRED_SETTING_NAME)
		    && strcmp (connection_type, NM_SETTING_PPPOE_SETTING_NAME))
			continue;

		s_wired = (NMSettingWired *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED);

		/* No wired setting; therefore the PPPoE connection applies to any device */
		if (!s_wired && !strcmp (connection_type, NM_SETTING_PPPOE_SETTING_NAME)) {
			ret = TRUE;
			break;
		}

		setting_mac = nm_setting_wired_get_mac_address (s_wired);
		if (setting_mac) {
			/* A connection mac-locked to this device */
			if (!memcmp (setting_mac->data, mac->data, ETH_ALEN)) {
				ret = TRUE;
				break;
			}
		} else {
			/* A connection that applies to any wired device */
			ret = TRUE;
			break;
		}
	}

	g_slist_free (list);
	return ret;
}

/* Search through the list of blacklisted MAC addresses in the config file. */
static gboolean
is_mac_auto_wired_blacklisted (NMSysconfigSettings *self, const GByteArray *mac)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GKeyFile *config;
	char **list, **iter;
	gboolean found = FALSE;

	g_return_val_if_fail (mac != NULL, FALSE);

	if (!priv->config_file)
		return FALSE;

	config = g_key_file_new ();
	if (!config) {
		g_warning ("%s: not enough memory to load config file.", __func__);
		return FALSE;
	}

	g_key_file_set_list_separator (config, ',');
	if (!g_key_file_load_from_file (config, priv->config_file, G_KEY_FILE_NONE, NULL))
		goto out;

	list = g_key_file_get_string_list (config, "main", CONFIG_KEY_NO_AUTO_DEFAULT, NULL, NULL);
	for (iter = list; iter && *iter; iter++) {
		struct ether_addr *candidate;

		candidate = ether_aton (*iter);
		if (candidate && !memcmp (mac->data, candidate->ether_addr_octet, ETH_ALEN)) {
			found = TRUE;
			break;
		}
	}

	if (list)
		g_strfreev (list);

out:
	g_key_file_free (config);
	return found;
}

#define DEFAULT_WIRED_TAG "default-wired"

static void
default_wired_deleted (NMDefaultWiredConnection *wired,
                       const GByteArray *mac,
                       NMSysconfigSettings *self)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	NMConnection *wrapped;
	NMSettingConnection *s_con;
	char *tmp;
	GKeyFile *config;
	char **list, **iter, **updated;
	gboolean found = FALSE;
	gsize len = 0;
	char *data;

	/* If there was no config file specified, there's nothing to do */
	if (!priv->config_file)
		goto cleanup;

	/* When the default wired connection is removed (either deleted or saved
	 * to a new persistent connection by a plugin), write the MAC address of
	 * the wired device to the config file and don't create a new default wired
	 * connection for that device again.
	 */

	wrapped = nm_exported_connection_get_connection (NM_EXPORTED_CONNECTION (wired));
	g_assert (wrapped);
	s_con = (NMSettingConnection *) nm_connection_get_setting (wrapped, NM_TYPE_SETTING_CONNECTION);
	g_assert (s_con);

	/* Ignore removals of read-only connections, since they couldn't have
	 * been removed by the user.
	 */
	if (nm_setting_connection_get_read_only (s_con))
		goto cleanup;

	config = g_key_file_new ();
	if (!config)
		goto cleanup;

	g_key_file_set_list_separator (config, ',');
	g_key_file_load_from_file (config, priv->config_file, G_KEY_FILE_KEEP_COMMENTS, NULL);

	list = g_key_file_get_string_list (config, "main", CONFIG_KEY_NO_AUTO_DEFAULT, &len, NULL);
	/* Traverse entire list to get count of # items */
	for (iter = list; iter && *iter; iter++) {
		struct ether_addr *candidate;

		candidate = ether_aton (*iter);
		if (candidate && !memcmp (mac->data, candidate->ether_addr_octet, ETH_ALEN))
			found = TRUE;
	}

	/* Add this device's MAC to the list */
	if (!found) {
		tmp = g_strdup_printf ("%02x:%02x:%02x:%02x:%02x:%02x",
		                       mac->data[0], mac->data[1], mac->data[2],
		                       mac->data[3], mac->data[4], mac->data[5]);

		updated = g_malloc0 (sizeof (char*) * (len + 2));
		if (list && len)
			memcpy (updated, list, len);
		updated[len] = tmp;

		g_key_file_set_string_list (config,
		                            "main", CONFIG_KEY_NO_AUTO_DEFAULT,
		                            (const char **) updated,
		                            len + 1);
		/* g_free() not g_strfreev() since 'updated' isn't a deep-copy */
		g_free (updated);
		g_free (tmp);

		data = g_key_file_to_data (config, &len, NULL);
		if (data) {
			g_file_set_contents (priv->config_file, data, len, NULL);
			g_free (data);
		}
	}

	if (list)
		g_strfreev (list);
	g_key_file_free (config);

cleanup:
	g_object_set_data (G_OBJECT (nm_default_wired_connection_get_device (wired)),
	                   DEFAULT_WIRED_TAG,
	                   NULL);
}

static void
default_wired_try_update (NMDefaultWiredConnection *wired,
                          GHashTable *new_settings,
                          NMSysconfigSettings *self)
{
	GError *error = NULL;
	NMConnection *wrapped;
	NMSettingConnection *s_con;
	const char *id;

	/* Try to move this default wired conneciton to a plugin so that it has
	 * persistent storage.
	 */

	wrapped = nm_exported_connection_get_connection (NM_EXPORTED_CONNECTION (wired));
	g_assert (wrapped);
	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (wrapped, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);
	id = nm_setting_connection_get_id (s_con);
	g_assert (id);

	nm_sysconfig_settings_remove_connection (self, NM_EXPORTED_CONNECTION (wired), FALSE);
	if (nm_sysconfig_settings_add_new_connection (self, new_settings, &error)) {
		g_object_set_data (G_OBJECT (nm_default_wired_connection_get_device (wired)),
		                   DEFAULT_WIRED_TAG,
		                   NULL);
		g_message ("Saved default wired connection '%s' to persistent storage", id);
		return;
	}

	g_warning ("%s: couldn't save default wired connection '%s': %d / %s",
	           __func__, id, error ? error->code : -1,
	           (error && error->message) ? error->message : "(unknown)");
	g_clear_error (&error);

	/* If there was an error, don't destroy the default wired connection,
	 * but add it back to the system settings service. Connection is already
	 * exported on the bus, don't export it again, thus do_export == FALSE.
	 */
	nm_sysconfig_settings_add_connection (self, NM_EXPORTED_CONNECTION (wired), FALSE);
}

void
nm_sysconfig_settings_device_added (NMSysconfigSettings *self, NMDevice *device)
{
	GByteArray *mac = NULL;
	struct ether_addr tmp;
	NMDefaultWiredConnection *connection;
	NMSettingConnection *s_con;
	NMConnection *wrapped;
	gboolean read_only = TRUE;
	const char *id;

	if (nm_device_get_device_type (device) != NM_DEVICE_TYPE_ETHERNET)
		return;

	/* If the device isn't managed or it already has a default wired connection,
	 * ignore it.
	 */
	if (   !nm_device_get_managed (device)
	    || g_object_get_data (G_OBJECT (device), DEFAULT_WIRED_TAG))
		return;

	nm_device_ethernet_get_address (NM_DEVICE_ETHERNET (device), &tmp);

	mac = g_byte_array_sized_new (ETH_ALEN);
	g_byte_array_append (mac, tmp.ether_addr_octet, ETH_ALEN);

	if (   have_connection_for_device (self, mac)
	    || is_mac_auto_wired_blacklisted (self, mac))
		goto ignore;

	if (nm_sysconfig_settings_get_plugin (self, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS))
		read_only = FALSE;

	connection = nm_default_wired_connection_new (mac, device, read_only);
	if (!connection)
		goto ignore;

	wrapped = nm_exported_connection_get_connection (NM_EXPORTED_CONNECTION (connection));
	g_assert (wrapped);
	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (wrapped, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);
	id = nm_setting_connection_get_id (s_con);
	g_assert (id);

	g_message ("Added default wired connection '%s' for %s", id, nm_device_get_udi (device));

	g_signal_connect (connection, "try-update", (GCallback) default_wired_try_update, self);
	g_signal_connect (connection, "deleted", (GCallback) default_wired_deleted, self);
	nm_sysconfig_settings_add_connection (self, NM_EXPORTED_CONNECTION (connection), TRUE);
	g_object_unref (connection);

	g_object_set_data (G_OBJECT (device), DEFAULT_WIRED_TAG, connection);

ignore:
	g_byte_array_free (mac, TRUE);
}

void
nm_sysconfig_settings_device_removed (NMSysconfigSettings *self, NMDevice *device)
{
	NMExportedConnection *exported;

	if (nm_device_get_device_type (device) != NM_DEVICE_TYPE_ETHERNET)
		return;

	exported = (NMExportedConnection *) g_object_get_data (G_OBJECT (device), DEFAULT_WIRED_TAG);
	if (exported)
		nm_sysconfig_settings_remove_connection (self, exported, TRUE);
}

NMSysconfigSettings *
nm_sysconfig_settings_new (const char *config_file,
                           const char *plugins,
                           GError **error)
{
	NMSysconfigSettings *self;
	NMSysconfigSettingsPrivate *priv;
	DBusGConnection *g_connection;

	self = g_object_new (NM_TYPE_SYSCONFIG_SETTINGS, NULL);
	if (!self)
		return NULL;

	priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	priv->config_file = g_strdup (config_file);

	priv->dbus_mgr = nm_dbus_manager_get ();
	g_assert (priv->dbus_mgr);

	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	dbus_g_connection_register_g_object (g_connection, NM_DBUS_PATH_SETTINGS, G_OBJECT (self));

	if (plugins) {
		/* Load the plugins; fail if a plugin is not found. */
		if (!load_plugins (self, plugins, error)) {
			g_object_unref (self);
			return NULL;
		}
	}

	return self;
}

