/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

/* NetworkManager system settings service
 *
 * Søren Sandmann <sandmann@daimi.au.dk>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2007 Red Hat, Inc.
 */

#include <NetworkManager.h>
#include <nm-connection.h>
#include <dbus/dbus.h>
#include <string.h>

#include <nm-setting-connection.h>

#include "nm-dbus-glib-types.h"
#include "dbus-settings.h"
#include "nm-utils.h"

#define NM_SS_PLUGIN_TAG "nm-ss-plugin"

static void exported_connection_get_secrets (NMExportedConnection *connection,
                                             const gchar *setting_name,
                                             const gchar **hints,
                                             gboolean request_new,
                                             DBusGMethodInvocation *context);

G_DEFINE_TYPE (NMSysconfigExportedConnection, nm_sysconfig_exported_connection, NM_TYPE_EXPORTED_CONNECTION);

/*
 * NMSysconfigExportedConnection
 */

static void
check_for_secrets (gpointer key, gpointer data, gpointer user_data)
{
	gboolean *have_secrets = (gboolean *) user_data;

	if (*have_secrets)
		return;

	*have_secrets = g_hash_table_size ((GHashTable *) data) ? TRUE : FALSE;
}

static void
exported_connection_get_secrets (NMExportedConnection *sys_connection,
				 const gchar *setting_name,
				 const gchar **hints,
				 gboolean request_new,
				 DBusGMethodInvocation *context)
{
	NMConnection *connection;
	GError *error = NULL;
	NMSettingConnection *s_con;
	NMSetting *setting;
	GHashTable *settings = NULL;
	NMSystemConfigInterface *plugin;
	gboolean have_secrets = FALSE;

	connection = nm_exported_connection_get_connection (sys_connection);

	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (setting_name != NULL);

	setting = nm_connection_get_setting_by_name (connection, setting_name);
	if (!setting) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Connection didn't have requested setting '%s'.",
		             __FILE__, __LINE__, setting_name);
		goto error;
	}

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection,
												   NM_TYPE_SETTING_CONNECTION));
	if (!s_con || !s_con->id || !strlen (s_con->id) || !s_con->type) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Connection didn't have required '"
		             NM_SETTING_CONNECTION_SETTING_NAME
		             "' setting , or the connection name was invalid.",
		             __FILE__, __LINE__);
		goto error;
	}

	plugin = g_object_get_data (G_OBJECT (sys_connection), NM_SS_PLUGIN_TAG);
	if (!plugin) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Connection had no plugin to ask for secrets.",
		             __FILE__, __LINE__);
		goto error;
	}

	settings = nm_system_config_interface_get_secrets (plugin, connection, setting);
	if (!settings || (g_hash_table_size (settings) == 0)) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Connection's plugin did not return a secrets hash.",
		             __FILE__, __LINE__);
		goto error;
	}

	g_hash_table_foreach (settings, check_for_secrets, &have_secrets);
	if (!have_secrets) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Secrets were found for setting '%s' but none"
		             " were valid.", __FILE__, __LINE__, setting_name);
		goto error;
	} else {
		dbus_g_method_return (context, settings);
	}

	g_hash_table_destroy (settings);
	return;

error:
	if (settings)
		g_hash_table_destroy (settings);

	g_warning (error->message);
	dbus_g_method_return_error (context, error);
	g_error_free (error);
}

static void
nm_sysconfig_exported_connection_finalize (GObject *object)
{
	G_OBJECT_CLASS (nm_sysconfig_exported_connection_parent_class)->finalize (object);
}

static void
nm_sysconfig_exported_connection_class_init (NMSysconfigExportedConnectionClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);
	NMExportedConnectionClass *connection = NM_EXPORTED_CONNECTION_CLASS (class);

	object_class->finalize = nm_sysconfig_exported_connection_finalize;

	connection->get_secrets = exported_connection_get_secrets;
}

static void
nm_sysconfig_exported_connection_init (NMSysconfigExportedConnection *sysconfig_exported_connection)
{
}

NMSysconfigExportedConnection *
nm_sysconfig_exported_connection_new (NMConnection *connection,
                                      DBusGConnection *g_conn)
{
	NMSysconfigExportedConnection *exported;

	exported = g_object_new (NM_TYPE_SYSCONFIG_EXPORTED_CONNECTION,
	                         NM_EXPORTED_CONNECTION_CONNECTION, connection,
	                         NULL);

	nm_exported_connection_register_object (NM_EXPORTED_CONNECTION (exported),
	                                        NM_CONNECTION_SCOPE_SYSTEM,
	                                        g_conn);

	return exported;
}

/*
 * NMSettings
 */

static gboolean
impl_settings_add_connection (NMSysconfigSettings *self, GHashTable *hash, GError **err);

#include "nm-settings-system-glue.h"

typedef struct {
	DBusGConnection *g_connection;
	NMSystemConfigHalManager *hal_mgr;

	GSList *plugins;
	gboolean connections_loaded;
	GSList *connections;
	GHashTable *unmanaged_devices;

	gboolean in_plugin_signal_handler;
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
	PROP_UNMANAGED_DEVICES,

	LAST_PROP
};

static GPtrArray *
list_connections (NMSettings *settings)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (settings);
	GPtrArray *connections;
	GSList *iter;

	connections = g_ptr_array_new ();
	for (iter = nm_sysconfig_settings_get_connections (self); iter; iter = g_slist_next (iter)) {
		NMExportedConnection *exported = NM_EXPORTED_CONNECTION (iter->data);
		NMConnection *connection;
		char *path;

		connection = nm_exported_connection_get_connection (exported);
		path = g_strdup (nm_connection_get_path (connection));
		if (path)
			g_ptr_array_add (connections, path);
	}
	
	/* Return a list of strings with paths to connection settings objects */
	return connections;
}

static void
settings_finalize (GObject *object)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (object);
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	if (priv->connections) {
		g_slist_foreach (priv->connections, (GFunc) g_object_unref, NULL);
		g_slist_free (priv->connections);
		priv->connections = NULL;
	}

	g_hash_table_destroy (priv->unmanaged_devices);

	g_slist_foreach (priv->plugins, (GFunc) g_object_unref, NULL);
	g_slist_free (priv->plugins);

	g_object_unref (priv->hal_mgr);
	dbus_g_connection_unref (priv->g_connection);

	G_OBJECT_CLASS (nm_sysconfig_settings_parent_class)->finalize (object);
}

static void
add_one_unmanaged_device (gpointer key, gpointer data, gpointer user_data)
{
	GPtrArray *devices = (GPtrArray *) user_data;

	g_ptr_array_add (devices, g_strdup (key));	
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

static GPtrArray *
get_unmanaged_devices (NMSysconfigSettings *self)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GPtrArray *devices;

 	devices = g_ptr_array_sized_new (3);
	g_hash_table_foreach (priv->unmanaged_devices, (GHFunc) add_one_unmanaged_device, devices);
	return devices;
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (object);

	switch (prop_id) {
	case PROP_UNMANAGED_DEVICES:
		g_value_take_boxed (value, get_unmanaged_devices (self));
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
	
	g_type_class_add_private (settings_class, sizeof (NMSysconfigSettingsPrivate));

	/* virtual methods */
	object_class->notify = notify;
	object_class->get_property = get_property;
	object_class->finalize = settings_finalize;
	settings_class->list_connections = list_connections;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_UNMANAGED_DEVICES,
		 g_param_spec_boxed (NM_SYSCONFIG_SETTINGS_UNMANAGED_DEVICES,
							 "Unamanged devices",
							 "Unmanaged devices",
							 DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
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
}

static void
nm_sysconfig_settings_init (NMSysconfigSettings *self)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	priv->unmanaged_devices = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
}

NMSysconfigSettings *
nm_sysconfig_settings_new (DBusGConnection *g_conn, NMSystemConfigHalManager *hal_mgr)
{
	NMSysconfigSettings *settings;
	NMSysconfigSettingsPrivate *priv;

	g_return_val_if_fail (g_conn != NULL, NULL);
	g_return_val_if_fail (hal_mgr != NULL, NULL);

	settings = g_object_new (NM_TYPE_SYSCONFIG_SETTINGS, NULL);
	dbus_g_connection_register_g_object (g_conn, NM_DBUS_PATH_SETTINGS, G_OBJECT (settings));

	priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (settings);
	priv->g_connection = dbus_g_connection_ref (g_conn);
	priv->hal_mgr = g_object_ref (hal_mgr);

	return settings;
}

static void
plugin_connection_added (NMSystemConfigInterface *config,
					NMConnection *connection,
					gpointer user_data)
{
	nm_sysconfig_settings_add_connection (NM_SYSCONFIG_SETTINGS (user_data), config, connection);
}

static void
plugin_connection_removed (NMSystemConfigInterface *config,
					  NMConnection *connection,
					  gpointer user_data)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (user_data);

	priv->in_plugin_signal_handler = TRUE;
	nm_sysconfig_settings_remove_connection (NM_SYSCONFIG_SETTINGS (user_data), connection);
	priv->in_plugin_signal_handler = FALSE;
}

static void
plugin_connection_updated (NMSystemConfigInterface *config,
					  NMConnection *connection,
					  gpointer user_data)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (user_data);

	priv->in_plugin_signal_handler = TRUE;
	nm_sysconfig_settings_update_connection (NM_SYSCONFIG_SETTINGS (user_data), connection);
	priv->in_plugin_signal_handler = FALSE;
}

static void
unmanaged_devices_changed (NMSystemConfigInterface *config,
					  gpointer user_data)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (user_data);
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	g_hash_table_remove_all (priv->unmanaged_devices);

	/* Ask all the plugins for their unmanaged devices */
	for (iter = priv->plugins; iter; iter = g_slist_next (iter)) {
		GSList *udis = nm_system_config_interface_get_unmanaged_devices (NM_SYSTEM_CONFIG_INTERFACE (iter->data));
		GSList *udi_iter;

		for (udi_iter = udis; udi_iter; udi_iter = udi_iter->next) {
			if (!g_hash_table_lookup (priv->unmanaged_devices, udi_iter->data)) {
				g_hash_table_insert (priv->unmanaged_devices,
								 udi_iter->data,
								 GUINT_TO_POINTER (1));
			} else
				g_free (udi_iter->data);
		}

		g_slist_free (udis);
	}

	g_object_notify (G_OBJECT (self), NM_SYSCONFIG_SETTINGS_UNMANAGED_DEVICES);
}

void
nm_sysconfig_settings_add_plugin (NMSysconfigSettings *self,
						    NMSystemConfigInterface *plugin)
{
	NMSysconfigSettingsPrivate *priv;
	char *pname = NULL;
	char *pinfo = NULL;

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (self));
	g_return_if_fail (NM_IS_SYSTEM_CONFIG_INTERFACE (plugin));

	priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	priv->plugins = g_slist_append (priv->plugins, g_object_ref (plugin));

	g_signal_connect (plugin, "connection-added", G_CALLBACK (plugin_connection_added), self);
	g_signal_connect (plugin, "connection-removed", G_CALLBACK (plugin_connection_removed), self);
	g_signal_connect (plugin, "connection-updated", G_CALLBACK (plugin_connection_updated), self);

	g_signal_connect (plugin, "unmanaged-devices-changed", G_CALLBACK (unmanaged_devices_changed), self);

	nm_system_config_interface_init (plugin, priv->hal_mgr);

	g_object_get (G_OBJECT (plugin),
	              NM_SYSTEM_CONFIG_INTERFACE_NAME, &pname,
			    NM_SYSTEM_CONFIG_INTERFACE_INFO, &pinfo,
	              NULL);

	g_message ("Loaded plugin %s: %s", pname, pinfo);
	g_free (pname);
	g_free (pinfo);
}

static void
connection_updated (NMExportedConnection *sys_connection,
				GHashTable *new_settings,
				gpointer user_data)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (user_data);
	NMSystemConfigInterface *plugin;
	NMConnection *connection;

	if (priv->in_plugin_signal_handler)
		return;

	connection = nm_exported_connection_get_connection (sys_connection);
	plugin = (NMSystemConfigInterface *) g_object_get_data (G_OBJECT (sys_connection), NM_SS_PLUGIN_TAG);

	if (plugin) {
		nm_system_config_interface_update_connection (plugin, connection);
	} else {
		GSList *iter;

		for (iter = priv->plugins; iter; iter = iter->next)
			nm_system_config_interface_update_connection (NM_SYSTEM_CONFIG_INTERFACE (iter->data), connection);
	}
}

static void
connection_removed (NMExportedConnection *sys_connection,
				gpointer user_data)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (user_data);
	NMSystemConfigInterface *plugin;
	NMConnection *connection;

	if (priv->in_plugin_signal_handler)
		return;

	connection = nm_exported_connection_get_connection (sys_connection);
	plugin = (NMSystemConfigInterface *) g_object_get_data (G_OBJECT (sys_connection), NM_SS_PLUGIN_TAG);

	if (plugin) {
		nm_system_config_interface_remove_connection (plugin, connection);
	} else {
		GSList *iter;

		for (iter = priv->plugins; iter; iter = iter->next)
			nm_system_config_interface_remove_connection (NM_SYSTEM_CONFIG_INTERFACE (iter->data), connection);
	}
}

static NMExportedConnection *
find_existing_connection (NMSysconfigSettings *self, NMConnection *connection)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->connections; iter; iter = g_slist_next (iter)) {
		NMExportedConnection *exported = NM_EXPORTED_CONNECTION (iter->data);
		NMConnection *wrapped = nm_exported_connection_get_connection (exported);

		if (wrapped == connection)
			return exported;
	}

	return NULL;
}

void
nm_sysconfig_settings_add_connection (NMSysconfigSettings *self,
							   NMSystemConfigInterface *plugin,
							   NMConnection *connection)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	NMSysconfigExportedConnection *exported;

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (self));
	g_return_if_fail (NM_IS_CONNECTION (connection));

	if (find_existing_connection (self, connection)) {
		/* A plugin is lying to us */
		g_message ("Connection is already added, ignoring");
		return;
	}

	exported = nm_sysconfig_exported_connection_new (connection, priv->g_connection);
	if (exported) {
		priv->connections = g_slist_append (priv->connections, exported);

		g_signal_connect (exported, "updated", G_CALLBACK (connection_updated), self);
		g_signal_connect (exported, "removed", G_CALLBACK (connection_removed), self);

		if (plugin)
			g_object_set_data (G_OBJECT (exported), NM_SS_PLUGIN_TAG, plugin);

		nm_settings_signal_new_connection (NM_SETTINGS (self), NM_EXPORTED_CONNECTION (exported));
	} else
		g_warning ("%s: couldn't export the connection!", __func__);
}

void
nm_sysconfig_settings_remove_connection (NMSysconfigSettings *self,
								 NMConnection *connection)
{
	NMExportedConnection *exported;

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (self));
	g_return_if_fail (NM_IS_CONNECTION (connection));

	exported = find_existing_connection (self, connection);
	if (exported) {
		NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

		priv->connections = g_slist_remove (priv->connections, exported);
		nm_exported_connection_signal_removed (exported);
		g_object_unref (exported);
	}
}

void
nm_sysconfig_settings_update_connection (NMSysconfigSettings *self,
								 NMConnection *connection)
{
	NMExportedConnection *exported;

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (self));
	g_return_if_fail (NM_IS_CONNECTION (connection));

	exported = find_existing_connection (self, connection);
	if (exported) {
		if (nm_connection_verify (connection)) {
			GHashTable *hash;

			hash = nm_connection_to_hash (connection);
			nm_exported_connection_signal_updated (exported, hash);
			g_hash_table_destroy (hash);
		} else
			/* If the connection is no longer valid, it gets removed */
			nm_sysconfig_settings_remove_connection (self, connection);
	} else
		g_warning ("%s: cannot update unknown connection", __func__);
}

GSList *
nm_sysconfig_settings_get_connections (NMSysconfigSettings *self)
{
	NMSysconfigSettingsPrivate *priv;

	g_return_val_if_fail (NM_IS_SYSCONFIG_SETTINGS (self), NULL);

	priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	if (!priv->connections_loaded) {
		GSList *iter;

		for (iter = priv->plugins; iter; iter = g_slist_next (iter)) {
			NMSystemConfigInterface *plugin = NM_SYSTEM_CONFIG_INTERFACE (iter->data);
			GSList *plugin_connections;
			GSList *elt;

			plugin_connections = nm_system_config_interface_get_connections (plugin);

			// FIXME: ensure connections from plugins loaded with a lower priority
			// get rejected when they conflict with connections from a higher
			// priority plugin.

			for (elt = plugin_connections; elt; elt = g_slist_next (elt))
				nm_sysconfig_settings_add_connection (self, plugin, NM_CONNECTION (elt->data));

			g_slist_free (plugin_connections);
		}

		/* FIXME: Bad hack */
		unmanaged_devices_changed (NULL, self);

		priv->connections_loaded = TRUE;
	}

	return priv->connections;
}

gboolean
nm_sysconfig_settings_is_device_managed (NMSysconfigSettings *self,
                                         const char *udi)
{
	NMSysconfigSettingsPrivate *priv;

	g_return_val_if_fail (NM_IS_SYSCONFIG_SETTINGS (self), FALSE);

	priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	if (g_hash_table_lookup (priv->unmanaged_devices, udi))
		return FALSE;
	return TRUE;
}

static gboolean
impl_settings_add_connection (NMSysconfigSettings *self, GHashTable *hash, GError **err)
{
	NMConnection *connection;

	connection = nm_connection_new_from_hash (hash);
	if (connection) {
		NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
		GSList *iter;

		/* Here's how it works:
		   1) plugin writes a connection.
		   2) plugin notices that a new connection is available for reading.
		   3) plugin reads the new connection (the one it wrote in 1) and emits 'connection-added' signal.
		   4) NMSysconfigSettings receives the signal and adds it to it's connection list.

		   This does not work if none of the plugins is able to write, but that is sort of by design - 
		   if the connection is not saved, it won't be available after reboot and that would be very
		   inconsistent. Perhaps we should fail this call here as well, but with multiple plugins,
		   it's not very clear which failures we can ignore and which ones we can't.
		*/

		for (iter = priv->plugins; iter; iter = iter->next)
			nm_system_config_interface_add_connection (NM_SYSTEM_CONFIG_INTERFACE (iter->data), connection);

		g_object_unref (connection);
		return TRUE;
	} else {
		/* Invalid connection hash */
		/* FIXME: Set error */
		return FALSE;
	}
}
