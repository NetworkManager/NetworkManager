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

#include <NetworkManager.h>
#include <nm-connection.h>
#include <dbus/dbus.h>
#include <nm-setting-connection.h>

#include "nm-dbus-glib-types.h"
#include "dbus-settings.h"
#include "nm-polkit-helpers.h"
#include "nm-system-config-error.h"
#include "nm-utils.h"

static gboolean
impl_settings_add_connection (NMSysconfigSettings *self, GHashTable *hash, DBusGMethodInvocation *context);

static gboolean
impl_settings_save_hostname (NMSysconfigSettings *self, const char *hostname, DBusGMethodInvocation *context);

#include "nm-settings-system-glue.h"

static void unmanaged_devices_changed (NMSystemConfigInterface *config, gpointer user_data);

typedef struct {
	DBusGConnection *g_connection;
	PolKitContext *pol_ctx;
	NMSystemConfigHalManager *hal_mgr;

	GSList *plugins;
	gboolean connections_loaded;
	GHashTable *connections;
	GHashTable *unmanaged_devices;
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
	PROP_UNMANAGED_DEVICES,
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

static GSList *
list_connections (NMSettings *settings)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (settings);
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GSList *list = NULL;

	load_connections (self);

	g_hash_table_foreach (priv->connections, hash_keys_to_slist, &list);

	return list;
}

static void
settings_finalize (GObject *object)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (object);
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	g_hash_table_destroy (priv->connections);
	g_hash_table_destroy (priv->unmanaged_devices);

	g_slist_foreach (priv->plugins, (GFunc) g_object_unref, NULL);
	g_slist_free (priv->plugins);

	if (priv->pol_ctx)
		polkit_context_unref (priv->pol_ctx);

	g_object_unref (priv->hal_mgr);
	dbus_g_connection_unref (priv->g_connection);

	g_free (priv->orig_hostname);

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

	load_connections (self);

 	devices = g_ptr_array_sized_new (3);
	g_hash_table_foreach (priv->unmanaged_devices, (GHFunc) add_one_unmanaged_device, devices);
	return devices;
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

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (object);
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GSList *iter;


	switch (prop_id) {
	case PROP_UNMANAGED_DEVICES:
		g_value_take_boxed (value, get_unmanaged_devices (self));
		break;
	case PROP_HOSTNAME:
		/* Hostname returned is the hostname returned from the first plugin
		 * that provides one.
		 */
		for (iter = priv->plugins; iter; iter = iter->next) {
			NMSystemConfigInterfaceCapabilities caps = NM_SYSTEM_CONFIG_INTERFACE_CAP_NONE;

			g_object_get (G_OBJECT (iter->data), NM_SYSTEM_CONFIG_INTERFACE_CAPABILITIES, &caps, NULL);
			if (caps & NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME) {
				char *hostname = NULL;

				g_object_get (G_OBJECT (iter->data), NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME, &hostname, NULL);
				if (hostname && strlen (hostname)) {
					g_value_take_string (value, hostname);
					break;
				}
			}
		}

		/* If no plugin provided a hostname, try the original hostname of the machine */
		if (!g_value_get_string (value) && priv->orig_hostname)
			g_value_set_string (value, priv->orig_hostname);

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

	priv->connections = g_hash_table_new_full (g_direct_hash, g_direct_equal, g_object_unref, NULL);
	priv->unmanaged_devices = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

	priv->pol_ctx = create_polkit_context ();

	/* Grab hostname on startup and use that if no plugins provide one */
	memset (hostname, 0, sizeof (hostname));
	if (gethostname (&hostname[0], HOST_NAME_MAX) == 0) {
		/* only cache it if it's a valid hostname */
		if (strlen (hostname) && strcmp (hostname, "localhost") && strcmp (hostname, "localhost.localdomain"))
			priv->orig_hostname = g_strdup (hostname);
	}
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
                         NMExportedConnection *connection,
                         gpointer user_data)
{
	nm_sysconfig_settings_add_connection (NM_SYSCONFIG_SETTINGS (user_data), connection, TRUE);
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

static void
hostname_changed (NMSystemConfigInterface *config,
                  GParamSpec *pspec,
                  gpointer user_data)
{
	g_object_notify (G_OBJECT (user_data), NM_SYSCONFIG_SETTINGS_HOSTNAME);
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
	g_signal_connect (plugin, "unmanaged-devices-changed", G_CALLBACK (unmanaged_devices_changed), self);
	g_signal_connect (plugin, "notify::hostname", G_CALLBACK (hostname_changed), self);

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
		nm_exported_connection_register_object (connection, NM_CONNECTION_SCOPE_SYSTEM, priv->g_connection);
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
nm_sysconfig_settings_is_device_managed (NMSysconfigSettings *self,
                                         const char *udi)
{
	NMSysconfigSettingsPrivate *priv;

	g_return_val_if_fail (NM_IS_SYSCONFIG_SETTINGS (self), FALSE);

	priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	load_connections (self);

	if (g_hash_table_lookup (priv->unmanaged_devices, udi))
		return FALSE;
	return TRUE;
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
	GError *err = NULL;

	/* Do any of the plugins support adding? */
	if (!nm_sysconfig_settings_get_plugin (self, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS)) {
		err = g_error_new (NM_SYSCONFIG_SETTINGS_ERROR,
					    NM_SYSCONFIG_SETTINGS_ERROR_ADD_NOT_SUPPORTED,
					    "%s", "None of the registered plugins support add.");
		goto out;
	}

	if (!check_polkit_privileges (priv->g_connection, priv->pol_ctx, context, &err))
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

	/* Do any of the plugins support setting the hostname? */
	if (!nm_sysconfig_settings_get_plugin (self, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME)) {
		err = g_error_new (NM_SYSCONFIG_SETTINGS_ERROR,
		                   NM_SYSCONFIG_SETTINGS_ERROR_SAVE_HOSTNAME_NOT_SUPPORTED,
		                   "%s", "None of the registered plugins support setting the hostname.");
		goto out;
	}

	if (!check_polkit_privileges (priv->g_connection, priv->pol_ctx, context, &err))
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

