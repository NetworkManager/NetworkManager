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
 * (C) Copyright 2007 - 2010 Red Hat, Inc.
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
#include <dbus/dbus-glib-lowlevel.h>
#include <nm-settings-system-interface.h>

#include <nm-setting-8021x.h>
#include <nm-setting-bluetooth.h>
#include <nm-setting-cdma.h>
#include <nm-setting-connection.h>
#include <nm-setting-gsm.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-olpc-mesh.h>
#include <nm-setting-ppp.h>
#include <nm-setting-pppoe.h>
#include <nm-setting-serial.h>
#include <nm-setting-vpn.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-wireless-security.h>

#include "../nm-device-ethernet.h"
#include "nm-dbus-glib-types.h"
#include "nm-sysconfig-settings.h"
#include "nm-sysconfig-connection.h"
#include "nm-polkit-helpers.h"
#include "nm-system-config-error.h"
#include "nm-default-wired-connection.h"
#include "nm-logging.h"

#define CONFIG_KEY_NO_AUTO_DEFAULT "no-auto-default"

/* LINKER CRACKROCK */
#define EXPORT(sym) void * __export_##sym = &sym;

#include "nm-inotify-helper.h"
EXPORT(nm_inotify_helper_get_type)
EXPORT(nm_inotify_helper_get)
EXPORT(nm_inotify_helper_add_watch)
EXPORT(nm_inotify_helper_remove_watch)

EXPORT(nm_sysconfig_connection_get_type)
EXPORT(nm_sysconfig_connection_update)
/* END LINKER CRACKROCK */

static void claim_connection (NMSysconfigSettings *self,
                              NMSettingsConnectionInterface *connection,
                              gboolean do_export);

static void impl_settings_save_hostname (NMSysconfigSettings *self,
                                         const char *hostname,
                                         DBusGMethodInvocation *context);

static void impl_settings_get_permissions (NMSysconfigSettings *self,
                                           DBusGMethodInvocation *context);

#include "nm-settings-system-glue.h"

static void unmanaged_specs_changed (NMSystemConfigInterface *config, gpointer user_data);

typedef struct {
	PolkitAuthority *authority;
	guint auth_changed_id;
	char *config_file;

	GSList *pk_calls;
	GSList *permissions_calls;

	GSList *plugins;
	gboolean connections_loaded;
	GHashTable *connections;
	GSList *unmanaged_specs;
} NMSysconfigSettingsPrivate;

static void settings_system_interface_init (NMSettingsSystemInterface *klass);

G_DEFINE_TYPE_WITH_CODE (NMSysconfigSettings, nm_sysconfig_settings, NM_TYPE_SETTINGS_SERVICE,
                         G_IMPLEMENT_INTERFACE (NM_TYPE_SETTINGS_SYSTEM_INTERFACE,
                                                settings_system_interface_init))

#define NM_SYSCONFIG_SETTINGS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SYSCONFIG_SETTINGS, NMSysconfigSettingsPrivate))

enum {
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_UNMANAGED_SPECS,

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
			claim_connection (self, NM_SETTINGS_CONNECTION_INTERFACE (elt->data), TRUE);

		g_slist_free (plugin_connections);
	}

	priv->connections_loaded = TRUE;

	/* FIXME: Bad hack */
	unmanaged_specs_changed (NULL, self);
}

static GSList *
list_connections (NMSettingsService *settings)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (settings);
	GHashTableIter iter;
	gpointer key;
	GSList *list = NULL;

	load_connections (NM_SYSCONFIG_SETTINGS (settings));

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, &key, NULL))
		list = g_slist_prepend (list, NM_EXPORTED_CONNECTION (key));
	return g_slist_reverse (list);
}

static void
clear_unmanaged_specs (NMSysconfigSettings *self)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	g_slist_foreach (priv->unmanaged_specs, (GFunc) g_free, NULL);
	g_slist_free (priv->unmanaged_specs);
	priv->unmanaged_specs = NULL;
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

static NMSystemConfigInterface *
get_plugin (NMSysconfigSettings *self, guint32 capability)
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

	return hostname;
}

static void
plugin_connection_added (NMSystemConfigInterface *config,
                         NMSettingsConnectionInterface *connection,
                         gpointer user_data)
{
	claim_connection (NM_SYSCONFIG_SETTINGS (user_data), connection, TRUE);
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
unmanaged_specs_changed (NMSystemConfigInterface *config,
                         gpointer user_data)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (user_data);
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	clear_unmanaged_specs (self);

	/* Ask all the plugins for their unmanaged specs */
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
	g_object_notify (G_OBJECT (user_data), NM_SETTINGS_SYSTEM_INTERFACE_HOSTNAME);
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

	g_signal_connect (plugin, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED,
	                  G_CALLBACK (plugin_connection_added), self);
	g_signal_connect (plugin, "notify::hostname", G_CALLBACK (hostname_changed), self);

	nm_system_config_interface_init (plugin, NULL);

	g_object_get (G_OBJECT (plugin),
	              NM_SYSTEM_CONFIG_INTERFACE_NAME, &pname,
	              NM_SYSTEM_CONFIG_INTERFACE_INFO, &pinfo,
	              NULL);

	g_signal_connect (plugin, NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED,
	                  G_CALLBACK (unmanaged_specs_changed), self);

	nm_log_info (LOGD_SYS_SET, "Loaded plugin %s: %s", pname, pinfo);
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
connection_removed (NMSettingsConnectionInterface *connection,
                    gpointer user_data)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (user_data);

	g_hash_table_remove (priv->connections, connection);
}

static void
claim_connection (NMSysconfigSettings *self,
                  NMSettingsConnectionInterface *connection,
                  gboolean do_export)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (self));
	g_return_if_fail (NM_IS_SETTINGS_CONNECTION_INTERFACE (connection));

	if (g_hash_table_lookup (priv->connections, connection))
		/* A plugin is lying to us. */
		return;

	g_hash_table_insert (priv->connections, g_object_ref (connection), GINT_TO_POINTER (1));
	g_signal_connect (connection,
	                  NM_SETTINGS_CONNECTION_INTERFACE_REMOVED,
	                  G_CALLBACK (connection_removed),
	                  self);

	if (do_export) {
		nm_settings_service_export_connection (NM_SETTINGS_SERVICE (self), connection);
		g_signal_emit_by_name (self, NM_SETTINGS_INTERFACE_NEW_CONNECTION, connection);
	}
}

static void
remove_connection (NMSysconfigSettings *self,
                   NMSettingsConnectionInterface *connection,
                   gboolean do_signal)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (self));
	g_return_if_fail (NM_IS_SETTINGS_CONNECTION_INTERFACE (connection));

	if (g_hash_table_lookup (priv->connections, connection)) {
		g_signal_emit_by_name (G_OBJECT (connection), NM_SETTINGS_CONNECTION_INTERFACE_REMOVED);
		g_hash_table_remove (priv->connections, connection);
	}
}

typedef struct {
	NMSysconfigSettings *self;
	DBusGMethodInvocation *context;
	PolkitSubject *subject;
	GCancellable *cancellable;
	gboolean disposed;

	NMConnection *connection;
	NMSettingsAddConnectionFunc callback;
	gpointer callback_data;

	char *hostname;

	NMSettingsSystemPermissions permissions;
	guint32 permissions_calls;
} PolkitCall;

#include "nm-dbus-manager.h"

static PolkitCall *
polkit_call_new (NMSysconfigSettings *self,
                 DBusGMethodInvocation *context,
                 NMConnection *connection,
                 NMSettingsAddConnectionFunc callback,
                 gpointer callback_data,
                 const char *hostname)
{
	PolkitCall *call;
	char *sender;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (context != NULL, NULL);

	call = g_malloc0 (sizeof (PolkitCall));
	call->self = self;
	call->cancellable = g_cancellable_new ();
	call->context = context;
	if (connection)
		call->connection = g_object_ref (connection);
	if (callback) {
		call->callback = callback;
		call->callback_data = callback_data;
	}
	if (hostname)
		call->hostname = g_strdup (hostname);

 	sender = dbus_g_method_get_sender (context);
	call->subject = polkit_system_bus_name_new (sender);
	g_free (sender);

	return call;
}

static void
polkit_call_free (PolkitCall *call)
{
	if (call->connection)
		g_object_unref (call->connection);
	g_object_unref (call->cancellable);
	g_free (call->hostname);
	g_object_unref (call->subject);
	g_free (call);
}

static gboolean
add_new_connection (NMSysconfigSettings *self,
                    NMConnection *connection,
                    GError **error)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GError *tmp_error = NULL, *last_error = NULL;
	GSList *iter;
	gboolean success = FALSE;

	/* Here's how it works:
	   1) plugin writes a connection.
	   2) plugin notices that a new connection is available for reading.
	   3) plugin reads the new connection (the one it wrote in 1) and emits 'connection-added' signal.
	   4) NMSysconfigSettings receives the signal and adds it to it's connection list.
	*/

	for (iter = priv->plugins; iter && !success; iter = iter->next) {
		success = nm_system_config_interface_add_connection (NM_SYSTEM_CONFIG_INTERFACE (iter->data),
		                                                     connection,
		                                                     &tmp_error);
		g_clear_error (&last_error);
		if (!success) {
			last_error = tmp_error;
			tmp_error = NULL;
		}
	}

	if (!success)
		*error = last_error;
	return success;
}

static void
pk_add_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	PolkitCall *call = user_data;
	NMSysconfigSettings *self = call->self;
	NMSysconfigSettingsPrivate *priv;
	PolkitAuthorizationResult *pk_result;
	GError *error = NULL, *add_error = NULL;

	/* If NMSysconfigSettings is already gone, do nothing */
	if (call->disposed) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_GENERAL,
		                             "Request was canceled.");
		dbus_g_method_return_error (call->context, error);
		g_error_free (error);
		polkit_call_free (call);
		return;
	}

	priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	priv->pk_calls = g_slist_remove (priv->pk_calls, call);

	pk_result = polkit_authority_check_authorization_finish (priv->authority,
	                                                         result,
	                                                         &error);
	/* Some random error happened */
	if (error) {
		call->callback (NM_SETTINGS_INTERFACE (self), error, call->callback_data);
		goto out;
	}

	/* Caller didn't successfully authenticate */
	if (!polkit_authorization_result_get_is_authorized (pk_result)) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_NOT_PRIVILEGED,
		                             "Insufficient privileges.");
		call->callback (NM_SETTINGS_INTERFACE (self), error, call->callback_data);
		goto out;
	}

	if (add_new_connection (self, call->connection, &add_error))
		call->callback (NM_SETTINGS_INTERFACE (self), NULL, call->callback_data);
	else {
		error = g_error_new (NM_SYSCONFIG_SETTINGS_ERROR,
		                     NM_SYSCONFIG_SETTINGS_ERROR_ADD_FAILED,
		                     "Saving connection failed: (%d) %s",
		                     add_error ? add_error->code : -1,
		                     (add_error && add_error->message) ? add_error->message : "(unknown)");
		g_error_free (add_error);
		call->callback (NM_SETTINGS_INTERFACE (self), error, call->callback_data);
	}

out:
	g_clear_error (&error);
	polkit_call_free (call);
	if (pk_result)
		g_object_unref (pk_result);
}

static void
add_connection (NMSettingsService *service,
	            NMConnection *connection,
	            DBusGMethodInvocation *context, /* Only present for D-Bus calls */
	            NMSettingsAddConnectionFunc callback,
	            gpointer user_data)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (service);
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	PolkitCall *call;
	GError *error = NULL;

	/* Do any of the plugins support adding? */
	if (!get_plugin (self, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS)) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_ADD_NOT_SUPPORTED,
		                             "None of the registered plugins support add.");
		callback (NM_SETTINGS_INTERFACE (service), error, user_data);
		g_error_free (error);
		return;
	}

	call = polkit_call_new (self, context, connection, callback, user_data, NULL);
	g_assert (call);
	polkit_authority_check_authorization (priv->authority,
	                                      call->subject,
	                                      NM_SYSCONFIG_POLICY_ACTION_CONNECTION_MODIFY,
	                                      NULL,
	                                      POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
	                                      call->cancellable,
	                                      pk_add_cb,
	                                      call);
	priv->pk_calls = g_slist_append (priv->pk_calls, call);
}

static void
pk_hostname_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	PolkitCall *call = user_data;
	NMSysconfigSettings *self = call->self;
	NMSysconfigSettingsPrivate *priv;
	PolkitAuthorizationResult *pk_result;
	GError *error = NULL;
	GSList *iter;
	gboolean success = FALSE;

	/* If our NMSysconfigConnection is already gone, do nothing */
	if (call->disposed) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_GENERAL,
		                             "Request was canceled.");
		dbus_g_method_return_error (call->context, error);
		g_error_free (error);
		polkit_call_free (call);
		return;
	}

	priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	priv->pk_calls = g_slist_remove (priv->pk_calls, call);

	pk_result = polkit_authority_check_authorization_finish (priv->authority,
	                                                         result,
	                                                         &error);
	/* Some random error happened */
	if (error) {
		dbus_g_method_return_error (call->context, error);
		goto out;
	}

	/* Caller didn't successfully authenticate */
	if (!polkit_authorization_result_get_is_authorized (pk_result)) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_NOT_PRIVILEGED,
		                             "Insufficient privileges.");
		dbus_g_method_return_error (call->context, error);
		goto out;
	}

	/* Set the hostname in all plugins */
	for (iter = priv->plugins; iter; iter = iter->next) {
		NMSystemConfigInterfaceCapabilities caps = NM_SYSTEM_CONFIG_INTERFACE_CAP_NONE;

		g_object_get (G_OBJECT (iter->data), NM_SYSTEM_CONFIG_INTERFACE_CAPABILITIES, &caps, NULL);
		if (caps & NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME) {
			g_object_set (G_OBJECT (iter->data), NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME, call->hostname, NULL);
			success = TRUE;
		}
	}

	if (success) {
		dbus_g_method_return (call->context);
	} else {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_SAVE_HOSTNAME_FAILED,
		                             "Saving the hostname failed.");
		dbus_g_method_return_error (call->context, error);
	}

out:
	g_clear_error (&error);
	polkit_call_free (call);
	if (pk_result)
		g_object_unref (pk_result);
}

static void
impl_settings_save_hostname (NMSysconfigSettings *self,
                             const char *hostname,
                             DBusGMethodInvocation *context)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	PolkitCall *call;
	GError *error = NULL;

	/* Do any of the plugins support setting the hostname? */
	if (!get_plugin (self, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME)) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_SAVE_HOSTNAME_NOT_SUPPORTED,
		                             "None of the registered plugins support setting the hostname.");
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	call = polkit_call_new (self, context, NULL, NULL, NULL, hostname);
	g_assert (call);
	polkit_authority_check_authorization (priv->authority,
	                                      call->subject,
	                                      NM_SYSCONFIG_POLICY_ACTION_HOSTNAME_MODIFY,
	                                      NULL,
	                                      POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
	                                      call->cancellable,
	                                      pk_hostname_cb,
	                                      call);
	priv->pk_calls = g_slist_append (priv->pk_calls, call);
}

static void
pk_authority_changed_cb (GObject *object, gpointer user_data)
{
	/* Let clients know they should re-check their authorization */
	g_signal_emit_by_name (NM_SYSCONFIG_SETTINGS (user_data),
                           NM_SETTINGS_SYSTEM_INTERFACE_CHECK_PERMISSIONS);
}

typedef struct {
	PolkitCall *pk_call;
	const char *pk_action;
	GCancellable *cancellable;
	NMSettingsSystemPermissions permission;
	gboolean disposed;
} PermissionsCall;

static void
permission_call_done (GObject *object, GAsyncResult *result, gpointer user_data)
{
	PermissionsCall *call = user_data;
	PolkitCall *pk_call = call->pk_call;
	NMSysconfigSettings *self = pk_call->self;
	NMSysconfigSettingsPrivate *priv;
	PolkitAuthorizationResult *pk_result;
	GError *error = NULL;

	/* If NMSysconfigSettings is gone, just skip to the end */
	if (call->disposed)
		goto done;

	priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	priv->permissions_calls = g_slist_remove (priv->permissions_calls, call);

	pk_result = polkit_authority_check_authorization_finish (priv->authority,
	                                                         result,
	                                                         &error);
	/* Some random error happened */
	if (error) {
		nm_log_err (LOGD_SYS_SET, "error checking '%s' permission: (%d) %s",
		            __FILE__, __LINE__, __func__,
		            call->pk_action,
		            error ? error->code : -1,
		            error && error->message ? error->message : "(unknown)");
		if (error)
			g_error_free (error);
	} else {
		/* If the caller is authorized, or the caller could authorize via a
		 * challenge, then authorization is possible.  Otherwise, caller is out of
		 * luck.
		 */
		if (   polkit_authorization_result_get_is_authorized (pk_result)
		    || polkit_authorization_result_get_is_challenge (pk_result))
		    pk_call->permissions |= call->permission;
	}

	g_object_unref (pk_result);

done:
	pk_call->permissions_calls--;
	if (pk_call->permissions_calls == 0) {
		if (call->disposed) {
			error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
			                             NM_SYSCONFIG_SETTINGS_ERROR_GENERAL,
			                             "Request was canceled.");
			dbus_g_method_return_error (pk_call->context, error);
			g_error_free (error);
		} else {
			/* All the permissions calls are done, return the full permissions
			 * bitfield back to the user.
			 */
			dbus_g_method_return (pk_call->context, pk_call->permissions);
		}

		polkit_call_free (pk_call);
	}
	memset (call, 0, sizeof (PermissionsCall));
	g_free (call);
}

static void
start_permission_check (NMSysconfigSettings *self,
                        PolkitCall *pk_call,
                        const char *pk_action,
                        NMSettingsSystemPermissions permission)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	PermissionsCall *call;

	g_return_if_fail (pk_call != NULL);
	g_return_if_fail (pk_action != NULL);
	g_return_if_fail (permission != NM_SETTINGS_SYSTEM_PERMISSION_NONE);

	call = g_malloc0 (sizeof (PermissionsCall));
	call->pk_call = pk_call;
	call->pk_action = pk_action;
	call->permission = permission;
	call->cancellable = g_cancellable_new ();

	pk_call->permissions_calls++;

	polkit_authority_check_authorization (priv->authority,
	                                      pk_call->subject,
	                                      pk_action,
	                                      NULL,
	                                      0,
	                                      call->cancellable,
	                                      permission_call_done,
	                                      call);
	priv->permissions_calls = g_slist_append (priv->permissions_calls, call);
}

static void
impl_settings_get_permissions (NMSysconfigSettings *self,
                               DBusGMethodInvocation *context)
{
	PolkitCall *call;

	call = polkit_call_new (self, context, NULL, NULL, NULL, FALSE);
	g_assert (call);

	/* Start checks for the various permissions */

	/* Only check for connection-modify if one of our plugins supports it. */
	if (get_plugin (self, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS)) {
		start_permission_check (self, call,
		                        NM_SYSCONFIG_POLICY_ACTION_CONNECTION_MODIFY,
		                        NM_SETTINGS_SYSTEM_PERMISSION_CONNECTION_MODIFY);
	}

	/* Only check for hostname-modify if one of our plugins supports it. */
	if (get_plugin (self, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME)) {
		start_permission_check (self, call,
		                        NM_SYSCONFIG_POLICY_ACTION_HOSTNAME_MODIFY,
		                        NM_SETTINGS_SYSTEM_PERMISSION_HOSTNAME_MODIFY);
	}

	// FIXME: hook these into plugin permissions like the modify permissions */
	start_permission_check (self, call,
	                        NM_SYSCONFIG_POLICY_ACTION_WIFI_SHARE_OPEN,
	                        NM_SETTINGS_SYSTEM_PERMISSION_WIFI_SHARE_OPEN);
	start_permission_check (self, call,
	                        NM_SYSCONFIG_POLICY_ACTION_WIFI_SHARE_PROTECTED,
	                        NM_SETTINGS_SYSTEM_PERMISSION_WIFI_SHARE_PROTECTED);
}

static gboolean
get_permissions (NMSettingsSystemInterface *settings,
                 NMSettingsSystemGetPermissionsFunc callback,
                 gpointer user_data)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (settings);
	NMSettingsSystemPermissions permissions = NM_SETTINGS_SYSTEM_PERMISSION_NONE;

	/* Local caller (ie, NM) gets full permissions by default because it doesn't
	 * need authorization.  However, permissions are still subject to plugin's
	 * restrictions.  i.e. if no plugins support connection-modify, then even
	 * the local caller won't get that permission.
	 */

	/* Only check for connection-modify if one of our plugins supports it. */
	if (get_plugin (self, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS))
		permissions |= NM_SETTINGS_SYSTEM_PERMISSION_CONNECTION_MODIFY;

	/* Only check for hostname-modify if one of our plugins supports it. */
	if (get_plugin (self, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME))
		permissions |= NM_SETTINGS_SYSTEM_PERMISSION_HOSTNAME_MODIFY;

	// FIXME: hook these into plugin permissions like the modify permissions */
	permissions |= NM_SETTINGS_SYSTEM_PERMISSION_WIFI_SHARE_OPEN;
	permissions |= NM_SETTINGS_SYSTEM_PERMISSION_WIFI_SHARE_PROTECTED;

	callback (settings, permissions, NULL, user_data);
	return TRUE;
}

static gboolean
have_connection_for_device (NMSysconfigSettings *self, GByteArray *mac)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer key;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	const GByteArray *setting_mac;
	gboolean ret = FALSE;

	g_return_val_if_fail (NM_IS_SYSCONFIG_SETTINGS (self), FALSE);
	g_return_val_if_fail (mac != NULL, FALSE);

	/* Find a wired connection locked to the given MAC address, if any */
	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, &key, NULL)) {
		NMConnection *connection = NM_CONNECTION (key);
		const char *connection_type;

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
		nm_log_warn (LOGD_SYS_SET, "not enough memory to load config file.");
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
	NMSettingConnection *s_con;
	char *tmp;
	GKeyFile *config;
	char **list, **iter, **updated;
	gboolean found = FALSE;
	gsize len = 0, i;
	char *data;

	/* If there was no config file specified, there's nothing to do */
	if (!priv->config_file)
		goto cleanup;

	/* When the default wired connection is removed (either deleted or saved
	 * to a new persistent connection by a plugin), write the MAC address of
	 * the wired device to the config file and don't create a new default wired
	 * connection for that device again.
	 */

	s_con = (NMSettingConnection *) nm_connection_get_setting (NM_CONNECTION (wired),
	                                                           NM_TYPE_SETTING_CONNECTION);
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

		/* New list; size + 1 for the new element, + 1 again for ending NULL */
		updated = g_malloc0 (sizeof (char*) * (len + 2));

		/* Copy original list and add new MAC */
		for (i = 0; list && list[i]; i++)
			updated[i] = list[i];
		updated[i++] = tmp;
		updated[i] = NULL;

		g_key_file_set_string_list (config,
		                            "main", CONFIG_KEY_NO_AUTO_DEFAULT,
		                            (const char **) updated,
		                            len + 2);
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
delete_cb (NMSettingsConnectionInterface *connection, GError *error, gpointer user_data)
{
}

static gboolean
default_wired_try_update (NMDefaultWiredConnection *wired,
                          NMSysconfigSettings *self)
{
	GError *error = NULL;
	NMSettingConnection *s_con;
	const char *id;

	/* Try to move this default wired conneciton to a plugin so that it has
	 * persistent storage.
	 */

	s_con = (NMSettingConnection *) nm_connection_get_setting (NM_CONNECTION (wired),
	                                                           NM_TYPE_SETTING_CONNECTION);
	g_assert (s_con);
	id = nm_setting_connection_get_id (s_con);
	g_assert (id);

	remove_connection (self, NM_SETTINGS_CONNECTION_INTERFACE (wired), FALSE);
	if (add_new_connection (self, NM_CONNECTION (wired), &error)) {
		nm_settings_connection_interface_delete (NM_SETTINGS_CONNECTION_INTERFACE (wired),
		                                         delete_cb,
		                                         NULL);

		g_object_set_data (G_OBJECT (nm_default_wired_connection_get_device (wired)),
		                   DEFAULT_WIRED_TAG,
		                   NULL);
		nm_log_info (LOGD_SYS_SET, "Saved default wired connection '%s' to persistent storage", id);
		return FALSE;
	}

	nm_log_warn (LOGD_SYS_SET, "couldn't save default wired connection '%s': %d / %s",
	             id,
	             error ? error->code : -1,
	             (error && error->message) ? error->message : "(unknown)");

	/* If there was an error, don't destroy the default wired connection,
	 * but add it back to the system settings service. Connection is already
	 * exported on the bus, don't export it again, thus do_export == FALSE.
	 */
	claim_connection (self, NM_SETTINGS_CONNECTION_INTERFACE (wired), FALSE);
	return TRUE;
}

void
nm_sysconfig_settings_device_added (NMSysconfigSettings *self, NMDevice *device)
{
	GByteArray *mac = NULL;
	struct ether_addr tmp;
	NMDefaultWiredConnection *wired;
	NMSettingConnection *s_con;
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

	if (get_plugin (self, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS))
		read_only = FALSE;

	wired = nm_default_wired_connection_new (mac, device, read_only);
	if (!wired)
		goto ignore;

	s_con = (NMSettingConnection *) nm_connection_get_setting (NM_CONNECTION (wired),
	                                                           NM_TYPE_SETTING_CONNECTION);
	g_assert (s_con);
	id = nm_setting_connection_get_id (s_con);
	g_assert (id);

	nm_log_info (LOGD_SYS_SET, "Added default wired connection '%s' for %s",
	             id, nm_device_get_udi (device));

	g_signal_connect (wired, "try-update", (GCallback) default_wired_try_update, self);
	g_signal_connect (wired, "deleted", (GCallback) default_wired_deleted, self);
	claim_connection (self, NM_SETTINGS_CONNECTION_INTERFACE (wired), TRUE);
	g_object_unref (wired);

	g_object_set_data (G_OBJECT (device), DEFAULT_WIRED_TAG, wired);

ignore:
	g_byte_array_free (mac, TRUE);
}

void
nm_sysconfig_settings_device_removed (NMSysconfigSettings *self, NMDevice *device)
{
	NMDefaultWiredConnection *connection;

	if (nm_device_get_device_type (device) != NM_DEVICE_TYPE_ETHERNET)
		return;

	connection = (NMDefaultWiredConnection *) g_object_get_data (G_OBJECT (device), DEFAULT_WIRED_TAG);
	if (connection)
		remove_connection (self, NM_SETTINGS_CONNECTION_INTERFACE (connection), TRUE);
}

NMSysconfigSettings *
nm_sysconfig_settings_new (const char *config_file,
                           const char *plugins,
                           DBusGConnection *bus,
                           GError **error)
{
	NMSysconfigSettings *self;
	NMSysconfigSettingsPrivate *priv;

	self = g_object_new (NM_TYPE_SYSCONFIG_SETTINGS,
	                     NM_SETTINGS_SERVICE_BUS, bus,
	                     NM_SETTINGS_SERVICE_SCOPE, NM_CONNECTION_SCOPE_SYSTEM,
	                     NULL);
	if (!self)
		return NULL;

	priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	priv->config_file = g_strdup (config_file);

	if (plugins) {
		/* Load the plugins; fail if a plugin is not found. */
		if (!load_plugins (self, plugins, error)) {
			g_object_unref (self);
			return NULL;
		}
		unmanaged_specs_changed (NULL, self);
	}

	return self;
}

/***************************************************************/

static void
dispose (GObject *object)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (object);
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	if (priv->auth_changed_id) {
		g_signal_handler_disconnect (priv->authority, priv->auth_changed_id);
		priv->auth_changed_id = 0;
	}

	/* Cancel PolicyKit requests */
	for (iter = priv->pk_calls; iter; iter = g_slist_next (iter)) {
		PolkitCall *call = iter->data;

		call->disposed = TRUE;
		g_cancellable_cancel (call->cancellable);
	}
	g_slist_free (priv->pk_calls);
	priv->pk_calls = NULL;

	/* Cancel PolicyKit permissions requests */
	for (iter = priv->permissions_calls; iter; iter = g_slist_next (iter)) {
		PermissionsCall *call = iter->data;

		call->disposed = TRUE;
		g_cancellable_cancel (call->cancellable);
	}
	g_slist_free (priv->permissions_calls);
	priv->permissions_calls = NULL;

	G_OBJECT_CLASS (nm_sysconfig_settings_parent_class)->dispose (object);
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

	g_free (priv->config_file);

	G_OBJECT_CLASS (nm_sysconfig_settings_parent_class)->finalize (object);
}

static void
settings_system_interface_init (NMSettingsSystemInterface *iface)
{
	iface->get_permissions = get_permissions;

	dbus_g_object_type_install_info (G_TYPE_FROM_INTERFACE (iface),
	                                 &dbus_glib_nm_settings_system_object_info);
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
	case NM_SETTINGS_SYSTEM_INTERFACE_PROP_HOSTNAME:
		g_value_take_string (value, nm_sysconfig_settings_get_hostname (self));

		/* Don't ever pass NULL through D-Bus */
		if (!g_value_get_string (value))
			g_value_set_static_string (value, "");
		break;
	case NM_SETTINGS_SYSTEM_INTERFACE_PROP_CAN_MODIFY:
		g_value_set_boolean (value, !!get_plugin (self, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS));
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
	NMSettingsServiceClass *ss_class = NM_SETTINGS_SERVICE_CLASS (class);
	
	g_type_class_add_private (class, sizeof (NMSysconfigSettingsPrivate));

	/* virtual methods */
	object_class->notify = notify;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	ss_class->list_connections = list_connections;
	ss_class->add_connection = add_connection;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_UNMANAGED_SPECS,
		 g_param_spec_boxed (NM_SYSCONFIG_SETTINGS_UNMANAGED_SPECS,
							 "Unamanged device specs",
							 "Unmanaged device specs",
							 DBUS_TYPE_G_LIST_OF_STRING,
							 G_PARAM_READABLE));

	g_object_class_override_property (object_class,
									  NM_SETTINGS_SYSTEM_INTERFACE_PROP_HOSTNAME,
									  NM_SETTINGS_SYSTEM_INTERFACE_HOSTNAME);

	g_object_class_override_property (object_class,
									  NM_SETTINGS_SYSTEM_INTERFACE_PROP_CAN_MODIFY,
									  NM_SETTINGS_SYSTEM_INTERFACE_CAN_MODIFY);

	/* signals */
	signals[PROPERTIES_CHANGED] = 
	                g_signal_new ("properties-changed",
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST,
	                              G_STRUCT_OFFSET (NMSysconfigSettingsClass, properties_changed),
	                              NULL, NULL,
	                              g_cclosure_marshal_VOID__BOXED,
	                              G_TYPE_NONE, 1, DBUS_TYPE_G_MAP_OF_VARIANT);

	dbus_g_error_domain_register (NM_SYSCONFIG_SETTINGS_ERROR,
	                              NM_DBUS_IFACE_SETTINGS_SYSTEM,
	                              NM_TYPE_SYSCONFIG_SETTINGS_ERROR);

	dbus_g_error_domain_register (NM_SETTINGS_INTERFACE_ERROR,
	                              NM_DBUS_IFACE_SETTINGS,
	                              NM_TYPE_SETTINGS_INTERFACE_ERROR);

	/* And register all the settings errors with D-Bus */
	dbus_g_error_domain_register (NM_CONNECTION_ERROR, NULL, NM_TYPE_CONNECTION_ERROR);
	dbus_g_error_domain_register (NM_SETTING_802_1X_ERROR, NULL, NM_TYPE_SETTING_802_1X_ERROR);
	dbus_g_error_domain_register (NM_SETTING_BLUETOOTH_ERROR, NULL, NM_TYPE_SETTING_BLUETOOTH_ERROR);
	dbus_g_error_domain_register (NM_SETTING_CDMA_ERROR, NULL, NM_TYPE_SETTING_CDMA_ERROR);
	dbus_g_error_domain_register (NM_SETTING_CONNECTION_ERROR, NULL, NM_TYPE_SETTING_CONNECTION_ERROR);
	dbus_g_error_domain_register (NM_SETTING_GSM_ERROR, NULL, NM_TYPE_SETTING_GSM_ERROR);
	dbus_g_error_domain_register (NM_SETTING_IP4_CONFIG_ERROR, NULL, NM_TYPE_SETTING_IP4_CONFIG_ERROR);
	dbus_g_error_domain_register (NM_SETTING_IP6_CONFIG_ERROR, NULL, NM_TYPE_SETTING_IP6_CONFIG_ERROR);
	dbus_g_error_domain_register (NM_SETTING_OLPC_MESH_ERROR, NULL, NM_TYPE_SETTING_OLPC_MESH_ERROR);
	dbus_g_error_domain_register (NM_SETTING_PPP_ERROR, NULL, NM_TYPE_SETTING_PPP_ERROR);
	dbus_g_error_domain_register (NM_SETTING_PPPOE_ERROR, NULL, NM_TYPE_SETTING_PPPOE_ERROR);
	dbus_g_error_domain_register (NM_SETTING_SERIAL_ERROR, NULL, NM_TYPE_SETTING_SERIAL_ERROR);
	dbus_g_error_domain_register (NM_SETTING_VPN_ERROR, NULL, NM_TYPE_SETTING_VPN_ERROR);
	dbus_g_error_domain_register (NM_SETTING_WIRED_ERROR, NULL, NM_TYPE_SETTING_WIRED_ERROR);
	dbus_g_error_domain_register (NM_SETTING_WIRELESS_SECURITY_ERROR, NULL, NM_TYPE_SETTING_WIRELESS_SECURITY_ERROR);
	dbus_g_error_domain_register (NM_SETTING_WIRELESS_ERROR, NULL, NM_TYPE_SETTING_WIRELESS_ERROR);
	dbus_g_error_domain_register (NM_SETTING_ERROR, NULL, NM_TYPE_SETTING_ERROR);
}

static void
nm_sysconfig_settings_init (NMSysconfigSettings *self)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	priv->connections = g_hash_table_new_full (g_direct_hash, g_direct_equal, g_object_unref, NULL);

	priv->authority = polkit_authority_get ();
	if (priv->authority) {
		priv->auth_changed_id = g_signal_connect (priv->authority,
		                                          "changed",
		                                          G_CALLBACK (pk_authority_changed_cb),
		                                          self);
	} else
		nm_log_warn (LOGD_SYS_SET, "failed to create PolicyKit authority.");
}

