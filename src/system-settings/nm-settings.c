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
#include "nm-settings.h"
#include "nm-sysconfig-connection.h"
#include "nm-polkit-helpers.h"
#include "nm-system-config-error.h"
#include "nm-default-wired-connection.h"
#include "nm-logging.h"
#include "nm-dbus-manager.h"
#include "nm-manager-auth.h"
#include "nm-session-monitor.h"

#define CONFIG_KEY_NO_AUTO_DEFAULT "no-auto-default"

/* LINKER CRACKROCK */
#define EXPORT(sym) void * __export_##sym = &sym;

#include "nm-inotify-helper.h"
EXPORT(nm_inotify_helper_get_type)
EXPORT(nm_inotify_helper_get)
EXPORT(nm_inotify_helper_add_watch)
EXPORT(nm_inotify_helper_remove_watch)

EXPORT(nm_sysconfig_connection_get_type)
EXPORT(nm_sysconfig_connection_replace_settings)
EXPORT(nm_sysconfig_connection_replace_and_commit)
/* END LINKER CRACKROCK */

static void claim_connection (NMSettings *self,
                              NMSysconfigConnection *connection,
                              gboolean do_export);

static gboolean impl_settings_list_connections (NMSettings *self,
                                                GPtrArray **connections,
                                                GError **error);

static void impl_settings_add_connection (NMSettings *self,
                                          GHashTable *settings,
                                          DBusGMethodInvocation *context);

static void impl_settings_save_hostname (NMSettings *self,
                                         const char *hostname,
                                         DBusGMethodInvocation *context);

#include "nm-settings-glue.h"

static void unmanaged_specs_changed (NMSystemConfigInterface *config, gpointer user_data);

typedef struct {
	NMDBusManager *dbus_mgr;
	DBusGConnection *bus;

	PolkitAuthority *authority;
	guint auth_changed_id;
	char *config_file;

	GSList *pk_calls;

	GSList *plugins;
	gboolean connections_loaded;
	GHashTable *connections;
	GSList *unmanaged_specs;
} NMSettingsPrivate;

G_DEFINE_TYPE (NMSettings, nm_settings, G_TYPE_OBJECT)

#define NM_SETTINGS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTINGS, NMSettingsPrivate))

enum {
	PROPERTIES_CHANGED,
	CONNECTION_ADDED,
	CONNECTION_UPDATED,
	CONNECTION_REMOVED,
	CONNECTION_VISIBILITY_CHANGED,
	CONNECTIONS_LOADED,

	NEW_CONNECTION, /* exported, not used internally */
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
load_connections (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
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
			claim_connection (self, NM_SYSCONFIG_CONNECTION (elt->data), TRUE);

		g_slist_free (plugin_connections);
	}

	priv->connections_loaded = TRUE;

	/* FIXME: Bad hack */
	unmanaged_specs_changed (NULL, self);

	g_signal_emit (self, signals[CONNECTIONS_LOADED], 0);
}

void
nm_settings_for_each_connection (NMSettings *self,
                                 NMSettingsForEachFunc for_each_func,
                                 gpointer user_data)
{
	NMSettingsPrivate *priv;
	GHashTableIter iter;
	gpointer data;

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_SETTINGS (self));
	g_return_if_fail (for_each_func != NULL);
	
	priv = NM_SETTINGS_GET_PRIVATE (self);

	load_connections (self);

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &data))
		for_each_func (self, NM_SYSCONFIG_CONNECTION (data), user_data);
}

static gboolean
impl_settings_list_connections (NMSettings *self,
                                GPtrArray **connections,
                                GError **error)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer key;

	load_connections (self);

	*connections = g_ptr_array_sized_new (g_hash_table_size (priv->connections) + 1);
	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, &key, NULL))
		g_ptr_array_add (*connections, g_strdup ((const char *) key));
	return TRUE;
}

static int
connection_sort (gconstpointer pa, gconstpointer pb)
{
	NMConnection *a = NM_CONNECTION (pa);
	NMSettingConnection *con_a;
	NMConnection *b = NM_CONNECTION (pb);
	NMSettingConnection *con_b;

	con_a = (NMSettingConnection *) nm_connection_get_setting (a, NM_TYPE_SETTING_CONNECTION);
	g_assert (con_a);
	con_b = (NMSettingConnection *) nm_connection_get_setting (b, NM_TYPE_SETTING_CONNECTION);
	g_assert (con_b);

	if (nm_setting_connection_get_autoconnect (con_a) != nm_setting_connection_get_autoconnect (con_b)) {
		if (nm_setting_connection_get_autoconnect (con_a))
			return -1;
		return 1;
	}

	if (nm_setting_connection_get_timestamp (con_a) > nm_setting_connection_get_timestamp (con_b))
		return -1;
	else if (nm_setting_connection_get_timestamp (con_a) == nm_setting_connection_get_timestamp (con_b))
		return 0;
	return 1;
}

/* Returns a GSList of referenced NMConnection objects, caller must
 * unref the connections in the list and destroy the list.
 */
GSList *
nm_settings_get_connections (NMSettings *self)
{
	GHashTableIter iter;
	gpointer data = NULL;
	GSList *list = NULL;

	g_return_val_if_fail (NM_IS_SETTINGS (self), NULL);

	g_hash_table_iter_init (&iter, NM_SETTINGS_GET_PRIVATE (self)->connections);
	while (g_hash_table_iter_next (&iter, NULL, &data))
		list = g_slist_insert_sorted (list, data, connection_sort);
	return g_slist_reverse (list);
}

NMSysconfigConnection *
nm_settings_get_connection_by_path (NMSettings *self, const char *path)
{
	NMSettingsPrivate *priv;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_SETTINGS (self), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	priv = NM_SETTINGS_GET_PRIVATE (self);

	load_connections (self);

	return (NMSysconfigConnection *) g_hash_table_lookup (priv->connections, path);
}

static void
clear_unmanaged_specs (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

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
nm_settings_get_unmanaged_specs (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	load_connections (self);
	return priv->unmanaged_specs;
}

static NMSystemConfigInterface *
get_plugin (NMSettings *self, guint32 capability)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
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

/* Returns an allocated string which the caller owns and must eventually free */
char *
nm_settings_get_hostname (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
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

	return NULL;
}

static void
plugin_connection_added (NMSystemConfigInterface *config,
                         NMSysconfigConnection *connection,
                         gpointer user_data)
{
	claim_connection (NM_SETTINGS (user_data), connection, TRUE);
}

static gboolean
find_unmanaged_device (NMSettings *self, const char *needle)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
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
	NMSettings *self = NM_SETTINGS (user_data);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
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

	g_object_notify (G_OBJECT (self), NM_SETTINGS_UNMANAGED_SPECS);
}

static void
hostname_changed (NMSystemConfigInterface *config,
                  GParamSpec *pspec,
                  gpointer user_data)
{
	g_object_notify (G_OBJECT (user_data), NM_SETTINGS_HOSTNAME);
}

static void
add_plugin (NMSettings *self, NMSystemConfigInterface *plugin)
{
	NMSettingsPrivate *priv;
	char *pname = NULL;
	char *pinfo = NULL;

	g_return_if_fail (NM_IS_SETTINGS (self));
	g_return_if_fail (NM_IS_SYSTEM_CONFIG_INTERFACE (plugin));

	priv = NM_SETTINGS_GET_PRIVATE (self);

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
load_plugins (NMSettings *self, const char *plugins, GError **error)
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
		const char *pname = g_strstrip (*iter);
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
connection_removed (NMSysconfigConnection *connection, gpointer user_data)
{
	g_object_ref (connection);

	g_hash_table_remove (NM_SETTINGS_GET_PRIVATE (user_data)->connections, connection);
	g_signal_emit (NM_SETTINGS (user_data),
	               signals[CONNECTION_REMOVED],
	               0,
	               connection);
	g_object_unref (connection);
}

static void
connection_updated (NMSysconfigConnection *connection, gpointer user_data)
{
	g_signal_emit (NM_SETTINGS (user_data),
	               signals[CONNECTION_UPDATED],
	               0,
	               connection);
}

static void
connection_visibility_changed (NMSysconfigConnection *connection,
                               GParamSpec *pspec,
                               gpointer user_data)
{
	g_signal_emit (NM_SETTINGS (user_data),
	               signals[CONNECTION_VISIBILITY_CHANGED],
	               0,
	               connection);
}

static void
claim_connection (NMSettings *self,
                  NMSysconfigConnection *connection,
                  gboolean do_export)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	static guint32 ec_counter = 0;
	GError *error = NULL;
	GHashTableIter iter;
	gpointer data;
	char *path;

	g_return_if_fail (NM_IS_SYSCONFIG_CONNECTION (connection));

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &data)) {
		/* prevent duplicates */
		if (data == connection)
			return;
	}

	if (!nm_connection_verify (NM_CONNECTION (connection), &error)) {
		nm_log_warn (LOGD_SYS_SET, "plugin provided invalid connection: '%s' / '%s' invalid: %d",
		             g_type_name (nm_connection_lookup_setting_type_by_quark (error->domain)),
		             error->message, error->code);
		g_error_free (error);
		return;
	}

	/* Ensure it's initial visibility is up-to-date */
	nm_sysconfig_connection_recheck_visibility (connection);

	g_signal_connect (connection,
	                  NM_SYSCONFIG_CONNECTION_REMOVED,
	                  G_CALLBACK (connection_removed),
	                  self);

	g_signal_connect (connection,
	                  NM_SYSCONFIG_CONNECTION_UPDATED,
	                  G_CALLBACK (connection_updated),
	                  self);

	g_signal_connect (connection, "notify::" NM_SYSCONFIG_CONNECTION_VISIBLE,
	                  G_CALLBACK (connection_visibility_changed),
	                  self);

	/* Export the connection over D-Bus */
	g_warn_if_fail (nm_connection_get_path (NM_CONNECTION (connection)) == NULL);
	path = g_strdup_printf ("%s/%u", NM_DBUS_PATH_SETTINGS, ec_counter++);
	nm_connection_set_path (NM_CONNECTION (connection), path);
	dbus_g_connection_register_g_object (priv->bus, path, G_OBJECT (connection));
	g_free (path);

	g_hash_table_insert (priv->connections,
	                     (gpointer) nm_connection_get_path (NM_CONNECTION (connection)),
	                     g_object_ref (connection));

	/* Only emit the individual connection-added signal after connections
	 * have been initially loaded.  While getting the first list of connections
	 * we suppress it, then send the connections-loaded signal after we're all
	 * done to minimize processing.
	 */
	if (priv->connections_loaded) {
		/* Internal added signal */
		g_signal_emit (self, signals[CONNECTION_ADDED], 0, connection);

		/* Exported D-Bus signal */
		g_signal_emit (self, signals[NEW_CONNECTION], 0, connection);
	}
}

// TODO it seems that this is only ever used to remove a
// NMDefaultWiredConnection, and it probably needs to stay that way. So this
// *needs* a better name!
static void
remove_default_wired_connection (NMSettings *self,
                                 NMSysconfigConnection *connection,
                                 gboolean do_signal)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	const char *path = nm_connection_get_path (NM_CONNECTION (connection));

	if (g_hash_table_lookup (priv->connections, path)) {
		g_signal_emit_by_name (G_OBJECT (connection), NM_SYSCONFIG_CONNECTION_REMOVED);
		g_hash_table_remove (priv->connections, path);
	}
}

typedef struct {
	NMSettings *self;
	DBusGMethodInvocation *context;
	PolkitSubject *subject;
	GCancellable *cancellable;
	gboolean disposed;

	NMConnection *connection;
	gpointer callback_data;

	char *hostname;
} PolkitCall;

#include "nm-dbus-manager.h"

static PolkitCall *
polkit_call_new (NMSettings *self,
                 DBusGMethodInvocation *context,
                 NMConnection *connection,
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
add_new_connection (NMSettings *self,
                    NMConnection *connection,
                    GError **error)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GError *tmp_error = NULL, *last_error = NULL;
	GSList *iter;
	gboolean success = FALSE;

	/* Here's how it works:
	   1) plugin writes a connection.
	   2) plugin notices that a new connection is available for reading.
	   3) plugin reads the new connection (the one it wrote in 1) and emits 'connection-added' signal.
	   4) NMSettings receives the signal and adds it to it's connection list.
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
	NMSettings *self = call->self;
	NMSettingsPrivate *priv;
	PolkitAuthorizationResult *pk_result;
	GError *error = NULL, *add_error = NULL;

	/* If NMSettings is already gone, do nothing */
	if (call->disposed) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_GENERAL,
		                             "Request was canceled.");
		dbus_g_method_return_error (call->context, error);
		g_error_free (error);
		polkit_call_free (call);
		return;
	}

	priv = NM_SETTINGS_GET_PRIVATE (self);

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

	if (add_new_connection (self, call->connection, &add_error))
		dbus_g_method_return (call->context);
	else {
		error = g_error_new (NM_SYSCONFIG_SETTINGS_ERROR,
		                     NM_SYSCONFIG_SETTINGS_ERROR_ADD_FAILED,
		                     "Saving connection failed: (%d) %s",
		                     add_error ? add_error->code : -1,
		                     (add_error && add_error->message) ? add_error->message : "(unknown)");
		g_error_free (add_error);
		dbus_g_method_return_error (call->context, error);
	}

out:
	g_clear_error (&error);
	polkit_call_free (call);
	if (pk_result)
		g_object_unref (pk_result);
}

static void
impl_settings_add_connection (NMSettings *self,
                              GHashTable *settings,
                              DBusGMethodInvocation *context)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	PolkitCall *call;
	NMConnection *connection;
	GError *error = NULL;

	connection = nm_connection_new_from_hash (settings, &error);
	if (!connection) {
		g_assert (error);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	/* Do any of the plugins support adding? */
	if (!get_plugin (self, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS)) {
		error = g_error_new_literal (NM_SYSCONFIG_SETTINGS_ERROR,
		                             NM_SYSCONFIG_SETTINGS_ERROR_ADD_NOT_SUPPORTED,
		                             "None of the registered plugins support add.");
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	call = polkit_call_new (self, context, connection, NULL);
	g_assert (call);
	polkit_authority_check_authorization (priv->authority,
	                                      call->subject,
	                                      NM_AUTH_PERMISSION_SETTINGS_CONNECTION_MODIFY,
	                                      NULL,
	                                      POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
	                                      call->cancellable,
	                                      pk_add_cb,
	                                      call);
	priv->pk_calls = g_slist_append (priv->pk_calls, call);

	g_object_unref (connection);
}

static void
pk_hostname_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	PolkitCall *call = user_data;
	NMSettings *self = call->self;
	NMSettingsPrivate *priv;
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

	priv = NM_SETTINGS_GET_PRIVATE (self);

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
impl_settings_save_hostname (NMSettings *self,
                             const char *hostname,
                             DBusGMethodInvocation *context)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
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

	call = polkit_call_new (self, context, NULL, hostname);
	g_assert (call);
	polkit_authority_check_authorization (priv->authority,
	                                      call->subject,
	                                      NM_AUTH_PERMISSION_SETTINGS_HOSTNAME_MODIFY,
	                                      NULL,
	                                      POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
	                                      call->cancellable,
	                                      pk_hostname_cb,
	                                      call);
	priv->pk_calls = g_slist_append (priv->pk_calls, call);
}

static gboolean
have_connection_for_device (NMSettings *self, GByteArray *mac)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer data;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	const GByteArray *setting_mac;
	gboolean ret = FALSE;

	g_return_val_if_fail (NM_IS_SETTINGS (self), FALSE);
	g_return_val_if_fail (mac != NULL, FALSE);

	/* Find a wired connection locked to the given MAC address, if any */
	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &data)) {
		NMConnection *connection = NM_CONNECTION (data);
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
is_mac_auto_wired_blacklisted (NMSettings *self, const GByteArray *mac)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
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

		if (strcmp(g_strstrip(*iter), "*") == 0) {
			found = TRUE;
			break;
		}

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
                       NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
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
	for (iter = list; iter && *iter; iter++) {
		struct ether_addr *candidate;

		if (strcmp(g_strstrip(*iter), "*") == 0) {
			found = TRUE;
			break;
		}

		candidate = ether_aton (*iter);
		if (candidate && !memcmp (mac->data, candidate->ether_addr_octet, ETH_ALEN)) {
			found = TRUE;
			break;
		}
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
delete_cb (NMSysconfigConnection *connection, GError *error, gpointer user_data)
{
}

static gboolean
default_wired_try_update (NMDefaultWiredConnection *wired,
                          NMSettings *self)
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

	remove_default_wired_connection (self, NM_SYSCONFIG_CONNECTION (wired), FALSE);
	if (add_new_connection (self, NM_CONNECTION (wired), &error)) {
		nm_sysconfig_connection_delete (NM_SYSCONFIG_CONNECTION (wired),
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
	claim_connection (self, NM_SYSCONFIG_CONNECTION (wired), FALSE);
	return TRUE;
}

void
nm_settings_device_added (NMSettings *self, NMDevice *device)
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
	claim_connection (self, NM_SYSCONFIG_CONNECTION (wired), TRUE);
	g_object_unref (wired);

	g_object_set_data (G_OBJECT (device), DEFAULT_WIRED_TAG, wired);

ignore:
	g_byte_array_free (mac, TRUE);
}

void
nm_settings_device_removed (NMSettings *self, NMDevice *device)
{
	NMDefaultWiredConnection *connection;

	if (nm_device_get_device_type (device) != NM_DEVICE_TYPE_ETHERNET)
		return;

	connection = (NMDefaultWiredConnection *) g_object_get_data (G_OBJECT (device), DEFAULT_WIRED_TAG);
	if (connection)
		remove_default_wired_connection (self, NM_SYSCONFIG_CONNECTION (connection), TRUE);
}

/***************************************************************/

NMSettings *
nm_settings_new (const char *config_file,
                           const char *plugins,
                           GError **error)
{
	NMSettings *self;
	NMSettingsPrivate *priv;

	self = g_object_new (NM_TYPE_SETTINGS, NULL);
	if (!self)
		return NULL;

	priv = NM_SETTINGS_GET_PRIVATE (self);

	priv->config_file = g_strdup (config_file);
	priv->dbus_mgr = nm_dbus_manager_get ();
	priv->bus = nm_dbus_manager_get_connection (priv->dbus_mgr);

	if (plugins) {
		/* Load the plugins; fail if a plugin is not found. */
		if (!load_plugins (self, plugins, error)) {
			g_object_unref (self);
			return NULL;
		}
		unmanaged_specs_changed (NULL, self);
	}

	dbus_g_connection_register_g_object (priv->bus, NM_DBUS_PATH_SETTINGS, G_OBJECT (self));
	return self;
}

static void
dispose (GObject *object)
{
	NMSettings *self = NM_SETTINGS (object);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
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

	g_object_unref (priv->dbus_mgr);

	G_OBJECT_CLASS (nm_settings_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMSettings *self = NM_SETTINGS (object);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	g_hash_table_destroy (priv->connections);

	clear_unmanaged_specs (self);

	g_slist_foreach (priv->plugins, (GFunc) g_object_unref, NULL);
	g_slist_free (priv->plugins);

	g_free (priv->config_file);

	G_OBJECT_CLASS (nm_settings_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMSettings *self = NM_SETTINGS (object);
	const GSList *specs, *iter;
	GSList *copy = NULL;

	switch (prop_id) {
	case PROP_UNMANAGED_SPECS:
		specs = nm_settings_get_unmanaged_specs (self);
		for (iter = specs; iter; iter = g_slist_next (iter))
			copy = g_slist_append (copy, g_strdup (iter->data));
		g_value_take_boxed (value, copy);
		break;
	case PROP_HOSTNAME:
		g_value_take_string (value, nm_settings_get_hostname (self));

		/* Don't ever pass NULL through D-Bus */
		if (!g_value_get_string (value))
			g_value_set_static_string (value, "");
		break;
	case PROP_CAN_MODIFY:
		g_value_set_boolean (value, !!get_plugin (self, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_settings_class_init (NMSettingsClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);
	
	g_type_class_add_private (class, sizeof (NMSettingsPrivate));

	/* virtual methods */
	object_class->notify = notify;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* properties */

	g_object_class_install_property
		(object_class, PROP_UNMANAGED_SPECS,
		 g_param_spec_boxed (NM_SETTINGS_UNMANAGED_SPECS,
							 "Unamanged device specs",
							 "Unmanaged device specs",
							 DBUS_TYPE_G_LIST_OF_STRING,
							 G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_HOSTNAME,
		 g_param_spec_string (NM_SETTINGS_HOSTNAME,
		                      "Hostname",
		                      "Persistent hostname",
		                      NULL,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_CAN_MODIFY,
		 g_param_spec_boolean (NM_SETTINGS_CAN_MODIFY,
		                       "CanModify",
		                       "Can modify anything (hostname, connections, etc)",
		                       FALSE,
		                       G_PARAM_READABLE));

	/* signals */
	signals[PROPERTIES_CHANGED] = 
	                g_signal_new ("properties-changed",
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST,
	                              G_STRUCT_OFFSET (NMSettingsClass, properties_changed),
	                              NULL, NULL,
	                              g_cclosure_marshal_VOID__BOXED,
	                              G_TYPE_NONE, 1, DBUS_TYPE_G_MAP_OF_VARIANT);
	signals[CONNECTION_ADDED] = 
	                g_signal_new (NM_SETTINGS_CONNECTION_ADDED,
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST,
	                              G_STRUCT_OFFSET (NMSettingsClass, connection_added),
	                              NULL, NULL,
	                              g_cclosure_marshal_VOID__OBJECT,
	                              G_TYPE_NONE, 1, G_TYPE_OBJECT);

	signals[CONNECTION_UPDATED] = 
	                g_signal_new (NM_SETTINGS_CONNECTION_UPDATED,
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST,
	                              G_STRUCT_OFFSET (NMSettingsClass, connection_updated),
	                              NULL, NULL,
	                              g_cclosure_marshal_VOID__OBJECT,
	                              G_TYPE_NONE, 1, G_TYPE_OBJECT);

	signals[CONNECTION_REMOVED] = 
	                g_signal_new (NM_SETTINGS_CONNECTION_REMOVED,
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST,
	                              G_STRUCT_OFFSET (NMSettingsClass, connection_removed),
	                              NULL, NULL,
	                              g_cclosure_marshal_VOID__OBJECT,
	                              G_TYPE_NONE, 1, G_TYPE_OBJECT);

	signals[CONNECTION_VISIBILITY_CHANGED] = 
	                g_signal_new (NM_SETTINGS_CONNECTION_VISIBILITY_CHANGED,
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST,
	                              G_STRUCT_OFFSET (NMSettingsClass, connection_visibility_changed),
	                              NULL, NULL,
	                              g_cclosure_marshal_VOID__OBJECT,
	                              G_TYPE_NONE, 1, G_TYPE_OBJECT);

	signals[CONNECTIONS_LOADED] = 
	                g_signal_new (NM_SETTINGS_CONNECTIONS_LOADED,
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST,
	                              G_STRUCT_OFFSET (NMSettingsClass, connections_loaded),
	                              NULL, NULL,
	                              g_cclosure_marshal_VOID__VOID,
	                              G_TYPE_NONE, 0);

	signals[NEW_CONNECTION] = 
	                g_signal_new ("new-connection",
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST, 0, NULL, NULL,
	                              g_cclosure_marshal_VOID__OBJECT,
	                              G_TYPE_NONE, 0);

	dbus_g_error_domain_register (NM_SYSCONFIG_SETTINGS_ERROR,
	                              NM_DBUS_IFACE_SETTINGS,
	                              NM_TYPE_SYSCONFIG_SETTINGS_ERROR);

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

	dbus_g_object_type_install_info (NM_TYPE_SETTINGS, &dbus_glib_nm_settings_object_info);

}

static void
nm_settings_init (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GError *error = NULL;

	priv->connections = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);

	priv->authority = polkit_authority_get_sync (NULL, &error);
	if (!priv->authority) {
		nm_log_warn (LOGD_SYS_SET, "failed to create PolicyKit authority: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}
}

