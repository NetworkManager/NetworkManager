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
 * (C) Copyright 2007 - 2011 Red Hat, Inc.
 * (C) Copyright 2008 Novell, Inc.
 */

#include "config.h"

#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <gmodule.h>
#include <pwd.h>

#if HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include <nm-dbus-interface.h>
#include <nm-connection.h>
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
#include <nm-setting-adsl.h>
#include <nm-setting-wireless.h>
#include <nm-setting-wireless-security.h>
#include <nm-setting-bond.h>
#include <nm-utils.h>
#include "nm-core-internal.h"

#include "nm-device-ethernet.h"
#include "nm-settings.h"
#include "nm-settings-connection.h"
#include "nm-settings-plugin.h"
#include "nm-default.h"
#include "nm-bus-manager.h"
#include "nm-auth-utils.h"
#include "nm-auth-subject.h"
#include "nm-session-monitor.h"
#include "plugins/keyfile/plugin.h"
#include "nm-agent-manager.h"
#include "nm-connection-provider.h"
#include "nm-config.h"
#include "nm-audit-manager.h"
#include "NetworkManagerUtils.h"
#include "nm-dispatcher.h"

#include "nmdbus-settings.h"

#define LOG(level, ...) \
	G_STMT_START { \
		nm_log ((level), LOGD_CORE, \
		        "settings: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__) \
		        _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
	} G_STMT_END

/* LINKER CRACKROCK */
#define EXPORT(sym) void * __export_##sym = &sym;

#include "nm-inotify-helper.h"
EXPORT(nm_inotify_helper_get_type)
EXPORT(nm_inotify_helper_get)
EXPORT(nm_inotify_helper_add_watch)
EXPORT(nm_inotify_helper_remove_watch)

EXPORT(nm_settings_connection_get_type)
EXPORT(nm_settings_connection_replace_settings)
EXPORT(nm_settings_connection_replace_and_commit)
/* END LINKER CRACKROCK */

#define HOSTNAMED_SERVICE_NAME      "org.freedesktop.hostname1"
#define HOSTNAMED_SERVICE_PATH      "/org/freedesktop/hostname1"
#define HOSTNAMED_SERVICE_INTERFACE "org.freedesktop.hostname1"

#define HOSTNAME_FILE_DEFAULT   "/etc/hostname"
#define HOSTNAME_FILE_SUSE      "/etc/HOSTNAME"
#define HOSTNAME_FILE_GENTOO    "/etc/conf.d/hostname"
#define IFCFG_DIR               SYSCONFDIR "/sysconfig/network"
#define CONF_DHCP               IFCFG_DIR "/dhcp"

#define PLUGIN_MODULE_PATH      "plugin-module-path"

#if defined(HOSTNAME_PERSIST_SUSE)
#define HOSTNAME_FILE           HOSTNAME_FILE_SUSE
#elif defined(HOSTNAME_PERSIST_GENTOO)
#define HOSTNAME_FILE           HOSTNAME_FILE_GENTOO
#else
#define HOSTNAME_FILE           HOSTNAME_FILE_DEFAULT
#endif

static void claim_connection (NMSettings *self,
                              NMSettingsConnection *connection);

static void unmanaged_specs_changed (NMSettingsPlugin *config, gpointer user_data);
static void unrecognized_specs_changed (NMSettingsPlugin *config, gpointer user_data);

static void connection_provider_iface_init (NMConnectionProviderInterface *cp_iface);

G_DEFINE_TYPE_EXTENDED (NMSettings, nm_settings, NM_TYPE_EXPORTED_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_CONNECTION_PROVIDER, connection_provider_iface_init))


typedef struct {
	NMAgentManager *agent_mgr;

	NMConfig *config;

	GSList *auths;

	GSList *plugins;
	gboolean connections_loaded;
	GHashTable *connections;
	GSList *unmanaged_specs;
	GSList *unrecognized_specs;
	GSList *get_connections_cache;

	gboolean started;
	gboolean startup_complete;

	struct {
		char *value;
		char *file;
		GFileMonitor *monitor;
		GFileMonitor *dhcp_monitor;
		guint monitor_id;
		guint dhcp_monitor_id;
		GDBusProxy *hostnamed_proxy;
	} hostname;
} NMSettingsPrivate;

#define NM_SETTINGS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTINGS, NMSettingsPrivate))

enum {
	CONNECTION_ADDED,
	CONNECTION_UPDATED,
	CONNECTION_UPDATED_BY_USER,
	CONNECTION_REMOVED,
	CONNECTION_VISIBILITY_CHANGED,
	AGENT_REGISTERED,

	NEW_CONNECTION, /* exported, not used internally */
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_UNMANAGED_SPECS,
	PROP_HOSTNAME,
	PROP_CAN_MODIFY,
	PROP_CONNECTIONS,
	PROP_STARTUP_COMPLETE,

	LAST_PROP
};

static void
check_startup_complete (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GHashTableIter iter;
	NMSettingsConnection *conn;

	if (priv->startup_complete)
		return;

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &conn)) {
		if (!nm_settings_connection_get_ready (conn))
			return;
	}

	priv->startup_complete = TRUE;
	g_object_notify (G_OBJECT (self), NM_SETTINGS_STARTUP_COMPLETE);
}

static void
connection_ready_changed (NMSettingsConnection *conn,
                          GParamSpec *pspec,
                          gpointer user_data)
{
	NMSettings *self = NM_SETTINGS (user_data);

	if (nm_settings_connection_get_ready (conn))
		check_startup_complete (self);
}

static void
plugin_connection_added (NMSettingsPlugin *config,
                         NMSettingsConnection *connection,
                         gpointer user_data)
{
	claim_connection (NM_SETTINGS (user_data), connection);
}

static void
load_connections (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->plugins; iter; iter = g_slist_next (iter)) {
		NMSettingsPlugin *plugin = NM_SETTINGS_PLUGIN (iter->data);
		GSList *plugin_connections;
		GSList *elt;

		plugin_connections = nm_settings_plugin_get_connections (plugin);

		// FIXME: ensure connections from plugins loaded with a lower priority
		// get rejected when they conflict with connections from a higher
		// priority plugin.

		for (elt = plugin_connections; elt; elt = g_slist_next (elt))
			claim_connection (self, NM_SETTINGS_CONNECTION (elt->data));

		g_slist_free (plugin_connections);

		g_signal_connect (plugin, NM_SETTINGS_PLUGIN_CONNECTION_ADDED,
		                  G_CALLBACK (plugin_connection_added), self);
		g_signal_connect (plugin, NM_SETTINGS_PLUGIN_UNMANAGED_SPECS_CHANGED,
		                  G_CALLBACK (unmanaged_specs_changed), self);
		g_signal_connect (plugin, NM_SETTINGS_PLUGIN_UNRECOGNIZED_SPECS_CHANGED,
		                  G_CALLBACK (unrecognized_specs_changed), self);
	}

	priv->connections_loaded = TRUE;

	unmanaged_specs_changed (NULL, self);
	unrecognized_specs_changed (NULL, self);
}

void
nm_settings_for_each_connection (NMSettings *self,
                                 NMSettingsForEachFunc for_each_func,
                                 gpointer user_data)
{
	NMSettingsPrivate *priv;
	GHashTableIter iter;
	gpointer data;

	g_return_if_fail (NM_IS_SETTINGS (self));
	g_return_if_fail (for_each_func != NULL);
	
	priv = NM_SETTINGS_GET_PRIVATE (self);

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &data))
		for_each_func (self, NM_SETTINGS_CONNECTION (data), user_data);
}

static void
impl_settings_list_connections (NMSettings *self,
                                GDBusMethodInvocation *context)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GPtrArray *connections;
	GHashTableIter iter;
	gpointer key;

	connections = g_ptr_array_sized_new (g_hash_table_size (priv->connections) + 1);
	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, &key, NULL))
		g_ptr_array_add (connections, key);
	g_ptr_array_add (connections, NULL);

	g_dbus_method_invocation_return_value (context,
	                                       g_variant_new ("(^ao)", connections->pdata));
	g_ptr_array_unref (connections);
}

NMSettingsConnection *
nm_settings_get_connection_by_uuid (NMSettings *self, const char *uuid)
{
	NMSettingsPrivate *priv;
	NMSettingsConnection *candidate;
	GHashTableIter iter;

	g_return_val_if_fail (NM_IS_SETTINGS (self), NULL);
	g_return_val_if_fail (uuid != NULL, NULL);

	priv = NM_SETTINGS_GET_PRIVATE (self);

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &candidate)) {
		if (g_strcmp0 (uuid, nm_settings_connection_get_uuid (candidate)) == 0)
			return candidate;
	}

	return NULL;
}

static void
impl_settings_get_connection_by_uuid (NMSettings *self,
                                      GDBusMethodInvocation *context,
                                      const char *uuid)
{
	NMSettingsConnection *connection = NULL;
	NMAuthSubject *subject = NULL;
	GError *error = NULL;
	char *error_desc = NULL;

	connection = nm_settings_get_connection_by_uuid (self, uuid);
	if (!connection) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                             "No connection with the UUID was found.");
		goto error;
	}

	subject = nm_auth_subject_new_unix_process_from_context (context);
	if (!subject) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Unable to determine UID of request.");
		goto error;
	}

	if (!nm_auth_is_subject_in_acl (NM_CONNECTION (connection),
	                                subject,
	                                &error_desc)) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             error_desc);
		g_free (error_desc);
		goto error;
	}

	g_clear_object (&subject);
	g_dbus_method_invocation_return_value (
		context,
		g_variant_new ("(o)", nm_connection_get_path (NM_CONNECTION (connection))));
	return;

error:
	g_assert (error);
	g_dbus_method_invocation_take_error (context, error);
	g_clear_object (&subject);
}

static int
connection_sort (gconstpointer pa, gconstpointer pb)
{
	NMConnection *a = NM_CONNECTION (pa);
	NMSettingConnection *con_a;
	NMConnection *b = NM_CONNECTION (pb);
	NMSettingConnection *con_b;
	guint64 ts_a = 0, ts_b = 0;
	gboolean can_ac_a, can_ac_b;

	con_a = nm_connection_get_setting_connection (a);
	g_assert (con_a);
	con_b = nm_connection_get_setting_connection (b);
	g_assert (con_b);

	can_ac_a = !!nm_setting_connection_get_autoconnect (con_a);
	can_ac_b = !!nm_setting_connection_get_autoconnect (con_b);
	if (can_ac_a != can_ac_b)
		return can_ac_a ? -1 : 1;

	nm_settings_connection_get_timestamp (NM_SETTINGS_CONNECTION (pa), &ts_a);
	nm_settings_connection_get_timestamp (NM_SETTINGS_CONNECTION (pb), &ts_b);
	if (ts_a > ts_b)
		return -1;
	else if (ts_a == ts_b)
		return 0;
	return 1;
}

/* Returns a list of NMSettingsConnections.
 * The list is sorted in the order suitable for auto-connecting, i.e.
 * first go connections with autoconnect=yes and most recent timestamp.
 * Caller must free the list with g_slist_free().
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
	return list;
}

NMSettingsConnection *
nm_settings_get_connection_by_path (NMSettings *self, const char *path)
{
	NMSettingsPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTINGS (self), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	priv = NM_SETTINGS_GET_PRIVATE (self);

	return (NMSettingsConnection *) g_hash_table_lookup (priv->connections, path);
}

gboolean
nm_settings_has_connection (NMSettings *self, NMConnection *connection)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer data;

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &data))
		if (data == connection)
			return TRUE;

	return FALSE;
}

const GSList *
nm_settings_get_unmanaged_specs (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	return priv->unmanaged_specs;
}

static NMSettingsPlugin *
get_plugin (NMSettings *self, guint32 capability)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	g_return_val_if_fail (self != NULL, NULL);

	/* Do any of the plugins support the given capability? */
	for (iter = priv->plugins; iter; iter = iter->next) {
		NMSettingsPluginCapabilities caps = NM_SETTINGS_PLUGIN_CAP_NONE;

		g_object_get (G_OBJECT (iter->data), NM_SETTINGS_PLUGIN_CAPABILITIES, &caps, NULL);
		if (NM_FLAGS_ALL (caps, capability))
			return NM_SETTINGS_PLUGIN (iter->data);
	}

	return NULL;
}

#if defined(HOSTNAME_PERSIST_GENTOO)
static gchar *
read_hostname_gentoo (const char *path)
{
	gchar *contents = NULL, *result = NULL, *tmp;
	gchar **all_lines = NULL;
	guint line_num, i;

	if (!g_file_get_contents (path, &contents, NULL, NULL))
		return NULL;
	all_lines = g_strsplit (contents, "\n", 0);
	line_num = g_strv_length (all_lines);
	for (i = 0; i < line_num; i++) {
		g_strstrip (all_lines[i]);
		if (all_lines[i][0] == '#' || all_lines[i][0] == '\0')
			continue;
		if (g_str_has_prefix (all_lines[i], "hostname=")) {
			tmp = &all_lines[i][STRLEN ("hostname=")];
			result = g_shell_unquote (tmp, NULL);
			break;
		}
	}
	g_strfreev (all_lines);
	g_free (contents);
	return result;
}
#endif

#if defined(HOSTNAME_PERSIST_SUSE)
static gboolean
hostname_is_dynamic (void)
{
	GIOChannel *channel;
	char *str = NULL;
	gboolean dynamic = FALSE;

	channel = g_io_channel_new_file (CONF_DHCP, "r", NULL);
	if (!channel)
		return dynamic;

	while (g_io_channel_read_line (channel, &str, NULL, NULL, NULL) != G_IO_STATUS_EOF) {
		if (str) {
			g_strstrip (str);
			if (g_str_has_prefix (str, "DHCLIENT_SET_HOSTNAME="))
				dynamic = strcmp (&str[STRLEN ("DHCLIENT_SET_HOSTNAME=")], "\"yes\"") == 0;
			g_free (str);
		}
	}

	g_io_channel_shutdown (channel, FALSE, NULL);
	g_io_channel_unref (channel);

	return dynamic;
}
#endif

/* Returns an allocated string which the caller owns and must eventually free */
char *
nm_settings_get_hostname (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	char *hostname = NULL;

	if (!priv->started)
		return NULL;

	if (priv->hostname.hostnamed_proxy) {
		hostname = g_strdup (priv->hostname.value);
		goto out;
	}

#if defined(HOSTNAME_PERSIST_GENTOO)
	hostname = read_hostname_gentoo (priv->hostname.file);
#else

#if defined(HOSTNAME_PERSIST_SUSE)
	if (priv->hostname.dhcp_monitor_id && hostname_is_dynamic ())
		return NULL;
#endif
	if (g_file_get_contents (priv->hostname.file, &hostname, NULL, NULL))
		g_strchomp (hostname);

#endif /* HOSTNAME_PERSIST_GENTOO */

out:
	if (hostname && !hostname[0]) {
		g_free (hostname);
		hostname = NULL;
	}

	return hostname;
}

static gboolean
find_spec (GSList *spec_list, const char *spec)
{
	GSList *iter;

	for (iter = spec_list; iter; iter = g_slist_next (iter)) {
		if (!strcmp ((const char *) iter->data, spec))
			return TRUE;
	}
	return FALSE;
}

static void
update_specs (NMSettings *self, GSList **specs_ptr,
              GSList * (*get_specs_func) (NMSettingsPlugin *))
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	g_slist_free_full (*specs_ptr, g_free);
	*specs_ptr = NULL;

	for (iter = priv->plugins; iter; iter = g_slist_next (iter)) {
		GSList *specs, *specs_iter;

		specs = get_specs_func (NM_SETTINGS_PLUGIN (iter->data));
		for (specs_iter = specs; specs_iter; specs_iter = specs_iter->next) {
			if (!find_spec (*specs_ptr, (const char *) specs_iter->data)) {
				*specs_ptr = g_slist_prepend (*specs_ptr, specs_iter->data);
			} else
				g_free (specs_iter->data);
		}

		g_slist_free (specs);
	}
}

static void
unmanaged_specs_changed (NMSettingsPlugin *config,
                         gpointer user_data)
{
	NMSettings *self = NM_SETTINGS (user_data);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	update_specs (self, &priv->unmanaged_specs,
	              nm_settings_plugin_get_unmanaged_specs);
	g_object_notify (G_OBJECT (self), NM_SETTINGS_UNMANAGED_SPECS);
}

static void
unrecognized_specs_changed (NMSettingsPlugin *config,
                               gpointer user_data)
{
	NMSettings *self = NM_SETTINGS (user_data);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	update_specs (self, &priv->unrecognized_specs,
	              nm_settings_plugin_get_unrecognized_specs);
}

static gboolean
add_plugin (NMSettings *self, NMSettingsPlugin *plugin)
{
	NMSettingsPrivate *priv;
	char *pname = NULL;
	char *pinfo = NULL;
	const char *path;

	g_return_val_if_fail (NM_IS_SETTINGS (self), FALSE);
	g_return_val_if_fail (NM_IS_SETTINGS_PLUGIN (plugin), FALSE);

	priv = NM_SETTINGS_GET_PRIVATE (self);

	if (g_slist_find (priv->plugins, plugin)) {
		/* don't add duplicates. */
		return FALSE;
	}

	priv->plugins = g_slist_append (priv->plugins, g_object_ref (plugin));
	nm_settings_plugin_init (plugin);

	g_object_get (G_OBJECT (plugin),
	              NM_SETTINGS_PLUGIN_NAME, &pname,
	              NM_SETTINGS_PLUGIN_INFO, &pinfo,
	              NULL);

	path = g_object_get_data (G_OBJECT (plugin), PLUGIN_MODULE_PATH);

	nm_log_info (LOGD_SETTINGS, "Loaded settings plugin %s: %s%s%s%s", pname, pinfo,
	             NM_PRINT_FMT_QUOTED (path, " (", path, ")", ""));
	g_free (pname);
	g_free (pinfo);

	return TRUE;
}

static GObject *
find_plugin (GSList *list, const char *pname)
{
	GSList *iter;
	GObject *obj = NULL;

	g_return_val_if_fail (pname != NULL, NULL);

	for (iter = list; iter && !obj; iter = g_slist_next (iter)) {
		NMSettingsPlugin *plugin = NM_SETTINGS_PLUGIN (iter->data);
		char *list_pname = NULL;

		g_object_get (G_OBJECT (plugin),
		              NM_SETTINGS_PLUGIN_NAME,
		              &list_pname,
		              NULL);
		if (list_pname && !strcmp (pname, list_pname))
			obj = G_OBJECT (plugin);

		g_free (list_pname);
	}

	return obj;
}

static void
add_keyfile_plugin (NMSettings *self)
{
	gs_unref_object GObject *keyfile_plugin = NULL;

	keyfile_plugin = nm_settings_keyfile_plugin_new ();
	g_assert (keyfile_plugin);
	if (!add_plugin (self, NM_SETTINGS_PLUGIN (keyfile_plugin)))
		g_return_if_reached ();
}

static gboolean
load_plugins (NMSettings *self, const char **plugins, GError **error)
{
	GSList *list = NULL;
	const char **iter;
	gboolean keyfile_added = FALSE;
	gboolean success = TRUE;
	gboolean add_ibft = FALSE;
	gboolean has_no_ibft;
	gssize idx_no_ibft, idx_ibft;

	idx_ibft    = _nm_utils_strv_find_first ((char **) plugins, -1, "ibft");
	idx_no_ibft = _nm_utils_strv_find_first ((char **) plugins, -1, "no-ibft");
	has_no_ibft = idx_no_ibft >= 0 && idx_no_ibft > idx_ibft;
#if WITH_SETTINGS_PLUGIN_IBFT
	add_ibft = idx_no_ibft < 0 && idx_ibft < 0;
#endif

	for (iter = plugins; iter && *iter; iter++) {
		const char *pname = *iter;
		GObject *obj;

		if (!*pname || strchr (pname, '/')) {
			LOG (LOGL_WARN, "ignore invalid plugin \"%s\"", pname);
			continue;
		}

		if (!strcmp (pname, "ifcfg-suse")) {
			LOG (LOGL_WARN, "skipping deprecated plugin ifcfg-suse");
			continue;
		}

		if (!strcmp (pname, "no-ibft"))
			continue;
		if (has_no_ibft && !strcmp (pname, "ibft"))
			continue;

		/* keyfile plugin is built-in now */
		if (strcmp (pname, "keyfile") == 0) {
			if (!keyfile_added) {
				add_keyfile_plugin (self);
				keyfile_added = TRUE;
			}
			continue;
		}

		if (_nm_utils_strv_find_first ((char **) plugins,
		                               iter - plugins,
		                               pname) >= 0) {
			/* the plugin is already mentioned in the list previously.
			 * Don't load a duplicate. */
			continue;
		}

		if (find_plugin (list, pname))
			continue;

load_plugin:
		{
			GModule *plugin;
			gs_free char *full_name = NULL;
			gs_free char *path = NULL;
			GObject * (*factory_func) (void);
			struct stat st;
			int errsv;

			full_name = g_strdup_printf ("nm-settings-plugin-%s", pname);
			path = g_module_build_path (NMPLUGINDIR, full_name);

			if (stat (path, &st) != 0) {
				errsv = errno;
				LOG (LOGL_WARN, "Could not load plugin '%s' from file '%s': %s", pname, path, strerror (errsv));
				goto next;
			}
			if (!S_ISREG (st.st_mode)) {
				LOG (LOGL_WARN, "Could not load plugin '%s' from file '%s': not a file", pname, path);
				goto next;
			}
			if (st.st_uid != 0) {
				LOG (LOGL_WARN, "Could not load plugin '%s' from file '%s': file must be owned by root", pname, path);
				goto next;
			}
			if (st.st_mode & (S_IWGRP | S_IWOTH | S_ISUID)) {
				LOG (LOGL_WARN, "Could not load plugin '%s' from file '%s': invalid file permissions", pname, path);
				goto next;
			}

			plugin = g_module_open (path, G_MODULE_BIND_LOCAL);
			if (!plugin) {
				LOG (LOGL_WARN, "Could not load plugin '%s' from file '%s': %s",
				     pname, path, g_module_error ());
				goto next;
			}

			/* errors after this point are fatal, because we loaded the shared library already. */

			if (!g_module_symbol (plugin, "nm_settings_plugin_factory", (gpointer) (&factory_func))) {
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
				             "Could not find plugin '%s' factory function.",
				             pname);
				success = FALSE;
				g_module_close (plugin);
				break;
			}

			obj = (*factory_func) ();
			if (!obj || !NM_IS_SETTINGS_PLUGIN (obj)) {
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
				             "Plugin '%s' returned invalid system config object.",
				             pname);
				success = FALSE;
				g_module_close (plugin);
				break;
			}

			g_module_make_resident (plugin);
			g_object_weak_ref (obj, (GWeakNotify) g_module_close, plugin);
			g_object_set_data_full (obj, PLUGIN_MODULE_PATH, path, g_free);
			path = NULL;
			if (add_plugin (self, NM_SETTINGS_PLUGIN (obj)))
				list = g_slist_append (list, obj);
			else
				g_object_unref (obj);
		}
next:
		if (add_ibft && !strcmp (pname, "ifcfg-rh")) {
			/* The plugin ibft is not explicitly mentioned but we just enabled "ifcfg-rh".
			 * Enable "ibft" by default after "ifcfg-rh". */
			pname = "ibft";
			add_ibft = FALSE;
			goto load_plugin;
		}
	}

	/* If keyfile plugin was not among configured plugins, add it as the last one */
	if (!keyfile_added)
		add_keyfile_plugin (self);

	g_slist_free_full (list, g_object_unref);

	return success;
}

static void
connection_updated (NMSettingsConnection *connection, gpointer user_data)
{
	/* Re-emit for listeners like NMPolicy */
	g_signal_emit (NM_SETTINGS (user_data),
	               signals[CONNECTION_UPDATED],
	               0,
	               connection);
	g_signal_emit_by_name (NM_SETTINGS (user_data), NM_CP_SIGNAL_CONNECTION_UPDATED, connection);
}

static void
connection_updated_by_user (NMSettingsConnection *connection, gpointer user_data)
{
	/* Re-emit for listeners like NMPolicy */
	g_signal_emit (NM_SETTINGS (user_data),
	               signals[CONNECTION_UPDATED_BY_USER],
	               0,
	               connection);
}

static void
connection_visibility_changed (NMSettingsConnection *connection,
                               GParamSpec *pspec,
                               gpointer user_data)
{
	/* Re-emit for listeners like NMPolicy */
	g_signal_emit (NM_SETTINGS (user_data),
	               signals[CONNECTION_VISIBILITY_CHANGED],
	               0,
	               connection);
}

static void
connection_removed (NMSettingsConnection *connection, gpointer user_data)
{
	NMSettings *self = NM_SETTINGS (user_data);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	const char *cpath = nm_connection_get_path (NM_CONNECTION (connection));

	if (!g_hash_table_lookup (priv->connections, cpath))
		g_return_if_reached ();
	g_object_ref (connection);

	/* Disconnect signal handlers, as plugins might still keep references
	 * to the connection (and thus the signal handlers would still be live)
	 * even after NMSettings has dropped all its references.
	 */

	g_signal_handlers_disconnect_by_func (connection, G_CALLBACK (connection_removed), self);
	g_signal_handlers_disconnect_by_func (connection, G_CALLBACK (connection_updated), self);
	g_signal_handlers_disconnect_by_func (connection, G_CALLBACK (connection_updated_by_user), self);
	g_signal_handlers_disconnect_by_func (connection, G_CALLBACK (connection_visibility_changed), self);
	g_signal_handlers_disconnect_by_func (connection, G_CALLBACK (connection_ready_changed), self);
	g_object_unref (self);

	/* Forget about the connection internally */
	g_hash_table_remove (priv->connections, (gpointer) cpath);

	/* Notify D-Bus */
	g_signal_emit (self, signals[CONNECTION_REMOVED], 0, connection);

	/* Re-emit for listeners like NMPolicy */
	g_signal_emit_by_name (self, NM_CP_SIGNAL_CONNECTION_REMOVED, connection);
	g_object_notify (G_OBJECT (self), NM_SETTINGS_CONNECTIONS);

	check_startup_complete (self);

	g_object_unref (connection);
}

static void
secret_agent_registered (NMAgentManager *agent_mgr,
                         NMSecretAgent *agent,
                         gpointer user_data)
{
	/* Re-emit for listeners like NMPolicy */
	g_signal_emit (NM_SETTINGS (user_data),
	               signals[AGENT_REGISTERED],
	               0,
	               agent);
}

#define NM_DBUS_SERVICE_OPENCONNECT    "org.freedesktop.NetworkManager.openconnect"
#define NM_OPENCONNECT_KEY_GATEWAY "gateway"
#define NM_OPENCONNECT_KEY_COOKIE "cookie"
#define NM_OPENCONNECT_KEY_GWCERT "gwcert"
#define NM_OPENCONNECT_KEY_XMLCONFIG "xmlconfig"
#define NM_OPENCONNECT_KEY_LASTHOST "lasthost"
#define NM_OPENCONNECT_KEY_AUTOCONNECT "autoconnect"
#define NM_OPENCONNECT_KEY_CERTSIGS "certsigs"

static void
openconnect_migrate_hack (NMConnection *connection)
{
	NMSettingVpn *s_vpn;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NOT_SAVED;

	/* Huge hack.  There were some openconnect changes that needed to happen
	 * pretty late, too late to get into distros.  Migration has already
	 * happened for many people, and their secret flags are wrong.  But we
	 * don't want to requrie re-migration, so we have to fix it up here. Ugh.
	 */

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (s_vpn == NULL)
		return;

	if (g_strcmp0 (nm_setting_vpn_get_service_type (s_vpn), NM_DBUS_SERVICE_OPENCONNECT) == 0) {
		/* These are different for every login session, and should not be stored */
		nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_OPENCONNECT_KEY_GATEWAY, flags, NULL);
		nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_OPENCONNECT_KEY_COOKIE, flags, NULL);
		nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_OPENCONNECT_KEY_GWCERT, flags, NULL);

		/* These are purely internal data for the auth-dialog, and should be stored */
		flags = 0;
		nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_OPENCONNECT_KEY_XMLCONFIG, flags, NULL);
		nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_OPENCONNECT_KEY_LASTHOST, flags, NULL);
		nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_OPENCONNECT_KEY_AUTOCONNECT, flags, NULL);
		nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_OPENCONNECT_KEY_CERTSIGS, flags, NULL);
	}
}

static void
claim_connection (NMSettings *self, NMSettingsConnection *connection)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GError *error = NULL;
	GHashTableIter iter;
	gpointer data;
	const char *path;
	NMSettingsConnection *existing;

	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (connection));
	g_return_if_fail (nm_connection_get_path (NM_CONNECTION (connection)) == NULL);

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &data)) {
		/* prevent duplicates */
		if (data == connection)
			return;
	}

	if (!nm_connection_normalize (NM_CONNECTION (connection), NULL, NULL, &error)) {
		nm_log_warn (LOGD_SETTINGS, "plugin provided invalid connection: %s",
		             error->message);
		g_error_free (error);
		return;
	}

	existing = nm_settings_get_connection_by_uuid (self, nm_settings_connection_get_uuid (connection));
	if (existing) {
		/* Cannot add duplicate connections per UUID. Just return without action and
		 * log a warning.
		 *
		 * This means, that plugins must not provide duplicate connections (UUID).
		 * In fact, none of the plugins currently would do that.
		 *
		 * But globaly, over different setting plugins, there could be duplicates
		 * without the individual plugins being aware. Don't handle that at all, just
		 * error out. That should not happen unless the admin misconfigured the system
		 * to create conflicting connections. */
		nm_log_warn (LOGD_SETTINGS, "plugin provided duplicate connection with UUID %s",
		             nm_settings_connection_get_uuid (connection));
		return;
	}

	/* Read timestamp from look-aside file and put it into the connection's data */
	nm_settings_connection_read_and_fill_timestamp (connection);

	/* Read seen-bssids from look-aside file and put it into the connection's data */
	nm_settings_connection_read_and_fill_seen_bssids (connection);

	/* Ensure it's initial visibility is up-to-date */
	nm_settings_connection_recheck_visibility (connection);

	/* Evil openconnect migration hack */
	openconnect_migrate_hack (NM_CONNECTION (connection));

	g_object_ref (self);
	g_signal_connect (connection, NM_SETTINGS_CONNECTION_REMOVED,
	                  G_CALLBACK (connection_removed), self);
	g_signal_connect (connection, NM_SETTINGS_CONNECTION_UPDATED,
	                  G_CALLBACK (connection_updated), self);
	g_signal_connect (connection, NM_SETTINGS_CONNECTION_UPDATED_BY_USER,
	                  G_CALLBACK (connection_updated_by_user), self);
	g_signal_connect (connection, "notify::" NM_SETTINGS_CONNECTION_VISIBLE,
	                  G_CALLBACK (connection_visibility_changed),
	                  self);
	if (!priv->startup_complete) {
		g_signal_connect (connection, "notify::" NM_SETTINGS_CONNECTION_READY,
		                  G_CALLBACK (connection_ready_changed),
		                  self);
	}

	/* Export the connection over D-Bus */
	g_warn_if_fail (nm_connection_get_path (NM_CONNECTION (connection)) == NULL);
	path = nm_exported_object_export (NM_EXPORTED_OBJECT (connection));
	nm_connection_set_path (NM_CONNECTION (connection), path);

	g_hash_table_insert (priv->connections,
	                     (gpointer) nm_connection_get_path (NM_CONNECTION (connection)),
	                     g_object_ref (connection));

	nm_utils_log_connection_diff (NM_CONNECTION (connection), NULL, LOGL_DEBUG, LOGD_CORE, "new connection", "++ ");

	/* Only emit the individual connection-added signal after connections
	 * have been initially loaded.
	 */
	if (priv->connections_loaded) {
		/* Internal added signal */
		g_signal_emit (self, signals[CONNECTION_ADDED], 0, connection);
		g_signal_emit_by_name (self, NM_CP_SIGNAL_CONNECTION_ADDED, connection);
		g_object_notify (G_OBJECT (self), NM_SETTINGS_CONNECTIONS);

		/* Exported D-Bus signal */
		g_signal_emit (self, signals[NEW_CONNECTION], 0, connection);
	}
}

/**
 * nm_settings_add_connection:
 * @self: the #NMSettings object
 * @connection: the source connection to create a new #NMSettingsConnection from
 * @save_to_disk: %TRUE to save the connection to disk immediately, %FALSE to
 * not save to disk
 * @error: on return, a location to store any errors that may occur
 *
 * Creates a new #NMSettingsConnection for the given source @connection.  
 * The returned object is owned by @self and the caller must reference
 * the object to continue using it.
 *
 * Returns: the new #NMSettingsConnection or %NULL
 */
NMSettingsConnection *
nm_settings_add_connection (NMSettings *self,
                            NMConnection *connection,
                            gboolean save_to_disk,
                            GError **error)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GSList *iter;
	NMSettingsConnection *added = NULL;
	GHashTableIter citer;
	NMConnection *candidate = NULL;

	/* Make sure a connection with this UUID doesn't already exist */
	g_hash_table_iter_init (&citer, priv->connections);
	while (g_hash_table_iter_next (&citer, NULL, (gpointer *) &candidate)) {
		if (g_strcmp0 (nm_connection_get_uuid (connection),
		               nm_connection_get_uuid (candidate)) == 0) {
			g_set_error_literal (error,
			                     NM_SETTINGS_ERROR,
			                     NM_SETTINGS_ERROR_UUID_EXISTS,
			                     "A connection with this UUID already exists.");
			return NULL;
		}
	}

	/* 1) plugin writes the NMConnection to disk
	 * 2) plugin creates a new NMSettingsConnection subclass with the settings
	 *     from the NMConnection and returns it to the settings service
	 * 3) settings service exports the new NMSettingsConnection subclass
	 * 4) plugin notices that something on the filesystem has changed
	 * 5) plugin reads the changes and ignores them because they will
	 *     contain the same data as the connection it already knows about
	 */
	for (iter = priv->plugins; iter; iter = g_slist_next (iter)) {
		NMSettingsPlugin *plugin = NM_SETTINGS_PLUGIN (iter->data);
		GError *add_error = NULL;

		added = nm_settings_plugin_add_connection (plugin, connection, save_to_disk, &add_error);
		if (added) {
			claim_connection (self, added);
			return added;
		}
		nm_log_dbg (LOGD_SETTINGS, "Failed to add %s/'%s': %s",
		            nm_connection_get_uuid (connection),
		            nm_connection_get_id (connection),
		            add_error ? add_error->message : "(unknown)");
		g_clear_error (&add_error);
	}

	g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
	                     "No plugin supported adding this connection");
	return NULL;
}

static NMConnection *
_nm_connection_provider_add_connection (NMConnectionProvider *provider,
                                        NMConnection *connection,
                                        gboolean save_to_disk,
                                        GError **error)
{
	g_assert (NM_IS_CONNECTION_PROVIDER (provider) && NM_IS_SETTINGS (provider));
	return NM_CONNECTION (nm_settings_add_connection (NM_SETTINGS (provider), connection, save_to_disk, error));
}

static gboolean
secrets_filter_cb (NMSetting *setting,
                   const char *secret,
                   NMSettingSecretFlags flags,
                   gpointer user_data)
{
	NMSettingSecretFlags filter_flags = GPOINTER_TO_UINT (user_data);

	/* Returns TRUE to remove the secret */

	/* Can't use bitops with SECRET_FLAG_NONE so handle that specifically */
	if (   (flags == NM_SETTING_SECRET_FLAG_NONE)
	    && (filter_flags == NM_SETTING_SECRET_FLAG_NONE))
		return FALSE;

	/* Otherwise if the secret has at least one of the desired flags keep it */
	return (flags & filter_flags) ? FALSE : TRUE;
}

static void
send_agent_owned_secrets (NMSettings *self,
                          NMSettingsConnection *connection,
                          NMAuthSubject *subject)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMConnection *for_agent;

	/* Dupe the connection so we can clear out non-agent-owned secrets,
	 * as agent-owned secrets are the only ones we send back to be saved.
	 * Only send secrets to agents of the same UID that called update too.
	 */
	for_agent = nm_simple_connection_new_clone (NM_CONNECTION (connection));
	nm_connection_clear_secrets_with_flags (for_agent,
	                                        secrets_filter_cb,
	                                        GUINT_TO_POINTER (NM_SETTING_SECRET_FLAG_AGENT_OWNED));
	nm_agent_manager_save_secrets (priv->agent_mgr,
	                               nm_connection_get_path (NM_CONNECTION (for_agent)),
	                               for_agent,
	                               subject);
	g_object_unref (for_agent);
}

static void
pk_add_cb (NMAuthChain *chain,
           GError *chain_error,
           GDBusMethodInvocation *context,
           gpointer user_data)
{
	NMSettings *self = NM_SETTINGS (user_data);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMAuthCallResult result;
	GError *error = NULL;
	NMConnection *connection = NULL;
	NMSettingsConnection *added = NULL;
	NMSettingsAddCallback callback;
	gpointer callback_data;
	NMAuthSubject *subject;
	const char *perm;
	gboolean save_to_disk;

	g_assert (context);

	priv->auths = g_slist_remove (priv->auths, chain);

	perm = nm_auth_chain_get_data (chain, "perm");
	g_assert (perm);
	result = nm_auth_chain_get_result (chain, perm);

	if (chain_error) {
		error = g_error_new (NM_SETTINGS_ERROR,
		                     NM_SETTINGS_ERROR_FAILED,
		                     "Error checking authorization: %s",
		                     chain_error->message ? chain_error->message : "(unknown)");
	} else if (result != NM_AUTH_CALL_RESULT_YES) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Insufficient privileges.");
	} else {
		/* Authorized */
		connection = nm_auth_chain_get_data (chain, "connection");
		g_assert (connection);
		save_to_disk = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "save-to-disk"));
		added = nm_settings_add_connection (self, connection, save_to_disk, &error);
	}

	callback = nm_auth_chain_get_data (chain, "callback");
	callback_data = nm_auth_chain_get_data (chain, "callback-data");
	subject = nm_auth_chain_get_data (chain, "subject");

	callback (self, added, error, context, subject, callback_data);

	/* Send agent-owned secrets to the agents */
	if (!error && added && nm_settings_has_connection (self, (NMConnection *) added))
		send_agent_owned_secrets (self, added, subject);

	g_clear_error (&error);
	nm_auth_chain_unref (chain);
}

/* FIXME: remove if/when kernel supports adhoc wpa */
static gboolean
is_adhoc_wpa (NMConnection *connection)
{
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	const char *mode, *key_mgmt;

	/* The kernel doesn't support Ad-Hoc WPA connections well at this time,
	 * and turns them into open networks.  It's been this way since at least
	 * 2.6.30 or so; until that's fixed, disable WPA-protected Ad-Hoc networks.
	 */

	s_wifi = nm_connection_get_setting_wireless (connection);
	if (!s_wifi)
		return FALSE;

	mode = nm_setting_wireless_get_mode (s_wifi);
	if (g_strcmp0 (mode, NM_SETTING_WIRELESS_MODE_ADHOC) != 0)
		return FALSE;

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (!s_wsec)
		return FALSE;

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	if (g_strcmp0 (key_mgmt, "wpa-none") != 0)
		return FALSE;

	return TRUE;
}

void
nm_settings_add_connection_dbus (NMSettings *self,
                                 NMConnection *connection,
                                 gboolean save_to_disk,
                                 GDBusMethodInvocation *context,
                                 NMSettingsAddCallback callback,
                                 gpointer user_data)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	NMAuthSubject *subject = NULL;
	NMAuthChain *chain;
	GError *error = NULL, *tmp_error = NULL;
	char *error_desc = NULL;
	const char *perm;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (context != NULL);

	/* Connection must be valid, of course */
	if (!nm_connection_verify (connection, &tmp_error)) {
		error = g_error_new (NM_SETTINGS_ERROR,
		                     NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "The connection was invalid: %s",
		                     tmp_error ? tmp_error->message : "(unknown)");
		g_error_free (tmp_error);
		goto done;
	}

	/* The kernel doesn't support Ad-Hoc WPA connections well at this time,
	 * and turns them into open networks.  It's been this way since at least
	 * 2.6.30 or so; until that's fixed, disable WPA-protected Ad-Hoc networks.
	 */
	if (is_adhoc_wpa (connection)) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                             "WPA Ad-Hoc disabled due to kernel bugs");
		goto done;
	}

	/* Do any of the plugins support adding? */
	if (!get_plugin (self, NM_SETTINGS_PLUGIN_CAP_MODIFY_CONNECTIONS)) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_NOT_SUPPORTED,
		                             "None of the registered plugins support add.");
		goto done;
	}

	subject = nm_auth_subject_new_unix_process_from_context (context);
	if (!subject) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Unable to determine UID of request.");
		goto done;
	}

	/* Ensure the caller's username exists in the connection's permissions,
	 * or that the permissions is empty (ie, visible by everyone).
	 */
	if (!nm_auth_is_subject_in_acl (connection,
	                                subject,
	                                &error_desc)) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             error_desc);
		g_free (error_desc);
		goto done;
	}

	/* If the caller is the only user in the connection's permissions, then
	 * we use the 'modify.own' permission instead of 'modify.system'.  If the
	 * request affects more than just the caller, require 'modify.system'.
	 */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	if (nm_setting_connection_get_num_permissions (s_con) == 1)
		perm = NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN;
	else
		perm = NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM;

	/* Validate the user request */
	chain = nm_auth_chain_new_subject (subject, context, pk_add_cb, self);
	if (!chain) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Unable to authenticate the request.");
		goto done;
	}

	priv->auths = g_slist_append (priv->auths, chain);
	nm_auth_chain_add_call (chain, perm, TRUE);
	nm_auth_chain_set_data (chain, "perm", (gpointer) perm, NULL);
	nm_auth_chain_set_data (chain, "connection", g_object_ref (connection), g_object_unref);
	nm_auth_chain_set_data (chain, "callback", callback, NULL);
	nm_auth_chain_set_data (chain, "callback-data", user_data, NULL);
	nm_auth_chain_set_data (chain, "subject", g_object_ref (subject), g_object_unref);
	nm_auth_chain_set_data (chain, "save-to-disk", GUINT_TO_POINTER (save_to_disk), NULL);

done:
	if (error)
		callback (self, NULL, error, context, subject, user_data);

	g_clear_error (&error);
	g_clear_object (&subject);
}

static void
impl_settings_add_connection_add_cb (NMSettings *self,
                                     NMSettingsConnection *connection,
                                     GError *error,
                                     GDBusMethodInvocation *context,
                                     NMAuthSubject *subject,
                                     gpointer user_data)
{
	if (error) {
		g_dbus_method_invocation_return_gerror (context, error);
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ADD, NULL, FALSE, subject, error->message);
	} else {
		g_dbus_method_invocation_return_value (
			context,
			g_variant_new ("(o)", nm_connection_get_path (NM_CONNECTION (connection))));
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ADD, NM_CONNECTION (connection), TRUE,
		                            subject, NULL);
	}
}

static void
impl_settings_add_connection_helper (NMSettings *self,
                                     GDBusMethodInvocation *context,
                                     GVariant *settings,
                                     gboolean save_to_disk)
{
	NMConnection *connection;
	GError *error = NULL;

	connection = nm_simple_connection_new_from_dbus (settings, &error);
	if (connection) {
		nm_settings_add_connection_dbus (self,
		                                 connection,
		                                 save_to_disk,
		                                 context,
		                                 impl_settings_add_connection_add_cb,
		                                 NULL);
		g_object_unref (connection);
	} else {
		g_assert (error);
		g_dbus_method_invocation_take_error (context, error);
	}
}

static void
impl_settings_add_connection (NMSettings *self,
                              GDBusMethodInvocation *context,
                              GVariant *settings)
{
	impl_settings_add_connection_helper (self, context, settings, TRUE);
}

static void
impl_settings_add_connection_unsaved (NMSettings *self,
                                      GDBusMethodInvocation *context,
                                      GVariant *settings)
{
	impl_settings_add_connection_helper (self, context, settings, FALSE);
}

static gboolean
ensure_root (NMBusManager          *dbus_mgr,
             GDBusMethodInvocation *context)
{
	gulong caller_uid;
	GError *error = NULL;

	if (!nm_bus_manager_get_caller_info (dbus_mgr, context, NULL, &caller_uid, NULL)) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Unable to determine request UID.");
		g_dbus_method_invocation_take_error (context, error);
		return FALSE;
	}
	if (caller_uid != 0) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Permission denied");
		g_dbus_method_invocation_take_error (context, error);
		return FALSE;
	}

	return TRUE;
}

static void
impl_settings_load_connections (NMSettings *self,
                                GDBusMethodInvocation *context,
                                char **filenames)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GPtrArray *failures;
	GSList *iter;
	int i;

	if (!ensure_root (nm_bus_manager_get (), context))
		return;

	failures = g_ptr_array_new ();

	for (i = 0; filenames[i]; i++) {
		for (iter = priv->plugins; iter; iter = g_slist_next (iter)) {
			NMSettingsPlugin *plugin = NM_SETTINGS_PLUGIN (iter->data);

			if (nm_settings_plugin_load_connection (plugin, filenames[i]))
				break;
		}

		if (!iter) {
			if (!g_path_is_absolute (filenames[i]))
				nm_log_warn (LOGD_SETTINGS, "Connection filename '%s' is not an absolute path", filenames[i]);
			g_ptr_array_add (failures, (char *) filenames[i]);
		}
	}

	g_ptr_array_add (failures, NULL);
	g_dbus_method_invocation_return_value (
		context,
		g_variant_new ("(b^as)",
		               failures->len == 1,
		               failures->pdata));
	g_ptr_array_unref (failures);
}

static void
impl_settings_reload_connections (NMSettings *self,
                                  GDBusMethodInvocation *context)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	if (!ensure_root (nm_bus_manager_get (), context))
		return;

	for (iter = priv->plugins; iter; iter = g_slist_next (iter)) {
		NMSettingsPlugin *plugin = NM_SETTINGS_PLUGIN (iter->data);

		nm_settings_plugin_reload_connections (plugin);
	}

	g_dbus_method_invocation_return_value (context, g_variant_new ("(b)", TRUE));
}

static gboolean
write_hostname (NMSettingsPrivate *priv, const char *hostname)
{
	char *hostname_eol;
	gboolean ret;
	gs_free_error GError *error = NULL;
	const char *file = priv->hostname.file;
	gs_unref_variant GVariant *var = NULL;
#if HAVE_SELINUX
	security_context_t se_ctx_prev = NULL, se_ctx = NULL;
	struct stat file_stat = { .st_mode = 0 };
	mode_t st_mode = 0;
#endif

	if (priv->hostname.hostnamed_proxy) {
		var = g_dbus_proxy_call_sync (priv->hostname.hostnamed_proxy,
		                              "SetStaticHostname",
		                              g_variant_new ("(sb)", hostname, FALSE),
		                              G_DBUS_CALL_FLAGS_NONE,
		                              -1,
		                              NULL,
		                              &error);
		if (error)
			nm_log_warn (LOGD_SETTINGS, "Could not set hostname: %s", error->message);

		return !error;
	}

#if HAVE_SELINUX
	/* Get default context for hostname file and set it for fscreate */
	if (stat (file, &file_stat) == 0)
		st_mode = file_stat.st_mode;
	matchpathcon (file, st_mode, &se_ctx);
	matchpathcon_fini ();
	getfscreatecon (&se_ctx_prev);
	setfscreatecon (se_ctx);
#endif

#if defined (HOSTNAME_PERSIST_GENTOO)
	hostname_eol = g_strdup_printf ("#Generated by NetworkManager\n"
	                                "hostname=\"%s\"\n", hostname);
#else
	hostname_eol = g_strdup_printf ("%s\n", hostname);
#endif

	/* FIXME: g_file_set_contents() writes first to a temporary file
	 * and renames it atomically. We should hack g_file_set_contents()
	 * to set the SELINUX labels before renaming the file. */
	ret = g_file_set_contents (file, hostname_eol, -1, &error);

#if HAVE_SELINUX
	/* Restore previous context and cleanup */
	setfscreatecon (se_ctx_prev);
	freecon (se_ctx);
	freecon (se_ctx_prev);
#endif

	g_free (hostname_eol);

	if (!ret) {
		nm_log_warn (LOGD_SETTINGS, "Could not save hostname to %s: %s", file, error->message);
		return FALSE;
	}

	return TRUE;
}

static void
pk_hostname_cb (NMAuthChain *chain,
                GError *chain_error,
                GDBusMethodInvocation *context,
                gpointer user_data)
{
	NMSettings *self = NM_SETTINGS (user_data);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMAuthCallResult result;
	GError *error = NULL;
	const char *hostname;

	g_assert (context);

	priv->auths = g_slist_remove (priv->auths, chain);

	result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_SETTINGS_MODIFY_HOSTNAME);

	/* If our NMSettingsConnection is already gone, do nothing */
	if (chain_error) {
		error = g_error_new (NM_SETTINGS_ERROR,
		                     NM_SETTINGS_ERROR_FAILED,
		                     "Error checking authorization: %s",
		                     chain_error->message ? chain_error->message : "(unknown)");
	} else if (result != NM_AUTH_CALL_RESULT_YES) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Insufficient privileges.");
	} else {
		hostname = nm_auth_chain_get_data (chain, "hostname");

		if (!write_hostname (priv, hostname)) {
			error = g_error_new_literal (NM_SETTINGS_ERROR,
			                             NM_SETTINGS_ERROR_FAILED,
			                             "Saving the hostname failed.");
		}
	}

	if (error)
		g_dbus_method_invocation_take_error (context, error);
	else
		g_dbus_method_invocation_return_value (context, NULL);

	nm_auth_chain_unref (chain);
}

static gboolean
validate_hostname (const char *hostname)
{
	const char *p;
	gboolean dot = TRUE;

	if (!hostname || !hostname[0])
		return FALSE;

	for (p = hostname; *p; p++) {
		if (*p == '.') {
			if (dot)
				return FALSE;
			dot = TRUE;
		} else {
			if (!g_ascii_isalnum (*p) && (*p != '-') && (*p != '_'))
				return FALSE;
			dot = FALSE;
		}
	}

	if (dot)
		return FALSE;

	return (p - hostname <= HOST_NAME_MAX);
}

static void
impl_settings_save_hostname (NMSettings *self,
                             GDBusMethodInvocation *context,
                             const char *hostname)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMAuthChain *chain;
	GError *error = NULL;

	/* Minimal validation of the hostname */
	if (!validate_hostname (hostname)) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_INVALID_HOSTNAME,
		                             "The hostname was too long or contained invalid characters.");
		goto done;
	}

	chain = nm_auth_chain_new_context (context, pk_hostname_cb, self);
	if (!chain) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Unable to authenticate the request.");
		goto done;
	}

	priv->auths = g_slist_append (priv->auths, chain);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_SETTINGS_MODIFY_HOSTNAME, TRUE);
	nm_auth_chain_set_data (chain, "hostname", g_strdup (hostname), g_free);

done:
	if (error)
		g_dbus_method_invocation_take_error (context, error);
}

static void
hostname_maybe_changed (NMSettings *settings)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (settings);
	char *new_hostname;

	new_hostname = nm_settings_get_hostname (settings);

	if (   (new_hostname && !priv->hostname.value)
	    || (!new_hostname && priv->hostname.value)
	    || (priv->hostname.value && new_hostname && strcmp (priv->hostname.value, new_hostname))) {

		nm_log_info (LOGD_SETTINGS, "hostname changed from %s%s%s to %s%s%s",
		             NM_PRINT_FMT_QUOTED (priv->hostname.value, "\"", priv->hostname.value, "\"", "(none)"),
		             NM_PRINT_FMT_QUOTED (new_hostname, "\"", new_hostname, "\"", "(none)"));
		g_free (priv->hostname.value);
		priv->hostname.value = new_hostname;
		g_object_notify (G_OBJECT (settings), NM_SETTINGS_HOSTNAME);
	} else
		g_free (new_hostname);
}

static void
hostname_file_changed_cb (GFileMonitor *monitor,
                          GFile *file,
                          GFile *other_file,
                          GFileMonitorEvent event_type,
                          gpointer user_data)
{
	hostname_maybe_changed (user_data);
}

static gboolean
have_connection_for_device (NMSettings *self, NMDevice *device)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer data;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	const char *setting_hwaddr;
	const char *device_hwaddr;

	g_return_val_if_fail (NM_IS_SETTINGS (self), FALSE);

	device_hwaddr = nm_device_get_hw_address (device);

	/* Find a wired connection locked to the given MAC address, if any */
	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &data)) {
		NMConnection *connection = NM_CONNECTION (data);
		const char *ctype, *iface;

		if (!nm_device_check_connection_compatible (device, connection))
			continue;

		s_con = nm_connection_get_setting_connection (connection);

		iface = nm_setting_connection_get_interface_name (s_con);
		if (iface && strcmp (iface, nm_device_get_iface (device)) != 0)
			continue;

		ctype = nm_setting_connection_get_connection_type (s_con);
		if (   strcmp (ctype, NM_SETTING_WIRED_SETTING_NAME)
		    && strcmp (ctype, NM_SETTING_PPPOE_SETTING_NAME))
			continue;

		s_wired = nm_connection_get_setting_wired (connection);

		if (!s_wired && !strcmp (ctype, NM_SETTING_PPPOE_SETTING_NAME)) {
			/* No wired setting; therefore the PPPoE connection applies to any device */
			return TRUE;
		}

		g_assert (s_wired != NULL);

		setting_hwaddr = nm_setting_wired_get_mac_address (s_wired);
		if (setting_hwaddr) {
			/* A connection mac-locked to this device */
			if (   device_hwaddr
			    && nm_utils_hwaddr_matches (setting_hwaddr, -1, device_hwaddr, -1))
				return TRUE;
		} else {
			/* A connection that applies to any wired device */
			return TRUE;
		}
	}

	/* See if there's a known non-NetworkManager configuration for the device */
	if (nm_device_spec_match_list (device, priv->unrecognized_specs))
		return TRUE;

	return FALSE;
}

#define DEFAULT_WIRED_CONNECTION_TAG "default-wired-connection"
#define DEFAULT_WIRED_DEVICE_TAG     "default-wired-device"

static void default_wired_clear_tag (NMSettings *self,
                                     NMDevice *device,
                                     NMSettingsConnection *connection,
                                     gboolean add_to_no_auto_default);

static void
default_wired_connection_removed_cb (NMSettingsConnection *connection, NMSettings *self)
{
	NMDevice *device;

	/* When the default wired connection is removed (either deleted or saved to
	 * a new persistent connection by a plugin), write the MAC address of the
	 * wired device to the config file and don't create a new default wired
	 * connection for that device again.
	 */
	device = g_object_get_data (G_OBJECT (connection), DEFAULT_WIRED_DEVICE_TAG);
	if (device)
		default_wired_clear_tag (self, device, connection, TRUE);
}

static void
default_wired_connection_updated_by_user_cb (NMSettingsConnection *connection, NMSettings *self)
{
	NMDevice *device;

	/* The connection has been changed by the user, it should no longer be
	 * considered a default wired connection, and should no longer affect
	 * the no-auto-default configuration option.
	 */
	device = g_object_get_data (G_OBJECT (connection), DEFAULT_WIRED_DEVICE_TAG);
	if (device)
		default_wired_clear_tag (self, device, connection, FALSE);
}

static void
default_wired_clear_tag (NMSettings *self,
                         NMDevice *device,
                         NMSettingsConnection *connection,
                         gboolean add_to_no_auto_default)
{
	g_return_if_fail (NM_IS_SETTINGS (self));
	g_return_if_fail (NM_IS_DEVICE (device));
	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (device == g_object_get_data (G_OBJECT (connection), DEFAULT_WIRED_DEVICE_TAG));
	g_return_if_fail (connection == g_object_get_data (G_OBJECT (device), DEFAULT_WIRED_CONNECTION_TAG));

	g_object_set_data (G_OBJECT (connection), DEFAULT_WIRED_DEVICE_TAG, NULL);
	g_object_set_data (G_OBJECT (device), DEFAULT_WIRED_CONNECTION_TAG, NULL);

	g_signal_handlers_disconnect_by_func (connection, G_CALLBACK (default_wired_connection_removed_cb), self);
	g_signal_handlers_disconnect_by_func (connection, G_CALLBACK (default_wired_connection_updated_by_user_cb), self);

	if (add_to_no_auto_default)
		nm_config_set_no_auto_default_for_device (NM_SETTINGS_GET_PRIVATE (self)->config, device);
}

void
nm_settings_device_added (NMSettings *self, NMDevice *device)
{
	NMConnection *connection;
	NMSettingsConnection *added;
	GError *error = NULL;

	/* If the device isn't managed or it already has a default wired connection,
	 * ignore it.
	 */
	if (   !nm_device_get_managed (device)
	    || g_object_get_data (G_OBJECT (device), DEFAULT_WIRED_CONNECTION_TAG)
	    || have_connection_for_device (self, device))
		return;

	connection = nm_device_new_default_connection (device);
	if (!connection)
		return;

	/* Add the connection */
	added = nm_settings_add_connection (self, connection, FALSE, &error);
	g_object_unref (connection);

	if (!added) {
		nm_log_warn (LOGD_SETTINGS, "(%s) couldn't create default wired connection: %s",
		             nm_device_get_iface (device),
		             (error && error->message) ? error->message : "(unknown)");
		g_clear_error (&error);
		return;
	}

	g_object_set_data (G_OBJECT (added), DEFAULT_WIRED_DEVICE_TAG, device);
	g_object_set_data (G_OBJECT (device), DEFAULT_WIRED_CONNECTION_TAG, added);

	g_signal_connect (added, NM_SETTINGS_CONNECTION_UPDATED_BY_USER,
	                  G_CALLBACK (default_wired_connection_updated_by_user_cb), self);
	g_signal_connect (added, NM_SETTINGS_CONNECTION_REMOVED,
	                  G_CALLBACK (default_wired_connection_removed_cb), self);

	nm_log_info (LOGD_SETTINGS, "(%s): created default wired connection '%s'",
	             nm_device_get_iface (device),
	             nm_settings_connection_get_id (added));
}

void
nm_settings_device_removed (NMSettings *self, NMDevice *device, gboolean quitting)
{
	NMSettingsConnection *connection;

	connection = g_object_get_data (G_OBJECT (device), DEFAULT_WIRED_CONNECTION_TAG);
	if (connection) {
		default_wired_clear_tag (self, device, connection, FALSE);

		/* Don't delete the default wired connection on shutdown, so that it
		 * remains up and can be assumed if NM starts again.
		 */
		if (quitting == FALSE)
			nm_settings_connection_delete (connection, NULL, NULL);
	}
}

/***************************************************************/

/* GCompareFunc helper for sorting "best" connections.
 * The function sorts connections in ascending timestamp order.
 * That means an older connection (lower timestamp) goes before
 * a newer one.
 */
gint
nm_settings_sort_connections (gconstpointer a, gconstpointer b)
{
	NMSettingsConnection *ac = (NMSettingsConnection *) a;
	NMSettingsConnection *bc = (NMSettingsConnection *) b;
	guint64 ats = 0, bts = 0;

	if (ac == bc)
		return 0;
	if (!ac)
		return -1;
	if (!bc)
		return 1;

	/* In the future we may use connection priorities in addition to timestamps */
	nm_settings_connection_get_timestamp (ac, &ats);
	nm_settings_connection_get_timestamp (bc, &bts);

	if (ats < bts)
		return -1;
	else if (ats > bts)
		return 1;
	return 0;
}

static GSList *
get_best_connections (NMConnectionProvider *provider,
                      guint max_requested,
                      const char *ctype1,
                      const char *ctype2,
                      NMConnectionFilterFunc func,
                      gpointer func_data)
{
	NMSettings *self = NM_SETTINGS (provider);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GSList *sorted = NULL;
	GHashTableIter iter;
	NMSettingsConnection *connection;
	guint added = 0;
	guint64 oldest = 0;

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &connection)) {
		guint64 cur_ts = 0;

		if (ctype1 && !nm_connection_is_type (NM_CONNECTION (connection), ctype1))
			continue;
		if (ctype2 && !nm_connection_is_type (NM_CONNECTION (connection), ctype2))
			continue;
		if (func && !func (provider, NM_CONNECTION (connection), func_data))
			continue;

		/* Don't bother with a connection that's older than the oldest one in the list */
		if (max_requested && added >= max_requested) {
		    nm_settings_connection_get_timestamp (connection, &cur_ts);
		    if (cur_ts <= oldest)
				continue;
		}

		/* List is sorted with oldest first */
		sorted = g_slist_insert_sorted (sorted, connection, nm_settings_sort_connections);
		added++;

		if (max_requested && added > max_requested) {
			/* Over the limit, remove the oldest one */
			sorted = g_slist_delete_link (sorted, sorted);
			added--;
		}

		nm_settings_connection_get_timestamp (NM_SETTINGS_CONNECTION (sorted->data), &oldest);
	}

	return g_slist_reverse (sorted);
}

static const GSList *
get_connections (NMConnectionProvider *provider)
{
	GSList *list = NULL;
	NMSettings *self = NM_SETTINGS (provider);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	list = _nm_utils_hash_values_to_slist (priv->connections);

	/* Cache the list every call so we can keep it 'const' for callers */
	g_slist_free (priv->get_connections_cache);
	priv->get_connections_cache = list;
	return list;
}

static NMConnection *
cp_get_connection_by_uuid (NMConnectionProvider *provider, const char *uuid)
{
	return NM_CONNECTION (nm_settings_get_connection_by_uuid (NM_SETTINGS (provider), uuid));
}

/***************************************************************/

gboolean
nm_settings_get_startup_complete (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	return priv->startup_complete;
}

/***************************************************************/

static void
hostnamed_properties_changed (GDBusProxy *proxy,
                              GVariant *changed_properties,
                              char **invalidated_properties,
                              gpointer user_data)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (user_data);
	GVariant *v_hostname;
	const char *hostname;

	v_hostname = g_dbus_proxy_get_cached_property (priv->hostname.hostnamed_proxy,
	                                               "StaticHostname");
	if (!v_hostname)
		return;

	hostname = g_variant_get_string (v_hostname, NULL);

	if (g_strcmp0 (priv->hostname.value, hostname) != 0) {
		nm_log_info (LOGD_SETTINGS, "hostname changed from %s%s%s to %s%s%s",
		             NM_PRINT_FMT_QUOTED (priv->hostname.value, "\"", priv->hostname.value, "\"", "(none)"),
		             NM_PRINT_FMT_QUOTED (hostname, "\"", hostname, "\"", "(none)"));
		g_free (priv->hostname.value);
		priv->hostname.value = g_strdup (hostname);
		g_object_notify (G_OBJECT (user_data), NM_SETTINGS_HOSTNAME);
		nm_dispatcher_call (DISPATCHER_ACTION_HOSTNAME, NULL, NULL, NULL, NULL, NULL);
	}

	g_variant_unref (v_hostname);
}

static void
setup_hostname_file_monitors (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GFileMonitor *monitor;
	GFile *file;

	priv->hostname.file = HOSTNAME_FILE;
	priv->hostname.value = nm_settings_get_hostname (self);

	/* monitor changes to hostname file */
	file = g_file_new_for_path (priv->hostname.file);
	monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);
	if (monitor) {
		priv->hostname.monitor_id = g_signal_connect (monitor, "changed",
		                                              G_CALLBACK (hostname_file_changed_cb),
		                                              self);
		priv->hostname.monitor = monitor;
	}

#if defined (HOSTNAME_PERSIST_SUSE)
	/* monitor changes to dhcp file to know whether the hostname is valid */
	file = g_file_new_for_path (CONF_DHCP);
	monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);
	if (monitor) {
		priv->hostname.dhcp_monitor_id = g_signal_connect (monitor, "changed",
		                                                   G_CALLBACK (hostname_file_changed_cb),
		                                                   self);
		priv->hostname.dhcp_monitor = monitor;
	}
#endif

	hostname_maybe_changed (self);
}

NMSettings *
nm_settings_new (void)
{
	NMSettings *self;
	NMSettingsPrivate *priv;

	self = g_object_new (NM_TYPE_SETTINGS, NULL);

	priv = NM_SETTINGS_GET_PRIVATE (self);

	priv->config = nm_config_get ();

	nm_exported_object_export (NM_EXPORTED_OBJECT (self));
	return self;
}

gboolean
nm_settings_start (NMSettings *self, GError **error)
{
	NMSettingsPrivate *priv;
	GDBusProxy *proxy;
	GVariant *variant;
	GError *local_error = NULL;

	priv = NM_SETTINGS_GET_PRIVATE (self);

	/* Load the plugins; fail if a plugin is not found. */
	if (!load_plugins (self, nm_config_get_plugins (priv->config), error)) {
		g_object_unref (self);
		return FALSE;
	}

	load_connections (self);
	check_startup_complete (self);

	proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM, 0, NULL,
	                                       HOSTNAMED_SERVICE_NAME, HOSTNAMED_SERVICE_PATH,
	                                       HOSTNAMED_SERVICE_INTERFACE, NULL, &local_error);
	if (proxy) {
		variant = g_dbus_proxy_get_cached_property (proxy, "StaticHostname");
		if (variant) {
			nm_log_info (LOGD_SETTINGS, "hostname: using hostnamed");
			priv->hostname.hostnamed_proxy = proxy;
			g_signal_connect (proxy, "g-properties-changed",
			                  G_CALLBACK (hostnamed_properties_changed), self);
			hostnamed_properties_changed (proxy, NULL, NULL, self);
			g_variant_unref (variant);
		} else {
			nm_log_info (LOGD_SETTINGS, "hostname: couldn't get property from hostnamed");
			g_object_unref (proxy);
		}
	} else {
		nm_log_info (LOGD_SETTINGS, "hostname: hostnamed not used as proxy creation failed with: %s",
		             local_error->message);
		g_clear_error (&local_error);
	}

	if (!priv->hostname.hostnamed_proxy)
		setup_hostname_file_monitors (self);

	priv->started = TRUE;
	g_object_notify (G_OBJECT (self), NM_SETTINGS_HOSTNAME);
	return TRUE;
}

static void
connection_provider_iface_init (NMConnectionProviderInterface *cp_iface)
{
    cp_iface->get_best_connections = get_best_connections;
    cp_iface->get_connections = get_connections;
    cp_iface->add_connection = _nm_connection_provider_add_connection;
    cp_iface->get_connection_by_uuid = cp_get_connection_by_uuid;
}

static void
nm_settings_init (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	priv->connections = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);

	/* Hold a reference to the agent manager so it stays alive; the only
	 * other holders are NMSettingsConnection objects which are often
	 * transient, and we don't want the agent manager to get destroyed and
	 * recreated often.
	 */
	priv->agent_mgr = g_object_ref (nm_agent_manager_get ());

	g_signal_connect (priv->agent_mgr, "agent-registered", G_CALLBACK (secret_agent_registered), self);
}

static void
dispose (GObject *object)
{
	NMSettings *self = NM_SETTINGS (object);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	g_slist_free_full (priv->auths, (GDestroyNotify) nm_auth_chain_unref);
	priv->auths = NULL;

	g_object_unref (priv->agent_mgr);

	if (priv->hostname.hostnamed_proxy) {
		g_signal_handlers_disconnect_by_func (priv->hostname.hostnamed_proxy,
		                                      G_CALLBACK (hostnamed_properties_changed),
		                                      self);
		g_clear_object (&priv->hostname.hostnamed_proxy);
	}

	if (priv->hostname.monitor) {
		if (priv->hostname.monitor_id)
			g_signal_handler_disconnect (priv->hostname.monitor, priv->hostname.monitor_id);

		g_file_monitor_cancel (priv->hostname.monitor);
		g_clear_object (&priv->hostname.monitor);
	}

	if (priv->hostname.dhcp_monitor) {
		if (priv->hostname.dhcp_monitor_id)
			g_signal_handler_disconnect (priv->hostname.dhcp_monitor,
			                             priv->hostname.dhcp_monitor_id);

		g_file_monitor_cancel (priv->hostname.dhcp_monitor);
		g_clear_object (&priv->hostname.dhcp_monitor);
	}

	g_clear_pointer (&priv->hostname.value, g_free);

	G_OBJECT_CLASS (nm_settings_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMSettings *self = NM_SETTINGS (object);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	g_hash_table_destroy (priv->connections);
	g_slist_free (priv->get_connections_cache);

	g_slist_free_full (priv->unmanaged_specs, g_free);
	g_slist_free_full (priv->unrecognized_specs, g_free);

	g_slist_free_full (priv->plugins, g_object_unref);

	G_OBJECT_CLASS (nm_settings_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMSettings *self = NM_SETTINGS (object);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	const GSList *specs, *iter;
	GHashTableIter citer;
	GPtrArray *array;
	const char *path;

	switch (prop_id) {
	case PROP_UNMANAGED_SPECS:
		array = g_ptr_array_new ();
		specs = nm_settings_get_unmanaged_specs (self);
		for (iter = specs; iter; iter = g_slist_next (iter))
			g_ptr_array_add (array, g_strdup (iter->data));
		g_ptr_array_add (array, NULL);
		g_value_take_boxed (value, (char **) g_ptr_array_free (array, FALSE));
		break;
	case PROP_HOSTNAME:
		g_value_take_string (value, nm_settings_get_hostname (self));

		/* Don't ever pass NULL through D-Bus */
		if (!g_value_get_string (value))
			g_value_set_static_string (value, "");
		break;
	case PROP_CAN_MODIFY:
		g_value_set_boolean (value, !!get_plugin (self, NM_SETTINGS_PLUGIN_CAP_MODIFY_CONNECTIONS));
		break;
	case PROP_CONNECTIONS:
		array = g_ptr_array_sized_new (g_hash_table_size (priv->connections) + 1);
		g_hash_table_iter_init (&citer, priv->connections);
		while (g_hash_table_iter_next (&citer, (gpointer) &path, NULL))
			g_ptr_array_add (array, g_strdup (path));
		g_ptr_array_add (array, NULL);
		g_value_take_boxed (value, (char **) g_ptr_array_free (array, FALSE));
		break;
	case PROP_STARTUP_COMPLETE:
		g_value_set_boolean (value, nm_settings_get_startup_complete (self));
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
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (class);

	g_type_class_add_private (class, sizeof (NMSettingsPrivate));

	exported_object_class->export_path = NM_DBUS_PATH_SETTINGS;

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* properties */

	g_object_class_install_property
		(object_class, PROP_UNMANAGED_SPECS,
		 g_param_spec_boxed (NM_SETTINGS_UNMANAGED_SPECS, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_HOSTNAME,
		 g_param_spec_string (NM_SETTINGS_HOSTNAME, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_CAN_MODIFY,
		 g_param_spec_boolean (NM_SETTINGS_CAN_MODIFY, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_CONNECTIONS,
		 g_param_spec_boxed (NM_SETTINGS_CONNECTIONS, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/* signals */
	signals[CONNECTION_ADDED] = 
	                g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_ADDED,
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST,
	                              G_STRUCT_OFFSET (NMSettingsClass, connection_added),
	                              NULL, NULL,
	                              g_cclosure_marshal_VOID__OBJECT,
	                              G_TYPE_NONE, 1, NM_TYPE_SETTINGS_CONNECTION);

	signals[CONNECTION_UPDATED] = 
	                g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_UPDATED,
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST,
	                              G_STRUCT_OFFSET (NMSettingsClass, connection_updated),
	                              NULL, NULL,
	                              g_cclosure_marshal_VOID__OBJECT,
	                              G_TYPE_NONE, 1, NM_TYPE_SETTINGS_CONNECTION);

	signals[CONNECTION_UPDATED_BY_USER] =
	                g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_UPDATED_BY_USER,
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST,
	                              0,
	                              NULL, NULL,
	                              g_cclosure_marshal_VOID__OBJECT,
	                              G_TYPE_NONE, 1, NM_TYPE_SETTINGS_CONNECTION);

	signals[CONNECTION_REMOVED] = 
	                g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_REMOVED,
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST,
	                              G_STRUCT_OFFSET (NMSettingsClass, connection_removed),
	                              NULL, NULL,
	                              g_cclosure_marshal_VOID__OBJECT,
	                              G_TYPE_NONE, 1, NM_TYPE_SETTINGS_CONNECTION);

	signals[CONNECTION_VISIBILITY_CHANGED] = 
	                g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_VISIBILITY_CHANGED,
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST,
	                              G_STRUCT_OFFSET (NMSettingsClass, connection_visibility_changed),
	                              NULL, NULL,
	                              g_cclosure_marshal_VOID__OBJECT,
	                              G_TYPE_NONE, 1, NM_TYPE_SETTINGS_CONNECTION);

	signals[AGENT_REGISTERED] =
		g_signal_new (NM_SETTINGS_SIGNAL_AGENT_REGISTERED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMSettingsClass, agent_registered),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE, 1, NM_TYPE_SECRET_AGENT);


	signals[NEW_CONNECTION] = 
	                g_signal_new ("new-connection",
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST, 0, NULL, NULL,
	                              g_cclosure_marshal_VOID__OBJECT,
	                              G_TYPE_NONE, 1, NM_TYPE_SETTINGS_CONNECTION);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (class),
	                                        NMDBUS_TYPE_SETTINGS_SKELETON,
	                                        "ListConnections", impl_settings_list_connections,
	                                        "GetConnectionByUuid", impl_settings_get_connection_by_uuid,
	                                        "AddConnection", impl_settings_add_connection,
	                                        "AddConnectionUnsaved", impl_settings_add_connection_unsaved,
	                                        "LoadConnections", impl_settings_load_connections,
	                                        "ReloadConnections", impl_settings_reload_connections,
	                                        "SaveHostname", impl_settings_save_hostname,
	                                        NULL);
}

