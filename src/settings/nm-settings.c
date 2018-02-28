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

#include "nm-default.h"

#include "nm-settings.h"

#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <gmodule.h>
#include <pwd.h>

#if HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "nm-common-macros.h"
#include "nm-dbus-interface.h"
#include "nm-connection.h"
#include "nm-setting-8021x.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-cdma.h"
#include "nm-setting-connection.h"
#include "nm-setting-gsm.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-olpc-mesh.h"
#include "nm-setting-ppp.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-serial.h"
#include "nm-setting-vpn.h"
#include "nm-setting-wired.h"
#include "nm-setting-adsl.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-proxy.h"
#include "nm-setting-bond.h"
#include "nm-utils.h"
#include "nm-core-internal.h"

#include "devices/nm-device-ethernet.h"
#include "nm-settings-connection.h"
#include "nm-settings-plugin.h"
#include "nm-bus-manager.h"
#include "nm-auth-utils.h"
#include "nm-auth-subject.h"
#include "nm-session-monitor.h"
#include "plugins/keyfile/nms-keyfile-plugin.h"
#include "nm-agent-manager.h"
#include "nm-config.h"
#include "nm-audit-manager.h"
#include "NetworkManagerUtils.h"
#include "nm-dispatcher.h"
#include "nm-hostname-manager.h"

#include "introspection/org.freedesktop.NetworkManager.Settings.h"

/*****************************************************************************/

#define EXPORT(sym) void * __export_##sym = &sym;

EXPORT(nm_settings_connection_get_type)
EXPORT(nm_settings_connection_update)

/*****************************************************************************/

static NM_CACHED_QUARK_FCN ("plugin-module-path", plugin_module_path_quark)
static NM_CACHED_QUARK_FCN ("default-wired-connection", _default_wired_connection_quark)
static NM_CACHED_QUARK_FCN ("default-wired-device", _default_wired_device_quark)

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMSettings,
	PROP_UNMANAGED_SPECS,
	PROP_HOSTNAME,
	PROP_CAN_MODIFY,
	PROP_CONNECTIONS,
	PROP_STARTUP_COMPLETE,
);

enum {
	CONNECTION_ADDED,
	CONNECTION_UPDATED,
	CONNECTION_REMOVED,
	CONNECTION_FLAGS_CHANGED,
	NEW_CONNECTION, /* exported, not used internally */
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	NMAgentManager *agent_mgr;

	NMConfig *config;

	GSList *auths;

	GSList *plugins;
	gboolean connections_loaded;
	GHashTable *connections;
	NMSettingsConnection **connections_cached_list;
	GSList *unmanaged_specs;
	GSList *unrecognized_specs;

	gboolean started;
	gboolean startup_complete;

	NMHostnameManager *hostname_manager;

} NMSettingsPrivate;

struct _NMSettings {
	NMExportedObject parent;
	NMSettingsPrivate _priv;
};

struct _NMSettingsClass {
	NMExportedObjectClass parent;
};

G_DEFINE_TYPE (NMSettings, nm_settings, NM_TYPE_EXPORTED_OBJECT);

#define NM_SETTINGS_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMSettings, NM_IS_SETTINGS)

/*****************************************************************************/

#define _NMLOG_DOMAIN         LOGD_SETTINGS
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "settings", __VA_ARGS__)

/*****************************************************************************/

static void claim_connection (NMSettings *self,
                              NMSettingsConnection *connection);

static void unmanaged_specs_changed (NMSettingsPlugin *config, gpointer user_data);
static void unrecognized_specs_changed (NMSettingsPlugin *config, gpointer user_data);

static void connection_ready_changed (NMSettingsConnection *conn,
                                      GParamSpec *pspec,
                                      gpointer user_data);

/*****************************************************************************/

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

	/* the connection_ready_changed signal handler is no longer needed. */
	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &conn))
		g_signal_handlers_disconnect_by_func (conn, G_CALLBACK (connection_ready_changed), self);

	priv->startup_complete = TRUE;
	_notify (self, PROP_STARTUP_COMPLETE);
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
	_notify (self, PROP_CONNECTIONS);

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

/**
 * nm_settings_get_connections:
 * @self: the #NMSettings
 * @out_len: (out): (allow-none): returns the number of returned
 *   connections.
 *
 * Returns: (transfer-none): a list of NMSettingsConnections. The list is
 * unsorted and NULL terminated. The result is never %NULL, in case of no
 * connections, it returns an empty list.
 * The returned list is cached internally, only valid until the next
 * NMSettings operation.
 */
NMSettingsConnection *const*
nm_settings_get_connections (NMSettings *self, guint *out_len)
{
	GHashTableIter iter;
	NMSettingsPrivate *priv;
	guint l, i;
	NMSettingsConnection **v;
	NMSettingsConnection *con;

	g_return_val_if_fail (NM_IS_SETTINGS (self), NULL);

	priv = NM_SETTINGS_GET_PRIVATE (self);

	if (G_LIKELY (priv->connections_cached_list)) {
		NM_SET_OUT (out_len, g_hash_table_size (priv->connections));
		return priv->connections_cached_list;
	}

	l = g_hash_table_size (priv->connections);

	v = g_new (NMSettingsConnection *, (gsize) l + 1);

	i = 0;
	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &con)) {
		nm_assert (i < l);
		v[i++] = con;
	}
	nm_assert (i == l);
	v[i] = NULL;

	NM_SET_OUT (out_len, l);
	priv->connections_cached_list = v;
	return v;
}

/**
 * nm_settings_get_connections_clone:
 * @self: the #NMSetting
 * @out_len: (allow-none): optional output argument
 * @func: caller-supplied function for filtering connections
 * @func_data: caller-supplied data passed to @func
 * @sort_compare_func: (allow-none): optional function pointer for
 *   sorting the returned list.
 * @sort_data: user data for @sort_compare_func.
 *
 * Returns: (transfer container) (element-type NMSettingsConnection):
 *   an NULL terminated array of #NMSettingsConnection objects that were
 *   filtered by @func (or all connections if no filter was specified).
 *   The order is arbitrary.
 *   Caller is responsible for freeing the returned array with free(),
 *   the contained values do not need to be unrefed.
 */
NMSettingsConnection **
nm_settings_get_connections_clone (NMSettings *self,
                                   guint *out_len,
                                   NMSettingsConnectionFilterFunc func,
                                   gpointer func_data,
                                   GCompareDataFunc sort_compare_func,
                                   gpointer sort_data)
{
	NMSettingsConnection *const*list_cached;
	NMSettingsConnection **list;
	guint len, i, j;

	g_return_val_if_fail (NM_IS_SETTINGS (self), NULL);

	list_cached = nm_settings_get_connections (self, &len);

#if NM_MORE_ASSERTS
	nm_assert (list_cached);
	for (i = 0; i < len; i++)
		nm_assert (NM_IS_SETTINGS_CONNECTION (list_cached[i]));
	nm_assert (!list_cached[i]);
#endif

	list = g_new (NMSettingsConnection *, ((gsize) len + 1));
	if (func) {
		for (i = 0, j = 0; i < len; i++) {
			if (func (self, list_cached[i], func_data))
				list[j++] = list_cached[i];
		}
		list[j] = NULL;
		len = j;
	} else
		memcpy (list, list_cached, sizeof (list[0]) * ((gsize) len + 1));

	if (   len > 1
	    && sort_compare_func) {
		g_qsort_with_data (list, len, sizeof (NMSettingsConnection *),
		                   sort_compare_func, sort_data);
	}
	NM_SET_OUT (out_len, len);
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
nm_settings_has_connection (NMSettings *self, NMSettingsConnection *connection)
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
	_notify (self, PROP_UNMANAGED_SPECS);
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

	path = g_object_get_qdata (G_OBJECT (plugin), plugin_module_path_quark ());

	_LOGI ("loaded plugin %s: %s%s%s%s", pname, pinfo,
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
	gs_unref_object NMSKeyfilePlugin *keyfile_plugin = NULL;

	keyfile_plugin = nms_keyfile_plugin_new ();
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

	idx_ibft    = nm_utils_strv_find_first ((char **) plugins, -1, "ibft");
	idx_no_ibft = nm_utils_strv_find_first ((char **) plugins, -1, "no-ibft");
	has_no_ibft = idx_no_ibft >= 0 && idx_no_ibft > idx_ibft;
#if WITH_SETTINGS_PLUGIN_IBFT
	add_ibft = idx_no_ibft < 0 && idx_ibft < 0;
#endif

	for (iter = plugins; iter && *iter; iter++) {
		const char *pname = *iter;
		GObject *obj;

		if (!*pname || strchr (pname, '/')) {
			_LOGW ("ignore invalid plugin \"%s\"", pname);
			continue;
		}

		if (!strcmp (pname, "ifcfg-suse")) {
			_LOGW ("skipping deprecated plugin ifcfg-suse");
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

		if (nm_utils_strv_find_first ((char **) plugins,
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
				_LOGW ("could not load plugin '%s' from file '%s': %s", pname, path, strerror (errsv));
				goto next;
			}
			if (!S_ISREG (st.st_mode)) {
				_LOGW ("could not load plugin '%s' from file '%s': not a file", pname, path);
				goto next;
			}
			if (st.st_uid != 0) {
				_LOGW ("could not load plugin '%s' from file '%s': file must be owned by root", pname, path);
				goto next;
			}
			if (st.st_mode & (S_IWGRP | S_IWOTH | S_ISUID)) {
				_LOGW ("could not load plugin '%s' from file '%s': invalid file permissions", pname, path);
				goto next;
			}

			plugin = g_module_open (path, G_MODULE_BIND_LOCAL);
			if (!plugin) {
				_LOGW ("could not load plugin '%s' from file '%s': %s",
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

			/* after accessing the plugin we cannot unload it anymore, because the glib
			 * types cannot be properly unregistered. */
			g_module_make_resident (plugin);

			obj = (*factory_func) ();
			if (!obj || !NM_IS_SETTINGS_PLUGIN (obj)) {
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
				             "Plugin '%s' returned invalid system config object.",
				             pname);
				success = FALSE;
				break;
			}

			g_object_set_qdata_full (obj, plugin_module_path_quark (), path, g_free);
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
connection_updated (NMSettingsConnection *connection, gboolean by_user, gpointer user_data)
{
	g_signal_emit (NM_SETTINGS (user_data),
	               signals[CONNECTION_UPDATED],
	               0,
	               connection,
	               by_user);
}

static void
connection_flags_changed (NMSettingsConnection *connection,
                          GParamSpec *pspec,
                          gpointer user_data)
{
	g_signal_emit (NM_SETTINGS (user_data),
	               signals[CONNECTION_FLAGS_CHANGED],
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
	g_signal_handlers_disconnect_by_func (connection, G_CALLBACK (connection_flags_changed), self);
	if (!priv->startup_complete)
		g_signal_handlers_disconnect_by_func (connection, G_CALLBACK (connection_ready_changed), self);
	g_object_unref (self);

	/* Forget about the connection internally */
	g_hash_table_remove (priv->connections, (gpointer) cpath);
	g_clear_pointer (&priv->connections_cached_list, g_free);

	/* Notify D-Bus */
	g_signal_emit (self, signals[CONNECTION_REMOVED], 0, connection);

	/* Re-emit for listeners like NMPolicy */
	_notify (self, PROP_CONNECTIONS);
	if (nm_exported_object_is_exported (NM_EXPORTED_OBJECT (connection)))
		nm_exported_object_unexport (NM_EXPORTED_OBJECT (connection));

	check_startup_complete (self);

	g_object_unref (connection);
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
		_LOGW ("plugin provided invalid connection: %s", error->message);
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
		_LOGW ("plugin provided duplicate connection with UUID %s",
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
	/* This one unexports the connection, it needs to run late to give the active
	 * connection a chance to deal with its reference to this settings connection. */
	g_signal_connect_after (connection, NM_SETTINGS_CONNECTION_REMOVED,
	                        G_CALLBACK (connection_removed), self);
	g_signal_connect (connection, NM_SETTINGS_CONNECTION_UPDATED_INTERNAL,
	                  G_CALLBACK (connection_updated), self);
	g_signal_connect (connection, "notify::" NM_SETTINGS_CONNECTION_FLAGS,
	                  G_CALLBACK (connection_flags_changed),
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
	g_clear_pointer (&priv->connections_cached_list, g_free);

	nm_utils_log_connection_diff (NM_CONNECTION (connection), NULL, LOGL_DEBUG, LOGD_CORE, "new connection", "++ ");

	/* Only emit the individual connection-added signal after connections
	 * have been initially loaded.
	 */
	if (priv->connections_loaded) {
		/* Internal added signal */
		g_signal_emit (self, signals[CONNECTION_ADDED], 0, connection);
		_notify (self, PROP_CONNECTIONS);

		/* Exported D-Bus signal */
		g_signal_emit (self, signals[NEW_CONNECTION], 0, connection);
	}

	nm_settings_connection_added (connection);
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
		gs_unref_object NMConnection *simple = NULL;
		gs_unref_variant GVariant *secrets = NULL;

		/* Make a copy of agent-owned secrets because they won't be present in
		 * the connection returned by plugins, as plugins return only what was
		 * reread from the file. */
		simple = nm_simple_connection_new_clone (connection);
		nm_connection_clear_secrets_with_flags (simple,
		                                        secrets_filter_cb,
		                                        GUINT_TO_POINTER (NM_SETTING_SECRET_FLAG_AGENT_OWNED));
		secrets = nm_connection_to_dbus (simple, NM_CONNECTION_SERIALIZE_ONLY_SECRETS);

		added = nm_settings_plugin_add_connection (plugin, connection, save_to_disk, &add_error);
		if (added) {
			if (secrets)
				nm_connection_update_secrets (NM_CONNECTION (added), NULL, secrets, NULL);
			claim_connection (self, added);
			return added;
		}
		_LOGD ("Failed to add %s/'%s': %s",
		       nm_connection_get_uuid (connection),
		       nm_connection_get_id (connection),
		       add_error->message);
		g_clear_error (&add_error);
	}

	g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
	                     "No plugin supported adding this connection");
	return NULL;
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
	                               nm_connection_get_path (NM_CONNECTION (connection)),
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
		                     chain_error->message);
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
	if (!error && added && nm_settings_has_connection (self, added))
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
		                     tmp_error->message);
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
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ADD, NULL, FALSE, NULL, subject, error->message);
	} else {
		g_dbus_method_invocation_return_value (
		    context,
		    g_variant_new ("(o)", nm_connection_get_path (NM_CONNECTION (connection))));
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ADD, connection, TRUE, NULL,
		                            subject, NULL);
	}
}

static void
impl_settings_add_connection_helper (NMSettings *self,
                                     GDBusMethodInvocation *context,
                                     GVariant *settings,
                                     gboolean save_to_disk)
{
	gs_unref_object NMConnection *connection = NULL;
	GError *error = NULL;

	connection = _nm_simple_connection_new_from_dbus (settings,
	                                                    NM_SETTING_PARSE_FLAGS_STRICT
	                                                  | NM_SETTING_PARSE_FLAGS_NORMALIZE,
	                                                  &error);

	if (   !connection
	    || !nm_connection_verify_secrets (connection, &error)) {
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	nm_settings_add_connection_dbus (self,
	                                 connection,
	                                 save_to_disk,
	                                 context,
	                                 impl_settings_add_connection_add_cb,
	                                 NULL);
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

static void
impl_settings_load_connections (NMSettings *self,
                                GDBusMethodInvocation *context,
                                char **filenames)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GPtrArray *failures;
	GSList *iter;
	int i;

	/* The permission is already enforced by the D-Bus daemon, but we ensure
	 * that the caller is still alive so that clients are forced to wait and
	 * we'll be able to switch to polkit without breaking behavior.
	 */
	if (!nm_bus_manager_ensure_uid (nm_bus_manager_get (),
	                                context,
	                                G_MAXULONG,
	                                NM_SETTINGS_ERROR,
	                                NM_SETTINGS_ERROR_PERMISSION_DENIED))
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
				_LOGW ("connection filename '%s' is not an absolute path", filenames[i]);
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

	/* The permission is already enforced by the D-Bus daemon, but we ensure
	 * that the caller is still alive so that clients are forced to wait and
	 * we'll be able to switch to polkit without breaking behavior.
	 */
	if (!nm_bus_manager_ensure_uid (nm_bus_manager_get (),
	                                context,
	                                G_MAXULONG,
	                                NM_SETTINGS_ERROR,
	                                NM_SETTINGS_ERROR_PERMISSION_DENIED))
		return;

	for (iter = priv->plugins; iter; iter = g_slist_next (iter)) {
		NMSettingsPlugin *plugin = NM_SETTINGS_PLUGIN (iter->data);

		nm_settings_plugin_reload_connections (plugin);
	}

	g_dbus_method_invocation_return_value (context, g_variant_new ("(b)", TRUE));
}

/*****************************************************************************/

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
		                     chain_error->message);
	} else if (result != NM_AUTH_CALL_RESULT_YES) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Insufficient privileges.");
	} else {
		hostname = nm_auth_chain_get_data (chain, "hostname");

		if (!nm_hostname_manager_write_hostname (priv->hostname_manager, hostname)) {
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

static void
impl_settings_save_hostname (NMSettings *self,
                             GDBusMethodInvocation *context,
                             const char *hostname)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMAuthChain *chain;
	GError *error = NULL;

	/* Minimal validation of the hostname */
	if (!nm_hostname_manager_validate_hostname (hostname)) {
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

/*****************************************************************************/

static gboolean
have_connection_for_device (NMSettings *self, NMDevice *device)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer data;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	const char *setting_hwaddr;
	const char *perm_hw_addr;

	g_return_val_if_fail (NM_IS_SETTINGS (self), FALSE);

	perm_hw_addr = nm_device_get_permanent_hw_address (device);

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
			if (   perm_hw_addr
			    && nm_utils_hwaddr_matches (setting_hwaddr, -1, perm_hw_addr, -1))
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
	device = g_object_get_qdata (G_OBJECT (connection), _default_wired_device_quark ());
	if (device)
		default_wired_clear_tag (self, device, connection, TRUE);
}

static void
default_wired_connection_updated_by_user_cb (NMSettingsConnection *connection, gboolean by_user, NMSettings *self)
{
	NMDevice *device;

	if (!by_user)
		return;

	/* The connection has been changed by the user, it should no longer be
	 * considered a default wired connection, and should no longer affect
	 * the no-auto-default configuration option.
	 */
	device = g_object_get_qdata (G_OBJECT (connection), _default_wired_device_quark ());
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
	g_return_if_fail (device == g_object_get_qdata (G_OBJECT (connection), _default_wired_device_quark ()));
	g_return_if_fail (connection == g_object_get_qdata (G_OBJECT (device), _default_wired_connection_quark ()));

	g_object_set_qdata (G_OBJECT (connection), _default_wired_device_quark (), NULL);
	g_object_set_qdata (G_OBJECT (device), _default_wired_connection_quark (), NULL);

	g_signal_handlers_disconnect_by_func (connection, G_CALLBACK (default_wired_connection_removed_cb), self);
	g_signal_handlers_disconnect_by_func (connection, G_CALLBACK (default_wired_connection_updated_by_user_cb), self);

	if (add_to_no_auto_default)
		nm_config_set_no_auto_default_for_device (NM_SETTINGS_GET_PRIVATE (self)->config, device);
}

static void
device_realized (NMDevice *device, GParamSpec *pspec, NMSettings *self)
{
	NMConnection *connection;
	NMSettingsConnection *added;
	GError *error = NULL;

	if (!nm_device_is_real (device))
		return;

	g_signal_handlers_disconnect_by_func (device,
	                                      G_CALLBACK (device_realized),
	                                      self);

	/* If the device isn't managed or it already has a default wired connection,
	 * ignore it.
	 */
	if (   !nm_device_get_managed (device, FALSE)
	    || g_object_get_qdata (G_OBJECT (device), _default_wired_connection_quark ())
	    || have_connection_for_device (self, device))
		return;

	connection = nm_device_new_default_connection (device);
	if (!connection)
		return;

	/* Add the connection */
	added = nm_settings_add_connection (self, connection, FALSE, &error);
	g_object_unref (connection);

	if (!added) {
		if (!g_error_matches (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_UUID_EXISTS)) {
			_LOGW ("(%s) couldn't create default wired connection: %s",
			       nm_device_get_iface (device),
			       error->message);
		}
		g_clear_error (&error);
		return;
	}

	g_object_set_qdata (G_OBJECT (added), _default_wired_device_quark (), device);
	g_object_set_qdata (G_OBJECT (device), _default_wired_connection_quark (), added);

	g_signal_connect (added, NM_SETTINGS_CONNECTION_UPDATED_INTERNAL,
	                  G_CALLBACK (default_wired_connection_updated_by_user_cb), self);
	g_signal_connect (added, NM_SETTINGS_CONNECTION_REMOVED,
	                  G_CALLBACK (default_wired_connection_removed_cb), self);

	_LOGI ("(%s): created default wired connection '%s'",
	       nm_device_get_iface (device),
	       nm_settings_connection_get_id (added));
}

void
nm_settings_device_added (NMSettings *self, NMDevice *device)
{
	if (nm_device_is_real (device))
		device_realized (device, NULL, self);
	else {
		g_signal_connect_after (device, "notify::" NM_DEVICE_REAL,
		                        G_CALLBACK (device_realized),
		                        self);
	}
}

void
nm_settings_device_removed (NMSettings *self, NMDevice *device, gboolean quitting)
{
	NMSettingsConnection *connection;

	g_signal_handlers_disconnect_by_func (device,
	                                      G_CALLBACK (device_realized),
	                                      self);

	connection = g_object_get_qdata (G_OBJECT (device), _default_wired_connection_quark ());
	if (connection) {
		default_wired_clear_tag (self, device, connection, FALSE);

		/* Don't delete the default wired connection on shutdown, so that it
		 * remains up and can be assumed if NM starts again.
		 */
		if (quitting == FALSE)
			nm_settings_connection_delete (connection, NULL);
	}
}

/*****************************************************************************/

gboolean
nm_settings_get_startup_complete (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	return priv->startup_complete;
}

/*****************************************************************************/

static void
_hostname_changed_cb (NMHostnameManager *hostname_manager,
                      GParamSpec *pspec,
                      gpointer user_data)
{
	_notify (user_data, PROP_HOSTNAME);
}

/*****************************************************************************/

gboolean
nm_settings_start (NMSettings *self, GError **error)
{
	NMSettingsPrivate *priv;
	gs_strfreev char **plugins = NULL;

	priv = NM_SETTINGS_GET_PRIVATE (self);

	/* Load the plugins; fail if a plugin is not found. */
	plugins = nm_config_data_get_plugins (nm_config_get_data_orig (priv->config), TRUE);

	if (!load_plugins (self, (const char **) plugins, error)) {
		g_object_unref (self);
		return FALSE;
	}

	load_connections (self);
	check_startup_complete (self);

	priv->hostname_manager = g_object_ref (nm_hostname_manager_get ());
	g_signal_connect (priv->hostname_manager,
	                  "notify::"NM_HOSTNAME_MANAGER_HOSTNAME,
	                  G_CALLBACK (_hostname_changed_cb),
	                  self);
	if (nm_hostname_manager_get_hostname (priv->hostname_manager))
		_notify (self, PROP_HOSTNAME);

	return TRUE;
}

/*****************************************************************************/

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
		g_value_set_string (value,
		                    priv->hostname_manager
		                      ? nm_hostname_manager_get_hostname (priv->hostname_manager)
		                      : NULL);
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

/*****************************************************************************/

static void
nm_settings_init (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	priv->connections = g_hash_table_new_full (nm_str_hash, g_str_equal, NULL, g_object_unref);

	priv->agent_mgr = g_object_ref (nm_agent_manager_get ());
	priv->config = g_object_ref (nm_config_get ());
}

NMSettings *
nm_settings_new (void)
{
	return g_object_new (NM_TYPE_SETTINGS, NULL);
}

static void
dispose (GObject *object)
{
	NMSettings *self = NM_SETTINGS (object);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	g_slist_free_full (priv->auths, (GDestroyNotify) nm_auth_chain_unref);
	priv->auths = NULL;

	g_object_unref (priv->agent_mgr);

	if (priv->hostname_manager) {
		g_signal_handlers_disconnect_by_func (priv->hostname_manager,
		                                      G_CALLBACK (_hostname_changed_cb),
		                                      self);
		g_clear_object (&priv->hostname_manager);
	}

	G_OBJECT_CLASS (nm_settings_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMSettings *self = NM_SETTINGS (object);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	g_hash_table_destroy (priv->connections);
	g_clear_pointer (&priv->connections_cached_list, g_free);

	g_slist_free_full (priv->unmanaged_specs, g_free);
	g_slist_free_full (priv->unrecognized_specs, g_free);

	g_slist_free_full (priv->plugins, g_object_unref);

	g_clear_object (&priv->config);

	G_OBJECT_CLASS (nm_settings_parent_class)->finalize (object);
}

static void
nm_settings_class_init (NMSettingsClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (class);

	exported_object_class->export_path = NM_DBUS_PATH_SETTINGS;

	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	obj_properties[PROP_UNMANAGED_SPECS] =
	    g_param_spec_boxed (NM_SETTINGS_UNMANAGED_SPECS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_HOSTNAME] =
	    g_param_spec_string (NM_SETTINGS_HOSTNAME, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CAN_MODIFY] =
	    g_param_spec_boolean (NM_SETTINGS_CAN_MODIFY, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CONNECTIONS] =
	    g_param_spec_boxed (NM_SETTINGS_CONNECTIONS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_STARTUP_COMPLETE] =
	    g_param_spec_boolean (NM_SETTINGS_STARTUP_COMPLETE, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[CONNECTION_ADDED] =
	    g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__OBJECT,
	                  G_TYPE_NONE, 1, NM_TYPE_SETTINGS_CONNECTION);

	signals[CONNECTION_UPDATED] =
	    g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_UPDATED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  NULL,
	                  G_TYPE_NONE, 2, NM_TYPE_SETTINGS_CONNECTION, G_TYPE_BOOLEAN);

	signals[CONNECTION_REMOVED] =
	    g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__OBJECT,
	                  G_TYPE_NONE, 1, NM_TYPE_SETTINGS_CONNECTION);

	signals[CONNECTION_FLAGS_CHANGED] =
	    g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_FLAGS_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__OBJECT,
	                  G_TYPE_NONE, 1, NM_TYPE_SETTINGS_CONNECTION);

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

