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
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2008 Red Hat, Inc.
 */

#include "config.h"

#include <signal.h>
#include "nm-glib-compat.h"
#include "nm-vpn-plugin.h"
#include "nm-vpn-enum-types.h"
#include "nm-utils.h"
#include "nm-connection.h"
#include "nm-dbus-glib-types.h"
#include "nm-macros-internal.h"

static gboolean impl_vpn_plugin_connect    (NMVPNPlugin *plugin,
                                            GHashTable *connection,
                                            GError **error);

static gboolean impl_vpn_plugin_connect_interactive (NMVPNPlugin *plugin,
                                                     GHashTable *connection,
                                                     GHashTable *details,
                                                     GError **error);

static gboolean impl_vpn_plugin_need_secrets (NMVPNPlugin *plugin,
                                              GHashTable *connection,
                                              char **service_name,
                                              GError **err);

static gboolean impl_vpn_plugin_new_secrets (NMVPNPlugin *plugin,
                                             GHashTable *connection,
                                             GError **err);

static gboolean impl_vpn_plugin_disconnect (NMVPNPlugin *plugin,
                                            GError **err);

static gboolean impl_vpn_plugin_set_config (NMVPNPlugin *plugin,
                                            GHashTable *config,
                                            GError **err);

static gboolean impl_vpn_plugin_set_ip4_config (NMVPNPlugin *plugin,
                                                GHashTable *config,
                                                GError **err);

static gboolean impl_vpn_plugin_set_ip6_config (NMVPNPlugin *plugin,
                                                GHashTable *config,
                                                GError **err);

static gboolean impl_vpn_plugin_set_failure (NMVPNPlugin *plugin,
                                             char *reason,
                                             GError **err);

#include "nm-vpn-plugin-glue.h"

#define NM_VPN_PLUGIN_QUIT_TIMER    20

G_DEFINE_ABSTRACT_TYPE (NMVPNPlugin, nm_vpn_plugin, G_TYPE_OBJECT)

typedef struct {
	NMVPNServiceState state;

	/* DBUS-y stuff */
	DBusGConnection *connection;
	char *dbus_service_name;

	/* Temporary stuff */
	guint connect_timer;
	guint quit_timer;
	guint fail_stop_id;
	gboolean interactive;

	gboolean got_config;
	gboolean has_ip4, got_ip4;
	gboolean has_ip6, got_ip6;

	/* Config stuff copied from config to ip4config */
	GValue banner, tundev, gateway, mtu;
} NMVPNPluginPrivate;

#define NM_VPN_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_PLUGIN, NMVPNPluginPrivate))

enum {
	STATE_CHANGED,
	CONFIG,
	IP4_CONFIG,
	IP6_CONFIG,
	LOGIN_BANNER,
	FAILURE,
	QUIT,
	SECRETS_REQUIRED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_DBUS_SERVICE_NAME,
	PROP_STATE,

	LAST_PROP
};

static GSList *active_plugins = NULL;


GQuark
nm_vpn_plugin_error_quark (void)
{
	static GQuark quark = 0;

	if (!quark)
		quark = g_quark_from_static_string ("nm_vpn_plugin_error");

	return quark;
}


static void
nm_vpn_plugin_set_connection (NMVPNPlugin *plugin,
                              DBusGConnection *connection)
{
	NMVPNPluginPrivate *priv = NM_VPN_PLUGIN_GET_PRIVATE (plugin);

	if (priv->connection)
		dbus_g_connection_unref (priv->connection);

	priv->connection = connection;
}

DBusGConnection *
nm_vpn_plugin_get_connection (NMVPNPlugin *plugin)
{
	DBusGConnection *connection;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), NULL);

	connection = NM_VPN_PLUGIN_GET_PRIVATE (plugin)->connection;

	if (connection)
		dbus_g_connection_ref (connection);

	return connection;
}

NMVPNServiceState
nm_vpn_plugin_get_state (NMVPNPlugin *plugin)
{
	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), NM_VPN_SERVICE_STATE_UNKNOWN);

	return NM_VPN_PLUGIN_GET_PRIVATE (plugin)->state;
}

void
nm_vpn_plugin_set_state (NMVPNPlugin *plugin,
                         NMVPNServiceState state)
{
	NMVPNPluginPrivate *priv;

	g_return_if_fail (NM_IS_VPN_PLUGIN (plugin));

	priv = NM_VPN_PLUGIN_GET_PRIVATE (plugin);
	if (priv->state != state) {
		priv->state = state;
		g_signal_emit (plugin, signals[STATE_CHANGED], 0, state);
	}
}

void
nm_vpn_plugin_set_login_banner (NMVPNPlugin *plugin,
                                const char *banner)
{
	g_return_if_fail (NM_IS_VPN_PLUGIN (plugin));
	g_return_if_fail (banner != NULL);

	g_signal_emit (plugin, signals[LOGIN_BANNER], 0, banner);
}

void
nm_vpn_plugin_failure (NMVPNPlugin *plugin,
                       NMVPNPluginFailure reason)
{
	g_return_if_fail (NM_IS_VPN_PLUGIN (plugin));

	g_signal_emit (plugin, signals[FAILURE], 0, reason);
}

gboolean
nm_vpn_plugin_disconnect (NMVPNPlugin *plugin, GError **err)
{
	gboolean ret = FALSE;
	NMVPNServiceState state;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), FALSE);

	state = nm_vpn_plugin_get_state (plugin);
	switch (state) {
	case NM_VPN_SERVICE_STATE_STOPPING:
		g_set_error (err,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_STOPPING_IN_PROGRESS,
		             "%s",
		             "Could not process the request because the VPN connection is already being stopped.");
		break;
	case NM_VPN_SERVICE_STATE_STOPPED:
		g_set_error (err,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_ALREADY_STOPPED,
		             "%s",
		             "Could not process the request because no VPN connection was active.");
		break;
	case NM_VPN_SERVICE_STATE_STARTING:
	case NM_VPN_SERVICE_STATE_STARTED:
		nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPING);
		ret = NM_VPN_PLUGIN_GET_CLASS (plugin)->disconnect (plugin, err);
		nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
		break;
	case NM_VPN_SERVICE_STATE_INIT:
		ret = TRUE;
		break;

	default:
		g_warning ("Unhandled VPN service state %d", state);
		g_assert_not_reached ();
		break;
	}

	return ret;
}

static void
nm_vpn_plugin_emit_quit (NMVPNPlugin *plugin)
{
	g_signal_emit (plugin, signals[QUIT], 0);
}

static gboolean
connect_timer_expired (gpointer data)
{
	NMVPNPlugin *plugin = NM_VPN_PLUGIN (data);
	GError *err = NULL;

	NM_VPN_PLUGIN_GET_PRIVATE (plugin)->connect_timer = 0;
	g_message ("Connect timer expired, disconnecting.");
	nm_vpn_plugin_disconnect (plugin, &err);
	if (err) {
		g_warning ("Disconnect failed: %s", err->message);
		g_error_free (err);
	}

	return G_SOURCE_REMOVE;
}

static gboolean
quit_timer_expired (gpointer data)
{
	NMVPNPlugin *self = NM_VPN_PLUGIN (data);

	NM_VPN_PLUGIN_GET_PRIVATE (self)->quit_timer = 0;
	nm_vpn_plugin_emit_quit (self);
	return G_SOURCE_REMOVE;
}

static gboolean
fail_stop (gpointer data)
{
	NMVPNPlugin *self = NM_VPN_PLUGIN (data);

	NM_VPN_PLUGIN_GET_PRIVATE (self)->fail_stop_id = 0;
	nm_vpn_plugin_set_state (self, NM_VPN_SERVICE_STATE_STOPPED);
	return G_SOURCE_REMOVE;
}

static void
schedule_fail_stop (NMVPNPlugin *plugin)
{
	NMVPNPluginPrivate *priv = NM_VPN_PLUGIN_GET_PRIVATE (plugin);

	nm_clear_g_source (&priv->fail_stop_id);
	priv->fail_stop_id = g_idle_add (fail_stop, plugin);
}

static void
_g_value_set (GValue *dst, GValue *src)
{
	if (src) {
		GType type = G_VALUE_TYPE (src);

		if (G_IS_VALUE (dst))
			g_value_unset (dst);
		g_value_init (dst, type);
		g_value_copy (src, dst);
	} else if (G_IS_VALUE (dst))
		g_value_unset (dst);
}

void
nm_vpn_plugin_set_config (NMVPNPlugin *plugin,
                          GHashTable *config)
{
	NMVPNPluginPrivate *priv = NM_VPN_PLUGIN_GET_PRIVATE (plugin);
	GValue *val;

	g_return_if_fail (NM_IS_VPN_PLUGIN (plugin));
	g_return_if_fail (config != NULL);

	priv->got_config = TRUE;

	val = g_hash_table_lookup (config, NM_VPN_PLUGIN_CONFIG_HAS_IP4);
	if (val && g_value_get_boolean (val))
		priv->has_ip4 = TRUE;
	val = g_hash_table_lookup (config, NM_VPN_PLUGIN_CONFIG_HAS_IP6);
	if (val && g_value_get_boolean (val))
		priv->has_ip6 = TRUE;

	g_warn_if_fail (priv->has_ip4 || priv->has_ip6);

	/* Record the items that need to also be inserted into the
	 * ip4config, for compatibility with older daemons.
	 */
	_g_value_set (&priv->banner, g_hash_table_lookup (config, NM_VPN_PLUGIN_CONFIG_BANNER));
	_g_value_set (&priv->tundev, g_hash_table_lookup (config, NM_VPN_PLUGIN_CONFIG_TUNDEV));
	_g_value_set (&priv->gateway, g_hash_table_lookup (config, NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY));
	_g_value_set (&priv->mtu, g_hash_table_lookup (config, NM_VPN_PLUGIN_CONFIG_MTU));

	g_signal_emit (plugin, signals[CONFIG], 0, config);
}

void
nm_vpn_plugin_set_ip4_config (NMVPNPlugin *plugin,
                              GHashTable *ip4_config)
{
	NMVPNPluginPrivate *priv = NM_VPN_PLUGIN_GET_PRIVATE (plugin);
	GHashTable *combined_config;
	GHashTableIter iter;
	gpointer key, value;

	g_return_if_fail (NM_IS_VPN_PLUGIN (plugin));
	g_return_if_fail (ip4_config != NULL);

	priv->got_ip4 = TRUE;

	/* Old plugins won't send the "config" signal and thus can't send
	 * NM_VPN_PLUGIN_CONFIG_HAS_IP4 either.  But since they don't support IPv6,
	 * we can safely assume that, if we don't receive a "config" signal but do
	 * receive an "ip4-config" signal, the old plugin supports IPv4.
	 */
	if (!priv->got_config)
		priv->has_ip4 = TRUE;

	/* Older NetworkManager daemons expect all config info to be in
	 * the ip4 config, so they won't even notice the "config" signal
	 * being emitted. So just copy all of that data into the ip4
	 * config too.
	 */
	combined_config = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_iter_init (&iter, ip4_config);
	while (g_hash_table_iter_next (&iter, &key, &value))
		g_hash_table_insert (combined_config, key, value);

	if (G_VALUE_TYPE (&priv->banner) != G_TYPE_INVALID)
		g_hash_table_insert (combined_config, NM_VPN_PLUGIN_IP4_CONFIG_BANNER, &priv->banner);
	if (G_VALUE_TYPE (&priv->tundev) != G_TYPE_INVALID)
		g_hash_table_insert (combined_config, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, &priv->tundev);
	if (G_VALUE_TYPE (&priv->gateway) != G_TYPE_INVALID)
		g_hash_table_insert (combined_config, NM_VPN_PLUGIN_IP4_CONFIG_EXT_GATEWAY, &priv->gateway);
	if (G_VALUE_TYPE (&priv->mtu) != G_TYPE_INVALID)
		g_hash_table_insert (combined_config, NM_VPN_PLUGIN_IP4_CONFIG_MTU, &priv->mtu);

	g_signal_emit (plugin, signals[IP4_CONFIG], 0, combined_config);
	g_hash_table_destroy (combined_config);

	if (   priv->has_ip4 == priv->got_ip4
	    && priv->has_ip6 == priv->got_ip6)
		nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STARTED);
}

void
nm_vpn_plugin_set_ip6_config (NMVPNPlugin *plugin,
                              GHashTable *ip6_config)
{
	NMVPNPluginPrivate *priv = NM_VPN_PLUGIN_GET_PRIVATE (plugin);

	g_return_if_fail (NM_IS_VPN_PLUGIN (plugin));
	g_return_if_fail (ip6_config != NULL);

	priv->got_ip6 = TRUE;
	g_signal_emit (plugin, signals[IP6_CONFIG], 0, ip6_config);

	if (   priv->has_ip4 == priv->got_ip4
	    && priv->has_ip6 == priv->got_ip6)
		nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STARTED);
}

static void
connect_timer_start (NMVPNPlugin *plugin)
{
	NMVPNPluginPrivate *priv = NM_VPN_PLUGIN_GET_PRIVATE (plugin);

	priv->connect_timer = g_timeout_add_seconds (60, connect_timer_expired, plugin);
}

static gboolean
_connect_generic (NMVPNPlugin *plugin,
                  GHashTable *properties,
                  GHashTable *details,
                  GError **error)
{
	NMVPNPluginPrivate *priv = NM_VPN_PLUGIN_GET_PRIVATE (plugin);
	NMVPNPluginClass *vpn_class = NM_VPN_PLUGIN_GET_CLASS (plugin);
	NMConnection *connection;
	gboolean success = FALSE;
	GError *local = NULL;

	if (priv->state != NM_VPN_SERVICE_STATE_STOPPED &&
	    priv->state != NM_VPN_SERVICE_STATE_INIT) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_WRONG_STATE,
		             "Could not start connection: wrong plugin state %d",
		             priv->state);
		return FALSE;
	}

	connection = nm_connection_new_from_hash (properties, &local);
	if (!connection) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Invalid connection: (%d) %s",
		             local->code, local->message);
		g_clear_error (&local);
		return FALSE;
	}


	priv->interactive = FALSE;
	if (details && !vpn_class->connect_interactive) {
		g_set_error_literal (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_INTERACTIVE_NOT_SUPPORTED,
		                     "Plugin does not implement ConnectInteractive()");
		return FALSE;
	}

	nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STARTING);

	if (details) {
		priv->interactive = TRUE;
		success = vpn_class->connect_interactive (plugin, connection, details, error);
	} else
		success = vpn_class->connect (plugin, connection, error);

	if (success) {
		/* Add a timer to make sure we do not wait indefinitely for the successful connect. */
		connect_timer_start (plugin);
	} else {
		/* Stop the plugin from an idle handler so that the Connect
		 * method return gets sent before the STOP StateChanged signal.
		 */
		schedule_fail_stop (plugin);
	}

	g_object_unref (connection);
	return success;
}

static gboolean
impl_vpn_plugin_connect (NMVPNPlugin *plugin,
                         GHashTable *connection,
                         GError **error)
{
	return _connect_generic (plugin, connection, NULL, error);
}

static gboolean
impl_vpn_plugin_connect_interactive (NMVPNPlugin *plugin,
                                     GHashTable *connection,
                                     GHashTable *details,
                                     GError **error)
{
	return _connect_generic (plugin, connection, details, error);
}

/***************************************************************/

static gboolean
impl_vpn_plugin_need_secrets (NMVPNPlugin *plugin,
                              GHashTable *properties,
                              char **setting_name,
                              GError **err)
{
	gboolean ret = FALSE;
	NMConnection *connection;
	char *sn = NULL;
	GError *ns_err = NULL;
	gboolean needed = FALSE;
	GError *cnfh_err = NULL;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (properties != NULL, FALSE);

	connection = nm_connection_new_from_hash (properties, &cnfh_err);
	if (!connection) {
		g_set_error (err,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "The connection was invalid: '%s' / '%s' invalid: %d.",
		             g_type_name (nm_connection_lookup_setting_type_by_quark (cnfh_err->domain)),
		             cnfh_err->message, cnfh_err->code);
		g_error_free (cnfh_err);
		return FALSE;
	}

	if (!NM_VPN_PLUGIN_GET_CLASS (plugin)->need_secrets) {
		*setting_name = "";
		ret = TRUE;
		goto out;
	}

	needed = NM_VPN_PLUGIN_GET_CLASS (plugin)->need_secrets (plugin, connection, &sn, &ns_err);
	if (ns_err) {
		*err = g_error_copy (ns_err);
		g_error_free (ns_err);
		goto out;
	}

	ret = TRUE;
	if (needed) {
		g_assert (sn);
		*setting_name = g_strdup (sn);
	} else {
		/* No secrets required */
		*setting_name = g_strdup ("");
	}

out:
	return ret;
}

static gboolean
impl_vpn_plugin_new_secrets (NMVPNPlugin *plugin,
                             GHashTable *properties,
                             GError **error)
{
	NMVPNPluginPrivate *priv = NM_VPN_PLUGIN_GET_PRIVATE (plugin);
	NMConnection *connection;
	GError *local = NULL;
	gboolean success;

	if (priv->state != NM_VPN_SERVICE_STATE_STARTING) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_WRONG_STATE,
		             "Could not accept new secrets: wrong plugin state %d",
		             priv->state);
		return FALSE;
	}

	connection = nm_connection_new_from_hash (properties, &local);
	if (!connection) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Invalid connection: (%d) %s",
		             local->code, local->message);
		g_clear_error (&local);
		return FALSE;
	}

	if (!NM_VPN_PLUGIN_GET_CLASS (plugin)->new_secrets) {
		g_set_error_literal (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_INTERACTIVE_NOT_SUPPORTED,
		                     "Could not accept new secrets: plugin cannot process interactive secrets");
		g_object_unref (connection);
		return FALSE;
	}

	success = NM_VPN_PLUGIN_GET_CLASS (plugin)->new_secrets (plugin, connection, error);
	if (success) {
		/* Add a timer to make sure we do not wait indefinitely for the successful connect. */
		connect_timer_start (plugin);
	} else {
		/* Stop the plugin from and idle handler so that the NewSecrets
		 * method return gets sent before the STOP StateChanged signal.
		 */
		schedule_fail_stop (plugin);
	}

	g_object_unref (connection);
	return success;
}

/**
 * nm_vpn_plugin_secrets_required:
 * @plugin: the #NMVPNPlugin
 * @message: an information message about why secrets are required, if any
 * @hints: VPN specific secret names for required new secrets
 *
 * Called by VPN plugin implementations to signal to NetworkManager that secrets
 * are required during the connection process.  This signal may be used to
 * request new secrets when the secrets originally provided by NetworkManager
 * are insufficient, or the VPN process indicates that it needs additional
 * information to complete the request.
 *
 * Since: 0.9.10
 */
void
nm_vpn_plugin_secrets_required (NMVPNPlugin *plugin,
                                const char *message,
                                const char **hints)
{
	NMVPNPluginPrivate *priv = NM_VPN_PLUGIN_GET_PRIVATE (plugin);

	/* Plugin must be able to accept the new secrets if it calls this method */
	g_return_if_fail (NM_VPN_PLUGIN_GET_CLASS (plugin)->new_secrets);

	/* Plugin cannot call this method if NetworkManager didn't originally call
	 * ConnectInteractive().
	 */
	g_return_if_fail (priv->interactive == TRUE);

	/* Cancel the connect timer since secrets might take a while.  It'll
	 * get restarted when the secrets come back via NewSecrets().
	 */
	nm_clear_g_source (&priv->connect_timer);

	g_signal_emit (plugin, signals[SECRETS_REQUIRED], 0, message, hints);
}

/***************************************************************/

static gboolean
impl_vpn_plugin_disconnect (NMVPNPlugin *plugin,
                            GError **err)
{
	return nm_vpn_plugin_disconnect (plugin, err);
}

static gboolean
impl_vpn_plugin_set_config (NMVPNPlugin *plugin,
                            GHashTable *config,
                            GError **err)
{
	nm_vpn_plugin_set_config (plugin, config);

	return TRUE;
}

static gboolean
impl_vpn_plugin_set_ip4_config (NMVPNPlugin *plugin,
                                GHashTable *config,
                                GError **err)
{
	nm_vpn_plugin_set_ip4_config (plugin, config);

	return TRUE;
}

static gboolean
impl_vpn_plugin_set_ip6_config (NMVPNPlugin *plugin,
                                GHashTable *config,
                                GError **err)
{
	nm_vpn_plugin_set_ip6_config (plugin, config);

	return TRUE;
}

static gboolean
impl_vpn_plugin_set_failure (NMVPNPlugin *plugin,
                             char *reason,
                             GError **err)
{
	nm_vpn_plugin_failure (plugin, NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG);

	return TRUE;
}

/*********************************************************************/

static void
sigterm_handler (int signum)
{
	g_slist_foreach (active_plugins, (GFunc) nm_vpn_plugin_emit_quit, NULL);
}

static void
setup_unix_signal_handler (void)
{
	struct sigaction action;
	sigset_t block_mask;

	action.sa_handler = sigterm_handler;
	sigemptyset (&block_mask);
	action.sa_mask = block_mask;
	action.sa_flags = 0;
	sigaction (SIGINT, &action, NULL);
	sigaction (SIGTERM, &action, NULL);
}

/*********************************************************************/

static void
one_plugin_destroyed (gpointer data,
                      GObject *object)
{
	active_plugins = g_slist_remove (active_plugins, object);
}

static void
nm_vpn_plugin_init (NMVPNPlugin *plugin)
{
	active_plugins = g_slist_append (active_plugins, plugin);
	g_object_weak_ref (G_OBJECT (plugin),
	                   one_plugin_destroyed,
	                   NULL);
}

static GObject *
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	NMVPNPlugin *plugin;
	NMVPNPluginPrivate *priv;
	DBusGConnection *connection;
	DBusGProxy *proxy;
	guint request_name_result;
	GError *err = NULL;

	object = G_OBJECT_CLASS (nm_vpn_plugin_parent_class)->constructor (type,
	                                                                   n_construct_params,
	                                                                   construct_params);
	if (!object)
		return NULL;

	priv = NM_VPN_PLUGIN_GET_PRIVATE (object);
	if (!priv->dbus_service_name)
		goto err;

	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!connection)
		goto err;

	proxy = dbus_g_proxy_new_for_name (connection,
	                                   "org.freedesktop.DBus",
	                                   "/org/freedesktop/DBus",
	                                   "org.freedesktop.DBus");

	if (!dbus_g_proxy_call (proxy, "RequestName", &err,
	                        G_TYPE_STRING, priv->dbus_service_name,
	                        G_TYPE_UINT, 0,
	                        G_TYPE_INVALID,
	                        G_TYPE_UINT, &request_name_result,
	                        G_TYPE_INVALID)) {
		g_object_unref (proxy);
		goto err;
	}

	g_object_unref (proxy);

	dbus_g_connection_register_g_object (connection,
	                                     NM_VPN_DBUS_PLUGIN_PATH,
	                                     object);

	plugin = NM_VPN_PLUGIN (object);

	nm_vpn_plugin_set_connection (plugin, connection);
	nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_INIT);

	return object;

 err:
	if (err) {
		g_warning ("Failed to initialize VPN plugin: %s", err->message);
		g_error_free (err);
	}

	if (object)
		g_object_unref (object);

	return NULL;
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMVPNPluginPrivate *priv = NM_VPN_PLUGIN_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_DBUS_SERVICE_NAME:
		/* Construct-only */
		priv->dbus_service_name = g_strdup (g_value_get_string (value));
		break;
	case PROP_STATE:
		nm_vpn_plugin_set_state (NM_VPN_PLUGIN (object),
		                         (NMVPNServiceState) g_value_get_uint (value));
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
	NMVPNPluginPrivate *priv = NM_VPN_PLUGIN_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_DBUS_SERVICE_NAME:
		g_value_set_string (value, priv->dbus_service_name);
		break;
	case PROP_STATE:
		g_value_set_uint (value, nm_vpn_plugin_get_state (NM_VPN_PLUGIN (object)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMVPNPlugin *plugin = NM_VPN_PLUGIN (object);
	NMVPNPluginPrivate *priv = NM_VPN_PLUGIN_GET_PRIVATE (plugin);
	NMVPNServiceState state;
	GError *err = NULL;

	nm_clear_g_source (&priv->fail_stop_id);
	nm_clear_g_source (&priv->quit_timer);
	nm_clear_g_source (&priv->connect_timer);

	state = nm_vpn_plugin_get_state (plugin);

	if (state == NM_VPN_SERVICE_STATE_STARTED ||
	    state == NM_VPN_SERVICE_STATE_STARTING)
		nm_vpn_plugin_disconnect (plugin, &err);

	if (err) {
		g_warning ("Error disconnecting VPN connection: %s", err->message);
		g_error_free (err);
	}

	G_OBJECT_CLASS (nm_vpn_plugin_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMVPNPlugin *plugin = NM_VPN_PLUGIN (object);
	NMVPNPluginPrivate *priv = NM_VPN_PLUGIN_GET_PRIVATE (plugin);

	nm_vpn_plugin_set_connection (plugin, NULL);
	g_free (priv->dbus_service_name);

	if (G_IS_VALUE (&priv->banner))
		g_value_unset (&priv->banner);
	if (G_IS_VALUE (&priv->tundev))
		g_value_unset (&priv->tundev);
	if (G_IS_VALUE (&priv->gateway))
		g_value_unset (&priv->gateway);
	if (G_IS_VALUE (&priv->mtu))
		g_value_unset (&priv->mtu);

	G_OBJECT_CLASS (nm_vpn_plugin_parent_class)->finalize (object);
}

static void
state_changed (NMVPNPlugin *plugin, NMVPNServiceState state)
{
	NMVPNPluginPrivate *priv = NM_VPN_PLUGIN_GET_PRIVATE (plugin);

	switch (state) {
	case NM_VPN_SERVICE_STATE_STARTING:
		nm_clear_g_source (&priv->quit_timer);
		nm_clear_g_source (&priv->fail_stop_id);
		break;
	case NM_VPN_SERVICE_STATE_STOPPED:
		priv->quit_timer = g_timeout_add_seconds (NM_VPN_PLUGIN_QUIT_TIMER,
		                                          quit_timer_expired,
		                                          plugin);
		break;
	default:
		/* Clean up all timers we might have set up. */
		nm_clear_g_source (&priv->connect_timer);
		nm_clear_g_source (&priv->quit_timer);
		nm_clear_g_source (&priv->fail_stop_id);
		break;
	}
}

static void
nm_vpn_plugin_class_init (NMVPNPluginClass *plugin_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (plugin_class);

	g_type_class_add_private (object_class, sizeof (NMVPNPluginPrivate));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (plugin_class),
	                                 &dbus_glib_nm_vpn_plugin_object_info);

	/* virtual methods */
	object_class->constructor  = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose      = dispose;
	object_class->finalize     = finalize;

	plugin_class->state_changed = state_changed;

	/* properties */

	/**
	 * NMVPNPlugin:service-name:
	 *
	 * The D-Bus service name of this plugin.
	 */
	g_object_class_install_property
		(object_class, PROP_DBUS_SERVICE_NAME,
		 g_param_spec_string (NM_VPN_PLUGIN_DBUS_SERVICE_NAME, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMVPNPlugin:state:
	 *
	 * The state of the plugin.
	 */
	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_uint (NM_VPN_PLUGIN_STATE, "", "",
		                    NM_VPN_SERVICE_STATE_UNKNOWN,
		                    NM_VPN_SERVICE_STATE_STOPPED,
		                    NM_VPN_SERVICE_STATE_INIT,
		                    G_PARAM_READWRITE |
		                    G_PARAM_STATIC_STRINGS));

	/* signals */
	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMVPNPluginClass, state_changed),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__UINT,
		              G_TYPE_NONE, 1,
		              G_TYPE_UINT);

	signals[SECRETS_REQUIRED] =
		g_signal_new ("secrets-required",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL,
		              NULL,
		              G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_STRV);

	signals[CONFIG] =
		g_signal_new ("config",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMVPNPluginClass, config),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__BOXED,
		              G_TYPE_NONE, 1,
		              DBUS_TYPE_G_MAP_OF_VARIANT);

	signals[IP4_CONFIG] =
		g_signal_new ("ip4-config",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMVPNPluginClass, ip4_config),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__BOXED,
		              G_TYPE_NONE, 1,
		              DBUS_TYPE_G_MAP_OF_VARIANT);

	signals[IP6_CONFIG] =
		g_signal_new ("ip6-config",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMVPNPluginClass, ip6_config),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__BOXED,
		              G_TYPE_NONE, 1,
		              DBUS_TYPE_G_MAP_OF_VARIANT);

	signals[LOGIN_BANNER] =
		g_signal_new ("login-banner",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMVPNPluginClass, login_banner),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__STRING,
		              G_TYPE_NONE, 1,
		              G_TYPE_STRING);

	signals[FAILURE] =
		g_signal_new ("failure",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMVPNPluginClass, failure),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__UINT,
		              G_TYPE_NONE, 1,
		              G_TYPE_UINT);

	signals[QUIT] =
		g_signal_new ("quit",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMVPNPluginClass, quit),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0,
		              G_TYPE_NONE);

	dbus_g_error_domain_register (NM_VPN_PLUGIN_ERROR,
	                              NM_DBUS_VPN_ERROR_PREFIX,
	                              NM_TYPE_VPN_PLUGIN_ERROR);

	setup_unix_signal_handler ();
}
