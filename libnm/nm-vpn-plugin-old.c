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

/* This interface is expected to be deprecated in NM 1.2, at which point there
 * will be a new "NMVpnPlugin" class to replace it.
 */

#include "config.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>

#include <glib/gi18n-lib.h>
#include <gio/gio.h>

#include "nm-glib-compat.h"
#include "nm-vpn-plugin-old.h"
#include "nm-enum-types.h"
#include "nm-utils.h"
#include "nm-connection.h"
#include "nm-dbus-helpers.h"
#include "nm-core-internal.h"
#include "nm-simple-connection.h"

#include "nmdbus-vpn-plugin.h"

#define NM_VPN_PLUGIN_OLD_QUIT_TIMER    20

static void nm_vpn_plugin_old_initable_iface_init (GInitableIface *iface);

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (NMVpnPluginOld, nm_vpn_plugin_old, G_TYPE_OBJECT,
                                  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_vpn_plugin_old_initable_iface_init);
                                  )

typedef struct {
	NMVpnServiceState state;

	/* DBUS-y stuff */
	GDBusConnection *connection;
	NMDBusVpnPlugin *dbus_vpn_plugin_old;
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
	char *banner, *tundev, *gateway, *mtu;
} NMVpnPluginOldPrivate;

#define NM_VPN_PLUGIN_OLD_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_PLUGIN_OLD, NMVpnPluginOldPrivate))

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


static void
nm_vpn_plugin_old_set_connection (NMVpnPluginOld *plugin,
                                  GDBusConnection *connection)
{
	NMVpnPluginOldPrivate *priv = NM_VPN_PLUGIN_OLD_GET_PRIVATE (plugin);

	g_clear_object (&priv->connection);

	priv->connection = g_object_ref (connection);
}

/**
 * nm_vpn_plugin_old_get_connection:
 *
 * Returns: (transfer full):
 */
GDBusConnection *
nm_vpn_plugin_old_get_connection (NMVpnPluginOld *plugin)
{
	GDBusConnection *connection;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN_OLD (plugin), NULL);

	connection = NM_VPN_PLUGIN_OLD_GET_PRIVATE (plugin)->connection;

	if (connection)
		g_object_ref (connection);

	return connection;
}

NMVpnServiceState
nm_vpn_plugin_old_get_state (NMVpnPluginOld *plugin)
{
	g_return_val_if_fail (NM_IS_VPN_PLUGIN_OLD (plugin), NM_VPN_SERVICE_STATE_UNKNOWN);

	return NM_VPN_PLUGIN_OLD_GET_PRIVATE (plugin)->state;
}

void
nm_vpn_plugin_old_set_state (NMVpnPluginOld *plugin,
                             NMVpnServiceState state)
{
	NMVpnPluginOldPrivate *priv;

	g_return_if_fail (NM_IS_VPN_PLUGIN_OLD (plugin));

	priv = NM_VPN_PLUGIN_OLD_GET_PRIVATE (plugin);
	if (priv->state != state) {
		priv->state = state;
		g_signal_emit (plugin, signals[STATE_CHANGED], 0, state);
	}
}

void
nm_vpn_plugin_old_set_login_banner (NMVpnPluginOld *plugin,
                                    const char *banner)
{
	g_return_if_fail (NM_IS_VPN_PLUGIN_OLD (plugin));
	g_return_if_fail (banner != NULL);

	g_signal_emit (plugin, signals[LOGIN_BANNER], 0, banner);
}

void
nm_vpn_plugin_old_failure (NMVpnPluginOld *plugin,
                           NMVpnPluginFailure reason)
{
	g_return_if_fail (NM_IS_VPN_PLUGIN_OLD (plugin));

	g_signal_emit (plugin, signals[FAILURE], 0, reason);
}

gboolean
nm_vpn_plugin_old_disconnect (NMVpnPluginOld *plugin, GError **err)
{
	gboolean ret = FALSE;
	NMVpnServiceState state;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN_OLD (plugin), FALSE);

	state = nm_vpn_plugin_old_get_state (plugin);
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
		nm_vpn_plugin_old_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPING);
		ret = NM_VPN_PLUGIN_OLD_GET_CLASS (plugin)->disconnect (plugin, err);
		nm_vpn_plugin_old_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
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
nm_vpn_plugin_old_emit_quit (NMVpnPluginOld *plugin)
{
	g_signal_emit (plugin, signals[QUIT], 0);
}

static gboolean
connect_timer_expired (gpointer data)
{
	NMVpnPluginOld *plugin = NM_VPN_PLUGIN_OLD (data);
	GError *err = NULL;

	g_message ("Connect timer expired, disconnecting.");
	nm_vpn_plugin_old_disconnect (plugin, &err);
	if (err) {
		g_warning ("Disconnect failed: %s", err->message);
		g_error_free (err);
	}

	return FALSE;
}

static gboolean
quit_timer_expired (gpointer data)
{
	NMVpnPluginOld *plugin = NM_VPN_PLUGIN_OLD (data);

	nm_vpn_plugin_old_emit_quit (plugin);

	return FALSE;
}

static gboolean
fail_stop (gpointer data)
{
	NMVpnPluginOld *plugin = NM_VPN_PLUGIN_OLD (data);

	nm_vpn_plugin_old_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
	return FALSE;
}

static void
schedule_fail_stop (NMVpnPluginOld *plugin)
{
	NMVpnPluginOldPrivate *priv = NM_VPN_PLUGIN_OLD_GET_PRIVATE (plugin);

	if (priv->fail_stop_id)
		g_source_remove (priv->fail_stop_id);
	priv->fail_stop_id = g_idle_add (fail_stop, plugin);
}

void
nm_vpn_plugin_old_set_config (NMVpnPluginOld *plugin,
                              GVariant *config)
{
	NMVpnPluginOldPrivate *priv = NM_VPN_PLUGIN_OLD_GET_PRIVATE (plugin);

	g_return_if_fail (NM_IS_VPN_PLUGIN_OLD (plugin));
	g_return_if_fail (config != NULL);

	priv->got_config = TRUE;

	g_variant_lookup (config, NM_VPN_PLUGIN_CONFIG_HAS_IP4, "b", &priv->has_ip4);
	g_variant_lookup (config, NM_VPN_PLUGIN_CONFIG_HAS_IP6, "b", &priv->has_ip6);

	g_warn_if_fail (priv->has_ip4 || priv->has_ip6);

	/* Record the items that need to also be inserted into the
	 * ip4config, for compatibility with older daemons.
	 */
	g_clear_pointer (&priv->banner, g_free);
	g_variant_lookup (config, NM_VPN_PLUGIN_CONFIG_BANNER, "&s", &priv->banner);
	g_clear_pointer (&priv->tundev, g_free);
	g_variant_lookup (config, NM_VPN_PLUGIN_CONFIG_TUNDEV, "&s", &priv->tundev);
	g_clear_pointer (&priv->gateway, g_free);
	g_variant_lookup (config, NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, "&s", &priv->gateway);
	g_clear_pointer (&priv->mtu, g_free);
	g_variant_lookup (config, NM_VPN_PLUGIN_CONFIG_MTU, "&s", &priv->mtu);

	g_signal_emit (plugin, signals[CONFIG], 0, config);
}

void
nm_vpn_plugin_old_set_ip4_config (NMVpnPluginOld *plugin,
                                  GVariant *ip4_config)
{
	NMVpnPluginOldPrivate *priv = NM_VPN_PLUGIN_OLD_GET_PRIVATE (plugin);
	GVariant *combined_config;
	GVariantBuilder builder;
	GVariantIter iter;
	const char *key, *value;

	g_return_if_fail (NM_IS_VPN_PLUGIN_OLD (plugin));
	g_return_if_fail (ip4_config != NULL);

	priv->got_ip4 = TRUE;

	/* Old plugins won't send the "config" signal and thus can't send
	 * NM_VPN_PLUGIN_OLD_CONFIG_HAS_IP4 either.  But since they don't support IPv6,
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
	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));
	g_variant_iter_init (&iter, ip4_config);
	while (g_variant_iter_next (&iter, "{&s&s}", &key, &value))
		g_variant_builder_add (&builder, "{ss}", key, value);

	if (priv->banner)
		g_variant_builder_add (&builder, "{ss}", NM_VPN_PLUGIN_IP4_CONFIG_BANNER, &priv->banner);
	if (priv->tundev)
		g_variant_builder_add (&builder, "{ss}", NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, &priv->tundev);
	if (priv->gateway)
		g_variant_builder_add (&builder, "{ss}", NM_VPN_PLUGIN_IP4_CONFIG_EXT_GATEWAY, &priv->gateway);
	if (priv->mtu)
		g_variant_builder_add (&builder, "{ss}", NM_VPN_PLUGIN_IP4_CONFIG_MTU, &priv->mtu);

	combined_config = g_variant_builder_end (&builder);
	g_variant_ref_sink (combined_config);
	g_signal_emit (plugin, signals[IP4_CONFIG], 0, combined_config);
	g_variant_unref (combined_config);

	if (   priv->has_ip4 == priv->got_ip4
	    && priv->has_ip6 == priv->got_ip6)
		nm_vpn_plugin_old_set_state (plugin, NM_VPN_SERVICE_STATE_STARTED);
}

void
nm_vpn_plugin_old_set_ip6_config (NMVpnPluginOld *plugin,
                                  GVariant *ip6_config)
{
	NMVpnPluginOldPrivate *priv = NM_VPN_PLUGIN_OLD_GET_PRIVATE (plugin);

	g_return_if_fail (NM_IS_VPN_PLUGIN_OLD (plugin));
	g_return_if_fail (ip6_config != NULL);

	priv->got_ip6 = TRUE;
	g_signal_emit (plugin, signals[IP6_CONFIG], 0, ip6_config);

	if (   priv->has_ip4 == priv->got_ip4
	    && priv->has_ip6 == priv->got_ip6)
		nm_vpn_plugin_old_set_state (plugin, NM_VPN_SERVICE_STATE_STARTED);
}

static void
connect_timer_removed (gpointer data)
{
	NM_VPN_PLUGIN_OLD_GET_PRIVATE (data)->connect_timer = 0;
}

static void
connect_timer_start (NMVpnPluginOld *plugin)
{
	NMVpnPluginOldPrivate *priv = NM_VPN_PLUGIN_OLD_GET_PRIVATE (plugin);

	priv->connect_timer = g_timeout_add_seconds_full (G_PRIORITY_DEFAULT,
	                                                  60,
	                                                  connect_timer_expired,
	                                                  plugin,
	                                                  connect_timer_removed);
}

static void
_connect_generic (NMVpnPluginOld *plugin,
                  GDBusMethodInvocation *context,
                  GVariant *properties,
                  GVariant *details)
{
	NMVpnPluginOldPrivate *priv = NM_VPN_PLUGIN_OLD_GET_PRIVATE (plugin);
	NMVpnPluginOldClass *vpn_class = NM_VPN_PLUGIN_OLD_GET_CLASS (plugin);
	NMConnection *connection;
	gboolean success = FALSE;
	GError *error = NULL;

	if (priv->state != NM_VPN_SERVICE_STATE_STOPPED &&
	    priv->state != NM_VPN_SERVICE_STATE_INIT) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_VPN_PLUGIN_ERROR,
		                                       NM_VPN_PLUGIN_ERROR_WRONG_STATE,
		                                       "Could not start connection: wrong plugin state %d",
		                                       priv->state);
		return;
	}

	connection = nm_simple_connection_new_from_dbus (properties, &error);
	if (!connection) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_VPN_PLUGIN_ERROR,
		                                       NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                                       "Invalid connection: (%d) %s",
		                                       error->code, error->message);
		g_clear_error (&error);
	}

	priv->interactive = FALSE;
	if (details && !vpn_class->connect_interactive) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_VPN_PLUGIN_ERROR,
		                                       NM_VPN_PLUGIN_ERROR_INTERACTIVE_NOT_SUPPORTED,
		                                       "Plugin does not implement ConnectInteractive()");
		return;
	}

	nm_vpn_plugin_old_set_state (plugin, NM_VPN_SERVICE_STATE_STARTING);

	if (details) {
		priv->interactive = TRUE;
		success = vpn_class->connect_interactive (plugin, connection, details, &error);
	} else
		success = vpn_class->connect (plugin, connection, &error);

	if (success) {
		g_dbus_method_invocation_return_value (context, NULL);

		/* Add a timer to make sure we do not wait indefinitely for the successful connect. */
		connect_timer_start (plugin);
	} else {
		g_dbus_method_invocation_take_error (context, error);

		/* Stop the plugin from an idle handler so that the Connect
		 * method return gets sent before the STOP StateChanged signal.
		 */
		schedule_fail_stop (plugin);
	}

	g_object_unref (connection);
}

static void
impl_vpn_plugin_old_connect (NMVpnPluginOld *plugin,
                             GDBusMethodInvocation *context,
                             GVariant *connection,
                             gpointer user_data)
{
	_connect_generic (plugin, context, connection, NULL);
}

static void
impl_vpn_plugin_old_connect_interactive (NMVpnPluginOld *plugin,
                                         GDBusMethodInvocation *context,
                                         GVariant *connection,
                                         GVariant *details,
                                         gpointer user_data)
{
	_connect_generic (plugin, context, connection, details);
}

/***************************************************************/

static void
impl_vpn_plugin_old_need_secrets (NMVpnPluginOld *plugin,
                                  GDBusMethodInvocation *context,
                                  GVariant *properties,
                                  gpointer user_data)
{
	NMConnection *connection;
	char *setting_name;
	gboolean needed;
	GError *error = NULL;

	connection = nm_simple_connection_new_from_dbus (properties, &error);
	if (!connection) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_VPN_PLUGIN_ERROR,
		                                       NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                                       "The connection was invalid: %s",
		                                       error->message);
		g_error_free (error);
		return;
	}

	if (!NM_VPN_PLUGIN_OLD_GET_CLASS (plugin)->need_secrets) {
		g_dbus_method_invocation_return_value (context,
		                                       g_variant_new ("(s)", ""));
		return;
	}

	needed = NM_VPN_PLUGIN_OLD_GET_CLASS (plugin)->need_secrets (plugin, connection, &setting_name, &error);
	if (error) {
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	if (needed) {
		g_assert (setting_name);
		g_dbus_method_invocation_return_value (context,
		                                       g_variant_new ("(s)", setting_name));
		g_free (setting_name);
	} else {
		/* No secrets required */
		g_dbus_method_invocation_return_value (context,
		                                       g_variant_new ("(s)", ""));
	}
}

static void
impl_vpn_plugin_old_new_secrets (NMVpnPluginOld *plugin,
                                 GDBusMethodInvocation *context,
                                 GVariant *properties,
                                 gpointer user_data)
{
	NMVpnPluginOldPrivate *priv = NM_VPN_PLUGIN_OLD_GET_PRIVATE (plugin);
	NMConnection *connection;
	GError *error = NULL;
	gboolean success;

	if (priv->state != NM_VPN_SERVICE_STATE_STARTING) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_VPN_PLUGIN_ERROR,
		                                       NM_VPN_PLUGIN_ERROR_WRONG_STATE,
		                                       "Could not accept new secrets: wrong plugin state %d",
		                                       priv->state);
		return;
	}

	connection = nm_simple_connection_new_from_dbus (properties, &error);
	if (!connection) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_VPN_PLUGIN_ERROR,
		                                       NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                                       "Invalid connection: (%d) %s",
		                                       error->code, error->message);
		g_clear_error (&error);
		return;
	}

	if (!NM_VPN_PLUGIN_OLD_GET_CLASS (plugin)->new_secrets) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_VPN_PLUGIN_ERROR,
		                                       NM_VPN_PLUGIN_ERROR_INTERACTIVE_NOT_SUPPORTED,
		                                       "Could not accept new secrets: plugin cannot process interactive secrets");
		g_object_unref (connection);
		return;
	}

	success = NM_VPN_PLUGIN_OLD_GET_CLASS (plugin)->new_secrets (plugin, connection, &error);
	if (success) {
		g_dbus_method_invocation_return_value (context, NULL);

		/* Add a timer to make sure we do not wait indefinitely for the successful connect. */
		connect_timer_start (plugin);
	} else {
		g_dbus_method_invocation_take_error (context, error);

		/* Stop the plugin from and idle handler so that the NewSecrets
		 * method return gets sent before the STOP StateChanged signal.
		 */
		schedule_fail_stop (plugin);
	}

	g_object_unref (connection);
}

/**
 * nm_vpn_plugin_old_secrets_required:
 * @plugin: the #NMVpnPluginOld
 * @message: an information message about why secrets are required, if any
 * @hints: VPN specific secret names for required new secrets
 *
 * Called by VPN plugin implementations to signal to NetworkManager that secrets
 * are required during the connection process.  This signal may be used to
 * request new secrets when the secrets originally provided by NetworkManager
 * are insufficient, or the VPN process indicates that it needs additional
 * information to complete the request.
 */
void
nm_vpn_plugin_old_secrets_required (NMVpnPluginOld *plugin,
                                    const char *message,
                                    const char **hints)
{
	NMVpnPluginOldPrivate *priv = NM_VPN_PLUGIN_OLD_GET_PRIVATE (plugin);

	/* Plugin must be able to accept the new secrets if it calls this method */
	g_return_if_fail (NM_VPN_PLUGIN_OLD_GET_CLASS (plugin)->new_secrets);

	/* Plugin cannot call this method if NetworkManager didn't originally call
	 * ConnectInteractive().
	 */
	g_return_if_fail (priv->interactive == TRUE);

	/* Cancel the connect timer since secrets might take a while.  It'll
	 * get restarted when the secrets come back via NewSecrets().
	 */
	if (priv->connect_timer)
		g_source_remove (priv->connect_timer);

	g_signal_emit (plugin, signals[SECRETS_REQUIRED], 0, message, hints);
}

/***************************************************************/

#define DATA_KEY_TAG "DATA_KEY="
#define DATA_VAL_TAG "DATA_VAL="
#define SECRET_KEY_TAG "SECRET_KEY="
#define SECRET_VAL_TAG "SECRET_VAL="

static void
free_secret (gpointer data)
{
	char *secret = data;

	memset (secret, 0, strlen (secret));
	g_free (secret);
}

/**
 * nm_vpn_plugin_old_read_vpn_details:
 * @fd: file descriptor to read from, usually stdin (0)
 * @out_data: (out) (transfer full): on successful return, a hash table
 * (mapping char*:char*) containing the key/value pairs of VPN data items
 * @out_secrets: (out) (transfer full): on successful return, a hash table
 * (mapping char*:char*) containing the key/value pairsof VPN secrets
 *
 * Parses key/value pairs from a file descriptor (normally stdin) passed by
 * an applet when the applet calls the authentication dialog of the VPN plugin.
 *
 * Returns: %TRUE if reading values was successful, %FALSE if not
 **/
gboolean
nm_vpn_plugin_old_read_vpn_details (int fd,
                                    GHashTable **out_data,
                                    GHashTable **out_secrets)
{
	GHashTable *data, *secrets;
	gboolean success = FALSE;
	char *key = NULL, *val = NULL;
	GString *line;
	gchar c;

	if (out_data)
		g_return_val_if_fail (*out_data == NULL, FALSE);
	if (out_secrets)
		g_return_val_if_fail (*out_secrets == NULL, FALSE);

	data = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	secrets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, free_secret);

	line = g_string_new (NULL);

	/* Read stdin for data and secret items until we get a DONE */
	while (1) {
		ssize_t nr;
		GHashTable *hash = NULL;

		errno = 0;
		nr = read (fd, &c, 1);
		if (nr == -1) {
			if (errno == EAGAIN) {
				g_usleep (100);
				continue;
			}
			break;
		}

		if (c != '\n') {
			g_string_append_c (line, c);
			continue;
		}

		/* Check for the finish marker */
		if (strcmp (line->str, "DONE") == 0)
			break;

		/* Otherwise it's a data/secret item */
		if (strncmp (line->str, DATA_KEY_TAG, strlen (DATA_KEY_TAG)) == 0) {
			hash = data;
			key = g_strdup (line->str + strlen (DATA_KEY_TAG));
		} else if (strncmp (line->str, DATA_VAL_TAG, strlen (DATA_VAL_TAG)) == 0) {
			hash = data;
			val = g_strdup (line->str + strlen (DATA_VAL_TAG));
		} else if (strncmp (line->str, SECRET_KEY_TAG, strlen (SECRET_KEY_TAG)) == 0) {
			hash = secrets;
			key = g_strdup (line->str + strlen (SECRET_KEY_TAG));
		} else if (strncmp (line->str, SECRET_VAL_TAG, strlen (SECRET_VAL_TAG)) == 0) {
			hash = secrets;
			val = g_strdup (line->str + strlen (SECRET_VAL_TAG));
		}
		g_string_truncate (line, 0);

		if (key && val && hash) {
			g_hash_table_insert (hash, key, val);
			key = NULL;
			val = NULL;
			success = TRUE;  /* Got at least one value */
		}
	}

	if (success) {
		if (out_data)
			*out_data = data;
		else
			g_hash_table_destroy (data);

		if (out_secrets)
			*out_secrets = secrets;
		else
			g_hash_table_destroy (secrets);
	} else {
		g_hash_table_destroy (data);
		g_hash_table_destroy (secrets);
	}

	g_string_free (line, TRUE);
	return success;
}

/**
 * nm_vpn_plugin_old_get_secret_flags:
 * @data: hash table containing VPN key/value pair data items
 * @secret_name: VPN secret key name for which to retrieve flags for
 * @out_flags: (out): on success, the flags associated with @secret_name
 *
 * Given a VPN secret key name, attempts to find the corresponding flags data
 * item in @data.  If found, converts the flags data item to
 * #NMSettingSecretFlags and returns it.
 *
 * Returns: %TRUE if the flag data item was found and successfully converted
 * to flags, %FALSE if not
 **/
gboolean
nm_vpn_plugin_old_get_secret_flags (GHashTable *data,
                                    const char *secret_name,
                                    NMSettingSecretFlags *out_flags)
{
	char *flag_name;
	const char *val;
	unsigned long tmp;
	gboolean success = FALSE;

	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (secret_name != NULL, FALSE);
	g_return_val_if_fail (out_flags != NULL, FALSE);
	g_return_val_if_fail (*out_flags == NM_SETTING_SECRET_FLAG_NONE, FALSE);

	flag_name = g_strdup_printf ("%s-flags", secret_name);

	/* Try new flags value first */
	val = g_hash_table_lookup (data, flag_name);
	if (val) {
		errno = 0;
		tmp = strtoul (val, NULL, 10);
		if (errno == 0 && tmp <= NM_SETTING_SECRET_FLAGS_ALL) {
			*out_flags = (NMSettingSecretFlags) tmp;
			success = TRUE;
		}
	}

	g_free (flag_name);
	return success;
}

/***************************************************************/

static void
impl_vpn_plugin_old_disconnect (NMVpnPluginOld *plugin,
                                GDBusMethodInvocation *context,
                                gpointer user_data)
{
	GError *error = NULL;

	if (nm_vpn_plugin_old_disconnect (plugin, &error))
		g_dbus_method_invocation_return_value (context, NULL);
	else
		g_dbus_method_invocation_take_error (context, error);
}

static void
impl_vpn_plugin_old_set_config (NMVpnPluginOld *plugin,
                                GDBusMethodInvocation *context,
                                GVariant *config,
                                gpointer user_data)
{
	nm_vpn_plugin_old_set_config (plugin, config);
	g_dbus_method_invocation_return_value (context, NULL);
}

static void
impl_vpn_plugin_old_set_ip4_config (NMVpnPluginOld *plugin,
                                    GDBusMethodInvocation *context,
                                    GVariant *config,
                                    gpointer user_data)
{
	nm_vpn_plugin_old_set_ip4_config (plugin, config);
	g_dbus_method_invocation_return_value (context, NULL);
}

static void
impl_vpn_plugin_old_set_ip6_config (NMVpnPluginOld *plugin,
                                    GDBusMethodInvocation *context,
                                    GVariant *config,
                                    gpointer user_data)
{
	nm_vpn_plugin_old_set_ip6_config (plugin, config);
	g_dbus_method_invocation_return_value (context, NULL);
}

static void
impl_vpn_plugin_old_set_failure (NMVpnPluginOld *plugin,
                                 GDBusMethodInvocation *context,
                                 char *reason,
                                 gpointer user_data)
{
	nm_vpn_plugin_old_failure (plugin, NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG);
	g_dbus_method_invocation_return_value (context, NULL);
}

/*********************************************************************/

static void
sigterm_handler (int signum)
{
	g_slist_foreach (active_plugins, (GFunc) nm_vpn_plugin_old_emit_quit, NULL);
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
nm_vpn_plugin_old_init (NMVpnPluginOld *plugin)
{
	active_plugins = g_slist_append (active_plugins, plugin);
	g_object_weak_ref (G_OBJECT (plugin),
	                   one_plugin_destroyed,
	                   NULL);
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMVpnPluginOld *plugin = NM_VPN_PLUGIN_OLD (initable);
	NMVpnPluginOldPrivate *priv = NM_VPN_PLUGIN_OLD_GET_PRIVATE (plugin);
	GDBusConnection *connection = NULL;
	GDBusProxy *proxy;
	GVariant *ret;
	gboolean success = FALSE;

	if (!priv->dbus_service_name) {
		g_set_error_literal (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                     _("No service name specified"));
		return FALSE;
	}

	connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, error);
	if (!connection)
		return FALSE;

	proxy = g_dbus_proxy_new_sync (connection,
	                               G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                               G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
	                               NULL,
	                               DBUS_SERVICE_DBUS,
	                               DBUS_PATH_DBUS,
	                               DBUS_INTERFACE_DBUS,
	                               cancellable, error);
	if (!proxy)
		goto out;

	ret = g_dbus_proxy_call_sync (proxy,
	                              "RequestName",
	                              g_variant_new ("(su)", priv->dbus_service_name, 0),
	                              G_DBUS_CALL_FLAGS_NONE, -1,
	                              cancellable, error);
	g_object_unref (proxy);
	if (!ret) {
		if (error && *error)
			g_dbus_error_strip_remote_error (*error);
		goto out;
	}
	g_variant_unref (ret);

	priv->dbus_vpn_plugin_old = nmdbus_vpn_plugin_skeleton_new ();
	if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (priv->dbus_vpn_plugin_old),
	                                       connection,
	                                       NM_VPN_DBUS_PLUGIN_PATH,
	                                       error))
		goto out;

	_nm_dbus_bind_properties (plugin, priv->dbus_vpn_plugin_old);
	_nm_dbus_bind_methods (plugin, priv->dbus_vpn_plugin_old,
	                       "Connect", impl_vpn_plugin_old_connect,
	                       "ConnectInteractive", impl_vpn_plugin_old_connect_interactive,
	                       "NeedSecrets", impl_vpn_plugin_old_need_secrets,
	                       "NewSecrets", impl_vpn_plugin_old_new_secrets,
	                       "Disconnect", impl_vpn_plugin_old_disconnect,
	                       "SetConfig", impl_vpn_plugin_old_set_config,
	                       "SetIp4Config", impl_vpn_plugin_old_set_ip4_config,
	                       "SetIp6Config", impl_vpn_plugin_old_set_ip6_config,
	                       "SetFailure", impl_vpn_plugin_old_set_failure,
	                       NULL);

	nm_vpn_plugin_old_set_connection (plugin, connection);
	nm_vpn_plugin_old_set_state (plugin, NM_VPN_SERVICE_STATE_INIT);

	success = TRUE;

 out:
	g_clear_object (&connection);

	return success;
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMVpnPluginOldPrivate *priv = NM_VPN_PLUGIN_OLD_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_DBUS_SERVICE_NAME:
		/* Construct-only */
		priv->dbus_service_name = g_value_dup_string (value);
		break;
	case PROP_STATE:
		nm_vpn_plugin_old_set_state (NM_VPN_PLUGIN_OLD (object),
		                             (NMVpnServiceState) g_value_get_enum (value));
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
	NMVpnPluginOldPrivate *priv = NM_VPN_PLUGIN_OLD_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_DBUS_SERVICE_NAME:
		g_value_set_string (value, priv->dbus_service_name);
		break;
	case PROP_STATE:
		g_value_set_enum (value, nm_vpn_plugin_old_get_state (NM_VPN_PLUGIN_OLD (object)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMVpnPluginOld *plugin = NM_VPN_PLUGIN_OLD (object);
	NMVpnPluginOldPrivate *priv = NM_VPN_PLUGIN_OLD_GET_PRIVATE (plugin);
	NMVpnServiceState state;
	GError *err = NULL;

	if (priv->fail_stop_id) {
		g_source_remove (priv->fail_stop_id);
		priv->fail_stop_id = 0;
	}

	state = nm_vpn_plugin_old_get_state (plugin);

	if (state == NM_VPN_SERVICE_STATE_STARTED ||
	    state == NM_VPN_SERVICE_STATE_STARTING)
		nm_vpn_plugin_old_disconnect (plugin, &err);

	if (err) {
		g_warning ("Error disconnecting VPN connection: %s", err->message);
		g_error_free (err);
	}

	G_OBJECT_CLASS (nm_vpn_plugin_old_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMVpnPluginOld *plugin = NM_VPN_PLUGIN_OLD (object);
	NMVpnPluginOldPrivate *priv = NM_VPN_PLUGIN_OLD_GET_PRIVATE (plugin);

	nm_vpn_plugin_old_set_connection (plugin, NULL);
	g_free (priv->dbus_service_name);

	g_clear_pointer (&priv->banner, g_free);
	g_clear_pointer (&priv->tundev, g_free);
	g_clear_pointer (&priv->gateway, g_free);
	g_clear_pointer (&priv->mtu, g_free);

	G_OBJECT_CLASS (nm_vpn_plugin_old_parent_class)->finalize (object);
}

static void
quit_timer_removed (gpointer data)
{
	NM_VPN_PLUGIN_OLD_GET_PRIVATE (data)->quit_timer = 0;
}

static void
state_changed (NMVpnPluginOld *plugin, NMVpnServiceState state)
{
	NMVpnPluginOldPrivate *priv = NM_VPN_PLUGIN_OLD_GET_PRIVATE (plugin);

	switch (state) {
	case NM_VPN_SERVICE_STATE_STARTING:
		/* Remove the quit timer. */
		if (priv->quit_timer)
			g_source_remove (priv->quit_timer);

		if (priv->fail_stop_id) {
			g_source_remove (priv->fail_stop_id);
			priv->fail_stop_id = 0;
		}
		break;
	case NM_VPN_SERVICE_STATE_STOPPED:
		priv->quit_timer = g_timeout_add_seconds_full (G_PRIORITY_DEFAULT,
		                                               NM_VPN_PLUGIN_OLD_QUIT_TIMER,
		                                               quit_timer_expired,
		                                               plugin,
		                                               quit_timer_removed);
		break;
	default:
		/* Clean up all timers we might have set up. */
		if (priv->connect_timer)
			g_source_remove (priv->connect_timer);

		if (priv->quit_timer)
			g_source_remove (priv->quit_timer);

		if (priv->fail_stop_id) {
			g_source_remove (priv->fail_stop_id);
			priv->fail_stop_id = 0;
		}
		break;
	}
}

static void
nm_vpn_plugin_old_class_init (NMVpnPluginOldClass *plugin_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (plugin_class);

	g_type_class_add_private (object_class, sizeof (NMVpnPluginOldPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose      = dispose;
	object_class->finalize     = finalize;

	plugin_class->state_changed = state_changed;

	/* properties */

	/**
	 * NMVpnPluginOld:service-name:
	 *
	 * The D-Bus service name of this plugin.
	 */
	g_object_class_install_property
		(object_class, PROP_DBUS_SERVICE_NAME,
		 g_param_spec_string (NM_VPN_PLUGIN_OLD_DBUS_SERVICE_NAME, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMVpnPluginOld:state:
	 *
	 * The state of the plugin.
	 */
	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_enum (NM_VPN_PLUGIN_OLD_STATE, "", "",
		                    NM_TYPE_VPN_SERVICE_STATE,
		                    NM_VPN_SERVICE_STATE_INIT,
		                    G_PARAM_READWRITE |
		                    G_PARAM_STATIC_STRINGS));

	/* signals */
	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMVpnPluginOldClass, state_changed),
		              NULL, NULL,
		              NULL,
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
		              G_STRUCT_OFFSET (NMVpnPluginOldClass, config),
		              NULL, NULL,
		              NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_VARIANT);

	signals[IP4_CONFIG] =
		g_signal_new ("ip4-config",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMVpnPluginOldClass, ip4_config),
		              NULL, NULL,
		              NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_VARIANT);

	signals[IP6_CONFIG] =
		g_signal_new ("ip6-config",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMVpnPluginOldClass, ip6_config),
		              NULL, NULL,
		              NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_VARIANT);

	signals[LOGIN_BANNER] =
		g_signal_new ("login-banner",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMVpnPluginOldClass, login_banner),
		              NULL, NULL,
		              NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_STRING);

	signals[FAILURE] =
		g_signal_new ("failure",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMVpnPluginOldClass, failure),
		              NULL, NULL,
		              NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_UINT);

	signals[QUIT] =
		g_signal_new ("quit",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMVpnPluginOldClass, quit),
		              NULL, NULL,
		              NULL,
		              G_TYPE_NONE, 0,
		              G_TYPE_NONE);

	setup_unix_signal_handler ();
}

static void
nm_vpn_plugin_old_initable_iface_init (GInitableIface *iface)
{
	iface->init = init_sync;
}
