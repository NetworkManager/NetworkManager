/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2005 Red Hat, Inc.
 */


#include <glib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "NetworkManagerVPN.h"
#include "nm-vpn-connection.h"
#include "nm-setting-connection.h"
#include "nm-setting-vpn.h"
#include "nm-dbus-manager.h"
#include "nm-manager.h"
#include "NetworkManagerSystem.h"
#include "nm-utils.h"
#include "nm-vpn-plugin-bindings.h"
#include "nm-marshal.h"

static gboolean impl_vpn_connection_disconnect (NMVPNConnection *connection, GError **err);

#define CONNECTION_GET_SECRETS_CALL_TAG "get-secrets-call"

#include "nm-vpn-connection-glue.h"

G_DEFINE_TYPE (NMVPNConnection, nm_vpn_connection, G_TYPE_OBJECT)

typedef struct {
	NMConnection *connection;
	NMDevice *parent_dev;
	char *object_path;
	
	NMVPNConnectionState state;
	gulong device_monitor;
	DBusGProxy *proxy;
	guint ipconfig_timeout;
	NMIP4Config *ip4_config;
	char *tundev;
	char *banner;
} NMVPNConnectionPrivate;

#define NM_VPN_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_CONNECTION, NMVPNConnectionPrivate))

enum {
	STATE_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_NAME,
	PROP_STATE,
	PROP_BANNER,

	LAST_PROP
};

static void
nm_vpn_connection_set_state (NMVPNConnection *connection,
                             NMVPNConnectionState state,
                             NMVPNConnectionStateReason reason)
{
	NMVPNConnectionPrivate *priv;

	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	if (state == priv->state)
		return;

	priv->state = state;

	g_object_ref (connection);
	g_signal_emit (connection, signals[STATE_CHANGED], 0, state, reason);
	g_object_unref (connection);
}

static void
device_state_changed (NMDevice *device, NMDeviceState state, gpointer user_data)
{
	NMVPNConnection *connection = NM_VPN_CONNECTION (user_data);

	if (state == NM_DEVICE_STATE_DISCONNECTED) {
		nm_vpn_connection_set_state (connection,
		                             NM_VPN_CONNECTION_STATE_DISCONNECTED,
		                             NM_VPN_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED);
	}
}

NMVPNConnection *
nm_vpn_connection_new (NMConnection *connection,
				   NMDevice *parent_device)
{
	NMVPNConnection *vpn_connection;
	NMVPNConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (NM_IS_DEVICE (parent_device), NULL);

	vpn_connection = (NMVPNConnection *) g_object_new (NM_TYPE_VPN_CONNECTION, NULL);
	if (!vpn_connection)
		return NULL;

	priv = NM_VPN_CONNECTION_GET_PRIVATE (vpn_connection);

	priv->connection = g_object_ref (connection);
	priv->parent_dev = g_object_ref (parent_device);

	priv->device_monitor = g_signal_connect (parent_device, "state-changed",
									 G_CALLBACK (device_state_changed),
									 vpn_connection);
	return vpn_connection;
}

static char *
nm_vpn_connection_get_service (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	NMSettingVPN *setting;

	setting = (NMSettingVPN *) nm_connection_get_setting (priv->connection, NM_TYPE_SETTING_VPN);
	return setting->service_type;
}

static GSList *
nm_vpn_connection_get_routes (NMVPNConnection *connection)
{
	NMSettingVPN *setting;

	setting = (NMSettingVPN *) nm_connection_get_setting (NM_VPN_CONNECTION_GET_PRIVATE (connection)->connection,
											    NM_TYPE_SETTING_VPN);

	return setting->routes;
}

static void
plugin_state_changed (DBusGProxy *proxy,
				  NMVPNServiceState state,
				  gpointer user_data)
{
	NMVPNConnection *connection = NM_VPN_CONNECTION (user_data);

	nm_debug ("plugin state changed: %d", state);

	if (state == NM_VPN_SERVICE_STATE_STOPPED) {
		switch (nm_vpn_connection_get_state (connection)) {
		case NM_VPN_CONNECTION_STATE_CONNECT:
		case NM_VPN_CONNECTION_STATE_IP_CONFIG_GET:
			nm_vpn_connection_set_state (connection,
			                             NM_VPN_CONNECTION_STATE_FAILED,
			                             NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED);
			break;
		case NM_VPN_CONNECTION_STATE_ACTIVATED:
			nm_vpn_connection_set_state (connection,
			                             NM_VPN_CONNECTION_STATE_DISCONNECTED,
			                             NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED);
			break;
		default:
			break;
		}
	}
}

static void
print_vpn_config (NMIP4Config *config,
			   const char *tundev,
			   const char *banner)
{
	struct in_addr temp_addr;
	char *         dns_domain = NULL;
	guint32        num;
	guint32        i;

	g_return_if_fail (config != NULL);

	temp_addr.s_addr = nm_ip4_config_get_gateway (config);
	nm_info ("VPN Gateway: %s", inet_ntoa (temp_addr));
	nm_info ("Tunnel Device: %s", tundev);
	temp_addr.s_addr = nm_ip4_config_get_address (config);
	nm_info ("Internal IP4 Address: %s", inet_ntoa (temp_addr));
	temp_addr.s_addr = nm_ip4_config_get_netmask (config);
	nm_info ("Internal IP4 Netmask: %s", inet_ntoa (temp_addr));
	temp_addr.s_addr = nm_ip4_config_get_ptp_address (config);
	nm_info ("Internal IP4 Point-to-Point Address: %s", inet_ntoa (temp_addr));
	nm_info ("Maximum Segment Size (MSS): %d", nm_ip4_config_get_mss (config));

	num = nm_ip4_config_get_num_nameservers (config);
	for (i = 0; i < num; i++) {
		temp_addr.s_addr = nm_ip4_config_get_nameserver (config, i);
		nm_info ("Internal IP4 DNS: %s", inet_ntoa (temp_addr));
	}

	if (nm_ip4_config_get_num_domains (config) > 0)
		dns_domain = (char *) nm_ip4_config_get_domain (config, 0);
	nm_info ("DNS Domain: '%s'", dns_domain ? dns_domain : "(none)");
	nm_info ("Login Banner:");
	nm_info ("-----------------------------------------");
	nm_info ("%s", banner);
	nm_info ("-----------------------------------------");
}

static void
nm_vpn_connection_ip4_config_get (DBusGProxy *proxy,
						    GHashTable *config_hash,
						    gpointer user_data)
{
	NMVPNConnection *connection = NM_VPN_CONNECTION (user_data);
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	NMIP4Config *config;
	GValue *val;
	int i;

	nm_info ("VPN connection '%s' (IP Config Get) reply received.",
		    nm_vpn_connection_get_name (connection));

	g_source_remove (priv->ipconfig_timeout);
	priv->ipconfig_timeout = 0;

	config = nm_ip4_config_new ();
	nm_ip4_config_set_secondary (config, TRUE);

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_GATEWAY);
	if (val)
		nm_ip4_config_set_gateway (config, g_value_get_uint (val));

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS);
	if (val)
		nm_ip4_config_set_address (config, g_value_get_uint (val));

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_PTP);
	if (val)
		nm_ip4_config_set_ptp_address (config, g_value_get_uint (val));

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_NETMASK);
	if (val)
		nm_ip4_config_set_netmask (config, g_value_get_uint (val));
	else
		/* If no netmask, default to Class C address */
		nm_ip4_config_set_netmask (config, 0x00FF);

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_DNS);
	if (val) {
		GArray *dns = (GArray *) g_value_get_boxed (val);

		for (i = 0; i < dns->len; i++)
			nm_ip4_config_add_nameserver (config, g_array_index (dns, guint, i));
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_NBNS);
	if (val) {
		GArray *nbns = (GArray *) g_value_get_boxed (val);

		for (i = 0; i < nbns->len; i++)
			nm_ip4_config_add_nameserver (config, g_array_index (nbns, guint, i));
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_MSS);
	if (val)
		nm_ip4_config_set_mss (config, g_value_get_uint (val));

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_MTU);
	if (val)
		nm_ip4_config_set_mtu (config, g_value_get_uint (val));

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV);
	if (val)
		priv->tundev = g_strdup (g_value_get_string (val));

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN);
	if (val)
		nm_ip4_config_add_domain (config, g_value_get_string (val));

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_BANNER);
	if (val) {
		if (priv->banner)
			g_free (priv->banner);
		priv->banner = g_strdup (g_value_get_string (val));
	}

	print_vpn_config (config, priv->tundev, priv->banner);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	priv->ip4_config = config;

	if (nm_system_vpn_device_set_from_ip4_config (priv->parent_dev, priv->tundev, priv->ip4_config,
										 nm_vpn_connection_get_routes (connection))) {
		nm_info ("VPN connection '%s' (IP Config Get) complete.",
			    nm_vpn_connection_get_name (connection));
		nm_vpn_connection_set_state (connection,
		                             NM_VPN_CONNECTION_STATE_ACTIVATED,
		                             NM_VPN_CONNECTION_STATE_REASON_NONE);
	} else {
		nm_warning ("VPN connection '%s' did not receive valid IP config information.",
				  nm_vpn_connection_get_name (connection));
		nm_vpn_connection_set_state (connection,
		                             NM_VPN_CONNECTION_STATE_FAILED,
		                             NM_VPN_CONNECTION_STATE_REASON_IP_CONFIG_INVALID);
	}
}

static gboolean
nm_vpn_connection_ip_config_timeout (gpointer user_data)
{
	NMVPNConnection *connection = NM_VPN_CONNECTION (user_data);
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	priv->ipconfig_timeout = 0;

	/* If the activation request's state is still IP_CONFIG_GET and we're
	 * in this timeout, cancel activation because it's taken too long.
	 */
	if (nm_vpn_connection_get_state (connection) == NM_VPN_CONNECTION_STATE_IP_CONFIG_GET) {
		nm_info ("VPN connection '%s' (IP Config Get) timeout exceeded.",
		         nm_vpn_connection_get_name (connection));
		nm_vpn_connection_set_state (connection,
		                             NM_VPN_CONNECTION_STATE_FAILED,
		                             NM_VPN_CONNECTION_STATE_REASON_CONNECT_TIMEOUT);
	}

	return FALSE;
}

static void
nm_vpn_connection_connect_cb (DBusGProxy *proxy, GError *err, gpointer user_data)
{
	NMVPNConnection *connection = NM_VPN_CONNECTION (user_data);
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	nm_info ("VPN connection '%s' (Connect) reply received.",
		    nm_vpn_connection_get_name (connection));

	if (err) {
		nm_warning ("(VPN connection '%s' could not start.  dbus says: '%s'.", 
				  nm_vpn_connection_get_name (connection), err->message);
		nm_vpn_connection_set_state (connection,
		                             NM_VPN_CONNECTION_STATE_FAILED,
		                             NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED);
	} else {
		nm_vpn_connection_set_state (connection,
		                             NM_VPN_CONNECTION_STATE_IP_CONFIG_GET,
		                             NM_VPN_CONNECTION_STATE_REASON_NONE);
		
		/* 40 second timeout waiting for IP config signal from VPN service */
		priv->ipconfig_timeout = g_timeout_add (40000, nm_vpn_connection_ip_config_timeout, connection);
	}
}

static void
really_activate (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv;

	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));
	g_return_if_fail (nm_vpn_connection_get_state (connection) == NM_VPN_CONNECTION_STATE_NEED_AUTH);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	/* Ip4Config signal */
	dbus_g_object_register_marshaller (g_cclosure_marshal_VOID__BOXED,
								G_TYPE_NONE, G_TYPE_VALUE, G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->proxy, "Ip4Config",
						dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
						G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Ip4Config",
						    G_CALLBACK (nm_vpn_connection_ip4_config_get),
						    connection, NULL);

	org_freedesktop_NetworkManager_VPN_Plugin_connect_async (priv->proxy,
												  nm_connection_to_hash (priv->connection),
												  nm_vpn_connection_connect_cb,
												  connection);

	nm_vpn_connection_set_state (connection,
	                             NM_VPN_CONNECTION_STATE_CONNECT,
	                             NM_VPN_CONNECTION_STATE_REASON_NONE);
}

void
nm_vpn_connection_activate (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv;
	NMDBusManager *dbus_mgr;

	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));
	g_return_if_fail (nm_vpn_connection_get_state (connection) == NM_VPN_CONNECTION_STATE_PREPARE);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	dbus_mgr = nm_dbus_manager_get ();
	priv->proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (dbus_mgr),
	                                         nm_vpn_connection_get_service (connection),
	                                         NM_VPN_DBUS_PLUGIN_PATH,
	                                         NM_VPN_DBUS_PLUGIN_INTERFACE);
	g_object_unref (dbus_mgr);

	/* StateChanged signal */
	dbus_g_proxy_add_signal (priv->proxy, "StateChanged", G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "StateChanged",
						    G_CALLBACK (plugin_state_changed),
						    connection, NULL);

	nm_vpn_connection_set_state (connection,
	                             NM_VPN_CONNECTION_STATE_NEED_AUTH,
	                             NM_VPN_CONNECTION_STATE_REASON_NONE);
}

const char *
nm_vpn_connection_get_object_path (NMVPNConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->object_path;
}

const char *
nm_vpn_connection_get_name (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv;
	NMSettingConnection *setting;

	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NULL);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	setting = (NMSettingConnection *) nm_connection_get_setting (priv->connection, NM_TYPE_SETTING_CONNECTION);

	return setting->id;
}

NMVPNConnectionState
nm_vpn_connection_get_state (NMVPNConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NM_VPN_CONNECTION_STATE_UNKNOWN);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->state;
}

const char *
nm_vpn_connection_get_banner (NMVPNConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->banner;
}

void
nm_vpn_connection_fail (NMVPNConnection *connection,
                        NMVPNConnectionStateReason reason)
{
	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));

	nm_vpn_connection_set_state (connection,
	                             NM_VPN_CONNECTION_STATE_FAILED,
	                             reason);
}

void
nm_vpn_connection_disconnect (NMVPNConnection *connection,
                              NMVPNConnectionStateReason reason)
{
	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));

	nm_vpn_connection_set_state (connection,
	                             NM_VPN_CONNECTION_STATE_DISCONNECTED,
	                             reason);
}

static gboolean
impl_vpn_connection_disconnect (NMVPNConnection *connection, GError **err)
{
	nm_vpn_connection_disconnect (connection, NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED);

	return TRUE;
}

/******************************************************************************/

static void
clear_need_auth (NMVPNConnection *vpn_connection)
{
	NMVPNConnectionPrivate *priv;
	DBusGProxy *proxy;
	DBusGProxyCall *call;

	g_return_if_fail (vpn_connection != NULL);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (vpn_connection);
	g_assert (priv->connection);

	proxy = g_object_get_data (G_OBJECT (priv->connection), NM_MANAGER_CONNECTION_SECRETS_PROXY_TAG);
	if (!proxy || !DBUS_IS_G_PROXY (proxy))
		return;

	call = g_object_get_data (G_OBJECT (vpn_connection), CONNECTION_GET_SECRETS_CALL_TAG);
	if (!call)
		return;

	dbus_g_proxy_cancel_call (proxy, call);
	g_object_set_data (G_OBJECT (vpn_connection), CONNECTION_GET_SECRETS_CALL_TAG, NULL);
}

typedef struct GetSecretsInfo {
	NMVPNConnection *vpn_connection;
	char *setting_name;
} GetSecretsInfo;

static void
free_get_secrets_info (gpointer data)
{
	GetSecretsInfo * info = (GetSecretsInfo *) data;

	g_free (info->setting_name);
	if (info->vpn_connection)
		g_object_unref (info->vpn_connection);
	g_slice_free (GetSecretsInfo, info);
}

static void
get_secrets_cb (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	GetSecretsInfo *info = (GetSecretsInfo *) user_data;
	NMVPNConnectionPrivate *priv;
	GError *err = NULL;
	GHashTable *secrets = NULL;

	if (!info || !info->vpn_connection || !info->setting_name)
		goto error;

	priv = NM_VPN_CONNECTION_GET_PRIVATE (info->vpn_connection);

	g_object_set_data (G_OBJECT (info->vpn_connection), CONNECTION_GET_SECRETS_CALL_TAG, NULL);

	if (!dbus_g_proxy_end_call (proxy, call, &err,
								dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE), &secrets,
								G_TYPE_INVALID)) {
		nm_warning ("Couldn't get connection secrets: %s.", err->message);
		g_error_free (err);
		goto error;
	}

	if (g_hash_table_size (secrets) == 0) {
		// FIXME: some better way to handle invalid message?
		nm_warning ("GetSecrets call returned but no secrets were found.");
		goto error;
	}

	nm_connection_update_secrets (priv->connection, info->setting_name, secrets);
	g_hash_table_destroy (secrets);
	really_activate (info->vpn_connection);
	return;

error:
	nm_vpn_connection_fail (info->vpn_connection, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS);
}

#define DBUS_TYPE_STRING_ARRAY   (dbus_g_type_get_collection ("GPtrArray", G_TYPE_STRING))

static gboolean
get_connection_secrets (NMVPNConnection *vpn_connection,
                        const char *setting_name,
                        gboolean request_new)
{
	NMVPNConnectionPrivate *priv;
	DBusGProxy *secrets_proxy;
	GetSecretsInfo *info = NULL;
	DBusGProxyCall *call;
	GPtrArray *hints;

	g_return_val_if_fail (vpn_connection != NULL, FALSE);
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn_connection), FALSE);
	g_return_val_if_fail (setting_name != NULL, FALSE);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (vpn_connection);
	g_assert (priv->connection);

	secrets_proxy = g_object_get_data (G_OBJECT (priv->connection),
	                                   NM_MANAGER_CONNECTION_SECRETS_PROXY_TAG);
	g_return_val_if_fail (secrets_proxy && DBUS_IS_G_PROXY (secrets_proxy), FALSE);

	info = g_slice_new0 (GetSecretsInfo);
	g_return_val_if_fail (info != NULL, FALSE);

	info->setting_name = g_strdup (setting_name);
	if (!info->setting_name) {
		nm_warning ("Not enough memory to get secrets");
		goto error;
	}

	info->vpn_connection = g_object_ref (vpn_connection);

	/* Empty for now... */
	hints = g_ptr_array_new ();

	/* use ..._with_timeout to give the user time to enter secrets */
	call = dbus_g_proxy_begin_call_with_timeout (secrets_proxy, "GetSecrets",
	                                             get_secrets_cb,
	                                             info,
	                                             free_get_secrets_info,
	                                             G_MAXINT32,
	                                             G_TYPE_STRING, setting_name,
	                                             DBUS_TYPE_STRING_ARRAY, hints,
	                                             G_TYPE_BOOLEAN, request_new,
	                                             G_TYPE_INVALID);
	g_ptr_array_free (hints, TRUE);
	if (!call) {
		nm_warning ("Could not call GetSecrets");
		goto error;
	}

	g_object_set_data (G_OBJECT (vpn_connection),
	                   CONNECTION_GET_SECRETS_CALL_TAG,
	                   call);
	return TRUE;

error:
	if (info)
		free_get_secrets_info (info);
	return FALSE;
}

static void
connection_need_secrets_cb  (DBusGProxy *proxy,
                             char *setting_name,
                             GError *error,
                             gpointer user_data)
{
	NMVPNConnection *vpn_connection = NM_VPN_CONNECTION (user_data);

	g_object_set_data (G_OBJECT (vpn_connection),
	                   CONNECTION_GET_SECRETS_CALL_TAG,
	                   NULL);

	if (error) {
		g_warning ("%s.%d: NeedSecrets failed: %s %s",
		           __FILE__, __LINE__,
		           g_quark_to_string (error->domain), error->message);
		nm_vpn_connection_fail (vpn_connection, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS);
		return;
	}

	if (setting_name && strlen (setting_name)) {
		if (!get_connection_secrets (vpn_connection, setting_name, FALSE))
			nm_vpn_connection_fail (vpn_connection, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS);
	} else {
		/* No secrets needed */
		really_activate (vpn_connection);
	}
}

static void
call_need_secrets (NMVPNConnection *vpn_connection)
{
	NMVPNConnectionPrivate *priv;
	GHashTable *settings;

	priv = NM_VPN_CONNECTION_GET_PRIVATE (vpn_connection);
	settings = nm_connection_to_hash (priv->connection);
	org_freedesktop_NetworkManager_VPN_Plugin_need_secrets_async (priv->proxy,
	                         settings,
	                         connection_need_secrets_cb,
	                         vpn_connection);
	g_hash_table_destroy (settings);
}

static void
connection_state_changed (NMVPNConnection *connection,
                          NMVPNConnectionState state,
                          NMVPNConnectionStateReason reason)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	clear_need_auth (connection);

	switch (state) {
	case NM_VPN_CONNECTION_STATE_NEED_AUTH:
		call_need_secrets (connection);
		break;
	case NM_VPN_CONNECTION_STATE_DISCONNECTED:
	case NM_VPN_CONNECTION_STATE_FAILED:
		if (priv->proxy) {
			GError *err = NULL;

			org_freedesktop_NetworkManager_VPN_Plugin_disconnect (priv->proxy, &err);
			if (err) {
				nm_warning ("%s", err->message);
				g_error_free (err);
			}

			g_object_unref (priv->proxy);
			priv->proxy = NULL;
		}

		if (priv->tundev) {
			nm_system_device_set_up_down_with_iface (priv->tundev, FALSE);
			nm_system_device_flush_routes_with_iface (priv->tundev);
			nm_system_device_flush_addresses_with_iface (priv->tundev);
		}

		if (priv->ip4_config) {
			/* Remove attributes of the VPN's IP4 Config */
			nm_system_vpn_device_unset_from_ip4_config (priv->parent_dev, priv->tundev, priv->ip4_config);

			/* Reset routes, nameservers, and domains of the currently active device */
			nm_system_device_set_from_ip4_config (priv->parent_dev);
		}

		if (priv->banner) {
			g_free (priv->banner);
			priv->banner = NULL;
		}
		break;
	default:
		break;
	}
}

static void
nm_vpn_connection_init (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	NMDBusManager *dbus_mgr;
	static guint32 counter = 0;

	priv->state = NM_VPN_CONNECTION_STATE_PREPARE;
	priv->object_path = g_strdup_printf (NM_DBUS_PATH_VPN_CONNECTION "/%d", counter++);

	dbus_mgr = nm_dbus_manager_get ();
	dbus_g_connection_register_g_object (nm_dbus_manager_get_connection (dbus_mgr),
								  priv->object_path,
								  G_OBJECT (connection));
	g_object_unref (dbus_mgr);
}

static void
finalize (GObject *object)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);

	if (priv->parent_dev) {
		if (priv->device_monitor)
			g_signal_handler_disconnect (priv->parent_dev, priv->device_monitor);

		g_object_unref (priv->parent_dev);
	}

	if (priv->banner)
		g_free (priv->banner);

	g_free (priv->tundev);

	if (priv->ip4_config)
		g_object_unref (priv->ip4_config);

	if (priv->ipconfig_timeout)
		g_source_remove (priv->ipconfig_timeout);

	if (priv->proxy)
		g_object_unref (priv->proxy);

	g_object_unref (priv->connection);

	g_free (priv->object_path);

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	const char *tmp;

	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, nm_vpn_connection_get_name (NM_VPN_CONNECTION (object)));
		break;
	case PROP_STATE:
		g_value_set_uint (value, nm_vpn_connection_get_state (NM_VPN_CONNECTION (object)));
		break;
	case PROP_BANNER:
		tmp = nm_vpn_connection_get_banner (NM_VPN_CONNECTION (object));
		g_value_set_string (value, tmp ? tmp : "");
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_vpn_connection_class_init (NMVPNConnectionClass *connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (connection_class);

	g_type_class_add_private (connection_class, sizeof (NMVPNConnectionPrivate));

	/* virtual methods */
	connection_class->state_changed = connection_state_changed;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_NAME,
		 g_param_spec_string (NM_VPN_CONNECTION_NAME,
						  "Name",
						  "Connection name",
						  NULL,
						  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_uint (NM_VPN_CONNECTION_STATE,
						"State",
						"Current state",
						NM_VPN_CONNECTION_STATE_UNKNOWN,
						NM_VPN_CONNECTION_STATE_DISCONNECTED,
						NM_VPN_CONNECTION_STATE_UNKNOWN,
						G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_BANNER,
		 g_param_spec_string (NM_VPN_CONNECTION_BANNER,
						  "Banner",
						  "Login Banner",
						  NULL,
						  G_PARAM_READABLE));

	/* signals */
	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMVPNConnectionClass, state_changed),
				    NULL, NULL,
				    nm_marshal_VOID__UINT_UINT,
				    G_TYPE_NONE, 2,
				    G_TYPE_UINT, G_TYPE_UINT);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (connection_class),
							   &dbus_glib_nm_vpn_connection_object_info);
}
