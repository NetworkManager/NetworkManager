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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2008 Red Hat, Inc.
 */


#include <glib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>

#include "NetworkManager.h"
#include "NetworkManagerVPN.h"
#include "nm-vpn-connection.h"
#include "nm-setting-connection.h"
#include "nm-setting-vpn.h"
#include "nm-setting-vpn-properties.h"
#include "nm-setting-ip4-config.h"
#include "nm-dbus-manager.h"
#include "nm-manager.h"
#include "NetworkManagerSystem.h"
#include "nm-utils.h"
#include "nm-vpn-plugin-bindings.h"
#include "nm-marshal.h"
#include "nm-active-connection.h"
#include "nm-properties-changed-signal.h"
#include "nm-dbus-glib-types.h"
#include "NetworkManagerUtils.h"

#include "nm-vpn-connection-glue.h"

G_DEFINE_TYPE (NMVPNConnection, nm_vpn_connection, G_TYPE_OBJECT)

typedef struct {
	gboolean disposed;

	NMConnection *connection;
	DBusGProxyCall *secrets_call;

	NMActRequest *act_request;
	NMDevice *parent_dev;
	char *ac_path;

	gboolean is_default;
	NMActiveConnectionState state;

	NMVPNConnectionState vpn_state;
	gulong device_monitor;
	DBusGProxy *proxy;
	guint ipconfig_timeout;
	NMIP4Config *ip4_config;
	char *tundev;
	char *tapdev;
	char *banner;
} NMVPNConnectionPrivate;

#define NM_VPN_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_CONNECTION, NMVPNConnectionPrivate))

enum {
	PROPERTIES_CHANGED,
	VPN_STATE_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_SERVICE_NAME,
	PROP_CONNECTION,
	PROP_SPECIFIC_OBJECT,
	PROP_DEVICES,
	PROP_STATE,
	PROP_DEFAULT,
	PROP_VPN,
	PROP_VPN_STATE,
	PROP_BANNER,

	LAST_PROP
};

static void
nm_vpn_connection_set_vpn_state (NMVPNConnection *connection,
                                 NMVPNConnectionState vpn_state,
                                 NMVPNConnectionStateReason reason)
{
	NMVPNConnectionPrivate *priv;
	NMActiveConnectionState new_ac_state;
	NMVPNConnectionState old_vpn_state;

	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	if (vpn_state == priv->vpn_state)
		return;

	old_vpn_state = priv->vpn_state;
	priv->vpn_state = vpn_state;

	/* Set the NMActiveConnection state based on VPN state */
	switch (vpn_state) {
	case NM_VPN_CONNECTION_STATE_PREPARE:
	case NM_VPN_CONNECTION_STATE_NEED_AUTH:
	case NM_VPN_CONNECTION_STATE_CONNECT:
	case NM_VPN_CONNECTION_STATE_IP_CONFIG_GET:
		new_ac_state = NM_ACTIVE_CONNECTION_STATE_ACTIVATING;
		break;
	case NM_VPN_CONNECTION_STATE_ACTIVATED:
		new_ac_state = NM_ACTIVE_CONNECTION_STATE_ACTIVATED;
		break;
	default:
		new_ac_state = NM_ACTIVE_CONNECTION_STATE_UNKNOWN;
		break;
	}

	if (new_ac_state != priv->state) {
		priv->state = new_ac_state;
		g_object_notify (G_OBJECT (connection), NM_ACTIVE_CONNECTION_STATE);
	}

	/* The connection gets destroyed by the VPN manager when it enters the
	 * disconnected/failed state, but we need to keep it around for a bit
	 * to send out signals and handle the dispatcher.  So ref it.
	 */
	g_object_ref (connection);

	g_signal_emit (connection, signals[VPN_STATE_CHANGED], 0, vpn_state, reason);
	g_object_notify (G_OBJECT (connection), NM_VPN_CONNECTION_VPN_STATE);

	/* Call dispatcher after the event gets processed internally */
	switch (vpn_state) {
	case NM_VPN_CONNECTION_STATE_ACTIVATED:
		nm_utils_call_dispatcher ("vpn-up",
		                          priv->connection,
		                          priv->parent_dev,
		                          priv->tapdev ? priv->tapdev : priv->tundev);
		break;
	case NM_VPN_CONNECTION_STATE_FAILED:
	case NM_VPN_CONNECTION_STATE_DISCONNECTED:
		if (old_vpn_state == NM_VPN_CONNECTION_STATE_ACTIVATED) {
			nm_utils_call_dispatcher ("vpn-down",
			                          priv->connection,
			                          priv->parent_dev,
			                          priv->tapdev ? priv->tapdev : priv->tundev);
		}
		break;
	default:
		break;
	}

	g_object_unref (connection);
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMVPNConnection *connection = NM_VPN_CONNECTION (user_data);

	if (new_state <= NM_DEVICE_STATE_DISCONNECTED) {
		nm_vpn_connection_set_vpn_state (connection,
		                                 NM_VPN_CONNECTION_STATE_DISCONNECTED,
		                                 NM_VPN_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED);
	} else if (new_state == NM_DEVICE_STATE_FAILED) {
		nm_vpn_connection_set_vpn_state (connection,
		                                 NM_VPN_CONNECTION_STATE_FAILED,
		                                 NM_VPN_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED);
	}
}

NMVPNConnection *
nm_vpn_connection_new (NMConnection *connection,
                       NMActRequest *act_request,
                       NMDevice *parent_device)
{
	NMVPNConnection *vpn_connection;
	NMVPNConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (act_request), NULL);
	g_return_val_if_fail (NM_IS_DEVICE (parent_device), NULL);

	vpn_connection = (NMVPNConnection *) g_object_new (NM_TYPE_VPN_CONNECTION, NULL);
	if (!vpn_connection)
		return NULL;

	priv = NM_VPN_CONNECTION_GET_PRIVATE (vpn_connection);

	priv->connection = g_object_ref (connection);
	priv->act_request = g_object_ref (act_request);
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

static void
plugin_state_changed (DBusGProxy *proxy,
				  NMVPNServiceState state,
				  gpointer user_data)
{
	NMVPNConnection *connection = NM_VPN_CONNECTION (user_data);

	nm_info ("VPN plugin state changed: %d", state);

	if (state != NM_VPN_SERVICE_STATE_STOPPED)
		return;

	switch (nm_vpn_connection_get_vpn_state (connection)) {
	case NM_VPN_CONNECTION_STATE_PREPARE:
	case NM_VPN_CONNECTION_STATE_NEED_AUTH:
	case NM_VPN_CONNECTION_STATE_CONNECT:
	case NM_VPN_CONNECTION_STATE_IP_CONFIG_GET:
	case NM_VPN_CONNECTION_STATE_ACTIVATED:
		nm_vpn_connection_set_vpn_state (connection,
		                                 NM_VPN_CONNECTION_STATE_FAILED,
		                                 NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED);
		break;
	default:
		break;
	}
}

static const char *
ip_address_to_string (guint32 numeric)
{
	struct in_addr temp_addr;
	char buf[INET_ADDRSTRLEN+1];

	memset (&buf, '\0', sizeof (buf));
	temp_addr.s_addr = numeric;

	if (inet_ntop (AF_INET, &temp_addr, buf, INET_ADDRSTRLEN)) {
		return g_strdup (buf);
	} else {
		nm_warning ("%s: error converting IP4 address 0x%X",
		            __func__, ntohl (temp_addr.s_addr));
		return NULL;
	}
}

static void
print_vpn_config (NMIP4Config *config,
			   const char *tundev,
			   const char *banner)
{
	const NMSettingIP4Address *addr;
	char *         dns_domain = NULL;
	guint32        num;
	guint32        i;

	g_return_if_fail (config != NULL);

	addr = nm_ip4_config_get_address (config, 0);

	nm_info ("VPN Gateway: %s", ip_address_to_string (addr->gateway));
	nm_info ("Tunnel Device: %s", tundev);
	nm_info ("Internal IP4 Address: %s", ip_address_to_string (addr->address));
	nm_info ("Internal IP4 Prefix: %d", addr->prefix);
	nm_info ("Internal IP4 Point-to-Point Address: %s",
		    ip_address_to_string (nm_ip4_config_get_ptp_address (config)));
	nm_info ("Maximum Segment Size (MSS): %d", nm_ip4_config_get_mss (config));

	num = nm_ip4_config_get_num_routes (config);
	for (i = 0; i < num; i++) {
		const NMSettingIP4Route *route;

		route = nm_ip4_config_get_route (config, i);
		nm_info ("Static Route: %s/%d   Next Hop: %s",
			    ip_address_to_string (route->address),
			    route->prefix,
			    ip_address_to_string (route->next_hop));
	}

	num = nm_ip4_config_get_num_nameservers (config);
	for (i = 0; i < num; i++)
		nm_info ("Internal IP4 DNS: %s", ip_address_to_string (nm_ip4_config_get_nameserver (config, i)));

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
	NMSettingIP4Config *s_ip4;
	NMSettingIP4Address *addr;
	NMIP4Config *config;
	GValue *val;
	int i;

	nm_info ("VPN connection '%s' (IP Config Get) reply received.",
		    nm_vpn_connection_get_name (connection));

	g_source_remove (priv->ipconfig_timeout);
	priv->ipconfig_timeout = 0;

	config = nm_ip4_config_new ();

	addr = g_malloc0 (sizeof (NMSettingIP4Address));
	addr->prefix = 24; /* default to class C */

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_GATEWAY);
	if (val)
		addr->gateway = g_value_get_uint (val);

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS);
	if (val)
		addr->address = g_value_get_uint (val);

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_PTP);
	if (val)
		nm_ip4_config_set_ptp_address (config, g_value_get_uint (val));

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX);
	if (val)
		addr->prefix = g_value_get_uint (val);

	if (addr->address && addr->prefix) {
		nm_ip4_config_take_address (config, addr);
	} else {
		g_warning ("%s: invalid IP4 config received!", __func__);
		g_free (addr);
	}

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

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_ROUTES);
	if (val) {
		GSList *routes;
		GSList *iter;

		routes = nm_utils_ip4_routes_from_gvalue (val);
		for (iter = routes; iter; iter = iter->next)
			nm_ip4_config_take_route (config, (NMSettingIP4Route *) iter->data);

		g_slist_free (routes);
	}

	print_vpn_config (config, priv->tundev, priv->banner);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	priv->ip4_config = config;

	/* Merge in user overrides from the NMConnection's IPv4 setting */
	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (priv->connection, NM_TYPE_SETTING_IP4_CONFIG));
	nm_utils_merge_ip4_config (config, s_ip4);

	if (nm_system_vpn_device_set_from_ip4_config (priv->parent_dev, priv->tundev, priv->ip4_config)) {
		nm_info ("VPN connection '%s' (IP Config Get) complete.",
			    nm_vpn_connection_get_name (connection));
		nm_vpn_connection_set_vpn_state (connection,
		                                 NM_VPN_CONNECTION_STATE_ACTIVATED,
		                                 NM_VPN_CONNECTION_STATE_REASON_NONE);
	} else {
		nm_warning ("VPN connection '%s' did not receive valid IP config information.",
				  nm_vpn_connection_get_name (connection));
		nm_vpn_connection_set_vpn_state (connection,
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
	if (nm_vpn_connection_get_vpn_state (connection) == NM_VPN_CONNECTION_STATE_IP_CONFIG_GET) {
		nm_info ("VPN connection '%s' (IP Config Get) timeout exceeded.",
		         nm_vpn_connection_get_name (connection));
		nm_vpn_connection_set_vpn_state (connection,
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
		nm_vpn_connection_set_vpn_state (connection,
		                                 NM_VPN_CONNECTION_STATE_FAILED,
		                                 NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED);
	} else {
		nm_vpn_connection_set_vpn_state (connection,
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
	g_return_if_fail (nm_vpn_connection_get_vpn_state (connection) == NM_VPN_CONNECTION_STATE_NEED_AUTH);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	/* Ip4Config signal */
	dbus_g_object_register_marshaller (g_cclosure_marshal_VOID__BOXED,
								G_TYPE_NONE, G_TYPE_VALUE, G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->proxy, "Ip4Config",
						DBUS_TYPE_G_MAP_OF_VARIANT,
						G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Ip4Config",
						    G_CALLBACK (nm_vpn_connection_ip4_config_get),
						    connection, NULL);

	org_freedesktop_NetworkManager_VPN_Plugin_connect_async (priv->proxy,
												  nm_connection_to_hash (priv->connection),
												  nm_vpn_connection_connect_cb,
												  connection);

	nm_vpn_connection_set_vpn_state (connection,
	                                 NM_VPN_CONNECTION_STATE_CONNECT,
	                                 NM_VPN_CONNECTION_STATE_REASON_NONE);
}

void
nm_vpn_connection_activate (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv;
	NMDBusManager *dbus_mgr;

	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));
	g_return_if_fail (nm_vpn_connection_get_vpn_state (connection) == NM_VPN_CONNECTION_STATE_PREPARE);

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

	nm_vpn_connection_set_vpn_state (connection,
	                                 NM_VPN_CONNECTION_STATE_NEED_AUTH,
	                                 NM_VPN_CONNECTION_STATE_REASON_NONE);
}

const char *
nm_vpn_connection_get_active_connection_path (NMVPNConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->ac_path;
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

NMConnection *
nm_vpn_connection_get_connection (NMVPNConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->connection;
}

NMVPNConnectionState
nm_vpn_connection_get_vpn_state (NMVPNConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NM_VPN_CONNECTION_STATE_UNKNOWN);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->vpn_state;
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

	nm_vpn_connection_set_vpn_state (connection,
	                                 NM_VPN_CONNECTION_STATE_FAILED,
	                                 reason);
}

void
nm_vpn_connection_disconnect (NMVPNConnection *connection,
                              NMVPNConnectionStateReason reason)
{
	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));

	nm_vpn_connection_set_vpn_state (connection,
	                                 NM_VPN_CONNECTION_STATE_DISCONNECTED,
	                                 reason);
}

/******************************************************************************/

static void
cleanup_secrets_dbus_call (NMVPNConnection *self)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	DBusGProxy *proxy;

	g_return_if_fail (priv->connection != NULL);
	g_return_if_fail (NM_IS_CONNECTION (priv->connection));

	proxy = g_object_get_data (G_OBJECT (priv->connection), NM_MANAGER_CONNECTION_SECRETS_PROXY_TAG);
	g_assert (proxy);

	if (priv->secrets_call) {
		dbus_g_proxy_cancel_call (proxy, priv->secrets_call);
		priv->secrets_call = NULL;
	}
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
update_vpn_properties_secrets (gpointer key, gpointer data, gpointer user_data)
{
	NMConnection *connection = NM_CONNECTION (user_data);

	if (strcmp (key, NM_SETTING_VPN_PROPERTIES_SETTING_NAME))
		return;

	nm_connection_update_secrets (connection,
	                              NM_SETTING_VPN_PROPERTIES_SETTING_NAME,
	                              (GHashTable *) data);
}

static void
get_secrets_cb (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	GetSecretsInfo *info = (GetSecretsInfo *) user_data;
	NMVPNConnectionPrivate *priv;
	GError *err = NULL;
	GHashTable *settings = NULL;

	if (!info || !info->vpn_connection || !info->setting_name)
		goto error;

	priv = NM_VPN_CONNECTION_GET_PRIVATE (info->vpn_connection);

	priv->secrets_call = NULL;

	if (!dbus_g_proxy_end_call (proxy, call, &err,
								DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, &settings,
								G_TYPE_INVALID)) {
		nm_warning ("Couldn't get connection secrets: %s.", err->message);
		g_error_free (err);
		goto error;
	}

	if (g_hash_table_size (settings) == 0) {
		// FIXME: some better way to handle invalid message?
		nm_warning ("GetSecrets call returned but no secrets were found.");
		goto error;
	}

	g_hash_table_foreach (settings, update_vpn_properties_secrets, priv->connection);
	g_hash_table_destroy (settings);
	really_activate (info->vpn_connection);
	return;

error:
	nm_vpn_connection_fail (info->vpn_connection, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS);
}

static gboolean
get_connection_secrets (NMVPNConnection *vpn_connection,
                        const char *setting_name,
                        gboolean request_new)
{
	NMVPNConnectionPrivate *priv;
	DBusGProxy *secrets_proxy;
	GetSecretsInfo *info = NULL;
	GPtrArray *hints;

	g_return_val_if_fail (vpn_connection != NULL, FALSE);
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn_connection), FALSE);
	g_return_val_if_fail (setting_name != NULL, FALSE);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (vpn_connection);
	g_assert (priv->connection);

	secrets_proxy = g_object_get_data (G_OBJECT (priv->connection), NM_MANAGER_CONNECTION_SECRETS_PROXY_TAG);
	g_assert (secrets_proxy);

	info = g_slice_new0 (GetSecretsInfo);
	g_return_val_if_fail (info != NULL, FALSE);

	info->setting_name = g_strdup (setting_name);
	info->vpn_connection = g_object_ref (vpn_connection);

	/* Empty for now... */
	hints = g_ptr_array_new ();

	/* use ..._with_timeout to give the user time to enter secrets */
	priv->secrets_call = dbus_g_proxy_begin_call_with_timeout (secrets_proxy, "GetSecrets",
	                                                           get_secrets_cb,
	                                                           info,
	                                                           free_get_secrets_info,
	                                                           G_MAXINT32,
	                                                           G_TYPE_STRING, setting_name,
	                                                           DBUS_TYPE_G_ARRAY_OF_STRING, hints,
	                                                           G_TYPE_BOOLEAN, request_new,
	                                                           G_TYPE_INVALID);
	g_ptr_array_free (hints, TRUE);
	if (!priv->secrets_call) {
		nm_warning ("Could not call GetSecrets");
		goto error;
	}
	return TRUE;

error:
	if (info)
		free_get_secrets_info (info);
	cleanup_secrets_dbus_call (vpn_connection);
	return FALSE;
}

static void
connection_need_secrets_cb  (DBusGProxy *proxy,
                             char *setting_name,
                             GError *error,
                             gpointer user_data)
{
	NMVPNConnection *vpn_connection = NM_VPN_CONNECTION (user_data);

	cleanup_secrets_dbus_call (vpn_connection);

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
connection_vpn_state_changed (NMVPNConnection *connection,
                              NMVPNConnectionState state,
                              NMVPNConnectionStateReason reason)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	cleanup_secrets_dbus_call (connection);

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
			nm_system_device_flush_ip4_routes_with_iface (priv->tundev);
			nm_system_device_flush_ip4_addresses_with_iface (priv->tundev);
		}

		if (priv->ip4_config) {
			NMIP4Config *dev_ip4_config;

			/* Remove attributes of the VPN's IP4 Config */
			nm_system_vpn_device_unset_from_ip4_config (priv->parent_dev, priv->tundev, priv->ip4_config);

			/* Reset routes, nameservers, and domains of the currently active device */
			dev_ip4_config = nm_device_get_ip4_config (priv->parent_dev);
			if (dev_ip4_config) {
				NMDeviceStateReason dev_reason = NM_DEVICE_STATE_REASON_NONE;

				/* Since the config we're setting is also the device's current
				 * config, have to ref the config to ensure it doesn't get
				 * destroyed when the device unrefs it in nm_device_set_ip4_config().
				 */
				nm_device_set_ip4_config (priv->parent_dev,
				                          g_object_ref (dev_ip4_config),
				                          &dev_reason);
			}
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

	priv->state = NM_ACTIVE_CONNECTION_STATE_UNKNOWN;
	priv->vpn_state = NM_VPN_CONNECTION_STATE_PREPARE;
	priv->ac_path = nm_active_connection_get_next_object_path ();

	dbus_mgr = nm_dbus_manager_get ();
	dbus_g_connection_register_g_object (nm_dbus_manager_get_connection (dbus_mgr),
								  priv->ac_path,
								  G_OBJECT (connection));
	g_object_unref (dbus_mgr);
}

static void
dispose (GObject *object)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_vpn_connection_parent_class)->dispose (object);
		return;
	}
	priv->disposed = TRUE;

	cleanup_secrets_dbus_call (NM_VPN_CONNECTION (object));

	if (priv->parent_dev) {
		if (priv->device_monitor)
			g_signal_handler_disconnect (priv->parent_dev, priv->device_monitor);

		g_object_unref (priv->parent_dev);
	}

	if (priv->ip4_config)
		g_object_unref (priv->ip4_config);

	if (priv->ipconfig_timeout)
		g_source_remove (priv->ipconfig_timeout);

	if (priv->proxy)
		g_object_unref (priv->proxy);

	g_object_unref (priv->connection);

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);

	g_free (priv->banner);
	g_free (priv->tundev);
	g_free (priv->ac_path);

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_SERVICE_NAME:
		nm_active_connection_scope_to_value (priv->connection, value);
		break;
	case PROP_CONNECTION:
		g_value_set_boxed (value, nm_connection_get_path (priv->connection));
		break;
	case PROP_SPECIFIC_OBJECT:
		g_value_set_boxed (value, nm_act_request_get_active_connection_path (priv->act_request));
		break;
	case PROP_DEVICES:
		g_value_take_boxed (value, g_ptr_array_new ());
		break;
	case PROP_STATE:
		g_value_set_uint (value, priv->state);
		break;
	case PROP_DEFAULT:
		g_value_set_boolean (value, priv->is_default);
		break;
	case PROP_VPN:
		g_value_set_boolean (value, TRUE);
		break;
	case PROP_VPN_STATE:
		g_value_set_uint (value, priv->vpn_state);
		break;
	case PROP_BANNER:
		g_value_set_string (value, priv->banner ? priv->banner : "");
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
	connection_class->vpn_state_changed = connection_vpn_state_changed;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_SERVICE_NAME,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_SERVICE_NAME,
							  "Service name",
							  "Service name",
							  NULL,
							  G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_CONNECTION,
		 g_param_spec_boxed (NM_ACTIVE_CONNECTION_CONNECTION,
							  "Connection",
							  "Connection",
							  DBUS_TYPE_G_OBJECT_PATH,
							  G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_SPECIFIC_OBJECT,
		 g_param_spec_boxed (NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT,
							  "Specific object",
							  "Specific object",
							  DBUS_TYPE_G_OBJECT_PATH,
							  G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_DEVICES,
		 g_param_spec_boxed (NM_ACTIVE_CONNECTION_DEVICES,
							  "Devices",
							  "Devices",
							  DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
							  G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_uint (NM_ACTIVE_CONNECTION_STATE,
							  "State",
							  "State",
							  NM_ACTIVE_CONNECTION_STATE_UNKNOWN,
							  NM_ACTIVE_CONNECTION_STATE_ACTIVATED,
							  NM_ACTIVE_CONNECTION_STATE_UNKNOWN,
							  G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_DEFAULT,
		 g_param_spec_boolean (NM_ACTIVE_CONNECTION_DEFAULT,
							   "Default",
							   "Is the default active connection",
							   FALSE,
							   G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_VPN,
		 g_param_spec_boolean (NM_ACTIVE_CONNECTION_VPN,
							   "VPN",
							   "Is a VPN connection",
							   TRUE,
							   G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_VPN_STATE,
		 g_param_spec_uint (NM_VPN_CONNECTION_VPN_STATE,
						"VpnState",
						"Current VPN state",
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
	signals[VPN_STATE_CHANGED] =
		g_signal_new ("vpn-state-changed",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMVPNConnectionClass, vpn_state_changed),
				    NULL, NULL,
				    nm_marshal_VOID__UINT_UINT,
				    G_TYPE_NONE, 2,
				    G_TYPE_UINT, G_TYPE_UINT);

	signals[PROPERTIES_CHANGED] = 
		nm_properties_changed_signal_new (object_class,
								    G_STRUCT_OFFSET (NMVPNConnectionClass, properties_changed));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (object_class),
									 &dbus_glib_nm_vpn_connection_object_info);
}

