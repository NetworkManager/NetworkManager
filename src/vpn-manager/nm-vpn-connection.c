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

#include "nm-vpn-connection.h"
#include "nm-dbus-manager.h"
#include "NetworkManagerSystem.h"
#include "nm-utils.h"
#include "nm-vpn-plugin-bindings.h"

static gboolean impl_vpn_connection_disconnect (NMVPNConnection *connection, GError **err);

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

	LAST_PROP
};

static void
nm_vpn_connection_set_state (NMVPNConnection *connection,
					    NMVPNConnectionState state)
{
	NMVPNConnectionPrivate *priv;

	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	if (state != priv->state) {
		priv->state = state;

		g_object_ref (connection);
		g_signal_emit (connection, signals[STATE_CHANGED], 0, state);
		g_object_unref (connection);
	}
}

static void
device_state_changed (NMDevice *device, NMDeviceState state, gpointer user_data)
{
	NMVPNConnection *connection = NM_VPN_CONNECTION (user_data);

	if (state == NM_DEVICE_STATE_DISCONNECTED)
		nm_vpn_connection_set_state (connection, NM_VPN_CONNECTION_STATE_DISCONNECTED);
}

NMVPNConnection *
nm_vpn_connection_new (NMConnection *connection,
				   NMDevice *parent_device)
{
	NMVPNConnection *vpn_connection;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (NM_IS_DEVICE (parent_device), NULL);

	vpn_connection = (NMVPNConnection *) g_object_new (NM_TYPE_VPN_CONNECTION, NULL);
	if (vpn_connection) {
		NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (vpn_connection);

		priv->connection = connection;
		priv->parent_dev = g_object_ref (parent_device);

		priv->device_monitor = g_signal_connect (parent_device, "state-changed",
										 G_CALLBACK (device_state_changed),
										 vpn_connection);
	}

	return vpn_connection;
}

static char *
nm_vpn_connection_get_service (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	NMSettingVPN *setting;

	setting = (NMSettingVPN *) nm_connection_get_setting (priv->connection, NM_SETTING_VPN);
	return setting->service_type;
}

static char **
nm_vpn_connection_get_routes (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	NMSettingVPN *setting;
	char **routes;
	int i;
	GSList *iter;

	setting = (NMSettingVPN *) nm_connection_get_setting (priv->connection, NM_SETTING_VPN);

	routes = g_new (gchar*, g_slist_length (setting->routes) + 1);

	i = 0;
	for (iter = setting->routes; iter; iter = iter->next)
		routes[i++] = g_strdup (iter->data);

	routes[i] = NULL;

	return routes;
}

static GHashTable *
nm_vpn_connection_get_vpn_data (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	NMSettingVPNProperties *setting;

	setting = (NMSettingVPNProperties *) nm_connection_get_setting (priv->connection, NM_SETTING_VPN_PROPERTIES);
	return setting->data;
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
			nm_vpn_connection_set_state (connection, NM_VPN_CONNECTION_STATE_FAILED);
			break;
		case NM_VPN_CONNECTION_STATE_ACTIVATED:
			nm_vpn_connection_set_state (connection, NM_VPN_CONNECTION_STATE_DISCONNECTED);
			break;
		default:
			break;
		}
	}
}

static void
print_vpn_config (NMIP4Config *config,
			   const char *tundev,
			   const char *login_banner)
{
        struct in_addr  temp_addr;
        char *          dns_domain = NULL;
        guint32         num;
        guint32                 i;

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
        for (i = 1; i <= num; i++)
        {
                temp_addr.s_addr = nm_ip4_config_get_nameserver (config, i);
                nm_info ("Internal IP4 DNS: %s", inet_ntoa (temp_addr));
        }

        if (nm_ip4_config_get_num_domains (config) > 0)
                dns_domain = (char *) nm_ip4_config_get_domain (config, 1);
        nm_info ("DNS Domain: '%s'", dns_domain ? dns_domain : "(none)");
        nm_info ("Login Banner:");
        nm_info ("-----------------------------------------");
        nm_info ("%s", login_banner);
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
	const char *banner = NULL;
	char **routes;
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
	if (val)
		banner = g_value_get_string (val);

	print_vpn_config (config, priv->tundev, banner);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	priv->ip4_config = config;

	routes = nm_vpn_connection_get_routes (connection);

	if (nm_system_vpn_device_set_from_ip4_config (priv->parent_dev, priv->tundev, priv->ip4_config, routes)) {
		nm_info ("VPN connection '%s' (IP Config Get) complete.",
			    nm_vpn_connection_get_name (connection));
		nm_vpn_connection_set_state (connection, NM_VPN_CONNECTION_STATE_ACTIVATED);
	} else {
		nm_warning ("VPN connection '%s' did not receive valid IP config information.",
				  nm_vpn_connection_get_name (connection));
		nm_vpn_connection_set_state (connection, NM_VPN_CONNECTION_STATE_FAILED);
	}

	if (routes)
		g_strfreev (routes);
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
		nm_vpn_connection_set_state (connection, NM_VPN_CONNECTION_STATE_FAILED);
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
		g_error_free (err);
		nm_vpn_connection_set_state (connection, NM_VPN_CONNECTION_STATE_FAILED);
	} else {
		nm_vpn_connection_set_state (connection, NM_VPN_CONNECTION_STATE_IP_CONFIG_GET);
		
		/* 40 second timeout waiting for IP config signal from VPN service */
		priv->ipconfig_timeout = g_timeout_add (40000, nm_vpn_connection_ip_config_timeout, connection);
	}
}

void
nm_vpn_connection_activate (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv;
	NMDBusManager *dbus_mgr;
	char **routes;

	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));
	g_return_if_fail (nm_vpn_connection_get_state (connection) == NM_VPN_CONNECTION_STATE_PREPARE);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	dbus_mgr = nm_dbus_manager_get ();

	priv->proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (dbus_mgr),
									 nm_vpn_connection_get_service (connection),
									 NM_VPN_DBUS_PLUGIN_PATH,
									 NM_VPN_DBUS_PLUGIN_INTERFACE);
	g_object_unref (dbus_mgr);

	/* StateChanges signal */
	dbus_g_proxy_add_signal (priv->proxy, "StateChanged", G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "StateChanged",
						    G_CALLBACK (plugin_state_changed),
						    connection, NULL);

	/* Ip4Config signal */
	dbus_g_object_register_marshaller (g_cclosure_marshal_VOID__BOXED,
								G_TYPE_NONE, G_TYPE_VALUE, G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->proxy, "Ip4Config",
						dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
						G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Ip4Config",
						    G_CALLBACK (nm_vpn_connection_ip4_config_get),
						    connection, NULL);

	routes = nm_vpn_connection_get_routes (connection);
	org_freedesktop_NetworkManager_VPN_Plugin_connect_async (priv->proxy,
												  nm_vpn_connection_get_vpn_data (connection),
												  (const char**)routes,
												  nm_vpn_connection_connect_cb,
												  connection);

	if (routes)
		g_strfreev (routes);

	nm_vpn_connection_set_state (connection, NM_VPN_CONNECTION_STATE_CONNECT);
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
	setting = (NMSettingConnection *) nm_connection_get_setting (priv->connection, NM_SETTING_CONNECTION);

	return setting->name;
}

NMVPNConnectionState
nm_vpn_connection_get_state (NMVPNConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NM_VPN_CONNECTION_STATE_UNKNOWN);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->state;
}

void
nm_vpn_connection_fail (NMVPNConnection *connection)
{
	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));

	nm_vpn_connection_set_state (connection, NM_VPN_CONNECTION_STATE_FAILED);
}

void
nm_vpn_connection_disconnect (NMVPNConnection *connection)
{
	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));

	nm_vpn_connection_set_state (connection, NM_VPN_CONNECTION_STATE_DISCONNECTED);
}

static gboolean
impl_vpn_connection_disconnect (NMVPNConnection *connection, GError **err)
{
	nm_vpn_connection_disconnect (connection);

	return TRUE;
}

/******************************************************************************/

static void
connection_state_changed (NMVPNConnection *connection, NMVPNConnectionState state)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	switch (state) {
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
	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, nm_vpn_connection_get_name (NM_VPN_CONNECTION (object)));
		break;
	case PROP_STATE:
		g_value_set_uint (value, nm_vpn_connection_get_state (NM_VPN_CONNECTION (object)));
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

	/* signals */
	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMVPNConnectionClass, state_changed),
				    NULL, NULL,
				    g_cclosure_marshal_VOID__UINT,
				    G_TYPE_NONE, 1,
				    G_TYPE_UINT);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (connection_class),
							   &dbus_glib_nm_vpn_connection_object_info);
}
