/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2005 - 2012 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
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
#include "nm-setting-ip4-config.h"
#include "nm-dbus-manager.h"
#include "nm-system.h"
#include "nm-logging.h"
#include "nm-utils.h"
#include "nm-vpn-plugin-bindings.h"
#include "nm-marshal.h"
#include "nm-active-connection.h"
#include "nm-properties-changed-signal.h"
#include "nm-dbus-glib-types.h"
#include "NetworkManagerUtils.h"
#include "nm-netlink-monitor.h"
#include "nm-netlink-utils.h"
#include "nm-glib-compat.h"
#include "settings/nm-settings-connection.h"
#include "nm-dispatcher.h"

#include "nm-vpn-connection-glue.h"

G_DEFINE_TYPE (NMVPNConnection, nm_vpn_connection, NM_TYPE_ACTIVE_CONNECTION)

typedef enum {
	/* Only system secrets */
	SECRETS_REQ_SYSTEM = 0,
	/* All existing secrets including agent secrets */
	SECRETS_REQ_EXISTING = 1,
	/* New secrets required; ask an agent */
	SECRETS_REQ_NEW = 2,
	/* Placeholder for bounds checking */
	SECRETS_REQ_LAST
} SecretsReq;

typedef struct {
	gboolean disposed;

	NMConnection *connection;

	guint32 secrets_id;
	SecretsReq secrets_idx;
	char *username;

	NMDevice *parent_dev;
	gulong device_monitor;
	gulong device_ip4;
	gulong device_ip6;

	NMVPNConnectionState vpn_state;
	NMVPNConnectionStateReason failure_reason;
	DBusGProxy *proxy;
	guint ipconfig_timeout;
	gboolean has_ip4;
	NMIP4Config *ip4_config;
	guint32 ip4_internal_gw;
	guint32 ip4_external_gw;
	gboolean has_ip6;
	NMIP6Config *ip6_config;
	struct in6_addr *ip6_internal_gw;
	struct in6_addr *ip6_external_gw;
	char *ip_iface;
	int ip_ifindex;
	char *banner;
	guint32 mtu;

	struct rtnl_route *gw_route;
} NMVPNConnectionPrivate;

#define NM_VPN_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_CONNECTION, NMVPNConnectionPrivate))

enum {
	PROPERTIES_CHANGED,
	VPN_STATE_CHANGED,
	INTERNAL_STATE_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_VPN_STATE,
	PROP_BANNER,
	PROP_MASTER = 2000,

	LAST_PROP
};

static void get_secrets (NMVPNConnection *self, SecretsReq secrets_idx);

static NMActiveConnectionState
ac_state_from_vpn_state (NMVPNConnectionState vpn_state)
{
	/* Set the NMActiveConnection state based on VPN state */
	switch (vpn_state) {
	case NM_VPN_CONNECTION_STATE_PREPARE:
	case NM_VPN_CONNECTION_STATE_NEED_AUTH:
	case NM_VPN_CONNECTION_STATE_CONNECT:
	case NM_VPN_CONNECTION_STATE_IP_CONFIG_GET:
		return NM_ACTIVE_CONNECTION_STATE_ACTIVATING;
	case NM_VPN_CONNECTION_STATE_ACTIVATED:
		return NM_ACTIVE_CONNECTION_STATE_ACTIVATED;
	case NM_VPN_CONNECTION_STATE_FAILED:
	case NM_VPN_CONNECTION_STATE_DISCONNECTED:
		return NM_ACTIVE_CONNECTION_STATE_DEACTIVATED;
	default:
		break;
	}
	return NM_ACTIVE_CONNECTION_STATE_UNKNOWN;
}

static void
call_plugin_disconnect (NMVPNConnection *self)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	GError *error = NULL;

	if (priv->proxy) {
		org_freedesktop_NetworkManager_VPN_Plugin_disconnect (priv->proxy, &error);
		if (error)
			nm_log_warn (LOGD_VPN, "error disconnecting VPN: %s", error->message);
		g_clear_error (&error);

		g_object_unref (priv->proxy);
		priv->proxy = NULL;
	}
}

static void
vpn_cleanup (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	if (priv->ip_ifindex) {
		nm_system_iface_set_up (priv->ip_ifindex, FALSE, NULL);
		nm_system_iface_flush_routes (priv->ip_ifindex, AF_UNSPEC);
		nm_system_iface_flush_addresses (priv->ip_ifindex, AF_UNSPEC);
	}

	if (priv->gw_route) {
		nm_netlink_route_delete (priv->gw_route);
		rtnl_route_put (priv->gw_route);
		priv->gw_route = NULL;
	}

	g_free (priv->banner);
	priv->banner = NULL;

	g_free (priv->ip_iface);
	priv->ip_iface = NULL;
	priv->ip_ifindex = 0;

	/* Clear out connection secrets to ensure that the settings service
	 * gets asked for them next time the connection is activated.
	 */
	if (priv->connection)
		nm_connection_clear_secrets (priv->connection);
}

static void
nm_vpn_connection_set_vpn_state (NMVPNConnection *connection,
                                 NMVPNConnectionState vpn_state,
                                 NMVPNConnectionStateReason reason)
{
	NMVPNConnectionPrivate *priv;
	NMVPNConnectionState old_vpn_state;

	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	if (vpn_state == priv->vpn_state)
		return;

	old_vpn_state = priv->vpn_state;
	priv->vpn_state = vpn_state;

	/* Update active connection base class state */
	nm_active_connection_set_state (NM_ACTIVE_CONNECTION (connection),
	                                ac_state_from_vpn_state (vpn_state));

	/* Clear any in-progress secrets request */
	if (priv->secrets_id) {
		nm_settings_connection_cancel_secrets (NM_SETTINGS_CONNECTION (priv->connection), priv->secrets_id);
		priv->secrets_id = 0;
	}
	priv->secrets_idx = SECRETS_REQ_SYSTEM;

	/* The connection gets destroyed by the VPN manager when it enters the
	 * disconnected/failed state, but we need to keep it around for a bit
	 * to send out signals and handle the dispatcher.  So ref it.
	 */
	g_object_ref (connection);

	g_signal_emit (connection, signals[VPN_STATE_CHANGED], 0, vpn_state, reason);
	g_signal_emit (connection, signals[INTERNAL_STATE_CHANGED], 0, vpn_state, old_vpn_state, reason);
	g_object_notify (G_OBJECT (connection), NM_VPN_CONNECTION_VPN_STATE);

	switch (vpn_state) {
	case NM_VPN_CONNECTION_STATE_NEED_AUTH:
		/* Kick off the secrets requests; first we get existing system secrets
		 * and ask the plugin if these are sufficient, next we get all existing
		 * secrets from system and from user agents and ask the plugin again,
		 * and last we ask the user for new secrets if required.
		 */
		get_secrets (connection, SECRETS_REQ_SYSTEM);
		break;
	case NM_VPN_CONNECTION_STATE_ACTIVATED:
		/* Secrets no longer needed now that we're connected */
		nm_connection_clear_secrets (priv->connection);

		/* Let dispatcher scripts know we're up and running */
		nm_dispatcher_call_vpn (DISPATCHER_ACTION_VPN_UP,
		                        priv->connection,
		                        priv->parent_dev,
		                        priv->ip_iface,
		                        priv->ip4_config,
		                        priv->ip6_config,
		                        NULL,
		                        NULL);
		break;
	case NM_VPN_CONNECTION_STATE_FAILED:
	case NM_VPN_CONNECTION_STATE_DISCONNECTED:
		if (old_vpn_state == NM_VPN_CONNECTION_STATE_ACTIVATED) {
			/* Let dispatcher scripts know we're about to go down */
			nm_dispatcher_call_vpn (DISPATCHER_ACTION_VPN_DOWN,
			                        priv->connection,
			                        priv->parent_dev,
			                        priv->ip_iface,
			                        NULL,
			                        NULL,
			                        NULL,
			                        NULL);
		}

		/* Tear down and clean up the connection */
		call_plugin_disconnect (connection);
		vpn_cleanup (connection);
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

static void
device_ip4_config_changed (NMDevice *device,
                           GParamSpec *pspec,
                           gpointer user_data)
{
	NMVPNConnection *vpn = NM_VPN_CONNECTION (user_data);
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (vpn);

	if (   (priv->vpn_state != NM_VPN_CONNECTION_STATE_ACTIVATED)
	    || !nm_device_get_ip4_config (device))
		return;

	/* Re-add the VPN gateway route */
	if (priv->ip4_external_gw) {
		if (priv->gw_route)
			rtnl_route_put (priv->gw_route);
		priv->gw_route = nm_system_add_ip4_vpn_gateway_route (priv->parent_dev,
		                                                      priv->ip4_external_gw);
	}
}

static void
device_ip6_config_changed (NMDevice *device,
                           GParamSpec *pspec,
                           gpointer user_data)
{
	NMVPNConnection *vpn = NM_VPN_CONNECTION (user_data);
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (vpn);

	if (   (priv->vpn_state != NM_VPN_CONNECTION_STATE_ACTIVATED)
	    || !nm_device_get_ip6_config (device))
		return;

	/* Re-add the VPN gateway route */
	if (priv->ip6_external_gw) {
		if (priv->gw_route)
			rtnl_route_put (priv->gw_route);
		priv->gw_route = nm_system_add_ip6_vpn_gateway_route (priv->parent_dev,
		                                                      priv->ip6_external_gw);
	}
}

NMVPNConnection *
nm_vpn_connection_new (NMConnection *connection,
                       NMDevice *parent_device,
                       const char *specific_object,
                       gboolean user_requested,
                       gulong user_uid)
{
	NMVPNConnection *self;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (NM_IS_DEVICE (parent_device), NULL);

	self = (NMVPNConnection *) g_object_new (NM_TYPE_VPN_CONNECTION,
	                                         NM_ACTIVE_CONNECTION_INT_CONNECTION, connection,
	                                         NM_ACTIVE_CONNECTION_INT_DEVICE, parent_device,
	                                         NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT, specific_object,
	                                         NM_ACTIVE_CONNECTION_INT_USER_REQUESTED, user_requested,
	                                         NM_ACTIVE_CONNECTION_INT_USER_UID, user_uid,
	                                         NM_ACTIVE_CONNECTION_VPN, TRUE,
	                                         NULL);
	if (self)
		nm_active_connection_export (NM_ACTIVE_CONNECTION (self));

	return self;
}

static const char *
nm_vpn_connection_get_service (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	NMSettingVPN *s_vpn;

	s_vpn = nm_connection_get_setting_vpn (priv->connection);
	return nm_setting_vpn_get_service_type (s_vpn);
}

static void
plugin_failed (DBusGProxy *proxy,
			   NMVPNPluginFailure plugin_failure,
			   gpointer user_data)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (user_data);

	nm_log_warn (LOGD_VPN, "VPN plugin failed: %d", plugin_failure);

	switch (plugin_failure) {
	case NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED:
		priv->failure_reason = NM_VPN_CONNECTION_STATE_REASON_LOGIN_FAILED;
		break;
	case NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG:
		priv->failure_reason = NM_VPN_CONNECTION_STATE_REASON_IP_CONFIG_INVALID;
		break;
	default:
		priv->failure_reason = NM_VPN_CONNECTION_STATE_REASON_UNKNOWN;
	}
}

static const char *
vpn_state_to_string (NMVPNServiceState state)
{
	switch (state) {
	case NM_VPN_SERVICE_STATE_INIT:
		return "init";
	case NM_VPN_SERVICE_STATE_SHUTDOWN:
		return "shutdown";
	case NM_VPN_SERVICE_STATE_STARTING:
		return "starting";
	case NM_VPN_SERVICE_STATE_STARTED:
		return "started";
	case NM_VPN_SERVICE_STATE_STOPPING:
		return "stopping";
	case NM_VPN_SERVICE_STATE_STOPPED:
		return "stopped";
	default:
		break;
	}
	return "unknown";
}

static void
plugin_state_changed (DBusGProxy *proxy,
                      NMVPNServiceState state,
                      gpointer user_data)
{
	NMVPNConnection *connection = NM_VPN_CONNECTION (user_data);
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	nm_log_info (LOGD_VPN, "VPN plugin state changed: %s (%d)",
	             vpn_state_to_string (state), state);

	if (state == NM_VPN_SERVICE_STATE_STOPPED) {
		/* Clear connection secrets to ensure secrets get requested each time the
		 * connection is activated.
		 */
		nm_connection_clear_secrets (priv->connection);

		switch (nm_vpn_connection_get_vpn_state (connection)) {
		case NM_VPN_CONNECTION_STATE_PREPARE:
		case NM_VPN_CONNECTION_STATE_NEED_AUTH:
		case NM_VPN_CONNECTION_STATE_CONNECT:
		case NM_VPN_CONNECTION_STATE_IP_CONFIG_GET:
		case NM_VPN_CONNECTION_STATE_ACTIVATED:
			nm_log_info (LOGD_VPN, "VPN plugin state change reason: %d", priv->failure_reason);
			nm_vpn_connection_set_vpn_state (connection,
			                                 NM_VPN_CONNECTION_STATE_FAILED,
											 priv->failure_reason);

			/* Reset the failure reason */
			priv->failure_reason = NM_VPN_CONNECTION_STATE_REASON_UNKNOWN;
			break;
		default:
			break;
		}
	}
}

static char addr_to_string_buf[INET6_ADDRSTRLEN + 1];

static const char *
ip_address_to_string (guint32 numeric)
{
	struct in_addr temp_addr;

	memset (&addr_to_string_buf, '\0', sizeof (addr_to_string_buf));
	temp_addr.s_addr = numeric;

	if (inet_ntop (AF_INET, &temp_addr, addr_to_string_buf, INET_ADDRSTRLEN)) {
		return addr_to_string_buf;
	} else {
		nm_log_warn (LOGD_VPN, "error converting IP4 address 0x%X",
		             ntohl (temp_addr.s_addr));
		return NULL;
	}
}

static const char *
ip6_address_to_string (const struct in6_addr *addr)
{
	memset (addr_to_string_buf, '\0', sizeof (addr_to_string_buf));
	if (inet_ntop (AF_INET6, addr, addr_to_string_buf, INET6_ADDRSTRLEN)) {
		return addr_to_string_buf;
	} else {
		nm_log_warn (LOGD_VPN, "error converting IP6 address");
		return NULL;
	}
}

static void
print_vpn_config (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	NMIP4Address *addr;
	NMIP6Address *addr6;
	char *dns_domain = NULL;
	guint32 num, i;

	if (priv->ip4_external_gw) {
		nm_log_info (LOGD_VPN, "VPN Gateway: %s",
		             ip_address_to_string (priv->ip4_external_gw));
	} else if (priv->ip6_external_gw) {
		nm_log_info (LOGD_VPN, "VPN Gateway: %s",
		             ip6_address_to_string (priv->ip6_external_gw));
	} 

	nm_log_info (LOGD_VPN, "Tunnel Device: %s", priv->ip_iface);

	if (priv->ip4_config) {
		nm_log_info (LOGD_VPN, "IPv4 configuration:");

		addr = nm_ip4_config_get_address (priv->ip4_config, 0);

		if (priv->ip4_internal_gw)
			nm_log_info (LOGD_VPN, "  Internal Gateway: %s", ip_address_to_string (priv->ip4_internal_gw));
		nm_log_info (LOGD_VPN, "  Internal Address: %s", ip_address_to_string (nm_ip4_address_get_address (addr)));
		nm_log_info (LOGD_VPN, "  Internal Prefix: %d", nm_ip4_address_get_prefix (addr));
		nm_log_info (LOGD_VPN, "  Internal Point-to-Point Address: %s",
					 ip_address_to_string (nm_ip4_config_get_ptp_address (priv->ip4_config)));
		nm_log_info (LOGD_VPN, "  Maximum Segment Size (MSS): %d", nm_ip4_config_get_mss (priv->ip4_config));

		num = nm_ip4_config_get_num_routes (priv->ip4_config);
		for (i = 0; i < num; i++) {
			NMIP4Route *route;

			route = nm_ip4_config_get_route (priv->ip4_config, i);
			nm_log_info (LOGD_VPN, "  Static Route: %s/%d   Next Hop: %s",
						 ip_address_to_string (nm_ip4_route_get_dest (route)),
						 nm_ip4_route_get_prefix (route),
						 ip_address_to_string (nm_ip4_route_get_next_hop (route)));
		}

		nm_log_info (LOGD_VPN, "  Forbid Default Route: %s",
					 nm_ip4_config_get_never_default (priv->ip4_config) ? "yes" : "no");

		num = nm_ip4_config_get_num_nameservers (priv->ip4_config);
		for (i = 0; i < num; i++) {
			nm_log_info (LOGD_VPN, "  Internal DNS: %s",
						 ip_address_to_string (nm_ip4_config_get_nameserver (priv->ip4_config, i)));
		}

		if (nm_ip4_config_get_num_domains (priv->ip4_config) > 0)
			dns_domain = (char *) nm_ip4_config_get_domain (priv->ip4_config, 0);

		nm_log_info (LOGD_VPN, "  DNS Domain: '%s'", dns_domain ? dns_domain : "(none)");
	} else
		nm_log_info (LOGD_VPN, "No IPv4 configuration");

	if (priv->ip6_config) {
		nm_log_info (LOGD_VPN, "IPv6 configuration:");

		addr6 = nm_ip6_config_get_address (priv->ip6_config, 0);

		if (priv->ip6_internal_gw)
			nm_log_info (LOGD_VPN, "  Internal Gateway: %s", ip6_address_to_string (priv->ip6_internal_gw));
		nm_log_info (LOGD_VPN, "  Internal Address: %s", ip6_address_to_string (nm_ip6_address_get_address (addr6)));
		nm_log_info (LOGD_VPN, "  Internal Prefix: %d", nm_ip6_address_get_prefix (addr6));
		nm_log_info (LOGD_VPN, "  Internal Point-to-Point Address: %s",
					 ip6_address_to_string (nm_ip6_config_get_ptp_address (priv->ip6_config)));
		nm_log_info (LOGD_VPN, "  Maximum Segment Size (MSS): %d", nm_ip6_config_get_mss (priv->ip6_config));

		num = nm_ip6_config_get_num_routes (priv->ip6_config);
		for (i = 0; i < num; i++) {
			NMIP6Route *route;

			route = nm_ip6_config_get_route (priv->ip6_config, i);
			nm_log_info (LOGD_VPN, "  Static Route: %s/%d   Next Hop: %s",
						 ip6_address_to_string (nm_ip6_route_get_dest (route)),
						 nm_ip6_route_get_prefix (route),
						 ip6_address_to_string (nm_ip6_route_get_next_hop (route)));
		}

		nm_log_info (LOGD_VPN, "  Forbid Default Route: %s",
					 nm_ip6_config_get_never_default (priv->ip6_config) ? "yes" : "no");

		num = nm_ip6_config_get_num_nameservers (priv->ip6_config);
		for (i = 0; i < num; i++) {
			nm_log_info (LOGD_VPN, "  Internal DNS: %s",
						 ip6_address_to_string (nm_ip6_config_get_nameserver (priv->ip6_config, i)));
		}

		if (nm_ip6_config_get_num_domains (priv->ip6_config) > 0)
			dns_domain = (char *) nm_ip6_config_get_domain (priv->ip6_config, 0);

		nm_log_info (LOGD_VPN, "  DNS Domain: '%s'", dns_domain ? dns_domain : "(none)");
	} else
		nm_log_info (LOGD_VPN, "No IPv6 configuration");

	if (priv->banner && strlen (priv->banner)) {
		nm_log_info (LOGD_VPN, "Login Banner:");
		nm_log_info (LOGD_VPN, "-----------------------------------------");
		nm_log_info (LOGD_VPN, "%s", priv->banner);
		nm_log_info (LOGD_VPN, "-----------------------------------------");
	}
}

static gboolean
nm_vpn_connection_apply_config (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	nm_system_iface_set_up (priv->ip_ifindex, TRUE, NULL);

	if (priv->ip4_config) {
		if (!nm_system_apply_ip4_config (priv->ip_ifindex, priv->ip4_config,
		                                 0, NM_IP4_COMPARE_FLAG_ALL))
			return FALSE;
	}

	if (priv->ip6_config) {
		if (!nm_system_apply_ip6_config (priv->ip_ifindex, priv->ip6_config,
		                                 0, NM_IP6_COMPARE_FLAG_ALL))
			/* FIXME: remove ip4 config */
			return FALSE;
	}

	/* Add any explicit route to the VPN gateway through the parent device */
	if (priv->ip4_external_gw) {
		priv->gw_route = nm_system_add_ip4_vpn_gateway_route (priv->parent_dev,
		                                                      priv->ip4_external_gw);
	} else if (priv->ip6_external_gw) {
		priv->gw_route = nm_system_add_ip6_vpn_gateway_route (priv->parent_dev,
		                                                      priv->ip6_external_gw);
	} else {
		priv->gw_route = NULL;
	}

	nm_log_info (LOGD_VPN, "VPN connection '%s' (IP Config Get) complete.",
	             nm_connection_get_id (priv->connection));
	nm_vpn_connection_set_vpn_state (connection,
	                                 NM_VPN_CONNECTION_STATE_ACTIVATED,
	                                 NM_VPN_CONNECTION_STATE_REASON_NONE);
	return TRUE;
}

static void
nm_vpn_connection_config_maybe_complete (NMVPNConnection *connection,
                                         gboolean         success)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	if (priv->ipconfig_timeout == 0) {
		/* config_complete() was already called with an error;
		 * ignore further calls.
		 */
		return;
	}

	if (success) {
		if (   (priv->has_ip4 && !priv->ip4_config)
		    || (priv->has_ip6 && !priv->ip6_config)) {
			/* Need to wait for other config */
			return;
		}
	}

	g_source_remove (priv->ipconfig_timeout);
	priv->ipconfig_timeout = 0;

	if (success) {
		print_vpn_config (connection);

		if (nm_vpn_connection_apply_config (connection))
			return;
	}

	g_clear_object (&priv->ip4_config);
	g_clear_object (&priv->ip6_config);

	nm_log_warn (LOGD_VPN, "VPN connection '%s' did not receive valid IP config information.",
	             nm_connection_get_id (priv->connection));
	nm_vpn_connection_set_vpn_state (connection,
	                                 NM_VPN_CONNECTION_STATE_FAILED,
	                                 NM_VPN_CONNECTION_STATE_REASON_IP_CONFIG_INVALID);
}

static gboolean
process_generic_config (NMVPNConnection *connection,
                        GHashTable *config_hash)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	GValue *val;

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_CONFIG_TUNDEV);
	if (val)
		priv->ip_iface = g_strdup (g_value_get_string (val));
	else {
		nm_log_err (LOGD_VPN, "invalid or missing tunnel device received!");
		nm_vpn_connection_config_maybe_complete (connection, FALSE);
		return FALSE;
	}

	/* Grab the interface index for address/routing operations */
	priv->ip_ifindex = nm_netlink_iface_to_index (priv->ip_iface);
	if (priv->ip_ifindex <= 0) {
		nm_log_err (LOGD_VPN, "(%s): failed to look up VPN interface index", priv->ip_iface);
		nm_vpn_connection_config_maybe_complete (connection, FALSE);
		return FALSE;
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_CONFIG_BANNER);
	if (val) {
		g_free (priv->banner);
		priv->banner = g_strdup (g_value_get_string (val));
	}

	/* External world-visible address of the VPN server */
	priv->ip4_external_gw = 0;
	priv->ip6_external_gw = NULL;
	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY);
	if (val) {
		if (G_VALUE_HOLDS (val, G_TYPE_UINT)) {
			priv->ip4_external_gw = g_value_get_uint (val);
		} else if (G_VALUE_HOLDS (val, DBUS_TYPE_G_UCHAR_ARRAY)) {
			GByteArray *ba = g_value_get_boxed (val);

			if (ba->len == sizeof (struct in6_addr))
				priv->ip6_external_gw = g_memdup (ba->data, ba->len);
		} else {
			nm_log_err (LOGD_VPN, "(%s): VPN gateway is neither IPv4 nor IPv6", priv->ip_iface);
			nm_vpn_connection_config_maybe_complete (connection, FALSE);
			return FALSE;
		}
	}

	/* MTU; this is a per-connection value, though NM's API treats it
	 * like it's IP4-specific. So we store it for now and retrieve it
	 * later in ip4_config_get.
	 */
	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_CONFIG_MTU);
	if (val)
		priv->mtu = g_value_get_uint (val);
	else
		priv->mtu = 0;

	return TRUE;
}

static void
nm_vpn_connection_config_get (DBusGProxy *proxy,
                              GHashTable *config_hash,
                              gpointer user_data)
{
	NMVPNConnection *connection = NM_VPN_CONNECTION (user_data);
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	GValue *val;

	nm_log_info (LOGD_VPN, "VPN connection '%s' (IP Config Get) reply received.",
	             nm_connection_get_id (priv->connection));

	if (!process_generic_config (connection, config_hash))
		return;

	/* Note whether to expect IPv4 and IPv6 configs */
	val = g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_CONFIG_HAS_IP4);
	priv->has_ip4 = val ? g_value_get_boolean (val) : FALSE;
	g_clear_object (&priv->ip4_config);

	val = g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_CONFIG_HAS_IP6);
	priv->has_ip6 = val ? g_value_get_boolean (val) : FALSE;
	g_clear_object (&priv->ip6_config);
}

static void
nm_vpn_connection_ip4_config_get (DBusGProxy *proxy,
                                  GHashTable *config_hash,
                                  gpointer user_data)
{
	NMVPNConnection *connection = NM_VPN_CONNECTION (user_data);
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	NMSettingIP4Config *s_ip4;
	NMIP4Address *addr;
	NMIP4Config *config;
	GValue *val;
	int i;

	if (priv->has_ip4) {
		nm_log_info (LOGD_VPN, "VPN connection '%s' (IP4 Config Get) reply received.",
		             nm_connection_get_id (priv->connection));

		if (g_hash_table_size (config_hash) == 0) {
			priv->has_ip4 = FALSE;
			nm_vpn_connection_config_maybe_complete (connection, TRUE);
			return;
		}
	} else {
		nm_log_info (LOGD_VPN, "VPN connection '%s' (IP4 Config Get) reply received from old-style plugin.",
		             nm_connection_get_id (priv->connection));

		/* In the old API, the generic and IPv4 configuration items
		 * were mixed together.
		 */
		if (!process_generic_config (connection, config_hash))
			return;

		priv->has_ip4 = TRUE;
		priv->has_ip6 = FALSE;
	}

	config = nm_ip4_config_new ();

	addr = nm_ip4_address_new ();
	nm_ip4_address_set_prefix (addr, 24); /* default to class C */
	if (priv->ip4_external_gw)
		nm_ip4_address_set_gateway (addr, priv->ip4_external_gw);

	/* Internal address of the VPN subnet's gateway */
	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_INT_GATEWAY);
	if (val)
		priv->ip4_internal_gw = g_value_get_uint (val);

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS);
	if (val)
		nm_ip4_address_set_address (addr, g_value_get_uint (val));

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_PTP);
	if (val)
		nm_ip4_config_set_ptp_address (config, g_value_get_uint (val));

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX);
	if (val)
		nm_ip4_address_set_prefix (addr, g_value_get_uint (val));

	if (nm_ip4_address_get_address (addr) && nm_ip4_address_get_prefix (addr)) {
		nm_ip4_config_take_address (config, addr);
	} else {
		nm_log_err (LOGD_VPN, "invalid IP4 config received!");
		nm_ip4_address_unref (addr);
		g_object_unref (config);
		nm_vpn_connection_config_maybe_complete (connection, FALSE);
		return;
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
			nm_ip4_config_add_wins (config, g_array_index (nbns, guint, i));
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_MSS);
	if (val)
		nm_ip4_config_set_mss (config, g_value_get_uint (val));

	if (priv->mtu)
		nm_ip4_config_set_mtu (config, priv->mtu);

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN);
	if (val)
		nm_ip4_config_add_domain (config, g_value_get_string (val));

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_DOMAINS);
	if (val) {
		const char **domains = g_value_get_boxed (val);
		const char **domain;

		for (domain = domains; domain && *domain; domain++)
			nm_ip4_config_add_domain (config, *domain);
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_ROUTES);
	if (val) {
		GSList *routes;
		GSList *iter;

		routes = nm_utils_ip4_routes_from_gvalue (val);
		for (iter = routes; iter; iter = iter->next) {
			NMIP4Route *route = iter->data;

			/* Ignore host routes to the VPN gateway since NM adds one itself
			 * below.  Since NM knows more about the routing situation than
			 * the VPN server, we want to use the NM created route instead of
			 * whatever the server provides.
			 */
			if (   priv->ip4_external_gw
			    && nm_ip4_route_get_dest (route) == priv->ip4_external_gw
			    && nm_ip4_route_get_prefix (route) == 32) {
				nm_ip4_route_unref (route);
				continue;
			}

			/* Otherwise accept the VPN-provided route */
			nm_ip4_config_take_route (config, route);
		}

		g_slist_free (routes);
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT);
	if (val && G_VALUE_HOLDS_BOOLEAN (val))
		nm_ip4_config_set_never_default (config, g_value_get_boolean (val));

	/* Merge in user overrides from the NMConnection's IPv4 setting */
	s_ip4 = nm_connection_get_setting_ip4_config (priv->connection);
	nm_utils_merge_ip4_config (config, s_ip4);

	priv->ip4_config = config;
	nm_vpn_connection_config_maybe_complete (connection, TRUE);
}

static void
nm_vpn_connection_ip6_config_get (DBusGProxy *proxy,
                                  GHashTable *config_hash,
                                  gpointer user_data)
{
	NMVPNConnection *connection = NM_VPN_CONNECTION (user_data);
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	NMSettingIP6Config *s_ip6;
	NMIP6Address *addr;
	NMIP6Config *config;
	GValue *val;
	int i;

	nm_log_info (LOGD_VPN, "VPN connection '%s' (IP6 Config Get) reply received.",
	             nm_connection_get_id (priv->connection));

	if (g_hash_table_size (config_hash) == 0) {
		priv->has_ip6 = FALSE;
		nm_vpn_connection_config_maybe_complete (connection, TRUE);
		return;
	}

	config = nm_ip6_config_new ();

	addr = nm_ip6_address_new ();
	nm_ip6_address_set_prefix (addr, 128); /* default to class C */
	if (priv->ip6_external_gw)
		nm_ip6_address_set_gateway (addr, priv->ip6_external_gw);

	/* Internal address of the VPN subnet's gateway */
	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP6_CONFIG_INT_GATEWAY);
	if (val) {
		GByteArray *ba = g_value_get_boxed (val);

		if (ba->len == sizeof (struct in6_addr))
			priv->ip6_internal_gw = g_memdup (ba->data, ba->len);
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP6_CONFIG_ADDRESS);
	if (val) {
		GByteArray *ba = g_value_get_boxed (val);

		if (ba->len == sizeof (struct in6_addr))
			nm_ip6_address_set_address (addr, (struct in6_addr *)ba->data);
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP6_CONFIG_PTP);
	if (val) {
		GByteArray *ba = g_value_get_boxed (val);

		if (ba->len == sizeof (struct in6_addr))
			nm_ip6_config_set_ptp_address (config, (struct in6_addr *)ba->data);
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP6_CONFIG_PREFIX);
	if (val)
		nm_ip6_address_set_prefix (addr, g_value_get_uint (val));

	if (nm_ip6_address_get_address (addr) && nm_ip6_address_get_prefix (addr)) {
		nm_ip6_config_take_address (config, addr);
	} else {
		nm_log_err (LOGD_VPN, "invalid IP6 config received!");
		nm_ip6_address_unref (addr);
		g_object_unref (config);
		nm_vpn_connection_config_maybe_complete (connection, FALSE);
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP6_CONFIG_DNS);
	if (val) {
		GPtrArray *dns = (GPtrArray *) g_value_get_boxed (val);
		GByteArray *ba;

		for (i = 0; i < dns->len; i++) {
			ba = dns->pdata[i];
			if (ba->len == sizeof (struct in6_addr))
				nm_ip6_config_add_nameserver (config, (struct in6_addr *)ba->data);
		}
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP6_CONFIG_MSS);
	if (val)
		nm_ip6_config_set_mss (config, g_value_get_uint (val));

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP6_CONFIG_DOMAIN);
	if (val)
		nm_ip6_config_add_domain (config, g_value_get_string (val));

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP6_CONFIG_DOMAINS);
	if (val) {
		const char **domains = g_value_get_boxed (val);
		const char **domain;

		for (domain = domains; domain && *domain; domain++)
			nm_ip6_config_add_domain (config, *domain);
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP6_CONFIG_ROUTES);
	if (val) {
		GSList *routes;
		GSList *iter;

		routes = nm_utils_ip6_routes_from_gvalue (val);
		for (iter = routes; iter; iter = iter->next) {
			NMIP6Route *route = iter->data;

			/* Ignore host routes to the VPN gateway since NM adds one itself
			 * below.  Since NM knows more about the routing situation than
			 * the VPN server, we want to use the NM created route instead of
			 * whatever the server provides.
			 */
			if (   priv->ip6_external_gw
			    && nm_ip6_route_get_prefix (route) == 128
				&& memcmp (nm_ip6_route_get_dest (route), priv->ip6_external_gw,
				           sizeof (struct in6_addr)) == 0) {
				nm_ip6_route_unref (route);
				continue;
			}

			/* Otherwise accept the VPN-provided route */
			nm_ip6_config_take_route (config, route);
		}

		g_slist_free (routes);
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_VPN_PLUGIN_IP6_CONFIG_NEVER_DEFAULT);
	if (val && G_VALUE_HOLDS_BOOLEAN (val))
		nm_ip6_config_set_never_default (config, g_value_get_boolean (val));

	/* Merge in user overrides from the NMConnection's IPv6 setting */
	s_ip6 = nm_connection_get_setting_ip6_config (priv->connection);
	nm_utils_merge_ip6_config (config, s_ip6);

	priv->ip6_config = config;
	nm_vpn_connection_config_maybe_complete (connection, TRUE);
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
		nm_log_warn (LOGD_VPN, "VPN connection '%s' (IP Config Get) timeout exceeded.",
		             nm_connection_get_id (priv->connection));
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

	nm_log_info (LOGD_VPN, "VPN connection '%s' (Connect) reply received.",
	             nm_connection_get_id (priv->connection));

	if (err) {
		nm_log_warn (LOGD_VPN, "VPN connection '%s' failed to connect: '%s'.", 
		             nm_connection_get_id (priv->connection), err->message);
		nm_vpn_connection_set_vpn_state (connection,
		                                 NM_VPN_CONNECTION_STATE_FAILED,
		                                 NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED);
	} else {
		nm_vpn_connection_set_vpn_state (connection,
		                                 NM_VPN_CONNECTION_STATE_IP_CONFIG_GET,
		                                 NM_VPN_CONNECTION_STATE_REASON_NONE);
		
		/* 40 second timeout waiting for IP config signal from VPN service */
		priv->ipconfig_timeout = g_timeout_add_seconds (40, nm_vpn_connection_ip_config_timeout, connection);
	}
}

/* Add a username to a hashed connection */
static GHashTable *
_hash_with_username (NMConnection *connection, const char *username)
{
	NMConnection *dup;
	NMSettingVPN *s_vpn;
	GHashTable *hash;
	const char *existing;

	/* Shortcut if we weren't given a username or if there already was one in
	 * the VPN setting; don't bother duplicating the connection and everything.
	 */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);
	existing = nm_setting_vpn_get_user_name (s_vpn);
	if (username == NULL || existing)
		return nm_connection_to_hash (connection, NM_SETTING_HASH_FLAG_ALL);

	dup = nm_connection_duplicate (connection);
	g_assert (dup);
	s_vpn = nm_connection_get_setting_vpn (dup);
	g_assert (s_vpn);
	g_object_set (s_vpn, NM_SETTING_VPN_USER_NAME, username, NULL);
	hash = nm_connection_to_hash (dup, NM_SETTING_HASH_FLAG_ALL);
	g_object_unref (dup);
	return hash;
}

static void
really_activate (NMVPNConnection *connection, const char *username)
{
	NMVPNConnectionPrivate *priv;
	GHashTable *hash;

	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));
	g_return_if_fail (nm_vpn_connection_get_vpn_state (connection) == NM_VPN_CONNECTION_STATE_NEED_AUTH);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	dbus_g_object_register_marshaller (g_cclosure_marshal_VOID__BOXED,
								G_TYPE_NONE, G_TYPE_VALUE, G_TYPE_INVALID);

	/* Config signal */
	dbus_g_proxy_add_signal (priv->proxy, "Config",
						DBUS_TYPE_G_MAP_OF_VARIANT,
						G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Config",
						    G_CALLBACK (nm_vpn_connection_config_get),
						    connection, NULL);

	/* Ip4Config signal */
	dbus_g_proxy_add_signal (priv->proxy, "Ip4Config",
						DBUS_TYPE_G_MAP_OF_VARIANT,
						G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Ip4Config",
						    G_CALLBACK (nm_vpn_connection_ip4_config_get),
						    connection, NULL);

	/* Ip6Config signal */
	dbus_g_proxy_add_signal (priv->proxy, "Ip6Config",
						DBUS_TYPE_G_MAP_OF_VARIANT,
						G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Ip6Config",
						    G_CALLBACK (nm_vpn_connection_ip6_config_get),
						    connection, NULL);

	hash = _hash_with_username (priv->connection, username);
	org_freedesktop_NetworkManager_VPN_Plugin_connect_async (priv->proxy,
	                                                         hash,
	                                                         nm_vpn_connection_connect_cb,
	                                                         connection);
	g_hash_table_destroy (hash);

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

	dbus_g_proxy_add_signal (priv->proxy, "Failure", G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "Failure",
								 G_CALLBACK (plugin_failed),
								 connection, NULL);

	/* StateChanged signal */
	dbus_g_proxy_add_signal (priv->proxy, "StateChanged", G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "StateChanged",
	                             G_CALLBACK (plugin_state_changed),
	                             connection, NULL);

	nm_vpn_connection_set_vpn_state (connection,
	                                 NM_VPN_CONNECTION_STATE_NEED_AUTH,
	                                 NM_VPN_CONNECTION_STATE_REASON_NONE);
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

NMIP4Config *
nm_vpn_connection_get_ip4_config (NMVPNConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->ip4_config;
}

NMIP6Config *
nm_vpn_connection_get_ip6_config (NMVPNConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->ip6_config;
}

const char *
nm_vpn_connection_get_ip_iface (NMVPNConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->ip_iface;
}

int
nm_vpn_connection_get_ip_ifindex (NMVPNConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), -1);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->ip_ifindex;
}

NMDevice *
nm_vpn_connection_get_parent_device (NMVPNConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->parent_dev;
}

guint32
nm_vpn_connection_get_ip4_internal_gateway (NMVPNConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), 0);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->ip4_internal_gw;
}

struct in6_addr *
nm_vpn_connection_get_ip6_internal_gateway (NMVPNConnection *connection)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (connection), 0);

	return NM_VPN_CONNECTION_GET_PRIVATE (connection)->ip6_internal_gw;
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
plugin_need_secrets_cb  (DBusGProxy *proxy,
                         char *setting_name,
                         GError *error,
                         gpointer user_data)
{
	NMVPNConnection *self = NM_VPN_CONNECTION (user_data);
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	if (error) {
		nm_log_err (LOGD_VPN, "(%s/%s) plugin NeedSecrets request #%d failed: %s %s",
		            nm_connection_get_uuid (priv->connection),
		            nm_connection_get_id (priv->connection),
		            priv->secrets_idx + 1,
		            g_quark_to_string (error->domain),
		            error->message);
		nm_vpn_connection_fail (self, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS);
		return;
	}

	if (setting_name && strlen (setting_name)) {
		/* More secrets required */

		if (priv->secrets_idx == SECRETS_REQ_NEW) {
			nm_log_err (LOGD_VPN, "(%s/%s) final secrets request failed to provide sufficient secrets",
			            nm_connection_get_uuid (priv->connection),
			            nm_connection_get_id (priv->connection));
			nm_vpn_connection_fail (self, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS);
		} else {
			nm_log_dbg (LOGD_VPN, "(%s/%s) service indicated additional secrets required",
			            nm_connection_get_uuid (priv->connection),
			            nm_connection_get_id (priv->connection));

			get_secrets (self, priv->secrets_idx + 1);
		}
		return;
	}

	nm_log_dbg (LOGD_VPN, "(%s/%s) service indicated no additional secrets required",
	            nm_connection_get_uuid (priv->connection),
	            nm_connection_get_id (priv->connection));

	/* No secrets required; we can start the VPN */
	really_activate (self, priv->username);
}

static void
get_secrets_cb (NMSettingsConnection *connection,
                guint32 call_id,
                const char *agent_username,
                const char *setting_name,
                GError *error,
                gpointer user_data)
{
	NMVPNConnection *self = NM_VPN_CONNECTION (user_data);
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	GHashTable *hash;

	g_return_if_fail (NM_CONNECTION (connection) == priv->connection);
	g_return_if_fail (call_id == priv->secrets_id);

	priv->secrets_id = 0;

	if (error) {
		nm_log_err (LOGD_VPN, "Failed to request VPN secrets #%d: (%d) %s",
		            priv->secrets_idx + 1, error->code, error->message);
		nm_vpn_connection_fail (self, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS);
	} else {
		nm_log_dbg (LOGD_VPN, "(%s/%s) asking service if additional secrets are required",
		            nm_connection_get_uuid (priv->connection),
		            nm_connection_get_id (priv->connection));

		/* Cache the username for later */
		if (agent_username) {
			g_free (priv->username);
			priv->username = g_strdup (agent_username);
		}

		/* Ask the VPN service if more secrets are required */
		hash = _hash_with_username (priv->connection, priv->username);
		org_freedesktop_NetworkManager_VPN_Plugin_need_secrets_async (priv->proxy,
		                                                              hash,
		                                                              plugin_need_secrets_cb,
		                                                              self);
		g_hash_table_destroy (hash);
	}
}

static void
get_secrets (NMVPNConnection *self, SecretsReq secrets_idx)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	NMSettingsGetSecretsFlags flags = NM_SETTINGS_GET_SECRETS_FLAG_NONE;
	GError *error = NULL;
	gboolean filter_by_uid;

	g_return_if_fail (secrets_idx < SECRETS_REQ_LAST);
	priv->secrets_idx = secrets_idx;

	filter_by_uid = nm_active_connection_get_user_requested (NM_ACTIVE_CONNECTION (self));

	nm_log_dbg (LOGD_VPN, "(%s/%s) requesting VPN secrets pass #%d",
	            nm_connection_get_uuid (priv->connection),
	            nm_connection_get_id (priv->connection),
	            priv->secrets_idx + 1);

	switch (priv->secrets_idx) {
	case SECRETS_REQ_SYSTEM:
		flags = NM_SETTINGS_GET_SECRETS_FLAG_ONLY_SYSTEM;
		filter_by_uid = FALSE;
		break;
	case SECRETS_REQ_EXISTING:
		flags = NM_SETTINGS_GET_SECRETS_FLAG_NONE;
		break;
	case SECRETS_REQ_NEW:
		flags = NM_SETTINGS_GET_SECRETS_FLAG_ALLOW_INTERACTION;
		break;
	default:
		g_assert_not_reached ();
	}

	if (nm_active_connection_get_user_requested (NM_ACTIVE_CONNECTION (self)))
		flags |= NM_SETTINGS_GET_SECRETS_FLAG_USER_REQUESTED;

	priv->secrets_id = nm_settings_connection_get_secrets (NM_SETTINGS_CONNECTION (priv->connection),
	                                                       filter_by_uid,
	                                                       nm_active_connection_get_user_uid (NM_ACTIVE_CONNECTION (self)),
	                                                       NM_SETTING_VPN_SETTING_NAME,
	                                                       flags,
	                                                       NULL,
	                                                       get_secrets_cb,
	                                                       self,
	                                                       &error);
	if (!priv->secrets_id) {
		if (error) {
			nm_log_err (LOGD_VPN, "failed to request VPN secrets #%d: (%d) %s",
			            priv->secrets_idx + 1, error->code, error->message);
		}
		nm_vpn_connection_fail (self, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS);
		g_clear_error (&error);
	}
}

/******************************************************************************/

static void
nm_vpn_connection_init (NMVPNConnection *self)
{
	NM_VPN_CONNECTION_GET_PRIVATE (self)->vpn_state = NM_VPN_CONNECTION_STATE_PREPARE;
}

static void
constructed (GObject *object)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);
	NMConnection *connection;
	NMDevice *device;

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->constructed (object);

	connection = nm_active_connection_get_connection (NM_ACTIVE_CONNECTION (object));
	priv->connection = g_object_ref (connection);

	device = (NMDevice *) nm_active_connection_get_device (NM_ACTIVE_CONNECTION (object));
	g_assert (device);

	priv->parent_dev = g_object_ref (device);

	priv->device_monitor = g_signal_connect (device, "state-changed",
	                                         G_CALLBACK (device_state_changed),
	                                         object);

	priv->device_ip4 = g_signal_connect (device, "notify::" NM_DEVICE_IP4_CONFIG,
	                                     G_CALLBACK (device_ip4_config_changed),
	                                     object);
	priv->device_ip6 = g_signal_connect (device, "notify::" NM_DEVICE_IP6_CONFIG,
	                                     G_CALLBACK (device_ip6_config_changed),
	                                     object);
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

	if (priv->gw_route)
		rtnl_route_put (priv->gw_route);
	if (priv->ip6_internal_gw)
		g_free (priv->ip6_internal_gw);
	if (priv->ip6_external_gw)
		g_free (priv->ip6_external_gw);

	if (priv->device_ip4)
		g_signal_handler_disconnect (priv->parent_dev, priv->device_ip4);
	if (priv->device_ip6)
		g_signal_handler_disconnect (priv->parent_dev, priv->device_ip6);

	if (priv->device_monitor)
		g_signal_handler_disconnect (priv->parent_dev, priv->device_monitor);

	g_clear_object (&priv->parent_dev);

	if (priv->ip4_config)
		g_object_unref (priv->ip4_config);
	if (priv->ip6_config)
		g_object_unref (priv->ip6_config);

	if (priv->ipconfig_timeout)
		g_source_remove (priv->ipconfig_timeout);

	if (priv->proxy)
		g_object_unref (priv->proxy);

	if (priv->secrets_id) {
		nm_settings_connection_cancel_secrets (NM_SETTINGS_CONNECTION (priv->connection),
		                                       priv->secrets_id);
	}

	g_clear_object (&priv->connection);
	g_free (priv->username);

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);

	g_free (priv->banner);
	g_free (priv->ip_iface);

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_VPN_STATE:
		g_value_set_uint (value, priv->vpn_state);
		break;
	case PROP_BANNER:
		g_value_set_string (value, priv->banner ? priv->banner : "");
		break;
	case PROP_MASTER:
		g_value_set_boxed (value, nm_device_get_path (priv->parent_dev));
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
	object_class->get_property = get_property;
	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	g_object_class_override_property (object_class, PROP_MASTER, NM_ACTIVE_CONNECTION_MASTER);

	/* properties */
	g_object_class_install_property (object_class, PROP_VPN_STATE,
		g_param_spec_uint (NM_VPN_CONNECTION_VPN_STATE,
		                   "VpnState",
		                   "Current VPN state",
		                   NM_VPN_CONNECTION_STATE_UNKNOWN,
		                   NM_VPN_CONNECTION_STATE_DISCONNECTED,
		                   NM_VPN_CONNECTION_STATE_UNKNOWN,
		                   G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_BANNER,
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
		              0, NULL, NULL,
		              _nm_marshal_VOID__UINT_UINT,
		              G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);

	signals[INTERNAL_STATE_CHANGED] =
		g_signal_new (NM_VPN_CONNECTION_INTERNAL_STATE_CHANGED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL,
		              _nm_marshal_VOID__UINT_UINT_UINT,
		              G_TYPE_NONE, 3, G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (object_class),
	                                 &dbus_glib_nm_vpn_connection_object_info);
}

