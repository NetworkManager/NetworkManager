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
 * Copyright (C) 2005 - 2013 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "config.h"

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>

#include "nm-default.h"
#include "nm-vpn-connection.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-platform.h"
#include "nm-active-connection.h"
#include "NetworkManagerUtils.h"
#include "settings/nm-settings-connection.h"
#include "nm-dispatcher.h"
#include "nm-agent-manager.h"
#include "nm-core-internal.h"
#include "nm-default-route-manager.h"
#include "nm-route-manager.h"
#include "nm-firewall-manager.h"
#include "nm-config.h"

#include "nmdbus-vpn-connection.h"

G_DEFINE_TYPE (NMVpnConnection, nm_vpn_connection, NM_TYPE_ACTIVE_CONNECTION)

typedef enum {
	/* Only system secrets */
	SECRETS_REQ_SYSTEM = 0,
	/* All existing secrets including agent secrets */
	SECRETS_REQ_EXISTING = 1,
	/* New secrets required; ask an agent */
	SECRETS_REQ_NEW = 2,
	/* Plugin requests secrets interactively */
	SECRETS_REQ_INTERACTIVE = 3,
	/* Placeholder for bounds checking */
	SECRETS_REQ_LAST
} SecretsReq;

/* Internal VPN states, private to NMVpnConnection */
typedef enum {
	STATE_UNKNOWN = 0,
	STATE_WAITING,
	STATE_PREPARE,
	STATE_NEED_AUTH,
	STATE_CONNECT,
	STATE_IP_CONFIG_GET,
	STATE_PRE_UP,
	STATE_ACTIVATED,
	STATE_DEACTIVATING,
	STATE_DISCONNECTED,
	STATE_FAILED,
} VpnState;

typedef struct {
	gboolean service_can_persist;
	gboolean connection_can_persist;

	NMSettingsConnectionCallId secrets_id;
	SecretsReq secrets_idx;
	char *username;

	VpnState vpn_state;
	guint dispatcher_id;
	NMVpnConnectionStateReason failure_reason;

	NMVpnServiceState service_state;

	/* Firewall */
	NMFirewallManagerCallId fw_call;

	NMDefaultRouteManager *default_route_manager;
	NMRouteManager *route_manager;
	GDBusProxy *proxy;
	GCancellable *cancellable;
	GVariant *connect_hash;
	guint connect_timeout;
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
} NMVpnConnectionPrivate;

#define NM_VPN_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_CONNECTION, NMVpnConnectionPrivate))

enum {
	VPN_STATE_CHANGED,
	INTERNAL_STATE_CHANGED,
	INTERNAL_RETRY_AFTER_FAILURE,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_VPN_STATE,
	PROP_BANNER,
	PROP_IP4_CONFIG,
	PROP_IP6_CONFIG,
	PROP_MASTER = 2000,

	LAST_PROP
};

static NMSettingsConnection *_get_settings_connection (NMVpnConnection *self,
                                                       gboolean allow_missing);

static void get_secrets (NMVpnConnection *self,
                         SecretsReq secrets_idx,
                         const char **hints);

static void plugin_interactive_secrets_required (NMVpnConnection *self,
                                                 const char *message,
                                                 const char **secrets);

static void _set_vpn_state (NMVpnConnection *self,
                            VpnState vpn_state,
                            NMVpnConnectionStateReason reason,
                            gboolean quitting);

/*********************************************************************/

#define _NMLOG_DOMAIN      LOGD_VPN
#define _NMLOG_PREFIX_NAME "vpn-connection"

#define __NMLOG_prefix_buf_len 128

static const char *
__LOG_create_prefix (char *buf, NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv;
	NMConnection *con;
	const char *id;

	if (!self)
		return _NMLOG_PREFIX_NAME;

	priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	con = NM_CONNECTION (_get_settings_connection (self, TRUE));
	id = con ? nm_connection_get_id (con) : NULL;

	g_snprintf (buf, __NMLOG_prefix_buf_len,
	            "%s["
	            "%p"       /*self*/
	            "%s%s"     /*con-uuid*/
	            "%s%s%s%s" /*con-id*/
	            ",%d"      /*ifindex*/
	            "%s%s%s%s" /*iface*/
	            "]",
	            _NMLOG_PREFIX_NAME,
	            self,
	            con ? "," : "--", con ? str_if_set (nm_connection_get_uuid (con), "??") : "",
	            con ? "," : "", NM_PRINT_FMT_QUOTED (id, "\"", id, "\"", con ? "??" : ""),
	            priv->ip_ifindex,
	            priv->ip_iface ? ":" : "", NM_PRINT_FMT_QUOTED (priv->ip_iface, "(", priv->ip_iface, ")", "")
	            );

	return buf;
}

#define _NMLOG(level, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        \
        if (nm_logging_enabled (__level, _NMLOG_DOMAIN)) { \
            char __prefix[__NMLOG_prefix_buf_len]; \
            \
            _nm_log (__level, _NMLOG_DOMAIN, 0, \
                     "%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     __LOG_create_prefix (__prefix, self) \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*********************************************************************/

static void
cancel_get_secrets (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	if (priv->secrets_id) {
		nm_settings_connection_cancel_secrets (_get_settings_connection (self, FALSE),
		                                       priv->secrets_id);
		g_warn_if_fail (!priv->secrets_id);
		priv->secrets_id = NULL;
	}
}

static NMVpnConnectionState
_state_to_nm_vpn_state (VpnState state)
{
	switch (state) {
	case STATE_WAITING:
	case STATE_PREPARE:
		return NM_VPN_CONNECTION_STATE_PREPARE;
	case STATE_NEED_AUTH:
		return NM_VPN_CONNECTION_STATE_NEED_AUTH;
	case STATE_CONNECT:
		return NM_VPN_CONNECTION_STATE_CONNECT;
	case STATE_IP_CONFIG_GET:
	case STATE_PRE_UP:
		return NM_VPN_CONNECTION_STATE_IP_CONFIG_GET;
	case STATE_ACTIVATED:
		return NM_VPN_CONNECTION_STATE_ACTIVATED;
	case STATE_DEACTIVATING: {
		/* Map DEACTIVATING to ACTIVATED to preserve external API behavior,
		 * since our API has no DEACTIVATING state of its own.  Since this can
		 * take some time, and the VPN isn't actually disconnected until it
		 * hits the DISCONNECTED state, to clients it should still appear
		 * connected.
		 */
		return NM_VPN_CONNECTION_STATE_ACTIVATED;
	}
	case STATE_DISCONNECTED:
		return NM_VPN_CONNECTION_STATE_DISCONNECTED;
	case STATE_FAILED:
		return NM_VPN_CONNECTION_STATE_FAILED;
	default:
		return NM_VPN_CONNECTION_STATE_UNKNOWN;
	}
}

static NMActiveConnectionState
_state_to_ac_state (VpnState vpn_state)
{
	/* Set the NMActiveConnection state based on VPN state */
	switch (vpn_state) {
	case STATE_WAITING:
	case STATE_PREPARE:
	case STATE_NEED_AUTH:
	case STATE_CONNECT:
	case STATE_IP_CONFIG_GET:
	case STATE_PRE_UP:
		return NM_ACTIVE_CONNECTION_STATE_ACTIVATING;
	case STATE_ACTIVATED:
		return NM_ACTIVE_CONNECTION_STATE_ACTIVATED;
	case STATE_DEACTIVATING:
		return NM_ACTIVE_CONNECTION_STATE_DEACTIVATING;
	case STATE_DISCONNECTED:
	case STATE_FAILED:
		return NM_ACTIVE_CONNECTION_STATE_DEACTIVATED;
	default:
		break;
	}
	return NM_ACTIVE_CONNECTION_STATE_UNKNOWN;
}

static NMSettingsConnection *
_get_settings_connection (NMVpnConnection *self, gboolean allow_missing)
{
	NMSettingsConnection *con;

	/* Currently we operate on the assumption, that the settings-connection
	 * never changes after it is set (though initially, it might be unset).
	 * Later we might want to change that, but then we need fixes here too. */

	con = _nm_active_connection_get_settings_connection (NM_ACTIVE_CONNECTION (self));
	if (!con && !allow_missing)
		g_return_val_if_reached (NULL);
	return con;
}

static NMConnection *
_get_applied_connection (NMVpnConnection *connection)
{
	NMConnection *con;

	con = nm_active_connection_get_applied_connection (NM_ACTIVE_CONNECTION (connection));
	g_return_val_if_fail (con, NULL);
	return con;
}

static void
call_plugin_disconnect (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	if (priv->proxy) {
		g_dbus_proxy_call (priv->proxy, "Disconnect", NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL, NULL);
		g_clear_object (&priv->proxy);
	}
}

static void
fw_call_cleanup (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	if (priv->fw_call) {
		nm_firewall_manager_cancel_call (priv->fw_call);
		g_warn_if_fail (!priv->fw_call);
		priv->fw_call = NULL;
	}
}

static void
vpn_cleanup (NMVpnConnection *self, NMDevice *parent_dev)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	if (priv->ip_ifindex) {
		nm_platform_link_set_down (NM_PLATFORM_GET, priv->ip_ifindex);
		nm_route_manager_route_flush (priv->route_manager, priv->ip_ifindex);
		nm_platform_address_flush (NM_PLATFORM_GET, priv->ip_ifindex);
	}

	nm_device_set_vpn4_config (parent_dev, NULL);
	nm_device_set_vpn6_config (parent_dev, NULL);

	/* Remove zone from firewall */
	if (priv->ip_iface) {
		nm_firewall_manager_remove_from_zone (nm_firewall_manager_get (),
		                                      priv->ip_iface,
		                                      NULL,
		                                      NULL,
		                                      NULL);
	}
	/* Cancel pending firewall call */
	fw_call_cleanup (self);

	g_free (priv->banner);
	priv->banner = NULL;

	g_free (priv->ip_iface);
	priv->ip_iface = NULL;
	priv->ip_ifindex = 0;

	/* Clear out connection secrets to ensure that the settings service
	 * gets asked for them next time the connection is activated.
	 */
	nm_active_connection_clear_secrets (NM_ACTIVE_CONNECTION (self));
}

static void
dispatcher_pre_down_done (guint call_id, gpointer user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	priv->dispatcher_id = 0;
	_set_vpn_state (self, STATE_DISCONNECTED, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);
}

static void
dispatcher_pre_up_done (guint call_id, gpointer user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	priv->dispatcher_id = 0;
	_set_vpn_state (self, STATE_ACTIVATED, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);
}

static void
dispatcher_cleanup (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	if (priv->dispatcher_id) {
		nm_dispatcher_call_cancel (priv->dispatcher_id);
		priv->dispatcher_id = 0;
	}
}

static void
_set_vpn_state (NMVpnConnection *self,
                VpnState vpn_state,
                NMVpnConnectionStateReason reason,
                gboolean quitting)
{
	NMVpnConnectionPrivate *priv;
	VpnState old_vpn_state;
	NMVpnConnectionState new_external_state, old_external_state;
	NMDevice *parent_dev = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (self));

	g_return_if_fail (NM_IS_VPN_CONNECTION (self));

	priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	if (vpn_state == priv->vpn_state)
		return;

	old_vpn_state = priv->vpn_state;
	priv->vpn_state = vpn_state;

	/* The device gets destroyed by active connection when it enters
	 * the deactivated state, so we need to ref it for usage below.
	 */
	if (parent_dev)
		g_object_ref (parent_dev);

	/* Update active connection base class state */
	nm_active_connection_set_state (NM_ACTIVE_CONNECTION (self),
	                                _state_to_ac_state (vpn_state));

	/* Clear any in-progress secrets request */
	cancel_get_secrets (self);

	dispatcher_cleanup (self);

	nm_default_route_manager_ip4_update_default_route (priv->default_route_manager, self);
	nm_default_route_manager_ip6_update_default_route (priv->default_route_manager, self);

	/* The connection gets destroyed by the VPN manager when it enters the
	 * disconnected/failed state, but we need to keep it around for a bit
	 * to send out signals and handle the dispatcher.  So ref it.
	 */
	g_object_ref (self);

	old_external_state = _state_to_nm_vpn_state (old_vpn_state);
	new_external_state = _state_to_nm_vpn_state (priv->vpn_state);
	if (new_external_state != old_external_state) {
		g_signal_emit (self, signals[VPN_STATE_CHANGED], 0, new_external_state, reason);
		g_signal_emit (self, signals[INTERNAL_STATE_CHANGED], 0,
		               new_external_state,
		               old_external_state,
		               reason);
		g_object_notify (G_OBJECT (self), NM_VPN_CONNECTION_VPN_STATE);
	}

	switch (vpn_state) {
	case STATE_NEED_AUTH:
		/* Do nothing; not part of 'default' because we don't want to touch
		 * priv->secrets_req as NEED_AUTH is re-entered during interactive
		 * secrets.
		 */
		break;
	case STATE_PRE_UP:
		if (!nm_dispatcher_call_vpn (DISPATCHER_ACTION_VPN_PRE_UP,
		                             _get_settings_connection (self, FALSE),
		                             _get_applied_connection (self),
		                             parent_dev,
		                             priv->ip_iface,
		                             priv->ip4_config,
		                             priv->ip6_config,
		                             dispatcher_pre_up_done,
		                             self,
		                             &priv->dispatcher_id)) {
			/* Just proceed on errors */
			dispatcher_pre_up_done (0, self);
		}
		break;
	case STATE_ACTIVATED:
		/* Secrets no longer needed now that we're connected */
		nm_active_connection_clear_secrets (NM_ACTIVE_CONNECTION (self));

		/* Let dispatcher scripts know we're up and running */
		nm_dispatcher_call_vpn (DISPATCHER_ACTION_VPN_UP,
		                        _get_settings_connection (self, FALSE),
		                        _get_applied_connection (self),
		                        parent_dev,
		                        priv->ip_iface,
		                        priv->ip4_config,
		                        priv->ip6_config,
		                        NULL,
		                        NULL,
		                        NULL);
		break;
	case STATE_DEACTIVATING:
		if (quitting) {
			nm_dispatcher_call_vpn_sync (DISPATCHER_ACTION_VPN_PRE_DOWN,
			                             _get_settings_connection (self, FALSE),
			                             _get_applied_connection (self),
			                             parent_dev,
			                             priv->ip_iface,
			                             priv->ip4_config,
			                             priv->ip6_config);
		} else {
			if (!nm_dispatcher_call_vpn (DISPATCHER_ACTION_VPN_PRE_DOWN,
			                             _get_settings_connection (self, FALSE),
			                             _get_applied_connection (self),
			                             parent_dev,
			                             priv->ip_iface,
			                             priv->ip4_config,
			                             priv->ip6_config,
			                             dispatcher_pre_down_done,
			                             self,
			                             &priv->dispatcher_id)) {
				/* Just proceed on errors */
				dispatcher_pre_down_done (0, self);
			}
		}
		break;
	case STATE_FAILED:
	case STATE_DISCONNECTED:
		if (   old_vpn_state >= STATE_ACTIVATED
		    && old_vpn_state <= STATE_DEACTIVATING) {
			/* Let dispatcher scripts know we're about to go down */
			if (quitting) {
				nm_dispatcher_call_vpn_sync (DISPATCHER_ACTION_VPN_DOWN,
				                             _get_settings_connection (self, FALSE),
				                             _get_applied_connection (self),
				                             parent_dev,
				                             priv->ip_iface,
				                             NULL,
				                             NULL);
			} else {
				nm_dispatcher_call_vpn (DISPATCHER_ACTION_VPN_DOWN,
				                        _get_settings_connection (self, FALSE),
				                        _get_applied_connection (self),
				                        parent_dev,
				                        priv->ip_iface,
				                        NULL,
				                        NULL,
				                        NULL,
				                        NULL,
				                        NULL);
			}
		}

		/* Tear down and clean up the connection */
		call_plugin_disconnect (self);
		vpn_cleanup (self, parent_dev);
		/* Fall through */
	default:
		priv->secrets_idx = SECRETS_REQ_SYSTEM;
		break;
	}

	g_object_unref (self);
	if (parent_dev)
		g_object_unref (parent_dev);
}

static gboolean
_service_and_connection_can_persist (NMVpnConnection *self)
{
	return NM_VPN_CONNECTION_GET_PRIVATE (self)->connection_can_persist &&
	       NM_VPN_CONNECTION_GET_PRIVATE (self)->service_can_persist;
}

static gboolean
_connection_only_can_persist (NMVpnConnection *self)
{
	return NM_VPN_CONNECTION_GET_PRIVATE (self)->connection_can_persist &&
	       !NM_VPN_CONNECTION_GET_PRIVATE (self)->service_can_persist;
}

static void
device_state_changed (NMActiveConnection *active,
                      NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state)
{
	if (_service_and_connection_can_persist (NM_VPN_CONNECTION (active))) {
		if (new_state <= NM_DEVICE_STATE_DISCONNECTED ||
		    new_state == NM_DEVICE_STATE_FAILED) {
			nm_active_connection_set_device (active, NULL);
		}
		return;
	}

	if (new_state <= NM_DEVICE_STATE_DISCONNECTED) {
		_set_vpn_state (NM_VPN_CONNECTION (active),
		                STATE_DISCONNECTED,
		                NM_VPN_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED,
		                FALSE);
	} else if (new_state == NM_DEVICE_STATE_FAILED) {
		_set_vpn_state (NM_VPN_CONNECTION (active),
		                STATE_FAILED,
		                NM_VPN_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED,
		                FALSE);
	}

	/* FIXME: map device DEACTIVATING state to VPN DEACTIVATING state and
	 * block device deactivation on VPN deactivation.
	 */
}

static void
add_ip4_vpn_gateway_route (NMIP4Config *config, NMDevice *parent_device, guint32 vpn_gw)
{
	NMIP4Config *parent_config;
	guint32 parent_gw;
	NMPlatformIP4Route route;
	guint32 route_metric;

	g_return_if_fail (NM_IS_IP4_CONFIG (config));
	g_return_if_fail (NM_IS_DEVICE (parent_device));
	g_return_if_fail (vpn_gw != 0);

	/* Set up a route to the VPN gateway's public IP address through the default
	 * network device if the VPN gateway is on a different subnet.
	 */

	parent_config = nm_device_get_ip4_config (parent_device);
	g_return_if_fail (parent_config != NULL);
	parent_gw = nm_ip4_config_get_gateway (parent_config);
	if (!parent_gw)
		return;

	route_metric = nm_device_get_ip4_route_metric (parent_device);

	memset (&route, 0, sizeof (route));
	route.network = vpn_gw;
	route.plen = 32;
	route.gateway = parent_gw;

	/* If the VPN gateway is in the same subnet as one of the parent device's
	 * IP addresses, don't add the host route to it, but a route through the
	 * parent device.
	 */
	if (nm_ip4_config_destination_is_direct (parent_config, vpn_gw, 32))
		route.gateway = 0;

	route.source = NM_IP_CONFIG_SOURCE_VPN;
	route.metric = route_metric;
	nm_ip4_config_add_route (config, &route);

	/* Ensure there's a route to the parent device's gateway through the
	 * parent device, since if the VPN claims the default route and the VPN
	 * routes include a subnet that matches the parent device's subnet,
	 * the parent device's gateway would get routed through the VPN and fail.
	 */
	memset (&route, 0, sizeof (route));
	route.network = parent_gw;
	route.plen = 32;
	route.source = NM_IP_CONFIG_SOURCE_VPN;
	route.metric = route_metric;

	nm_ip4_config_add_route (config, &route);
}

static void
add_ip6_vpn_gateway_route (NMIP6Config *config,
                           NMDevice *parent_device,
                           const struct in6_addr *vpn_gw)
{
	NMIP6Config *parent_config;
	const struct in6_addr *parent_gw;
	NMPlatformIP6Route route;
	guint32 route_metric;

	g_return_if_fail (NM_IS_IP6_CONFIG (config));
	g_return_if_fail (NM_IS_DEVICE (parent_device));
	g_return_if_fail (vpn_gw != NULL);

	parent_config = nm_device_get_ip6_config (parent_device);
	g_return_if_fail (parent_config != NULL);
	parent_gw = nm_ip6_config_get_gateway (parent_config);
	if (!parent_gw)
		return;

	route_metric = nm_device_get_ip6_route_metric (parent_device);

	memset (&route, 0, sizeof (route));
	route.network = *vpn_gw;
	route.plen = 128;
	route.gateway = *parent_gw;

	/* If the VPN gateway is in the same subnet as one of the parent device's
	 * IP addresses, don't add the host route to it, but a route through the
	 * parent device.
	 */
	if (nm_ip6_config_destination_is_direct (parent_config, vpn_gw, 128))
		route.gateway = in6addr_any;

	route.source = NM_IP_CONFIG_SOURCE_VPN;
	route.metric = route_metric;
	nm_ip6_config_add_route (config, &route);

	/* Ensure there's a route to the parent device's gateway through the
	 * parent device, since if the VPN claims the default route and the VPN
	 * routes include a subnet that matches the parent device's subnet,
	 * the parent device's gateway would get routed through the VPN and fail.
	 */
	memset (&route, 0, sizeof (route));
	route.network = *parent_gw;
	route.plen = 128;
	route.source = NM_IP_CONFIG_SOURCE_VPN;
	route.metric = route_metric;

	nm_ip6_config_add_route (config, &route);
}

NMVpnConnection *
nm_vpn_connection_new (NMSettingsConnection *settings_connection,
                       NMDevice *parent_device,
                       const char *specific_object,
                       NMAuthSubject *subject)
{
	g_return_val_if_fail (!settings_connection || NM_IS_SETTINGS_CONNECTION (settings_connection), NULL);
	g_return_val_if_fail (NM_IS_DEVICE (parent_device), NULL);

	return (NMVpnConnection *) g_object_new (NM_TYPE_VPN_CONNECTION,
	                                         NM_ACTIVE_CONNECTION_INT_SETTINGS_CONNECTION, settings_connection,
	                                         NM_ACTIVE_CONNECTION_INT_DEVICE, parent_device,
	                                         NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT, specific_object,
	                                         NM_ACTIVE_CONNECTION_INT_SUBJECT, subject,
	                                         NM_ACTIVE_CONNECTION_VPN, TRUE,
	                                         NULL);
}

static const char *
nm_vpn_connection_get_service (NMVpnConnection *self)
{
	NMSettingVpn *s_vpn;

	s_vpn = nm_connection_get_setting_vpn (_get_applied_connection (self));
	return nm_setting_vpn_get_service_type (s_vpn);
}

static const char *
vpn_plugin_failure_to_string (NMVpnPluginFailure failure)
{
	switch (failure) {
	case NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED:
		return "login-failed";
	case NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED:
		return "connect-failed";
	case NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG:
		return "bad-ip-config";
	default:
		break;
	}
	return "unknown";
}

static void
plugin_failed (NMVpnConnection *self, guint reason)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	_LOGW ("VPN plugin: failed: %s (%d)", vpn_plugin_failure_to_string (reason), reason);

	switch (reason) {
	case NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED:
		priv->failure_reason = NM_VPN_CONNECTION_STATE_REASON_LOGIN_FAILED;
		break;
	case NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG:
		priv->failure_reason = NM_VPN_CONNECTION_STATE_REASON_IP_CONFIG_INVALID;
		break;
	default:
		priv->failure_reason = NM_VPN_CONNECTION_STATE_REASON_UNKNOWN;
		break;
	}
}

static const char *
vpn_service_state_to_string (NMVpnServiceState state)
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

static const char *state_table[] = {
	[STATE_UNKNOWN]       = "unknown",
	[STATE_WAITING]       = "waiting",
	[STATE_PREPARE]       = "prepare",
	[STATE_NEED_AUTH]     = "need-auth",
	[STATE_CONNECT]       = "connect",
	[STATE_IP_CONFIG_GET] = "ip-config-get",
	[STATE_PRE_UP]        = "pre-up",
	[STATE_ACTIVATED]     = "activated",
	[STATE_DEACTIVATING]  = "deactivating",
	[STATE_DISCONNECTED]  = "disconnected",
	[STATE_FAILED]        = "failed",
};

static const char *
vpn_state_to_string (VpnState state)
{
	if ((gsize) state < G_N_ELEMENTS (state_table))
		return state_table[state];
	return "unknown";
}

static const char *
vpn_reason_to_string (NMVpnConnectionStateReason reason)
{
	switch (reason) {
	case NM_VPN_CONNECTION_STATE_REASON_NONE:
		return "none";
	case NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED:
		return "user-disconnected";
	case NM_VPN_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED:
		return "device-disconnected";
	case NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED:
		return "service-stopped";
	case NM_VPN_CONNECTION_STATE_REASON_IP_CONFIG_INVALID:
		return "ip-config-invalid";
	case NM_VPN_CONNECTION_STATE_REASON_CONNECT_TIMEOUT:
		return "connect-timeout";
	case NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT:
		return "service-start-timeout";
	case NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED:
		return "service-start-failed";
	case NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS:
		return "no-secrets";
	case NM_VPN_CONNECTION_STATE_REASON_LOGIN_FAILED:
		return "login-failed";
	case NM_VPN_CONNECTION_STATE_REASON_CONNECTION_REMOVED:
		return "connection-removed";
	default:
		break;
	}
	return "unknown";
}

static void
plugin_state_changed (NMVpnConnection *self, NMVpnServiceState new_service_state)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	NMVpnServiceState old_service_state = priv->service_state;

	_LOGI ("VPN plugin: state changed: %s (%d)",
	       vpn_service_state_to_string (new_service_state), new_service_state);
	priv->service_state = new_service_state;

	if (new_service_state == NM_VPN_SERVICE_STATE_STOPPED) {
		/* Clear connection secrets to ensure secrets get requested each time the
		 * connection is activated.
		 */
		nm_active_connection_clear_secrets (NM_ACTIVE_CONNECTION (self));

		if ((priv->vpn_state >= STATE_WAITING) && (priv->vpn_state <= STATE_ACTIVATED)) {
			VpnState old_state = priv->vpn_state;

			_LOGI ("VPN plugin: state change reason: %s (%d)",
			       vpn_reason_to_string (priv->failure_reason), priv->failure_reason);
			_set_vpn_state (self, STATE_FAILED, priv->failure_reason, FALSE);

			/* Reset the failure reason */
			priv->failure_reason = NM_VPN_CONNECTION_STATE_REASON_UNKNOWN;

			/* If the connection failed, the service cannot persist, but the
			 * connection can persist, ask listeners to re-activate the connection.
			 */
			if (   old_state == STATE_ACTIVATED
			    && priv->vpn_state == STATE_FAILED
			    && _connection_only_can_persist (self))
				g_signal_emit (self, signals[INTERNAL_RETRY_AFTER_FAILURE], 0);
		}
	} else if (new_service_state == NM_VPN_SERVICE_STATE_STARTING &&
	           old_service_state == NM_VPN_SERVICE_STATE_STARTED) {
		/* The VPN service got disconnected and is attempting to reconnect */
		_set_vpn_state (self, STATE_CONNECT, NM_VPN_CONNECTION_STATE_REASON_CONNECT_TIMEOUT, FALSE);
	}
}

static void
print_vpn_config (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	const NMPlatformIP4Address *address4;
	const NMPlatformIP6Address *address6;
	char *dns_domain = NULL;
	guint32 num, i;
	char buf[NM_UTILS_INET_ADDRSTRLEN];

	if (priv->ip4_external_gw) {
		_LOGI ("Data: VPN Gateway: %s",
		       nm_utils_inet4_ntop (priv->ip4_external_gw, NULL));
	} else if (priv->ip6_external_gw) {
		_LOGI ("Data: VPN Gateway: %s",
		       nm_utils_inet6_ntop (priv->ip6_external_gw, NULL));
	}

	_LOGI ("Data: Tunnel Device: %s", priv->ip_iface ? priv->ip_iface : "(none)");

	if (priv->ip4_config) {
		_LOGI ("Data: IPv4 configuration:");

		address4 = nm_ip4_config_get_address (priv->ip4_config, 0);

		if (priv->ip4_internal_gw)
			_LOGI ("Data:   Internal Gateway: %s", nm_utils_inet4_ntop (priv->ip4_internal_gw, NULL));
		_LOGI ("Data:   Internal Address: %s", nm_utils_inet4_ntop (address4->address, NULL));
		_LOGI ("Data:   Internal Prefix: %d", address4->plen);
		_LOGI ("Data:   Internal Point-to-Point Address: %s", nm_utils_inet4_ntop (address4->peer_address, NULL));
		_LOGI ("Data:   Maximum Segment Size (MSS): %d", nm_ip4_config_get_mss (priv->ip4_config));

		num = nm_ip4_config_get_num_routes (priv->ip4_config);
		for (i = 0; i < num; i++) {
			const NMPlatformIP4Route *route = nm_ip4_config_get_route (priv->ip4_config, i);

			_LOGI ("Data:   Static Route: %s/%d   Next Hop: %s",
			       nm_utils_inet4_ntop (route->network, NULL),
			       route->plen,
			       nm_utils_inet4_ntop (route->gateway, buf));
		}

		_LOGI ("Data:   Forbid Default Route: %s",
		       nm_ip4_config_get_never_default (priv->ip4_config) ? "yes" : "no");

		num = nm_ip4_config_get_num_nameservers (priv->ip4_config);
		for (i = 0; i < num; i++) {
			_LOGI ("Data:   Internal DNS: %s",
			       nm_utils_inet4_ntop (nm_ip4_config_get_nameserver (priv->ip4_config, i), NULL));
		}

		if (nm_ip4_config_get_num_domains (priv->ip4_config) > 0)
			dns_domain = (char *) nm_ip4_config_get_domain (priv->ip4_config, 0);

		_LOGI ("Data:   DNS Domain: '%s'", dns_domain ? dns_domain : "(none)");
	} else
		_LOGI ("Data: No IPv4 configuration");

	if (priv->ip6_config) {
		_LOGI ("Data: IPv6 configuration:");

		address6 = nm_ip6_config_get_address (priv->ip6_config, 0);

		if (priv->ip6_internal_gw)
			_LOGI ("Data:   Internal Gateway: %s", nm_utils_inet6_ntop (priv->ip6_internal_gw, NULL));
		_LOGI ("Data:   Internal Address: %s", nm_utils_inet6_ntop (&address6->address, NULL));
		_LOGI ("Data:   Internal Prefix: %d", address6->plen);
		_LOGI ("Data:   Internal Point-to-Point Address: %s", nm_utils_inet6_ntop (&address6->peer_address, NULL));
		_LOGI ("Data:   Maximum Segment Size (MSS): %d", nm_ip6_config_get_mss (priv->ip6_config));

		num = nm_ip6_config_get_num_routes (priv->ip6_config);
		for (i = 0; i < num; i++) {
			const NMPlatformIP6Route *route = nm_ip6_config_get_route (priv->ip6_config, i);

			_LOGI ("Data:   Static Route: %s/%d   Next Hop: %s",
			       nm_utils_inet6_ntop (&route->network, NULL),
			       route->plen,
			       nm_utils_inet6_ntop (&route->gateway, buf));
		}

		_LOGI ("Data:   Forbid Default Route: %s",
		       nm_ip6_config_get_never_default (priv->ip6_config) ? "yes" : "no");

		num = nm_ip6_config_get_num_nameservers (priv->ip6_config);
		for (i = 0; i < num; i++) {
			_LOGI ("Data:   Internal DNS: %s",
			       nm_utils_inet6_ntop (nm_ip6_config_get_nameserver (priv->ip6_config, i), NULL));
		}

		if (nm_ip6_config_get_num_domains (priv->ip6_config) > 0)
			dns_domain = (char *) nm_ip6_config_get_domain (priv->ip6_config, 0);

		_LOGI ("Data:   DNS Domain: '%s'", dns_domain ? dns_domain : "(none)");
	} else
		_LOGI ("Data: No IPv6 configuration");

	if (priv->banner && strlen (priv->banner)) {
		_LOGI ("Data: Login Banner:");
		_LOGI ("Data: -----------------------------------------");
		_LOGI ("Data: %s", priv->banner);
		_LOGI ("Data: -----------------------------------------");
	}
}

static void
apply_parent_device_config (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	NMDevice *parent_dev = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (self));
	NMIP4Config *vpn4_parent_config = NULL;
	NMIP6Config *vpn6_parent_config = NULL;

	if (priv->ip_ifindex > 0) {
		if (priv->ip4_config)
			vpn4_parent_config = nm_ip4_config_new (priv->ip_ifindex);
		if (priv->ip6_config)
			vpn6_parent_config = nm_ip6_config_new (priv->ip_ifindex);
	} else {
		int ifindex;

		/* If the VPN didn't return a network interface, it is a route-based
		 * VPN (like kernel IPSec) and all IP addressing and routing should
		 * be done on the parent interface instead.
		 */

		/* Also clear the gateway. We don't configure the gateway as part of the
		 * vpn-config. Instead we tell NMDefaultRouteManager directly about the
		 * default route. */
		ifindex = nm_device_get_ip_ifindex (parent_dev);
		if (priv->ip4_config) {
			vpn4_parent_config = nm_ip4_config_new (ifindex);
			nm_ip4_config_merge (vpn4_parent_config, priv->ip4_config, NM_IP_CONFIG_MERGE_DEFAULT);
			nm_ip4_config_unset_gateway (vpn4_parent_config);
		}
		if (priv->ip6_config) {
			vpn6_parent_config = nm_ip6_config_new (ifindex);
			nm_ip6_config_merge (vpn6_parent_config, priv->ip6_config, NM_IP_CONFIG_MERGE_DEFAULT);
			nm_ip6_config_set_gateway (vpn6_parent_config, NULL);
		}
	}

	if (vpn4_parent_config) {
		/* Add any explicit route to the VPN gateway through the parent device */
		if (priv->ip4_external_gw)
			add_ip4_vpn_gateway_route (vpn4_parent_config, parent_dev, priv->ip4_external_gw);

		nm_device_set_vpn4_config (parent_dev, vpn4_parent_config);
		g_object_unref (vpn4_parent_config);
	}
	if (vpn6_parent_config) {
		/* Add any explicit route to the VPN gateway through the parent device */
		if (priv->ip6_external_gw)
			add_ip6_vpn_gateway_route (vpn6_parent_config, parent_dev, priv->ip6_external_gw);

		nm_device_set_vpn6_config (parent_dev, vpn6_parent_config);
		g_object_unref (vpn6_parent_config);
	}
}

static gboolean
nm_vpn_connection_apply_config (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	if (priv->ip_ifindex > 0) {
		nm_platform_link_set_up (NM_PLATFORM_GET, priv->ip_ifindex, NULL);

		if (priv->ip4_config) {
			if (!nm_ip4_config_commit (priv->ip4_config, priv->ip_ifindex,
			                           TRUE,
			                           nm_vpn_connection_get_ip4_route_metric (self)))
				return FALSE;
		}

		if (priv->ip6_config) {
			if (!nm_ip6_config_commit (priv->ip6_config,
			                           priv->ip_ifindex,
			                           TRUE))
				return FALSE;
		}

		if (priv->mtu && priv->mtu != nm_platform_link_get_mtu (NM_PLATFORM_GET, priv->ip_ifindex))
			nm_platform_link_set_mtu (NM_PLATFORM_GET, priv->ip_ifindex, priv->mtu);
	}

	apply_parent_device_config (self);

	nm_default_route_manager_ip4_update_default_route (priv->default_route_manager, self);
	nm_default_route_manager_ip6_update_default_route (priv->default_route_manager, self);

	_LOGI ("VPN connection: (IP Config Get) complete");
	_set_vpn_state (self, STATE_PRE_UP, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);
	return TRUE;
}

static void
_cleanup_failed_config (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	g_clear_object (&priv->ip4_config);
	g_clear_object (&priv->ip6_config);

	_LOGW ("VPN connection: did not receive valid IP config information");
	_set_vpn_state (self, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_IP_CONFIG_INVALID, FALSE);
}

static void
fw_change_zone_cb (NMFirewallManager *firewall_manager,
                   NMFirewallManagerCallId call_id,
                   GError *error,
                   gpointer user_data)
{
	NMVpnConnection *self = user_data;
	NMVpnConnectionPrivate *priv;

	g_return_if_fail (NM_IS_VPN_CONNECTION (self));

	priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	g_return_if_fail (priv->fw_call == call_id);

	priv->fw_call = NULL;

	if (nm_utils_error_is_cancelled (error, FALSE))
		return;

	if (error) {
		// FIXME: fail the activation?
	}

	if (!nm_vpn_connection_apply_config (self))
		_cleanup_failed_config (self);
}

static void
nm_vpn_connection_config_maybe_complete (NMVpnConnection *self,
                                         gboolean         success)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	NMConnection *base_con;
	NMSettingConnection *s_con;
	const char *zone;

	if (priv->vpn_state < STATE_IP_CONFIG_GET || priv->vpn_state > STATE_ACTIVATED)
		return;

	if (success) {
		if (   (priv->has_ip4 && !priv->ip4_config)
		    || (priv->has_ip6 && !priv->ip6_config)) {
			/* Need to wait for other config */
			return;
		}
	}

	if (priv->connect_timeout) {
		g_source_remove (priv->connect_timeout);
		priv->connect_timeout = 0;
	}

	if (success) {
		print_vpn_config (self);

		/* Add the tunnel interface to the specified firewall zone */
		if (priv->ip_iface) {
			base_con = _get_applied_connection (self);
			s_con = nm_connection_get_setting_connection (base_con);
			zone = nm_setting_connection_get_zone (s_con);

			_LOGD ("setting firewall zone %s%s%s for '%s'",
			       NM_PRINT_FMT_QUOTED (zone, "'", zone, "'", "(default)"),
			       priv->ip_iface);
			fw_call_cleanup (self);
			priv->fw_call = nm_firewall_manager_add_or_change_zone (nm_firewall_manager_get (),
			                                                        priv->ip_iface,
			                                                        zone,
			                                                        FALSE,
			                                                        fw_change_zone_cb,
			                                                        self);
			return;
		} else
			if (nm_vpn_connection_apply_config (self))
				return;
	}

	_cleanup_failed_config (self);
}

static gboolean
ip6_addr_from_variant (GVariant *v, struct in6_addr *addr)
{
	const guint8 *bytes;
	gsize len;

	g_return_val_if_fail (v, FALSE);
	g_return_val_if_fail (addr, FALSE);

	if (g_variant_is_of_type (v, G_VARIANT_TYPE ("ay"))) {
		bytes = g_variant_get_fixed_array (v, &len, sizeof (guint8));
		if (len == sizeof (struct in6_addr) && !IN6_IS_ADDR_UNSPECIFIED (bytes)) {
			memcpy (addr, bytes, len);
			return TRUE;
		}
	}
	return FALSE;
}

static struct in6_addr *
ip6_addr_dup_from_variant (GVariant *v)
{
	struct in6_addr *addr;

	addr = g_malloc0 (sizeof (*addr));
	if (ip6_addr_from_variant (v, addr))
		return addr;
	g_free (addr);
	return NULL;
}

static gboolean
process_generic_config (NMVpnConnection *self, GVariant *dict)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	const char *str;
	GVariant *v;
	guint32 u32;
	gboolean b, success = FALSE;

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_CAN_PERSIST, "b", &b) && b) {
		/* Defaults to FALSE, so only let service indicate TRUE */
		priv->service_can_persist = TRUE;
	}

	g_clear_pointer (&priv->ip_iface, g_free);
	if (g_variant_lookup (dict, NM_VPN_PLUGIN_CONFIG_TUNDEV, "&s", &str)) {
		/* Backwards compat with NM-openswan */
		if (g_strcmp0 (str, "_none_") != 0)
			priv->ip_iface = g_strdup (str);
	}

	if (priv->ip_iface) {
		/* Grab the interface index for address/routing operations */
		priv->ip_ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, priv->ip_iface);
		if (priv->ip_ifindex <= 0) {
			_LOGE ("failed to look up VPN interface index for \"%s\"", priv->ip_iface);
			nm_vpn_connection_config_maybe_complete (self, FALSE);
			return FALSE;
		}
	}

	g_clear_pointer (&priv->banner, g_free);
	if (g_variant_lookup (dict, NM_VPN_PLUGIN_CONFIG_BANNER, "&s", &str))
		priv->banner = g_strdup (str);

	/* External world-visible address of the VPN server */
	priv->ip4_external_gw = 0;
	g_clear_pointer (&priv->ip6_external_gw, g_free);

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, "u", &u32)) {
		priv->ip4_external_gw = u32;
		success = TRUE;
	} else if (g_variant_lookup (dict, NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, "@ay", &v)) {
		priv->ip6_external_gw = ip6_addr_dup_from_variant (v);
		success = !!priv->ip6_external_gw;
		g_variant_unref (v);
	}

	if (!success) {
		_LOGE ("VPN gateway is neither IPv4 nor IPv6");
		nm_vpn_connection_config_maybe_complete (self, FALSE);
		return FALSE;
	}

	priv->mtu = 0;
	if (g_variant_lookup (dict, NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, "u", &u32))
		priv->mtu = u32;

	return TRUE;
}

static void
nm_vpn_connection_config_get (NMVpnConnection *self, GVariant *dict)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	gboolean b;

	g_return_if_fail (dict && g_variant_is_of_type (dict, G_VARIANT_TYPE_VARDICT));

	_LOGI ("VPN connection: (IP Config Get) reply received.");

	if (priv->vpn_state == STATE_CONNECT)
		_set_vpn_state (self, STATE_IP_CONFIG_GET, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);

	if (!process_generic_config (self, dict))
		return;

	/* Note whether to expect IPv4 and IPv6 configs */
	priv->has_ip4 = FALSE;
	if (g_variant_lookup (dict, NM_VPN_PLUGIN_CONFIG_HAS_IP4, "b", &b))
		priv->has_ip4 = b;
	g_clear_object (&priv->ip4_config);

	priv->has_ip6 = FALSE;
	if (g_variant_lookup (dict, NM_VPN_PLUGIN_CONFIG_HAS_IP6, "b", &b))
		priv->has_ip6 = b;
	g_clear_object (&priv->ip6_config);
}

guint32
nm_vpn_connection_get_ip4_route_metric (NMVpnConnection *self)
{
	gint64 route_metric;
	NMConnection *applied;

	applied = _get_applied_connection (self);
	route_metric = nm_setting_ip_config_get_route_metric (nm_connection_get_setting_ip4_config (applied));

	return (route_metric >= 0) ? route_metric : NM_VPN_ROUTE_METRIC_DEFAULT;
}

guint32
nm_vpn_connection_get_ip6_route_metric (NMVpnConnection *self)
{
	gint64 route_metric;
	NMConnection *applied;

	applied = _get_applied_connection (self);
	route_metric = nm_setting_ip_config_get_route_metric (nm_connection_get_setting_ip6_config (applied));

	return (route_metric >= 0) ? route_metric : NM_VPN_ROUTE_METRIC_DEFAULT;
}

static void
nm_vpn_connection_ip4_config_get (NMVpnConnection *self, GVariant *dict)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	NMPlatformIP4Address address;
	NMIP4Config *config;
	guint32 u32, route_metric;
	GVariantIter *iter;
	const char *str;
	GVariant *v;
	gboolean b;

	g_return_if_fail (dict && g_variant_is_of_type (dict, G_VARIANT_TYPE_VARDICT));

	if (priv->vpn_state == STATE_CONNECT)
		_set_vpn_state (self, STATE_IP_CONFIG_GET, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);

	if (priv->has_ip4) {
		_LOGI ("VPN connection: (IP4 Config Get) reply received");

		if (g_variant_n_children (dict) == 0) {
			priv->has_ip4 = FALSE;
			nm_vpn_connection_config_maybe_complete (self, TRUE);
			return;
		}
	} else {
		_LOGI ("VPN connection: (IP4 Config Get) reply received from old-style plugin");

		/* In the old API, the generic and IPv4 configuration items
		 * were mixed together.
		 */
		if (!process_generic_config (self, dict))
			return;

		priv->has_ip4 = TRUE;
		priv->has_ip6 = FALSE;
	}

	config = nm_ip4_config_new (priv->ip_ifindex);

	memset (&address, 0, sizeof (address));
	address.plen = 24;

	/* Internal address of the VPN subnet's gateway */
	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_INT_GATEWAY, "u", &u32)) {
		priv->ip4_internal_gw = u32;
		nm_ip4_config_set_gateway (config, priv->ip4_internal_gw);
	}

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, "u", &u32))
		address.address = u32;

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_PTP, "u", &u32))
		address.peer_address = u32;

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, "u", &u32))
		address.plen = u32;

	if (address.address && address.plen) {
		address.source = NM_IP_CONFIG_SOURCE_VPN;
		nm_ip4_config_add_address (config, &address);
	} else {
		_LOGE ("invalid IP4 config received!");
		g_object_unref (config);
		nm_vpn_connection_config_maybe_complete (self, FALSE);
		return;
	}

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_DNS, "au", &iter)) {
		while (g_variant_iter_next (iter, "u", &u32))
			nm_ip4_config_add_nameserver (config, u32);
		g_variant_iter_free (iter);
	}

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_NBNS, "au", &iter)) {
		while (g_variant_iter_next (iter, "u", &u32))
			nm_ip4_config_add_wins (config, u32);
		g_variant_iter_free (iter);
	}

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_MSS, "u", &u32))
		nm_ip4_config_set_mss (config, u32);

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN, "&s", &str))
		nm_ip4_config_add_domain (config, str);

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_DOMAINS, "as", &iter)) {
		while (g_variant_iter_next (iter, "&s", &str))
			nm_ip4_config_add_domain (config, str);
		g_variant_iter_free (iter);
	}

	route_metric = nm_vpn_connection_get_ip4_route_metric (self);

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_ROUTES, "aau", &iter)) {
		while (g_variant_iter_next (iter, "@au", &v)) {
			NMPlatformIP4Route route;

			if (g_variant_n_children (v) == 4) {
				memset (&route, 0, sizeof (route));
				g_variant_get_child (v, 0, "u", &route.network);
				g_variant_get_child (v, 1, "u", &route.plen);
				g_variant_get_child (v, 2, "u", &route.gateway);
				/* 4th item is unused route metric */
				route.metric = route_metric;
				route.source = NM_IP_CONFIG_SOURCE_VPN;

				/* Ignore host routes to the VPN gateway since NM adds one itself
				 * below.  Since NM knows more about the routing situation than
				 * the VPN server, we want to use the NM created route instead of
				 * whatever the server provides.
				 */
				if (!(priv->ip4_external_gw && route.network == priv->ip4_external_gw && route.plen == 32))
					nm_ip4_config_add_route (config, &route);
			}
			g_variant_unref (v);
		}
		g_variant_iter_free (iter);
	}

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT, "b", &b))
		nm_ip4_config_set_never_default (config, b);

	/* Merge in user overrides from the NMConnection's IPv4 setting */
	nm_ip4_config_merge_setting (config,
	                             nm_connection_get_setting_ip4_config (_get_applied_connection (self)),
	                             route_metric);

	g_clear_object (&priv->ip4_config);
	priv->ip4_config = config;
	nm_exported_object_export (NM_EXPORTED_OBJECT (config));
	g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_IP4_CONFIG);
	nm_vpn_connection_config_maybe_complete (self, TRUE);
}

static void
nm_vpn_connection_ip6_config_get (NMVpnConnection *self, GVariant *dict)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	NMPlatformIP6Address address;
	guint32 u32, route_metric;
	NMIP6Config *config;
	GVariantIter *iter;
	const char *str;
	GVariant *v;
	gboolean b;

	g_return_if_fail (dict && g_variant_is_of_type (dict, G_VARIANT_TYPE_VARDICT));

	_LOGI ("VPN connection: (IP6 Config Get) reply received");

	if (priv->vpn_state == STATE_CONNECT)
		_set_vpn_state (self, STATE_IP_CONFIG_GET, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);

	if (g_variant_n_children (dict) == 0) {
		priv->has_ip6 = FALSE;
		nm_vpn_connection_config_maybe_complete (self, TRUE);
		return;
	}

	config = nm_ip6_config_new (priv->ip_ifindex);

	memset (&address, 0, sizeof (address));
	address.plen = 128;

	/* Internal address of the VPN subnet's gateway */
	g_clear_pointer (&priv->ip6_internal_gw, g_free);
	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP6_CONFIG_INT_GATEWAY, "@ay", &v)) {
		priv->ip6_internal_gw = ip6_addr_dup_from_variant (v);
		nm_ip6_config_set_gateway (config, priv->ip6_internal_gw);
		g_variant_unref (v);
	}

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP6_CONFIG_ADDRESS, "@ay", &v)) {
		ip6_addr_from_variant (v, &address.address);
		g_variant_unref (v);
	}

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP6_CONFIG_PTP, "@ay", &v)) {
		ip6_addr_from_variant (v, &address.peer_address);
		g_variant_unref (v);
	}

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP6_CONFIG_PREFIX, "u", &u32))
		address.plen = u32;

	if (!IN6_IS_ADDR_UNSPECIFIED (&address.address) && address.plen) {
		address.source = NM_IP_CONFIG_SOURCE_VPN;
		nm_ip6_config_add_address (config, &address);
	} else {
		_LOGE ("invalid IP6 config received!");
		g_object_unref (config);
		nm_vpn_connection_config_maybe_complete (self, FALSE);
		return;
	}

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP6_CONFIG_DNS, "aay", &iter)) {
		while (g_variant_iter_next (iter, "@ay", &v)) {
			struct in6_addr dns;

			if (ip6_addr_from_variant (v, &dns))
				nm_ip6_config_add_nameserver (config, &dns);
			g_variant_unref (v);
		}
		g_variant_iter_free (iter);
	}

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP6_CONFIG_MSS, "u", &u32))
		nm_ip6_config_set_mss (config, u32);

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP6_CONFIG_DOMAIN, "&s", &str))
		nm_ip6_config_add_domain (config, str);

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP6_CONFIG_DOMAINS, "as", &iter)) {
		while (g_variant_iter_next (iter, "&s", &str))
			nm_ip6_config_add_domain (config, str);
		g_variant_iter_free (iter);
	}

	route_metric = nm_vpn_connection_get_ip6_route_metric (self);

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP6_CONFIG_ROUTES, "a(ayuayu)", &iter)) {
		GVariant *dest, *next_hop;
		guint32 prefix, metric;

		while (g_variant_iter_next (iter, "(@ayu@ayu)", &dest, &prefix, &next_hop, &metric)) {
			NMPlatformIP6Route route;

			memset (&route, 0, sizeof (route));

			if (!ip6_addr_from_variant (dest, &route.network)) {
				_LOGW ("VPN connection: received invalid IPv6 dest address");
				goto next;
			}

			route.plen = prefix;
			ip6_addr_from_variant (next_hop, &route.gateway);
			route.metric = route_metric;
			route.source = NM_IP_CONFIG_SOURCE_VPN;

			/* Ignore host routes to the VPN gateway since NM adds one itself.
			 * Since NM knows more about the routing situation than the VPN
			 * server, we want to use the NM created route instead of whatever
			 * the server provides.
			 */
			if (!(priv->ip6_external_gw && IN6_ARE_ADDR_EQUAL (&route.network, priv->ip6_external_gw) && route.plen == 128))
				nm_ip6_config_add_route (config, &route);

next:
			g_variant_unref (dest);
			g_variant_unref (next_hop);
		}
		g_variant_iter_free (iter);
	}

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP6_CONFIG_NEVER_DEFAULT, "b", &b))
		nm_ip6_config_set_never_default (config, b);

	/* Merge in user overrides from the NMConnection's IPv6 setting */
	nm_ip6_config_merge_setting (config,
	                             nm_connection_get_setting_ip6_config (_get_applied_connection (self)),
	                             route_metric);

	g_clear_object (&priv->ip6_config);
	priv->ip6_config = config;
	nm_exported_object_export (NM_EXPORTED_OBJECT (config));
	g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_IP6_CONFIG);
	nm_vpn_connection_config_maybe_complete (self, TRUE);
}

static gboolean
connect_timeout_cb (gpointer user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	priv->connect_timeout = 0;

	/* Cancel activation if it's taken too long */
	if (priv->vpn_state == STATE_CONNECT ||
	    priv->vpn_state == STATE_IP_CONFIG_GET) {
		_LOGW ("VPN connection: connect timeout exceeded.");
		_set_vpn_state (self, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_CONNECT_TIMEOUT, FALSE);
	}

	return FALSE;
}

static void
connect_success (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	guint32 timeout;

	s_vpn = nm_connection_get_setting_vpn (_get_applied_connection (self));
	g_assert (s_vpn);

	/* Timeout waiting for IP config signal from VPN service
	 * It is a configured value or 60 seconds */
	timeout = nm_setting_vpn_get_timeout (s_vpn);
	if (timeout == 0) {
		char *value;

		value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
		                                              "vpn.timeout", NULL);
		timeout = _nm_utils_ascii_str_to_int64 (value, 10, 0, G_MAXUINT32, 60);
		timeout = timeout == 0 ? 60 : timeout;
		g_free (value);
	}
	priv->connect_timeout = g_timeout_add_seconds (timeout, connect_timeout_cb, self);

	g_clear_pointer (&priv->connect_hash, g_variant_unref);
}

static void
connect_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMVpnConnection *self;
	gs_unref_variant GVariant *reply = NULL;
	gs_free_error GError *error = NULL;

	reply = g_dbus_proxy_call_finish (proxy, result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_VPN_CONNECTION (user_data);

	if (error) {
		g_dbus_error_strip_remote_error (error);
		_LOGW ("VPN connection: failed to connect: '%s'",
		       error->message);
		_set_vpn_state (self, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED, FALSE);
	} else
		connect_success (self);
}

static void
connect_interactive_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMVpnConnection *self;
	NMVpnConnectionPrivate *priv;
	gs_unref_variant GVariant *reply = NULL;
	gs_free_error GError *error = NULL;

	reply = g_dbus_proxy_call_finish (proxy, result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_VPN_CONNECTION (user_data);
	priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	_LOGI ("VPN connection: (ConnectInteractive) reply received");

	if (g_error_matches (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_INTERACTIVE_NOT_SUPPORTED)) {
		_LOGD ("VPN connection: falling back to non-interactive connect");

		/* Fall back to Connect() */
		g_dbus_proxy_call (priv->proxy,
		                   "Connect",
		                   g_variant_new ("(@a{sa{sv}})", priv->connect_hash),
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   priv->cancellable,
		                   (GAsyncReadyCallback) connect_cb,
		                   self);
	} else if (error) {
		g_dbus_error_strip_remote_error (error);
		_LOGW ("VPN connection: failed to connect interactively: '%s'",
		       error->message);
		_set_vpn_state (self, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED, FALSE);
	} else
		connect_success (self);
}

/* Add a username to a hashed connection */
static GVariant *
_hash_with_username (NMConnection *connection, const char *username)
{
	gs_unref_object NMConnection *dup = NULL;
	NMSettingVpn *s_vpn;

	/* Shortcut if we weren't given a username or if there already was one in
	 * the VPN setting; don't bother duplicating the connection and everything.
	 */
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);
	if (username == NULL || nm_setting_vpn_get_user_name (s_vpn))
		return nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);

	dup = nm_simple_connection_new_clone (connection);
	g_assert (dup);
	s_vpn = nm_connection_get_setting_vpn (dup);
	g_assert (s_vpn);
	g_object_set (s_vpn, NM_SETTING_VPN_USER_NAME, username, NULL);
	return nm_connection_to_dbus (dup, NM_CONNECTION_SERIALIZE_ALL);
}

static void
really_activate (NMVpnConnection *self, const char *username)
{
	NMVpnConnectionPrivate *priv;
	GVariantBuilder details;

	g_return_if_fail (NM_IS_VPN_CONNECTION (self));

	priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	g_return_if_fail (priv->vpn_state == STATE_NEED_AUTH);

	g_clear_pointer (&priv->connect_hash, g_variant_unref);
	priv->connect_hash = _hash_with_username (_get_applied_connection (self), username);
	g_variant_ref_sink (priv->connect_hash);

	/* If at least one agent doesn't support VPN hints, then we can't use
	 * ConnectInteractive(), because that agent won't be able to pass hints
	 * from the VPN plugin's interactive secrets requests to the VPN authentication
	 * dialog and we won't get the secrets we need.  In this case fall back to
	 * the old Connect() call.
	 */
	if (nm_agent_manager_all_agents_have_capability (nm_agent_manager_get (),
	                                                 nm_active_connection_get_subject (NM_ACTIVE_CONNECTION (self)),
	                                                 NM_SECRET_AGENT_CAPABILITY_VPN_HINTS)) {
		_LOGD ("Allowing interactive secrets as all agents have that capability");

		g_variant_builder_init (&details, G_VARIANT_TYPE_VARDICT);
		g_dbus_proxy_call (priv->proxy,
		                   "ConnectInteractive",
		                   g_variant_new ("(@a{sa{sv}}a{sv})", priv->connect_hash, &details),
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   priv->cancellable,
		                   (GAsyncReadyCallback) connect_interactive_cb,
		                   self);
	} else {
		_LOGD ("Calling old Connect function as not all agents support interactive secrets");
		g_dbus_proxy_call (priv->proxy,
		                   "Connect",
		                   g_variant_new ("(@a{sa{sv}})", priv->connect_hash),
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   priv->cancellable,
		                   (GAsyncReadyCallback) connect_cb,
		                   self);
	}

	_set_vpn_state (self, STATE_CONNECT, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);
}

static void
failure_cb (GDBusProxy *proxy,
            guint32     reason,
            gpointer    user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);

	plugin_failed (self, reason);
}

static void
state_changed_cb (GDBusProxy *proxy,
                  guint32     new_service_state,
                  gpointer    user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);

	plugin_state_changed (self, new_service_state);
}

static void
secrets_required_cb (GDBusProxy  *proxy,
                     const char  *message,
                     const char **secrets,
                     gpointer     user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);

	plugin_interactive_secrets_required (self, message, secrets);
}

static void
config_cb (GDBusProxy *proxy,
           GVariant   *dict,
           gpointer    user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	/* Only list to this signals during and after connection */
	if (priv->vpn_state >= STATE_NEED_AUTH)
		nm_vpn_connection_config_get (self, dict);
}

static void
ip4_config_cb (GDBusProxy *proxy,
               GVariant   *dict,
               gpointer    user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	/* Only list to this signals during and after connection */
	if (priv->vpn_state >= STATE_NEED_AUTH)
		nm_vpn_connection_ip4_config_get (self, dict);
}

static void
ip6_config_cb (GDBusProxy *proxy,
               GVariant   *dict,
               gpointer    user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	/* Only list to this signals during and after connection */
	if (priv->vpn_state >= STATE_NEED_AUTH)
		nm_vpn_connection_ip6_config_get (self, dict);
}

static void
on_proxy_acquired (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMVpnConnection *self;
	NMVpnConnectionPrivate *priv;
	gs_free_error GError *error = NULL;
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_new_for_bus_finish (result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_VPN_CONNECTION (user_data);
	priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	if (error) {
		_LOGE ("failed to acquire dbus proxy for VPN service: %s",
		       error->message);
		_set_vpn_state (self,
		                STATE_FAILED,
		                NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED,
		                FALSE);
		return;
	}

	priv->proxy = proxy;
	_nm_dbus_signal_connect (priv->proxy, "Failure", G_VARIANT_TYPE ("(u)"),
	                         G_CALLBACK (failure_cb), self);
	_nm_dbus_signal_connect (priv->proxy, "StateChanged", G_VARIANT_TYPE ("(u)"),
	                         G_CALLBACK (state_changed_cb), self);
	_nm_dbus_signal_connect (priv->proxy, "SecretsRequired", G_VARIANT_TYPE ("(sas)"),
	                         G_CALLBACK (secrets_required_cb), self);
	_nm_dbus_signal_connect (priv->proxy, "Config", G_VARIANT_TYPE ("(a{sv})"),
	                         G_CALLBACK (config_cb), self);
	_nm_dbus_signal_connect (priv->proxy, "Ip4Config", G_VARIANT_TYPE ("(a{sv})"),
	                         G_CALLBACK (ip4_config_cb), self);
	_nm_dbus_signal_connect (priv->proxy, "Ip6Config", G_VARIANT_TYPE ("(a{sv})"),
	                         G_CALLBACK (ip6_config_cb), self);

	_set_vpn_state (self, STATE_NEED_AUTH, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);

	/* Kick off the secrets requests; first we get existing system secrets
	 * and ask the plugin if these are sufficient, next we get all existing
	 * secrets from system and from user agents and ask the plugin again,
	 * and last we ask the user for new secrets if required.
	 */
	get_secrets (self, SECRETS_REQ_SYSTEM, NULL);
}

void
nm_vpn_connection_activate (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv;
	NMSettingVpn *s_vpn;

	g_return_if_fail (NM_IS_VPN_CONNECTION (self));

	priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	s_vpn = nm_connection_get_setting_vpn (_get_applied_connection (self));
	g_assert (s_vpn);
	priv->connection_can_persist = nm_setting_vpn_get_persistent (s_vpn);

	_set_vpn_state (self, STATE_PREPARE, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);

	priv->cancellable = g_cancellable_new ();
	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                          NULL,
	                          nm_vpn_connection_get_service (self),
	                          NM_VPN_DBUS_PLUGIN_PATH,
	                          NM_VPN_DBUS_PLUGIN_INTERFACE,
	                          priv->cancellable,
	                          (GAsyncReadyCallback) on_proxy_acquired,
	                          self);
}

NMVpnConnectionState
nm_vpn_connection_get_vpn_state (NMVpnConnection *self)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (self), NM_VPN_CONNECTION_STATE_UNKNOWN);

	return _state_to_nm_vpn_state (NM_VPN_CONNECTION_GET_PRIVATE (self)->vpn_state);
}

const char *
nm_vpn_connection_get_banner (NMVpnConnection *self)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (self), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (self)->banner;
}

NMIP4Config *
nm_vpn_connection_get_ip4_config (NMVpnConnection *self)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (self), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (self)->ip4_config;
}

NMIP6Config *
nm_vpn_connection_get_ip6_config (NMVpnConnection *self)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (self), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (self)->ip6_config;
}

const char *
nm_vpn_connection_get_ip_iface (NMVpnConnection *self)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (self), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (self)->ip_iface;
}

int
nm_vpn_connection_get_ip_ifindex (NMVpnConnection *self)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (self), -1);

	return NM_VPN_CONNECTION_GET_PRIVATE (self)->ip_ifindex;
}

guint32
nm_vpn_connection_get_ip4_internal_gateway (NMVpnConnection *self)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (self), 0);

	return NM_VPN_CONNECTION_GET_PRIVATE (self)->ip4_internal_gw;
}

struct in6_addr *
nm_vpn_connection_get_ip6_internal_gateway (NMVpnConnection *self)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (self), 0);

	return NM_VPN_CONNECTION_GET_PRIVATE (self)->ip6_internal_gw;
}

void
nm_vpn_connection_disconnect (NMVpnConnection *self,
                              NMVpnConnectionStateReason reason,
                              gboolean quitting)
{
	g_return_if_fail (NM_IS_VPN_CONNECTION (self));

	_set_vpn_state (self, STATE_DISCONNECTED, reason, quitting);
}

gboolean
nm_vpn_connection_deactivate (NMVpnConnection *self,
                              NMVpnConnectionStateReason reason,
                              gboolean quitting)
{
	NMVpnConnectionPrivate *priv;
	gboolean success = FALSE;

	g_return_val_if_fail (NM_IS_VPN_CONNECTION (self), FALSE);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	if (priv->vpn_state > STATE_UNKNOWN && priv->vpn_state <= STATE_DEACTIVATING) {
		_set_vpn_state (self, STATE_DEACTIVATING, reason, quitting);
		success = TRUE;
	}
	return success;
}

/******************************************************************************/

static void
plugin_need_secrets_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMVpnConnection *self;
	NMVpnConnectionPrivate *priv;
	gs_unref_variant GVariant *reply = NULL;
	gs_free_error GError *error = NULL;
	const char *setting_name;

	reply = _nm_dbus_proxy_call_finish (proxy, result, G_VARIANT_TYPE ("(s)"), &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_VPN_CONNECTION (user_data);
	priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	if (error) {
		g_dbus_error_strip_remote_error (error);
		_LOGE ("plugin NeedSecrets request #%d failed: %s",
		       priv->secrets_idx + 1,
		       error->message);
		_set_vpn_state (self, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
		return;
	}

	g_variant_get (reply, "(&s)", &setting_name);
	if (!strlen (setting_name)) {
		_LOGD ("service indicated no additional secrets required");

		/* No secrets required; we can start the VPN */
		really_activate (self, priv->username);
		return;
	}

	/* More secrets required */
	if (priv->secrets_idx == SECRETS_REQ_NEW) {
		_LOGE ("final secrets request failed to provide sufficient secrets");
		_set_vpn_state (self, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
	} else {
		_LOGD ("service indicated additional secrets required");
		get_secrets (self, priv->secrets_idx + 1, NULL);
	}
}

static void
plugin_new_secrets_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMVpnConnection *self;
	NMVpnConnectionPrivate *priv;
	gs_unref_variant GVariant *reply = NULL;
	gs_free_error GError *error = NULL;

	reply = g_dbus_proxy_call_finish (proxy, result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_VPN_CONNECTION (user_data);
	priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	if (error) {
		g_dbus_error_strip_remote_error (error);
		_LOGE ("sending new secrets to the plugin failed: %s",
		       error->message);
		_set_vpn_state (self, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
	} else
		_set_vpn_state (self, STATE_CONNECT, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);
}

static void
get_secrets_cb (NMSettingsConnection *connection,
                NMSettingsConnectionCallId call_id,
                const char *agent_username,
                const char *setting_name,
                GError *error,
                gpointer user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv;
	GVariant *dict;

	g_return_if_fail (NM_IS_VPN_CONNECTION (self));

	priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	g_return_if_fail (connection && connection == _get_settings_connection (self, FALSE));
	g_return_if_fail (call_id == priv->secrets_id);

	priv->secrets_id = NULL;

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	if (error && priv->secrets_idx >= SECRETS_REQ_NEW) {
		_LOGE ("Failed to request VPN secrets #%d: (%d) %s",
		       priv->secrets_idx + 1, error->code, error->message);
		_set_vpn_state (self, STATE_FAILED, NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
		return;
	}

	/* Cache the username for later */
	if (agent_username) {
		g_free (priv->username);
		priv->username = g_strdup (agent_username);
	}

	dict = _hash_with_username (_get_applied_connection (self), priv->username);

	if (priv->secrets_idx == SECRETS_REQ_INTERACTIVE) {
		_LOGD ("sending secrets to the plugin");

		/* Send the secrets back to the plugin */
		g_dbus_proxy_call (priv->proxy,
		                   "NewSecrets",
		                   g_variant_new ("(@a{sa{sv}})", dict),
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   priv->cancellable,
		                   (GAsyncReadyCallback) plugin_new_secrets_cb,
		                   self);
	} else {
		_LOGD ("asking service if additional secrets are required");

		/* Ask the VPN service if more secrets are required */
		g_dbus_proxy_call (priv->proxy,
		                   "NeedSecrets",
		                   g_variant_new ("(@a{sa{sv}})", dict),
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   priv->cancellable,
		                   (GAsyncReadyCallback) plugin_need_secrets_cb,
		                   self);
	}
}

static void
get_secrets (NMVpnConnection *self,
             SecretsReq secrets_idx,
             const char **hints)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	NMSecretAgentGetSecretsFlags flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_NONE;

	g_return_if_fail (secrets_idx < SECRETS_REQ_LAST);
	priv->secrets_idx = secrets_idx;

	cancel_get_secrets (self);

	_LOGD ("requesting VPN secrets pass #%d",
	       priv->secrets_idx + 1);

	switch (priv->secrets_idx) {
	case SECRETS_REQ_SYSTEM:
		flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ONLY_SYSTEM;
		break;
	case SECRETS_REQ_EXISTING:
		flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_NONE;
		break;
	case SECRETS_REQ_NEW:
	case SECRETS_REQ_INTERACTIVE:
		flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;
		break;
	default:
		g_assert_not_reached ();
	}

	if (nm_active_connection_get_user_requested (NM_ACTIVE_CONNECTION (self)))
		flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_USER_REQUESTED;

	priv->secrets_id = nm_settings_connection_get_secrets (_get_settings_connection (self, FALSE),
	                                                       _get_applied_connection (self),
	                                                       nm_active_connection_get_subject (NM_ACTIVE_CONNECTION (self)),
	                                                       NM_SETTING_VPN_SETTING_NAME,
	                                                       flags,
	                                                       hints,
	                                                       get_secrets_cb,
	                                                       self);
	g_return_if_fail (priv->secrets_id);
}

static void
plugin_interactive_secrets_required (NMVpnConnection *self,
                                     const char *message,
                                     const char **secrets)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	guint32 secrets_len = secrets ? g_strv_length ((char **) secrets) : 0;
	char **hints;
	guint32 i;

	_LOGI ("VPN plugin: requested secrets; state %s (%d)",
	       vpn_state_to_string (priv->vpn_state), priv->vpn_state);

	g_return_if_fail (priv->vpn_state == STATE_CONNECT ||
	                  priv->vpn_state == STATE_NEED_AUTH);

	priv->secrets_idx = SECRETS_REQ_INTERACTIVE;
	_set_vpn_state (self, STATE_NEED_AUTH, NM_VPN_CONNECTION_STATE_REASON_NONE, FALSE);

	/* Copy hints and add message to the end */
	hints = g_malloc0 (sizeof (char *) * (secrets_len + 2));
	for (i = 0; i < secrets_len; i++)
		hints[i] = g_strdup (secrets[i]);
	if (message)
		hints[i] = g_strdup_printf ("x-vpn-message:%s", message);

	get_secrets (self, SECRETS_REQ_INTERACTIVE, (const char **) hints);
	g_strfreev (hints);
}

/******************************************************************************/

static void
device_changed (NMActiveConnection *active,
                NMDevice *new_device,
                NMDevice *old_device)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (active);

	if (!_service_and_connection_can_persist (NM_VPN_CONNECTION (active)))
		return;
	if (priv->vpn_state < STATE_CONNECT || priv->vpn_state > STATE_ACTIVATED)
		return;

	/* Route-based VPNs must update their routing and send a new IP config
	 * since all their routes need to be adjusted for new_device.
	 */
	if (priv->ip_ifindex <= 0)
		return;

	/* Device changed underneath the VPN connection.  Let the plugin figure
	 * out that connectivity is down and start its reconnect attempt if it
	 * needs to.
	 */
	if (old_device) {
		nm_device_set_vpn4_config (old_device, NULL);
		nm_device_set_vpn6_config (old_device, NULL);
	}

	if (new_device)
		apply_parent_device_config (NM_VPN_CONNECTION (active));
}

/******************************************************************************/

static void
nm_vpn_connection_init (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	priv->vpn_state = STATE_WAITING;
	priv->secrets_idx = SECRETS_REQ_SYSTEM;
	priv->default_route_manager = g_object_ref (nm_default_route_manager_get ());
	priv->route_manager = g_object_ref (nm_route_manager_get ());
}

static void
dispose (GObject *object)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (object);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	g_clear_pointer (&priv->connect_hash, g_variant_unref);

	if (priv->connect_timeout) {
		g_source_remove (priv->connect_timeout);
		priv->connect_timeout = 0;
	}

	dispatcher_cleanup (self);

	cancel_get_secrets (self);

	if (priv->cancellable) {
		g_cancellable_cancel (priv->cancellable);
		g_clear_object (&priv->cancellable);
	}
	g_clear_object (&priv->ip4_config);
	g_clear_object (&priv->ip6_config);
	g_clear_object (&priv->proxy);

	fw_call_cleanup (self);

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->dispose (object);

	g_clear_object (&priv->default_route_manager);
	g_clear_object (&priv->route_manager);
}

static void
finalize (GObject *object)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);

	g_free (priv->banner);
	g_free (priv->ip_iface);
	g_free (priv->username);
	g_free (priv->ip6_internal_gw);
	g_free (priv->ip6_external_gw);

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->finalize (object);
}

static gboolean
ip_config_valid (VpnState state)
{
	return (state == STATE_PRE_UP || state == STATE_ACTIVATED);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);
	NMDevice *parent_dev;

	switch (prop_id) {
	case PROP_VPN_STATE:
		g_value_set_uint (value, _state_to_nm_vpn_state (priv->vpn_state));
		break;
	case PROP_BANNER:
		g_value_set_string (value, priv->banner ? priv->banner : "");
		break;
	case PROP_IP4_CONFIG:
		nm_utils_g_value_set_object_path (value, ip_config_valid (priv->vpn_state) ? priv->ip4_config : NULL);
		break;
	case PROP_IP6_CONFIG:
		nm_utils_g_value_set_object_path (value, ip_config_valid (priv->vpn_state) ? priv->ip6_config : NULL);
		break;
	case PROP_MASTER:
		parent_dev = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (object));
		nm_utils_g_value_set_object_path (value, parent_dev);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_vpn_connection_class_init (NMVpnConnectionClass *connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (connection_class);
	NMActiveConnectionClass *active_class = NM_ACTIVE_CONNECTION_CLASS (connection_class);

	g_type_class_add_private (connection_class, sizeof (NMVpnConnectionPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	active_class->device_state_changed = device_state_changed;
	active_class->device_changed = device_changed;

	g_object_class_override_property (object_class, PROP_MASTER, NM_ACTIVE_CONNECTION_MASTER);

	/* properties */
	g_object_class_install_property
		(object_class, PROP_VPN_STATE,
		 g_param_spec_uint (NM_VPN_CONNECTION_VPN_STATE, "", "",
		                    NM_VPN_CONNECTION_STATE_UNKNOWN,
		                    NM_VPN_CONNECTION_STATE_DISCONNECTED,
		                    NM_VPN_CONNECTION_STATE_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_BANNER,
		 g_param_spec_string (NM_VPN_CONNECTION_BANNER, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_override_property (object_class, PROP_IP4_CONFIG,
	                                  NM_ACTIVE_CONNECTION_IP4_CONFIG);
	g_object_class_override_property (object_class, PROP_IP6_CONFIG,
	                                  NM_ACTIVE_CONNECTION_IP6_CONFIG);

	/* signals */
	signals[VPN_STATE_CHANGED] =
		g_signal_new ("vpn-state-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);

	signals[INTERNAL_STATE_CHANGED] =
		g_signal_new (NM_VPN_CONNECTION_INTERNAL_STATE_CHANGED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 3, G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT);

	signals[INTERNAL_RETRY_AFTER_FAILURE] =
		g_signal_new (NM_VPN_CONNECTION_INTERNAL_RETRY_AFTER_FAILURE,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (connection_class),
	                                        NMDBUS_TYPE_VPN_CONNECTION_SKELETON,
	                                        NULL);
}

