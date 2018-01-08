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

#include "nm-default.h"

#include "nm-vpn-connection.h"

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <linux/rtnetlink.h>

#include "nm-proxy-config.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "platform/nm-platform.h"
#include "nm-active-connection.h"
#include "NetworkManagerUtils.h"
#include "settings/nm-settings-connection.h"
#include "nm-dispatcher.h"
#include "nm-netns.h"
#include "settings/nm-agent-manager.h"
#include "nm-core-internal.h"
#include "nm-pacrunner-manager.h"
#include "nm-firewall-manager.h"
#include "nm-config.h"
#include "nm-vpn-plugin-info.h"
#include "nm-vpn-manager.h"
#include "dns/nm-dns-manager.h"

#include "introspection/org.freedesktop.NetworkManager.VPN.Connection.h"

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

enum {
	VPN_STATE_CHANGED,
	INTERNAL_STATE_CHANGED,
	INTERNAL_RETRY_AFTER_FAILURE,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

NM_GOBJECT_PROPERTIES_DEFINE (NMVpnConnection,
	PROP_VPN_STATE,
	PROP_BANNER,
#define PROP_IP4_CONFIG 2000
#define PROP_IP6_CONFIG 2001
#define PROP_MASTER     2002
);

typedef struct {
	gboolean service_can_persist;
	gboolean connection_can_persist;

	NMSettingsConnectionCallId *secrets_id;
	SecretsReq secrets_idx;
	char *username;

	VpnState vpn_state;
	guint dispatcher_id;
	NMActiveConnectionStateReason failure_reason;

	NMVpnServiceState service_state;
	guint start_timeout;
	gboolean service_running;
	NMVpnPluginInfo *plugin_info;
	char *bus_name;

	/* Firewall */
	NMFirewallManagerCallId fw_call;

	NMNetns *netns;

	GPtrArray *ip4_dev_route_blacklist;

	GDBusProxy *proxy;
	GCancellable *cancellable;
	GVariant *connect_hash;
	guint connect_timeout;
	NMProxyConfig *proxy_config;
	NMPacrunnerManager *pacrunner_manager;
	NMPacrunnerCallId *pacrunner_call_id;
	gboolean has_ip4;
	NMIP4Config *ip4_config;
	guint32 ip4_internal_gw;
	guint32 ip4_external_gw;
	gboolean has_ip6;
	NMIP6Config *ip6_config;

	/* These config instances are passed on to NMDevice and modified by NMDevice.
	 * This pointer is only useful for nm_device_replace_vpn4_config() to clear the
	 * previous configuration. Consider these instances to be owned by NMDevice. */
	NMIP4Config *last_device_ip4_config;
	NMIP6Config *last_device_ip6_config;

	struct in6_addr *ip6_internal_gw;
	struct in6_addr *ip6_external_gw;
	char *ip_iface;
	int ip_ifindex;
	char *banner;
	guint32 mtu;
} NMVpnConnectionPrivate;

struct _NMVpnConnection {
	NMActiveConnection parent;
	NMVpnConnectionPrivate _priv;
};

struct _NMVpnConnectionClass {
	NMActiveConnectionClass parent;

	/* Signals */
	void (*vpn_state_changed) (NMVpnConnection *self,
	                           NMVpnConnectionState new_state,
	                           NMActiveConnectionStateReason reason);

	/* not exported over D-Bus */
	void (*internal_state_changed) (NMVpnConnection *self,
	                                NMVpnConnectionState new_state,
	                                NMVpnConnectionState old_state,
	                                NMActiveConnectionStateReason reason);

	void (*internal_failed_retry)  (NMVpnConnection *self);
};

G_DEFINE_TYPE (NMVpnConnection, nm_vpn_connection, NM_TYPE_ACTIVE_CONNECTION)

#define NM_VPN_CONNECTION_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMVpnConnection, NM_IS_VPN_CONNECTION)

/*****************************************************************************/

static NMSettingsConnection *_get_settings_connection (NMVpnConnection *self,
                                                       gboolean allow_missing);

static void get_secrets (NMVpnConnection *self,
                         SecretsReq secrets_idx,
                         const char *const*hints);

static guint32 get_route_table (NMVpnConnection *self, int addr_family, gboolean fallback_main);

static void plugin_interactive_secrets_required (NMVpnConnection *self,
                                                 const char *message,
                                                 const char *const*secrets);

static void _set_vpn_state (NMVpnConnection *self,
                            VpnState vpn_state,
                            NMActiveConnectionStateReason reason,
                            gboolean quitting);

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_VPN
#define _NMLOG_PREFIX_NAME "vpn-connection"

#define __NMLOG_prefix_buf_len 128

static const char *
__LOG_create_prefix (char *buf, NMVpnConnection *self, NMConnection *con)
{
	NMVpnConnectionPrivate *priv;
	const char *id;

	if (!self)
		return _NMLOG_PREFIX_NAME;

	priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	id = con ? nm_connection_get_id (con) : NULL;

	g_snprintf (buf, __NMLOG_prefix_buf_len,
	            "%s["
	            "%p"       /*self*/
	            "%s%s"     /*con-uuid*/
	            "%s%s%s%s" /*con-id*/
	            ",%d"      /*ifindex*/
	            "%s%s%s" /*iface*/
	            "]",
	            _NMLOG_PREFIX_NAME,
	            self,
	            con ? "," : "--", con ? (nm_connection_get_uuid (con) ?: "??") : "",
	            con ? "," : "", NM_PRINT_FMT_QUOTED (id, "\"", id, "\"", con ? "??" : ""),
	            priv->ip_ifindex,
	            NM_PRINT_FMT_QUOTED (priv->ip_iface, ":(", priv->ip_iface, ")", "")
	            );

	return buf;
}

#define _NMLOG(level, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        NMConnection *__con = (self) ? (NMConnection *) _get_settings_connection (self, TRUE) : NULL; \
        \
        if (nm_logging_enabled (__level, _NMLOG_DOMAIN)) { \
            char __prefix[__NMLOG_prefix_buf_len]; \
            \
            _nm_log (__level, _NMLOG_DOMAIN, 0, \
                     (self) ? NM_VPN_CONNECTION_GET_PRIVATE (self)->ip_iface : NULL, \
                     (__con) ? nm_connection_get_uuid (__con) : NULL, \
                     "%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     __LOG_create_prefix (__prefix, (self), __con) \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

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
disconnect_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	GVariant *variant;

	variant = g_dbus_proxy_call_finish (proxy, result, NULL);
	if (variant)
		g_variant_unref (variant);
	g_object_unref (user_data);
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
remove_parent_device_config (NMVpnConnection *connection, NMDevice *device)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	if (priv->last_device_ip4_config) {
		nm_device_replace_vpn4_config (device, priv->last_device_ip4_config, NULL);
		g_clear_object (&priv->last_device_ip4_config);
	}

	if (priv->last_device_ip6_config) {
		nm_device_replace_vpn6_config (device, priv->last_device_ip6_config, NULL);
		g_clear_object (&priv->last_device_ip6_config);
	}
}

static void
vpn_cleanup (NMVpnConnection *self, NMDevice *parent_dev)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	if (priv->ip_ifindex) {
		NMPlatform *platform = nm_netns_get_platform (priv->netns);

		nm_platform_link_set_down (platform, priv->ip_ifindex);
		nm_platform_ip_route_flush (platform, AF_UNSPEC, priv->ip_ifindex);
		nm_platform_ip_address_flush (platform, AF_UNSPEC, priv->ip_ifindex);
	}

	remove_parent_device_config (self, parent_dev);

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

	g_free (priv->bus_name);
	priv->bus_name = NULL;

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
	_set_vpn_state (self, STATE_DISCONNECTED, NM_ACTIVE_CONNECTION_STATE_REASON_USER_DISCONNECTED, FALSE);
}

static void
dispatcher_pre_up_done (guint call_id, gpointer user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	priv->dispatcher_id = 0;
	_set_vpn_state (self, STATE_ACTIVATED, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);
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
                NMActiveConnectionStateReason reason,
                gboolean quitting)
{
	NMVpnConnectionPrivate *priv;
	VpnState old_vpn_state;
	NMVpnConnectionState new_external_state, old_external_state;
	NMDevice *parent_dev = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (self));
	NMConnection *applied;

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
	                                _state_to_ac_state (vpn_state),
	                                reason);

	/* Clear any in-progress secrets request */
	cancel_get_secrets (self);

	dispatcher_cleanup (self);

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
		_notify (self, PROP_VPN_STATE);
	}

	switch (vpn_state) {
	case STATE_NEED_AUTH:
		/* Do nothing; not part of 'default' because we don't want to touch
		 * priv->secrets_req as NEED_AUTH is re-entered during interactive
		 * secrets.
		 */
		break;
	case STATE_PRE_UP:
		if (!nm_dispatcher_call_vpn (NM_DISPATCHER_ACTION_VPN_PRE_UP,
		                             _get_settings_connection (self, FALSE),
		                             _get_applied_connection (self),
		                             parent_dev,
		                             priv->ip_iface,
		                             priv->proxy_config,
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
		applied = _get_applied_connection (self);

		/* Secrets no longer needed now that we're connected */
		nm_active_connection_clear_secrets (NM_ACTIVE_CONNECTION (self));

		/* Let dispatcher scripts know we're up and running */
		nm_dispatcher_call_vpn (NM_DISPATCHER_ACTION_VPN_UP,
		                        _get_settings_connection (self, FALSE),
		                        applied,
		                        parent_dev,
		                        priv->ip_iface,
		                        priv->proxy_config,
		                        priv->ip4_config,
		                        priv->ip6_config,
		                        NULL,
		                        NULL,
		                        NULL);

		if (priv->proxy_config) {
			nm_pacrunner_manager_remove_clear (priv->pacrunner_manager,
			                                   &priv->pacrunner_call_id);
			if (!priv->pacrunner_manager) {
				/* the pending call doesn't keep NMPacrunnerManager alive.
				 * Take a reference to it. */
				priv->pacrunner_manager = g_object_ref (nm_pacrunner_manager_get ());
			}
			priv->pacrunner_call_id = nm_pacrunner_manager_send (priv->pacrunner_manager,
			                                                     priv->ip_iface,
			                                                     priv->proxy_config,
			                                                     priv->ip4_config,
			                                                     priv->ip6_config);
		}
		break;
	case STATE_DEACTIVATING:
		applied = _get_applied_connection (self);
		if (quitting) {
			nm_dispatcher_call_vpn_sync (NM_DISPATCHER_ACTION_VPN_PRE_DOWN,
			                             _get_settings_connection (self, FALSE),
			                             applied,
			                             parent_dev,
			                             priv->ip_iface,
			                             priv->proxy_config,
			                             priv->ip4_config,
			                             priv->ip6_config);
		} else {
			if (!nm_dispatcher_call_vpn (NM_DISPATCHER_ACTION_VPN_PRE_DOWN,
			                             _get_settings_connection (self, FALSE),
			                             applied,
			                             parent_dev,
			                             priv->ip_iface,
			                             priv->proxy_config,
			                             priv->ip4_config,
			                             priv->ip6_config,
			                             dispatcher_pre_down_done,
			                             self,
			                             &priv->dispatcher_id)) {
				/* Just proceed on errors */
				dispatcher_pre_down_done (0, self);
			}
		}

		nm_pacrunner_manager_remove_clear (priv->pacrunner_manager,
		                                   &priv->pacrunner_call_id);
		break;
	case STATE_FAILED:
	case STATE_DISCONNECTED:
		if (   old_vpn_state >= STATE_ACTIVATED
		    && old_vpn_state <= STATE_DEACTIVATING) {
			/* Let dispatcher scripts know we're about to go down */
			if (quitting) {
				nm_dispatcher_call_vpn_sync (NM_DISPATCHER_ACTION_VPN_DOWN,
				                             _get_settings_connection (self, FALSE),
				                             _get_applied_connection (self),
				                             parent_dev,
				                             priv->ip_iface,
				                             NULL,
				                             NULL,
				                             NULL);
			} else {
				nm_dispatcher_call_vpn (NM_DISPATCHER_ACTION_VPN_DOWN,
				                        _get_settings_connection (self, FALSE),
				                        _get_applied_connection (self),
				                        parent_dev,
				                        priv->ip_iface,
				                        NULL,
				                        NULL,
				                        NULL,
				                        NULL,
				                        NULL,
				                        NULL);
			}
		}

		/* Tear down and clean up the connection */
		if (priv->proxy) {
			g_dbus_proxy_call (priv->proxy,
			                   "Disconnect",
			                   NULL,
			                   G_DBUS_CALL_FLAGS_NONE,
			                   -1,
			                   priv->cancellable,
			                   (GAsyncReadyCallback) disconnect_cb,
			                   g_object_ref (self));
		}

		vpn_cleanup (self, parent_dev);
		/* fall through */
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
		                NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED,
		                FALSE);
	} else if (new_state == NM_DEVICE_STATE_FAILED) {
		_set_vpn_state (NM_VPN_CONNECTION (active),
		                STATE_FAILED,
		                NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED,
		                FALSE);
	}

	/* FIXME: map device DEACTIVATING state to VPN DEACTIVATING state and
	 * block device deactivation on VPN deactivation.
	 */
}

static void
add_ip4_vpn_gateway_route (NMIP4Config *config,
                           NMDevice *parent_device,
                           in_addr_t vpn_gw,
                           NMPlatform *platform)
{
	guint32 parent_gw = 0;
	gboolean has_parent_gw = FALSE;
	NMPlatformIP4Route route;
	int ifindex;
	guint32 route_metric;
	nm_auto_nmpobj const NMPObject *route_resolved = NULL;

	g_return_if_fail (NM_IS_IP4_CONFIG (config));
	g_return_if_fail (NM_IS_DEVICE (parent_device));
	g_return_if_fail (vpn_gw != 0);

	ifindex = nm_ip4_config_get_ifindex (config);

	nm_assert (ifindex > 0);
	nm_assert (ifindex == nm_device_get_ip_ifindex (parent_device));

	/* Ask kernel how to reach @vpn_gw. We can only inject the route in
	 * @parent_device, so whatever we resolve, it can only be on @ifindex. */
	if (nm_platform_ip_route_get (platform,
	                              AF_INET,
	                              &vpn_gw,
	                              ifindex,
	                              (NMPObject **) &route_resolved) == NM_PLATFORM_ERROR_SUCCESS) {
		const NMPlatformIP4Route *r = NMP_OBJECT_CAST_IP4_ROUTE (route_resolved);

		if (r->ifindex == ifindex) {
			/* `ip route get` always resolves the route, even if the destination is unreachable.
			 * In which case, it pretends the destination is directly reachable.
			 *
			 * So, only accept direct routes, if @vpn_gw is a private network. */
			if (   nm_platform_route_table_is_main (r->table_coerced)
			    && (   r->gateway
			        || nm_utils_ip_is_site_local (AF_INET, &vpn_gw))) {
				parent_gw = r->gateway;
				has_parent_gw = TRUE;
			}
		}
	}

	if (!has_parent_gw)
		return;

	route_metric = nm_device_get_route_metric (parent_device, AF_INET);

	memset (&route, 0, sizeof (route));
	route.ifindex = ifindex;
	route.network = vpn_gw;
	route.plen = 32;
	route.gateway = parent_gw;
	route.rt_source = NM_IP_CONFIG_SOURCE_VPN;
	route.metric = route_metric;
	nm_ip4_config_add_route (config, &route, NULL);

	if (parent_gw) {
		/* Ensure there's a route to the parent device's gateway through the
		 * parent device, since if the VPN claims the default route and the VPN
		 * routes include a subnet that matches the parent device's subnet,
		 * the parent device's gateway would get routed through the VPN and fail.
		 */
		memset (&route, 0, sizeof (route));
		route.network = parent_gw;
		route.plen = 32;
		route.rt_source = NM_IP_CONFIG_SOURCE_VPN;
		route.metric = route_metric;
		nm_ip4_config_add_route (config, &route, NULL);
	}
}

static void
add_ip6_vpn_gateway_route (NMIP6Config *config,
                           NMDevice *parent_device,
                           const struct in6_addr *vpn_gw,
                           NMPlatform *platform)
{
	const struct in6_addr *parent_gw = NULL;
	gboolean has_parent_gw = FALSE;
	NMPlatformIP6Route route;
	int ifindex;
	guint32 route_metric;
	nm_auto_nmpobj const NMPObject *route_resolved = NULL;

	g_return_if_fail (NM_IS_IP6_CONFIG (config));
	g_return_if_fail (NM_IS_DEVICE (parent_device));
	g_return_if_fail (vpn_gw != NULL);

	ifindex = nm_ip6_config_get_ifindex (config);

	nm_assert (ifindex > 0);
	nm_assert (ifindex == nm_device_get_ip_ifindex (parent_device));

	/* Ask kernel how to reach @vpn_gw. We can only inject the route in
	 * @parent_device, so whatever we resolve, it can only be on @ifindex. */
	if (nm_platform_ip_route_get (platform,
	                              AF_INET6,
	                              vpn_gw,
	                              ifindex,
	                              (NMPObject **) &route_resolved) == NM_PLATFORM_ERROR_SUCCESS) {
		const NMPlatformIP6Route *r = NMP_OBJECT_CAST_IP6_ROUTE (route_resolved);

		if (r->ifindex == ifindex) {
			/* `ip route get` always resolves the route, even if the destination is unreachable.
			 * In which case, it pretends the destination is directly reachable.
			 *
			 * So, only accept direct routes, if @vpn_gw is a private network. */
			if (   nm_platform_route_table_is_main (r->table_coerced)
			    && (   !IN6_IS_ADDR_UNSPECIFIED (&r->gateway)
			        || nm_utils_ip_is_site_local (AF_INET6, &vpn_gw))) {
				parent_gw = &r->gateway;
				has_parent_gw = TRUE;
			}
		}
	}

	if (!has_parent_gw)
		return;

	route_metric = nm_device_get_route_metric (parent_device, AF_INET6);

	memset (&route, 0, sizeof (route));
	route.ifindex = ifindex;
	route.network = *vpn_gw;
	route.plen = 128;
	if (parent_gw)
		route.gateway = *parent_gw;
	route.rt_source = NM_IP_CONFIG_SOURCE_VPN;
	route.metric = route_metric;
	nm_ip6_config_add_route (config, &route, NULL);

	/* Ensure there's a route to the parent device's gateway through the
	 * parent device, since if the VPN claims the default route and the VPN
	 * routes include a subnet that matches the parent device's subnet,
	 * the parent device's gateway would get routed through the VPN and fail.
	 */
	if (parent_gw && !IN6_IS_ADDR_UNSPECIFIED (parent_gw)) {
		memset (&route, 0, sizeof (route));
		route.network = *parent_gw;
		route.plen = 128;
		route.rt_source = NM_IP_CONFIG_SOURCE_VPN;
		route.metric = route_metric;
		nm_ip6_config_add_route (config, &route, NULL);
	}
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

const char *
nm_vpn_connection_get_service (NMVpnConnection *self)
{
	NMSettingVpn *s_vpn;

	s_vpn = nm_connection_get_setting_vpn (_get_applied_connection (self));
	return nm_setting_vpn_get_service_type (s_vpn);
}

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (_vpn_plugin_failure_to_string, NMVpnPluginFailure,
	NM_UTILS_LOOKUP_DEFAULT (NULL),
	NM_UTILS_LOOKUP_STR_ITEM (NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED,   "login-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED, "connect-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG,  "bad-ip-config"),
);
#define vpn_plugin_failure_to_string(failure) NM_UTILS_LOOKUP_STR (_vpn_plugin_failure_to_string, failure)

static void
plugin_failed (NMVpnConnection *self, guint reason)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	_LOGW ("VPN plugin: failed: %s (%d)", vpn_plugin_failure_to_string (reason), reason);

	switch (reason) {
	case NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED:
		priv->failure_reason = NM_ACTIVE_CONNECTION_STATE_REASON_LOGIN_FAILED;
		break;
	case NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG:
		priv->failure_reason = NM_ACTIVE_CONNECTION_STATE_REASON_IP_CONFIG_INVALID;
		break;
	default:
		priv->failure_reason = NM_ACTIVE_CONNECTION_STATE_REASON_UNKNOWN;
		break;
	}
}

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (_vpn_service_state_to_string, NMVpnServiceState,
	NM_UTILS_LOOKUP_DEFAULT (NULL),
	NM_UTILS_LOOKUP_STR_ITEM (NM_VPN_SERVICE_STATE_UNKNOWN,  "unknown"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_VPN_SERVICE_STATE_INIT,     "init"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_VPN_SERVICE_STATE_SHUTDOWN, "shutdown"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_VPN_SERVICE_STATE_STARTING, "starting"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_VPN_SERVICE_STATE_STARTED,  "started"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_VPN_SERVICE_STATE_STOPPING, "stopping"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_VPN_SERVICE_STATE_STOPPED,  "stopped"),
);
#define vpn_service_state_to_string(state) NM_UTILS_LOOKUP_STR (_vpn_service_state_to_string, state)

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (_vpn_state_to_string, VpnState,
	NM_UTILS_LOOKUP_DEFAULT (NULL),
	NM_UTILS_LOOKUP_STR_ITEM (STATE_UNKNOWN,       "unknown"),
	NM_UTILS_LOOKUP_STR_ITEM (STATE_WAITING,       "waiting"),
	NM_UTILS_LOOKUP_STR_ITEM (STATE_PREPARE,       "prepare"),
	NM_UTILS_LOOKUP_STR_ITEM (STATE_NEED_AUTH,     "need-auth"),
	NM_UTILS_LOOKUP_STR_ITEM (STATE_CONNECT,       "connect"),
	NM_UTILS_LOOKUP_STR_ITEM (STATE_IP_CONFIG_GET, "ip-config-get"),
	NM_UTILS_LOOKUP_STR_ITEM (STATE_PRE_UP,        "pre-up"),
	NM_UTILS_LOOKUP_STR_ITEM (STATE_ACTIVATED,     "activated"),
	NM_UTILS_LOOKUP_STR_ITEM (STATE_DEACTIVATING,  "deactivating"),
	NM_UTILS_LOOKUP_STR_ITEM (STATE_DISCONNECTED,  "disconnected"),
	NM_UTILS_LOOKUP_STR_ITEM (STATE_FAILED,        "failed"),
);
#define vpn_state_to_string(state) NM_UTILS_LOOKUP_STR (_vpn_state_to_string, state)

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

			_set_vpn_state (self, STATE_FAILED, priv->failure_reason, FALSE);

			/* Reset the failure reason */
			priv->failure_reason = NM_ACTIVE_CONNECTION_STATE_REASON_UNKNOWN;

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
		_set_vpn_state (self, STATE_CONNECT, NM_ACTIVE_CONNECTION_STATE_REASON_CONNECT_TIMEOUT, FALSE);
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
	NMDedupMultiIter ipconf_iter;

	if (priv->ip4_external_gw) {
		_LOGI ("Data: VPN Gateway: %s",
		       nm_utils_inet4_ntop (priv->ip4_external_gw, NULL));
	} else if (priv->ip6_external_gw) {
		_LOGI ("Data: VPN Gateway: %s",
		       nm_utils_inet6_ntop (priv->ip6_external_gw, NULL));
	}

	_LOGI ("Data: Tunnel Device: %s%s%s", NM_PRINT_FMT_QUOTE_STRING (priv->ip_iface));

	if (priv->ip4_config) {
		const NMPlatformIP4Route *route;

		_LOGI ("Data: IPv4 configuration:");

		address4 = nm_ip4_config_get_first_address (priv->ip4_config);
		nm_assert (address4);

		if (priv->ip4_internal_gw)
			_LOGI ("Data:   Internal Gateway: %s", nm_utils_inet4_ntop (priv->ip4_internal_gw, NULL));
		_LOGI ("Data:   Internal Address: %s", address4 ? nm_utils_inet4_ntop (address4->address, NULL) : "??");
		_LOGI ("Data:   Internal Prefix: %d", address4 ? (int) address4->plen : -1);
		_LOGI ("Data:   Internal Point-to-Point Address: %s", nm_utils_inet4_ntop (address4->peer_address, NULL));

		nm_ip_config_iter_ip4_route_for_each (&ipconf_iter, priv->ip4_config, &route) {
			_LOGI ("Data:   Static Route: %s/%d   Next Hop: %s",
			       nm_utils_inet4_ntop (route->network, NULL),
			       route->plen,
			       nm_utils_inet4_ntop (route->gateway, buf));
		}

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
		const NMPlatformIP6Route *route;

		_LOGI ("Data: IPv6 configuration:");

		address6 = nm_ip6_config_get_first_address (priv->ip6_config);
		nm_assert (address6);

		if (priv->ip6_internal_gw)
			_LOGI ("Data:   Internal Gateway: %s", nm_utils_inet6_ntop (priv->ip6_internal_gw, NULL));
		_LOGI ("Data:   Internal Address: %s", nm_utils_inet6_ntop (&address6->address, NULL));
		_LOGI ("Data:   Internal Prefix: %d", address6->plen);
		_LOGI ("Data:   Internal Point-to-Point Address: %s", nm_utils_inet6_ntop (&address6->peer_address, NULL));

		nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, priv->ip6_config, &route) {
			_LOGI ("Data:   Static Route: %s/%d   Next Hop: %s",
			       nm_utils_inet6_ntop (&route->network, NULL),
			       route->plen,
			       nm_utils_inet6_ntop (&route->gateway, buf));
		}

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
	int ifindex;
	NMIP4Config *vpn4_parent_config = NULL;
	NMIP6Config *vpn6_parent_config = NULL;

	ifindex = nm_device_get_ip_ifindex (parent_dev);
	if (ifindex > 0) {
		/* If the VPN didn't return a network interface, it is a route-based
		 * VPN (like kernel IPSec) and all IP addressing and routing should
		 * be done on the parent interface instead.
		 */
		if (priv->ip4_config) {
			vpn4_parent_config = nm_ip4_config_new (nm_netns_get_multi_idx (priv->netns),
			                                        ifindex);
			if (priv->ip_ifindex <= 0)
				nm_ip4_config_merge (vpn4_parent_config, priv->ip4_config, NM_IP_CONFIG_MERGE_NO_DNS, 0);
		}
		if (priv->ip6_config) {
			vpn6_parent_config = nm_ip6_config_new (nm_netns_get_multi_idx (priv->netns),
			                                        ifindex);
			if (priv->ip_ifindex <= 0)
				nm_ip6_config_merge (vpn6_parent_config, priv->ip6_config, NM_IP_CONFIG_MERGE_NO_DNS, 0);
		}
	}

	/* Add any explicit route to the VPN gateway through the parent device */
	if (   vpn4_parent_config
	    && priv->ip4_external_gw) {
		add_ip4_vpn_gateway_route (vpn4_parent_config,
		                           parent_dev,
		                           priv->ip4_external_gw,
		                           nm_netns_get_platform (priv->netns));
	}
	if (   vpn6_parent_config
	    && priv->ip6_external_gw) {
		add_ip6_vpn_gateway_route (vpn6_parent_config,
		                           parent_dev,
		                           priv->ip6_external_gw,
		                           nm_netns_get_platform (priv->netns));
	}

	nm_device_replace_vpn4_config (parent_dev, priv->last_device_ip4_config, vpn4_parent_config);
	g_clear_object (&priv->last_device_ip4_config);
	priv->last_device_ip4_config = vpn4_parent_config;

	nm_device_replace_vpn6_config (parent_dev, priv->last_device_ip6_config, vpn6_parent_config);
	g_clear_object (&priv->last_device_ip6_config);
	priv->last_device_ip6_config = vpn6_parent_config;
}

static gboolean
nm_vpn_connection_apply_config (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	apply_parent_device_config (self);

	if (priv->ip_ifindex > 0) {
		nm_platform_link_set_up (nm_netns_get_platform (priv->netns), priv->ip_ifindex, NULL);

		if (priv->ip4_config) {
			nm_assert (priv->ip_ifindex == nm_ip4_config_get_ifindex (priv->ip4_config));
			if (!nm_ip4_config_commit (priv->ip4_config,
			                           nm_netns_get_platform (priv->netns),
			                           get_route_table (self, AF_INET, FALSE)
			                             ? NM_IP_ROUTE_TABLE_SYNC_MODE_FULL
			                             : NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN))
				return FALSE;
			nm_platform_ip4_dev_route_blacklist_set (nm_netns_get_platform (priv->netns),
			                                         priv->ip_ifindex,
			                                         priv->ip4_dev_route_blacklist);
		}

		if (priv->ip6_config) {
			nm_assert (priv->ip_ifindex == nm_ip6_config_get_ifindex (priv->ip6_config));
			if (!nm_ip6_config_commit (priv->ip6_config,
			                           nm_netns_get_platform (priv->netns),
			                           get_route_table (self, AF_INET6, FALSE)
			                             ? NM_IP_ROUTE_TABLE_SYNC_MODE_FULL
			                             : NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN,
			                           NULL))
				return FALSE;
		}

		if (priv->mtu && priv->mtu != nm_platform_link_get_mtu (nm_netns_get_platform (priv->netns), priv->ip_ifindex))
			nm_platform_link_set_mtu (nm_netns_get_platform (priv->netns), priv->ip_ifindex, priv->mtu);
	}

	_LOGI ("VPN connection: (IP Config Get) complete");
	if (priv->vpn_state < STATE_PRE_UP)
		_set_vpn_state (self, STATE_PRE_UP, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);
	return TRUE;
}

static void
_cleanup_failed_config (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	nm_exported_object_clear_and_unexport (&priv->ip4_config);
	nm_exported_object_clear_and_unexport (&priv->ip6_config);

	_LOGW ("VPN connection: did not receive valid IP config information");
	_set_vpn_state (self, STATE_FAILED, NM_ACTIVE_CONNECTION_STATE_REASON_IP_CONFIG_INVALID, FALSE);
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

	nm_clear_g_source (&priv->connect_timeout);

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
	gboolean b;

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_CAN_PERSIST, "b", &b) && b) {
		/* Defaults to FALSE, so only let service indicate TRUE */
		priv->service_can_persist = TRUE;
	}

	g_clear_pointer (&priv->ip_iface, g_free);
	priv->ip_ifindex = 0;

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_CONFIG_TUNDEV, "&s", &str)) {
		/* Backwards compat with NM-openswan */
		if (g_strcmp0 (str, "_none_") != 0)
			priv->ip_iface = g_strdup (str);
	}

	if (priv->ip_iface) {
		/* Grab the interface index for address/routing operations */
		priv->ip_ifindex = nm_platform_link_get_ifindex (nm_netns_get_platform (priv->netns), priv->ip_iface);
		if (priv->ip_ifindex <= 0) {
			nm_platform_process_events (nm_netns_get_platform (priv->netns));
			priv->ip_ifindex = nm_platform_link_get_ifindex (nm_netns_get_platform (priv->netns), priv->ip_iface);
		}
		if (priv->ip_ifindex <= 0) {
			_LOGE ("failed to look up VPN interface index for \"%s\"", priv->ip_iface);
			g_clear_pointer (&priv->ip_iface, g_free);
			priv->ip_ifindex = 0;
			nm_vpn_connection_config_maybe_complete (self, FALSE);
			return FALSE;
		}
	}

	g_clear_pointer (&priv->banner, g_free);
	if (g_variant_lookup (dict, NM_VPN_PLUGIN_CONFIG_BANNER, "&s", &str)) {
		priv->banner = g_strdup (str);
		_notify (self, PROP_BANNER);
	}

	/* Proxy Config */
	g_clear_object (&priv->proxy_config);
	priv->proxy_config = nm_proxy_config_new ();

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_CONFIG_PROXY_PAC, "&s", &str)) {
		nm_proxy_config_set_method (priv->proxy_config, NM_PROXY_CONFIG_METHOD_AUTO);
		nm_proxy_config_set_pac_url (priv->proxy_config, str);
	} else
		nm_proxy_config_set_method (priv->proxy_config, NM_PROXY_CONFIG_METHOD_NONE);

	/* User overrides if any from the NMConnection's Proxy settings */
	nm_proxy_config_merge_setting (priv->proxy_config,
	                               nm_connection_get_setting_proxy (_get_applied_connection (self)));

	/* External world-visible address of the VPN server */
	priv->ip4_external_gw = 0;
	g_clear_pointer (&priv->ip6_external_gw, g_free);

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, "u", &u32)) {
		priv->ip4_external_gw = u32;
	} else if (g_variant_lookup (dict, NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, "@ay", &v)) {
		priv->ip6_external_gw = ip6_addr_dup_from_variant (v);
		g_variant_unref (v);

		if (!priv->ip6_external_gw) {
			_LOGE ("Invalid IPv6 VPN gateway address received");
			nm_vpn_connection_config_maybe_complete (self, FALSE);
			return FALSE;
		}
	}

	priv->mtu = 0;
	if (g_variant_lookup (dict, NM_VPN_PLUGIN_CONFIG_MTU, "u", &u32))
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
		_set_vpn_state (self, STATE_IP_CONFIG_GET, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);

	if (!process_generic_config (self, dict))
		return;

	/* Note whether to expect IPv4 and IPv6 configs */
	priv->has_ip4 = FALSE;
	if (g_variant_lookup (dict, NM_VPN_PLUGIN_CONFIG_HAS_IP4, "b", &b))
		priv->has_ip4 = b;
	nm_exported_object_clear_and_unexport (&priv->ip4_config);

	priv->has_ip6 = FALSE;
	if (g_variant_lookup (dict, NM_VPN_PLUGIN_CONFIG_HAS_IP6, "b", &b))
		priv->has_ip6 = b;
	nm_exported_object_clear_and_unexport (&priv->ip6_config);

	nm_vpn_connection_config_maybe_complete (self, TRUE);
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

static guint32
get_route_table (NMVpnConnection *self,
                 int addr_family,
                 gboolean fallback_main)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip;
	guint32 route_table = 0;

	nm_assert (NM_IN_SET (addr_family, AF_INET, AF_INET6));

	connection = _get_applied_connection (self);
	if (connection) {
		if (addr_family == AF_INET)
			s_ip = nm_connection_get_setting_ip4_config (connection);
		else
			s_ip = nm_connection_get_setting_ip6_config (connection);

		if (s_ip)
			route_table = nm_setting_ip_config_get_route_table  (s_ip);
	}

	return route_table ?: (fallback_main ? RT_TABLE_MAIN : 0);
}

static void
nm_vpn_connection_ip4_config_get (NMVpnConnection *self, GVariant *dict)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	NMPlatformIP4Address address;
	guint32 u32, route_metric;
	NMSettingIPConfig *s_ip;
	NMSettingConnection *s_con;
	guint32 route_table;
	NMIP4Config *config;
	GVariantIter *iter;
	const char *str;
	GVariant *v;
	gboolean b;
	int ip_ifindex;
	guint32 mss = 0;
	gboolean never_default = FALSE;

	g_return_if_fail (dict && g_variant_is_of_type (dict, G_VARIANT_TYPE_VARDICT));

	if (priv->vpn_state == STATE_CONNECT)
		_set_vpn_state (self, STATE_IP_CONFIG_GET, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);

	if (priv->vpn_state > STATE_ACTIVATED) {
		_LOGI ("VPN connection: (IP4 Config Get) ignoring, the connection is no longer active");
		return;
	}

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

	ip_ifindex = nm_vpn_connection_get_ip_ifindex (self, TRUE);
	if (ip_ifindex <= 0)
		g_return_if_reached ();

	config = nm_ip4_config_new (nm_netns_get_multi_idx (priv->netns),
	                            ip_ifindex);
	nm_ip4_config_set_dns_priority (config, NM_DNS_PRIORITY_DEFAULT_VPN);

	memset (&address, 0, sizeof (address));
	address.plen = 24;

	/* Internal address of the VPN subnet's gateway */
	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_INT_GATEWAY, "u", &u32))
		priv->ip4_internal_gw = u32;

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, "u", &u32))
		address.address = u32;

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_PTP, "u", &u32))
		address.peer_address = u32;
	else
		address.peer_address = address.address;

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, "u", &u32))
		address.plen = u32;

	if (address.address && address.plen && address.plen <= 32) {
		address.addr_source = NM_IP_CONFIG_SOURCE_VPN;
		nm_ip4_config_add_address (config, &address);
	} else {
		_LOGW ("invalid IP4 config received!");
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
		mss = u32;

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN, "&s", &str))
		nm_ip4_config_add_domain (config, str);

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_DOMAINS, "as", &iter)) {
		while (g_variant_iter_next (iter, "&s", &str))
			nm_ip4_config_add_domain (config, str);
		g_variant_iter_free (iter);
	}

	route_table = get_route_table (self, AF_INET, TRUE);
	route_metric = nm_vpn_connection_get_ip4_route_metric (self);
	s_ip = nm_connection_get_setting_ip4_config (_get_applied_connection (self));
	s_con = nm_connection_get_setting_connection (_get_applied_connection (self));

	if (nm_setting_ip_config_get_ignore_auto_routes (s_ip)) {
		/* ignore VPN routes */
	} else if (   g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_PRESERVE_ROUTES, "b", &b)
	           && b) {
		if (priv->ip4_config) {
			NMDedupMultiIter ipconf_iter;
			const NMPlatformIP4Route *route;

			nm_ip_config_iter_ip4_route_for_each (&ipconf_iter, priv->ip4_config, &route)
				nm_ip4_config_add_route (config, route, NULL);
		}
	} else if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_ROUTES, "aau", &iter)) {
		while (g_variant_iter_next (iter, "@au", &v)) {
			NMPlatformIP4Route route = { 0, };
			guint32 plen;

			switch (g_variant_n_children (v)) {
			case 5:
				g_variant_get_child (v, 4, "u", &route.pref_src);
				/* fall through */
			case 4:
				g_variant_get_child (v, 0, "u", &route.network);
				g_variant_get_child (v, 1, "u", &plen);
				g_variant_get_child (v, 2, "u", &route.gateway);
				/* 4th item is unused route metric */
				route.table_coerced = nm_platform_route_table_coerce (route_table);
				route.metric = route_metric;
				route.rt_source = NM_IP_CONFIG_SOURCE_VPN;

				if (plen > 32 || plen == 0)
					break;
				route.plen = plen;
				route.network = nm_utils_ip4_address_clear_host_address (route.network, plen);

				/* Ignore host routes to the VPN gateway since NM adds one itself
				 * below.  Since NM knows more about the routing situation than
				 * the VPN server, we want to use the NM created route instead of
				 * whatever the server provides.
				 */
				if (!(priv->ip4_external_gw && route.network == priv->ip4_external_gw && route.plen == 32))
					nm_ip4_config_add_route (config, &route, NULL);
				break;
			default:
				break;
			}
			g_variant_unref (v);
		}
		g_variant_iter_free (iter);
	}

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT, "b", &b))
		never_default = b;

	/* Merge in user overrides from the NMConnection's IPv4 setting */
	nm_ip4_config_merge_setting (config,
	                             s_ip,
	                             nm_setting_connection_get_mdns (s_con),
	                             route_table,
	                             route_metric);

	if (   !never_default
	    && !nm_setting_ip_config_get_never_default (s_ip)) {
		const NMPlatformIP4Route r = {
			.ifindex   = ip_ifindex,
			.rt_source = NM_IP_CONFIG_SOURCE_VPN,
			.gateway   = priv->ip4_internal_gw,
			.table_coerced = nm_platform_route_table_coerce (route_table),
			.metric    = route_metric,
			.mss       = mss,
		};

		nm_ip4_config_add_route (config, &r, NULL);
	}

	g_clear_pointer (&priv->ip4_dev_route_blacklist, g_ptr_array_unref);

	nm_ip4_config_add_dependent_routes (config,
	                                    route_table,
	                                    nm_vpn_connection_get_ip4_route_metric (self),
	                                    &priv->ip4_dev_route_blacklist);

	if (priv->ip4_config) {
		nm_ip4_config_replace (priv->ip4_config, config, NULL);
		g_object_unref (config);
	} else {
		priv->ip4_config = config;
		nm_exported_object_export (NM_EXPORTED_OBJECT (config));
		g_object_notify ((GObject *) self, NM_ACTIVE_CONNECTION_IP4_CONFIG);
	}

	nm_vpn_connection_config_maybe_complete (self, TRUE);
}

static void
nm_vpn_connection_ip6_config_get (NMVpnConnection *self, GVariant *dict)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	NMPlatformIP6Address address;
	guint32 u32, route_metric;
	NMSettingIPConfig *s_ip;
	guint32 route_table;
	NMIP6Config *config;
	GVariantIter *iter;
	const char *str;
	GVariant *v;
	gboolean b;
	int ip_ifindex;
	guint32 mss = 0;
	gboolean never_default = FALSE;

	g_return_if_fail (dict && g_variant_is_of_type (dict, G_VARIANT_TYPE_VARDICT));

	_LOGI ("VPN connection: (IP6 Config Get) reply received");

	if (priv->vpn_state == STATE_CONNECT)
		_set_vpn_state (self, STATE_IP_CONFIG_GET, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);

	if (priv->vpn_state > STATE_ACTIVATED) {
		_LOGI ("VPN connection: (IP6 Config Get) ignoring, the connection is no longer active");
		return;
	}

	if (g_variant_n_children (dict) == 0) {
		priv->has_ip6 = FALSE;
		nm_vpn_connection_config_maybe_complete (self, TRUE);
		return;
	}

	ip_ifindex = nm_vpn_connection_get_ip_ifindex (self, TRUE);
	if (ip_ifindex <= 0)
		g_return_if_reached ();

	config = nm_ip6_config_new (nm_netns_get_multi_idx (priv->netns),
	                            ip_ifindex);
	nm_ip6_config_set_dns_priority (config, NM_DNS_PRIORITY_DEFAULT_VPN);

	memset (&address, 0, sizeof (address));
	address.plen = 128;

	/* Internal address of the VPN subnet's gateway */
	g_clear_pointer (&priv->ip6_internal_gw, g_free);
	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP6_CONFIG_INT_GATEWAY, "@ay", &v)) {
		priv->ip6_internal_gw = ip6_addr_dup_from_variant (v);
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

	if (!IN6_IS_ADDR_UNSPECIFIED (&address.address) && address.plen && address.plen <= 128) {
		address.addr_source = NM_IP_CONFIG_SOURCE_VPN;
		nm_ip6_config_add_address (config, &address);
	} else {
		_LOGW ("invalid IP6 config received!");
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
		mss = u32;

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP6_CONFIG_DOMAIN, "&s", &str))
		nm_ip6_config_add_domain (config, str);

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP6_CONFIG_DOMAINS, "as", &iter)) {
		while (g_variant_iter_next (iter, "&s", &str))
			nm_ip6_config_add_domain (config, str);
		g_variant_iter_free (iter);
	}

	route_table = get_route_table (self, AF_INET6, TRUE);
	route_metric = nm_vpn_connection_get_ip6_route_metric (self);
	s_ip = nm_connection_get_setting_ip6_config (_get_applied_connection (self));

	if (nm_setting_ip_config_get_ignore_auto_routes (s_ip)) {
		/* Ignore VPN routes */
	} else if (   g_variant_lookup (dict, NM_VPN_PLUGIN_IP6_CONFIG_PRESERVE_ROUTES, "b", &b)
	           && b) {
		if (priv->ip6_config) {
			NMDedupMultiIter ipconf_iter;
			const NMPlatformIP6Route *route;

			nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, priv->ip6_config, &route)
				nm_ip6_config_add_route (config, route, NULL);
		}
	} else if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP6_CONFIG_ROUTES, "a(ayuayu)", &iter)) {
		GVariant *dest, *next_hop;
		guint32 prefix, metric;

		while (g_variant_iter_next (iter, "(@ayu@ayu)", &dest, &prefix, &next_hop, &metric)) {
			NMPlatformIP6Route route;

			memset (&route, 0, sizeof (route));

			if (!ip6_addr_from_variant (dest, &route.network))
				goto next;

			if (prefix > 128 || prefix == 0)
				goto next;

			route.plen = prefix;
			ip6_addr_from_variant (next_hop, &route.gateway);
			route.table_coerced = nm_platform_route_table_coerce (route_table);
			route.metric = route_metric;
			route.rt_source = NM_IP_CONFIG_SOURCE_VPN;

			/* Ignore host routes to the VPN gateway since NM adds one itself.
			 * Since NM knows more about the routing situation than the VPN
			 * server, we want to use the NM created route instead of whatever
			 * the server provides.
			 */
			if (!(priv->ip6_external_gw && IN6_ARE_ADDR_EQUAL (&route.network, priv->ip6_external_gw) && route.plen == 128))
				nm_ip6_config_add_route (config, &route, NULL);

next:
			g_variant_unref (dest);
			g_variant_unref (next_hop);
		}
		g_variant_iter_free (iter);
	}

	if (g_variant_lookup (dict, NM_VPN_PLUGIN_IP6_CONFIG_NEVER_DEFAULT, "b", &b))
		never_default = b;

	/* Merge in user overrides from the NMConnection's IPv6 setting */
	nm_ip6_config_merge_setting (config,
	                             s_ip,
	                             route_table,
	                             route_metric);

	if (   !never_default
	    && !nm_setting_ip_config_get_never_default (s_ip)) {
		const NMPlatformIP6Route r = {
			.ifindex   = ip_ifindex,
			.rt_source = NM_IP_CONFIG_SOURCE_VPN,
			.gateway   = *(priv->ip6_internal_gw ?: &in6addr_any),
			.table_coerced = nm_platform_route_table_coerce (route_table),
			.metric    = route_metric,
			.mss       = mss,
		};

		nm_ip6_config_add_route (config, &r, NULL);
	}

	nm_ip6_config_add_dependent_routes (config,
	                                    route_table,
	                                    route_metric);

	if (priv->ip6_config) {
		nm_ip6_config_replace (priv->ip6_config, config, NULL);
		g_object_unref (config);
	} else {
		priv->ip6_config = config;
		nm_exported_object_export (NM_EXPORTED_OBJECT (config));
		g_object_notify ((GObject *) self, NM_ACTIVE_CONNECTION_IP6_CONFIG);
	}

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
		_set_vpn_state (self, STATE_FAILED, NM_ACTIVE_CONNECTION_STATE_REASON_CONNECT_TIMEOUT, FALSE);
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
		_set_vpn_state (self, STATE_FAILED, NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_FAILED, FALSE);
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
		_set_vpn_state (self, STATE_FAILED, NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_FAILED, FALSE);
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

	_set_vpn_state (self, STATE_CONNECT, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);
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
                     const char *const*secrets,
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
_name_owner_changed (GObject *object,
                     GParamSpec *pspec,
                     gpointer user_data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	char *owner;

	owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (object));

	if (owner && !priv->service_running) {
		/* service appeared */
		priv->service_running = TRUE;
		_LOGI ("Saw the service appear; activating connection");

		/* No need to wait for the timeout any longer */
		nm_clear_g_source (&priv->start_timeout);

		/* Expect success because the VPN service has already appeared */
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

		_set_vpn_state (self, STATE_NEED_AUTH, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);

		/* Kick off the secrets requests; first we get existing system secrets
		 * and ask the plugin if these are sufficient, next we get all existing
		 * secrets from system and from user agents and ask the plugin again,
		 * and last we ask the user for new secrets if required.
		 */
		get_secrets (self, SECRETS_REQ_SYSTEM, NULL);
	} else if (!owner && priv->service_running) {
		/* service went away */
		priv->service_running = FALSE;
		_LOGI ("VPN service disappeared");
		nm_vpn_connection_disconnect (self, NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_STOPPED, FALSE);
	}

	g_free (owner);
}


static gboolean
_daemon_exec_timeout (gpointer data)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	_LOGW ("Timed out waiting for the service to start");
	priv->start_timeout = 0;
	nm_vpn_connection_disconnect (self, NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT, FALSE);
	return G_SOURCE_REMOVE;
}

static int
_get_log_level (void)
{
	NMLogLevel level;

	/* curiously enough, nm-logging also uses syslog. But it
	 * maps NMLogLevel differently to the syslog levels then we
	 * do here.
	 *
	 * The reason is, that LOG_NOTICE is already something worth
	 * highlighting in the journal, but we have 3 levels that are
	 * lower then LOG_NOTICE (LOGL_TRACE, LOGL_DEBUG, LOGL_INFO),
	 * On the other hand, syslog only defines LOG_DEBUG and LOG_INFO.
	 * Thus, we must map them differently.
	 *
	 * Inside the VPN plugin, you might want to treat LOG_NOTICE as
	 * as low severity, not worthy to be highlighted (like NM does). */

	level = nm_logging_get_level (LOGD_VPN_PLUGIN);
	if (level != _LOGL_OFF) {
		if (level <= LOGL_TRACE)
			return LOG_DEBUG;
		if (level <= LOGL_DEBUG)
			return LOG_INFO;
		if (level <= LOGL_INFO)
			return LOG_NOTICE;
		if (level <= LOGL_WARN)
			return LOG_WARNING;
		if (level <= LOGL_ERR)
			return LOG_ERR;
	}

	return LOG_EMERG;
}

static gboolean
nm_vpn_service_daemon_exec (NMVpnConnection *self, GError **error)
{
	NMVpnConnectionPrivate *priv;
	GPid pid;
	char *vpn_argv[4];
	gboolean success = FALSE;
	GError *spawn_error = NULL;
	guint i, j, n_environ;
	gs_free char **envp = NULL;
	char env_log_level[NM_STRLEN ("NM_VPN_LOG_LEVEL=") + 100];
	char env_log_syslog[NM_STRLEN ("NM_VPN_LOG_SYSLOG=") + 10];
	const int N_ENVIRON_EXTRA = 3;
	char **p_environ;

	g_return_val_if_fail (NM_IS_VPN_CONNECTION (self), FALSE);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	i = 0;
	vpn_argv[i++] = (char *) nm_vpn_plugin_info_get_program (priv->plugin_info);
	g_return_val_if_fail (vpn_argv[0], FALSE);
	if (nm_vpn_plugin_info_supports_multiple (priv->plugin_info)) {
		vpn_argv[i++] = "--bus-name";
		vpn_argv[i++] = priv->bus_name;
	}
	vpn_argv[i++] = NULL;

	/* we include <unistd.h> and "config.h" defines _GNU_SOURCE for us. So, we have @environ. */
	p_environ = environ;
	n_environ = p_environ ? g_strv_length (p_environ) : 0;
	envp = g_new (char *, n_environ + N_ENVIRON_EXTRA);
	for (i = 0, j = 0; j < n_environ; j++) {
		if (   g_str_has_prefix (p_environ[j], "NM_VPN_LOG_LEVEL=")
		    || g_str_has_prefix (p_environ[j], "NM_VPN_LOG_SYSLOG="))
			continue;
		envp[i++] = p_environ[j];
	}

	/* NM_VPN_LOG_LEVEL: the syslog logging level for the plugin. */
	envp[i++] = nm_sprintf_buf (env_log_level,  "NM_VPN_LOG_LEVEL=%d", _get_log_level ());

	/* NM_VPN_LOG_SYSLOG: whether to log to stdout or syslog. If NetworkManager itself runs in
	 * foreground, we also want the plugin to log to stdout.
	 * If the plugin runs in background, the plugin should prefer logging to syslog. Otherwise
	 * logging messages will be lost (unless using journald, in which case it wouldn't matter). */
	envp[i++] = nm_sprintf_buf (env_log_syslog, "NM_VPN_LOG_SYSLOG=%c", nm_logging_syslog_enabled () ? '1' : '0');

	envp[i++] = NULL;
	nm_assert (i <= n_environ + N_ENVIRON_EXTRA);

	success = g_spawn_async (NULL, vpn_argv, envp, 0, nm_utils_setpgid, NULL, &pid, &spawn_error);

	if (success) {
		_LOGI ("Started the VPN service, PID %ld", (long int) pid);
		priv->start_timeout = g_timeout_add_seconds (5, _daemon_exec_timeout, self);
	} else {
		g_set_error (error,
		             NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		             "%s", spawn_error ? spawn_error->message : "unknown g_spawn_async() error");

		if (spawn_error)
			g_error_free (spawn_error);
	}

	return success;
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
		                NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_FAILED,
		                FALSE);
		return;
	}

	priv->proxy = proxy;

	g_signal_connect (priv->proxy, "notify::g-name-owner",
	                  G_CALLBACK (_name_owner_changed), self);
	_name_owner_changed (G_OBJECT (priv->proxy), NULL, self);

	if (priv->service_running)
		return;

	if (!nm_vpn_service_daemon_exec (self, &error)) {
		_LOGW ("Could not launch the VPN service. error: %s.",
		       error->message);

		nm_vpn_connection_disconnect (self, NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_FAILED, FALSE);
	}
}

void
nm_vpn_connection_activate (NMVpnConnection *self,
                            NMVpnPluginInfo *plugin_info)
{
	NMVpnConnectionPrivate *priv;
	NMSettingVpn *s_vpn;
	const char *service;

	g_return_if_fail (NM_IS_VPN_CONNECTION (self));
	g_return_if_fail (NM_IS_VPN_PLUGIN_INFO (plugin_info));

	priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	g_return_if_fail (!priv->plugin_info);

	s_vpn = nm_connection_get_setting_vpn (_get_applied_connection (self));
	g_return_if_fail (s_vpn);

	service = nm_vpn_plugin_info_get_service (plugin_info);
	nm_assert (service);

	if (nm_vpn_plugin_info_supports_multiple (plugin_info)) {
		const char *path;

		path = nm_exported_object_get_path (NM_EXPORTED_OBJECT (self));
		if (path)
			path = strrchr (path, '/');
		g_return_if_fail (path);

		priv->bus_name = g_strdup_printf ("%s.Connection_%s", service, &path[1]);
	} else
		priv->bus_name = g_strdup (service);

	priv->connection_can_persist = nm_setting_vpn_get_persistent (s_vpn);
	priv->plugin_info = g_object_ref (plugin_info);
	priv->cancellable = g_cancellable_new ();

	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                          NULL,
	                          priv->bus_name,
	                          NM_VPN_DBUS_PLUGIN_PATH,
	                          NM_VPN_DBUS_PLUGIN_INTERFACE,
	                          priv->cancellable,
	                          (GAsyncReadyCallback) on_proxy_acquired,
	                          self);

	_set_vpn_state (self, STATE_PREPARE, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);
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

NMProxyConfig *
nm_vpn_connection_get_proxy_config (NMVpnConnection *self)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (self), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (self)->proxy_config;
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

static int
_get_ip_iface_for_device (NMVpnConnection *self, const char **out_iface)
{
	NMDevice *parent_dev;
	int ifindex;
	const char *iface;

	nm_assert (NM_IS_VPN_CONNECTION (self));

	/* the ifindex and the ifname in this case should come together.
	 * They either must be both set, or none. */

	parent_dev = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (self));
	if (!parent_dev)
		goto none;
	ifindex = nm_device_get_ip_ifindex (parent_dev);
	if (ifindex <= 0)
		goto none;
	iface = nm_device_get_ip_iface (parent_dev);
	if (!iface)
		goto none;

	NM_SET_OUT (out_iface, iface);
	return ifindex;
none:
	NM_SET_OUT (out_iface, NULL);
	return 0;
}

const char *
nm_vpn_connection_get_ip_iface (NMVpnConnection *self, gboolean fallback_device)
{
	NMVpnConnectionPrivate *priv;
	const char *iface;

	g_return_val_if_fail (NM_IS_VPN_CONNECTION (self), NULL);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	if (priv->ip_iface || !fallback_device)
		return priv->ip_iface;

	_get_ip_iface_for_device (self, &iface);
	return iface;
}

int
nm_vpn_connection_get_ip_ifindex (NMVpnConnection *self, gboolean fallback_device)
{
	NMVpnConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_VPN_CONNECTION (self), 0);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	if (priv->ip_ifindex > 0)
		return priv->ip_ifindex;
	if (!fallback_device)
		return 0;

	return _get_ip_iface_for_device (self, NULL);
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
                              NMActiveConnectionStateReason reason,
                              gboolean quitting)
{
	g_return_if_fail (NM_IS_VPN_CONNECTION (self));

	_set_vpn_state (self, STATE_DISCONNECTED, reason, quitting);
}

gboolean
nm_vpn_connection_deactivate (NMVpnConnection *self,
                              NMActiveConnectionStateReason reason,
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

/*****************************************************************************/

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
		_set_vpn_state (self, STATE_FAILED, NM_ACTIVE_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
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
		_set_vpn_state (self, STATE_FAILED, NM_ACTIVE_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
	} else {
		_LOGD ("service indicated additional secrets required");
		get_secrets (self, priv->secrets_idx + 1, NULL);
	}
}

static void
plugin_new_secrets_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
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
		_LOGE ("sending new secrets to the plugin failed: %s",
		       error->message);
		_set_vpn_state (self, STATE_FAILED, NM_ACTIVE_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
	} else
		_set_vpn_state (self, STATE_CONNECT, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);
}

static void
get_secrets_cb (NMSettingsConnection *connection,
                NMSettingsConnectionCallId *call_id,
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
		_LOGE ("Failed to request VPN secrets #%d: %s",
		       priv->secrets_idx + 1, error->message);
		_set_vpn_state (self, STATE_FAILED, NM_ACTIVE_CONNECTION_STATE_REASON_NO_SECRETS, FALSE);
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
             const char *const*hints)
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
                                     const char *const*secrets)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);
	const gsize secrets_len = NM_PTRARRAY_LEN (secrets);
	gsize i;
	gs_free const char **hints = NULL;
	gs_free char *message_hint = NULL;

	_LOGI ("VPN plugin: requested secrets; state %s (%d)",
	       vpn_state_to_string (priv->vpn_state), priv->vpn_state);

	g_return_if_fail (priv->vpn_state == STATE_CONNECT ||
	                  priv->vpn_state == STATE_NEED_AUTH);

	priv->secrets_idx = SECRETS_REQ_INTERACTIVE;
	_set_vpn_state (self, STATE_NEED_AUTH, NM_ACTIVE_CONNECTION_STATE_REASON_NONE, FALSE);

	/* Copy hints and add message to the end */
	hints = g_new (const char *, secrets_len + 2);
	for (i = 0; i < secrets_len; i++)
		hints[i] = secrets[i];
	if (message) {
		message_hint = g_strdup_printf ("x-vpn-message:%s", message);
		hints[i++] = message_hint;
	}
	hints[i] = NULL;
	nm_assert (i < secrets_len + 2);

	get_secrets (self, SECRETS_REQ_INTERACTIVE, hints);
}

/*****************************************************************************/

static void
device_changed (NMActiveConnection *active,
                NMDevice *new_device,
                NMDevice *old_device)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE ((NMVpnConnection *) active);

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
	if (old_device)
		remove_parent_device_config (NM_VPN_CONNECTION (active), old_device);

	if (new_device)
		apply_parent_device_config (NM_VPN_CONNECTION (active));
}

/*****************************************************************************/

static void
nm_vpn_connection_init (NMVpnConnection *self)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	priv->vpn_state = STATE_WAITING;
	priv->secrets_idx = SECRETS_REQ_SYSTEM;
	priv->netns = g_object_ref (nm_netns_get ());
}

static void
dispose (GObject *object)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (object);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (self);

	nm_clear_g_source (&priv->start_timeout);

	g_clear_pointer (&priv->connect_hash, g_variant_unref);

	g_clear_pointer (&priv->ip4_dev_route_blacklist, g_ptr_array_unref);

	nm_clear_g_source (&priv->connect_timeout);

	dispatcher_cleanup (self);

	cancel_get_secrets (self);

	nm_clear_g_cancellable (&priv->cancellable);

	g_clear_object (&priv->proxy_config);
	nm_exported_object_clear_and_unexport (&priv->ip4_config);
	nm_exported_object_clear_and_unexport (&priv->ip6_config);
	g_clear_object (&priv->proxy);
	g_clear_object (&priv->plugin_info);

	fw_call_cleanup (self);

	nm_pacrunner_manager_remove_clear (priv->pacrunner_manager,
	                                   &priv->pacrunner_call_id);
	g_clear_object (&priv->pacrunner_manager);

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE ((NMVpnConnection *) object);

	g_free (priv->banner);
	g_free (priv->ip_iface);
	g_free (priv->username);
	g_free (priv->ip6_internal_gw);
	g_free (priv->ip6_external_gw);

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->finalize (object);

	g_clear_object (&priv->netns);
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
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE ((NMVpnConnection *) object);
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

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	active_class->device_state_changed = device_state_changed;
	active_class->device_changed = device_changed;

	obj_properties[PROP_VPN_STATE] =
	    g_param_spec_uint (NM_VPN_CONNECTION_VPN_STATE, "", "",
	                       NM_VPN_CONNECTION_STATE_UNKNOWN,
	                       NM_VPN_CONNECTION_STATE_DISCONNECTED,
	                       NM_VPN_CONNECTION_STATE_UNKNOWN,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_BANNER] =
	    g_param_spec_string (NM_VPN_CONNECTION_BANNER, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	g_object_class_override_property (object_class, PROP_MASTER,
	                                  NM_ACTIVE_CONNECTION_MASTER);
	g_object_class_override_property (object_class, PROP_IP4_CONFIG,
	                                  NM_ACTIVE_CONNECTION_IP4_CONFIG);
	g_object_class_override_property (object_class, PROP_IP6_CONFIG,
	                                  NM_ACTIVE_CONNECTION_IP6_CONFIG);

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
