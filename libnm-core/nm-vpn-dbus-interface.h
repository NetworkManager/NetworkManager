/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2004 Red Hat, Inc.
 */

/* D-Bus-related definitions for NetworkManager VPN plugins.
 *
 * Note that although this header is installed as part of libnm, it is also
 * used by some external code that does not link to libnm.
 */

#ifndef __NM_VPN_DBUS_INTERFACE_H__
#define __NM_VPN_DBUS_INTERFACE_H__

#include "nm-dbus-interface.h"

#ifndef NM_VERSION_H
#define NM_DEPRECATED_IN_1_8_FOR(n)
#endif

/*
 * dbus services details
 */
#define NM_DBUS_PATH_VPN                  "/org/freedesktop/NetworkManager/VPN/Manager"
#define NM_DBUS_INTERFACE_VPN             "org.freedesktop.NetworkManager.VPN.Manager"

#define NM_DBUS_PATH_VPN_CONNECTION       "/org/freedesktop/NetworkManager/VPN/Connection"
#define NM_DBUS_INTERFACE_VPN_CONNECTION  "org.freedesktop.NetworkManager.VPN.Connection"

#define NM_VPN_DBUS_PLUGIN_PATH           "/org/freedesktop/NetworkManager/VPN/Plugin"
#define NM_VPN_DBUS_PLUGIN_INTERFACE      "org.freedesktop.NetworkManager.VPN.Plugin"

/*
 * VPN Errors
 */
#define NM_DBUS_NO_ACTIVE_VPN_CONNECTION "org.freedesktop.NetworkManager.VPNConnections.NoActiveVPNConnection"
#define NM_DBUS_NO_VPN_CONNECTIONS       "org.freedesktop.NetworkManager.VPNConnections.NoVPNConnections"
#define NM_DBUS_INVALID_VPN_CONNECTION   "org.freedesktop.NetworkManager.VPNConnections.InvalidVPNConnection"

#define NM_DBUS_VPN_ERROR_PREFIX              "org.freedesktop.NetworkManager.VPN.Error"
#define NM_DBUS_VPN_STARTING_IN_PROGRESS      "StartingInProgress"
#define NM_DBUS_VPN_ALREADY_STARTED           "AlreadyStarted"
#define NM_DBUS_VPN_STOPPING_IN_PROGRESS      "StoppingInProgress"
#define NM_DBUS_VPN_ALREADY_STOPPED           "AlreadyStopped"
#define NM_DBUS_VPN_WRONG_STATE               "WrongState"
#define NM_DBUS_VPN_BAD_ARGUMENTS             "BadArguments"
#define NM_DBUS_VPN_INTERACTIVE_NOT_SUPPORTED "InteractiveNotSupported"

/*
 * VPN daemon signals
 */
#define NM_DBUS_VPN_SIGNAL_LOGIN_BANNER   "LoginBanner"
#define NM_DBUS_VPN_SIGNAL_LOGIN_FAILED   "LoginFailed"
#define NM_DBUS_VPN_SIGNAL_LAUNCH_FAILED  "LaunchFailed"
#define NM_DBUS_VPN_SIGNAL_CONNECT_FAILED "ConnectFailed"
#define NM_DBUS_VPN_SIGNAL_VPN_CONFIG_BAD "VPNConfigBad"
#define NM_DBUS_VPN_SIGNAL_IP_CONFIG_BAD  "IPConfigBad"
#define NM_DBUS_VPN_SIGNAL_STATE_CHANGE   "StateChange"
#define NM_DBUS_VPN_SIGNAL_IP4_CONFIG     "IP4Config"

/**
 * NMVpnServiceState:
 * @NM_VPN_SERVICE_STATE_UNKNOWN: The state of the VPN plugin is unknown.
 * @NM_VPN_SERVICE_STATE_INIT: The VPN plugin is initialized.
 * @NM_VPN_SERVICE_STATE_SHUTDOWN: Not used.
 * @NM_VPN_SERVICE_STATE_STARTING: The plugin is attempting to connect to a VPN server.
 * @NM_VPN_SERVICE_STATE_STARTED: The plugin has connected to a VPN server.
 * @NM_VPN_SERVICE_STATE_STOPPING: The plugin is disconnecting from the VPN server.
 * @NM_VPN_SERVICE_STATE_STOPPED: The plugin has disconnected from the VPN server.
 *
 * VPN daemon states
 */
typedef enum {
	NM_VPN_SERVICE_STATE_UNKNOWN = 0,
	NM_VPN_SERVICE_STATE_INIT,
	NM_VPN_SERVICE_STATE_SHUTDOWN,
	NM_VPN_SERVICE_STATE_STARTING,
	NM_VPN_SERVICE_STATE_STARTED,
	NM_VPN_SERVICE_STATE_STOPPING,
	NM_VPN_SERVICE_STATE_STOPPED
} NMVpnServiceState;

/**
 * NMVpnConnectionState:
 * @NM_VPN_CONNECTION_STATE_UNKNOWN: The state of the VPN connection is
 *   unknown.
 * @NM_VPN_CONNECTION_STATE_PREPARE: The VPN connection is preparing to
 *   connect.
 * @NM_VPN_CONNECTION_STATE_NEED_AUTH: The VPN connection needs authorization
 *   credentials.
 * @NM_VPN_CONNECTION_STATE_CONNECT: The VPN connection is being established.
 * @NM_VPN_CONNECTION_STATE_IP_CONFIG_GET: The VPN connection is getting an IP
 *   address.
 * @NM_VPN_CONNECTION_STATE_ACTIVATED: The VPN connection is active.
 * @NM_VPN_CONNECTION_STATE_FAILED: The VPN connection failed.
 * @NM_VPN_CONNECTION_STATE_DISCONNECTED: The VPN connection is disconnected.
 *
 * VPN connection states
 */
typedef enum {
	NM_VPN_CONNECTION_STATE_UNKNOWN = 0,
	NM_VPN_CONNECTION_STATE_PREPARE,
	NM_VPN_CONNECTION_STATE_NEED_AUTH,
	NM_VPN_CONNECTION_STATE_CONNECT,
	NM_VPN_CONNECTION_STATE_IP_CONFIG_GET,
	NM_VPN_CONNECTION_STATE_ACTIVATED,
	NM_VPN_CONNECTION_STATE_FAILED,
	NM_VPN_CONNECTION_STATE_DISCONNECTED
} NMVpnConnectionState;

/**
 * NMVpnConnectionStateReason:
 * @NM_VPN_CONNECTION_STATE_REASON_UNKNOWN: The reason for the VPN connection
 *   state change is unknown.
 * @NM_VPN_CONNECTION_STATE_REASON_NONE: No reason was given for the VPN
 *   connection state change.
 * @NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED: The VPN connection changed
 *   state because the user disconnected it.
 * @NM_VPN_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED: The VPN connection
 *   changed state because the device it was using was disconnected.
 * @NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED: The service providing the
 *   VPN connection was stopped.
 * @NM_VPN_CONNECTION_STATE_REASON_IP_CONFIG_INVALID: The IP config of the VPN
 *   connection was invalid.
 * @NM_VPN_CONNECTION_STATE_REASON_CONNECT_TIMEOUT: The connection attempt to
 *   the VPN service timed out.
 * @NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT: A timeout occurred
 *   while starting the service providing the VPN connection.
 * @NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED: Starting the service
 *   starting the service providing the VPN connection failed.
 * @NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS: Necessary secrets for the VPN
 *   connection were not provided.
 * @NM_VPN_CONNECTION_STATE_REASON_LOGIN_FAILED: Authentication to the VPN
 *   server failed.
 * @NM_VPN_CONNECTION_STATE_REASON_CONNECTION_REMOVED: The connection was
 *   deleted from settings.
 *
 * VPN connection state reasons
 */
NM_DEPRECATED_IN_1_8_FOR(NMActiveConnectionStateReason)
typedef enum {
	NM_VPN_CONNECTION_STATE_REASON_UNKNOWN                  = NM_ACTIVE_CONNECTION_STATE_REASON_UNKNOWN,
	NM_VPN_CONNECTION_STATE_REASON_NONE                     = NM_ACTIVE_CONNECTION_STATE_REASON_NONE,
	NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED        = NM_ACTIVE_CONNECTION_STATE_REASON_USER_DISCONNECTED,
	NM_VPN_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED      = NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED,
	NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED          = NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_STOPPED,
	NM_VPN_CONNECTION_STATE_REASON_IP_CONFIG_INVALID        = NM_ACTIVE_CONNECTION_STATE_REASON_IP_CONFIG_INVALID,
	NM_VPN_CONNECTION_STATE_REASON_CONNECT_TIMEOUT          = NM_ACTIVE_CONNECTION_STATE_REASON_CONNECT_TIMEOUT,
	NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT    = NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT,
	NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED     = NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_FAILED,
	NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS               = NM_ACTIVE_CONNECTION_STATE_REASON_NO_SECRETS,
	NM_VPN_CONNECTION_STATE_REASON_LOGIN_FAILED             = NM_ACTIVE_CONNECTION_STATE_REASON_LOGIN_FAILED,
	NM_VPN_CONNECTION_STATE_REASON_CONNECTION_REMOVED       = NM_ACTIVE_CONNECTION_STATE_REASON_CONNECTION_REMOVED,
} NMVpnConnectionStateReason;

/**
 * NMVpnPluginFailure:
 * @NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED: Login failed.
 * @NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED: Connect failed.
 * @NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG: Invalid IP configuration returned from
 *   the VPN plugin.
 *
 * VPN plugin failure reasons
 */
typedef enum {
	NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED,
	NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED,
	NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG
} NMVpnPluginFailure;

#ifndef NM_VERSION_H
#undef NM_DEPRECATED_IN_1_8_FOR
#endif

/*** Generic config ***/

/* string: VPN interface name (tun0, tap0, etc) */
#define NM_VPN_PLUGIN_CONFIG_TUNDEV      "tundev"

/* string: Proxy PAC */
#define NM_VPN_PLUGIN_CONFIG_PROXY_PAC   "pac"

/* string: Login message */
#define NM_VPN_PLUGIN_CONFIG_BANNER      "banner"

/* uint32 / array of uint8: IP address of the public external VPN gateway (network byte order) */
#define NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY "gateway"

/* uint32: Maximum Transfer Unit that the VPN interface should use */
#define NM_VPN_PLUGIN_CONFIG_MTU         "mtu"

/* boolean: Has IP4 configuration? */
#define NM_VPN_PLUGIN_CONFIG_HAS_IP4     "has-ip4"

/* boolean: Has IP6 configuration? */
#define NM_VPN_PLUGIN_CONFIG_HAS_IP6     "has-ip6"

/* boolean: If %TRUE the VPN plugin can persist/reconnect the connection over
 * link changes and VPN server dropouts.
 */
#define NM_VPN_PLUGIN_CAN_PERSIST        "can-persist"

/*** Ip4Config ***/

/* uint32: IP address of the internal gateway of the subnet the VPN interface is
 *         on, if the VPN uses subnet configuration (network byte order)
 */
#define NM_VPN_PLUGIN_IP4_CONFIG_INT_GATEWAY "internal-gateway"

/* uint32: internal IP address of the local VPN interface (network byte order) */
#define NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS     "address"

/* uint32: IP address of the other side of Point-to-Point connection if the VPN
 *         uses Point-to-Point configuration. (network byte order)
 */
#define NM_VPN_PLUGIN_IP4_CONFIG_PTP         "ptp"

/* uint32: IP prefix of the VPN interface; 1 - 32 inclusive */
#define NM_VPN_PLUGIN_IP4_CONFIG_PREFIX      "prefix"

/* array of uint32: IP addresses of DNS servers for the VPN (network byte order) */
#define NM_VPN_PLUGIN_IP4_CONFIG_DNS         "dns"

/* array of uint32: IP addresses of NBNS/WINS servers for the VPN (network byte order) */
#define NM_VPN_PLUGIN_IP4_CONFIG_NBNS        "nbns"

/* uint32: Message Segment Size that the VPN interface should use */
#define NM_VPN_PLUGIN_IP4_CONFIG_MSS         "mss"

/* string: DNS domain name */
#define NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN      "domain"

/* array of strings: DNS domain names */
#define NM_VPN_PLUGIN_IP4_CONFIG_DOMAINS     "domains"

/* [ip4 routes]: custom routes the client should apply, in the format used
 *         by nm_utils_ip4_routes_to/from_gvalue
 */
#define NM_VPN_PLUGIN_IP4_CONFIG_ROUTES      "routes"

/* whether the previous IP4 routing configuration should be preserved. */
#define NM_VPN_PLUGIN_IP4_CONFIG_PRESERVE_ROUTES "preserve-routes"

/* boolean: prevent this VPN connection from ever getting the default route */
#define NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT "never-default"

/* Deprecated */
#define NM_VPN_PLUGIN_IP4_CONFIG_GATEWAY   NM_VPN_PLUGIN_IP4_CONFIG_EXT_GATEWAY

/* Legacy IP4 items; these are included in the IP4 config by older plugins,
 * but in the generic config by newer plugins.
 */

#define NM_VPN_PLUGIN_IP4_CONFIG_BANNER      NM_VPN_PLUGIN_CONFIG_BANNER
#define NM_VPN_PLUGIN_IP4_CONFIG_EXT_GATEWAY NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY
#define NM_VPN_PLUGIN_IP4_CONFIG_MTU         NM_VPN_PLUGIN_CONFIG_MTU
#define NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV      NM_VPN_PLUGIN_CONFIG_TUNDEV

/*** Ip6Config ***/

/* array of uint8: IP address of the internal gateway of the subnet the VPN interface is
 *         on, if the VPN uses subnet configuration (network byte order)
 */
#define NM_VPN_PLUGIN_IP6_CONFIG_INT_GATEWAY "internal-gateway"

/* array of uint8: internal IP address of the local VPN interface (network byte order) */
#define NM_VPN_PLUGIN_IP6_CONFIG_ADDRESS     "address"

/* array of uint8: IP address of the other side of Point-to-Point connection if the VPN
 *         uses Point-to-Point configuration. (network byte order)
 */
#define NM_VPN_PLUGIN_IP6_CONFIG_PTP         "ptp"

/* uint32: prefix length of the VPN interface; 1 - 128 inclusive */
#define NM_VPN_PLUGIN_IP6_CONFIG_PREFIX      "prefix"

/* array of array of uint8: IP addresses of DNS servers for the VPN (network byte order) */
#define NM_VPN_PLUGIN_IP6_CONFIG_DNS         "dns"

/* uint32: Message Segment Size that the VPN interface should use */
#define NM_VPN_PLUGIN_IP6_CONFIG_MSS         "mss"

/* string: DNS domain name */
#define NM_VPN_PLUGIN_IP6_CONFIG_DOMAIN      "domain"

/* array of strings: DNS domain names */
#define NM_VPN_PLUGIN_IP6_CONFIG_DOMAINS     "domains"

/* [ip6 routes]: custom routes the client should apply, in the format used
 *         by nm_utils_ip6_routes_to/from_gvalue
 */
#define NM_VPN_PLUGIN_IP6_CONFIG_ROUTES      "routes"

/* whether the previous IP6 routing configuration should be preserved. */
#define NM_VPN_PLUGIN_IP6_CONFIG_PRESERVE_ROUTES "preserve-routes"

/* boolean: prevent this VPN connection from ever getting the default route */
#define NM_VPN_PLUGIN_IP6_CONFIG_NEVER_DEFAULT "never-default"

#endif /* __NM_VPN_DBUS_INTERFACE_H__ */
