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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifndef NETWORK_MANAGER_VPN_H
#define NETWORK_MANAGER_VPN_H

/*
 * dbus services details
 */
#define	NM_DBUS_PATH_VPN                  "/org/freedesktop/NetworkManager/VPN/Manager"
#define	NM_DBUS_INTERFACE_VPN             "org.freedesktop.NetworkManager.VPN.Manager"

#define	NM_DBUS_PATH_VPN_CONNECTION       "/org/freedesktop/NetworkManager/VPN/Connection"
#define	NM_DBUS_INTERFACE_VPN_CONNECTION  "org.freedesktop.NetworkManager.VPN.Connection"

#define NM_VPN_DBUS_PLUGIN_PATH           "/org/freedesktop/NetworkManager/VPN/Plugin"
#define NM_VPN_DBUS_PLUGIN_INTERFACE      "org.freedesktop.NetworkManager.VPN.Plugin"

/*
 * VPN Errors
 */
#define NM_DBUS_NO_ACTIVE_VPN_CONNECTION	"org.freedesktop.NetworkManager.VPNConnections.NoActiveVPNConnection"
#define NM_DBUS_NO_VPN_CONNECTIONS			"org.freedesktop.NetworkManager.VPNConnections.NoVPNConnections"
#define NM_DBUS_INVALID_VPN_CONNECTION		"org.freedesktop.NetworkManager.VPNConnections.InvalidVPNConnection"

#define NM_DBUS_VPN_STARTING_IN_PROGRESS	"StartingInProgress"
#define NM_DBUS_VPN_ALREADY_STARTED		"AlreadyStarted"
#define NM_DBUS_VPN_STOPPING_IN_PROGRESS	"StoppingInProgress"
#define NM_DBUS_VPN_ALREADY_STOPPED		"AlreadyStopped"
#define NM_DBUS_VPN_WRONG_STATE			"WrongState"
#define NM_DBUS_VPN_BAD_ARGUMENTS			"BadArguments"


/*
 * VPN daemon signals
 */
#define NM_DBUS_VPN_SIGNAL_LOGIN_BANNER		"LoginBanner"
#define NM_DBUS_VPN_SIGNAL_LOGIN_FAILED		"LoginFailed"
#define NM_DBUS_VPN_SIGNAL_LAUNCH_FAILED	"LaunchFailed"
#define NM_DBUS_VPN_SIGNAL_CONNECT_FAILED	"ConnectFailed"
#define NM_DBUS_VPN_SIGNAL_VPN_CONFIG_BAD	"VPNConfigBad"
#define NM_DBUS_VPN_SIGNAL_IP_CONFIG_BAD	"IPConfigBad"
#define NM_DBUS_VPN_SIGNAL_STATE_CHANGE		"StateChange"
#define NM_DBUS_VPN_SIGNAL_IP4_CONFIG		"IP4Config"

/*
 * VPN daemon states
 */
typedef enum NMVPNServiceState
{
	NM_VPN_SERVICE_STATE_UNKNOWN = 0,
	NM_VPN_SERVICE_STATE_INIT,
	NM_VPN_SERVICE_STATE_SHUTDOWN,
	NM_VPN_SERVICE_STATE_STARTING,
	NM_VPN_SERVICE_STATE_STARTED,
	NM_VPN_SERVICE_STATE_STOPPING,
	NM_VPN_SERVICE_STATE_STOPPED
} NMVPNServiceState;


/*
 * VPN connection states
 */
typedef enum NMVPNConnectionState
{
	NM_VPN_CONNECTION_STATE_UNKNOWN = 0,
	NM_VPN_CONNECTION_STATE_PREPARE,
	NM_VPN_CONNECTION_STATE_NEED_AUTH,
	NM_VPN_CONNECTION_STATE_CONNECT,
	NM_VPN_CONNECTION_STATE_IP_CONFIG_GET,
	NM_VPN_CONNECTION_STATE_ACTIVATED,
	NM_VPN_CONNECTION_STATE_FAILED,
	NM_VPN_CONNECTION_STATE_DISCONNECTED
} NMVPNConnectionState;

typedef enum NMVPNConnectionStateReason
{
	NM_VPN_CONNECTION_STATE_REASON_UNKNOWN = 0,
	NM_VPN_CONNECTION_STATE_REASON_NONE,
	NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED,
	NM_VPN_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED,
	NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED,
	NM_VPN_CONNECTION_STATE_REASON_IP_CONFIG_INVALID,
	NM_VPN_CONNECTION_STATE_REASON_CONNECT_TIMEOUT,
	NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT,
	NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED,
	NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS
} NMVPNConnectionStateReason;

#define NM_VPN_PLUGIN_IP4_CONFIG_GATEWAY "gateway"
#define NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS "address"
#define NM_VPN_PLUGIN_IP4_CONFIG_PTP     "ptp"
#define NM_VPN_PLUGIN_IP4_CONFIG_NETMASK "netmask"
#define NM_VPN_PLUGIN_IP4_CONFIG_DNS     "dns"
#define NM_VPN_PLUGIN_IP4_CONFIG_NBNS    "nbns"
#define NM_VPN_PLUGIN_IP4_CONFIG_MSS     "mss"
#define NM_VPN_PLUGIN_IP4_CONFIG_MTU     "mtu"
#define NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV  "tundev"
#define NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN  "domain"
#define NM_VPN_PLUGIN_IP4_CONFIG_BANNER  "banner"
#define NM_VPN_PLUGIN_IP4_CONFIG_ROUTES  "routes"

#endif /* NETWORK_MANAGER_VPN_H */
