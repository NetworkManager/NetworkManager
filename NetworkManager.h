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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

/*
 * dbus services details
 */
#define	NM_DBUS_SERVICE			"org.freedesktop.NetworkManager"

#define	NM_DBUS_PATH				"/org/freedesktop/NetworkManager"
#define	NM_DBUS_INTERFACE			"org.freedesktop.NetworkManager"
#define	NM_DBUS_PATH_DEVICES		"/org/freedesktop/NetworkManager/Devices"
#define	NM_DBUS_INTERFACE_DEVICES	"org.freedesktop.NetworkManager.Devices"
#define	NM_DBUS_PATH_DHCP			"/org/freedesktop/NetworkManager/DhcpOptions"
#define	NM_DBUS_INTERFACE_DHCP		"org.freedesktop.NetworkManager.DhcpOptions"
#define	NM_DBUS_PATH_VPN			"/org/freedesktop/NetworkManager/VPNConnections"
#define	NM_DBUS_INTERFACE_VPN		"org.freedesktop.NetworkManager.VPNConnections"

#define	NMI_DBUS_SERVICE			"org.freedesktop.NetworkManagerInfo"
#define	NMI_DBUS_PATH				"/org/freedesktop/NetworkManagerInfo"
#define	NMI_DBUS_INTERFACE			"org.freedesktop.NetworkManagerInfo"


/*
 * Some common errors
 */
#define NM_DBUS_NO_DEVICES_ERROR		"org.freedesktop.NetworkManager.NoDevices"
#define NM_DBUS_NO_NETWORKS_ERROR		"org.freedesktop.NetworkManager.NoNetworks"
#define NM_DBUS_NO_ACTIVE_DEVICE_ERROR	"org.freedesktop.NetworkManager.NoActiveDevice"
#define NM_DBUS_NO_ACTIVE_NET_ERROR	"org.freedesktop.NetworkManager.NoActiveNetwork"

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
#define NM_DBUS_VPN_SIGNAL_CONFIG_BAD		"ConfigurationBad"
#define NM_DBUS_VPN_SIGNAL_STATE_CHANGE		"StateChange"
#define NM_DBUS_VPN_SIGNAL_IP4_CONFIG		"IP4Config"


/*
 * NetworkManager signals
 */
#define NM_DBUS_SIGNAL_STATE_CHANGE		"StateChange"


/*
 * Types of NetworkManager devices
 */
typedef enum NMState
{
	NM_STATE_UNKNOWN = 0,
	NM_STATE_ASLEEP,
	NM_STATE_CONNECTING,
	NM_STATE_CONNECTED,
	NM_STATE_DISCONNECTED
} NMState;


/*
 * Types of NetworkManager devices
 */
typedef enum NMDeviceType
{
	DEVICE_TYPE_DONT_KNOW = 0,
	DEVICE_TYPE_WIRED_ETHERNET,
	DEVICE_TYPE_WIRELESS_ETHERNET
} NMDeviceType;


/*
 * Encryption key types
 */
typedef enum NMEncKeyType
{
	NM_ENC_TYPE_UNKNOWN = 0,
	NM_ENC_TYPE_NONE,
	NM_ENC_TYPE_HEX_KEY,
	NM_ENC_TYPE_ASCII_KEY,
	NM_ENC_TYPE_128_BIT_PASSPHRASE
	/* FIXME: WPA and 802.1x support */
} NMEncKeyType;


/*
 * Driver support levels
 */
typedef enum NMDriverSupportLevel
{
	NM_DRIVER_UNSUPPORTED = 0,
	NM_DRIVER_NO_CARRIER_DETECT,
	NM_DRIVER_NO_WIRELESS_SCAN,
	NM_DRIVER_FULLY_SUPPORTED
} NMDriverSupportLevel;


/*
 * Wireless network modes
 */
typedef enum NMNetworkMode
{
	NETWORK_MODE_UNKNOWN = 0,
	NETWORK_MODE_INFRA,
	NETWORK_MODE_ADHOC
} NMNetworkMode;


/*
 * Wireless network update types
 */
typedef enum
{
	NETWORK_STATUS_DISAPPEARED = 0,
	NETWORK_STATUS_APPEARED,
	NETWORK_STATUS_STRENGTH_CHANGED
} NMNetworkStatus;


/*
 * Wireless network types
 */
typedef enum NMNetworkType
{
	NETWORK_TYPE_UNKNOWN = 0,
	NETWORK_TYPE_ALLOWED,
	NETWORK_TYPE_INVALID,
	NETWORK_TYPE_DEVICE
} NMNetworkType;


/*
 * Authentication modes
 */
typedef enum NMDeviceAuthMethod
{
	NM_DEVICE_AUTH_METHOD_UNKNOWN = 0,
	NM_DEVICE_AUTH_METHOD_NONE,
	NM_DEVICE_AUTH_METHOD_OPEN_SYSTEM,
	NM_DEVICE_AUTH_METHOD_SHARED_KEY
} NMDeviceAuthMethod;


/*
 * VPN daemon states
 */
typedef enum NMVPNState
{
	NM_VPN_STATE_ERROR = 0,
	NM_VPN_STATE_INIT,
	NM_VPN_STATE_SHUTDOWN,
	NM_VPN_STATE_STARTING,
	NM_VPN_STATE_STARTED,
	NM_VPN_STATE_STOPPING,
	NM_VPN_STATE_STOPPED
} NMVPNState;


/*
 * Device activation stages
 */
typedef enum NMActStage
{
	NM_ACT_STAGE_UNKNOWN = 0,
	NM_ACT_STAGE_DEVICE_PREPARE,
	NM_ACT_STAGE_DEVICE_CONFIG,
	NM_ACT_STAGE_NEED_USER_KEY,
	NM_ACT_STAGE_IP_CONFIG_START,
	NM_ACT_STAGE_IP_CONFIG_GET,
	NM_ACT_STAGE_IP_CONFIG_COMMIT,
	NM_ACT_STAGE_ACTIVATED,
	NM_ACT_STAGE_FAILED,
	NM_ACT_STAGE_CANCELLED
} NMActStage;


#endif
