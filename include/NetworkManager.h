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

#define	NMI_DBUS_SERVICE			"org.freedesktop.NetworkManagerInfo"
#define	NMI_DBUS_PATH				"/org/freedesktop/NetworkManagerInfo"
#define	NMI_DBUS_INTERFACE			"org.freedesktop.NetworkManagerInfo"


/*
 * Some common errors
 */
#define NM_DBUS_NO_DEVICES_ERROR		"org.freedesktop.NetworkManager.NoDevices"
#define NM_DBUS_NO_DIALUP_ERROR		"org.freedesktop.NetworkManager.NoDialup"
#define NM_DBUS_NO_NETWORKS_ERROR		"org.freedesktop.NetworkManager.NoNetworks"
#define NM_DBUS_NO_ACTIVE_DEVICE_ERROR	"org.freedesktop.NetworkManager.NoActiveDevice"
#define NM_DBUS_NO_ACTIVE_NET_ERROR	"org.freedesktop.NetworkManager.NoActiveNetwork"


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
	DEVICE_TYPE_UNKNOWN = 0,
	DEVICE_TYPE_802_3_ETHERNET,
	DEVICE_TYPE_802_11_WIRELESS
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
	/* FIXME: 802.1x support */
} NMEncKeyType;


/*
 * Device capability bits
 *
 */
#define NM_DEVICE_CAP_NONE			0x0000
#define NM_DEVICE_CAP_NM_SUPPORTED		0x0001
#define NM_DEVICE_CAP_CARRIER_DETECT	0x0002
#define NM_DEVICE_CAP_WIRELESS_SCAN	0x0004


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
