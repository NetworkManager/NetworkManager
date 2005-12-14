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
 * General device capability bits
 *
 */
#define NM_DEVICE_CAP_NONE			0x00000000
#define NM_DEVICE_CAP_NM_SUPPORTED		0x00000001
#define NM_DEVICE_CAP_CARRIER_DETECT	0x00000002
#define NM_DEVICE_CAP_WIRELESS_SCAN	0x00000004


/* 802.11 wireless-specific device capability bits */
#define NM_802_11_CAP_NONE				0x00000000
#define NM_802_11_CAP_KEY_MGMT_WPA			0x00000001
#define NM_802_11_CAP_KEY_MGMT_WPA_PSK		0x00000002
#define NM_802_11_CAP_KEY_MGMT_WPA2		0x00000004
#define NM_802_11_CAP_KEY_MGMT_WPA2_PSK		0x00000008
#define NM_802_11_CAP_KEY_MGMT_IEEE8021X	0x00000010
#define NM_802_11_CAP_KEY_MGMT_RESERVED1	0x00000020
#define NM_802_11_CAP_KEY_MGMT_RESERVED2	0x00000040
#define NM_802_11_CAP_KEY_MGMT_RESERVED3	0x00000080
#define NM_802_11_CAP_CIPHER_WEP40			0x00000100
#define NM_802_11_CAP_CIPHER_WEP104		0x00000200
#define NM_802_11_CAP_CIPHER_TKIP			0x00000400
#define NM_802_11_CAP_CIPHER_CCMP			0x00000800
#define NM_802_11_CAP_CIPHER_RESERVED1		0x00001000
#define NM_802_11_CAP_CIPHER_RESERVED2		0x00002000
#define NM_802_11_CAP_CIPHER_RESERVED3		0x00004000
#define NM_802_11_CAP_CIPHER_RESERVED4		0x00008000


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
