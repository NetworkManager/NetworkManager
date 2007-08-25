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
#define	NM_DBUS_PATH_DEVICE			"/org/freedesktop/NetworkManager/Device"
#define	NM_DBUS_INTERFACE_DEVICE	"org.freedesktop.NetworkManager.Device"
#define NM_DBUS_INTERFACE_DEVICE_WIRED "org.freedesktop.NetworkManager.Device.Wired"
#define NM_DBUS_INTERFACE_DEVICE_WIRELESS "org.freedesktop.NetworkManager.Device.Wireless"
#define NM_DBUS_PATH_ACCESS_POINT "/org/freedesktop/NetworkManager/AccessPoint"
#define NM_DBUS_INTERFACE_ACCESS_POINT "org.freedesktop.NetworkManager.AccessPoint"

#define NM_DBUS_PATH_CONNECTION_SETTINGS        "/org/freedesktop/NetworkManager/Settings/Connection"

#define	NMI_DBUS_SERVICE			"org.freedesktop.NetworkManagerInfo"
#define	NMI_DBUS_PATH				"/org/freedesktop/NetworkManagerInfo"
#define	NMI_DBUS_INTERFACE			"org.freedesktop.NetworkManagerInfo"


#define NMI_DBUS_USER_KEY_CANCELED_ERROR	"org.freedesktop.NetworkManagerInfo.CanceledError"


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
 * General device capability bits
 *
 */
#define NM_DEVICE_CAP_NONE			0x00000000
#define NM_DEVICE_CAP_NM_SUPPORTED		0x00000001
#define NM_DEVICE_CAP_CARRIER_DETECT	0x00000002


/* 802.11 wireless-specific device capability bits */
#define NM_802_11_CAP_NONE			0x00000000
#define NM_802_11_CAP_PROTO_NONE		0x00000001
#define NM_802_11_CAP_PROTO_WEP		0x00000002
#define NM_802_11_CAP_PROTO_WPA		0x00000004
#define NM_802_11_CAP_PROTO_WPA2		0x00000008
#define NM_802_11_CAP_RESERVED1		0x00000010
#define NM_802_11_CAP_RESERVED2		0x00000020
#define NM_802_11_CAP_KEY_MGMT_PSK		0x00000040
#define NM_802_11_CAP_KEY_MGMT_802_1X	0x00000080
#define NM_802_11_CAP_RESERVED3		0x00000100
#define NM_802_11_CAP_RESERVED4		0x00000200
#define NM_802_11_CAP_RESERVED5		0x00000400
#define NM_802_11_CAP_RESERVED6		0x00000800
#define NM_802_11_CAP_CIPHER_WEP40		0x00001000
#define NM_802_11_CAP_CIPHER_WEP104	0x00002000
#define NM_802_11_CAP_CIPHER_TKIP		0x00004000
#define NM_802_11_CAP_CIPHER_CCMP		0x00008000

/*
 * NM-supported Authentication Methods
 */
#define NM_AUTH_TYPE_WPA_PSK_AUTO		0x00000000
#define NM_AUTH_TYPE_NONE			0x00000001
#define NM_AUTH_TYPE_WEP40			0x00000002
#define NM_AUTH_TYPE_WPA_PSK_TKIP		0x00000004
#define NM_AUTH_TYPE_WPA_PSK_CCMP		0x00000008
#define NM_AUTH_TYPE_WEP104			0x00000010
#define NM_AUTH_TYPE_WPA_EAP			0x00000020
#define NM_AUTH_TYPE_LEAP			0x00000040

/*
 * EAP Methods
 */
#define NM_EAP_METHOD_MD5			0x00000001	/* EAP-MD5 */
#define NM_EAP_METHOD_MSCHAP			0x00000002	/* EAP-MSCHAPv2 */
#define NM_EAP_METHOD_OTP			0x00000004	/* EAP-OTP */
#define NM_EAP_METHOD_GTC			0x00000008	/* EAP-GTC */
#define NM_EAP_METHOD_PEAP			0x00000010	/* EAP-PEAP */
#define NM_EAP_METHOD_TLS			0x00000020	/* EAP-TLS */
#define NM_EAP_METHOD_TTLS			0x00000040	/* EAP-TTLS */

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
 * Device states. Will obsolete NMActStage soon.
 */
typedef enum
{
	NM_DEVICE_STATE_UNKNOWN = 0,
	NM_DEVICE_STATE_DOWN,
	NM_DEVICE_STATE_DISCONNECTED,
	NM_DEVICE_STATE_PREPARE,
	NM_DEVICE_STATE_CONFIG,
	NM_DEVICE_STATE_NEED_AUTH,
	NM_DEVICE_STATE_IP_CONFIG,
	NM_DEVICE_STATE_ACTIVATED,
	NM_DEVICE_STATE_FAILED,
	NM_DEVICE_STATE_CANCELLED,
} NMDeviceState;


#endif /* NETWORK_MANAGER_H */
