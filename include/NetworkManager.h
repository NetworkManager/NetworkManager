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

#define NMI_DBUS_USER_KEY_CANCELED_ERROR	"org.freedesktop.NetworkManagerInfo.CanceledError"


/*
 * NetworkManager signals
 */
#define NM_DBUS_SIGNAL_STATE_CHANGE	"StateChange"


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
#define NM_DEVICE_CAP_WIRELESS_SCAN	0x00000004


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
 * EAP Method in libnm-util is a bitfield of (EAP Method) | (Phase2 Method)
 */

#define NM_EAP_METHOD_MASK			0x0000ffff
#define NM_PHASE2_METHOD_MASK			0xffff0000

#define NM_EAP_TO_EAP_METHOD(eap)    (eap & NM_EAP_METHOD_MASK)
#define NM_EAP_TO_PHASE2_METHOD(eap) (eap & NM_PHASE2_METHOD_MASK)

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
 * Phase2 Methods
 */
#define NM_PHASE2_AUTH_NONE			0x00000000
#define NM_PHASE2_AUTH_PAP			0x00010000
#define NM_PHASE2_AUTH_MSCHAP			0x00020000
#define NM_PHASE2_AUTH_MSCHAPV2		0x00030000
#define NM_PHASE2_AUTH_GTC			0x00040000


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
