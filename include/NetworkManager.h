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
#define	NM_DBUS_INTERFACE_DEVICE	"org.freedesktop.NetworkManager.Device"
#define NM_DBUS_INTERFACE_DEVICE_WIRED "org.freedesktop.NetworkManager.Device.Wired"
#define NM_DBUS_INTERFACE_DEVICE_WIRELESS "org.freedesktop.NetworkManager.Device.Wireless"
#define NM_DBUS_PATH_ACCESS_POINT "/org/freedesktop/NetworkManager/AccessPoint"
#define NM_DBUS_INTERFACE_ACCESS_POINT "org.freedesktop.NetworkManager.AccessPoint"
#define NM_DBUS_INTERFACE_GSM_DEVICE "org.freedesktop.NetworkManager.Device.Gsm"
#define NM_DBUS_INTERFACE_CDMA_DEVICE "org.freedesktop.NetworkManager.Device.Cdma"

#define NM_DBUS_SERVICE_USER_SETTINGS     "org.freedesktop.NetworkManagerUserSettings"
#define NM_DBUS_SERVICE_SYSTEM_SETTINGS   "org.freedesktop.NetworkManagerSystemSettings"
#define NM_DBUS_IFACE_SETTINGS            "org.freedesktop.NetworkManagerSettings"
#define NM_DBUS_PATH_SETTINGS             "/org/freedesktop/NetworkManagerSettings"

#define NM_DBUS_IFACE_SETTINGS_CONNECTION "org.freedesktop.NetworkManagerSettings.Connection"
#define NM_DBUS_PATH_SETTINGS_CONNECTION  "/org/freedesktop/NetworkManagerSettings/Connection"
#define NM_DBUS_IFACE_SETTINGS_CONNECTION_SECRETS "org.freedesktop.NetworkManagerSettings.Connection.Secrets"

#define NMI_DBUS_USER_KEY_CANCELED_ERROR	"org.freedesktop.NetworkManagerInfo.CanceledError"


/*
 * Types of NetworkManager states
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
	DEVICE_TYPE_802_11_WIRELESS,
	DEVICE_TYPE_GSM,
	DEVICE_TYPE_CDMA
} NMDeviceType;


/*
 * General device capability bits
 *
 */
#define NM_DEVICE_CAP_NONE			0x00000000
#define NM_DEVICE_CAP_NM_SUPPORTED		0x00000001
#define NM_DEVICE_CAP_CARRIER_DETECT	0x00000002


/* 802.11 wireless device-specific capabilities */
#define NM_802_11_DEVICE_CAP_NONE			0x00000000
#define NM_802_11_DEVICE_CAP_CIPHER_WEP40	0x00000001
#define NM_802_11_DEVICE_CAP_CIPHER_WEP104	0x00000002
#define NM_802_11_DEVICE_CAP_CIPHER_TKIP	0x00000004
#define NM_802_11_DEVICE_CAP_CIPHER_CCMP	0x00000008
#define NM_802_11_DEVICE_CAP_WPA			0x00000010
#define NM_802_11_DEVICE_CAP_RSN			0x00000020


/*
 * 802.11 Access Point flags
 *
 */
#define NM_802_11_AP_FLAGS_NONE				0x00000000
#define NM_802_11_AP_FLAGS_PRIVACY			0x00000001

/*
 * 802.11 Access Point security flags
 *
 * These describe the current security requirements of the BSSID as extracted
 * from various pieces of beacon information, like beacon flags and various
 * information elements.
 */
#define NM_802_11_AP_SEC_NONE				0x00000000
#define NM_802_11_AP_SEC_PAIR_WEP40			0x00000001
#define NM_802_11_AP_SEC_PAIR_WEP104		0x00000002
#define NM_802_11_AP_SEC_PAIR_TKIP			0x00000004
#define NM_802_11_AP_SEC_PAIR_CCMP			0x00000008
#define NM_802_11_AP_SEC_GROUP_WEP40		0x00000010
#define NM_802_11_AP_SEC_GROUP_WEP104		0x00000020
#define NM_802_11_AP_SEC_GROUP_TKIP			0x00000040
#define NM_802_11_AP_SEC_GROUP_CCMP			0x00000080
#define NM_802_11_AP_SEC_KEY_MGMT_PSK		0x00000100
#define NM_802_11_AP_SEC_KEY_MGMT_802_1X	0x00000200


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
