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
#define NM_DBUS_NO_ACTIVE_NET_ERROR	"org.freedesktop.NetworkManager.NoActiveNetwork"
#define NM_DBUS_NO_ACTIVE_DEVICE_ERROR	"org.freedesktop.NetworkManager.NoActiveDevice"
#define NM_DBUS_NO_NETWORKS_ERROR		"org.freedesktop.NetworkManager.NoNetworks"


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
 * Info-daemon specific preference locations
 */
#define NMI_GCONF_WIRELESS_NETWORKS_PATH		"/system/networking/wireless/networks"

#endif
