/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * (C) Copyright 2004 - 2011 Red Hat, Inc.
 */

#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include "nm-version.h"

/*
 * dbus services details
 */
#define	NM_DBUS_SERVICE                     "org.freedesktop.NetworkManager"

#define	NM_DBUS_PATH                        "/org/freedesktop/NetworkManager"
#define	NM_DBUS_INTERFACE                   "org.freedesktop.NetworkManager"
#define	NM_DBUS_INTERFACE_DEVICE            NM_DBUS_INTERFACE ".Device"
#define NM_DBUS_INTERFACE_DEVICE_WIRED      NM_DBUS_INTERFACE_DEVICE ".Wired"
#define NM_DBUS_INTERFACE_DEVICE_WIRELESS   NM_DBUS_INTERFACE_DEVICE ".Wireless"
#define NM_DBUS_INTERFACE_DEVICE_BLUETOOTH  NM_DBUS_INTERFACE_DEVICE ".Bluetooth"
#define NM_DBUS_PATH_ACCESS_POINT           NM_DBUS_PATH "/AccessPoint"
#define NM_DBUS_INTERFACE_ACCESS_POINT      NM_DBUS_INTERFACE ".AccessPoint"
#define NM_DBUS_INTERFACE_DEVICE_MODEM      NM_DBUS_INTERFACE_DEVICE ".Modem"
#define NM_DBUS_INTERFACE_DEVICE_WIMAX      NM_DBUS_INTERFACE_DEVICE ".WiMax"
#define NM_DBUS_INTERFACE_WIMAX_NSP         NM_DBUS_INTERFACE ".WiMax.Nsp"
#define NM_DBUS_PATH_WIMAX_NSP              NM_DBUS_PATH "/Nsp"
#define NM_DBUS_INTERFACE_ACTIVE_CONNECTION NM_DBUS_INTERFACE ".Connection.Active"
#define NM_DBUS_INTERFACE_IP4_CONFIG        NM_DBUS_INTERFACE ".IP4Config"
#define NM_DBUS_INTERFACE_DHCP4_CONFIG      NM_DBUS_INTERFACE ".DHCP4Config"
#define NM_DBUS_INTERFACE_IP6_CONFIG        NM_DBUS_INTERFACE ".IP6Config"
#define NM_DBUS_INTERFACE_DHCP6_CONFIG      NM_DBUS_INTERFACE ".DHCP6Config"


#define NM_DBUS_IFACE_SETTINGS            "org.freedesktop.NetworkManager.Settings"
#define NM_DBUS_PATH_SETTINGS             "/org/freedesktop/NetworkManager/Settings"

#define NM_DBUS_IFACE_SETTINGS_CONNECTION "org.freedesktop.NetworkManager.Settings.Connection"
#define NM_DBUS_PATH_SETTINGS_CONNECTION  "/org/freedesktop/NetworkManager/Settings/Connection"
#define NM_DBUS_IFACE_SETTINGS_CONNECTION_SECRETS "org.freedesktop.NetworkManager.Settings.Connection.Secrets"

#define NM_DBUS_INTERFACE_AGENT_MANAGER   NM_DBUS_INTERFACE ".AgentManager"
#define NM_DBUS_PATH_AGENT_MANAGER        "/org/freedesktop/NetworkManager/AgentManager"

#define NM_DBUS_INTERFACE_SECRET_AGENT    NM_DBUS_INTERFACE ".SecretAgent"
#define NM_DBUS_PATH_SECRET_AGENT         "/org/freedesktop/NetworkManager/SecretAgent"

/**
 * NMState:
 * @NM_STATE_UNKNOWN: networking state is unknown
 * @NM_STATE_ASLEEP: networking is not enabled
 * @NM_STATE_DISCONNECTED: there is no active network connection
 * @NM_STATE_DISCONNECTING: network connections are being cleaned up
 * @NM_STATE_CONNECTING: a network connection is being started
 * @NM_STATE_CONNECTED_LOCAL: there is only local IPv4 and/or IPv6 connectivity
 * @NM_STATE_CONNECTED_SITE: there is only site-wide IPv4 and/or IPv6 connectivity
 * @NM_STATE_CONNECTED_GLOBAL: there is global IPv4 and/or IPv6 Internet connectivity
 *
 * #NMState values indicate the current overall networking state.
 */
typedef enum {
	NM_STATE_UNKNOWN          = 0,
	NM_STATE_ASLEEP           = 10,
	NM_STATE_DISCONNECTED     = 20,
	NM_STATE_DISCONNECTING    = 30,
	NM_STATE_CONNECTING       = 40,
	NM_STATE_CONNECTED_LOCAL  = 50,
	NM_STATE_CONNECTED_SITE   = 60,
	NM_STATE_CONNECTED_GLOBAL = 70
} NMState;

/* For backwards compat */
#define NM_STATE_CONNECTED NM_STATE_CONNECTED_GLOBAL

/**
 * NMDeviceType:
 * @NM_DEVICE_TYPE_UNKNOWN: unknown device
 * @NM_DEVICE_TYPE_ETHERNET: a wired ethernet device
 * @NM_DEVICE_TYPE_WIFI: an 802.11 WiFi device
 * @NM_DEVICE_TYPE_UNUSED1: not used
 * @NM_DEVICE_TYPE_UNUSED2: not used
 * @NM_DEVICE_TYPE_BT: a Bluetooth device supporting PAN or DUN access protocols
 * @NM_DEVICE_TYPE_OLPC_MESH: an OLPC XO mesh networking device
 * @NM_DEVICE_TYPE_WIMAX: an 802.16e Mobile WiMAX broadband device
 * @NM_DEVICE_TYPE_MODEM: a modem supporting analog telephone, CDMA/EVDO,
 * GSM/UMTS, or LTE network access protocols
 *
 * #NMState values indicate the current overall networking state.
 */
typedef enum {
	NM_DEVICE_TYPE_UNKNOWN   = 0,
	NM_DEVICE_TYPE_ETHERNET  = 1,
	NM_DEVICE_TYPE_WIFI      = 2,
	NM_DEVICE_TYPE_UNUSED1   = 3,
	NM_DEVICE_TYPE_UNUSED2   = 4,
	NM_DEVICE_TYPE_BT        = 5,  /* Bluetooth */
	NM_DEVICE_TYPE_OLPC_MESH = 6,
	NM_DEVICE_TYPE_WIMAX     = 7,
	NM_DEVICE_TYPE_MODEM     = 8,
} NMDeviceType;

/* General device capability flags */
typedef enum {
	NM_DEVICE_CAP_NONE           = 0x00000000,
	NM_DEVICE_CAP_NM_SUPPORTED   = 0x00000001,
	NM_DEVICE_CAP_CARRIER_DETECT = 0x00000002
} NMDeviceCapabilities;


/* 802.11 Wifi device capabilities */
typedef enum {
	NM_WIFI_DEVICE_CAP_NONE          = 0x00000000,
	NM_WIFI_DEVICE_CAP_CIPHER_WEP40  = 0x00000001,
	NM_WIFI_DEVICE_CAP_CIPHER_WEP104 = 0x00000002,
	NM_WIFI_DEVICE_CAP_CIPHER_TKIP   = 0x00000004,
	NM_WIFI_DEVICE_CAP_CIPHER_CCMP   = 0x00000008,
	NM_WIFI_DEVICE_CAP_WPA           = 0x00000010,
	NM_WIFI_DEVICE_CAP_RSN           = 0x00000020
} NMDeviceWifiCapabilities;


/* 802.11 Access Point flags */
typedef enum {
	/*< flags >*/
	NM_802_11_AP_FLAGS_NONE    = 0x00000000,
	NM_802_11_AP_FLAGS_PRIVACY = 0x00000001
} NM80211ApFlags;

/*
 * 802.11 Access Point security flags
 *
 * These describe the current security requirements of the BSSID as extracted
 * from various pieces of beacon information, like beacon flags and various
 * information elements.
 */
typedef enum {
	/*< flags >*/
	NM_802_11_AP_SEC_NONE            = 0x00000000,
	NM_802_11_AP_SEC_PAIR_WEP40      = 0x00000001,
	NM_802_11_AP_SEC_PAIR_WEP104     = 0x00000002,
	NM_802_11_AP_SEC_PAIR_TKIP       = 0x00000004,
	NM_802_11_AP_SEC_PAIR_CCMP       = 0x00000008,
	NM_802_11_AP_SEC_GROUP_WEP40     = 0x00000010,
	NM_802_11_AP_SEC_GROUP_WEP104    = 0x00000020,
	NM_802_11_AP_SEC_GROUP_TKIP      = 0x00000040,
	NM_802_11_AP_SEC_GROUP_CCMP      = 0x00000080,
	NM_802_11_AP_SEC_KEY_MGMT_PSK    = 0x00000100,
	NM_802_11_AP_SEC_KEY_MGMT_802_1X = 0x00000200
} NM80211ApSecurityFlags;

/*
 * 802.11 AP and Station modes
 *
 */
typedef enum {
	NM_802_11_MODE_UNKNOWN = 0,
	NM_802_11_MODE_ADHOC,
	NM_802_11_MODE_INFRA
} NM80211Mode;

/**
 * NMBluetoothCapabilities:
 * @NM_BT_CAPABILITY_NONE: device has no usable capabilities
 * @NM_BT_CAPABILITY_DUN: device provides Dial-Up Networking capability
 * @NM_BT_CAPABILITY_NAP: device provides Network Access Point capability
 *
 * #NMBluetoothCapabilities values indicate the usable capabilities of a
 * Bluetooth device.
 */
typedef enum {
	/*< flags >*/
	NM_BT_CAPABILITY_NONE = 0x00000000,
	NM_BT_CAPABILITY_DUN  = 0x00000001,
	NM_BT_CAPABILITY_NAP  = 0x00000002,
} NMBluetoothCapabilities;

/**
 * NMDeviceModemCapabilities:
 * @NM_DEVICE_MODEM_CAPABILITY_NONE: modem has no usable capabilities
 * @NM_DEVICE_MODEM_CAPABILITY_POTS: modem uses the analog wired telephone
 * network and is not a wireless/cellular device
 * @NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO: modem supports at least one of CDMA
 * 1xRTT, EVDO revision 0, EVDO revision A, or EVDO revision B
 * @NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS: modem supports at least one of GSM,
 * GPRS, EDGE, UMTS, HSDPA, HSUPA, or HSPA+ packet switched data capability
 * @NM_DEVICE_MODEM_CAPABILITY_LTE: modem has LTE data capability
 *
 * #NMDeviceModemCapabilities values indicate the generic radio access
 * technology families a modem device supports.  For more information on the
 * specific access technologies the device supports use the ModemManager D-Bus
 * API.
 */
typedef enum {
	/*< flags >*/
	NM_DEVICE_MODEM_CAPABILITY_NONE      = 0x00000000,
	NM_DEVICE_MODEM_CAPABILITY_POTS      = 0x00000001,
	NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO = 0x00000002,
	NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS  = 0x00000004,
	NM_DEVICE_MODEM_CAPABILITY_LTE       = 0x00000008,
} NMDeviceModemCapabilities;


/**
 * NMDeviceState:
 * @NM_DEVICE_STATE_UNKNOWN: the device's state is unknown
 * @NM_DEVICE_STATE_UNMANAGED: the device is recognized, but not managed by
 *   NetworkManager
 * @NM_DEVICE_STATE_UNAVAILABLE: the device is managed by NetworkManager, but
 *   is not available for use.  Reasons may include the wireless switched off,
 *   missing firmware, no ethernet carrier, missing supplicant or modem manager,
 *   etc.
 * @NM_DEVICE_STATE_DISCONNECTED: the device can be activated, but is currently
 *   idle and not connected to a network.
 * @NM_DEVICE_STATE_PREPARE: the device is preparing the connection to the
 *   network.  This may include operations like changing the MAC address,
 *   setting physical link properties, and anything else required to connect
 *   to the requested network.
 * @NM_DEVICE_STATE_CONFIG: the device is connecting to the requested network.
 *   This may include operations like associating with the WiFi AP, dialing
 *   the modem, connecting to the remote Bluetooth device, etc.
 * @NM_DEVICE_STATE_NEED_AUTH: the device requires more information to continue
 *   connecting to the requested network.  This includes secrets like WiFi
 *   passphrases, login passwords, PIN codes, etc.
 * @NM_DEVICE_STATE_IP_CONFIG: the device is requesting IPv4 and/or IPv6
 *   addresses and routing information from the network.
 * @NM_DEVICE_STATE_IP_CHECK: the device is checking whether further action is
 *   required for the requested network connection.  This may include checking
 *   whether only local network access is available, whether a captive portal
 *   is blocking access to the Internet, etc.
 * @NM_DEVICE_STATE_SECONDARIES: the device is waiting for a secondary
 *   connection (like a VPN) which must activated before the device can be
 *   activated
 * @NM_DEVICE_STATE_ACTIVATED: the device has a network connection, either local
 *   or global.
 * @NM_DEVICE_STATE_DEACTIVATING: a disconnection from the current network
 *   connection was requested, and the device is cleaning up resources used for
 *   that connection.  The network connection may still be valid.
 * @NM_DEVICE_STATE_FAILED: the device failed to connect to the requested
 *   network and is cleaning up the connection request
 *
 **/
typedef enum {
	NM_DEVICE_STATE_UNKNOWN      = 0,
	NM_DEVICE_STATE_UNMANAGED    = 10,
	NM_DEVICE_STATE_UNAVAILABLE  = 20,
	NM_DEVICE_STATE_DISCONNECTED = 30,
	NM_DEVICE_STATE_PREPARE      = 40,
	NM_DEVICE_STATE_CONFIG       = 50,
	NM_DEVICE_STATE_NEED_AUTH    = 60,
	NM_DEVICE_STATE_IP_CONFIG    = 70,
	NM_DEVICE_STATE_IP_CHECK     = 80,
	NM_DEVICE_STATE_SECONDARIES  = 90,
	NM_DEVICE_STATE_ACTIVATED    = 100,
	NM_DEVICE_STATE_DEACTIVATING = 110,
	NM_DEVICE_STATE_FAILED       = 120
} NMDeviceState;


/*
 * Device state change reason codes
 */
typedef enum {
	/* No reason given */
	NM_DEVICE_STATE_REASON_NONE = 0,

	/* Unknown error */
	NM_DEVICE_STATE_REASON_UNKNOWN = 1,

	/* Device is now managed */
	NM_DEVICE_STATE_REASON_NOW_MANAGED = 2,

	/* Device is now unmanaged */
	NM_DEVICE_STATE_REASON_NOW_UNMANAGED = 3,

	/* The device could not be readied for configuration */
	NM_DEVICE_STATE_REASON_CONFIG_FAILED = 4,

	/* IP configuration could not be reserved (no available address, timeout, etc) */
	NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE = 5,

	/* The IP config is no longer valid */
	NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED = 6,

	/* Secrets were required, but not provided */
	NM_DEVICE_STATE_REASON_NO_SECRETS = 7,

	/* 802.1x supplicant disconnected */
	NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT = 8,

	/* 802.1x supplicant configuration failed */
	NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED = 9,

	/* 802.1x supplicant failed */
	NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED = 10,

	/* 802.1x supplicant took too long to authenticate */
	NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT = 11,

	/* PPP service failed to start */
	NM_DEVICE_STATE_REASON_PPP_START_FAILED = 12,

	/* PPP service disconnected */
	NM_DEVICE_STATE_REASON_PPP_DISCONNECT = 13,

	/* PPP failed */
	NM_DEVICE_STATE_REASON_PPP_FAILED = 14,

	/* DHCP client failed to start */
	NM_DEVICE_STATE_REASON_DHCP_START_FAILED = 15,

	/* DHCP client error */
	NM_DEVICE_STATE_REASON_DHCP_ERROR = 16,

	/* DHCP client failed */
	NM_DEVICE_STATE_REASON_DHCP_FAILED = 17,

	/* Shared connection service failed to start */
	NM_DEVICE_STATE_REASON_SHARED_START_FAILED = 18,

	/* Shared connection service failed */
	NM_DEVICE_STATE_REASON_SHARED_FAILED = 19,

	/* AutoIP service failed to start */
	NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED = 20,

	/* AutoIP service error */
	NM_DEVICE_STATE_REASON_AUTOIP_ERROR = 21,

	/* AutoIP service failed */
	NM_DEVICE_STATE_REASON_AUTOIP_FAILED = 22,

	/* The line is busy */
	NM_DEVICE_STATE_REASON_MODEM_BUSY = 23,

	/* No dial tone */
	NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE = 24,

	/* No carrier could be established */
	NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER = 25,

	/* The dialing request timed out */
	NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT = 26,

	/* The dialing attempt failed */
	NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED = 27,

	/* Modem initialization failed */
	NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED = 28,

	/* Failed to select the specified APN */
	NM_DEVICE_STATE_REASON_GSM_APN_FAILED = 29,

	/* Not searching for networks */
	NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING = 30,

	/* Network registration denied */
	NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED = 31,

	/* Network registration timed out */
	NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT = 32,

	/* Failed to register with the requested network */
	NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED = 33,

	/* PIN check failed */
	NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED = 34,

	/* Necessary firmware for the device may be missing */
	NM_DEVICE_STATE_REASON_FIRMWARE_MISSING = 35,

	/* The device was removed */
	NM_DEVICE_STATE_REASON_REMOVED = 36,

	/* NetworkManager went to sleep */
	NM_DEVICE_STATE_REASON_SLEEPING = 37,

	/* The device's active connection disappeared */
	NM_DEVICE_STATE_REASON_CONNECTION_REMOVED = 38,

	/* Device disconnected by user or client */
	NM_DEVICE_STATE_REASON_USER_REQUESTED = 39,

	/* Carrier/link changed */
	NM_DEVICE_STATE_REASON_CARRIER = 40,

	/* The device's existing connection was assumed */
	NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED = 41,

	/* The supplicant is now available */
	NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE = 42,

	/* The modem could not be found */
	NM_DEVICE_STATE_REASON_MODEM_NOT_FOUND = 43,

	/* The Bluetooth connection failed or timed out */
	NM_DEVICE_STATE_REASON_BT_FAILED = 44,

	/* Unused */
	NM_DEVICE_STATE_REASON_LAST = 0xFFFF
} NMDeviceStateReason;


/**
 * NMActiveConnectionState:
 * @NM_ACTIVE_CONNECTION_STATE_UNKNOWN: the state of the connection is unknown
 * @NM_ACTIVE_CONNECTION_STATE_ACTIVATING: a network connection is being prepared
 * @NM_ACTIVE_CONNECTION_STATE_ACTIVATED: there is a connection to the network
 * @NM_ACTIVE_CONNECTION_STATE_DEACTIVATING: the network connection is being
 *   torn down and cleaned up
 *
 * #NMActiveConnectionState values indicate the state of a connection to a
 * specific network while it is starting, connected, or disconnecting from that
 * network.
 */
typedef enum {
	NM_ACTIVE_CONNECTION_STATE_UNKNOWN = 0,
	NM_ACTIVE_CONNECTION_STATE_ACTIVATING,
	NM_ACTIVE_CONNECTION_STATE_ACTIVATED,
	NM_ACTIVE_CONNECTION_STATE_DEACTIVATING
} NMActiveConnectionState;

#endif /* NETWORK_MANAGER_H */

