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
 * Copyright 2004 - 2014 Red Hat, Inc.
 */

/* Definitions related to NetworkManager's D-Bus interfaces.
 *
 * Note that although this header is installed as part of libnm, it is also
 * used by some external code that does not link to libnm.
 */

#ifndef __NM_DBUS_INTERFACE_H__
#define __NM_DBUS_INTERFACE_H__

#ifndef NM_VERSION_H
#define NM_AVAILABLE_IN_1_2
#endif

/*
 * dbus services details
 */
#define NM_DBUS_SERVICE                     "org.freedesktop.NetworkManager"

#define NM_DBUS_PATH                        "/org/freedesktop/NetworkManager"
#define NM_DBUS_INTERFACE                   "org.freedesktop.NetworkManager"
#define NM_DBUS_INTERFACE_DEVICE            NM_DBUS_INTERFACE ".Device"
#define NM_DBUS_INTERFACE_DEVICE_WIRED      NM_DBUS_INTERFACE_DEVICE ".Wired"
#define NM_DBUS_INTERFACE_DEVICE_ADSL       NM_DBUS_INTERFACE_DEVICE ".Adsl"
#define NM_DBUS_INTERFACE_DEVICE_WIRELESS   NM_DBUS_INTERFACE_DEVICE ".Wireless"
#define NM_DBUS_INTERFACE_DEVICE_BLUETOOTH  NM_DBUS_INTERFACE_DEVICE ".Bluetooth"
#define NM_DBUS_INTERFACE_DEVICE_OLPC_MESH  NM_DBUS_INTERFACE_DEVICE ".OlpcMesh"
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
#define NM_DBUS_INTERFACE_DEVICE_INFINIBAND NM_DBUS_INTERFACE_DEVICE ".Infiniband"
#define NM_DBUS_INTERFACE_DEVICE_BOND       NM_DBUS_INTERFACE_DEVICE ".Bond"
#define NM_DBUS_INTERFACE_DEVICE_TEAM       NM_DBUS_INTERFACE_DEVICE ".Team"
#define NM_DBUS_INTERFACE_DEVICE_VLAN       NM_DBUS_INTERFACE_DEVICE ".Vlan"
#define NM_DBUS_INTERFACE_DEVICE_BRIDGE     NM_DBUS_INTERFACE_DEVICE ".Bridge"
#define NM_DBUS_INTERFACE_DEVICE_GENERIC    NM_DBUS_INTERFACE_DEVICE ".Generic"
#define NM_DBUS_INTERFACE_DEVICE_VETH       NM_DBUS_INTERFACE_DEVICE ".Veth"
#define NM_DBUS_INTERFACE_DEVICE_TUN        NM_DBUS_INTERFACE_DEVICE ".Tun"
#define NM_DBUS_INTERFACE_DEVICE_MACVLAN    NM_DBUS_INTERFACE_DEVICE ".Macvlan"
#define NM_DBUS_INTERFACE_DEVICE_VXLAN      NM_DBUS_INTERFACE_DEVICE ".Vxlan"
#define NM_DBUS_INTERFACE_DEVICE_GRE        NM_DBUS_INTERFACE_DEVICE ".Gre"


#define NM_DBUS_INTERFACE_SETTINGS        "org.freedesktop.NetworkManager.Settings"
#define NM_DBUS_PATH_SETTINGS             "/org/freedesktop/NetworkManager/Settings"

#define NM_DBUS_INTERFACE_SETTINGS_CONNECTION "org.freedesktop.NetworkManager.Settings.Connection"
#define NM_DBUS_PATH_SETTINGS_CONNECTION  "/org/freedesktop/NetworkManager/Settings/Connection"
#define NM_DBUS_INTERFACE_SETTINGS_CONNECTION_SECRETS "org.freedesktop.NetworkManager.Settings.Connection.Secrets"

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
 *
 * (Corresponds to the NM_STATE type in nm-manager.xml.)
 **/
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

/**
 * NMConnectivityState:
 * @NM_CONNECTIVITY_UNKNOWN: Network connectivity is unknown.
 * @NM_CONNECTIVITY_NONE: The host is not connected to any network.
 * @NM_CONNECTIVITY_PORTAL: The host is behind a captive portal and
 *   cannot reach the full Internet.
 * @NM_CONNECTIVITY_LIMITED: The host is connected to a network, but
 *   does not appear to be able to reach the full Internet.
 * @NM_CONNECTIVITY_FULL: The host is connected to a network, and
 *   appears to be able to reach the full Internet.
 *
 * (Corresponds to the NM_CONNECTIVITY type in nm-manager.xml.)
 */
typedef enum {
	NM_CONNECTIVITY_UNKNOWN,
	NM_CONNECTIVITY_NONE,
	NM_CONNECTIVITY_PORTAL,
	NM_CONNECTIVITY_LIMITED,
	NM_CONNECTIVITY_FULL
} NMConnectivityState;

/**
 * NMDeviceType:
 * @NM_DEVICE_TYPE_UNKNOWN: unknown device
 * @NM_DEVICE_TYPE_GENERIC: generic support for unrecognized device types
 * @NM_DEVICE_TYPE_ETHERNET: a wired ethernet device
 * @NM_DEVICE_TYPE_WIFI: an 802.11 WiFi device
 * @NM_DEVICE_TYPE_UNUSED1: not used
 * @NM_DEVICE_TYPE_UNUSED2: not used
 * @NM_DEVICE_TYPE_BT: a Bluetooth device supporting PAN or DUN access protocols
 * @NM_DEVICE_TYPE_OLPC_MESH: an OLPC XO mesh networking device
 * @NM_DEVICE_TYPE_WIMAX: an 802.16e Mobile WiMAX broadband device
 * @NM_DEVICE_TYPE_MODEM: a modem supporting analog telephone, CDMA/EVDO,
 * GSM/UMTS, or LTE network access protocols
 * @NM_DEVICE_TYPE_INFINIBAND: an IP-over-InfiniBand device
 * @NM_DEVICE_TYPE_BOND: a bond master interface
 * @NM_DEVICE_TYPE_VLAN: an 802.1Q VLAN interface
 * @NM_DEVICE_TYPE_ADSL: ADSL modem
 * @NM_DEVICE_TYPE_BRIDGE: a bridge master interface
 * @NM_DEVICE_TYPE_TEAM: a team master interface
 *
 * #NMDeviceType values indicate the type of hardware represented by
 * an #NMDevice.
 *
 * (Corresponds to the NM_DEVICE_TYPE type in nm-device.xml.)
 **/
typedef enum {
	NM_DEVICE_TYPE_UNKNOWN    = 0,
	NM_DEVICE_TYPE_ETHERNET   = 1,
	NM_DEVICE_TYPE_WIFI       = 2,
	NM_DEVICE_TYPE_UNUSED1    = 3,
	NM_DEVICE_TYPE_UNUSED2    = 4,
	NM_DEVICE_TYPE_BT         = 5,  /* Bluetooth */
	NM_DEVICE_TYPE_OLPC_MESH  = 6,
	NM_DEVICE_TYPE_WIMAX      = 7,
	NM_DEVICE_TYPE_MODEM      = 8,
	NM_DEVICE_TYPE_INFINIBAND = 9,
	NM_DEVICE_TYPE_BOND       = 10,
	NM_DEVICE_TYPE_VLAN       = 11,
	NM_DEVICE_TYPE_ADSL       = 12,
	NM_DEVICE_TYPE_BRIDGE     = 13,
	NM_DEVICE_TYPE_GENERIC    = 14,
	NM_DEVICE_TYPE_TEAM       = 15,
} NMDeviceType;

/**
 * NMDeviceCapabilities:
 * @NM_DEVICE_CAP_NONE: device has no special capabilities
 * @NM_DEVICE_CAP_NM_SUPPORTED: NetworkManager supports this device
 * @NM_DEVICE_CAP_CARRIER_DETECT: this device can indicate carrier status
 * @NM_DEVICE_CAP_IS_SOFTWARE: this device is a software device
 *
 * General device capability flags.
 *
 * (Corresponds to the NM_DEVICE_CAP type in nm-device-wifi.xml.)
 **/
typedef enum { /*< flags >*/
	NM_DEVICE_CAP_NONE           = 0x00000000,
	NM_DEVICE_CAP_NM_SUPPORTED   = 0x00000001,
	NM_DEVICE_CAP_CARRIER_DETECT = 0x00000002,
	NM_DEVICE_CAP_IS_SOFTWARE    = 0x00000004,
} NMDeviceCapabilities;


/**
 * NMDeviceWifiCapabilities:
 * @NM_WIFI_DEVICE_CAP_NONE: device has no encryption/authentication capabilities
 * @NM_WIFI_DEVICE_CAP_CIPHER_WEP40: device supports 40/64-bit WEP encryption
 * @NM_WIFI_DEVICE_CAP_CIPHER_WEP104: device supports 104/128-bit WEP encryption
 * @NM_WIFI_DEVICE_CAP_CIPHER_TKIP: device supports TKIP encryption
 * @NM_WIFI_DEVICE_CAP_CIPHER_CCMP: device supports AES/CCMP encryption
 * @NM_WIFI_DEVICE_CAP_WPA: device supports WPA1 authentication
 * @NM_WIFI_DEVICE_CAP_RSN: device supports WPA2/RSN authentication
 * @NM_WIFI_DEVICE_CAP_AP: device supports Access Point mode
 * @NM_WIFI_DEVICE_CAP_ADHOC: device supports Ad-Hoc mode
 * @NM_WIFI_DEVICE_CAP_FREQ_VALID: device reports frequency capabilities
 * @NM_WIFI_DEVICE_CAP_FREQ_2GHZ: device supports 2.4GHz frequencies
 * @NM_WIFI_DEVICE_CAP_FREQ_5GHZ: device supports 5GHz frequencies
 *
 * 802.11 specific device encryption and authentication capabilities.
 *
 * (Corresponds to the NM_802_11_DEVICE_CAP type in nm-device-wifi.xml.)
 **/
typedef enum { /*< flags >*/
	NM_WIFI_DEVICE_CAP_NONE          = 0x00000000,
	NM_WIFI_DEVICE_CAP_CIPHER_WEP40  = 0x00000001,
	NM_WIFI_DEVICE_CAP_CIPHER_WEP104 = 0x00000002,
	NM_WIFI_DEVICE_CAP_CIPHER_TKIP   = 0x00000004,
	NM_WIFI_DEVICE_CAP_CIPHER_CCMP   = 0x00000008,
	NM_WIFI_DEVICE_CAP_WPA           = 0x00000010,
	NM_WIFI_DEVICE_CAP_RSN           = 0x00000020,
	NM_WIFI_DEVICE_CAP_AP            = 0x00000040,
	NM_WIFI_DEVICE_CAP_ADHOC         = 0x00000080,
	NM_WIFI_DEVICE_CAP_FREQ_VALID    = 0x00000100,
	NM_WIFI_DEVICE_CAP_FREQ_2GHZ     = 0x00000200,
	NM_WIFI_DEVICE_CAP_FREQ_5GHZ     = 0x00000400,
} NMDeviceWifiCapabilities;


/**
 * NM80211ApFlags:
 * @NM_802_11_AP_FLAGS_NONE: access point has no special capabilities
 * @NM_802_11_AP_FLAGS_PRIVACY: access point requires authentication and
 * encryption (usually means WEP)
 *
 * 802.11 access point flags.
 *
 * (Corresponds to the NM_802_11_AP_FLAGS type in nm-access-point.xml.)
 **/
typedef enum { /*< underscore_name=nm_802_11_ap_flags, flags >*/
	NM_802_11_AP_FLAGS_NONE    = 0x00000000,
	NM_802_11_AP_FLAGS_PRIVACY = 0x00000001
} NM80211ApFlags;

/**
 * NM80211ApSecurityFlags:
 * @NM_802_11_AP_SEC_NONE: the access point has no special security requirements
 * @NM_802_11_AP_SEC_PAIR_WEP40: 40/64-bit WEP is supported for
 * pairwise/unicast encryption
 * @NM_802_11_AP_SEC_PAIR_WEP104: 104/128-bit WEP is supported for
 * pairwise/unicast encryption
 * @NM_802_11_AP_SEC_PAIR_TKIP: TKIP is supported for pairwise/unicast encryption
 * @NM_802_11_AP_SEC_PAIR_CCMP: AES/CCMP is supported for pairwise/unicast encryption
 * @NM_802_11_AP_SEC_GROUP_WEP40: 40/64-bit WEP is supported for group/broadcast
 * encryption
 * @NM_802_11_AP_SEC_GROUP_WEP104: 104/128-bit WEP is supported for
 * group/broadcast encryption
 * @NM_802_11_AP_SEC_GROUP_TKIP: TKIP is supported for group/broadcast encryption
 * @NM_802_11_AP_SEC_GROUP_CCMP: AES/CCMP is supported for group/broadcast
 * encryption
 * @NM_802_11_AP_SEC_KEY_MGMT_PSK: WPA/RSN Pre-Shared Key encryption is
 * supported
 * @NM_802_11_AP_SEC_KEY_MGMT_802_1X: 802.1x authentication and key management
 * is supported
 *
 * 802.11 access point security and authentication flags.  These flags describe
 * the current security requirements of an access point as determined from the
 * access point's beacon.
 *
 * (Corresponds to the NM_802_11_AP_SEC type in nm-access-point.xml.)
 **/
typedef enum { /*< underscore_name=nm_802_11_ap_security_flags, flags >*/
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

/**
 * NM80211Mode:
 * @NM_802_11_MODE_UNKNOWN: the device or access point mode is unknown
 * @NM_802_11_MODE_ADHOC: for both devices and access point objects, indicates
 *   the object is part of an Ad-Hoc 802.11 network without a central
 *   coordinating access point.
 * @NM_802_11_MODE_INFRA: the device or access point is in infrastructure mode.
 *   For devices, this indicates the device is an 802.11 client/station.  For
 *   access point objects, this indicates the object is an access point that
 *   provides connectivity to clients.
 * @NM_802_11_MODE_AP: the device is an access point/hotspot.  Not valid for
 *   access point objects; used only for hotspot mode on the local machine.
 *
 * Indicates the 802.11 mode an access point or device is currently in.
 *
 * (Corresponds to the NM_802_11_MODE type in generic-types.xml.)
 **/
typedef enum { /*< underscore_name=nm_802_11_mode >*/
	NM_802_11_MODE_UNKNOWN = 0,
	NM_802_11_MODE_ADHOC,
	NM_802_11_MODE_INFRA,
	NM_802_11_MODE_AP
} NM80211Mode;

/**
 * NMBluetoothCapabilities:
 * @NM_BT_CAPABILITY_NONE: device has no usable capabilities
 * @NM_BT_CAPABILITY_DUN: device provides Dial-Up Networking capability
 * @NM_BT_CAPABILITY_NAP: device provides Network Access Point capability
 *
 * #NMBluetoothCapabilities values indicate the usable capabilities of a
 * Bluetooth device.
 *
 * (Corresponds to the NM_BT_CAPABILITY type in nm-device-bt.xml.)
 **/
typedef enum { /*< flags >*/
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
 *
 * (Corresponds to the NM_DEVICE_MODEM_CAPABILITY type in nm-device-modem.xml.)
 **/
typedef enum { /*< flags >*/
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
 * (Corresponds to the NM_DEVICE_STATE type in nm-device.xml.)
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

/**
 * NMDeviceStateReason:
 * @NM_DEVICE_STATE_REASON_NONE: No reason given
 * @NM_DEVICE_STATE_REASON_UNKNOWN: Unknown error
 * @NM_DEVICE_STATE_REASON_NOW_MANAGED: Device is now managed
 * @NM_DEVICE_STATE_REASON_NOW_UNMANAGED: Device is now unmanaged
 * @NM_DEVICE_STATE_REASON_CONFIG_FAILED: The device could not be readied for configuration
 * @NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE: IP configuration could not be reserved (no available address, timeout, etc)
 * @NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED: The IP config is no longer valid
 * @NM_DEVICE_STATE_REASON_NO_SECRETS: Secrets were required, but not provided
 * @NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT: 802.1x supplicant disconnected
 * @NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED: 802.1x supplicant configuration failed
 * @NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED: 802.1x supplicant failed
 * @NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT: 802.1x supplicant took too long to authenticate
 * @NM_DEVICE_STATE_REASON_PPP_START_FAILED: PPP service failed to start
 * @NM_DEVICE_STATE_REASON_PPP_DISCONNECT: PPP service disconnected
 * @NM_DEVICE_STATE_REASON_PPP_FAILED: PPP failed
 * @NM_DEVICE_STATE_REASON_DHCP_START_FAILED: DHCP client failed to start
 * @NM_DEVICE_STATE_REASON_DHCP_ERROR: DHCP client error
 * @NM_DEVICE_STATE_REASON_DHCP_FAILED: DHCP client failed
 * @NM_DEVICE_STATE_REASON_SHARED_START_FAILED: Shared connection service failed to start
 * @NM_DEVICE_STATE_REASON_SHARED_FAILED: Shared connection service failed
 * @NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED: AutoIP service failed to start
 * @NM_DEVICE_STATE_REASON_AUTOIP_ERROR: AutoIP service error
 * @NM_DEVICE_STATE_REASON_AUTOIP_FAILED: AutoIP service failed
 * @NM_DEVICE_STATE_REASON_MODEM_BUSY: The line is busy
 * @NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE: No dial tone
 * @NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER: No carrier could be established
 * @NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT: The dialing request timed out
 * @NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED: The dialing attempt failed
 * @NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED: Modem initialization failed
 * @NM_DEVICE_STATE_REASON_GSM_APN_FAILED: Failed to select the specified APN
 * @NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING: Not searching for networks
 * @NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED: Network registration denied
 * @NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT: Network registration timed out
 * @NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED: Failed to register with the requested network
 * @NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED: PIN check failed
 * @NM_DEVICE_STATE_REASON_FIRMWARE_MISSING: Necessary firmware for the device may be missing
 * @NM_DEVICE_STATE_REASON_REMOVED: The device was removed
 * @NM_DEVICE_STATE_REASON_SLEEPING: NetworkManager went to sleep
 * @NM_DEVICE_STATE_REASON_CONNECTION_REMOVED: The device's active connection disappeared
 * @NM_DEVICE_STATE_REASON_USER_REQUESTED: Device disconnected by user or client
 * @NM_DEVICE_STATE_REASON_CARRIER: Carrier/link changed
 * @NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED: The device's existing connection was assumed
 * @NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE: The supplicant is now available
 * @NM_DEVICE_STATE_REASON_MODEM_NOT_FOUND: The modem could not be found
 * @NM_DEVICE_STATE_REASON_BT_FAILED: The Bluetooth connection failed or timed out
 * @NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED: GSM Modem's SIM Card not inserted
 * @NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED: GSM Modem's SIM Pin required
 * @NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED: GSM Modem's SIM Puk required
 * @NM_DEVICE_STATE_REASON_GSM_SIM_WRONG: GSM Modem's SIM wrong
 * @NM_DEVICE_STATE_REASON_INFINIBAND_MODE: InfiniBand device does not support connected mode
 * @NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED: A dependency of the connection failed
 * @NM_DEVICE_STATE_REASON_BR2684_FAILED: Problem with the RFC 2684 Ethernet over ADSL bridge
 * @NM_DEVICE_STATE_REASON_MODEM_MANAGER_UNAVAILABLE: ModemManager not running
 * @NM_DEVICE_STATE_REASON_SSID_NOT_FOUND: The WiFi network could not be found
 * @NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED: A secondary connection of the base connection failed
 * @NM_DEVICE_STATE_REASON_DCB_FCOE_FAILED: DCB or FCoE setup failed
 * @NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED: teamd control failed
 * @NM_DEVICE_STATE_REASON_MODEM_FAILED: Modem failed or no longer available
 * @NM_DEVICE_STATE_REASON_MODEM_AVAILABLE: Modem now ready and available
 * @NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT: SIM PIN was incorrect
 * @NM_DEVICE_STATE_REASON_NEW_ACTIVATION: New connection activation was enqueued
 * @NM_DEVICE_STATE_REASON_PARENT_CHANGED: the device's parent changed
 * @NM_DEVICE_STATE_REASON_PARENT_MANAGED_CHANGED: the device parent's management changed
 *
 * Device state change reason codes
 *
 * (Corresponds to the NM_DEVICE_STATE_REASON type in nm-device.xml.)
 */
typedef enum {
	NM_DEVICE_STATE_REASON_NONE = 0,
	NM_DEVICE_STATE_REASON_UNKNOWN = 1,
	NM_DEVICE_STATE_REASON_NOW_MANAGED = 2,
	NM_DEVICE_STATE_REASON_NOW_UNMANAGED = 3,
	NM_DEVICE_STATE_REASON_CONFIG_FAILED = 4,
	NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE = 5,
	NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED = 6,
	NM_DEVICE_STATE_REASON_NO_SECRETS = 7,
	NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT = 8,
	NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED = 9,
	NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED = 10,
	NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT = 11,
	NM_DEVICE_STATE_REASON_PPP_START_FAILED = 12,
	NM_DEVICE_STATE_REASON_PPP_DISCONNECT = 13,
	NM_DEVICE_STATE_REASON_PPP_FAILED = 14,
	NM_DEVICE_STATE_REASON_DHCP_START_FAILED = 15,
	NM_DEVICE_STATE_REASON_DHCP_ERROR = 16,
	NM_DEVICE_STATE_REASON_DHCP_FAILED = 17,
	NM_DEVICE_STATE_REASON_SHARED_START_FAILED = 18,
	NM_DEVICE_STATE_REASON_SHARED_FAILED = 19,
	NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED = 20,
	NM_DEVICE_STATE_REASON_AUTOIP_ERROR = 21,
	NM_DEVICE_STATE_REASON_AUTOIP_FAILED = 22,
	NM_DEVICE_STATE_REASON_MODEM_BUSY = 23,
	NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE = 24,
	NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER = 25,
	NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT = 26,
	NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED = 27,
	NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED = 28,
	NM_DEVICE_STATE_REASON_GSM_APN_FAILED = 29,
	NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING = 30,
	NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED = 31,
	NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT = 32,
	NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED = 33,
	NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED = 34,
	NM_DEVICE_STATE_REASON_FIRMWARE_MISSING = 35,
	NM_DEVICE_STATE_REASON_REMOVED = 36,
	NM_DEVICE_STATE_REASON_SLEEPING = 37,
	NM_DEVICE_STATE_REASON_CONNECTION_REMOVED = 38,
	NM_DEVICE_STATE_REASON_USER_REQUESTED = 39,
	NM_DEVICE_STATE_REASON_CARRIER = 40,
	NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED = 41,
	NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE = 42,
	NM_DEVICE_STATE_REASON_MODEM_NOT_FOUND = 43,
	NM_DEVICE_STATE_REASON_BT_FAILED = 44,
	NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED = 45,
	NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED = 46,
	NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED = 47,
	NM_DEVICE_STATE_REASON_GSM_SIM_WRONG = 48,
	NM_DEVICE_STATE_REASON_INFINIBAND_MODE = 49,
	NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED = 50,
	NM_DEVICE_STATE_REASON_BR2684_FAILED = 51,
	NM_DEVICE_STATE_REASON_MODEM_MANAGER_UNAVAILABLE = 52,
	NM_DEVICE_STATE_REASON_SSID_NOT_FOUND = 53,
	NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED = 54,
	NM_DEVICE_STATE_REASON_DCB_FCOE_FAILED = 55,
	NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED = 56,
	NM_DEVICE_STATE_REASON_MODEM_FAILED = 57,
	NM_DEVICE_STATE_REASON_MODEM_AVAILABLE = 58,
	NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT = 59,
	NM_DEVICE_STATE_REASON_NEW_ACTIVATION = 60,
	NM_DEVICE_STATE_REASON_PARENT_CHANGED = 61,
	NM_DEVICE_STATE_REASON_PARENT_MANAGED_CHANGED = 62,
} NMDeviceStateReason;

/**
 * NMMetered:
 * @NM_METERED_UNKNOWN:     The metered status is unknown
 * @NM_METERED_YES:         Metered, the value was statically set
 * @NM_METERED_NO:          Not metered, the value was statically set
 * @NM_METERED_GUESS_YES:   Metered, the value was guessed
 * @NM_METERED_GUESS_NO:    Not metered, the value was guessed
 *
 * (Corresponds to the NM_METERED type in nm-device.xml.)
 *
 * Since: 1.2
 **/
NM_AVAILABLE_IN_1_2
typedef enum {
	NM_METERED_UNKNOWN    = 0,
	NM_METERED_YES        = 1,
	NM_METERED_NO         = 2,
	NM_METERED_GUESS_YES  = 3,
	NM_METERED_GUESS_NO   = 4,
} NMMetered;

/**
 * NMActiveConnectionState:
 * @NM_ACTIVE_CONNECTION_STATE_UNKNOWN: the state of the connection is unknown
 * @NM_ACTIVE_CONNECTION_STATE_ACTIVATING: a network connection is being prepared
 * @NM_ACTIVE_CONNECTION_STATE_ACTIVATED: there is a connection to the network
 * @NM_ACTIVE_CONNECTION_STATE_DEACTIVATING: the network connection is being
 *   torn down and cleaned up
 * @NM_ACTIVE_CONNECTION_STATE_DEACTIVATED: the network connection is disconnected
 *   and will be removed
 *
 * #NMActiveConnectionState values indicate the state of a connection to a
 * specific network while it is starting, connected, or disconnecting from that
 * network.
 *
 * (Corresponds to the NM_ACTIVE_CONNECTION_STATE type in nm-active-connection.xml.)
 **/
typedef enum {
	NM_ACTIVE_CONNECTION_STATE_UNKNOWN = 0,
	NM_ACTIVE_CONNECTION_STATE_ACTIVATING,
	NM_ACTIVE_CONNECTION_STATE_ACTIVATED,
	NM_ACTIVE_CONNECTION_STATE_DEACTIVATING,
	NM_ACTIVE_CONNECTION_STATE_DEACTIVATED
} NMActiveConnectionState;

/**
 * NMSecretAgentGetSecretsFlags:
 * @NM_SECRET_AGENT_GET_SECRETS_FLAG_NONE: no special behavior; by default no
 *   user interaction is allowed and requests for secrets are fulfilled from
 *   persistent storage, or if no secrets are available an error is returned.
 * @NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION: allows the request to
 *   interact with the user, possibly prompting via UI for secrets if any are
 *   required, or if none are found in persistent storage.
 * @NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW: explicitly prompt for new
 *   secrets from the user.  This flag signals that NetworkManager thinks any
 *   existing secrets are invalid or wrong.  This flag implies that interaction
 *   is allowed.
 * @NM_SECRET_AGENT_GET_SECRETS_FLAG_USER_REQUESTED: set if the request was
 *   initiated by user-requested action via the D-Bus interface, as opposed to
 *   automatically initiated by NetworkManager in response to (for example) scan
 *   results or carrier changes.
 * @NM_SECRET_AGENT_GET_SECRETS_FLAG_ONLY_SYSTEM: Internal flag, not part of
 *   the D-Bus API.
 * @NM_SECRET_AGENT_GET_SECRETS_FLAG_NO_ERRORS: Internal flag, not part of
 *   the D-Bus API.
 *
 * #NMSecretAgentGetSecretsFlags values modify the behavior of a GetSecrets request.
 *
 * (Corresponds to the NM_SECRET_AGENT_GET_SECRETS_FLAGS type in nm-secret-agent.xml.)
 */
typedef enum { /*< flags >*/
	NM_SECRET_AGENT_GET_SECRETS_FLAG_NONE = 0x0,
	NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION = 0x1,
	NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW = 0x2,
	NM_SECRET_AGENT_GET_SECRETS_FLAG_USER_REQUESTED = 0x4,

	/* Internal to NM; not part of the D-Bus API */
	NM_SECRET_AGENT_GET_SECRETS_FLAG_ONLY_SYSTEM = 0x80000000,
	NM_SECRET_AGENT_GET_SECRETS_FLAG_NO_ERRORS = 0x40000000,
} NMSecretAgentGetSecretsFlags;

/**
 * NMSecretAgentCapabilities:
 * @NM_SECRET_AGENT_CAPABILITY_NONE: the agent supports no special capabilities
 * @NM_SECRET_AGENT_CAPABILITY_VPN_HINTS: the agent supports passing hints to
 * VPN plugin authentication dialogs.
 * @NM_SECRET_AGENT_CAPABILITY_LAST: bounds checking value; should not be used.
 *
 * #NMSecretAgentCapabilities indicate various capabilities of the agent.
 *
 * (Corresponds to the NM_SECRET_AGENT_CAPABILITIES type in nm-secret-agent.xml.)
 */
typedef enum /*< flags >*/ {
	NM_SECRET_AGENT_CAPABILITY_NONE = 0x0,
	NM_SECRET_AGENT_CAPABILITY_VPN_HINTS = 0x1,

	/* boundary value */
	NM_SECRET_AGENT_CAPABILITY_LAST = NM_SECRET_AGENT_CAPABILITY_VPN_HINTS
} NMSecretAgentCapabilities;

#ifndef NM_VERSION_H
#undef NM_AVAILABLE_IN_1_2
#endif

#endif /* __NM_DBUS_INTERFACE_H__ */
