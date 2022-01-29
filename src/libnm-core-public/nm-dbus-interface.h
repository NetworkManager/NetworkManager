/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2004 - 2018 Red Hat, Inc.
 */

/* Definitions related to NetworkManager's D-Bus interfaces.
 *
 * Note that although this header is installed as part of libnm, it is also
 * used by some external code that does not link to libnm.
 */

#ifndef __NM_DBUS_INTERFACE_H__
#define __NM_DBUS_INTERFACE_H__

/* This header must not include glib or libnm. */

#ifndef NM_VERSION_H
#define NM_AVAILABLE_IN_1_2
#define NM_AVAILABLE_IN_1_8
#endif

/*
 * dbus services details
 */
#define NM_DBUS_SERVICE "org.freedesktop.NetworkManager"

#define NM_DBUS_INTERFACE                      "org.freedesktop.NetworkManager"
#define NM_DBUS_INTERFACE_ACCESS_POINT         NM_DBUS_INTERFACE ".AccessPoint"
#define NM_DBUS_INTERFACE_ACTIVE_CONNECTION    NM_DBUS_INTERFACE ".Connection.Active"
#define NM_DBUS_INTERFACE_CHECKPOINT           NM_DBUS_INTERFACE ".Checkpoint"
#define NM_DBUS_INTERFACE_DEVICE               NM_DBUS_INTERFACE ".Device"
#define NM_DBUS_INTERFACE_DEVICE_6LOWPAN       NM_DBUS_INTERFACE_DEVICE ".Lowpan"
#define NM_DBUS_INTERFACE_DEVICE_ADSL          NM_DBUS_INTERFACE_DEVICE ".Adsl"
#define NM_DBUS_INTERFACE_DEVICE_BLUETOOTH     NM_DBUS_INTERFACE_DEVICE ".Bluetooth"
#define NM_DBUS_INTERFACE_DEVICE_BOND          NM_DBUS_INTERFACE_DEVICE ".Bond"
#define NM_DBUS_INTERFACE_DEVICE_BRIDGE        NM_DBUS_INTERFACE_DEVICE ".Bridge"
#define NM_DBUS_INTERFACE_DEVICE_DUMMY         NM_DBUS_INTERFACE_DEVICE ".Dummy"
#define NM_DBUS_INTERFACE_DEVICE_GENERIC       NM_DBUS_INTERFACE_DEVICE ".Generic"
#define NM_DBUS_INTERFACE_DEVICE_GRE           NM_DBUS_INTERFACE_DEVICE ".Gre"
#define NM_DBUS_INTERFACE_DEVICE_INFINIBAND    NM_DBUS_INTERFACE_DEVICE ".Infiniband"
#define NM_DBUS_INTERFACE_DEVICE_IP_TUNNEL     NM_DBUS_INTERFACE_DEVICE ".IPTunnel"
#define NM_DBUS_INTERFACE_DEVICE_MACSEC        NM_DBUS_INTERFACE_DEVICE ".Macsec"
#define NM_DBUS_INTERFACE_DEVICE_MACVLAN       NM_DBUS_INTERFACE_DEVICE ".Macvlan"
#define NM_DBUS_INTERFACE_DEVICE_MODEM         NM_DBUS_INTERFACE_DEVICE ".Modem"
#define NM_DBUS_INTERFACE_DEVICE_OLPC_MESH     NM_DBUS_INTERFACE_DEVICE ".OlpcMesh"
#define NM_DBUS_INTERFACE_DEVICE_OVS_BRIDGE    NM_DBUS_INTERFACE_DEVICE ".OvsBridge"
#define NM_DBUS_INTERFACE_DEVICE_OVS_INTERFACE NM_DBUS_INTERFACE_DEVICE ".OvsInterface"
#define NM_DBUS_INTERFACE_DEVICE_OVS_PORT      NM_DBUS_INTERFACE_DEVICE ".OvsPort"
#define NM_DBUS_INTERFACE_DEVICE_PPP           NM_DBUS_INTERFACE_DEVICE ".Ppp"
#define NM_DBUS_INTERFACE_DEVICE_STATISTICS    NM_DBUS_INTERFACE_DEVICE ".Statistics"
#define NM_DBUS_INTERFACE_DEVICE_TEAM          NM_DBUS_INTERFACE_DEVICE ".Team"
#define NM_DBUS_INTERFACE_DEVICE_TUN           NM_DBUS_INTERFACE_DEVICE ".Tun"
#define NM_DBUS_INTERFACE_DEVICE_VETH          NM_DBUS_INTERFACE_DEVICE ".Veth"
#define NM_DBUS_INTERFACE_DEVICE_VLAN          NM_DBUS_INTERFACE_DEVICE ".Vlan"
#define NM_DBUS_INTERFACE_DEVICE_VRF           NM_DBUS_INTERFACE_DEVICE ".Vrf"
#define NM_DBUS_INTERFACE_DEVICE_VXLAN         NM_DBUS_INTERFACE_DEVICE ".Vxlan"
#define NM_DBUS_INTERFACE_DEVICE_WIFI_P2P      NM_DBUS_INTERFACE_DEVICE ".WifiP2P"
#define NM_DBUS_INTERFACE_DEVICE_WIMAX         NM_DBUS_INTERFACE_DEVICE ".WiMax"
#define NM_DBUS_INTERFACE_DEVICE_WIRED         NM_DBUS_INTERFACE_DEVICE ".Wired"
#define NM_DBUS_INTERFACE_DEVICE_WIREGUARD     NM_DBUS_INTERFACE_DEVICE ".WireGuard"
#define NM_DBUS_INTERFACE_DEVICE_WIRELESS      NM_DBUS_INTERFACE_DEVICE ".Wireless"
#define NM_DBUS_INTERFACE_DEVICE_WPAN          NM_DBUS_INTERFACE_DEVICE ".Wpan"
#define NM_DBUS_INTERFACE_DHCP4_CONFIG         NM_DBUS_INTERFACE ".DHCP4Config"
#define NM_DBUS_INTERFACE_DHCP6_CONFIG         NM_DBUS_INTERFACE ".DHCP6Config"
#define NM_DBUS_INTERFACE_IP4_CONFIG           NM_DBUS_INTERFACE ".IP4Config"
#define NM_DBUS_INTERFACE_IP6_CONFIG           NM_DBUS_INTERFACE ".IP6Config"
#define NM_DBUS_INTERFACE_WIFI_P2P_PEER        NM_DBUS_INTERFACE ".WifiP2PPeer"
#define NM_DBUS_INTERFACE_WIMAX_NSP            NM_DBUS_INTERFACE ".WiMax.Nsp"

#define NM_DBUS_PATH               "/org/freedesktop/NetworkManager"
#define NM_DBUS_PATH_ACCESS_POINT  NM_DBUS_PATH "/AccessPoint"
#define NM_DBUS_PATH_WIFI_P2P_PEER NM_DBUS_PATH "/WifiP2PPeer"
#define NM_DBUS_PATH_WIMAX_NSP     NM_DBUS_PATH "/Nsp"

#define NM_DBUS_INTERFACE_SETTINGS "org.freedesktop.NetworkManager.Settings"
#define NM_DBUS_PATH_SETTINGS      "/org/freedesktop/NetworkManager/Settings"

#define NM_DBUS_INTERFACE_SETTINGS_CONNECTION "org.freedesktop.NetworkManager.Settings.Connection"
#define NM_DBUS_PATH_SETTINGS_CONNECTION      "/org/freedesktop/NetworkManager/Settings/Connection"
#define NM_DBUS_INTERFACE_SETTINGS_CONNECTION_SECRETS \
    "org.freedesktop.NetworkManager.Settings.Connection.Secrets"

#define NM_DBUS_INTERFACE_AGENT_MANAGER NM_DBUS_INTERFACE ".AgentManager"
#define NM_DBUS_PATH_AGENT_MANAGER      "/org/freedesktop/NetworkManager/AgentManager"

#define NM_DBUS_INTERFACE_SECRET_AGENT NM_DBUS_INTERFACE ".SecretAgent"
#define NM_DBUS_PATH_SECRET_AGENT      "/org/freedesktop/NetworkManager/SecretAgent"

#define NM_DBUS_INTERFACE_DNS_MANAGER "org.freedesktop.NetworkManager.DnsManager"
#define NM_DBUS_PATH_DNS_MANAGER      "/org/freedesktop/NetworkManager/DnsManager"

/**
 * NMCapability:
 * @NM_CAPABILITY_TEAM: Teams can be managed. This means the team device plugin
 *   is loaded.
 * @NM_CAPABILITY_OVS: OpenVSwitch can be managed. This means the OVS device plugin
 *   is loaded. Since: 1.24.
 *
 * #NMCapability names the numbers in the Capabilities property.
 * Capabilities are positive numbers. They are part of stable API
 * and a certain capability number is guaranteed not to change.
 *
 * The range 0x7000 - 0x7FFF of capabilities is guaranteed not to be
 * used by upstream NetworkManager. It could thus be used for downstream
 * extensions.
 */
typedef enum {
    NM_CAPABILITY_TEAM = 1,
    NM_CAPABILITY_OVS  = 2,
} NMCapability;

/**
 * NMState:
 * @NM_STATE_UNKNOWN: Networking state is unknown. This indicates a daemon error
 *    that makes it unable to reasonably assess the state. In such event the
 *    applications are expected to assume Internet connectivity might be present
 *    and not disable controls that require network access.
 *    The graphical shells may hide the network accessibility indicator altogether
 *    since no meaningful status indication can be provided.
 * @NM_STATE_ASLEEP: Networking is not enabled, the system is being suspended or
 *    resumed from suspend.
 * @NM_STATE_DISCONNECTED: There is no active network connection.
 *    The graphical shell should indicate  no network connectivity and the
 *    applications should not attempt to access the network.
 * @NM_STATE_DISCONNECTING: Network connections are being cleaned up.
 *    The applications should tear down their network sessions.
 * @NM_STATE_CONNECTING: A network connection is being started
 *    The graphical shell should indicate the network is being connected while
 *    the applications should still make no attempts to connect the network.
 * @NM_STATE_CONNECTED_LOCAL: There is only local IPv4 and/or IPv6 connectivity,
 *    but no default route to access the Internet. The graphical shell should
 *    indicate no network connectivity.
 * @NM_STATE_CONNECTED_SITE: There is only site-wide IPv4 and/or IPv6 connectivity.
 *    This means a default route is available, but the Internet connectivity check
 *    (see "Connectivity" property) did not succeed. The graphical shell should
 *    indicate limited network connectivity.
 * @NM_STATE_CONNECTED_GLOBAL: There is global IPv4 and/or IPv6 Internet connectivity
 *    This means the Internet connectivity check succeeded, the graphical shell should
 *    indicate full network connectivity.
 *
 * #NMState values indicate the current overall networking state.
 **/
typedef enum {
    NM_STATE_UNKNOWN          = 0,
    NM_STATE_ASLEEP           = 10,
    NM_STATE_DISCONNECTED     = 20,
    NM_STATE_DISCONNECTING    = 30,
    NM_STATE_CONNECTING       = 40,
    NM_STATE_CONNECTED_LOCAL  = 50,
    NM_STATE_CONNECTED_SITE   = 60,
    NM_STATE_CONNECTED_GLOBAL = 70,
} NMState;

/**
 * NMConnectivityState:
 * @NM_CONNECTIVITY_UNKNOWN: Network connectivity is unknown. This means the
 *   connectivity checks are disabled (e.g. on server installations) or has
 *   not run yet. The graphical shell should assume the Internet connection
 *   might be available and not present a captive portal window.
 * @NM_CONNECTIVITY_NONE: The host is not connected to any network. There's
 *   no active connection that contains a default route to the internet and
 *   thus it makes no sense to even attempt a connectivity check. The graphical
 *   shell should use this state to indicate the network connection is unavailable.
 * @NM_CONNECTIVITY_PORTAL: The Internet connection is hijacked by a captive
 *   portal gateway. The graphical shell may open a sandboxed web browser window
 *   (because the captive portals typically attempt a man-in-the-middle attacks
 *   against the https connections) for the purpose of authenticating to a gateway
 *   and retrigger the connectivity check with CheckConnectivity() when the
 *   browser window is dismissed.
 * @NM_CONNECTIVITY_LIMITED: The host is connected to a network, does not appear
 *   to be able to reach the full Internet, but a captive portal has not been
 *   detected.
 * @NM_CONNECTIVITY_FULL: The host is connected to a network, and
 *   appears to be able to reach the full Internet.
 */
typedef enum {
    NM_CONNECTIVITY_UNKNOWN = 0,
    NM_CONNECTIVITY_NONE    = 1,
    NM_CONNECTIVITY_PORTAL  = 2,
    NM_CONNECTIVITY_LIMITED = 3,
    NM_CONNECTIVITY_FULL    = 4,
} NMConnectivityState;

/**
 * NMDeviceType:
 * @NM_DEVICE_TYPE_UNKNOWN: unknown device
 * @NM_DEVICE_TYPE_GENERIC: generic support for unrecognized device types
 * @NM_DEVICE_TYPE_ETHERNET: a wired ethernet device
 * @NM_DEVICE_TYPE_WIFI: an 802.11 Wi-Fi device
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
 * @NM_DEVICE_TYPE_TUN: a TUN or TAP interface
 * @NM_DEVICE_TYPE_IP_TUNNEL: a IP tunnel interface
 * @NM_DEVICE_TYPE_MACVLAN: a MACVLAN interface
 * @NM_DEVICE_TYPE_VXLAN: a VXLAN interface
 * @NM_DEVICE_TYPE_VETH: a VETH interface
 * @NM_DEVICE_TYPE_MACSEC: a MACsec interface
 * @NM_DEVICE_TYPE_DUMMY: a dummy interface
 * @NM_DEVICE_TYPE_PPP: a PPP interface
 * @NM_DEVICE_TYPE_OVS_INTERFACE: a Open vSwitch interface
 * @NM_DEVICE_TYPE_OVS_PORT: a Open vSwitch port
 * @NM_DEVICE_TYPE_OVS_BRIDGE: a Open vSwitch bridge
 * @NM_DEVICE_TYPE_WPAN: a IEEE 802.15.4 (WPAN) MAC Layer Device
 * @NM_DEVICE_TYPE_6LOWPAN: 6LoWPAN interface
 * @NM_DEVICE_TYPE_WIREGUARD: a WireGuard interface
 * @NM_DEVICE_TYPE_WIFI_P2P: an 802.11 Wi-Fi P2P device. Since: 1.16.
 * @NM_DEVICE_TYPE_VRF: A VRF (Virtual Routing and Forwarding) interface. Since: 1.24.
 *
 * #NMDeviceType values indicate the type of hardware represented by a
 * device object.
 **/
typedef enum {
    NM_DEVICE_TYPE_UNKNOWN       = 0,
    NM_DEVICE_TYPE_ETHERNET      = 1,
    NM_DEVICE_TYPE_WIFI          = 2,
    NM_DEVICE_TYPE_UNUSED1       = 3,
    NM_DEVICE_TYPE_UNUSED2       = 4,
    NM_DEVICE_TYPE_BT            = 5, /* Bluetooth */
    NM_DEVICE_TYPE_OLPC_MESH     = 6,
    NM_DEVICE_TYPE_WIMAX         = 7,
    NM_DEVICE_TYPE_MODEM         = 8,
    NM_DEVICE_TYPE_INFINIBAND    = 9,
    NM_DEVICE_TYPE_BOND          = 10,
    NM_DEVICE_TYPE_VLAN          = 11,
    NM_DEVICE_TYPE_ADSL          = 12,
    NM_DEVICE_TYPE_BRIDGE        = 13,
    NM_DEVICE_TYPE_GENERIC       = 14,
    NM_DEVICE_TYPE_TEAM          = 15,
    NM_DEVICE_TYPE_TUN           = 16,
    NM_DEVICE_TYPE_IP_TUNNEL     = 17,
    NM_DEVICE_TYPE_MACVLAN       = 18,
    NM_DEVICE_TYPE_VXLAN         = 19,
    NM_DEVICE_TYPE_VETH          = 20,
    NM_DEVICE_TYPE_MACSEC        = 21,
    NM_DEVICE_TYPE_DUMMY         = 22,
    NM_DEVICE_TYPE_PPP           = 23,
    NM_DEVICE_TYPE_OVS_INTERFACE = 24,
    NM_DEVICE_TYPE_OVS_PORT      = 25,
    NM_DEVICE_TYPE_OVS_BRIDGE    = 26,
    NM_DEVICE_TYPE_WPAN          = 27,
    NM_DEVICE_TYPE_6LOWPAN       = 28,
    NM_DEVICE_TYPE_WIREGUARD     = 29,
    NM_DEVICE_TYPE_WIFI_P2P      = 30,
    NM_DEVICE_TYPE_VRF           = 31,
} NMDeviceType;

/**
 * NMDeviceCapabilities:
 * @NM_DEVICE_CAP_NONE: device has no special capabilities
 * @NM_DEVICE_CAP_NM_SUPPORTED: NetworkManager supports this device
 * @NM_DEVICE_CAP_CARRIER_DETECT: this device can indicate carrier status
 * @NM_DEVICE_CAP_IS_SOFTWARE: this device is a software device
 * @NM_DEVICE_CAP_SRIOV: this device supports single-root I/O virtualization
 *
 * General device capability flags.
 **/
typedef enum { /*< flags >*/
               NM_DEVICE_CAP_NONE           = 0x00000000,
               NM_DEVICE_CAP_NM_SUPPORTED   = 0x00000001,
               NM_DEVICE_CAP_CARRIER_DETECT = 0x00000002,
               NM_DEVICE_CAP_IS_SOFTWARE    = 0x00000004,
               NM_DEVICE_CAP_SRIOV          = 0x00000008,
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
 * @NM_WIFI_DEVICE_CAP_MESH: device supports acting as a mesh point. Since: 1.20.
 * @NM_WIFI_DEVICE_CAP_IBSS_RSN: device supports WPA2/RSN in an IBSS network. Since: 1.22.
 *
 * 802.11 specific device encryption and authentication capabilities.
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
               NM_WIFI_DEVICE_CAP_MESH          = 0x00001000,
               NM_WIFI_DEVICE_CAP_IBSS_RSN      = 0x00002000,
} NMDeviceWifiCapabilities;

/**
 * NM80211ApFlags:
 * @NM_802_11_AP_FLAGS_NONE: access point has no special capabilities
 * @NM_802_11_AP_FLAGS_PRIVACY: access point requires authentication and
 * encryption (usually means WEP)
 * @NM_802_11_AP_FLAGS_WPS: access point supports some WPS method
 * @NM_802_11_AP_FLAGS_WPS_PBC: access point supports push-button WPS
 * @NM_802_11_AP_FLAGS_WPS_PIN: access point supports PIN-based WPS
 *
 * 802.11 access point flags.
 **/
typedef enum { /*< underscore_name=nm_802_11_ap_flags, flags >*/
               NM_802_11_AP_FLAGS_NONE    = 0x00000000,
               NM_802_11_AP_FLAGS_PRIVACY = 0x00000001,
               NM_802_11_AP_FLAGS_WPS     = 0x00000002,
               NM_802_11_AP_FLAGS_WPS_PBC = 0x00000004,
               NM_802_11_AP_FLAGS_WPS_PIN = 0x00000008,
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
 * @NM_802_11_AP_SEC_KEY_MGMT_SAE: WPA/RSN Simultaneous Authentication of Equals is
 * supported
 * @NM_802_11_AP_SEC_KEY_MGMT_OWE: WPA/RSN Opportunistic Wireless Encryption is
 * supported
 * @NM_802_11_AP_SEC_KEY_MGMT_OWE_TM: WPA/RSN Opportunistic Wireless Encryption
 * transition mode is supported. Since: 1.26.
 * @NM_802_11_AP_SEC_KEY_MGMT_EAP_SUITE_B_192: WPA3 Enterprise Suite-B 192 bit mode
 * is supported. Since: 1.30.
 *
 * 802.11 access point security and authentication flags.  These flags describe
 * the current security requirements of an access point as determined from the
 * access point's beacon.
 **/
typedef enum { /*< underscore_name=nm_802_11_ap_security_flags, flags >*/
               NM_802_11_AP_SEC_NONE                     = 0x00000000,
               NM_802_11_AP_SEC_PAIR_WEP40               = 0x00000001,
               NM_802_11_AP_SEC_PAIR_WEP104              = 0x00000002,
               NM_802_11_AP_SEC_PAIR_TKIP                = 0x00000004,
               NM_802_11_AP_SEC_PAIR_CCMP                = 0x00000008,
               NM_802_11_AP_SEC_GROUP_WEP40              = 0x00000010,
               NM_802_11_AP_SEC_GROUP_WEP104             = 0x00000020,
               NM_802_11_AP_SEC_GROUP_TKIP               = 0x00000040,
               NM_802_11_AP_SEC_GROUP_CCMP               = 0x00000080,
               NM_802_11_AP_SEC_KEY_MGMT_PSK             = 0x00000100,
               NM_802_11_AP_SEC_KEY_MGMT_802_1X          = 0x00000200,
               NM_802_11_AP_SEC_KEY_MGMT_SAE             = 0x00000400,
               NM_802_11_AP_SEC_KEY_MGMT_OWE             = 0x00000800,
               NM_802_11_AP_SEC_KEY_MGMT_OWE_TM          = 0x00001000,
               NM_802_11_AP_SEC_KEY_MGMT_EAP_SUITE_B_192 = 0x00002000,
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
 * @NM_802_11_MODE_MESH: the device is a 802.11s mesh point. Since: 1.20.
 *
 * Indicates the 802.11 mode an access point or device is currently in.
 **/
typedef enum { /*< underscore_name=nm_802_11_mode >*/
               NM_802_11_MODE_UNKNOWN = 0,
               NM_802_11_MODE_ADHOC   = 1,
               NM_802_11_MODE_INFRA   = 2,
               NM_802_11_MODE_AP      = 3,
               NM_802_11_MODE_MESH    = 4,
} NM80211Mode;

/**
 * NMBluetoothCapabilities:
 * @NM_BT_CAPABILITY_NONE: device has no usable capabilities
 * @NM_BT_CAPABILITY_DUN: device provides Dial-Up Networking capability
 * @NM_BT_CAPABILITY_NAP: device provides Network Access Point capability
 *
 * #NMBluetoothCapabilities values indicate the usable capabilities of a
 * Bluetooth device.
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
 * @NM_DEVICE_MODEM_CAPABILITY_5GNR: modem has 5GNR data capability (Since: 1.36)
 *
 * #NMDeviceModemCapabilities values indicate the generic radio access
 * technology families a modem device supports.  For more information on the
 * specific access technologies the device supports use the ModemManager D-Bus
 * API.
 **/
typedef enum { /*< flags >*/
               NM_DEVICE_MODEM_CAPABILITY_NONE      = 0x00000000,
               NM_DEVICE_MODEM_CAPABILITY_POTS      = 0x00000001,
               NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO = 0x00000002,
               NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS  = 0x00000004,
               NM_DEVICE_MODEM_CAPABILITY_LTE       = 0x00000008,
               NM_DEVICE_MODEM_CAPABILITY_5GNR      = 0x00000040,
} NMDeviceModemCapabilities;
/* Note: the numeric values of NMDeviceModemCapabilities must be identical to the values
 * in MMModemCapability. See the G_STATIC_ASSERT() in nm-modem-broadband.c's get_capabilities().  */

/**
 * NMWimaxNspNetworkType:
 * @NM_WIMAX_NSP_NETWORK_TYPE_UNKNOWN: unknown network type
 * @NM_WIMAX_NSP_NETWORK_TYPE_HOME: home network
 * @NM_WIMAX_NSP_NETWORK_TYPE_PARTNER: partner network
 * @NM_WIMAX_NSP_NETWORK_TYPE_ROAMING_PARTNER: roaming partner network
 *
 * WiMAX network type.
 */
typedef enum {
    NM_WIMAX_NSP_NETWORK_TYPE_UNKNOWN         = 0,
    NM_WIMAX_NSP_NETWORK_TYPE_HOME            = 1,
    NM_WIMAX_NSP_NETWORK_TYPE_PARTNER         = 2,
    NM_WIMAX_NSP_NETWORK_TYPE_ROAMING_PARTNER = 3,
} NMWimaxNspNetworkType;

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
 *   This may include operations like associating with the Wi-Fi AP, dialing
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
    NM_DEVICE_STATE_FAILED       = 120,
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
 * @NM_DEVICE_STATE_REASON_SSID_NOT_FOUND: The Wi-Fi network could not be found
 * @NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED: A secondary connection of the base connection failed
 * @NM_DEVICE_STATE_REASON_DCB_FCOE_FAILED: DCB or FCoE setup failed
 * @NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED: teamd control failed
 * @NM_DEVICE_STATE_REASON_MODEM_FAILED: Modem failed or no longer available
 * @NM_DEVICE_STATE_REASON_MODEM_AVAILABLE: Modem now ready and available
 * @NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT: SIM PIN was incorrect
 * @NM_DEVICE_STATE_REASON_NEW_ACTIVATION: New connection activation was enqueued
 * @NM_DEVICE_STATE_REASON_PARENT_CHANGED: the device's parent changed
 * @NM_DEVICE_STATE_REASON_PARENT_MANAGED_CHANGED: the device parent's management changed
 * @NM_DEVICE_STATE_REASON_OVSDB_FAILED: problem communicating with Open vSwitch database
 * @NM_DEVICE_STATE_REASON_IP_ADDRESS_DUPLICATE: a duplicate IP address was detected
 * @NM_DEVICE_STATE_REASON_IP_METHOD_UNSUPPORTED: The selected IP method is not supported
 * @NM_DEVICE_STATE_REASON_SRIOV_CONFIGURATION_FAILED: configuration of SR-IOV parameters failed
 * @NM_DEVICE_STATE_REASON_PEER_NOT_FOUND: The Wi-Fi P2P peer could not be found
 *
 * Device state change reason codes
 */
typedef enum {
    NM_DEVICE_STATE_REASON_NONE                           = 0,
    NM_DEVICE_STATE_REASON_UNKNOWN                        = 1,
    NM_DEVICE_STATE_REASON_NOW_MANAGED                    = 2,
    NM_DEVICE_STATE_REASON_NOW_UNMANAGED                  = 3,
    NM_DEVICE_STATE_REASON_CONFIG_FAILED                  = 4,
    NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE          = 5,
    NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED              = 6,
    NM_DEVICE_STATE_REASON_NO_SECRETS                     = 7,
    NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT          = 8,
    NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED       = 9,
    NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED              = 10,
    NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT             = 11,
    NM_DEVICE_STATE_REASON_PPP_START_FAILED               = 12,
    NM_DEVICE_STATE_REASON_PPP_DISCONNECT                 = 13,
    NM_DEVICE_STATE_REASON_PPP_FAILED                     = 14,
    NM_DEVICE_STATE_REASON_DHCP_START_FAILED              = 15,
    NM_DEVICE_STATE_REASON_DHCP_ERROR                     = 16,
    NM_DEVICE_STATE_REASON_DHCP_FAILED                    = 17,
    NM_DEVICE_STATE_REASON_SHARED_START_FAILED            = 18,
    NM_DEVICE_STATE_REASON_SHARED_FAILED                  = 19,
    NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED            = 20,
    NM_DEVICE_STATE_REASON_AUTOIP_ERROR                   = 21,
    NM_DEVICE_STATE_REASON_AUTOIP_FAILED                  = 22,
    NM_DEVICE_STATE_REASON_MODEM_BUSY                     = 23,
    NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE             = 24,
    NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER               = 25,
    NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT             = 26,
    NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED              = 27,
    NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED              = 28,
    NM_DEVICE_STATE_REASON_GSM_APN_FAILED                 = 29,
    NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING = 30,
    NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED        = 31,
    NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT       = 32,
    NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED        = 33,
    NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED           = 34,
    NM_DEVICE_STATE_REASON_FIRMWARE_MISSING               = 35,
    NM_DEVICE_STATE_REASON_REMOVED                        = 36,
    NM_DEVICE_STATE_REASON_SLEEPING                       = 37,
    NM_DEVICE_STATE_REASON_CONNECTION_REMOVED             = 38,
    NM_DEVICE_STATE_REASON_USER_REQUESTED                 = 39,
    NM_DEVICE_STATE_REASON_CARRIER                        = 40,
    NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED             = 41,
    NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE           = 42,
    NM_DEVICE_STATE_REASON_MODEM_NOT_FOUND                = 43,
    NM_DEVICE_STATE_REASON_BT_FAILED                      = 44,
    NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED           = 45,
    NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED           = 46,
    NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED           = 47,
    NM_DEVICE_STATE_REASON_GSM_SIM_WRONG                  = 48,
    NM_DEVICE_STATE_REASON_INFINIBAND_MODE                = 49,
    NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED              = 50,
    NM_DEVICE_STATE_REASON_BR2684_FAILED                  = 51,
    NM_DEVICE_STATE_REASON_MODEM_MANAGER_UNAVAILABLE      = 52,
    NM_DEVICE_STATE_REASON_SSID_NOT_FOUND                 = 53,
    NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED    = 54,
    NM_DEVICE_STATE_REASON_DCB_FCOE_FAILED                = 55,
    NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED           = 56,
    NM_DEVICE_STATE_REASON_MODEM_FAILED                   = 57,
    NM_DEVICE_STATE_REASON_MODEM_AVAILABLE                = 58,
    NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT              = 59,
    NM_DEVICE_STATE_REASON_NEW_ACTIVATION                 = 60,
    NM_DEVICE_STATE_REASON_PARENT_CHANGED                 = 61,
    NM_DEVICE_STATE_REASON_PARENT_MANAGED_CHANGED         = 62,
    NM_DEVICE_STATE_REASON_OVSDB_FAILED                   = 63,
    NM_DEVICE_STATE_REASON_IP_ADDRESS_DUPLICATE           = 64,
    NM_DEVICE_STATE_REASON_IP_METHOD_UNSUPPORTED          = 65,
    NM_DEVICE_STATE_REASON_SRIOV_CONFIGURATION_FAILED     = 66,
    NM_DEVICE_STATE_REASON_PEER_NOT_FOUND                 = 67,
} NMDeviceStateReason;

/**
 * NMMetered:
 * @NM_METERED_UNKNOWN:     The metered status is unknown
 * @NM_METERED_YES:         Metered, the value was explicitly configured
 * @NM_METERED_NO:          Not metered, the value was explicitly configured
 * @NM_METERED_GUESS_YES:   Metered, the value was guessed
 * @NM_METERED_GUESS_NO:    Not metered, the value was guessed
 *
 * The NMMetered enum has two different purposes: one is to configure
 * "connection.metered" setting of a connection profile in #NMSettingConnection, and
 * the other is to express the actual metered state of the #NMDevice at a given moment.
 *
 * For the connection profile only #NM_METERED_UNKNOWN, #NM_METERED_NO
 * and #NM_METERED_YES are allowed.
 *
 * The device's metered state at runtime is determined by the profile
 * which is currently active. If the profile explicitly specifies #NM_METERED_NO
 * or #NM_METERED_YES, then the device's metered state is as such.
 * If the connection profile leaves it undecided at #NM_METERED_UNKNOWN (the default),
 * then NetworkManager tries to guess the metered state, for example based on the
 * device type or on DHCP options (like Android devices exposing a "ANDROID_METERED"
 * DHCP vendor option). This then leads to either #NM_METERED_GUESS_NO or #NM_METERED_GUESS_YES.
 *
 * Most applications probably should treat the runtime state #NM_METERED_GUESS_YES
 * like #NM_METERED_YES, and all other states as not metered.
 *
 * Note that the per-device metered states are then combined to a global metered
 * state. This is basically the metered state of the device with the best default
 * route. However, that generalization of a global metered state may not be correct
 * if the default routes for IPv4 and IPv6 are on different devices, or if policy
 * routing is configured. In general, the global metered state tries to express whether
 * the traffic is likely metered, but since that depends on the traffic itself,
 * there is not one answer in all cases. Hence, an application may want to consider
 * the per-device's metered states.
 *
 * Since: 1.2
 **/
NM_AVAILABLE_IN_1_2
typedef enum {
    NM_METERED_UNKNOWN   = 0,
    NM_METERED_YES       = 1,
    NM_METERED_NO        = 2,
    NM_METERED_GUESS_YES = 3,
    NM_METERED_GUESS_NO  = 4,
} NMMetered;

/**
 * NMConnectionMultiConnect:
 * @NM_CONNECTION_MULTI_CONNECT_DEFAULT: indicates that the per-connection
 *   setting is unspecified. In this case, it will fallback to the default
 *   value, which is %NM_CONNECTION_MULTI_CONNECT_SINGLE.
 * @NM_CONNECTION_MULTI_CONNECT_SINGLE: the connection profile can only
 *   be active once at each moment. Activating a profile that is already active,
 *   will first deactivate it.
 * @NM_CONNECTION_MULTI_CONNECT_MANUAL_MULTIPLE: the profile can
 *   be manually activated multiple times on different devices. However,
 *   regarding autoconnect, the profile will autoconnect only if it is
 *   currently not connected otherwise.
 * @NM_CONNECTION_MULTI_CONNECT_MULTIPLE: the profile can autoactivate
 *   and be manually activated multiple times together.
 *
 * Since: 1.14
 */
typedef enum {
    NM_CONNECTION_MULTI_CONNECT_DEFAULT         = 0,
    NM_CONNECTION_MULTI_CONNECT_SINGLE          = 1,
    NM_CONNECTION_MULTI_CONNECT_MANUAL_MULTIPLE = 2,
    NM_CONNECTION_MULTI_CONNECT_MULTIPLE        = 3,
} NMConnectionMultiConnect;

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
 **/
typedef enum {
    NM_ACTIVE_CONNECTION_STATE_UNKNOWN      = 0,
    NM_ACTIVE_CONNECTION_STATE_ACTIVATING   = 1,
    NM_ACTIVE_CONNECTION_STATE_ACTIVATED    = 2,
    NM_ACTIVE_CONNECTION_STATE_DEACTIVATING = 3,
    NM_ACTIVE_CONNECTION_STATE_DEACTIVATED  = 4,
} NMActiveConnectionState;

/**
 * NMActiveConnectionStateReason:
 * @NM_ACTIVE_CONNECTION_STATE_REASON_UNKNOWN: The reason for the active connection
 *   state change is unknown.
 * @NM_ACTIVE_CONNECTION_STATE_REASON_NONE: No reason was given for the active
 *   connection state change.
 * @NM_ACTIVE_CONNECTION_STATE_REASON_USER_DISCONNECTED: The active connection changed
 *   state because the user disconnected it.
 * @NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED: The active connection
 *   changed state because the device it was using was disconnected.
 * @NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_STOPPED: The service providing the
 *   VPN connection was stopped.
 * @NM_ACTIVE_CONNECTION_STATE_REASON_IP_CONFIG_INVALID: The IP config of the active
 *   connection was invalid.
 * @NM_ACTIVE_CONNECTION_STATE_REASON_CONNECT_TIMEOUT: The connection attempt to
 *   the VPN service timed out.
 * @NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT: A timeout occurred
 *   while starting the service providing the VPN connection.
 * @NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_FAILED: Starting the service
 *   providing the VPN connection failed.
 * @NM_ACTIVE_CONNECTION_STATE_REASON_NO_SECRETS: Necessary secrets for the
 *   connection were not provided.
 * @NM_ACTIVE_CONNECTION_STATE_REASON_LOGIN_FAILED: Authentication to the
 *   server failed.
 * @NM_ACTIVE_CONNECTION_STATE_REASON_CONNECTION_REMOVED: The connection was
 *   deleted from settings.
 * @NM_ACTIVE_CONNECTION_STATE_REASON_DEPENDENCY_FAILED: Master connection of this
 *   connection failed to activate.
 * @NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_REALIZE_FAILED: Could not create the
 *   software device link.
 * @NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_REMOVED: The device this connection
 *   depended on disappeared.
 *
 * Active connection state reasons.
 *
 * Since: 1.8
 */
NM_AVAILABLE_IN_1_8
typedef enum {
    NM_ACTIVE_CONNECTION_STATE_REASON_UNKNOWN               = 0,
    NM_ACTIVE_CONNECTION_STATE_REASON_NONE                  = 1,
    NM_ACTIVE_CONNECTION_STATE_REASON_USER_DISCONNECTED     = 2,
    NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED   = 3,
    NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_STOPPED       = 4,
    NM_ACTIVE_CONNECTION_STATE_REASON_IP_CONFIG_INVALID     = 5,
    NM_ACTIVE_CONNECTION_STATE_REASON_CONNECT_TIMEOUT       = 6,
    NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT = 7,
    NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_FAILED  = 8,
    NM_ACTIVE_CONNECTION_STATE_REASON_NO_SECRETS            = 9,
    NM_ACTIVE_CONNECTION_STATE_REASON_LOGIN_FAILED          = 10,
    NM_ACTIVE_CONNECTION_STATE_REASON_CONNECTION_REMOVED    = 11,
    NM_ACTIVE_CONNECTION_STATE_REASON_DEPENDENCY_FAILED     = 12,
    NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_REALIZE_FAILED = 13,
    NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_REMOVED        = 14,
} NMActiveConnectionStateReason;

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
 * @NM_SECRET_AGENT_GET_SECRETS_FLAG_WPS_PBC_ACTIVE: indicates that WPS enrollment
 *   is active with PBC method. The agent may suggest that the user pushes a button
 *   on the router instead of supplying a PSK.
 * @NM_SECRET_AGENT_GET_SECRETS_FLAG_ONLY_SYSTEM: Internal flag, not part of
 *   the D-Bus API.
 * @NM_SECRET_AGENT_GET_SECRETS_FLAG_NO_ERRORS: Internal flag, not part of
 *   the D-Bus API.
 *
 * #NMSecretAgentGetSecretsFlags values modify the behavior of a GetSecrets request.
 */
typedef enum { /*< flags >*/
               NM_SECRET_AGENT_GET_SECRETS_FLAG_NONE              = 0x0,
               NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION = 0x1,
               NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW       = 0x2,
               NM_SECRET_AGENT_GET_SECRETS_FLAG_USER_REQUESTED    = 0x4,
               NM_SECRET_AGENT_GET_SECRETS_FLAG_WPS_PBC_ACTIVE    = 0x8,

               /* Internal to NM; not part of the D-Bus API */
               NM_SECRET_AGENT_GET_SECRETS_FLAG_ONLY_SYSTEM = 0x80000000,
               NM_SECRET_AGENT_GET_SECRETS_FLAG_NO_ERRORS   = 0x40000000,
} NMSecretAgentGetSecretsFlags;

/**
 * NMSecretAgentCapabilities:
 * @NM_SECRET_AGENT_CAPABILITY_NONE: the agent supports no special capabilities
 * @NM_SECRET_AGENT_CAPABILITY_VPN_HINTS: the agent supports passing hints to
 * VPN plugin authentication dialogs.
 * @NM_SECRET_AGENT_CAPABILITY_LAST: bounds checking value; should not be used.
 *
 * #NMSecretAgentCapabilities indicate various capabilities of the agent.
 */
typedef enum /*< flags >*/ {
    NM_SECRET_AGENT_CAPABILITY_NONE      = 0x0,
    NM_SECRET_AGENT_CAPABILITY_VPN_HINTS = 0x1,

    /* boundary value */
    NM_SECRET_AGENT_CAPABILITY_LAST = NM_SECRET_AGENT_CAPABILITY_VPN_HINTS,
} NMSecretAgentCapabilities;

#ifndef NM_VERSION_H
#undef NM_AVAILABLE_IN_1_2
#undef NM_AVAILABLE_IN_1_8
#endif

#define NM_LLDP_ATTR_RAW                  "raw"
#define NM_LLDP_ATTR_DESTINATION          "destination"
#define NM_LLDP_ATTR_CHASSIS_ID_TYPE      "chassis-id-type"
#define NM_LLDP_ATTR_CHASSIS_ID           "chassis-id"
#define NM_LLDP_ATTR_PORT_ID_TYPE         "port-id-type"
#define NM_LLDP_ATTR_PORT_ID              "port-id"
#define NM_LLDP_ATTR_PORT_DESCRIPTION     "port-description"
#define NM_LLDP_ATTR_SYSTEM_NAME          "system-name"
#define NM_LLDP_ATTR_SYSTEM_DESCRIPTION   "system-description"
#define NM_LLDP_ATTR_SYSTEM_CAPABILITIES  "system-capabilities"
#define NM_LLDP_ATTR_MANAGEMENT_ADDRESSES "management-addresses"

#define NM_LLDP_ATTR_IEEE_802_1_PVID   "ieee-802-1-pvid"
#define NM_LLDP_ATTR_IEEE_802_1_VLANS  "ieee-802-1-vlans"
#define NM_LLDP_ATTR_IEEE_802_1_PPVIDS "ieee-802-1-ppvids"

#define NM_LLDP_ATTR_IEEE_802_3_MAC_PHY_CONF   "ieee-802-3-mac-phy-conf"
#define NM_LLDP_ATTR_IEEE_802_3_POWER_VIA_MDI  "ieee-802-3-power-via-mdi"
#define NM_LLDP_ATTR_IEEE_802_3_MAX_FRAME_SIZE "ieee-802-3-max-frame-size"

#define NM_LLDP_ATTR_MUD_URL "mud-url"

/* These are deprecated in favor of NM_LLDP_ATTR_IEEE_802_1_VLANS,
 * which can report multiple VLANs */
#define NM_LLDP_ATTR_IEEE_802_1_VID       "ieee-802-1-vid"
#define NM_LLDP_ATTR_IEEE_802_1_VLAN_NAME "ieee-802-1-vlan-name"

/* These are deprecated in favor of NM_LLDP_ATTR_IEEE_802_1_PPVIDS,
 * which can report multiple PPVIDs */
#define NM_LLDP_ATTR_IEEE_802_1_PPVID       "ieee-802-1-ppvid"
#define NM_LLDP_ATTR_IEEE_802_1_PPVID_FLAGS "ieee-802-1-ppvid-flags"

#define NM_LLDP_DEST_NEAREST_BRIDGE          "nearest-bridge"
#define NM_LLDP_DEST_NEAREST_NON_TPMR_BRIDGE "nearest-non-tpmr-bridge"
#define NM_LLDP_DEST_NEAREST_CUSTOMER_BRIDGE "nearest-customer-bridge"

/**
 * NMIPTunnelMode:
 * @NM_IP_TUNNEL_MODE_UNKNOWN:   Unknown/unset tunnel mode
 * @NM_IP_TUNNEL_MODE_IPIP:      IP in IP tunnel
 * @NM_IP_TUNNEL_MODE_GRE:       GRE tunnel
 * @NM_IP_TUNNEL_MODE_SIT:       SIT tunnel
 * @NM_IP_TUNNEL_MODE_ISATAP:    ISATAP tunnel
 * @NM_IP_TUNNEL_MODE_VTI:       VTI tunnel
 * @NM_IP_TUNNEL_MODE_IP6IP6:    IPv6 in IPv6 tunnel
 * @NM_IP_TUNNEL_MODE_IPIP6:     IPv4 in IPv6 tunnel
 * @NM_IP_TUNNEL_MODE_IP6GRE:    IPv6 GRE tunnel
 * @NM_IP_TUNNEL_MODE_VTI6:      IPv6 VTI tunnel
 * @NM_IP_TUNNEL_MODE_GRETAP:    GRETAP tunnel
 * @NM_IP_TUNNEL_MODE_IP6GRETAP: IPv6 GRETAP tunnel
 *
 * The tunneling mode.
 *
 * Since: 1.2
 */
typedef enum {
    NM_IP_TUNNEL_MODE_UNKNOWN   = 0,
    NM_IP_TUNNEL_MODE_IPIP      = 1,
    NM_IP_TUNNEL_MODE_GRE       = 2,
    NM_IP_TUNNEL_MODE_SIT       = 3,
    NM_IP_TUNNEL_MODE_ISATAP    = 4,
    NM_IP_TUNNEL_MODE_VTI       = 5,
    NM_IP_TUNNEL_MODE_IP6IP6    = 6,
    NM_IP_TUNNEL_MODE_IPIP6     = 7,
    NM_IP_TUNNEL_MODE_IP6GRE    = 8,
    NM_IP_TUNNEL_MODE_VTI6      = 9,
    NM_IP_TUNNEL_MODE_GRETAP    = 10,
    NM_IP_TUNNEL_MODE_IP6GRETAP = 11,
} NMIPTunnelMode;

/**
 * NMCheckpointCreateFlags:
 * @NM_CHECKPOINT_CREATE_FLAG_NONE: no flags
 * @NM_CHECKPOINT_CREATE_FLAG_DESTROY_ALL: when creating
 *   a new checkpoint, destroy all existing ones.
 * @NM_CHECKPOINT_CREATE_FLAG_DELETE_NEW_CONNECTIONS: upon rollback,
 *   delete any new connection added after the checkpoint. Since: 1.6.
 * @NM_CHECKPOINT_CREATE_FLAG_DISCONNECT_NEW_DEVICES: upon rollback,
 *   disconnect any new device appeared after the checkpoint. Since: 1.6.
 * @NM_CHECKPOINT_CREATE_FLAG_ALLOW_OVERLAPPING: by default, creating
 *   a checkpoint fails if there are already existing checkoints that
 *   reference the same devices. With this flag, creation of such
 *   checkpoints is allowed, however, if an older checkpoint
 *   that references overlapping devices gets rolled back, it will
 *   automatically destroy this checkpoint during rollback. This
 *   allows to create several overlapping checkpoints in parallel,
 *   and rollback to them at will. With the special case that
 *   rolling back to an older checkpoint will invalidate all
 *   overlapping younger checkpoints. This opts-in that the
 *   checkpoint can be automatically destroyed by the rollback
 *   of an older checkpoint. Since: 1.12.
 *
 * The flags for CheckpointCreate call
 *
 * Since: 1.4 (gi flags generated since 1.12)
 */
typedef enum { /*< flags >*/
               NM_CHECKPOINT_CREATE_FLAG_NONE                   = 0,
               NM_CHECKPOINT_CREATE_FLAG_DESTROY_ALL            = 0x01,
               NM_CHECKPOINT_CREATE_FLAG_DELETE_NEW_CONNECTIONS = 0x02,
               NM_CHECKPOINT_CREATE_FLAG_DISCONNECT_NEW_DEVICES = 0x04,
               NM_CHECKPOINT_CREATE_FLAG_ALLOW_OVERLAPPING      = 0x08,
} NMCheckpointCreateFlags;

/**
 * NMRollbackResult:
 * @NM_ROLLBACK_RESULT_OK: the rollback succeeded.
 * @NM_ROLLBACK_RESULT_ERR_NO_DEVICE: the device no longer exists.
 * @NM_ROLLBACK_RESULT_ERR_DEVICE_UNMANAGED: the device is now unmanaged.
 * @NM_ROLLBACK_RESULT_ERR_FAILED: other errors during rollback.
 *
 * The result of a checkpoint Rollback() operation for a specific device.
 *
 * Since: 1.4
 **/
typedef enum { /*< skip >*/
               NM_ROLLBACK_RESULT_OK                   = 0,
               NM_ROLLBACK_RESULT_ERR_NO_DEVICE        = 1,
               NM_ROLLBACK_RESULT_ERR_DEVICE_UNMANAGED = 2,
               NM_ROLLBACK_RESULT_ERR_FAILED           = 3,
} NMRollbackResult;

/**
 * NMSettingsConnectionFlags:
 * @NM_SETTINGS_CONNECTION_FLAG_NONE: an alias for numeric zero, no flags set.
 * @NM_SETTINGS_CONNECTION_FLAG_UNSAVED: the connection is not saved to disk.
 *   That either means, that the connection is in-memory only and currently
 *   is not backed by a file. Or, that the connection is backed by a file,
 *   but has modifications in-memory that were not persisted to disk.
 * @NM_SETTINGS_CONNECTION_FLAG_NM_GENERATED: A connection is "nm-generated" if
 *  it was generated by NetworkManger. If the connection gets modified or saved
 *  by the user, the flag gets cleared. A nm-generated is also unsaved
 *  and has no backing file as it is in-memory only.
 * @NM_SETTINGS_CONNECTION_FLAG_VOLATILE: The connection will be deleted
 *  when it disconnects. That is for in-memory connections (unsaved), which are
 *  currently active but deleted on disconnect. Volatile connections are
 *  always unsaved, but they are also no backing file on disk and are entirely
 *  in-memory only.
 * @NM_SETTINGS_CONNECTION_FLAG_EXTERNAL: the profile was generated to represent
 *  an external configuration of a networking device. Since: 1.26.
 *
 * Flags describing the current activation state.
 *
 * Since: 1.12
 **/
typedef enum { /*< flags >*/
               NM_SETTINGS_CONNECTION_FLAG_NONE         = 0,
               NM_SETTINGS_CONNECTION_FLAG_UNSAVED      = 0x01,
               NM_SETTINGS_CONNECTION_FLAG_NM_GENERATED = 0x02,
               NM_SETTINGS_CONNECTION_FLAG_VOLATILE     = 0x04,
               NM_SETTINGS_CONNECTION_FLAG_EXTERNAL     = 0x08,
} NMSettingsConnectionFlags;

/**
 * NMActivationStateFlags:
 * @NM_ACTIVATION_STATE_FLAG_NONE: an alias for numeric zero, no flags set.
 * @NM_ACTIVATION_STATE_FLAG_IS_MASTER: the device is a master.
 * @NM_ACTIVATION_STATE_FLAG_IS_SLAVE: the device is a slave.
 * @NM_ACTIVATION_STATE_FLAG_LAYER2_READY: layer2 is activated and ready.
 * @NM_ACTIVATION_STATE_FLAG_IP4_READY: IPv4 setting is completed.
 * @NM_ACTIVATION_STATE_FLAG_IP6_READY: IPv6 setting is completed.
 * @NM_ACTIVATION_STATE_FLAG_MASTER_HAS_SLAVES: The master has any slave devices attached.
 *   This only makes sense if the device is a master.
 * @NM_ACTIVATION_STATE_FLAG_LIFETIME_BOUND_TO_PROFILE_VISIBILITY: the lifetime
 *   of the activation is bound to the visibility of the connection profile,
 *   which in turn depends on "connection.permissions" and whether a session
 *   for the user exists. Since: 1.16.
 * @NM_ACTIVATION_STATE_FLAG_EXTERNAL: the active connection was generated to
 *  represent an external configuration of a networking device. Since: 1.26.
 *
 * Flags describing the current activation state.
 *
 * Since: 1.10
 **/
typedef enum { /*< flags >*/
               NM_ACTIVATION_STATE_FLAG_NONE = 0,

               NM_ACTIVATION_STATE_FLAG_IS_MASTER                            = 0x1,
               NM_ACTIVATION_STATE_FLAG_IS_SLAVE                             = 0x2,
               NM_ACTIVATION_STATE_FLAG_LAYER2_READY                         = 0x4,
               NM_ACTIVATION_STATE_FLAG_IP4_READY                            = 0x8,
               NM_ACTIVATION_STATE_FLAG_IP6_READY                            = 0x10,
               NM_ACTIVATION_STATE_FLAG_MASTER_HAS_SLAVES                    = 0x20,
               NM_ACTIVATION_STATE_FLAG_LIFETIME_BOUND_TO_PROFILE_VISIBILITY = 0x40,
               NM_ACTIVATION_STATE_FLAG_EXTERNAL                             = 0x80,
} NMActivationStateFlags;

/**
 * NMSettingsAddConnection2Flags:
 * @NM_SETTINGS_ADD_CONNECTION2_FLAG_NONE: an alias for numeric zero, no flags set.
 * @NM_SETTINGS_ADD_CONNECTION2_FLAG_TO_DISK: to persist the connection to disk.
 * @NM_SETTINGS_ADD_CONNECTION2_FLAG_IN_MEMORY: to make the connection in-memory only.
 * @NM_SETTINGS_ADD_CONNECTION2_FLAG_BLOCK_AUTOCONNECT: usually, when the connection
 *   has autoconnect enabled and gets added, it becomes eligible to autoconnect
 *   right away. Setting this flag, disables autoconnect until the connection
 *   is manually activated.
 *
 * Numeric flags for the "flags" argument of AddConnection2() D-Bus API.
 *
 * Since: 1.20
 */
typedef enum { /*< flags >*/
               NM_SETTINGS_ADD_CONNECTION2_FLAG_NONE              = 0,
               NM_SETTINGS_ADD_CONNECTION2_FLAG_TO_DISK           = 0x1,
               NM_SETTINGS_ADD_CONNECTION2_FLAG_IN_MEMORY         = 0x2,
               NM_SETTINGS_ADD_CONNECTION2_FLAG_BLOCK_AUTOCONNECT = 0x20,
} NMSettingsAddConnection2Flags;

/**
 * NMSettingsUpdate2Flags:
 * @NM_SETTINGS_UPDATE2_FLAG_NONE: an alias for numeric zero, no flags set.
 * @NM_SETTINGS_UPDATE2_FLAG_TO_DISK: to persist the connection to disk.
 * @NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY: makes the profile in-memory.
 *   Note that such profiles are stored in keyfile format under /run.
 *   If the file is already in-memory, the file in /run is updated in-place.
 *   Otherwise, the previous storage for the profile is left unchanged
 *   on disk, and the in-memory copy shadows it.
 *   Note that the original filename of the previous persistent storage (if any)
 *   is remembered. That means, when later persisting the profile again to disk,
 *   the file on disk will be overwritten again.
 *   Likewise, when finally deleting the profile, both the storage from /run
 *   and persistent storage are deleted (or if the persistent storage does not
 *   allow deletion, and nmmeta file is written to mark the UUID as deleted).
 * @NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY_DETACHED: this is almost the same
 *   as %NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY, with one difference: when later deleting
 *   the profile, the original profile will not be deleted. Instead a nmmeta
 *   file is written to /run to indicate that the profile is gone.
 *   Note that if such a nmmeta tombstone file exists and hides a file in persistent
 *   storage, then when re-adding the profile with the same UUID, then the original
 *   storage is taken over again.
 * @NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY_ONLY: this is like %NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY,
 *   but if the connection has a corresponding file on persistent storage, the file
 *   will be deleted right away. If the profile is later again persisted to disk,
 *   a new, unused filename will be chosen.
 * @NM_SETTINGS_UPDATE2_FLAG_VOLATILE: This can be specified with either
 *   %NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY, %NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY_DETACHED
 *   or %NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY_ONLY.
 *   After making the connection in-memory only, the connection is marked
 *   as volatile. That means, if the connection is currently not active
 *   it will be deleted right away. Otherwise, it is marked to for deletion
 *   once the connection deactivates. A volatile connection cannot autoactivate
 *   again (because it's about to be deleted), but a manual activation will
 *   clear the volatile flag.
 * @NM_SETTINGS_UPDATE2_FLAG_BLOCK_AUTOCONNECT: usually, when the connection
 *   has autoconnect enabled and is modified, it becomes eligible to autoconnect
 *   right away. Setting this flag, disables autoconnect until the connection
 *   is manually activated.
 * @NM_SETTINGS_UPDATE2_FLAG_NO_REAPPLY: when a profile gets modified that is
 *   currently active, then these changes don't take effect for the active
 *   device unless the profile gets reactivated or the configuration reapplied.
 *   There are two exceptions: by default "connection.zone" and "connection.metered"
 *   properties take effect immediately. Specify this flag to prevent these
 *   properties to take effect, so that the change is restricted to modify
 *   the profile. Since: 1.20.
 *
 * Since: 1.12
 */
typedef enum { /*< flags >*/
               NM_SETTINGS_UPDATE2_FLAG_NONE               = 0,
               NM_SETTINGS_UPDATE2_FLAG_TO_DISK            = 0x1,
               NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY          = 0x2,
               NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY_DETACHED = 0x4,
               NM_SETTINGS_UPDATE2_FLAG_IN_MEMORY_ONLY     = 0x8,
               NM_SETTINGS_UPDATE2_FLAG_VOLATILE           = 0x10,
               NM_SETTINGS_UPDATE2_FLAG_BLOCK_AUTOCONNECT  = 0x20,
               NM_SETTINGS_UPDATE2_FLAG_NO_REAPPLY         = 0x40,
} NMSettingsUpdate2Flags;

/**
 * NMTernary:
 * @NM_TERNARY_DEFAULT: use the globally-configured default value.
 * @NM_TERNARY_FALSE: the option is disabled.
 * @NM_TERNARY_TRUE: the option is enabled.
 *
 * An boolean value that can be overridden by a default.
 *
 * Since: 1.14
 **/
typedef enum {
    NM_TERNARY_DEFAULT = -1,
    NM_TERNARY_FALSE   = 0,
    NM_TERNARY_TRUE    = 1,
} NMTernary;

/**
 * NMManagerReloadFlags:
 * @NM_MANAGER_RELOAD_FLAG_NONE: an alias for numeric zero, no flags set. This
 *   reloads everything that is supported and is identical to a SIGHUP.
 * @NM_MANAGER_RELOAD_FLAG_CONF: reload the NetworkManager.conf configuration
 *   from disk. Note that this does not include connections, which can be
 *   reloaded via Setting's ReloadConnections().
 * @NM_MANAGER_RELOAD_FLAG_DNS_RC: update DNS configuration, which usually
 *   involves writing /etc/resolv.conf anew.
 * @NM_MANAGER_RELOAD_FLAG_DNS_FULL: means to restart the DNS plugin. This
 *   is for example useful when using dnsmasq plugin, which uses additional
 *   configuration in /etc/NetworkManager/dnsmasq.d. If you edit those files,
 *   you can restart the DNS plugin. This action shortly interrupts name
 *   resolution.
 * @NM_MANAGER_RELOAD_FLAG_ALL: all flags.
 *
 * Flags for the manager Reload() call.
 *
 * Since: 1.22
 */
typedef enum {                                      /*< flags >*/
               NM_MANAGER_RELOAD_FLAG_NONE     = 0, /*< skip >*/
               NM_MANAGER_RELOAD_FLAG_CONF     = 0x1,
               NM_MANAGER_RELOAD_FLAG_DNS_RC   = 0x2,
               NM_MANAGER_RELOAD_FLAG_DNS_FULL = 0x4,
               NM_MANAGER_RELOAD_FLAG_ALL      = 0x7, /*< skip >*/
} NMManagerReloadFlags;

/**
 * NMDeviceInterfaceFlags:
 * @NM_DEVICE_INTERFACE_FLAG_NONE: an alias for numeric zero, no flags set.
 * @NM_DEVICE_INTERFACE_FLAG_UP: the interface is enabled from the
 *   administrative point of view. Corresponds to kernel IFF_UP.
 * @NM_DEVICE_INTERFACE_FLAG_LOWER_UP: the physical link is up. Corresponds
 *   to kernel IFF_LOWER_UP.
 * @NM_DEVICE_INTERFACE_FLAG_PROMISC: receive all packets. Corresponds to
 *   kernel IFF_PROMISC. Since: 1.32.
 * @NM_DEVICE_INTERFACE_FLAG_CARRIER: the interface has carrier. In most
 *   cases this is equal to the value of @NM_DEVICE_INTERFACE_FLAG_LOWER_UP.
 *   However some devices have a non-standard carrier detection mechanism.
 * @NM_DEVICE_INTERFACE_FLAG_LLDP_CLIENT_ENABLED: the flag to indicate device
 *   LLDP status. Since: 1.32.
 *
 * Flags for a network interface.
 *
 * Since: 1.22
 */
typedef enum { /*< flags >*/
               /* kernel flags */
               NM_DEVICE_INTERFACE_FLAG_NONE     = 0, /*< skip >*/
               NM_DEVICE_INTERFACE_FLAG_UP       = 0x1,
               NM_DEVICE_INTERFACE_FLAG_LOWER_UP = 0x2,
               NM_DEVICE_INTERFACE_FLAG_PROMISC  = 0x4,
               /* NM-specific flags */
               NM_DEVICE_INTERFACE_FLAG_CARRIER             = 0x10000,
               NM_DEVICE_INTERFACE_FLAG_LLDP_CLIENT_ENABLED = 0x20000,
} NMDeviceInterfaceFlags;

/**
 * NMClientPermission:
 * @NM_CLIENT_PERMISSION_NONE: unknown or no permission
 * @NM_CLIENT_PERMISSION_ENABLE_DISABLE_NETWORK: controls whether networking
 *  can be globally enabled or disabled
 * @NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIFI: controls whether Wi-Fi can be
 *  globally enabled or disabled
 * @NM_CLIENT_PERMISSION_ENABLE_DISABLE_WWAN: controls whether WWAN (3G) can be
 *  globally enabled or disabled
 * @NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIMAX: controls whether WiMAX can be
 *  globally enabled or disabled
 * @NM_CLIENT_PERMISSION_SLEEP_WAKE: controls whether the client can ask
 *  NetworkManager to sleep and wake
 * @NM_CLIENT_PERMISSION_NETWORK_CONTROL: controls whether networking connections
 *  can be started, stopped, and changed
 * @NM_CLIENT_PERMISSION_WIFI_SHARE_PROTECTED: controls whether a password
 *  protected Wi-Fi hotspot can be created
 * @NM_CLIENT_PERMISSION_WIFI_SHARE_OPEN: controls whether an open Wi-Fi hotspot
 *  can be created
 * @NM_CLIENT_PERMISSION_SETTINGS_MODIFY_SYSTEM: controls whether connections
 *  that are available to all users can be modified
 * @NM_CLIENT_PERMISSION_SETTINGS_MODIFY_OWN: controls whether connections
 *  owned by the current user can be modified
 * @NM_CLIENT_PERMISSION_SETTINGS_MODIFY_HOSTNAME: controls whether the
 *  persistent hostname can be changed
 * @NM_CLIENT_PERMISSION_SETTINGS_MODIFY_GLOBAL_DNS: modify persistent global
 *  DNS configuration
 * @NM_CLIENT_PERMISSION_RELOAD: controls access to Reload.
 * @NM_CLIENT_PERMISSION_CHECKPOINT_ROLLBACK: permission to create checkpoints.
 * @NM_CLIENT_PERMISSION_ENABLE_DISABLE_STATISTICS: controls whether device
 *  statistics can be globally enabled or disabled
 * @NM_CLIENT_PERMISSION_ENABLE_DISABLE_CONNECTIVITY_CHECK: controls whether
 *  connectivity check can be enabled or disabled
 * @NM_CLIENT_PERMISSION_WIFI_SCAN: controls whether wifi scans can be performed
 * @NM_CLIENT_PERMISSION_LAST: a reserved boundary value
 *
 * #NMClientPermission values indicate various permissions that NetworkManager
 * clients can obtain to perform certain tasks on behalf of the current user.
 **/
typedef enum {
    NM_CLIENT_PERMISSION_NONE                              = 0,
    NM_CLIENT_PERMISSION_ENABLE_DISABLE_NETWORK            = 1,
    NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIFI               = 2,
    NM_CLIENT_PERMISSION_ENABLE_DISABLE_WWAN               = 3,
    NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIMAX              = 4,
    NM_CLIENT_PERMISSION_SLEEP_WAKE                        = 5,
    NM_CLIENT_PERMISSION_NETWORK_CONTROL                   = 6,
    NM_CLIENT_PERMISSION_WIFI_SHARE_PROTECTED              = 7,
    NM_CLIENT_PERMISSION_WIFI_SHARE_OPEN                   = 8,
    NM_CLIENT_PERMISSION_SETTINGS_MODIFY_SYSTEM            = 9,
    NM_CLIENT_PERMISSION_SETTINGS_MODIFY_OWN               = 10,
    NM_CLIENT_PERMISSION_SETTINGS_MODIFY_HOSTNAME          = 11,
    NM_CLIENT_PERMISSION_SETTINGS_MODIFY_GLOBAL_DNS        = 12,
    NM_CLIENT_PERMISSION_RELOAD                            = 13,
    NM_CLIENT_PERMISSION_CHECKPOINT_ROLLBACK               = 14,
    NM_CLIENT_PERMISSION_ENABLE_DISABLE_STATISTICS         = 15,
    NM_CLIENT_PERMISSION_ENABLE_DISABLE_CONNECTIVITY_CHECK = 16,
    NM_CLIENT_PERMISSION_WIFI_SCAN                         = 17,

    NM_CLIENT_PERMISSION_LAST = 17,
} NMClientPermission;

/**
 * NMClientPermissionResult:
 * @NM_CLIENT_PERMISSION_RESULT_UNKNOWN: unknown or no authorization
 * @NM_CLIENT_PERMISSION_RESULT_YES: the permission is available
 * @NM_CLIENT_PERMISSION_RESULT_AUTH: authorization is necessary before the
 *  permission is available
 * @NM_CLIENT_PERMISSION_RESULT_NO: permission to perform the operation is
 *  denied by system policy
 *
 * #NMClientPermissionResult values indicate what authorizations and permissions
 * the user requires to obtain a given #NMClientPermission
 **/
typedef enum {
    NM_CLIENT_PERMISSION_RESULT_UNKNOWN = 0,
    NM_CLIENT_PERMISSION_RESULT_YES,
    NM_CLIENT_PERMISSION_RESULT_AUTH,
    NM_CLIENT_PERMISSION_RESULT_NO
} NMClientPermissionResult;

#endif /* __NM_DBUS_INTERFACE_H__ */
