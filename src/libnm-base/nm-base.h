/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_LIBNM_BASE_H__
#define __NM_LIBNM_BASE_H__

/*****************************************************************************/

/* this must be the same as NM_UTILS_HWADDR_LEN_MAX from libnm. */
#define _NM_UTILS_HWADDR_LEN_MAX 20

#define _NM_MAX_CLIENT_ID_LEN (sizeof(guint32) + 128)

enum {
    NM_DNS_PRIORITY_DEFAULT_NORMAL = 100,
    NM_DNS_PRIORITY_DEFAULT_VPN    = 50,
};

/*****************************************************************************/

typedef enum {
    NM_ETHTOOL_ID_UNKNOWN = -1,

    _NM_ETHTOOL_ID_FIRST = 0,

    _NM_ETHTOOL_ID_COALESCE_FIRST      = _NM_ETHTOOL_ID_FIRST,
    NM_ETHTOOL_ID_COALESCE_ADAPTIVE_RX = _NM_ETHTOOL_ID_COALESCE_FIRST,
    NM_ETHTOOL_ID_COALESCE_ADAPTIVE_TX,
    NM_ETHTOOL_ID_COALESCE_PKT_RATE_HIGH,
    NM_ETHTOOL_ID_COALESCE_PKT_RATE_LOW,
    NM_ETHTOOL_ID_COALESCE_RX_FRAMES,
    NM_ETHTOOL_ID_COALESCE_RX_FRAMES_HIGH,
    NM_ETHTOOL_ID_COALESCE_RX_FRAMES_IRQ,
    NM_ETHTOOL_ID_COALESCE_RX_FRAMES_LOW,
    NM_ETHTOOL_ID_COALESCE_RX_USECS,
    NM_ETHTOOL_ID_COALESCE_RX_USECS_HIGH,
    NM_ETHTOOL_ID_COALESCE_RX_USECS_IRQ,
    NM_ETHTOOL_ID_COALESCE_RX_USECS_LOW,
    NM_ETHTOOL_ID_COALESCE_SAMPLE_INTERVAL,
    NM_ETHTOOL_ID_COALESCE_STATS_BLOCK_USECS,
    NM_ETHTOOL_ID_COALESCE_TX_FRAMES,
    NM_ETHTOOL_ID_COALESCE_TX_FRAMES_HIGH,
    NM_ETHTOOL_ID_COALESCE_TX_FRAMES_IRQ,
    NM_ETHTOOL_ID_COALESCE_TX_FRAMES_LOW,
    NM_ETHTOOL_ID_COALESCE_TX_USECS,
    NM_ETHTOOL_ID_COALESCE_TX_USECS_HIGH,
    NM_ETHTOOL_ID_COALESCE_TX_USECS_IRQ,
    NM_ETHTOOL_ID_COALESCE_TX_USECS_LOW,
    _NM_ETHTOOL_ID_COALESCE_LAST = NM_ETHTOOL_ID_COALESCE_TX_USECS_LOW,

    _NM_ETHTOOL_ID_FEATURE_FIRST         = _NM_ETHTOOL_ID_COALESCE_LAST + 1,
    NM_ETHTOOL_ID_FEATURE_ESP_HW_OFFLOAD = _NM_ETHTOOL_ID_FEATURE_FIRST,
    NM_ETHTOOL_ID_FEATURE_ESP_TX_CSUM_HW_OFFLOAD,
    NM_ETHTOOL_ID_FEATURE_FCOE_MTU,
    NM_ETHTOOL_ID_FEATURE_GRO,
    NM_ETHTOOL_ID_FEATURE_GSO,
    NM_ETHTOOL_ID_FEATURE_HIGHDMA,
    NM_ETHTOOL_ID_FEATURE_HW_TC_OFFLOAD,
    NM_ETHTOOL_ID_FEATURE_L2_FWD_OFFLOAD,
    NM_ETHTOOL_ID_FEATURE_LOOPBACK,
    NM_ETHTOOL_ID_FEATURE_LRO,
    NM_ETHTOOL_ID_FEATURE_MACSEC_HW_OFFLOAD,
    NM_ETHTOOL_ID_FEATURE_NTUPLE,
    NM_ETHTOOL_ID_FEATURE_RX,
    NM_ETHTOOL_ID_FEATURE_RXHASH,
    NM_ETHTOOL_ID_FEATURE_RXVLAN,
    NM_ETHTOOL_ID_FEATURE_RX_ALL,
    NM_ETHTOOL_ID_FEATURE_RX_FCS,
    NM_ETHTOOL_ID_FEATURE_RX_GRO_HW,
    NM_ETHTOOL_ID_FEATURE_RX_GRO_LIST,
    NM_ETHTOOL_ID_FEATURE_RX_UDP_GRO_FORWARDING,
    NM_ETHTOOL_ID_FEATURE_RX_UDP_TUNNEL_PORT_OFFLOAD,
    NM_ETHTOOL_ID_FEATURE_RX_VLAN_FILTER,
    NM_ETHTOOL_ID_FEATURE_RX_VLAN_STAG_FILTER,
    NM_ETHTOOL_ID_FEATURE_RX_VLAN_STAG_HW_PARSE,
    NM_ETHTOOL_ID_FEATURE_SG,
    NM_ETHTOOL_ID_FEATURE_TLS_HW_RECORD,
    NM_ETHTOOL_ID_FEATURE_TLS_HW_RX_OFFLOAD,
    NM_ETHTOOL_ID_FEATURE_TLS_HW_TX_OFFLOAD,
    NM_ETHTOOL_ID_FEATURE_TSO,
    NM_ETHTOOL_ID_FEATURE_TX,
    NM_ETHTOOL_ID_FEATURE_TXVLAN,
    NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_FCOE_CRC,
    NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_IPV4,
    NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_IPV6,
    NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_IP_GENERIC,
    NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_SCTP,
    NM_ETHTOOL_ID_FEATURE_TX_ESP_SEGMENTATION,
    NM_ETHTOOL_ID_FEATURE_TX_FCOE_SEGMENTATION,
    NM_ETHTOOL_ID_FEATURE_TX_GRE_CSUM_SEGMENTATION,
    NM_ETHTOOL_ID_FEATURE_TX_GRE_SEGMENTATION,
    NM_ETHTOOL_ID_FEATURE_TX_GSO_LIST,
    NM_ETHTOOL_ID_FEATURE_TX_GSO_PARTIAL,
    NM_ETHTOOL_ID_FEATURE_TX_GSO_ROBUST,
    NM_ETHTOOL_ID_FEATURE_TX_IPXIP4_SEGMENTATION,
    NM_ETHTOOL_ID_FEATURE_TX_IPXIP6_SEGMENTATION,
    NM_ETHTOOL_ID_FEATURE_TX_NOCACHE_COPY,
    NM_ETHTOOL_ID_FEATURE_TX_SCATTER_GATHER,
    NM_ETHTOOL_ID_FEATURE_TX_SCATTER_GATHER_FRAGLIST,
    NM_ETHTOOL_ID_FEATURE_TX_SCTP_SEGMENTATION,
    NM_ETHTOOL_ID_FEATURE_TX_TCP6_SEGMENTATION,
    NM_ETHTOOL_ID_FEATURE_TX_TCP_ECN_SEGMENTATION,
    NM_ETHTOOL_ID_FEATURE_TX_TCP_MANGLEID_SEGMENTATION,
    NM_ETHTOOL_ID_FEATURE_TX_TCP_SEGMENTATION,
    NM_ETHTOOL_ID_FEATURE_TX_TUNNEL_REMCSUM_SEGMENTATION,
    NM_ETHTOOL_ID_FEATURE_TX_UDP_SEGMENTATION,
    NM_ETHTOOL_ID_FEATURE_TX_UDP_TNL_CSUM_SEGMENTATION,
    NM_ETHTOOL_ID_FEATURE_TX_UDP_TNL_SEGMENTATION,
    NM_ETHTOOL_ID_FEATURE_TX_VLAN_STAG_HW_INSERT,
    _NM_ETHTOOL_ID_FEATURE_LAST = NM_ETHTOOL_ID_FEATURE_TX_VLAN_STAG_HW_INSERT,

    _NM_ETHTOOL_ID_PAUSE_FIRST  = _NM_ETHTOOL_ID_FEATURE_LAST + 1,
    NM_ETHTOOL_ID_PAUSE_AUTONEG = _NM_ETHTOOL_ID_PAUSE_FIRST,
    NM_ETHTOOL_ID_PAUSE_RX,
    NM_ETHTOOL_ID_PAUSE_TX,
    _NM_ETHTOOL_ID_PAUSE_LAST = NM_ETHTOOL_ID_PAUSE_TX,

    _NM_ETHTOOL_ID_EEE_FIRST  = _NM_ETHTOOL_ID_PAUSE_LAST + 1,
    NM_ETHTOOL_ID_EEE_ENABLED = _NM_ETHTOOL_ID_EEE_FIRST,
    _NM_ETHTOOL_ID_EEE_LAST   = NM_ETHTOOL_ID_EEE_ENABLED,

    _NM_ETHTOOL_ID_RING_FIRST = _NM_ETHTOOL_ID_EEE_LAST + 1,
    NM_ETHTOOL_ID_RING_RX     = _NM_ETHTOOL_ID_RING_FIRST,
    NM_ETHTOOL_ID_RING_RX_JUMBO,
    NM_ETHTOOL_ID_RING_RX_MINI,
    NM_ETHTOOL_ID_RING_TX,
    _NM_ETHTOOL_ID_RING_LAST = NM_ETHTOOL_ID_RING_TX,

    _NM_ETHTOOL_ID_CHANNELS_FIRST = _NM_ETHTOOL_ID_RING_LAST + 1,
    NM_ETHTOOL_ID_CHANNELS_RX     = _NM_ETHTOOL_ID_CHANNELS_FIRST,
    NM_ETHTOOL_ID_CHANNELS_TX,
    NM_ETHTOOL_ID_CHANNELS_OTHER,
    NM_ETHTOOL_ID_CHANNELS_COMBINED,
    _NM_ETHTOOL_ID_CHANNELS_LAST = NM_ETHTOOL_ID_CHANNELS_COMBINED,

    _NM_ETHTOOL_ID_FEC_FIRST = _NM_ETHTOOL_ID_CHANNELS_LAST + 1,
    NM_ETHTOOL_ID_FEC_MODE   = _NM_ETHTOOL_ID_FEC_FIRST,
    _NM_ETHTOOL_ID_FEC_LAST  = NM_ETHTOOL_ID_FEC_MODE,

    _NM_ETHTOOL_ID_LAST = _NM_ETHTOOL_ID_FEC_LAST,

    _NM_ETHTOOL_ID_COALESCE_NUM =
        (_NM_ETHTOOL_ID_COALESCE_LAST - _NM_ETHTOOL_ID_COALESCE_FIRST + 1),
    _NM_ETHTOOL_ID_FEATURE_NUM = (_NM_ETHTOOL_ID_FEATURE_LAST - _NM_ETHTOOL_ID_FEATURE_FIRST + 1),
    _NM_ETHTOOL_ID_RING_NUM    = (_NM_ETHTOOL_ID_RING_LAST - _NM_ETHTOOL_ID_RING_FIRST + 1),
    _NM_ETHTOOL_ID_PAUSE_NUM   = (_NM_ETHTOOL_ID_PAUSE_LAST - _NM_ETHTOOL_ID_PAUSE_FIRST + 1),
    _NM_ETHTOOL_ID_CHANNELS_NUM =
        (_NM_ETHTOOL_ID_CHANNELS_LAST - _NM_ETHTOOL_ID_CHANNELS_FIRST + 1),
    _NM_ETHTOOL_ID_NUM = (_NM_ETHTOOL_ID_LAST - _NM_ETHTOOL_ID_FIRST + 1),
} NMEthtoolID;

#define _NM_ETHTOOL_ID_FEATURE_AS_IDX(ethtool_id)  ((ethtool_id) - _NM_ETHTOOL_ID_FEATURE_FIRST)
#define _NM_ETHTOOL_ID_COALESCE_AS_IDX(ethtool_id) ((ethtool_id) - _NM_ETHTOOL_ID_COALESCE_FIRST)

typedef enum {
    NM_ETHTOOL_TYPE_UNKNOWN,
    NM_ETHTOOL_TYPE_COALESCE,
    NM_ETHTOOL_TYPE_FEATURE,
    NM_ETHTOOL_TYPE_RING,
    NM_ETHTOOL_TYPE_PAUSE,
    NM_ETHTOOL_TYPE_CHANNELS,
    NM_ETHTOOL_TYPE_EEE,
    NM_ETHTOOL_TYPE_FEC,
} NMEthtoolType;

/****************************************************************************/

static inline gboolean
nm_ethtool_id_is_feature(NMEthtoolID id)
{
    return id >= _NM_ETHTOOL_ID_FEATURE_FIRST && id <= _NM_ETHTOOL_ID_FEATURE_LAST;
}

static inline gboolean
nm_ethtool_id_is_coalesce(NMEthtoolID id)
{
    return id >= _NM_ETHTOOL_ID_COALESCE_FIRST && id <= _NM_ETHTOOL_ID_COALESCE_LAST;
}

static inline gboolean
nm_ethtool_id_is_ring(NMEthtoolID id)
{
    return id >= _NM_ETHTOOL_ID_RING_FIRST && id <= _NM_ETHTOOL_ID_RING_LAST;
}

static inline gboolean
nm_ethtool_id_is_pause(NMEthtoolID id)
{
    return id >= _NM_ETHTOOL_ID_PAUSE_FIRST && id <= _NM_ETHTOOL_ID_PAUSE_LAST;
}

static inline gboolean
nm_ethtool_id_is_channels(NMEthtoolID id)
{
    return id >= _NM_ETHTOOL_ID_CHANNELS_FIRST && id <= _NM_ETHTOOL_ID_CHANNELS_LAST;
}

static inline gboolean
nm_ethtool_id_is_eee(NMEthtoolID id)
{
    return id >= _NM_ETHTOOL_ID_EEE_FIRST && id <= _NM_ETHTOOL_ID_EEE_LAST;
}

static inline gboolean
nm_ethtool_id_is_fec(NMEthtoolID id)
{
    return id >= _NM_ETHTOOL_ID_FEC_FIRST && id <= _NM_ETHTOOL_ID_FEC_LAST;
}

/*****************************************************************************/

typedef enum {
    /* Mirrors libnm's NMSettingWiredWakeOnLan */
    _NM_SETTING_WIRED_WAKE_ON_LAN_NONE      = 0,
    _NM_SETTING_WIRED_WAKE_ON_LAN_PHY       = 0x2,
    _NM_SETTING_WIRED_WAKE_ON_LAN_UNICAST   = 0x4,
    _NM_SETTING_WIRED_WAKE_ON_LAN_MULTICAST = 0x8,
    _NM_SETTING_WIRED_WAKE_ON_LAN_BROADCAST = 0x10,
    _NM_SETTING_WIRED_WAKE_ON_LAN_ARP       = 0x20,
    _NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC     = 0x40,

    _NM_SETTING_WIRED_WAKE_ON_LAN_ALL = 0x7E,

    _NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT         = 0x1,
    _NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE          = 0x8000,
    _NM_SETTING_WIRED_WAKE_ON_LAN_EXCLUSIVE_FLAGS = 0x8001,
} _NMSettingWiredWakeOnLan;

typedef enum {
    /* Mirrors libnm's NMSettingWirelessWakeOnWLan */
    _NM_SETTING_WIRELESS_WAKE_ON_WLAN_NONE                 = 0,
    _NM_SETTING_WIRELESS_WAKE_ON_WLAN_ANY                  = 0x2,
    _NM_SETTING_WIRELESS_WAKE_ON_WLAN_DISCONNECT           = 0x4,
    _NM_SETTING_WIRELESS_WAKE_ON_WLAN_MAGIC                = 0x8,
    _NM_SETTING_WIRELESS_WAKE_ON_WLAN_GTK_REKEY_FAILURE    = 0x10,
    _NM_SETTING_WIRELESS_WAKE_ON_WLAN_EAP_IDENTITY_REQUEST = 0x20,
    _NM_SETTING_WIRELESS_WAKE_ON_WLAN_4WAY_HANDSHAKE       = 0x40,
    _NM_SETTING_WIRELESS_WAKE_ON_WLAN_RFKILL_RELEASE       = 0x80,
    _NM_SETTING_WIRELESS_WAKE_ON_WLAN_TCP                  = 0x100,

    _NM_SETTING_WIRELESS_WAKE_ON_WLAN_ALL = 0x1FE,

    _NM_SETTING_WIRELESS_WAKE_ON_WLAN_DEFAULT = 0x1,
    _NM_SETTING_WIRELESS_WAKE_ON_WLAN_IGNORE  = 0x8000,

    _NM_SETTING_WIRELESS_WAKE_ON_WLAN_EXCLUSIVE_FLAGS =
        _NM_SETTING_WIRELESS_WAKE_ON_WLAN_DEFAULT | _NM_SETTING_WIRELESS_WAKE_ON_WLAN_IGNORE,
} _NMSettingWirelessWakeOnWLan;

typedef enum {
    /* Mirrors libnm's NMDeviceWifiCapabilities */
    _NM_WIFI_DEVICE_CAP_NONE          = 0x00000000,
    _NM_WIFI_DEVICE_CAP_CIPHER_WEP40  = 0x00000001,
    _NM_WIFI_DEVICE_CAP_CIPHER_WEP104 = 0x00000002,
    _NM_WIFI_DEVICE_CAP_CIPHER_TKIP   = 0x00000004,
    _NM_WIFI_DEVICE_CAP_CIPHER_CCMP   = 0x00000008,
    _NM_WIFI_DEVICE_CAP_WPA           = 0x00000010,
    _NM_WIFI_DEVICE_CAP_RSN           = 0x00000020,
    _NM_WIFI_DEVICE_CAP_AP            = 0x00000040,
    _NM_WIFI_DEVICE_CAP_ADHOC         = 0x00000080,
    _NM_WIFI_DEVICE_CAP_FREQ_VALID    = 0x00000100,
    _NM_WIFI_DEVICE_CAP_FREQ_2GHZ     = 0x00000200,
    _NM_WIFI_DEVICE_CAP_FREQ_5GHZ     = 0x00000400,
    _NM_WIFI_DEVICE_CAP_FREQ_6GHZ     = 0x00000800,
    _NM_WIFI_DEVICE_CAP_MESH          = 0x00001000,
    _NM_WIFI_DEVICE_CAP_IBSS_RSN      = 0x00002000,
} _NMDeviceWifiCapabilities;

typedef enum {
    /* Mirrors libnm's NM80211Mode */
    _NM_802_11_MODE_UNKNOWN = 0,
    _NM_802_11_MODE_ADHOC   = 1,
    _NM_802_11_MODE_INFRA   = 2,
    _NM_802_11_MODE_AP      = 3,
    _NM_802_11_MODE_MESH    = 4,
} _NM80211Mode;

typedef enum {
    /* Mirrors libnm's NMVlanFlags */
    _NM_VLAN_FLAG_REORDER_HEADERS = 0x1,
    _NM_VLAN_FLAG_GVRP            = 0x2,
    _NM_VLAN_FLAG_LOOSE_BINDING   = 0x4,
    _NM_VLAN_FLAG_MVRP            = 0x8,

    _NM_VLAN_FLAGS_ALL = _NM_VLAN_FLAG_REORDER_HEADERS | _NM_VLAN_FLAG_GVRP
                         | _NM_VLAN_FLAG_LOOSE_BINDING | _NM_VLAN_FLAG_MVRP,
} _NMVlanFlags;

typedef enum {
    /* Mirrors libnm's NMSriovEswitchMode.
     * Values >= 0 mirror kernel's enum devlink_eswitch_mode. */
    _NM_SRIOV_ESWITCH_MODE_PRESERVE  = -1,
    _NM_SRIOV_ESWITCH_MODE_UNKNOWN   = -1, /*< skip >*/
    _NM_SRIOV_ESWITCH_MODE_LEGACY    = 0,
    _NM_SRIOV_ESWITCH_MODE_SWITCHDEV = 1,
} _NMSriovEswitchMode;

typedef enum {
    /* Mirrors libnm's NMSriovEswitchInlineMode.
     * Values >= 0 mirror kernel's enum devlink_eswitch_inline_mode. */
    _NM_SRIOV_ESWITCH_INLINE_MODE_PRESERVE  = -1,
    _NM_SRIOV_ESWITCH_INLINE_MODE_UNKNOWN   = -1, /*< skip >*/
    _NM_SRIOV_ESWITCH_INLINE_MODE_NONE      = 0,
    _NM_SRIOV_ESWITCH_INLINE_MODE_LINK      = 1,
    _NM_SRIOV_ESWITCH_INLINE_MODE_NETWORK   = 2,
    _NM_SRIOV_ESWITCH_INLINE_MODE_TRANSPORT = 3,
} _NMSriovEswitchInlineMode;

typedef enum {
    /* Mirrors libnm's NMSriovEswitchEncapMode.
     * Values >= 0 mirror kernel's enum devlink_eswitch_encap_mode. */
    _NM_SRIOV_ESWITCH_ENCAP_MODE_PRESERVE = -1,
    _NM_SRIOV_ESWITCH_ENCAP_MODE_UNKNOWN  = -1, /*< skip >*/
    _NM_SRIOV_ESWITCH_ENCAP_MODE_NONE     = 0,
    _NM_SRIOV_ESWITCH_ENCAP_MODE_BASIC    = 1,
} _NMSriovEswitchEncapMode;

/*****************************************************************************/

typedef enum {
    /* In priority order; higher number == higher priority */

    NM_IP_CONFIG_SOURCE_UNKNOWN = 0,

    /* for routes, the source is mapped to the uint8 field rtm_protocol.
     * Reserve the range [1,0x100] for native RTPROT values. */

    NM_IP_CONFIG_SOURCE_RTPROT_UNSPEC   = 1 + 0,
    NM_IP_CONFIG_SOURCE_RTPROT_REDIRECT = 1 + 1,
    NM_IP_CONFIG_SOURCE_RTPROT_KERNEL   = 1 + 2,
    NM_IP_CONFIG_SOURCE_RTPROT_BOOT     = 1 + 3,
    NM_IP_CONFIG_SOURCE_RTPROT_STATIC   = 1 + 4,
    NM_IP_CONFIG_SOURCE_RTPROT_RA       = 1 + 9,
    NM_IP_CONFIG_SOURCE_RTPROT_DHCP     = 1 + 16,
    _NM_IP_CONFIG_SOURCE_RTPROT_LAST    = 1 + 0xFF,

    NM_IP_CONFIG_SOURCE_KERNEL,
    NM_IP_CONFIG_SOURCE_SHARED,
    NM_IP_CONFIG_SOURCE_IP4LL,
    NM_IP_CONFIG_SOURCE_IP6LL,
    NM_IP_CONFIG_SOURCE_PPP,
    NM_IP_CONFIG_SOURCE_WWAN,
    NM_IP_CONFIG_SOURCE_VPN,
    NM_IP_CONFIG_SOURCE_DHCP,
    NM_IP_CONFIG_SOURCE_NDISC,
    NM_IP_CONFIG_SOURCE_USER,
} NMIPConfigSource;

static inline gboolean
NM_IS_IP_CONFIG_SOURCE_RTPROT(NMIPConfigSource source)
{
    return source > NM_IP_CONFIG_SOURCE_UNKNOWN && source <= _NM_IP_CONFIG_SOURCE_RTPROT_LAST;
}

/*****************************************************************************/

/* IEEE 802.1D-1998 timer values */
#define NM_BRIDGE_HELLO_TIME_MIN     1u
#define NM_BRIDGE_HELLO_TIME_DEF     2u
#define NM_BRIDGE_HELLO_TIME_DEF_SYS (NM_BRIDGE_HELLO_TIME_DEF * 100u)
#define NM_BRIDGE_HELLO_TIME_MAX     10u

#define NM_BRIDGE_FORWARD_DELAY_MIN     2u
#define NM_BRIDGE_FORWARD_DELAY_DEF     15u
#define NM_BRIDGE_FORWARD_DELAY_DEF_SYS (NM_BRIDGE_FORWARD_DELAY_DEF * 100u)
#define NM_BRIDGE_FORWARD_DELAY_MAX     30u

#define NM_BRIDGE_MAX_AGE_MIN     6u
#define NM_BRIDGE_MAX_AGE_DEF     20u
#define NM_BRIDGE_MAX_AGE_DEF_SYS (NM_BRIDGE_MAX_AGE_DEF * 100u)
#define NM_BRIDGE_MAX_AGE_MAX     40u

/* IEEE 802.1D-1998 Table 7.4 */
#define NM_BRIDGE_AGEING_TIME_MIN     0u
#define NM_BRIDGE_AGEING_TIME_DEF     300u
#define NM_BRIDGE_AGEING_TIME_DEF_SYS (NM_BRIDGE_AGEING_TIME_DEF * 100u)
#define NM_BRIDGE_AGEING_TIME_MAX     1000000u

#define NM_BRIDGE_PORT_PRIORITY_MIN 0u
#define NM_BRIDGE_PORT_PRIORITY_DEF 32u
#define NM_BRIDGE_PORT_PRIORITY_MAX 63u

#define NM_BRIDGE_PORT_PATH_COST_MIN 0u
#define NM_BRIDGE_PORT_PATH_COST_DEF 100u
#define NM_BRIDGE_PORT_PATH_COST_MAX 65535u

#define NM_BRIDGE_MULTICAST_HASH_MAX_MIN 1u
#define NM_BRIDGE_MULTICAST_HASH_MAX_DEF 4096u
#define NM_BRIDGE_MULTICAST_HASH_MAX_MAX ((guint) G_MAXUINT32)

#define NM_BRIDGE_STP_DEF TRUE

#define NM_BRIDGE_GROUP_ADDRESS_DEF_BIN 0x01, 0x80, 0xC2, 0x00, 0x00, 0x00
#define NM_BRIDGE_GROUP_ADDRESS_DEF_STR "01:80:C2:00:00:00"

#define NM_BRIDGE_PRIORITY_MIN 0u
#define NM_BRIDGE_PRIORITY_DEF 0x8000u
#define NM_BRIDGE_PRIORITY_MAX ((guint) G_MAXUINT16)

#define NM_BRIDGE_MULTICAST_LAST_MEMBER_COUNT_MIN 0u
#define NM_BRIDGE_MULTICAST_LAST_MEMBER_COUNT_DEF 2u
#define NM_BRIDGE_MULTICAST_LAST_MEMBER_COUNT_MAX ((guint) G_MAXUINT32)

#define NM_BRIDGE_MULTICAST_LAST_MEMBER_INTERVAL_MIN ((guint64) 0)
#define NM_BRIDGE_MULTICAST_LAST_MEMBER_INTERVAL_DEF ((guint64) 100)
#define NM_BRIDGE_MULTICAST_LAST_MEMBER_INTERVAL_MAX G_MAXUINT64

#define NM_BRIDGE_MULTICAST_MEMBERSHIP_INTERVAL_MIN ((guint64) 0)
#define NM_BRIDGE_MULTICAST_MEMBERSHIP_INTERVAL_DEF ((guint64) 26000)
#define NM_BRIDGE_MULTICAST_MEMBERSHIP_INTERVAL_MAX G_MAXUINT64

#define NM_BRIDGE_MULTICAST_QUERIER_INTERVAL_MIN ((guint64) 0)
#define NM_BRIDGE_MULTICAST_QUERIER_INTERVAL_DEF ((guint64) 25500)
#define NM_BRIDGE_MULTICAST_QUERIER_INTERVAL_MAX G_MAXUINT64

#define NM_BRIDGE_MULTICAST_QUERIER_DEF FALSE

#define NM_BRIDGE_MULTICAST_QUERY_INTERVAL_MIN ((guint64) 0)
#define NM_BRIDGE_MULTICAST_QUERY_INTERVAL_DEF ((guint64) 12500)
#define NM_BRIDGE_MULTICAST_QUERY_INTERVAL_MAX G_MAXUINT64

#define NM_BRIDGE_MULTICAST_QUERY_RESPONSE_INTERVAL_MIN ((guint64) 0)
#define NM_BRIDGE_MULTICAST_QUERY_RESPONSE_INTERVAL_DEF ((guint64) 1000)
#define NM_BRIDGE_MULTICAST_QUERY_RESPONSE_INTERVAL_MAX G_MAXUINT64

#define NM_BRIDGE_MULTICAST_QUERY_USE_IFADDR_DEF FALSE

#define NM_BRIDGE_MULTICAST_SNOOPING_DEF TRUE

#define NM_BRIDGE_MULTICAST_STARTUP_QUERY_COUNT_MIN 0u
#define NM_BRIDGE_MULTICAST_STARTUP_QUERY_COUNT_DEF 2u
#define NM_BRIDGE_MULTICAST_STARTUP_QUERY_COUNT_MAX ((guint) G_MAXUINT32)

#define NM_BRIDGE_MULTICAST_STARTUP_QUERY_INTERVAL_MIN ((guint64) 0)
#define NM_BRIDGE_MULTICAST_STARTUP_QUERY_INTERVAL_DEF ((guint64) 3125)
#define NM_BRIDGE_MULTICAST_STARTUP_QUERY_INTERVAL_MAX G_MAXUINT64

#define NM_BRIDGE_VLAN_STATS_ENABLED_DEF FALSE

#define NM_BRIDGE_VLAN_DEFAULT_PVID_DEF 1u

/*****************************************************************************/

typedef struct {
    guint32 from;
    guint32 to;
} NMVlanQosMapping;

#define _NM_IP_TUNNEL_FLAG_ALL_IP6TNL                                              \
    (NM_IP_TUNNEL_FLAG_IP6_IGN_ENCAP_LIMIT | NM_IP_TUNNEL_FLAG_IP6_USE_ORIG_TCLASS \
     | NM_IP_TUNNEL_FLAG_IP6_USE_ORIG_FLOWLABEL | NM_IP_TUNNEL_FLAG_IP6_MIP6_DEV   \
     | NM_IP_TUNNEL_FLAG_IP6_RCV_DSCP_COPY | NM_IP_TUNNEL_FLAG_IP6_USE_ORIG_FWMARK)

/****************************************************************************/

#define NM_IW_ESSID_MAX_SIZE 32

/****************************************************************************/

#define NM_BOND_PORT_QUEUE_ID_DEF 0
#define NM_BOND_PORT_PRIO_DEF     0

/****************************************************************************/

/* ifindex generation is per-net namespace, and loopback is always the first
 * device in the network namespace, thus any loopback device should get ifindex 1. */
#define NM_LOOPBACK_IFINDEX 1

/*****************************************************************************/

/* NM_CRYPTO_ERROR is part of public API in libnm (implemented in libnm-core).
 * We also want to use it without libnm-core. So this "_" variant is the internal
 * version, with numerically same values -- to be used without libnm-base. */

#define _NM_CRYPTO_ERROR_FAILED            0
#define _NM_CRYPTO_ERROR_INVALID_DATA      1
#define _NM_CRYPTO_ERROR_INVALID_PASSWORD  2
#define _NM_CRYPTO_ERROR_UNKNOWN_CIPHER    3
#define _NM_CRYPTO_ERROR_DECRYPTION_FAILED 4
#define _NM_CRYPTO_ERROR_ENCRYPTION_FAILED 5

#define _NM_CRYPTO_ERROR _nm_crypto_error_quark()
GQuark _nm_crypto_error_quark(void);

typedef enum {
    NM_DNS_IP_CONFIG_TYPE_REMOVED = -1,

    NM_DNS_IP_CONFIG_TYPE_DEFAULT = 0,
    NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE,
    NM_DNS_IP_CONFIG_TYPE_VPN,
} NMDnsIPConfigType;

/*****************************************************************************/

#define NM_DHCP_IAID_TO_HEXSTR_BUF_LEN (3 * sizeof(guint32))

char *nm_dhcp_iaid_to_hexstr(guint32 iaid, char buf[static NM_DHCP_IAID_TO_HEXSTR_BUF_LEN]);

gboolean nm_dhcp_iaid_from_hexstr(const char *str, guint32 *out_value);

/*****************************************************************************/

const char *
nm_net_devname_infiniband(char name[static NM_IFNAMSIZ], const char *parent_name, int p_key);

#endif /* __NM_LIBNM_BASE_H__ */
