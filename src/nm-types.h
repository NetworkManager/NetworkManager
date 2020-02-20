// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2012 - 2018 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_TYPES_H__
#define __NETWORKMANAGER_TYPES_H__

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_DAEMON)
#error Cannot use this header.
#endif

#define _NM_SD_MAX_CLIENT_ID_LEN (sizeof (guint32) + 128)

/* core */
typedef struct _NMDBusObject         NMDBusObject;
typedef struct _NMActiveConnection   NMActiveConnection;
typedef struct _NMAuditManager       NMAuditManager;
typedef struct _NMVpnConnection      NMVpnConnection;
typedef struct _NMActRequest         NMActRequest;
typedef struct _NMAuthSubject        NMAuthSubject;
typedef struct _NMDBusManager        NMDBusManager;
typedef struct _NMConfig             NMConfig;
typedef struct _NMConfigData         NMConfigData;
typedef struct _NMConnectivity       NMConnectivity;
typedef struct _NMDevice             NMDevice;
typedef struct _NMDhcpConfig         NMDhcpConfig;
typedef struct _NMProxyConfig        NMProxyConfig;
typedef struct _NMIPConfig           NMIPConfig;
typedef struct _NMIP4Config          NMIP4Config;
typedef struct _NMIP6Config          NMIP6Config;
typedef struct _NMManager            NMManager;
typedef struct _NMNetns              NMNetns;
typedef struct _NMPolicy             NMPolicy;
typedef struct _NMRfkillManager      NMRfkillManager;
typedef struct _NMPacrunnerManager   NMPacrunnerManager;
typedef struct _NMSessionMonitor     NMSessionMonitor;
typedef struct _NMKeepAlive          NMKeepAlive;
typedef struct _NMSleepMonitor       NMSleepMonitor;
typedef struct _NMLldpListener       NMLldpListener;
typedef struct _NMConfigDeviceStateData NMConfigDeviceStateData;

struct _NMDedupMultiIndex;

typedef struct _NMRefString NMRefString;

/*****************************************************************************/

typedef enum {
	/* Do a full activation. */
	NM_ACTIVATION_TYPE_MANAGED = 0,

	/* gracefully/seamlessly take over the device. This leaves additional
	 * IP addresses and does not restore missing manual addresses. */
	NM_ACTIVATION_TYPE_ASSUME = 1,

	/* external activation. This device is not managed by NM, instead
	 * a in-memory connection is generated and NM pretends the device
	 * to be active, but it doesn't do anything really. */
	NM_ACTIVATION_TYPE_EXTERNAL = 2,
} NMActivationType;

typedef enum {
	NM_ACTIVATION_REASON_UNSET,
	NM_ACTIVATION_REASON_EXTERNAL,
	NM_ACTIVATION_REASON_ASSUME,
	NM_ACTIVATION_REASON_AUTOCONNECT,
	NM_ACTIVATION_REASON_AUTOCONNECT_SLAVES,
	NM_ACTIVATION_REASON_USER_REQUEST,
} NMActivationReason;

typedef enum {
	/* In priority order; higher number == higher priority */

	NM_IP_CONFIG_SOURCE_UNKNOWN                 = 0,

	/* for routes, the source is mapped to the uint8 field rtm_protocol.
	 * Reserve the range [1,0x100] for native RTPROT values. */

	NM_IP_CONFIG_SOURCE_RTPROT_UNSPEC           = 1 + 0,
	NM_IP_CONFIG_SOURCE_RTPROT_REDIRECT         = 1 + 1,
	NM_IP_CONFIG_SOURCE_RTPROT_KERNEL           = 1 + 2,
	NM_IP_CONFIG_SOURCE_RTPROT_BOOT             = 1 + 3,
	NM_IP_CONFIG_SOURCE_RTPROT_STATIC           = 1 + 4,
	NM_IP_CONFIG_SOURCE_RTPROT_RA               = 1 + 9,
	NM_IP_CONFIG_SOURCE_RTPROT_DHCP             = 1 + 16,
	_NM_IP_CONFIG_SOURCE_RTPROT_LAST            = 1 + 0xFF,

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
NM_IS_IP_CONFIG_SOURCE_RTPROT (NMIPConfigSource source)
{
	return source > NM_IP_CONFIG_SOURCE_UNKNOWN && source <= _NM_IP_CONFIG_SOURCE_RTPROT_LAST;
}

/* platform */
typedef struct _NMPlatform               NMPlatform;
typedef struct _NMPlatformObject         NMPlatformObject;
typedef struct _NMPlatformObjWithIfindex NMPlatformObjWithIfindex;
typedef struct _NMPlatformIP4Address     NMPlatformIP4Address;
typedef struct _NMPlatformIP4Route       NMPlatformIP4Route;
typedef struct _NMPlatformIP6Address     NMPlatformIP6Address;
typedef struct _NMPlatformIP6Route       NMPlatformIP6Route;
typedef struct _NMPlatformLink           NMPlatformLink;
typedef struct _NMPNetns                 NMPNetns;
typedef struct _NMPObject                NMPObject;

typedef enum {

	/* No type, used as error value */
	NM_LINK_TYPE_NONE,

	NM_LINK_TYPE_UNKNOWN,

	NM_LINK_TYPE_ANY,

#define _NM_LINK_TYPE_REAL_FIRST NM_LINK_TYPE_ETHERNET

	/* Hardware types */
#define _NM_LINK_TYPE_HW_FIRST NM_LINK_TYPE_ETHERNET
	NM_LINK_TYPE_ETHERNET,
	NM_LINK_TYPE_INFINIBAND,
	NM_LINK_TYPE_OLPC_MESH,
	NM_LINK_TYPE_WIFI,
	NM_LINK_TYPE_WWAN_NET,   /* WWAN kernel netdevice */
	NM_LINK_TYPE_WIMAX,
	NM_LINK_TYPE_WPAN,
	NM_LINK_TYPE_6LOWPAN,
	NM_LINK_TYPE_WIFI_P2P,
#define _NM_LINK_TYPE_HW_LAST  NM_LINK_TYPE_WIFI_P2P

	/* Software types */
#define _NM_LINK_TYPE_SW_FIRST NM_LINK_TYPE_BNEP
	NM_LINK_TYPE_BNEP,   /* Bluetooth Ethernet emulation */
	NM_LINK_TYPE_DUMMY,
	NM_LINK_TYPE_GRE,
	NM_LINK_TYPE_GRETAP,
	NM_LINK_TYPE_IFB,
	NM_LINK_TYPE_IP6TNL,
	NM_LINK_TYPE_IP6GRE,
	NM_LINK_TYPE_IP6GRETAP,
	NM_LINK_TYPE_IPIP,
	NM_LINK_TYPE_LOOPBACK,
	NM_LINK_TYPE_MACSEC,
	NM_LINK_TYPE_MACVLAN,
	NM_LINK_TYPE_MACVTAP,
	NM_LINK_TYPE_OPENVSWITCH,
	NM_LINK_TYPE_PPP,
	NM_LINK_TYPE_SIT,
	NM_LINK_TYPE_TUN,
	NM_LINK_TYPE_VETH,
	NM_LINK_TYPE_VLAN,
	NM_LINK_TYPE_VRF,
	NM_LINK_TYPE_VXLAN,
	NM_LINK_TYPE_WIREGUARD,
#define _NM_LINK_TYPE_SW_LAST  NM_LINK_TYPE_WIREGUARD

	/* Software types with slaves */
#define _NM_LINK_TYPE_SW_MASTER_FIRST NM_LINK_TYPE_BRIDGE
	NM_LINK_TYPE_BRIDGE,
	NM_LINK_TYPE_BOND,
	NM_LINK_TYPE_TEAM,
#define _NM_LINK_TYPE_SW_MASTER_LAST NM_LINK_TYPE_TEAM

#define _NM_LINK_TYPE_REAL_LAST NM_LINK_TYPE_TEAM

#define _NM_LINK_TYPE_REAL_NUM ((int) (_NM_LINK_TYPE_REAL_LAST - _NM_LINK_TYPE_REAL_FIRST + 1))

} NMLinkType;

static inline gboolean
nm_link_type_is_software (NMLinkType link_type)
{
	G_STATIC_ASSERT (_NM_LINK_TYPE_SW_LAST + 1 == _NM_LINK_TYPE_SW_MASTER_FIRST);

	return    link_type >= _NM_LINK_TYPE_SW_FIRST
	       && link_type <= _NM_LINK_TYPE_SW_MASTER_LAST;
}

static inline gboolean
nm_link_type_supports_slaves (NMLinkType link_type)
{
	return    link_type >= _NM_LINK_TYPE_SW_MASTER_FIRST
	       && link_type <= _NM_LINK_TYPE_SW_MASTER_LAST;
}

typedef enum {
	NMP_OBJECT_TYPE_UNKNOWN,
	NMP_OBJECT_TYPE_LINK,
	NMP_OBJECT_TYPE_IP4_ADDRESS,
	NMP_OBJECT_TYPE_IP6_ADDRESS,
	NMP_OBJECT_TYPE_IP4_ROUTE,
	NMP_OBJECT_TYPE_IP6_ROUTE,
	NMP_OBJECT_TYPE_ROUTING_RULE,

	NMP_OBJECT_TYPE_QDISC,

	NMP_OBJECT_TYPE_TFILTER,

	NMP_OBJECT_TYPE_LNK_GRE,
	NMP_OBJECT_TYPE_LNK_GRETAP,
	NMP_OBJECT_TYPE_LNK_INFINIBAND,
	NMP_OBJECT_TYPE_LNK_IP6TNL,
	NMP_OBJECT_TYPE_LNK_IP6GRE,
	NMP_OBJECT_TYPE_LNK_IP6GRETAP,
	NMP_OBJECT_TYPE_LNK_IPIP,
	NMP_OBJECT_TYPE_LNK_MACSEC,
	NMP_OBJECT_TYPE_LNK_MACVLAN,
	NMP_OBJECT_TYPE_LNK_MACVTAP,
	NMP_OBJECT_TYPE_LNK_SIT,
	NMP_OBJECT_TYPE_LNK_TUN,
	NMP_OBJECT_TYPE_LNK_VLAN,
	NMP_OBJECT_TYPE_LNK_VRF,
	NMP_OBJECT_TYPE_LNK_VXLAN,
	NMP_OBJECT_TYPE_LNK_WIREGUARD,

	__NMP_OBJECT_TYPE_LAST,
	NMP_OBJECT_TYPE_MAX = __NMP_OBJECT_TYPE_LAST - 1,
} NMPObjectType;

/**
 * NMIPConfigMergeFlags:
 * @NM_IP_CONFIG_MERGE_DEFAULT: no flags set
 * @NM_IP_CONFIG_MERGE_NO_ROUTES: don't merge routes
 * @NM_IP_CONFIG_MERGE_NO_DEFAULT_ROUTES: don't merge default routes
 * @NM_IP_CONFIG_MERGE_NO_DNS: don't merge DNS information
 * @NM_IP_CONFIG_MERGE_EXTERNAL: mark new addresses as external
 */
typedef enum {
	NM_IP_CONFIG_MERGE_DEFAULT                  = 0,
	NM_IP_CONFIG_MERGE_NO_ROUTES                = (1LL << 0),
	NM_IP_CONFIG_MERGE_NO_DEFAULT_ROUTES        = (1LL << 1),
	NM_IP_CONFIG_MERGE_NO_DNS                   = (1LL << 2),
	NM_IP_CONFIG_MERGE_EXTERNAL                 = (1LL << 3),
} NMIPConfigMergeFlags;

/**
 * NMIPRouteTableSyncMode:
 * @NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN: only the main table is synced. For all
 *   other tables, NM won't delete any extra routes.
 * @NM_IP_ROUTE_TABLE_SYNC_MODE_FULL: NM will sync all tables, except the
 *   local table (255).
 * @NM_IP_ROUTE_TABLE_SYNC_MODE_ALL: NM will sync all tables, including the
 *   local table (255).
 */
typedef enum {
	NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN        = 1,
	NM_IP_ROUTE_TABLE_SYNC_MODE_FULL        = 2,
	NM_IP_ROUTE_TABLE_SYNC_MODE_ALL         = 3,
} NMIPRouteTableSyncMode;

/* settings */
typedef struct _NMAgentManager       NMAgentManager;
typedef struct _NMSecretAgent        NMSecretAgent;
typedef struct _NMSettings           NMSettings;
typedef struct _NMSettingsConnection NMSettingsConnection;

/* utils */
typedef struct _NMUtilsIPv6IfaceId   NMUtilsIPv6IfaceId;

#define NM_SETTING_CONNECTION_MDNS_UNKNOWN ((NMSettingConnectionMdns) -42)

#endif  /* NM_TYPES_H */
