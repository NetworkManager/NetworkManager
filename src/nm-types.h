/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_TYPES_H__
#define __NETWORKMANAGER_TYPES_H__

#ifdef __NM_UTILS_PRIVATE_H__
#error "nm-utils-private.h" must not be used outside of libnm-core/. Do you want "nm-core-internal.h"?
#endif

/* core */
typedef struct _NMExportedObject     NMExportedObject;
typedef struct _NMActiveConnection   NMActiveConnection;
typedef struct _NMAuditManager       NMAuditManager;
typedef struct _NMVpnConnection      NMVpnConnection;
typedef struct _NMActRequest         NMActRequest;
typedef struct _NMAuthSubject        NMAuthSubject;
typedef struct _NMBusManager         NMBusManager;
typedef struct _NMConfig             NMConfig;
typedef struct _NMConfigData         NMConfigData;
typedef struct _NMArpingManager      NMArpingManager;
typedef struct _NMConnectionProvider NMConnectionProvider;
typedef struct _NMConnectivity       NMConnectivity;
typedef struct _NMDefaultRouteManager NMDefaultRouteManager;
typedef struct _NMDevice             NMDevice;
typedef struct _NMDhcp4Config        NMDhcp4Config;
typedef struct _NMDhcp6Config        NMDhcp6Config;
typedef struct _NMIP4Config          NMIP4Config;
typedef struct _NMIP6Config          NMIP6Config;
typedef struct _NMManager            NMManager;
typedef struct _NMPolicy             NMPolicy;
typedef struct _NMRfkillManager      NMRfkillManager;
typedef struct _NMRouteManager       NMRouteManager;
typedef struct _NMSessionMonitor     NMSessionMonitor;
typedef struct _NMSleepMonitor       NMSleepMonitor;
typedef struct _NMLldpListener       NMLldpListener;
typedef struct _NMConfigDeviceStateData NMConfigDeviceStateData;

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
	NM_IP_CONFIG_SOURCE_PPP,
	NM_IP_CONFIG_SOURCE_WWAN,
	NM_IP_CONFIG_SOURCE_VPN,
	NM_IP_CONFIG_SOURCE_DHCP,
	NM_IP_CONFIG_SOURCE_RDISC,
	NM_IP_CONFIG_SOURCE_USER,
} NMIPConfigSource;

inline static gboolean
NM_IS_IP_CONFIG_SOURCE_RTPROT (NMIPConfigSource source)
{
	return source > NM_IP_CONFIG_SOURCE_UNKNOWN && source <= _NM_IP_CONFIG_SOURCE_RTPROT_LAST;
}

/* platform */
typedef struct _NMPlatform           NMPlatform;
typedef struct _NMPlatformIP4Address NMPlatformIP4Address;
typedef struct _NMPlatformIP4Route   NMPlatformIP4Route;
typedef struct _NMPlatformIP6Address NMPlatformIP6Address;
typedef struct _NMPlatformIP6Route   NMPlatformIP6Route;
typedef struct _NMPlatformLink       NMPlatformLink;
typedef struct _NMPNetns             NMPNetns;
typedef struct _NMPObject            NMPObject;

typedef enum {
	/* Please don't interpret type numbers outside nm-platform and use functions
	 * like nm_platform_link_is_software() and nm_platform_supports_slaves().
	 *
	 * type & 0x10000 -> Software device type
	 * type & 0x20000 -> Type supports slaves
	 */

	/* No type, used as error value */
	NM_LINK_TYPE_NONE,

	/* Unknown type  */
	NM_LINK_TYPE_UNKNOWN,

	/* Hardware types */
	NM_LINK_TYPE_ETHERNET,
	NM_LINK_TYPE_INFINIBAND,
	NM_LINK_TYPE_OLPC_MESH,
	NM_LINK_TYPE_WIFI,
	NM_LINK_TYPE_WWAN_NET,   /* WWAN kernel netdevice */
	NM_LINK_TYPE_WIMAX,

	/* Software types */
	NM_LINK_TYPE_DUMMY = 0x10000,
	NM_LINK_TYPE_GRE,
	NM_LINK_TYPE_GRETAP,
	NM_LINK_TYPE_IFB,
	NM_LINK_TYPE_IP6TNL,
	NM_LINK_TYPE_IPIP,
	NM_LINK_TYPE_LOOPBACK,
	NM_LINK_TYPE_MACVLAN,
	NM_LINK_TYPE_MACVTAP,
	NM_LINK_TYPE_OPENVSWITCH,
	NM_LINK_TYPE_SIT,
	NM_LINK_TYPE_TAP,
	NM_LINK_TYPE_TUN,
	NM_LINK_TYPE_VETH,
	NM_LINK_TYPE_VLAN,
	NM_LINK_TYPE_VXLAN,
	NM_LINK_TYPE_BNEP,   /* Bluetooth Ethernet emulation */

	/* Software types with slaves */
	NM_LINK_TYPE_BRIDGE = 0x10000 | 0x20000,
	NM_LINK_TYPE_BOND,
	NM_LINK_TYPE_TEAM,

	NM_LINK_TYPE_ANY = G_MAXUINT32,
} NMLinkType;

typedef enum {
	NMP_OBJECT_TYPE_UNKNOWN,
	NMP_OBJECT_TYPE_LINK,
	NMP_OBJECT_TYPE_IP4_ADDRESS,
	NMP_OBJECT_TYPE_IP6_ADDRESS,
	NMP_OBJECT_TYPE_IP4_ROUTE,
	NMP_OBJECT_TYPE_IP6_ROUTE,

	NMP_OBJECT_TYPE_LNK_GRE,
	NMP_OBJECT_TYPE_LNK_INFINIBAND,
	NMP_OBJECT_TYPE_LNK_IP6TNL,
	NMP_OBJECT_TYPE_LNK_IPIP,
	NMP_OBJECT_TYPE_LNK_MACVLAN,
	NMP_OBJECT_TYPE_LNK_MACVTAP,
	NMP_OBJECT_TYPE_LNK_SIT,
	NMP_OBJECT_TYPE_LNK_VLAN,
	NMP_OBJECT_TYPE_LNK_VXLAN,

	__NMP_OBJECT_TYPE_LAST,
	NMP_OBJECT_TYPE_MAX = __NMP_OBJECT_TYPE_LAST - 1,
} NMPObjectType;

typedef enum {
	NM_IP_CONFIG_MERGE_DEFAULT                  = 0,
	NM_IP_CONFIG_MERGE_NO_ROUTES                = (1LL << 0),
	NM_IP_CONFIG_MERGE_NO_DNS                   = (1LL << 1),
} NMIPConfigMergeFlags;

/* settings */
typedef struct _NMAgentManager       NMAgentManager;
typedef struct _NMSecretAgent        NMSecretAgent;
typedef struct _NMSettings           NMSettings;
typedef struct _NMSettingsConnection NMSettingsConnection;

/* utils */
typedef struct _NMUtilsIPv6IfaceId   NMUtilsIPv6IfaceId;

#endif  /* NM_TYPES_H */
