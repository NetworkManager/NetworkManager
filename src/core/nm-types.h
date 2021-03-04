/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2012 - 2018 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_TYPES_H__
#define __NETWORKMANAGER_TYPES_H__

#if !((NETWORKMANAGER_COMPILATION) &NM_NETWORKMANAGER_COMPILATION_WITH_DAEMON)
    #error Cannot use this header.
#endif

#define _NM_SD_MAX_CLIENT_ID_LEN (sizeof(guint32) + 128)

/* core */
typedef struct _NMDBusObject            NMDBusObject;
typedef struct _NMActiveConnection      NMActiveConnection;
typedef struct _NMAuditManager          NMAuditManager;
typedef struct _NMVpnConnection         NMVpnConnection;
typedef struct _NMActRequest            NMActRequest;
typedef struct _NMAuthSubject           NMAuthSubject;
typedef struct _NMDBusManager           NMDBusManager;
typedef struct _NMConfig                NMConfig;
typedef struct _NMConfigData            NMConfigData;
typedef struct _NMConnectivity          NMConnectivity;
typedef struct _NML3Cfg                 NML3Cfg;
typedef struct _NML3ConfigData          NML3ConfigData;
typedef struct _NMDevice                NMDevice;
typedef struct _NMDhcpConfig            NMDhcpConfig;
typedef struct _NMProxyConfig           NMProxyConfig;
typedef struct _NMIPConfig              NMIPConfig;
typedef struct _NMIP4Config             NMIP4Config;
typedef struct _NMIP6Config             NMIP6Config;
typedef struct _NMManager               NMManager;
typedef struct _NMNetns                 NMNetns;
typedef struct _NMPolicy                NMPolicy;
typedef struct _NMRfkillManager         NMRfkillManager;
typedef struct _NMPacrunnerManager      NMPacrunnerManager;
typedef struct _NMSessionMonitor        NMSessionMonitor;
typedef struct _NMKeepAlive             NMKeepAlive;
typedef struct _NMSleepMonitor          NMSleepMonitor;
typedef struct _NMLldpListener          NMLldpListener;
typedef struct _NMConfigDeviceStateData NMConfigDeviceStateData;

typedef void (*NMManagerDeviceAuthRequestFunc)(NMDevice *             device,
                                               GDBusMethodInvocation *context,
                                               NMAuthSubject *        subject,
                                               GError *               error,
                                               gpointer               user_data);

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

/* platform */
typedef struct _NMPlatform               NMPlatform;
typedef struct _NMPlatformObject         NMPlatformObject;
typedef struct _NMPlatformObjWithIfindex NMPlatformObjWithIfindex;
typedef struct _NMPlatformIP4Address     NMPlatformIP4Address;
typedef struct _NMPlatformIP4Route       NMPlatformIP4Route;
typedef struct _NMPlatformIP6Address     NMPlatformIP6Address;
typedef struct _NMPlatformIP6Route       NMPlatformIP6Route;
typedef struct _NMPlatformLink           NMPlatformLink;
typedef struct _NMPObject                NMPObject;

typedef enum {
    NMP_OBJECT_TYPE_UNKNOWN,
    NMP_OBJECT_TYPE_LINK,

#define NMP_OBJECT_TYPE_IP_ADDRESS(is_ipv4) \
    ((is_ipv4) ? NMP_OBJECT_TYPE_IP4_ADDRESS : NMP_OBJECT_TYPE_IP6_ADDRESS)
    NMP_OBJECT_TYPE_IP4_ADDRESS,
    NMP_OBJECT_TYPE_IP6_ADDRESS,

#define NMP_OBJECT_TYPE_IP_ROUTE(is_ipv4) \
    ((is_ipv4) ? NMP_OBJECT_TYPE_IP4_ROUTE : NMP_OBJECT_TYPE_IP6_ROUTE)
    NMP_OBJECT_TYPE_IP4_ROUTE,
    NMP_OBJECT_TYPE_IP6_ROUTE,

    NMP_OBJECT_TYPE_ROUTING_RULE,

    NMP_OBJECT_TYPE_QDISC,

    NMP_OBJECT_TYPE_TFILTER,

    NMP_OBJECT_TYPE_LNK_BRIDGE,
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

static inline guint32
nmp_object_type_to_flags(NMPObjectType obj_type)
{
    G_STATIC_ASSERT_EXPR(NMP_OBJECT_TYPE_MAX < 32);

    nm_assert(_NM_INT_NOT_NEGATIVE(obj_type));
    nm_assert(obj_type < NMP_OBJECT_TYPE_MAX);

    return ((guint32) 1u) << obj_type;
}

/**
 * NMIPConfigMergeFlags:
 * @NM_IP_CONFIG_MERGE_DEFAULT: no flags set
 * @NM_IP_CONFIG_MERGE_NO_ROUTES: don't merge routes
 * @NM_IP_CONFIG_MERGE_NO_DEFAULT_ROUTES: don't merge default routes.
 *   Note that if the source IP config has NM_IP_CONFIG_FLAGS_IGNORE_MERGE_NO_DEFAULT_ROUTES
 *   set, this flag gets ignored during merge.
 * @NM_IP_CONFIG_MERGE_NO_DNS: don't merge DNS information
 * @NM_IP_CONFIG_MERGE_EXTERNAL: mark new addresses as external
 */
typedef enum {
    NM_IP_CONFIG_MERGE_DEFAULT           = 0,
    NM_IP_CONFIG_MERGE_NO_ROUTES         = (1LL << 0),
    NM_IP_CONFIG_MERGE_NO_DEFAULT_ROUTES = (1LL << 1),
    NM_IP_CONFIG_MERGE_NO_DNS            = (1LL << 2),
    NM_IP_CONFIG_MERGE_EXTERNAL          = (1LL << 3),
} NMIPConfigMergeFlags;

/**
 * NMIPRouteTableSyncMode:
 * @NM_IP_ROUTE_TABLE_SYNC_MODE_NONE: indicate an invalid setting.
 * @NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN: only the main table is synced. For all
 *   other tables, NM won't delete any extra routes.
 * @NM_IP_ROUTE_TABLE_SYNC_MODE_FULL: NM will sync all tables, except the
 *   local table (255).
 * @NM_IP_ROUTE_TABLE_SYNC_MODE_ALL: NM will sync all tables, including the
 *   local table (255).
 */
typedef enum {
    NM_IP_ROUTE_TABLE_SYNC_MODE_NONE = 0,
    NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN = 1,
    NM_IP_ROUTE_TABLE_SYNC_MODE_FULL = 2,
    NM_IP_ROUTE_TABLE_SYNC_MODE_ALL  = 3,
} NMIPRouteTableSyncMode;

/* settings */
typedef struct _NMAgentManager       NMAgentManager;
typedef struct _NMSecretAgent        NMSecretAgent;
typedef struct _NMSettings           NMSettings;
typedef struct _NMSettingsConnection NMSettingsConnection;

/* utils */
typedef struct _NMUtilsIPv6IfaceId NMUtilsIPv6IfaceId;

#define NM_SETTING_CONNECTION_MDNS_UNKNOWN ((NMSettingConnectionMdns) -42)

#endif /* NM_TYPES_H */
