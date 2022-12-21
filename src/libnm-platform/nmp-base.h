/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef __NMP_FWD_H__
#define __NMP_FWD_H__

#include "libnm-base/nm-base.h"

/*****************************************************************************/

#define NM_PLATFORM_LIFETIME_PERMANENT G_MAXUINT32

/*****************************************************************************/

/* IFNAMSIZ is both defined in <linux/if.h> and <net/if.h>. In the past, these
 * headers conflicted, so we cannot simply include either of them in a header-file.*/
#define NMP_IFNAMSIZ 16

/*****************************************************************************/

/* Define of the IN6_ADDR_GEN_MODE_* values to workaround old kernel headers
 * that don't define it. */
#define NM_IN6_ADDR_GEN_MODE_UNKNOWN        255 /* no corresponding value.  */
#define NM_IN6_ADDR_GEN_MODE_EUI64          0   /* IN6_ADDR_GEN_MODE_EUI64 */
#define NM_IN6_ADDR_GEN_MODE_NONE           1   /* IN6_ADDR_GEN_MODE_NONE */
#define NM_IN6_ADDR_GEN_MODE_STABLE_PRIVACY 2   /* IN6_ADDR_GEN_MODE_STABLE_PRIVACY */
#define NM_IN6_ADDR_GEN_MODE_RANDOM         3   /* IN6_ADDR_GEN_MODE_RANDOM */

/*****************************************************************************/

typedef enum {
    NM_PLATFORM_LINK_DUPLEX_UNKNOWN,
    NM_PLATFORM_LINK_DUPLEX_HALF,
    NM_PLATFORM_LINK_DUPLEX_FULL,
} NMPlatformLinkDuplexType;

/*****************************************************************************/

typedef struct {
    /* We don't want to include <linux/ethtool.h> in header files,
     * thus create a ABI compatible version of struct ethtool_drvinfo.*/
    guint32 _private_cmd;
    char    driver[32];
    char    version[32];
    char    fw_version[32];
    char    _private_bus_info[32];
    char    _private_erom_version[32];
    char    _private_reserved2[12];
    guint32 _private_n_priv_flags;
    guint32 _private_n_stats;
    guint32 _private_testinfo_len;
    guint32 _private_eedump_len;
    guint32 _private_regdump_len;
} NMPUtilsEthtoolDriverInfo;

typedef struct {
    NMEthtoolID ethtool_id;

    guint8 n_kernel_names;

    /* one NMEthtoolID refers to one or more kernel_names. The reason for supporting this complexity
     * (where one NMSettingEthtool option refers to multiple kernel features)  is to follow what
     * ethtool does, where "tx" is an alias for multiple features. */
    const char *const *kernel_names;
} NMEthtoolFeatureInfo;

typedef struct {
    const NMEthtoolFeatureInfo *info;

    guint idx_ss_features;

    /* one NMEthtoolFeatureInfo references one or more kernel_names. This is the index
     * of the matching info->kernel_names */
    guint8 idx_kernel_name;

    bool available : 1;
    bool requested : 1;
    bool active : 1;
    bool never_changed : 1;
} NMEthtoolFeatureState;

typedef struct {
    guint n_states;

    guint n_ss_features;

    /* indexed by NMEthtoolID - _NM_ETHTOOL_ID_FEATURE_FIRST */
    const NMEthtoolFeatureState *const *states_indexed[_NM_ETHTOOL_ID_FEATURE_NUM];

    /* the same content, here as a list of n_states entries. */
    const NMEthtoolFeatureState states_list[];
} NMEthtoolFeatureStates;

/*****************************************************************************/

typedef struct {
    guint32
        s[_NM_ETHTOOL_ID_COALESCE_NUM /* indexed by (NMEthtoolID - _NM_ETHTOOL_ID_COALESCE_FIRST) */
    ];
} NMEthtoolCoalesceState;

/*****************************************************************************/

typedef struct {
    guint32 rx_pending;
    guint32 rx_mini_pending;
    guint32 rx_jumbo_pending;
    guint32 tx_pending;
} NMEthtoolRingState;

typedef struct {
    bool autoneg : 1;
    bool rx : 1;
    bool tx : 1;
} NMEthtoolPauseState;

/*****************************************************************************/

typedef struct _NMPNetns                 NMPNetns;
typedef struct _NMPlatform               NMPlatform;
typedef struct _NMPlatformObject         NMPlatformObject;
typedef struct _NMPlatformObjWithIfindex NMPlatformObjWithIfindex;
typedef struct _NMPlatformIP4Address     NMPlatformIP4Address;
typedef struct _NMPlatformIP4Route       NMPlatformIP4Route;
typedef struct _NMPlatformIP6Address     NMPlatformIP6Address;
typedef struct _NMPlatformIP6Route       NMPlatformIP6Route;
typedef struct _NMPlatformLink           NMPlatformLink;
typedef struct _NMPObject                NMPObject;

typedef enum _nm_packed {
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
    NMP_OBJECT_TYPE_LNK_VTI,
    NMP_OBJECT_TYPE_LNK_VTI6,
    NMP_OBJECT_TYPE_LNK_VXLAN,
    NMP_OBJECT_TYPE_LNK_WIREGUARD,
    NMP_OBJECT_TYPE_LNK_BOND,

    NMP_OBJECT_TYPE_MPTCP_ADDR,

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

/*****************************************************************************/

/**
 * NMIPRouteTableSyncMode:
 * @NM_IP_ROUTE_TABLE_SYNC_MODE_NONE: indicate an invalid setting.
 * @NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN: only the main table is synced. For all
 *   other tables, NM won't delete any extra routes.
 * @NM_IP_ROUTE_TABLE_SYNC_MODE_FULL: NM will sync all tables, except the
 *   local table (255).
 * @NM_IP_ROUTE_TABLE_SYNC_MODE_ALL: NM will sync all tables, including the
 *   local table (255).
 * @NM_IP_ROUTE_TABLE_SYNC_MODE_ALL_PRUNE: NM will sync all tables (including
 *   the local table). It will thereby remove all addresses, that is during
 *   deactivation.
 */
typedef enum {
    NM_IP_ROUTE_TABLE_SYNC_MODE_NONE,
    NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN,
    NM_IP_ROUTE_TABLE_SYNC_MODE_FULL,
    NM_IP_ROUTE_TABLE_SYNC_MODE_ALL,
    NM_IP_ROUTE_TABLE_SYNC_MODE_ALL_PRUNE,
} NMIPRouteTableSyncMode;

/*****************************************************************************/

const char *nm_platform_link_flags2str(unsigned flags, char *buf, gsize len);
const char *nm_platform_link_inet6_addrgenmode2str(guint8 mode, char *buf, gsize len);
const char *nm_platform_addr_flags2str(unsigned flags, char *buf, gsize len);
const char *nm_platform_route_scope2str(int scope, char *buf, gsize len);

#endif /* __NMP_FWD_H__ */
