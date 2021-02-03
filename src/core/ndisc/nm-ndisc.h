/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_NDISC_H__
#define __NETWORKMANAGER_NDISC_H__

#include <stdlib.h>
#include <netinet/in.h>
#include <linux/if_addr.h>

#include "nm-setting-ip6-config.h"
#include "NetworkManagerUtils.h"

#include "platform/nm-platform.h"
#include "platform/nmp-object.h"

#define NM_RA_TIMEOUT_DEFAULT  ((guint32) 0)
#define NM_RA_TIMEOUT_INFINITY ((guint32) G_MAXINT32)

#define NM_TYPE_NDISC            (nm_ndisc_get_type())
#define NM_NDISC(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_NDISC, NMNDisc))
#define NM_NDISC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_NDISC, NMNDiscClass))
#define NM_IS_NDISC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_NDISC))
#define NM_IS_NDISC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_NDISC))
#define NM_NDISC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_NDISC, NMNDiscClass))

#define NM_NDISC_PLATFORM                     "platform"
#define NM_NDISC_IFINDEX                      "ifindex"
#define NM_NDISC_IFNAME                       "ifname"
#define NM_NDISC_NETWORK_ID                   "network-id"
#define NM_NDISC_ADDR_GEN_MODE                "addr-gen-mode"
#define NM_NDISC_STABLE_TYPE                  "stable-type"
#define NM_NDISC_NODE_TYPE                    "node-type"
#define NM_NDISC_MAX_ADDRESSES                "max-addresses"
#define NM_NDISC_RA_TIMEOUT                   "ra-timeout"
#define NM_NDISC_ROUTER_SOLICITATIONS         "router-solicitations"
#define NM_NDISC_ROUTER_SOLICITATION_INTERVAL "router-solicitation-interval"

#define NM_NDISC_CONFIG_RECEIVED   "config-received"
#define NM_NDISC_RA_TIMEOUT_SIGNAL "ra-timeout-signal"

typedef enum {
    NM_NDISC_DHCP_LEVEL_UNKNOWN,
    NM_NDISC_DHCP_LEVEL_NONE,
    NM_NDISC_DHCP_LEVEL_OTHERCONF,
    NM_NDISC_DHCP_LEVEL_MANAGED
} NMNDiscDHCPLevel;

#define NM_NDISC_INFINITY_U32 ((uint32_t) -1)

/* It's important that this is G_MAXINT64, so that we can meaningfully do
 * MIN(e1, e2) to find the minimum expiry time (and properly handle if any
 * of them is infinity).
 *
 * While usually you assign this to "expiry_msec", you might say the
 * unit of it is milliseconds. But of course, infinity has not really a unit. */
#define NM_NDISC_EXPIRY_INFINITY G_MAXINT64

/* in common cases, the expiry_msec tracks the timestamp in nm_utils_get_monotonic_timestamp_mses()
 * timestamp when the item expires.
 *
 * When we configure an NMNDiscAddress to be announced via the router advertisement,
 * then that address does not have a fixed expiry point in time, instead, the expiry
 * really contains the lifetime from the moment when we send the router advertisement.
 * In that case, the expiry_msec is more a "lifetime" that starts counting at timestamp
 * zero.
 *
 * The unit is milliseconds (but of course, the timestamp is zero, so it doesn't really matter). */
#define NM_NDISC_EXPIRY_BASE_TIMESTAMP ((gint64) 0)

static inline gint64
_nm_ndisc_lifetime_to_expiry(gint64 now_msec, guint32 lifetime)
{
    if (lifetime == NM_NDISC_INFINITY_U32)
        return NM_NDISC_EXPIRY_INFINITY;
    return now_msec + (((gint64) lifetime) * 1000);
}

static inline gint64
_nm_ndisc_lifetime_from_expiry(gint64 now_msec, gint64 expiry_msec, gboolean ceil)
{
    gint64 diff;

    if (expiry_msec == NM_NDISC_EXPIRY_INFINITY)
        return NM_NDISC_INFINITY_U32;

    /* we don't expect nor handle integer overflow. The time stamp and expiry
     * should be reasonably small so that it cannot happen. */

    diff = expiry_msec - now_msec;

    if (diff <= 0)
        return 0;

    if (ceil) {
        /* we ceil() towards the next full second (instead of floor()). */
        diff += 999;
    }

    return NM_MIN(diff / 1000, (gint64)(G_MAXUINT32 - 1));
}

/*****************************************************************************/

typedef struct _NMNDiscGateway {
    struct in6_addr    address;
    gint64             expiry_msec;
    NMIcmpv6RouterPref preference;
} NMNDiscGateway;

typedef struct _NMNDiscAddress {
    struct in6_addr address;
    gint64          expiry_msec;
    gint64          expiry_preferred_msec;
    guint8          dad_counter;
} NMNDiscAddress;

typedef struct _NMNDiscRoute {
    struct in6_addr    network;
    struct in6_addr    gateway;
    gint64             expiry_msec;
    NMIcmpv6RouterPref preference;
    guint8             plen;
} NMNDiscRoute;

typedef struct {
    struct in6_addr address;
    gint64          expiry_msec;
} NMNDiscDNSServer;

typedef struct {
    char * domain;
    gint64 expiry_msec;
} NMNDiscDNSDomain;

typedef enum {
    NM_NDISC_CONFIG_NONE           = 0,
    NM_NDISC_CONFIG_DHCP_LEVEL     = 1 << 0,
    NM_NDISC_CONFIG_GATEWAYS       = 1 << 1,
    NM_NDISC_CONFIG_ADDRESSES      = 1 << 2,
    NM_NDISC_CONFIG_ROUTES         = 1 << 3,
    NM_NDISC_CONFIG_DNS_SERVERS    = 1 << 4,
    NM_NDISC_CONFIG_DNS_DOMAINS    = 1 << 5,
    NM_NDISC_CONFIG_HOP_LIMIT      = 1 << 6,
    NM_NDISC_CONFIG_MTU            = 1 << 7,
    NM_NDISC_CONFIG_REACHABLE_TIME = 1 << 8,
    NM_NDISC_CONFIG_RETRANS_TIMER  = 1 << 9,
} NMNDiscConfigMap;

typedef enum {
    NM_NDISC_NODE_TYPE_INVALID,
    NM_NDISC_NODE_TYPE_HOST,
    NM_NDISC_NODE_TYPE_ROUTER,
} NMNDiscNodeType;

#define NM_NDISC_RFC4861_RTR_SOLICITATION_INTERVAL  4 /* seconds */
#define NM_NDISC_RFC4861_MAX_RTR_SOLICITATION_DELAY 1 /* seconds */

#define NM_NDISC_MAX_ADDRESSES_DEFAULT          16
#define NM_NDISC_ROUTER_SOLICITATIONS_DEFAULT   3 /* RFC4861, MAX_RTR_SOLICITATIONS */
#define NM_NDISC_ROUTER_ADVERTISEMENTS_DEFAULT  3 /* RFC4861, MAX_INITIAL_RTR_ADVERTISEMENTS */
#define NM_NDISC_ROUTER_ADVERT_DELAY            3 /* RFC4861, MIN_DELAY_BETWEEN_RAS */
#define NM_NDISC_ROUTER_ADVERT_INITIAL_INTERVAL 16 /* RFC4861, MAX_INITIAL_RTR_ADVERT_INTERVAL */
#define NM_NDISC_ROUTER_ADVERT_DELAY_MS         500 /* RFC4861, MAX_RA_DELAY_TIME */
#define NM_NDISC_ROUTER_ADVERT_MAX_INTERVAL     600 /* RFC4861, MaxRtrAdvInterval default */
#define NM_NDISC_ROUTER_LIFETIME                900 /* 1.5 * NM_NDISC_ROUTER_ADVERT_MAX_INTERVAL */

struct _NMNDiscPrivate;
struct _NMNDiscDataInternal;

typedef struct {
    NMNDiscDHCPLevel dhcp_level;
    guint32          mtu;
    int              hop_limit;
    guint32          reachable_time_ms;
    guint32          retrans_timer_ms;

    guint gateways_n;
    guint addresses_n;
    guint routes_n;
    guint dns_servers_n;
    guint dns_domains_n;

    const NMNDiscGateway *  gateways;
    const NMNDiscAddress *  addresses;
    const NMNDiscRoute *    routes;
    const NMNDiscDNSServer *dns_servers;
    const NMNDiscDNSDomain *dns_domains;
} NMNDiscData;

/**
 * NMNDisc:
 *
 * Interface-specific structure that handles incoming router advertisements,
 * caches advertised items and removes them when they are obsolete.
 */
typedef struct {
    GObject parent;
    union {
        struct _NMNDiscPrivate *     _priv;
        struct _NMNDiscDataInternal *rdata;
    };
} NMNDisc;

typedef struct {
    GObjectClass parent;

    void (*start)(NMNDisc *ndisc);
    void (*stop)(NMNDisc *ndisc);
    gboolean (*send_rs)(NMNDisc *ndisc, GError **error);
    gboolean (*send_ra)(NMNDisc *ndisc, GError **error);
} NMNDiscClass;

GType nm_ndisc_get_type(void);

void nm_ndisc_emit_config_change(NMNDisc *self, NMNDiscConfigMap changed);

int             nm_ndisc_get_ifindex(NMNDisc *self);
const char *    nm_ndisc_get_ifname(NMNDisc *self);
NMNDiscNodeType nm_ndisc_get_node_type(NMNDisc *self);

gboolean nm_ndisc_set_iid(NMNDisc *ndisc, const NMUtilsIPv6IfaceId iid);
void     nm_ndisc_start(NMNDisc *ndisc);
void     nm_ndisc_stop(NMNDisc *ndisc);
NMNDiscConfigMap
nm_ndisc_dad_failed(NMNDisc *ndisc, const struct in6_addr *address, gboolean emit_changed_signal);
void nm_ndisc_set_config(NMNDisc *     ndisc,
                         const GArray *addresses,
                         const GArray *dns_servers,
                         const GArray *dns_domains);

NMPlatform *nm_ndisc_get_platform(NMNDisc *self);
NMPNetns *  nm_ndisc_netns_get(NMNDisc *self);
gboolean    nm_ndisc_netns_push(NMNDisc *self, NMPNetns **netns);

static inline gboolean
nm_ndisc_dad_addr_is_fail_candidate_event(NMPlatformSignalChangeType  change_type,
                                          const NMPlatformIP6Address *addr)
{
    return !NM_FLAGS_HAS(addr->n_ifa_flags, IFA_F_TEMPORARY)
           && ((change_type == NM_PLATFORM_SIGNAL_CHANGED && addr->n_ifa_flags & IFA_F_DADFAILED)
               || (change_type == NM_PLATFORM_SIGNAL_REMOVED
                   && addr->n_ifa_flags & IFA_F_TENTATIVE));
}

static inline gboolean
nm_ndisc_dad_addr_is_fail_candidate(NMPlatform *platform, const NMPObject *obj)
{
    const NMPlatformIP6Address *addr;

    addr = NMP_OBJECT_CAST_IP6_ADDRESS(
        nm_platform_lookup_obj(platform, NMP_CACHE_ID_TYPE_OBJECT_TYPE, obj));
    if (addr
        && (NM_FLAGS_HAS(addr->n_ifa_flags, IFA_F_TEMPORARY)
            || !NM_FLAGS_HAS(addr->n_ifa_flags, IFA_F_DADFAILED))) {
        /* the address still/again exists and is not in DADFAILED state. Skip it. */
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

struct _NML3ConfigData;

struct _NML3ConfigData *nm_ndisc_data_to_l3cd(NMDedupMultiIndex *       multi_idx,
                                              int                       ifindex,
                                              const NMNDiscData *       rdata,
                                              NMSettingIP6ConfigPrivacy ip6_privacy,
                                              guint32                   route_table,
                                              guint32                   route_metric,
                                              gboolean                  kernel_support_rta_pref,
                                              gboolean kernel_support_extended_ifa_flags);

#endif /* __NETWORKMANAGER_NDISC_H__ */
