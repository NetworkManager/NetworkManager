/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-ndisc.h"

#include <arpa/inet.h>
#include <stdlib.h>

#include "libnm-platform/nm-platform-utils.h"
#include "libnm-platform/nm-platform.h"
#include "libnm-platform/nmp-netns.h"
#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "nm-l3-config-data.h"
#include "nm-l3cfg.h"
#include "nm-ndisc-private.h"
#include "nm-setting-ip6-config.h"
#include "nm-utils.h"

#define _NMLOG_PREFIX_NAME "ndisc"

#define RFC7559_IRT ((gint32) 4)    /* RFC7559, Initial Retransmission Time, in seconds */
#define RFC7559_MRT ((gint32) 3600) /* RFC7559, Maximum Retransmission Time, in seconds */

#define NM_NDISC_PRE_EXPIRY_TIME_MSEC         60000
#define NM_NDISC_PRE_EXPIRY_MIN_LIFETIME_MSEC 120000

#define _SIZE_MAX_GATEWAYS    100u
#define _SIZE_MAX_ADDRESSES   100u
#define _SIZE_MAX_ROUTES      1000u
#define _SIZE_MAX_DNS_SERVERS 64u
#define _SIZE_MAX_DNS_DOMAINS 64u

/*****************************************************************************/

struct _NMNDiscPrivate {
    /* this *must* be the first field. */
    NMNDiscDataInternal rdata;

    const NML3ConfigData *l3cd;

    char *last_error;

    GSource *ra_timeout_source;

    gint32 announcements_left;
    guint  send_ra_id;
    gint32 last_ra;

    gint32 solicit_retransmit_time_msec;
    gint64 last_rs_msec;

    GSource *solicit_timer_source;

    GSource *timeout_expire_source;

    NMUtilsIPv6IfaceId iid;
    gboolean           iid_is_token;

    /* immutable values from here on: */

    union {
        const NMNDiscConfig config;
        NMNDiscConfig       config_;
    };

    NMPNetns *netns;
};

typedef struct _NMNDiscPrivate NMNDiscPrivate;

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_CONFIG, );

enum {
    CONFIG_RECEIVED,
    RA_TIMEOUT_SIGNAL,
    LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

G_DEFINE_TYPE(NMNDisc, nm_ndisc, G_TYPE_OBJECT)

#define NM_NDISC_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMNDisc, NM_IS_NDISC)

/*****************************************************************************/

static void     _config_changed_log(NMNDisc *ndisc, NMNDiscConfigMap changed);
static gboolean timeout_expire_cb(gpointer user_data);

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE(nm_ndisc_dhcp_level_to_string,
                           NMNDiscDHCPLevel,
                           NM_UTILS_LOOKUP_DEFAULT("INVALID"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_NDISC_DHCP_LEVEL_UNKNOWN, "unknown"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_NDISC_DHCP_LEVEL_NONE, "none"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_NDISC_DHCP_LEVEL_OTHERCONF, "otherconf"),
                           NM_UTILS_LOOKUP_STR_ITEM(NM_NDISC_DHCP_LEVEL_MANAGED, "managed"), );

/*****************************************************************************/

NML3ConfigData *
nm_ndisc_data_to_l3cd(NMDedupMultiIndex        *multi_idx,
                      int                       ifindex,
                      const NMNDiscData        *rdata,
                      NMSettingIP6ConfigPrivacy ip6_privacy,
                      NMUtilsIPv6IfaceId       *token)
{
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
    guint32                                 ifa_flags;
    guint                                   i;
    const gint32                            now_sec = nm_utils_get_monotonic_timestamp_sec();

    l3cd = nm_l3_config_data_new(multi_idx, ifindex, NM_IP_CONFIG_SOURCE_NDISC);

    nm_l3_config_data_set_ip6_privacy(l3cd, ip6_privacy);

    ifa_flags = IFA_F_NOPREFIXROUTE;
    if (NM_IN_SET(ip6_privacy,
                  NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR,
                  NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR))
        ifa_flags |= IFA_F_MANAGETEMPADDR;

    for (i = 0; i < rdata->addresses_n; i++) {
        const NMNDiscAddress *ndisc_addr = &rdata->addresses[i];
        NMPlatformIP6Address  a;

        a = (NMPlatformIP6Address){
            .ifindex   = ifindex,
            .address   = ndisc_addr->address,
            .plen      = 64,
            .timestamp = now_sec,
            .lifetime  = _nm_ndisc_lifetime_from_expiry(((gint64) now_sec) * 1000,
                                                       ndisc_addr->expiry_msec,
                                                       TRUE),
            .preferred = _nm_ndisc_lifetime_from_expiry(
                ((gint64) now_sec) * 1000,
                NM_MIN(ndisc_addr->expiry_msec, ndisc_addr->expiry_preferred_msec),
                TRUE),
            .addr_source = NM_IP_CONFIG_SOURCE_NDISC,
            .n_ifa_flags = ifa_flags,
        };

        nm_l3_config_data_add_address_6(l3cd, &a);
    }

    for (i = 0; i < rdata->routes_n; i++) {
        const NMNDiscRoute *ndisc_route = &rdata->routes[i];
        NMPlatformIP6Route  r;

        r = (NMPlatformIP6Route){
            .ifindex       = ifindex,
            .network       = ndisc_route->network,
            .plen          = ndisc_route->plen,
            .gateway       = ndisc_route->gateway,
            .rt_source     = NM_IP_CONFIG_SOURCE_NDISC,
            .table_any     = TRUE,
            .table_coerced = 0,
            .metric_any    = TRUE,
            /* Non-on_link routes get a small penalty */
            .metric  = ndisc_route->duplicate && !ndisc_route->on_link ? 5 : 0,
            .rt_pref = ndisc_route->preference,
        };
        nm_assert((NMIcmpv6RouterPref) r.rt_pref == ndisc_route->preference);

        nm_l3_config_data_add_route_6(l3cd, &r);
    }

    if (rdata->gateways_n > 0) {
        NMPlatformIP6Route r = {
            .rt_source     = NM_IP_CONFIG_SOURCE_NDISC,
            .ifindex       = ifindex,
            .table_any     = TRUE,
            .table_coerced = 0,
            .metric_any    = TRUE,
            .metric        = 0,
        };

        for (i = 0; i < rdata->gateways_n; i++) {
            r.gateway = rdata->gateways[i].address;
            r.rt_pref = rdata->gateways[i].preference;
            nm_assert((NMIcmpv6RouterPref) r.rt_pref == rdata->gateways[i].preference);
            nm_l3_config_data_add_route_6(l3cd, &r);
        }
    }

    for (i = 0; i < rdata->dns_servers_n; i++) {
        nm_l3_config_data_add_nameserver_detail(l3cd,
                                                AF_INET6,
                                                &rdata->dns_servers[i].address,
                                                NULL);
    }

    for (i = 0; i < rdata->dns_domains_n; i++)
        nm_l3_config_data_add_search(l3cd, AF_INET6, rdata->dns_domains[i].domain);

    nm_l3_config_data_set_ndisc_hop_limit(l3cd, rdata->hop_limit);
    nm_l3_config_data_set_ndisc_reachable_time_msec(l3cd, rdata->reachable_time_ms);
    nm_l3_config_data_set_ndisc_retrans_timer_msec(l3cd, rdata->retrans_timer_ms);

    nm_l3_config_data_set_ip6_mtu(l3cd, rdata->mtu);
    if (token)
        nm_l3_config_data_set_ip6_token(l3cd, *token);

    return g_steal_pointer(&l3cd);
}

/*****************************************************************************/

static guint8
_preference_to_priority(NMIcmpv6RouterPref pref)
{
    switch (pref) {
    case NM_ICMPV6_ROUTER_PREF_LOW:
        return 1;
    case NM_ICMPV6_ROUTER_PREF_MEDIUM:
        return 2;
    case NM_ICMPV6_ROUTER_PREF_HIGH:
        return 3;
    case NM_ICMPV6_ROUTER_PREF_INVALID:
        break;
    }
    return 0;
}

/*****************************************************************************/

static gboolean
expiry_next(gint64 now_msec, gint64 expiry_msec, gint64 *next_msec)
{
    if (expiry_msec == NM_NDISC_EXPIRY_INFINITY)
        return TRUE;

    if (expiry_msec <= now_msec) {
        /* expired. */
        return FALSE;
    }

    if (next_msec) {
        if (*next_msec > expiry_msec)
            *next_msec = expiry_msec;
    }

    /* the timestamp is good (not yet expired) */
    return TRUE;
}

static const char *
_get_exp(char *buf, gsize buf_size, gint64 now_msec, gint64 expiry_time)
{
    int l;

    if (expiry_time == NM_NDISC_EXPIRY_INFINITY)
        return "permanent";
    l = g_snprintf(buf, buf_size, "%.3f", ((double) (expiry_time - now_msec)) / 1000);
    nm_assert(l < buf_size);
    return buf;
}

#define get_exp(buf, now_msec, item) \
    _get_exp((buf), G_N_ELEMENTS(buf), (now_msec), (item)->expiry_msec)

/*****************************************************************************/

NMPNetns *
nm_ndisc_netns_get(NMNDisc *self)
{
    g_return_val_if_fail(NM_IS_NDISC(self), NULL);

    return NM_NDISC_GET_PRIVATE(self)->netns;
}

gboolean
nm_ndisc_netns_push(NMNDisc *self, NMPNetns **netns)
{
    NMNDiscPrivate *priv;

    g_return_val_if_fail(NM_IS_NDISC(self), FALSE);

    priv = NM_NDISC_GET_PRIVATE(self);
    if (priv->netns && !nmp_netns_push(priv->netns)) {
        NM_SET_OUT(netns, NULL);
        return FALSE;
    }

    NM_SET_OUT(netns, priv->netns);
    return TRUE;
}

/*****************************************************************************/

int
nm_ndisc_get_ifindex(NMNDisc *self)
{
    g_return_val_if_fail(NM_IS_NDISC(self), 0);

    return nm_l3cfg_get_ifindex(NM_NDISC_GET_PRIVATE(self)->config.l3cfg);
}

const char *
nm_ndisc_get_ifname(NMNDisc *self)
{
    g_return_val_if_fail(NM_IS_NDISC(self), NULL);

    return NM_NDISC_GET_PRIVATE(self)->config.ifname;
}

NMNDiscNodeType
nm_ndisc_get_node_type(NMNDisc *self)
{
    g_return_val_if_fail(NM_IS_NDISC(self), NM_NDISC_NODE_TYPE_INVALID);

    return NM_NDISC_GET_PRIVATE(self)->config.node_type;
}

/*****************************************************************************/

static void
_ASSERT_data_gateways(const NMNDiscDataInternal *data)
{
#if NM_MORE_ASSERTS > 10
    guint                 i, j;
    const NMNDiscGateway *item_prev = NULL;

    if (!data->gateways->len)
        return;

    for (i = 0; i < data->gateways->len; i++) {
        const NMNDiscGateway *item = &nm_g_array_index(data->gateways, NMNDiscGateway, i);

        nm_assert(!IN6_IS_ADDR_UNSPECIFIED(&item->address));
        for (j = 0; j < i; j++) {
            const NMNDiscGateway *item2 = &nm_g_array_index(data->gateways, NMNDiscGateway, j);

            nm_assert(!IN6_ARE_ADDR_EQUAL(&item->address, &item2->address));
        }

        if (i > 0) {
            nm_assert(_preference_to_priority(item_prev->preference)
                      >= _preference_to_priority(item->preference));
        }

        item_prev = item;
    }
#endif
}

/*****************************************************************************/
static bool
is_duplicate_route(const NMNDiscRoute *r0, const NMNDiscRoute *r1)
{
    return IN6_ARE_ADDR_EQUAL(&r0->network, &r1->network) && r0->plen == r1->plen;
}

static void
_data_complete_prepare_routes(GArray *routes)
{
    guint i, j;

    for (i = 0; i < routes->len; i++) {
        NMNDiscRoute *r0 = &nm_g_array_index(routes, NMNDiscRoute, i);

        r0->duplicate = FALSE;
    }
    for (i = 0; i < routes->len; i++) {
        NMNDiscRoute *r0 = &nm_g_array_index(routes, NMNDiscRoute, i);

        for (j = i + 1; j < routes->len; j++) {
            NMNDiscRoute *r1 = &nm_g_array_index(routes, NMNDiscRoute, j);

            if (!is_duplicate_route(r0, r1))
                continue;

            r0->duplicate = TRUE;
            r1->duplicate = TRUE;

            /* Maybe after index j, there is yet another duplicate. But we
            * will find that later, when i becomes j. */
            break;
        }
    }
}

static const NMNDiscData *
_data_complete(NMNDiscDataInternal *data)
{
    _ASSERT_data_gateways(data);

    _data_complete_prepare_routes(data->routes);
#define _SET(data, field)                                      \
    G_STMT_START                                               \
    {                                                          \
        if ((data->public.field##_n = data->field->len) > 0)   \
            data->public.field = (gpointer) data->field->data; \
        else                                                   \
            data->public.field = NULL;                         \
    }                                                          \
    G_STMT_END
    _SET(data, gateways);
    _SET(data, addresses);
    _SET(data, routes);
    _SET(data, dns_servers);
    _SET(data, dns_domains);
#undef _SET
    return &data->public;
}

static void
nm_ndisc_emit_config_change(NMNDisc *self, NMNDiscConfigMap changed)
{
    NMNDiscPrivate                          *priv = NM_NDISC_GET_PRIVATE(self);
    nm_auto_unref_l3cd const NML3ConfigData *l3cd = NULL;
    const NMNDiscData                       *rdata;

    _config_changed_log(self, changed);

    rdata = _data_complete(&NM_NDISC_GET_PRIVATE(self)->rdata),

    l3cd = nm_ndisc_data_to_l3cd(nm_l3cfg_get_multi_idx(priv->config.l3cfg),
                                 nm_l3cfg_get_ifindex(priv->config.l3cfg),
                                 rdata,
                                 priv->config.ip6_privacy,
                                 priv->iid_is_token ? &priv->iid : NULL);
    l3cd = nm_l3_config_data_seal(l3cd);

    if (!nm_l3_config_data_equal(priv->l3cd, l3cd))
        NM_SWAP(&priv->l3cd, &l3cd);

    g_signal_emit(self, signals[CONFIG_RECEIVED], 0, rdata, (guint) changed, priv->l3cd);
}

/*****************************************************************************/

gboolean
nm_ndisc_add_gateway(NMNDisc *ndisc, const NMNDiscGateway *new_item, gint64 now_msec)
{
    NMNDiscDataInternal *rdata = &NM_NDISC_GET_PRIVATE(ndisc)->rdata;
    guint                i;
    guint                insert_idx = G_MAXUINT;

    for (i = 0; i < rdata->gateways->len;) {
        NMNDiscGateway *item = &nm_g_array_index(rdata->gateways, NMNDiscGateway, i);

        if (IN6_ARE_ADDR_EQUAL(&item->address, &new_item->address)) {
            if (new_item->expiry_msec <= now_msec) {
                g_array_remove_index(rdata->gateways, i);
                _ASSERT_data_gateways(rdata);
                return TRUE;
            }

            if (item->preference != new_item->preference) {
                g_array_remove_index(rdata->gateways, i);
                continue;
            }

            if (item->expiry_msec == new_item->expiry_msec)
                return FALSE;

            item->expiry_msec = new_item->expiry_msec;
            _ASSERT_data_gateways(rdata);
            return TRUE;
        }

        /* Put before less preferable gateways. */
        if (_preference_to_priority(item->preference)
                < _preference_to_priority(new_item->preference)
            && insert_idx == G_MAXUINT)
            insert_idx = i;

        i++;
    }

    if (rdata->gateways->len >= _SIZE_MAX_GATEWAYS)
        return FALSE;

    if (new_item->expiry_msec <= now_msec)
        return FALSE;

    g_array_insert_val(rdata->gateways,
                       insert_idx == G_MAXUINT ? rdata->gateways->len : insert_idx,
                       *new_item);
    _ASSERT_data_gateways(rdata);
    return TRUE;
}

/**
 * complete_address:
 * @ndisc: the #NMNDisc
 * @addr: the #NMNDiscAddress
 *
 * Adds the host part to the address that has network part set.
 * If the address already has a host part, add a different host part
 * if possible (this is useful in case DAD failed).
 *
 * Can fail if a different address can not be generated (DAD failure
 * for an EUI-64 address or DAD counter overflow).
 *
 * Returns: %TRUE if the address could be completed, %FALSE otherwise.
 **/
static gboolean
complete_address(NMNDisc *ndisc, NMNDiscAddress *addr)
{
    NMNDiscPrivate *priv;
    GError         *error = NULL;

    g_return_val_if_fail(NM_IS_NDISC(ndisc), FALSE);

    priv = NM_NDISC_GET_PRIVATE(ndisc);
    if (priv->config.addr_gen_mode == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY) {
        if (!nm_utils_ipv6_addr_set_stable_privacy_may_fail(priv->config.stable_type,
                                                            &addr->address,
                                                            priv->config.ifname,
                                                            priv->config.network_id,
                                                            addr->dad_counter++,
                                                            &error)) {
            _LOGW("complete-address: failed to generate a stable-privacy address: %s",
                  error->message);
            g_clear_error(&error);
            return FALSE;
        }
        _LOGD("complete-address: using a stable-privacy address");
        return TRUE;
    }

    if (!priv->iid.id) {
        _LOGW("complete-address: can't generate an EUI-64 address: no interface identifier");
        return FALSE;
    }

    if (addr->address.s6_addr32[2] == 0x0 && addr->address.s6_addr32[3] == 0x0) {
        _LOGD("complete-address: adding an EUI-64 address");
        nm_utils_ipv6_addr_set_interface_identifier(&addr->address, &priv->iid);
        return TRUE;
    }

    _LOGW("complete-address: can't generate a new EUI-64 address");
    return FALSE;
}

static gboolean
nm_ndisc_add_address(NMNDisc              *ndisc,
                     const NMNDiscAddress *new_item,
                     gint64                now_msec,
                     gboolean              from_ra)
{
    NMNDiscPrivate      *priv  = NM_NDISC_GET_PRIVATE(ndisc);
    NMNDiscDataInternal *rdata = &priv->rdata;
    NMNDiscAddress      *new2;
    NMNDiscAddress      *existing = NULL;
    guint                i;

    nm_assert(new_item);
    nm_assert(!IN6_IS_ADDR_UNSPECIFIED(&new_item->address));
    nm_assert(!IN6_IS_ADDR_LINKLOCAL(&new_item->address));
    nm_assert(new_item->expiry_preferred_msec <= new_item->expiry_msec);
    nm_assert((!!from_ra) == (now_msec > 0));

    for (i = 0; i < rdata->addresses->len; i++) {
        NMNDiscAddress *item = &nm_g_array_index(rdata->addresses, NMNDiscAddress, i);

        if (from_ra) {
            /* RFC4862 5.5.3.d, we find an existing address with the same prefix.
             * (note that all prefixes at this point have implicitly length /64). */
            if (memcmp(&item->address, &new_item->address, 8) == 0) {
                existing = item;
                break;
            }
        } else {
            if (IN6_ARE_ADDR_EQUAL(&item->address, &new_item->address)) {
                existing = item;
                break;
            }
        }
    }

    if (existing) {
        gint64 new_expiry_preferred_msec;
        gint64 new_expiry_msec;

        if (from_ra) {
            if (new_item->expiry_msec == NM_NDISC_EXPIRY_INFINITY)
                new_expiry_msec = NM_NDISC_EXPIRY_INFINITY;
            else {
                const gint64 NDISC_PREFIX_LFT_MIN_MSEC = 7200 * 1000; /* RFC4862 5.5.3.e */
                gint64       new_lifetime;
                gint64       existing_lifetime;

                new_lifetime = new_item->expiry_msec - now_msec;
                if (existing->expiry_msec == NM_NDISC_EXPIRY_INFINITY)
                    existing_lifetime = G_MAXINT64;
                else
                    existing_lifetime = existing->expiry_msec - now_msec;

                /* see RFC4862 5.5.3.e */
                if (new_lifetime >= NDISC_PREFIX_LFT_MIN_MSEC
                    || new_lifetime >= existing_lifetime) {
                    /* either extend the lifetime of the new_item lifetime is longer than
                     * NDISC_PREFIX_LFT_MIN_MSEC. */
                    new_expiry_msec = new_item->expiry_msec;
                } else if (existing_lifetime <= NDISC_PREFIX_LFT_MIN_MSEC) {
                    /* keep the current lifetime. */
                    new_expiry_msec = existing->expiry_msec;
                } else {
                    /* trim the current lifetime to NDISC_PREFIX_LFT_MIN_MSEC. */
                    new_expiry_msec = now_msec + NDISC_PREFIX_LFT_MIN_MSEC;
                }
            }

            new_expiry_preferred_msec =
                NM_MIN(new_item->expiry_preferred_msec, new_item->expiry_msec);
            new_expiry_preferred_msec = NM_MIN(new_expiry_preferred_msec, new_expiry_msec);
        } else {
            if (new_item->expiry_msec <= now_msec) {
                g_array_remove_index(rdata->addresses, i);
                return TRUE;
            }

            new_expiry_msec = new_item->expiry_msec;
            new_expiry_preferred_msec =
                NM_MIN(new_item->expiry_preferred_msec, new_item->expiry_msec);
        }

        /* the dad_counter does not get modified. */
        if (new_expiry_msec == existing->expiry_msec
            && new_expiry_preferred_msec == existing->expiry_preferred_msec) {
            return FALSE;
        }

        existing->expiry_msec           = new_expiry_msec;
        existing->expiry_preferred_msec = new_expiry_preferred_msec;
        return TRUE;
    }

    /* we create at most max_addresses autoconf addresses. This is different from
     * what the kernel does, because it considers *all* addresses (including
     * static and other temporary addresses).
     **/
    if (rdata->addresses->len >= priv->config.max_addresses)
        return FALSE;

    if (new_item->expiry_msec <= now_msec)
        return FALSE;

    new2 = nm_g_array_append_new(rdata->addresses, NMNDiscAddress);

    *new2 = *new_item;

    new2->expiry_preferred_msec = NM_MIN(new2->expiry_preferred_msec, new2->expiry_msec);

    if (from_ra) {
        new2->dad_counter = 0;
        if (!complete_address(ndisc, new2)) {
            g_array_set_size(rdata->addresses, rdata->addresses->len - 1);
            return FALSE;
        }
    }

    return TRUE;
}

gboolean
nm_ndisc_complete_and_add_address(NMNDisc *ndisc, const NMNDiscAddress *new_item, gint64 now_msec)
{
    return nm_ndisc_add_address(ndisc, new_item, now_msec, TRUE);
}

gboolean
nm_ndisc_add_route(NMNDisc *ndisc, const NMNDiscRoute *new_item, gint64 now_msec)
{
    NMNDiscPrivate      *priv;
    NMNDiscDataInternal *rdata;
    guint                i;
    guint                insert_idx = G_MAXUINT;
    gboolean             changed    = FALSE;

    if (new_item->plen == 0 || new_item->plen > 128) {
        /* Only expect non-default routes.  The router has no idea what the
         * local configuration or user preferences are, so sending routes
         * with a prefix length of 0 must be ignored by NMNDisc.
         *
         * Also, upper layers also don't expect that NMNDisc exposes routes
         * with a plen or zero or larger then 128.
         */
        g_return_val_if_reached(FALSE);
    }

    priv  = NM_NDISC_GET_PRIVATE(ndisc);
    rdata = &priv->rdata;

    for (i = 0; i < rdata->routes->len;) {
        NMNDiscRoute *item = &nm_g_array_index(rdata->routes, NMNDiscRoute, i);

        /*
         * It is possible that two entries in rdata->routes have
         * the same prefix as well as the same prefix length.
         * One of them, however, refers to the on-link prefix,
         * and the other one to a route from the route information field.
         * Moreover, they might have different route preferences.
         * Hence, if both routes differ in the on-link flag,
         * comparison is aborted, and both routes are added.
         */
        if (IN6_ARE_ADDR_EQUAL(&item->network, &new_item->network) && item->plen == new_item->plen
            && item->on_link == new_item->on_link) {
            if (new_item->expiry_msec <= now_msec) {
                g_array_remove_index(rdata->routes, i);
                return TRUE;
            }

            if (item->preference != new_item->preference) {
                g_array_remove_index(rdata->routes, i);
                changed = TRUE;
                continue;
            }

            if (item->expiry_msec == new_item->expiry_msec
                && IN6_ARE_ADDR_EQUAL(&item->gateway, &new_item->gateway))
                return FALSE;

            item->expiry_msec = new_item->expiry_msec;
            item->gateway     = new_item->gateway;
            return TRUE;
        }

        /* Put before less preferable routes. */
        if (_preference_to_priority(item->preference)
                < _preference_to_priority(new_item->preference)
            && insert_idx == G_MAXUINT)
            insert_idx = i;

        i++;
    }

    if (rdata->routes->len >= _SIZE_MAX_ROUTES)
        return FALSE;

    if (new_item->expiry_msec <= now_msec) {
        nm_assert(!changed);
        return FALSE;
    }

    g_array_insert_val(rdata->routes, insert_idx == G_MAXUINT ? 0u : insert_idx, *new_item);
    return TRUE;
}

gboolean
nm_ndisc_add_dns_server(NMNDisc *ndisc, const NMNDiscDNSServer *new_item, gint64 now_msec)
{
    NMNDiscPrivate      *priv;
    NMNDiscDataInternal *rdata;
    guint                i;

    priv  = NM_NDISC_GET_PRIVATE(ndisc);
    rdata = &priv->rdata;

    for (i = 0; i < rdata->dns_servers->len; i++) {
        NMNDiscDNSServer *item = &nm_g_array_index(rdata->dns_servers, NMNDiscDNSServer, i);

        if (IN6_ARE_ADDR_EQUAL(&item->address, &new_item->address)) {
            if (new_item->expiry_msec <= now_msec) {
                g_array_remove_index(rdata->dns_servers, i);
                return TRUE;
            }

            if (item->expiry_msec == new_item->expiry_msec)
                return FALSE;

            item->expiry_msec = new_item->expiry_msec;
            return TRUE;
        }
    }

    if (rdata->dns_servers->len >= _SIZE_MAX_DNS_SERVERS)
        return FALSE;

    if (new_item->expiry_msec <= now_msec)
        return FALSE;

    g_array_append_val(rdata->dns_servers, *new_item);
    return TRUE;
}

/* Copies new_item->domain if 'new_item' is added to the dns_domains list */
gboolean
nm_ndisc_add_dns_domain(NMNDisc *ndisc, const NMNDiscDNSDomain *new_item, gint64 now_msec)
{
    NMNDiscPrivate      *priv;
    NMNDiscDataInternal *rdata;
    NMNDiscDNSDomain    *item;
    guint                i;

    priv  = NM_NDISC_GET_PRIVATE(ndisc);
    rdata = &priv->rdata;

    for (i = 0; i < rdata->dns_domains->len; i++) {
        item = &nm_g_array_index(rdata->dns_domains, NMNDiscDNSDomain, i);

        if (nm_streq(item->domain, new_item->domain)) {
            if (new_item->expiry_msec <= now_msec) {
                g_array_remove_index(rdata->dns_domains, i);
                return TRUE;
            }

            if (item->expiry_msec == new_item->expiry_msec)
                return FALSE;

            item->expiry_msec = new_item->expiry_msec;
            return TRUE;
        }
    }

    if (rdata->dns_domains->len >= _SIZE_MAX_DNS_DOMAINS)
        return FALSE;

    if (new_item->expiry_msec <= now_msec)
        return FALSE;

    item  = nm_g_array_append_new(rdata->dns_domains, NMNDiscDNSDomain);
    *item = (NMNDiscDNSDomain){
        .domain      = g_strdup(new_item->domain),
        .expiry_msec = new_item->expiry_msec,
    };
    return TRUE;
}

/*****************************************************************************/

#define _MAYBE_WARN(...)                                                   \
    G_STMT_START                                                           \
    {                                                                      \
        gboolean _different_message;                                       \
                                                                           \
        _different_message = !nm_streq0(priv->last_error, error->message); \
        _NMLOG(_different_message ? LOGL_WARN : LOGL_DEBUG, __VA_ARGS__);  \
        if (_different_message) {                                          \
            nm_clear_g_free(&priv->last_error);                            \
            priv->last_error = g_strdup(error->message);                   \
        }                                                                  \
    }                                                                      \
    G_STMT_END

static gint32
solicit_retransmit_time_jitter(gint32 solicit_retransmit_time_msec)
{
    gint32 ten_percent;

    nm_assert(solicit_retransmit_time_msec > 0);
    nm_assert(solicit_retransmit_time_msec < 3 * RFC7559_MRT * 1000);

    /* Add a ±10% jitter.
     *
     * This is the "RAND" parameter from https://tools.ietf.org/html/rfc3315#section-14
     * as requested by RFC7559.  */

    ten_percent = NM_MAX(1, solicit_retransmit_time_msec / 10);

    return solicit_retransmit_time_msec - ten_percent
           + ((gint32) (g_random_int() % (2u * ((guint32) ten_percent))));
}

static gboolean
solicit_timer_cb(gpointer user_data)
{
    const gint32                TIMEOUT_APPROX_THRESHOLD_SEC = 10000;
    nm_auto_pop_netns NMPNetns *netns                        = NULL;
    NMNDisc                    *ndisc                        = user_data;
    NMNDiscClass               *klass                        = NM_NDISC_GET_CLASS(ndisc);
    NMNDiscPrivate             *priv                         = NM_NDISC_GET_PRIVATE(ndisc);
    gs_free_error GError       *error                        = NULL;
    gint32                      timeout_msec;

    if (!nm_ndisc_netns_push(ndisc, &netns)) {
        nm_utils_error_set(&error,
                           NM_UTILS_ERROR_UNKNOWN,
                           "failure to switch netns for soliciting routers");
    } else
        klass->send_rs(ndisc, &error);

    if (error)
        _MAYBE_WARN("solicit: failure sending router solicitation: %s", error->message);
    else {
        _LOGT("solicit: router solicitation sent");
        nm_clear_g_free(&priv->last_error);

        priv->last_rs_msec = nm_utils_get_monotonic_timestamp_msec();
    }

    /* https://tools.ietf.org/html/rfc4861#section-6.3.7 describes how to send solicitations:
     *
     *   > ... a host SHOULD transmit up to MAX_RTR_SOLICITATIONS Router Solicitation messages,
     *   > each separated by at least RTR_SOLICITATION_INTERVAL seconds.
     *
     * but this was extended by https://tools.ietf.org/html/rfc7559#section-2 to send continuously
     * and with exponential backoff (detailed the algorithm in https://tools.ietf.org/html/rfc3315#section-14).
     * We do RFC7559.
     */
    if (priv->solicit_retransmit_time_msec == 0) {
        G_STATIC_ASSERT(RFC7559_IRT == NM_NDISC_RFC4861_RTR_SOLICITATION_INTERVAL);
        priv->solicit_retransmit_time_msec = solicit_retransmit_time_jitter(RFC7559_IRT * 1000);
        timeout_msec                       = priv->solicit_retransmit_time_msec;
    } else {
        priv->solicit_retransmit_time_msec +=
            solicit_retransmit_time_jitter(priv->solicit_retransmit_time_msec);
        timeout_msec = priv->solicit_retransmit_time_msec;
        if (priv->solicit_retransmit_time_msec > RFC7559_MRT * 1000) {
            priv->solicit_retransmit_time_msec = RFC7559_MRT * 1000;
            timeout_msec = solicit_retransmit_time_jitter(priv->solicit_retransmit_time_msec);
        }
    }

    _LOGD("solicit: schedule sending next solicitation in%s %.3f seconds",
          timeout_msec / 1000 >= TIMEOUT_APPROX_THRESHOLD_SEC ? " about" : "",
          ((double) timeout_msec) / 1000);

    nm_clear_g_source_inst(&priv->solicit_timer_source);
    priv->solicit_timer_source = nm_g_timeout_add_source_approx(timeout_msec,
                                                                TIMEOUT_APPROX_THRESHOLD_SEC,
                                                                solicit_timer_cb,
                                                                ndisc);
    return G_SOURCE_CONTINUE;
}

static void
solicit_timer_start(NMNDisc *ndisc)
{
    NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE(ndisc);
    gint32          delay_msec;

    /* rfc4861, Section 6.3.7:
     *
     * We should randomly wait up to NM_NDISC_RFC4861_MAX_RTR_SOLICITATION_DELAY (1 second)
     * before sending the first RS. RFC4861 is from 2007, I don't think 1 second is
     * a suitable delay in 2021. Wait only up to 250 msec instead. */

    delay_msec =
        g_random_int() % ((guint32) (NM_NDISC_RFC4861_MAX_RTR_SOLICITATION_DELAY * 1000 / 4));

    _LOGD("solicit: schedule sending first solicitation (of %d) in %.3f seconds",
          priv->config.router_solicitations,
          ((double) delay_msec) / 1000);

    priv->solicit_retransmit_time_msec = 0;
    nm_clear_g_source_inst(&priv->solicit_timer_source);
    priv->solicit_timer_source = nm_g_timeout_add_source(delay_msec, solicit_timer_cb, ndisc);
}

/*****************************************************************************/

static gboolean
announce_router(NMNDisc *ndisc)
{
    nm_auto_pop_netns NMPNetns *netns = NULL;
    NMNDiscClass               *klass = NM_NDISC_GET_CLASS(ndisc);
    NMNDiscPrivate             *priv  = NM_NDISC_GET_PRIVATE(ndisc);
    GError                     *error = NULL;

    if (!nm_ndisc_netns_push(ndisc, &netns))
        return G_SOURCE_REMOVE;

    priv->last_ra = nm_utils_get_monotonic_timestamp_sec();
    if (klass->send_ra(ndisc, &error)) {
        _LOGD("router advertisement sent");
        nm_clear_g_free(&priv->last_error);
    } else {
        _MAYBE_WARN("failure sending router advertisement: %s", error->message);
        g_clear_error(&error);
    }

    if (--priv->announcements_left) {
        _LOGD("will resend an initial router advertisement");

        /* Schedule next initial announcement retransmit. */
        priv->send_ra_id =
            g_timeout_add_seconds(g_random_int_range(NM_NDISC_ROUTER_ADVERT_DELAY,
                                                     NM_NDISC_ROUTER_ADVERT_INITIAL_INTERVAL),
                                  (GSourceFunc) announce_router,
                                  ndisc);
    } else {
        _LOGD("will send an unsolicited router advertisement");

        /* Schedule next unsolicited announcement. */
        priv->announcements_left = 1;
        priv->send_ra_id         = g_timeout_add_seconds(NM_NDISC_ROUTER_ADVERT_MAX_INTERVAL,
                                                 (GSourceFunc) announce_router,
                                                 ndisc);
    }

    return G_SOURCE_REMOVE;
}

static void
announce_router_initial(NMNDisc *ndisc)
{
    NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE(ndisc);

    _LOGD("will send an initial router advertisement");

    /* Retry three more times. */
    priv->announcements_left = NM_NDISC_ROUTER_ADVERTISEMENTS_DEFAULT;

    /* Unschedule an unsolicited resend if we are allowed to send now. */
    if (G_LIKELY(nm_utils_get_monotonic_timestamp_sec() - priv->last_ra
                 > NM_NDISC_ROUTER_ADVERT_DELAY))
        nm_clear_g_source(&priv->send_ra_id);

    /* Schedule the initial send rather early. Clamp the delay by minimal
     * delay and not the initial advert internal so that we start fast. */
    if (G_LIKELY(!priv->send_ra_id)) {
        priv->send_ra_id =
            g_timeout_add_seconds(g_random_int_range(0, NM_NDISC_ROUTER_ADVERT_DELAY),
                                  (GSourceFunc) announce_router,
                                  ndisc);
    }
}

static void
announce_router_solicited(NMNDisc *ndisc)
{
    NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE(ndisc);

    _LOGD("will send an solicited router advertisement");

    /* Unschedule an unsolicited resend if we are allowed to send now. */
    if (nm_utils_get_monotonic_timestamp_sec() - priv->last_ra > NM_NDISC_ROUTER_ADVERT_DELAY)
        nm_clear_g_source(&priv->send_ra_id);

    if (!priv->send_ra_id) {
        priv->send_ra_id = g_timeout_add(g_random_int_range(0, NM_NDISC_ROUTER_ADVERT_DELAY_MS),
                                         (GSourceFunc) announce_router,
                                         ndisc);
    }
}

/*****************************************************************************/

void
nm_ndisc_set_config(NMNDisc *ndisc, const NML3ConfigData *l3cd)
{
    gboolean           changed = FALSE;
    const char *const *strvarr;
    NMDedupMultiIter   iter;
    const NMPObject   *obj;
    guint              len;
    guint              i;
    gint32             fake_now = NM_NDISC_EXPIRY_BASE_TIMESTAMP / 1000;

    nm_assert(NM_IS_NDISC(ndisc));
    nm_assert(nm_ndisc_get_node_type(ndisc) == NM_NDISC_NODE_TYPE_ROUTER);

    nm_l3_config_data_iter_obj_for_each (&iter, l3cd, &obj, NMP_OBJECT_TYPE_IP6_ADDRESS) {
        const NMPlatformIP6Address *addr = NMP_OBJECT_CAST_IP6_ADDRESS(obj);
        guint32                     preferred;
        guint32                     lifetime;
        NMNDiscAddress              a;

        if (IN6_IS_ADDR_UNSPECIFIED(&addr->address) || IN6_IS_ADDR_LINKLOCAL(&addr->address))
            continue;

        if (addr->n_ifa_flags & IFA_F_TENTATIVE || addr->n_ifa_flags & IFA_F_DADFAILED)
            continue;

        if (addr->plen != 64)
            continue;

        lifetime = nmp_utils_lifetime_get(addr->timestamp,
                                          addr->lifetime,
                                          addr->preferred,
                                          &fake_now,
                                          &preferred);
        if (!lifetime)
            continue;

        a = (NMNDiscAddress){
            .address     = addr->address,
            .expiry_msec = _nm_ndisc_lifetime_to_expiry(NM_NDISC_EXPIRY_BASE_TIMESTAMP, lifetime),
            .expiry_preferred_msec =
                _nm_ndisc_lifetime_to_expiry(NM_NDISC_EXPIRY_BASE_TIMESTAMP, preferred),
        };

        if (nm_ndisc_add_address(ndisc, &a, 0, FALSE))
            changed = TRUE;
    }

    strvarr = NULL;
    len     = 0;
    if (l3cd)
        strvarr = nm_l3_config_data_get_nameservers(l3cd, AF_INET6, &len);
    for (i = 0; i < len; i++) {
        struct in6_addr  a;
        NMNDiscDNSServer n;

        if (!nm_utils_dnsname_parse_assert(AF_INET6, strvarr[i], NULL, &a, NULL))
            continue;

        n = (NMNDiscDNSServer){
            .address     = a,
            .expiry_msec = _nm_ndisc_lifetime_to_expiry(NM_NDISC_EXPIRY_BASE_TIMESTAMP,
                                                        NM_NDISC_ROUTER_LIFETIME),
        };
        if (nm_ndisc_add_dns_server(ndisc, &n, G_MININT64))
            changed = TRUE;
    }

    strvarr = NULL;
    len     = 0;
    if (l3cd)
        strvarr = nm_l3_config_data_get_searches(l3cd, AF_INET6, &len);
    for (i = 0; i < len; i++) {
        NMNDiscDNSDomain n;

        n = (NMNDiscDNSDomain){
            .domain      = (char *) strvarr[i],
            .expiry_msec = _nm_ndisc_lifetime_to_expiry(NM_NDISC_EXPIRY_BASE_TIMESTAMP,
                                                        NM_NDISC_ROUTER_LIFETIME),
        };
        if (nm_ndisc_add_dns_domain(ndisc, &n, G_MININT64))
            changed = TRUE;
    }

    if (changed)
        announce_router_initial(ndisc);
}

/**
 * nm_ndisc_set_iid:
 * @ndisc: the #NMNDisc
 * @iid: the new interface ID
 *
 * Sets the "Modified EUI-64" interface ID to be used when generating
 * IPv6 addresses using received prefixes. Identifiers are either generated
 * from the hardware addresses or manually set by the operator with
 * "ip token" command.
 *
 * Upon token change (or initial setting) all addresses generated using
 * the old identifier are removed. The caller should ensure the addresses
 * will be reset by soliciting router advertisements.
 *
 * In case the stable privacy addressing is used %FALSE is returned and
 * addresses are left untouched.
 *
 * Returns: %TRUE if addresses need to be regenerated, %FALSE otherwise.
 **/
gboolean
nm_ndisc_set_iid(NMNDisc *ndisc, const NMUtilsIPv6IfaceId iid, gboolean is_token)
{
    NMNDiscPrivate      *priv;
    NMNDiscDataInternal *rdata;

    g_return_val_if_fail(NM_IS_NDISC(ndisc), FALSE);

    priv               = NM_NDISC_GET_PRIVATE(ndisc);
    priv->iid_is_token = is_token;
    rdata              = &priv->rdata;

    if (priv->iid.id != iid.id) {
        priv->iid = iid;

        if (priv->config.addr_gen_mode == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY)
            return FALSE;

        if (rdata->addresses->len) {
            _LOGD("IPv6 interface identifier changed, flushing addresses");
            g_array_remove_range(rdata->addresses, 0, rdata->addresses->len);
            nm_ndisc_emit_config_change(ndisc, NM_NDISC_CONFIG_ADDRESSES);
            solicit_timer_start(ndisc);
        }
        return TRUE;
    }

    return FALSE;
}

static gboolean
ra_timeout_cb(gpointer user_data)
{
    NMNDisc *ndisc = NM_NDISC(user_data);

    nm_clear_g_source_inst(&NM_NDISC_GET_PRIVATE(ndisc)->ra_timeout_source);
    g_signal_emit(ndisc, signals[RA_TIMEOUT_SIGNAL], 0);
    return G_SOURCE_CONTINUE;
}

void
nm_ndisc_start(NMNDisc *ndisc)
{
    nm_auto_pop_netns NMPNetns *netns = NULL;
    NMNDiscPrivate             *priv;

    g_return_if_fail(NM_IS_NDISC(ndisc));

    priv = NM_NDISC_GET_PRIVATE(ndisc);

    nm_assert(NM_NDISC_GET_CLASS(ndisc)->start);
    nm_assert(!priv->ra_timeout_source);

    _LOGD("starting neighbor discovery for ifindex %d%s",
          nm_l3cfg_get_ifindex(priv->config.l3cfg),
          priv->config.node_type == NM_NDISC_NODE_TYPE_HOST ? " (solicit)" : " (announce)");

    if (!nm_ndisc_netns_push(ndisc, &netns))
        return;

    NM_NDISC_GET_CLASS(ndisc)->start(ndisc);

    if (priv->config.node_type == NM_NDISC_NODE_TYPE_HOST) {
        G_STATIC_ASSERT_EXPR(NM_RA_TIMEOUT_DEFAULT == 0);
        G_STATIC_ASSERT_EXPR(NM_RA_TIMEOUT_INFINITY == G_MAXINT32);
        nm_assert(priv->config.ra_timeout > 0u);
        nm_assert(priv->config.ra_timeout <= NM_RA_TIMEOUT_INFINITY);

        if (priv->config.ra_timeout < NM_RA_TIMEOUT_INFINITY) {
            guint timeout_msec;

            _LOGD("scheduling RA timeout in %u seconds", priv->config.ra_timeout);
            if (priv->config.ra_timeout < G_MAXUINT / 1000u)
                timeout_msec = priv->config.ra_timeout * 1000u;
            else
                timeout_msec = G_MAXUINT;
            priv->ra_timeout_source = nm_g_timeout_add_source(timeout_msec, ra_timeout_cb, ndisc);
        }

        solicit_timer_start(ndisc);
        return;
    }

    nm_assert(priv->config.ra_timeout == 0u);
    nm_assert(priv->config.node_type == NM_NDISC_NODE_TYPE_ROUTER);
    announce_router_initial(ndisc);
}

void
nm_ndisc_stop(NMNDisc *ndisc)
{
    nm_auto_pop_netns NMPNetns *netns = NULL;
    NMNDiscDataInternal        *rdata;
    NMNDiscPrivate             *priv;

    g_return_if_fail(NM_IS_NDISC(ndisc));

    priv = NM_NDISC_GET_PRIVATE(ndisc);

    nm_assert(NM_NDISC_GET_CLASS(ndisc)->stop);

    _LOGD("stopping neighbor discovery for ifindex %d", nm_l3cfg_get_ifindex(priv->config.l3cfg));

    if (!nm_ndisc_netns_push(ndisc, &netns))
        return;

    NM_NDISC_GET_CLASS(ndisc)->stop(ndisc);

    rdata = &priv->rdata;

    g_array_set_size(rdata->gateways, 0);
    g_array_set_size(rdata->addresses, 0);
    g_array_set_size(rdata->routes, 0);
    g_array_set_size(rdata->dns_servers, 0);
    g_array_set_size(rdata->dns_domains, 0);
    priv->rdata.public.hop_limit = 64;

    nm_clear_g_source_inst(&priv->ra_timeout_source);
    nm_clear_g_source(&priv->send_ra_id);
    nm_clear_g_free(&priv->last_error);
    nm_clear_g_source_inst(&priv->timeout_expire_source);

    priv->solicit_retransmit_time_msec = 0;
    nm_clear_g_source_inst(&priv->solicit_timer_source);

    priv->announcements_left = 0;

    priv->last_ra = G_MININT32;
}

NMNDiscConfigMap
nm_ndisc_dad_failed(NMNDisc *ndisc, GArray *addresses, gboolean emit_changed_signal)
{
    NMNDiscDataInternal *rdata;
    guint                i;
    guint                j;
    gboolean             changed = FALSE;

    g_return_val_if_fail(addresses, NM_NDISC_CONFIG_NONE);

    rdata = &NM_NDISC_GET_PRIVATE(ndisc)->rdata;

    for (i = 0; i < addresses->len; i++) {
        const struct in6_addr *addr = &nm_g_array_index(addresses, struct in6_addr, i);

        for (j = 0; j < rdata->addresses->len;) {
            NMNDiscAddress *item = &nm_g_array_index(rdata->addresses, NMNDiscAddress, j);

            if (IN6_ARE_ADDR_EQUAL(&item->address, addr)) {
                char sbuf[NM_INET_ADDRSTRLEN];

                _LOGI("DAD failed for discovered address %s", nm_inet6_ntop(addr, sbuf));
                changed = TRUE;
                if (!complete_address(ndisc, item)) {
                    g_array_remove_index(rdata->addresses, j);
                    continue;
                }
            }
            j++;
        }
    }

    if (emit_changed_signal && changed)
        nm_ndisc_emit_config_change(ndisc, NM_NDISC_CONFIG_ADDRESSES);

    return changed ? NM_NDISC_CONFIG_ADDRESSES : NM_NDISC_CONFIG_NONE;
}

#define CONFIG_MAP_MAX_STR 7

static void
config_map_to_string(NMNDiscConfigMap map, char *p)
{
    if (map & NM_NDISC_CONFIG_DHCP_LEVEL)
        *p++ = 'd';
    if (map & NM_NDISC_CONFIG_GATEWAYS)
        *p++ = 'G';
    if (map & NM_NDISC_CONFIG_ADDRESSES)
        *p++ = 'A';
    if (map & NM_NDISC_CONFIG_ROUTES)
        *p++ = 'R';
    if (map & NM_NDISC_CONFIG_DNS_SERVERS)
        *p++ = 'S';
    if (map & NM_NDISC_CONFIG_DNS_DOMAINS)
        *p++ = 'D';
    *p = '\0';
}

static void
_config_changed_log(NMNDisc *ndisc, NMNDiscConfigMap changed)
{
    NMNDiscPrivate      *priv;
    NMNDiscDataInternal *rdata;
    guint                i;
    char                 changedstr[CONFIG_MAP_MAX_STR];
    char                 addrstr[NM_INET_ADDRSTRLEN];
    char                 str_pref[35];
    char                 str_exp[100];
    gint64               now_msec;

    if (!_LOGD_ENABLED())
        return;

    now_msec = nm_utils_get_monotonic_timestamp_msec();

    priv  = NM_NDISC_GET_PRIVATE(ndisc);
    rdata = &priv->rdata;

    config_map_to_string(changed, changedstr);
    _LOGD("neighbor discovery configuration changed [%s]:", changedstr);
    _LOGD("  dhcp-level %s", nm_ndisc_dhcp_level_to_string(priv->rdata.public.dhcp_level));

    if (rdata->public.hop_limit)
        _LOGD("  hop limit      : %d", rdata->public.hop_limit);
    if (rdata->public.reachable_time_ms)
        _LOGD("  reachable time : %u", (guint) rdata->public.reachable_time_ms);
    if (rdata->public.retrans_timer_ms)
        _LOGD("  retrans timer  : %u", (guint) rdata->public.retrans_timer_ms);

    for (i = 0; i < rdata->gateways->len; i++) {
        const NMNDiscGateway *gateway = &nm_g_array_index(rdata->gateways, NMNDiscGateway, i);

        _LOGD("  gateway %s pref %s exp %s",
              nm_inet6_ntop(&gateway->address, addrstr),
              nm_icmpv6_router_pref_to_string(gateway->preference, str_pref, sizeof(str_pref)),
              get_exp(str_exp, now_msec, gateway));
    }
    for (i = 0; i < rdata->addresses->len; i++) {
        const NMNDiscAddress *address = &nm_g_array_index(rdata->addresses, NMNDiscAddress, i);

        _LOGD("  address %s exp %s",
              nm_inet6_ntop(&address->address, addrstr),
              get_exp(str_exp, now_msec, address));
    }
    for (i = 0; i < rdata->routes->len; i++) {
        const NMNDiscRoute *route = &nm_g_array_index(rdata->routes, NMNDiscRoute, i);
        char                sbuf[NM_INET_ADDRSTRLEN];

        _LOGD("  route %s/%u via %s pref %s exp %s",
              nm_inet6_ntop(&route->network, addrstr),
              (guint) route->plen,
              nm_inet6_ntop(&route->gateway, sbuf),
              nm_icmpv6_router_pref_to_string(route->preference, str_pref, sizeof(str_pref)),
              get_exp(str_exp, now_msec, route));
    }
    for (i = 0; i < rdata->dns_servers->len; i++) {
        const NMNDiscDNSServer *dns_server =
            &nm_g_array_index(rdata->dns_servers, NMNDiscDNSServer, i);

        _LOGD("  dns_server %s exp %s",
              nm_inet6_ntop(&dns_server->address, addrstr),
              get_exp(str_exp, now_msec, dns_server));
    }
    for (i = 0; i < rdata->dns_domains->len; i++) {
        const NMNDiscDNSDomain *dns_domain =
            &nm_g_array_index(rdata->dns_domains, NMNDiscDNSDomain, i);

        _LOGD("  dns_domain %s exp %s", dns_domain->domain, get_exp(str_exp, now_msec, dns_domain));
    }
}

/*****************************************************************************/

static gboolean
_array_set_size_max(GArray *array, guint size_max)
{
    nm_assert(array);
    nm_assert(size_max > 0u);

    if (array->len <= size_max)
        return FALSE;

    g_array_set_size(array, size_max);
    return TRUE;
}

static void
clean_gateways(NMNDisc *ndisc, gint64 now_msec, NMNDiscConfigMap *changed, gint64 *next_msec)
{
    NMNDiscDataInternal *rdata = &NM_NDISC_GET_PRIVATE(ndisc)->rdata;
    NMNDiscGateway      *arr;
    guint                i;
    guint                j;

    if (rdata->gateways->len == 0)
        return;

    arr = &nm_g_array_first(rdata->gateways, NMNDiscGateway);

    for (i = 0, j = 0; i < rdata->gateways->len; i++) {
        if (!expiry_next(now_msec, arr[i].expiry_msec, next_msec))
            continue;
        if (i != j)
            arr[j] = arr[i];
        j++;
    }

    if (i != j) {
        *changed |= NM_NDISC_CONFIG_GATEWAYS;
        g_array_set_size(rdata->gateways, j);
    }

    if (_array_set_size_max(rdata->gateways, _SIZE_MAX_GATEWAYS))
        *changed |= NM_NDISC_CONFIG_GATEWAYS;

    _ASSERT_data_gateways(rdata);
}

static void
clean_addresses(NMNDisc *ndisc, gint64 now_msec, NMNDiscConfigMap *changed, gint64 *next_msec)
{
    NMNDiscPrivate      *priv  = NM_NDISC_GET_PRIVATE(ndisc);
    NMNDiscDataInternal *rdata = &NM_NDISC_GET_PRIVATE(ndisc)->rdata;
    NMNDiscAddress      *arr;
    guint                i;
    guint                j;

    if (rdata->addresses->len == 0)
        return;

    arr = &nm_g_array_first(rdata->addresses, NMNDiscAddress);

    for (i = 0, j = 0; i < rdata->addresses->len; i++) {
        if (!expiry_next(now_msec, arr[i].expiry_msec, next_msec))
            continue;
        if (i != j)
            arr[j] = arr[i];
        j++;
    }

    if (i != j) {
        *changed = NM_NDISC_CONFIG_ADDRESSES;
        g_array_set_size(rdata->addresses, j);
    }

    if (_array_set_size_max(rdata->gateways, priv->config.max_addresses))
        *changed |= NM_NDISC_CONFIG_ADDRESSES;
}

static void
clean_routes(NMNDisc *ndisc, gint64 now_msec, NMNDiscConfigMap *changed, gint64 *next_msec)
{
    NMNDiscDataInternal *rdata = &NM_NDISC_GET_PRIVATE(ndisc)->rdata;
    NMNDiscRoute        *arr;
    guint                i;
    guint                j;

    if (rdata->routes->len == 0)
        return;

    arr = &nm_g_array_first(rdata->routes, NMNDiscRoute);

    for (i = 0, j = 0; i < rdata->routes->len; i++) {
        if (!expiry_next(now_msec, arr[i].expiry_msec, next_msec))
            continue;
        if (i != j)
            arr[j] = arr[i];
        j++;
    }

    if (i != j) {
        *changed |= NM_NDISC_CONFIG_ROUTES;
        g_array_set_size(rdata->routes, j);
    }

    if (_array_set_size_max(rdata->gateways, _SIZE_MAX_ROUTES))
        *changed |= NM_NDISC_CONFIG_ROUTES;
}

static void
clean_dns_servers(NMNDisc *ndisc, gint64 now_msec, NMNDiscConfigMap *changed, gint64 *next_msec)
{
    NMNDiscDataInternal *rdata = &NM_NDISC_GET_PRIVATE(ndisc)->rdata;
    NMNDiscDNSServer    *arr;
    guint                i;
    guint                j;

    if (rdata->dns_servers->len == 0)
        return;

    arr = &nm_g_array_first(rdata->dns_servers, NMNDiscDNSServer);

    for (i = 0, j = 0; i < rdata->dns_servers->len; i++) {
        if (!expiry_next(now_msec, arr[i].expiry_msec, next_msec))
            continue;
        if (i != j)
            arr[j] = arr[i];
        j++;
    }

    if (i != j) {
        *changed |= NM_NDISC_CONFIG_DNS_SERVERS;
        g_array_set_size(rdata->dns_servers, j);
    }

    if (_array_set_size_max(rdata->gateways, _SIZE_MAX_DNS_SERVERS))
        *changed |= NM_NDISC_CONFIG_DNS_SERVERS;
}

static void
clean_dns_domains(NMNDisc *ndisc, gint64 now_msec, NMNDiscConfigMap *changed, gint64 *next_msec)
{
    NMNDiscDataInternal *rdata = &NM_NDISC_GET_PRIVATE(ndisc)->rdata;
    NMNDiscDNSDomain    *arr;
    guint                i;
    guint                j;

    if (rdata->dns_domains->len == 0)
        return;

    arr = &nm_g_array_first(rdata->dns_domains, NMNDiscDNSDomain);

    for (i = 0, j = 0; i < rdata->dns_domains->len; i++) {
        if (!expiry_next(now_msec, arr[i].expiry_msec, next_msec))
            continue;

        if (i != j) {
            g_free(arr[j].domain);
            arr[j]        = arr[i];
            arr[i].domain = NULL;
        }

        j++;
    }

    if (i != 0) {
        *changed |= NM_NDISC_CONFIG_DNS_DOMAINS;
        g_array_set_size(rdata->dns_domains, j);
    }

    if (_array_set_size_max(rdata->gateways, _SIZE_MAX_DNS_DOMAINS))
        *changed |= NM_NDISC_CONFIG_DNS_DOMAINS;
}

static void
check_timestamps(NMNDisc *ndisc, gint64 now_msec, NMNDiscConfigMap changed)
{
    NMNDiscPrivate *priv      = NM_NDISC_GET_PRIVATE(ndisc);
    gint64          next_msec = G_MAXINT64;

    _LOGT("router-data: check for changed router advertisement data");

    clean_gateways(ndisc, now_msec, &changed, &next_msec);
    clean_addresses(ndisc, now_msec, &changed, &next_msec);
    clean_routes(ndisc, now_msec, &changed, &next_msec);
    clean_dns_servers(ndisc, now_msec, &changed, &next_msec);
    clean_dns_domains(ndisc, now_msec, &changed, &next_msec);

    nm_assert(next_msec > now_msec);

    nm_clear_g_source_inst(&priv->timeout_expire_source);

    if (next_msec == NM_NDISC_EXPIRY_INFINITY)
        _LOGD("router-data: next lifetime expiration will happen: never");
    else {
        const gint64 timeout_msec = NM_MIN(next_msec - now_msec, ((gint64) G_MAXINT32));
        const guint  TIMEOUT_APPROX_THRESHOLD_SEC = 10000;

        _LOGD("router-data: next lifetime expiration will happen: in %s%.3f seconds",
              (timeout_msec / 1000) >= TIMEOUT_APPROX_THRESHOLD_SEC ? " about" : "",
              ((double) timeout_msec) / 1000);

        priv->timeout_expire_source = nm_g_timeout_add_source_approx(timeout_msec,
                                                                     TIMEOUT_APPROX_THRESHOLD_SEC,
                                                                     timeout_expire_cb,
                                                                     ndisc);
    }

    if (changed != NM_NDISC_CONFIG_NONE)
        nm_ndisc_emit_config_change(ndisc, changed);
}

static gboolean
timeout_expire_cb(gpointer user_data)
{
    check_timestamps(user_data, nm_utils_get_monotonic_timestamp_msec(), NM_NDISC_CONFIG_NONE);
    return G_SOURCE_CONTINUE;
}

/* Calculate the earliest time where some part of the advertised data is about
 * to expire.
 *
 * Entities are considered about to expire NM_NDISC_PRE_EXPIRY_TIME_MSEC before
 * their expiration time.
 *
 * However, data which has a lifetime (as calculated from the time the last
 * RS has been sent) shorter than NM_NDISC_PRE_EXPIRY_MIN_LIFETIME_MSEC, is
 * ignored. This is because when we send out RSs because some data is about
 * to expire, and the received RAs neither extend the lifetime nor remove
 * the offending data, the data would be considered about to expire again,
 * triggering more RS in an endless loop until it expired for good.
 */

static void
_calc_pre_expiry_rs_msec_worker(gint64 *earliest_expiry_msec,
                                gint64  last_rs_msec,
                                gint64  expiry_msec)
{
    if (expiry_msec == NM_NDISC_EXPIRY_INFINITY)
        return;

    if (expiry_msec < last_rs_msec + NM_NDISC_PRE_EXPIRY_MIN_LIFETIME_MSEC)
        return;

    *earliest_expiry_msec = NM_MIN(*earliest_expiry_msec, expiry_msec);
}

static gint64
calc_pre_expiry_rs_msec(NMNDisc *ndisc)
{
    NMNDiscPrivate      *priv        = NM_NDISC_GET_PRIVATE(ndisc);
    NMNDiscDataInternal *rdata       = &priv->rdata;
    gint64               expiry_msec = NM_NDISC_EXPIRY_INFINITY;
    guint                i;

    for (i = 0; i < rdata->gateways->len; i++) {
        _calc_pre_expiry_rs_msec_worker(
            &expiry_msec,
            priv->last_rs_msec,
            nm_g_array_index(rdata->gateways, NMNDiscGateway, i).expiry_msec);
    }

    for (i = 0; i < rdata->addresses->len; i++) {
        _calc_pre_expiry_rs_msec_worker(
            &expiry_msec,
            priv->last_rs_msec,
            nm_g_array_index(rdata->addresses, NMNDiscAddress, i).expiry_msec);
    }

    for (i = 0; i < rdata->routes->len; i++) {
        _calc_pre_expiry_rs_msec_worker(
            &expiry_msec,
            priv->last_rs_msec,
            nm_g_array_index(rdata->routes, NMNDiscRoute, i).expiry_msec);
    }

    for (i = 0; i < rdata->dns_servers->len; i++) {
        _calc_pre_expiry_rs_msec_worker(
            &expiry_msec,
            priv->last_rs_msec,
            nm_g_array_index(rdata->dns_servers, NMNDiscDNSServer, i).expiry_msec);
    }

    for (i = 0; i < rdata->dns_domains->len; i++) {
        _calc_pre_expiry_rs_msec_worker(
            &expiry_msec,
            priv->last_rs_msec,
            nm_g_array_index(rdata->dns_domains, NMNDiscDNSDomain, i).expiry_msec);
    }

    return expiry_msec - solicit_retransmit_time_jitter(NM_NDISC_PRE_EXPIRY_TIME_MSEC);
}

void
nm_ndisc_ra_received(NMNDisc *ndisc, gint64 now_msec, NMNDiscConfigMap changed)
{
    NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE(ndisc);
    gint64          pre_expiry_msec;
    gint32          timeout_msec;

    nm_clear_g_source_inst(&priv->ra_timeout_source);
    nm_clear_g_free(&priv->last_error);
    check_timestamps(ndisc, now_msec, changed);

    /* When we receive an RA, we don't disable solicitations.
     *
     * This contradicts https://tools.ietf.org/html/rfc7559#section-2.1, which
     * says that we SHOULD stop sending RS if we receive an RA -- but only on
     * a multicast capable link and if the RA has a valid router lifetime.
     *
     * But there are routers out in the wild that won't send unsolicited RAs.
     * So we begin sending out RS again when entities are about to expire.
     */
    pre_expiry_msec = NM_CLAMP(calc_pre_expiry_rs_msec(ndisc),
                               priv->last_rs_msec + RFC7559_IRT * 1000,
                               priv->last_rs_msec + RFC7559_MRT * 1000);
    timeout_msec    = NM_CLAMP(pre_expiry_msec - now_msec, (gint64) 0, (gint64) G_MAXINT32);

    _LOGD("solicit: schedule sending next (slow) solicitation in about %.3f seconds",
          ((double) timeout_msec) / 1000);

    priv->solicit_retransmit_time_msec = 0;
    nm_clear_g_source_inst(&priv->solicit_timer_source);
    priv->solicit_timer_source =
        nm_g_timeout_add_source_approx(timeout_msec, 0, solicit_timer_cb, ndisc);
}

void
nm_ndisc_rs_received(NMNDisc *ndisc)
{
    NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE(ndisc);

    nm_clear_g_free(&priv->last_error);
    announce_router_solicited(ndisc);
}

/*****************************************************************************/

static int
ipv6_sysctl_get(NMPlatform *platform,
                const char *ifname,
                const char *property,
                int         min,
                int         max,
                int         defval)
{
    return nm_platform_sysctl_ip_conf_get_int_checked(platform,
                                                      AF_INET6,
                                                      ifname,
                                                      property,
                                                      10,
                                                      min,
                                                      max,
                                                      defval);
}

void
nm_ndisc_get_sysctl(NMPlatform *platform,
                    const char *ifname,
                    int        *out_max_addresses,
                    int        *out_router_solicitations,
                    int        *out_router_solicitation_interval,
                    guint32    *out_default_ra_timeout)
{
    int router_solicitation_interval = 0;
    int router_solicitations         = 0;

    if (out_max_addresses) {
        *out_max_addresses = ipv6_sysctl_get(platform,
                                             ifname,
                                             "max_addresses",
                                             0,
                                             G_MAXINT32,
                                             NM_NDISC_MAX_ADDRESSES_DEFAULT);
    }
    if (out_router_solicitations || out_default_ra_timeout) {
        router_solicitations = ipv6_sysctl_get(platform,
                                               ifname,
                                               "router_solicitations",
                                               1,
                                               G_MAXINT32,
                                               NM_NDISC_ROUTER_SOLICITATIONS_DEFAULT);
        NM_SET_OUT(out_router_solicitations, router_solicitations);
    }
    if (out_router_solicitation_interval || out_default_ra_timeout) {
        router_solicitation_interval = ipv6_sysctl_get(platform,
                                                       ifname,
                                                       "router_solicitation_interval",
                                                       1,
                                                       G_MAXINT32,
                                                       NM_NDISC_RFC4861_RTR_SOLICITATION_INTERVAL);
        NM_SET_OUT(out_router_solicitation_interval, router_solicitation_interval);
    }
    if (out_default_ra_timeout) {
        *out_default_ra_timeout =
            NM_MAX((((gint64) router_solicitations) * router_solicitation_interval) + 1, 30);
    }
}

/*****************************************************************************/

static void
_config_clear(NMNDiscConfig *config)
{
    g_clear_object(&config->l3cfg);
    nm_clear_g_free((gpointer *) &config->ifname);
    nm_clear_g_free((gpointer *) &config->network_id);
}

static void
_config_init(NMNDiscConfig *config, const NMNDiscConfig *src)
{
    nm_assert(config);
    g_return_if_fail(src);

    /* we only allow to set @config if it was cleared (or is not yet initialized). */
    nm_assert(!config->l3cfg);
    nm_assert(!config->ifname);
    nm_assert(!config->network_id);

    g_return_if_fail(NM_IS_L3CFG(src->l3cfg));

    *config = *src;

    g_object_ref(config->l3cfg);
    config->ifname     = g_strdup(config->ifname);
    config->network_id = g_strdup(config->network_id);

    if (config->max_addresses <= 0)
        config->max_addresses = _SIZE_MAX_ADDRESSES;
    else if (config->max_addresses > 3u * _SIZE_MAX_ADDRESSES)
        config->max_addresses = 3u * _SIZE_MAX_ADDRESSES;

    /* This setter is only used in specific circumstances, and in this case,
     * we expect that @src only contains valid settings. We thus assert that to
     * be the case.*/
    g_return_if_fail(config->ifname && config->ifname[0]);
    g_return_if_fail(config->network_id);
    g_return_if_fail(config->stable_type >= NM_UTILS_STABLE_TYPE_UUID
                     && config->stable_type <= NM_UTILS_STABLE_TYPE_RANDOM);
    g_return_if_fail(config->addr_gen_mode >= NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64
                     && config->addr_gen_mode
                            <= NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY);
    nm_assert(config->max_addresses >= 0 && config->max_addresses <= G_MAXINT32);
    G_STATIC_ASSERT_EXPR(G_MAXINT32 == NM_RA_TIMEOUT_INFINITY);
    g_return_if_fail(config->ra_timeout <= NM_RA_TIMEOUT_INFINITY);
    g_return_if_fail(config->router_solicitations > 0
                     && config->router_solicitations <= G_MAXINT32);
    g_return_if_fail(config->router_solicitation_interval > 0
                     && config->router_solicitation_interval <= G_MAXINT32);
    g_return_if_fail(
        NM_IN_SET(config->node_type, NM_NDISC_NODE_TYPE_HOST, NM_NDISC_NODE_TYPE_ROUTER));
    g_return_if_fail(NM_IN_SET(config->ip6_privacy,
                               NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED,
                               NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR,
                               NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR));
}

/*****************************************************************************/

static void
dns_domain_free(gpointer data)
{
    g_free(((NMNDiscDNSDomain *) (data))->domain);
}

/*****************************************************************************/

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMNDisc        *self = NM_NDISC(object);
    NMNDiscPrivate *priv = NM_NDISC_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_CONFIG:
        /* construct-only */
        _config_init(&priv->config_, g_value_get_pointer(value));

        priv->netns =
            nm_g_object_ref(nm_platform_netns_get(nm_l3cfg_get_platform(priv->config.l3cfg)));
        g_return_if_fail(!priv->netns || priv->netns == nmp_netns_get_current());
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nm_ndisc_init(NMNDisc *ndisc)
{
    NMNDiscPrivate      *priv;
    NMNDiscDataInternal *rdata;

    priv         = G_TYPE_INSTANCE_GET_PRIVATE(ndisc, NM_TYPE_NDISC, NMNDiscPrivate);
    ndisc->_priv = priv;

    rdata = &priv->rdata;

    rdata->gateways    = g_array_new(FALSE, FALSE, sizeof(NMNDiscGateway));
    rdata->addresses   = g_array_new(FALSE, FALSE, sizeof(NMNDiscAddress));
    rdata->routes      = g_array_new(FALSE, FALSE, sizeof(NMNDiscRoute));
    rdata->dns_servers = g_array_new(FALSE, FALSE, sizeof(NMNDiscDNSServer));
    rdata->dns_domains = g_array_new(FALSE, FALSE, sizeof(NMNDiscDNSDomain));
    g_array_set_clear_func(rdata->dns_domains, dns_domain_free);
    priv->rdata.public.hop_limit = 64;
}

static void
dispose(GObject *object)
{
    NMNDisc        *ndisc = NM_NDISC(object);
    NMNDiscPrivate *priv  = NM_NDISC_GET_PRIVATE(ndisc);

    nm_clear_g_source_inst(&priv->ra_timeout_source);
    nm_clear_g_source_inst(&priv->solicit_timer_source);
    nm_clear_g_source(&priv->send_ra_id);
    nm_clear_g_free(&priv->last_error);

    nm_clear_g_source_inst(&priv->timeout_expire_source);

    G_OBJECT_CLASS(nm_ndisc_parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{
    NMNDisc             *ndisc = NM_NDISC(object);
    NMNDiscPrivate      *priv  = NM_NDISC_GET_PRIVATE(ndisc);
    NMNDiscDataInternal *rdata = &priv->rdata;

    g_array_unref(rdata->gateways);
    g_array_unref(rdata->addresses);
    g_array_unref(rdata->routes);
    g_array_unref(rdata->dns_servers);
    g_array_unref(rdata->dns_domains);

    g_clear_object(&priv->netns);

    _config_clear(&priv->config_);

    nm_clear_l3cd(&priv->l3cd);

    G_OBJECT_CLASS(nm_ndisc_parent_class)->finalize(object);
}

static void
nm_ndisc_class_init(NMNDiscClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    g_type_class_add_private(klass, sizeof(NMNDiscPrivate));

    object_class->set_property = set_property;
    object_class->dispose      = dispose;
    object_class->finalize     = finalize;

    obj_properties[PROP_CONFIG] =
        g_param_spec_pointer(NM_NDISC_CONFIG,
                             "",
                             "",
                             G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    signals[CONFIG_RECEIVED]   = g_signal_new(NM_NDISC_CONFIG_RECEIVED,
                                            G_OBJECT_CLASS_TYPE(klass),
                                            G_SIGNAL_RUN_FIRST,
                                            0,
                                            NULL,
                                            NULL,
                                            NULL,
                                            G_TYPE_NONE,
                                            3,
                                            G_TYPE_POINTER
                                            /* (const NMNDiscData *)rdata */,
                                            G_TYPE_UINT
                                            /* (guint) changed_i */,
                                            G_TYPE_POINTER
                                            /* (const NML3ConfigData *) l3cd */
    );
    signals[RA_TIMEOUT_SIGNAL] = g_signal_new(NM_NDISC_RA_TIMEOUT_SIGNAL,
                                              G_OBJECT_CLASS_TYPE(klass),
                                              G_SIGNAL_RUN_FIRST,
                                              0,
                                              NULL,
                                              NULL,
                                              NULL,
                                              G_TYPE_NONE,
                                              0);
}
