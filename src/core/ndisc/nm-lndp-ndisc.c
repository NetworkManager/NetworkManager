/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-lndp-ndisc.h"

#include <arpa/inet.h>
#include <netinet/icmp6.h>
/* stdarg.h included because of a bug in ndp.h */
#include <stdarg.h>
#include <ndp.h>

#include "nm-glib-aux/nm-str-buf.h"
#include "systemd/nm-sd-utils-shared.h"
#include "nm-ndisc-private.h"
#include "NetworkManagerUtils.h"
#include "platform/nm-platform.h"
#include "nm-platform/nmp-netns.h"

#define _NMLOG_PREFIX_NAME "ndisc-lndp"

/*****************************************************************************/

typedef struct {
    struct ndp *ndp;
    GSource *   event_source;
} NMLndpNDiscPrivate;

/*****************************************************************************/

struct _NMLndpNDisc {
    NMNDisc            parent;
    NMLndpNDiscPrivate _priv;
};

struct _NMLndpNDiscClass {
    NMNDiscClass parent;
};

/*****************************************************************************/

G_DEFINE_TYPE(NMLndpNDisc, nm_lndp_ndisc, NM_TYPE_NDISC)

#define NM_LNDP_NDISC_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMLndpNDisc, NM_IS_LNDP_NDISC, NMNDisc)

/*****************************************************************************/

static gboolean
send_rs(NMNDisc *ndisc, GError **error)
{
    NMLndpNDiscPrivate *priv = NM_LNDP_NDISC_GET_PRIVATE(ndisc);
    struct ndp_msg *    msg;
    int                 errsv;

    errsv = ndp_msg_new(&msg, NDP_MSG_RS);
    if (errsv) {
        g_set_error_literal(error,
                            NM_UTILS_ERROR,
                            NM_UTILS_ERROR_UNKNOWN,
                            "cannot create router solicitation");
        return FALSE;
    }
    ndp_msg_ifindex_set(msg, nm_ndisc_get_ifindex(ndisc));

    errsv = ndp_msg_send(priv->ndp, msg);
    ndp_msg_destroy(msg);
    if (errsv) {
        errsv = nm_errno_native(errsv);
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    "%s (%d)",
                    nm_strerror_native(errsv),
                    errsv);
        return FALSE;
    }

    return TRUE;
}

static NMIcmpv6RouterPref
_route_preference_coerce(enum ndp_route_preference pref)
{
#define _ASSERT_ENUM(v1, v2)                                      \
    G_STMT_START                                                  \
    {                                                             \
        G_STATIC_ASSERT((NMIcmpv6RouterPref)(v1) == (v2));        \
        G_STATIC_ASSERT((enum ndp_route_preference)(v2) == (v1)); \
        G_STATIC_ASSERT((gint64)(v1) == (v2));                    \
        G_STATIC_ASSERT((gint64)(v2) == (v1));                    \
    }                                                             \
    G_STMT_END

    switch (pref) {
    case NDP_ROUTE_PREF_LOW:
    case NDP_ROUTE_PREF_MEDIUM:
    case NDP_ROUTE_PREF_HIGH:
        _ASSERT_ENUM(NDP_ROUTE_PREF_LOW, NM_ICMPV6_ROUTER_PREF_LOW);
        _ASSERT_ENUM(NDP_ROUTE_PREF_MEDIUM, NM_ICMPV6_ROUTER_PREF_MEDIUM);
        _ASSERT_ENUM(NDP_ROUTE_PREF_HIGH, NM_ICMPV6_ROUTER_PREF_HIGH);
        return (NMIcmpv6RouterPref) pref;
    }

    /* unexpected value must be treated as MEDIUM (RFC 4191). */
    return NM_ICMPV6_ROUTER_PREF_MEDIUM;
}

static int
receive_ra(struct ndp *ndp, struct ndp_msg *msg, gpointer user_data)
{
    NMNDisc *            ndisc   = (NMNDisc *) user_data;
    NMNDiscDataInternal *rdata   = ndisc->rdata;
    NMNDiscConfigMap     changed = 0;
    struct ndp_msgra *   msgra   = ndp_msgra(msg);
    struct in6_addr      gateway_addr;
    const gint64         now_msec = nm_utils_get_monotonic_timestamp_msec();
    int                  offset;
    int                  hop_limit;
    guint32              val;

    /* Router discovery is subject to the following RFC documents:
     *
     * http://tools.ietf.org/html/rfc4861
     * http://tools.ietf.org/html/rfc4862
     *
     * The biggest difference from good old DHCP is that all configuration
     * items have their own lifetimes and they are merged from various
     * sources. Router discovery is *not* contract-based, so there is *no*
     * single time when the configuration is finished and updates can
     * come at any time.
     */
    _LOGD("received router advertisement at timestamp %" G_GINT64_FORMAT ".%03d seconds",
          now_msec / 1000,
          (int) (now_msec % 1000));

    gateway_addr = *ndp_msg_addrto(msg);
    if (IN6_IS_ADDR_UNSPECIFIED(&gateway_addr))
        g_return_val_if_reached(0);

    /* DHCP level:
     *
     * The problem with DHCP level is what to do if subsequent
     * router advertisements carry different flags. Currently, we just
     * rewrite the flag with every inbound RA.
     */
    {
        NMNDiscDHCPLevel dhcp_level;

        if (ndp_msgra_flag_managed(msgra))
            dhcp_level = NM_NDISC_DHCP_LEVEL_MANAGED;
        else if (ndp_msgra_flag_other(msgra))
            dhcp_level = NM_NDISC_DHCP_LEVEL_OTHERCONF;
        else
            dhcp_level = NM_NDISC_DHCP_LEVEL_NONE;

        /* when receiving multiple RA (possibly from different routers),
         * let's keep the "most managed" level. */
        G_STATIC_ASSERT_EXPR(NM_NDISC_DHCP_LEVEL_MANAGED > NM_NDISC_DHCP_LEVEL_OTHERCONF);
        G_STATIC_ASSERT_EXPR(NM_NDISC_DHCP_LEVEL_OTHERCONF > NM_NDISC_DHCP_LEVEL_NONE);
        dhcp_level = MAX(dhcp_level, rdata->public.dhcp_level);

        if (dhcp_level != rdata->public.dhcp_level) {
            rdata->public.dhcp_level = dhcp_level;
            changed |= NM_NDISC_CONFIG_DHCP_LEVEL;
        }
    }

    /* Default gateway:
     *
     * Subsequent router advertisements can represent new default gateways
     * on the network. We should present all of them in router preference
     * order.
     */
    {
        const NMNDiscGateway gateway = {
            .address     = gateway_addr,
            .expiry_msec = _nm_ndisc_lifetime_to_expiry(now_msec, ndp_msgra_router_lifetime(msgra)),
            .preference  = _route_preference_coerce(ndp_msgra_route_preference(msgra)),
        };

        /* https://tools.ietf.org/html/rfc2461#section-4.2
         *   > A Lifetime of 0 indicates that the router is not a
         *   > default router and SHOULD NOT appear on the default
         *   > router list.
         * We handle that by tracking a gateway that expires right now. */

        if (nm_ndisc_add_gateway(ndisc, &gateway, now_msec))
            changed |= NM_NDISC_CONFIG_GATEWAYS;
    }

    /* Addresses & Routes */
    ndp_msg_opt_for_each_offset (offset, msg, NDP_MSG_OPT_PREFIX) {
        guint8          r_plen;
        struct in6_addr r_network;

        /* Device route */

        r_plen = ndp_msg_opt_prefix_len(msg, offset);
        if (r_plen == 0 || r_plen > 128)
            continue;
        nm_utils_ip6_address_clear_host_address(&r_network,
                                                ndp_msg_opt_prefix(msg, offset),
                                                r_plen);

        if (IN6_IS_ADDR_UNSPECIFIED(&r_network) || IN6_IS_ADDR_LINKLOCAL(&r_network))
            continue;

        if (ndp_msg_opt_prefix_flag_on_link(msg, offset)) {
            const NMNDiscRoute route = {
                .network = r_network,
                .plen    = r_plen,
                .expiry_msec =
                    _nm_ndisc_lifetime_to_expiry(now_msec,
                                                 ndp_msg_opt_prefix_valid_time(msg, offset)),
            };

            if (nm_ndisc_add_route(ndisc, &route, now_msec))
                changed |= NM_NDISC_CONFIG_ROUTES;
        }

        /* Address */
        if (r_plen == 64 && ndp_msg_opt_prefix_flag_auto_addr_conf(msg, offset)) {
            const guint32 valid_time = ndp_msg_opt_prefix_valid_time(msg, offset);
            const guint32 preferred_time =
                NM_MIN(ndp_msg_opt_prefix_preferred_time(msg, offset), valid_time);
            const NMNDiscAddress address = {
                .address               = r_network,
                .expiry_msec           = _nm_ndisc_lifetime_to_expiry(now_msec, valid_time),
                .expiry_preferred_msec = _nm_ndisc_lifetime_to_expiry(now_msec, preferred_time),
            };

            if (nm_ndisc_complete_and_add_address(ndisc, &address, now_msec))
                changed |= NM_NDISC_CONFIG_ADDRESSES;
        }
    }
    ndp_msg_opt_for_each_offset (offset, msg, NDP_MSG_OPT_ROUTE) {
        guint8          plen = ndp_msg_opt_route_prefix_len(msg, offset);
        struct in6_addr network;

        if (plen == 0 || plen > 128)
            continue;

        nm_utils_ip6_address_clear_host_address(&network,
                                                ndp_msg_opt_route_prefix(msg, offset),
                                                plen);

        {
            const NMNDiscRoute route = {
                .network = network,
                .gateway = gateway_addr,
                .plen    = plen,
                .expiry_msec =
                    _nm_ndisc_lifetime_to_expiry(now_msec, ndp_msg_opt_route_lifetime(msg, offset)),
                .preference = _route_preference_coerce(ndp_msg_opt_route_preference(msg, offset)),
            };

            /* Routers through this particular gateway */
            if (nm_ndisc_add_route(ndisc, &route, now_msec))
                changed |= NM_NDISC_CONFIG_ROUTES;
        }
    }

    ndp_msg_opt_for_each_offset (offset, msg, NDP_MSG_OPT_RDNSS) {
        struct in6_addr *addr;
        int              addr_index;

        ndp_msg_opt_rdnss_for_each_addr (addr, addr_index, msg, offset) {
            const NMNDiscDNSServer dns_server = {
                .address = *addr,
                .expiry_msec =
                    _nm_ndisc_lifetime_to_expiry(now_msec, ndp_msg_opt_rdnss_lifetime(msg, offset)),
            };

            if (nm_ndisc_add_dns_server(ndisc, &dns_server, now_msec))
                changed |= NM_NDISC_CONFIG_DNS_SERVERS;
        }
    }
    ndp_msg_opt_for_each_offset (offset, msg, NDP_MSG_OPT_DNSSL) {
        char *domain;
        int   domain_index;

        ndp_msg_opt_dnssl_for_each_domain (domain, domain_index, msg, offset) {
            const NMNDiscDNSDomain dns_domain = {
                .domain = domain,
                .expiry_msec =
                    _nm_ndisc_lifetime_to_expiry(now_msec, ndp_msg_opt_dnssl_lifetime(msg, offset)),
            };

            if (nm_ndisc_add_dns_domain(ndisc, &dns_domain, now_msec))
                changed |= NM_NDISC_CONFIG_DNS_DOMAINS;
        }
    }

    hop_limit = ndp_msgra_curhoplimit(msgra);
    if (rdata->public.hop_limit != hop_limit) {
        rdata->public.hop_limit = hop_limit;
        changed |= NM_NDISC_CONFIG_HOP_LIMIT;
    }

    val = ndp_msgra_reachable_time(msgra);
    if (val && rdata->public.reachable_time_ms != val) {
        rdata->public.reachable_time_ms = val;
        changed |= NM_NDISC_CONFIG_REACHABLE_TIME;
    }

    val = ndp_msgra_retransmit_time(msgra);
    if (val && rdata->public.retrans_timer_ms != val) {
        rdata->public.retrans_timer_ms = val;
        changed |= NM_NDISC_CONFIG_RETRANS_TIMER;
    }

    /* MTU */
    ndp_msg_opt_for_each_offset (offset, msg, NDP_MSG_OPT_MTU) {
        guint32 mtu = ndp_msg_opt_mtu(msg, offset);
        if (mtu >= 1280) {
            if (rdata->public.mtu != mtu) {
                rdata->public.mtu = mtu;
                changed |= NM_NDISC_CONFIG_MTU;
            }
        } else {
            /* All sorts of bad things would happen if we accepted this.
             * Kernel would set it, but would flush out all IPv6 addresses away
             * from the link, even the link-local, and we wouldn't be able to
             * listen for further RAs that could fix the MTU. */
            _LOGW("MTU too small for IPv6 ignored: %d", mtu);
        }
    }

    nm_ndisc_ra_received(ndisc, now_msec, changed);
    return 0;
}

static void *
_ndp_msg_add_option(struct ndp_msg *msg, gsize len)
{
    gsize payload_len = ndp_msg_payload_len(msg);
    void *ret         = &((uint8_t *) msg)[payload_len];

    nm_assert(len <= G_MAXSIZE - payload_len);
    len += payload_len;

    if (len > ndp_msg_payload_maxlen(msg))
        return NULL;

    ndp_msg_payload_len_set(msg, len);
    nm_assert(len == ndp_msg_payload_len(msg));
    return ret;
}

/*****************************************************************************/

/* "Recursive DNS Server Option" at https://tools.ietf.org/html/rfc8106#section-5.1 */

#define NM_ND_OPT_RDNSS 25

typedef struct _nm_packed {
    struct nd_opt_hdr header;
    uint16_t          reserved;
    uint32_t          lifetime;
    struct in6_addr   addrs[0];
} NMLndpRdnssOption;

G_STATIC_ASSERT(sizeof(NMLndpRdnssOption) == 8u);

/*****************************************************************************/

/* "DNS Search List Option" at https://tools.ietf.org/html/rfc8106#section-5.2 */

#define NM_ND_OPT_DNSSL 31

typedef struct _nm_packed {
    struct nd_opt_hdr header;
    uint16_t          reserved;
    uint32_t          lifetime;
    uint8_t           search_list[0];
} NMLndpDnsslOption;

G_STATIC_ASSERT(sizeof(NMLndpDnsslOption) == 8u);

/*****************************************************************************/

static gboolean
send_ra(NMNDisc *ndisc, GError **error)
{
    NMLndpNDiscPrivate *     priv  = NM_LNDP_NDISC_GET_PRIVATE(ndisc);
    NMNDiscDataInternal *    rdata = ndisc->rdata;
    int                      errsv;
    struct in6_addr *        addr;
    struct ndp_msg *         msg;
    guint                    i;
    nm_auto_str_buf NMStrBuf sbuf = NM_STR_BUF_INIT(0, FALSE);

    errsv = ndp_msg_new(&msg, NDP_MSG_RA);
    if (errsv) {
        g_set_error_literal(error,
                            NM_UTILS_ERROR,
                            NM_UTILS_ERROR_UNKNOWN,
                            "cannot create a router advertisement");
        return FALSE;
    }

    ndp_msg_ifindex_set(msg, nm_ndisc_get_ifindex(ndisc));

    /* Multicast to all nodes. */
    addr               = ndp_msg_addrto(msg);
    addr->s6_addr32[0] = htonl(0xff020000);
    addr->s6_addr32[1] = 0;
    addr->s6_addr32[2] = 0;
    addr->s6_addr32[3] = htonl(0x1);

    ndp_msgra_router_lifetime_set(ndp_msgra(msg), NM_NDISC_ROUTER_LIFETIME);

    /* The device let us know about all addresses that the device got
     * whose prefixes are suitable for delegating. Let's announce them. */
    for (i = 0; i < rdata->addresses->len; i++) {
        const NMNDiscAddress *     address = &g_array_index(rdata->addresses, NMNDiscAddress, i);
        struct nd_opt_prefix_info *prefix;

        prefix = _ndp_msg_add_option(msg, sizeof(*prefix));
        if (!prefix) {
            /* Maybe we could sent separate RAs, but why bother... */
            _LOGW("The RA is too big, had to omit some some prefixes.");
            break;
        }

        prefix->nd_opt_pi_type       = ND_OPT_PREFIX_INFORMATION;
        prefix->nd_opt_pi_len        = 4;
        prefix->nd_opt_pi_prefix_len = 64;
        prefix->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_ONLINK;
        prefix->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
        prefix->nd_opt_pi_valid_time =
            htonl(_nm_ndisc_lifetime_from_expiry(NM_NDISC_EXPIRY_BASE_TIMESTAMP,
                                                 address->expiry_msec,
                                                 TRUE));
        prefix->nd_opt_pi_preferred_time =
            htonl(_nm_ndisc_lifetime_from_expiry(NM_NDISC_EXPIRY_BASE_TIMESTAMP,
                                                 address->expiry_preferred_msec,
                                                 TRUE));
        prefix->nd_opt_pi_prefix.s6_addr32[0] = address->address.s6_addr32[0];
        prefix->nd_opt_pi_prefix.s6_addr32[1] = address->address.s6_addr32[1];
        prefix->nd_opt_pi_prefix.s6_addr32[2] = 0;
        prefix->nd_opt_pi_prefix.s6_addr32[3] = 0;
    }

    if (rdata->dns_servers->len > 0u) {
        NMLndpRdnssOption *option;
        gsize len = sizeof(*option) + (sizeof(option->addrs[0]) * rdata->dns_servers->len);

        option = _ndp_msg_add_option(msg, len);
        if (!option) {
            _LOGW("The RA is too big, had to omit DNS information.");
            goto dns_servers_done;
        }

        option->header.nd_opt_type = NM_ND_OPT_RDNSS;
        option->header.nd_opt_len  = len / 8;
        option->lifetime           = htonl(900);

        for (i = 0; i < rdata->dns_servers->len; i++) {
            const NMNDiscDNSServer *dns_server =
                &g_array_index(rdata->dns_servers, NMNDiscDNSServer, i);

            option->addrs[i] = dns_server->address;
        }
    }
dns_servers_done:

    if (rdata->dns_domains->len > 0u) {
        NMLndpDnsslOption *option;
        gsize              padding;
        gsize              len;

        nm_str_buf_reset(&sbuf);

        for (i = 0; i < rdata->dns_domains->len; i++) {
            const NMNDiscDNSDomain *dns_domain =
                &g_array_index(rdata->dns_domains, NMNDiscDNSDomain, i);
            const char *domain = dns_domain->domain;
            gsize       domain_l;
            gsize       n_reserved;
            int         r;

            if (nm_str_is_empty(domain)) {
                nm_assert_not_reached();
                continue;
            }

            domain_l = strlen(domain);

            nm_str_buf_maybe_expand(&sbuf, domain_l + 2u, FALSE);
            n_reserved = sbuf.allocated - sbuf.len;

            r = nm_sd_dns_name_to_wire_format(
                domain,
                (guint8 *) (&nm_str_buf_get_str_unsafe(&sbuf)[sbuf.len]),
                n_reserved,
                FALSE);

            if (r < 0 || ((gsize) r) > n_reserved) {
                nm_assert(r != -ENOBUFS);
                nm_assert(r < 0);
                /* we don't expect errors here, unless the domain name is invalid.
                 * That should have been caught (and rejected) by upper layers, but
                 * at this point it seems dangerous to assert (as it's hard to review
                 * that all callers got it correct). So instead silently ignore the error. */
                continue;
            }

            nm_str_buf_set_size(&sbuf, sbuf.len + ((gsize) r), TRUE, FALSE);
        }

        if (sbuf.len == 0) {
            /* no valid domains? */
            goto dns_domains_done;
        }

        len     = sizeof(*option) + sbuf.len;
        padding = len % 8u;
        if (padding != 0u) {
            padding = 8u - padding;
            len += padding;
        }

        nm_assert(len % 8u == 0u);
        nm_assert(len > 0u);
        nm_assert(len / 8u >= 2u);

        if (len / 8u >= 256u || !(option = _ndp_msg_add_option(msg, len))) {
            _LOGW("The RA is too big, had to omit DNS search list.");
            goto dns_domains_done;
        }

        nm_str_buf_append_c_len(&sbuf, '\0', padding);

        option->header.nd_opt_type = NM_ND_OPT_DNSSL;
        option->header.nd_opt_len  = len / 8u;
        option->reserved           = 0;
        option->lifetime           = htonl(900);
        memcpy(option->search_list, nm_str_buf_get_str_unsafe(&sbuf), sbuf.len);
    }
dns_domains_done:

    errsv = ndp_msg_send(priv->ndp, msg);

    ndp_msg_destroy(msg);
    if (errsv) {
        errsv = nm_errno_native(errsv);
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    "%s (%d)",
                    nm_strerror_native(errsv),
                    errsv);
        return FALSE;
    }

    return TRUE;
}

static int
receive_rs(struct ndp *ndp, struct ndp_msg *msg, gpointer user_data)
{
    NMNDisc *ndisc = user_data;

    nm_ndisc_rs_received(ndisc);
    return 0;
}

static gboolean
event_ready(int fd, GIOCondition condition, gpointer user_data)
{
    gs_unref_object NMNDisc *ndisc    = g_object_ref(NM_NDISC(user_data));
    nm_auto_pop_netns NMPNetns *netns = NULL;
    NMLndpNDiscPrivate *        priv  = NM_LNDP_NDISC_GET_PRIVATE(ndisc);

    _LOGD("processing libndp events");

    if (!nm_ndisc_netns_push(ndisc, &netns)) {
        /* something is very wrong. Stop handling events. */
        nm_clear_g_source_inst(&priv->event_source);
        return G_SOURCE_REMOVE;
    }

    ndp_callall_eventfd_handler(priv->ndp);
    return G_SOURCE_CONTINUE;
}

static void
start(NMNDisc *ndisc)
{
    NMLndpNDiscPrivate *priv = NM_LNDP_NDISC_GET_PRIVATE(ndisc);
    int                 fd;

    g_return_if_fail(!priv->event_source);

    fd = ndp_get_eventfd(priv->ndp);

    priv->event_source =
        nm_g_unix_fd_source_new(fd, G_IO_IN, G_PRIORITY_DEFAULT, event_ready, ndisc, NULL);
    g_source_attach(priv->event_source, NULL);

    /* Flush any pending messages to avoid using obsolete information */
    event_ready(fd, 0, ndisc);

    switch (nm_ndisc_get_node_type(ndisc)) {
    case NM_NDISC_NODE_TYPE_HOST:
        ndp_msgrcv_handler_register(priv->ndp,
                                    receive_ra,
                                    NDP_MSG_RA,
                                    nm_ndisc_get_ifindex(ndisc),
                                    ndisc);
        break;
    case NM_NDISC_NODE_TYPE_ROUTER:
        ndp_msgrcv_handler_register(priv->ndp,
                                    receive_rs,
                                    NDP_MSG_RS,
                                    nm_ndisc_get_ifindex(ndisc),
                                    ndisc);
        break;
    default:
        g_assert_not_reached();
    }
}

static void
_cleanup(NMNDisc *ndisc)
{
    NMLndpNDiscPrivate *priv = NM_LNDP_NDISC_GET_PRIVATE(ndisc);

    nm_clear_g_source_inst(&priv->event_source);

    if (priv->ndp) {
        switch (nm_ndisc_get_node_type(ndisc)) {
        case NM_NDISC_NODE_TYPE_HOST:
            ndp_msgrcv_handler_unregister(priv->ndp,
                                          receive_ra,
                                          NDP_MSG_RA,
                                          nm_ndisc_get_ifindex(ndisc),
                                          ndisc);
            break;
        case NM_NDISC_NODE_TYPE_ROUTER:
            ndp_msgrcv_handler_unregister(priv->ndp,
                                          receive_rs,
                                          NDP_MSG_RS,
                                          nm_ndisc_get_ifindex(ndisc),
                                          ndisc);
            break;
        default:
            nm_assert_not_reached();
            break;
        }
        ndp_close(priv->ndp);
        priv->ndp = NULL;
    }
}

static void
stop(NMNDisc *ndisc)
{
    _cleanup(ndisc);
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
nm_lndp_ndisc_get_sysctl(NMPlatform *platform,
                         const char *ifname,
                         int *       out_max_addresses,
                         int *       out_router_solicitations,
                         int *       out_router_solicitation_interval,
                         guint32 *   out_default_ra_timeout)
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
nm_lndp_ndisc_init(NMLndpNDisc *lndp_ndisc)
{}

NMNDisc *
nm_lndp_ndisc_new(NMPlatform *                  platform,
                  int                           ifindex,
                  const char *                  ifname,
                  NMUtilsStableType             stable_type,
                  const char *                  network_id,
                  NMSettingIP6ConfigAddrGenMode addr_gen_mode,
                  NMNDiscNodeType               node_type,
                  int                           max_addresses,
                  int                           router_solicitations,
                  int                           router_solicitation_interval,
                  guint32                       ra_timeout,
                  GError **                     error)
{
    nm_auto_pop_netns NMPNetns *netns = NULL;
    NMNDisc *                   ndisc;
    NMLndpNDiscPrivate *        priv;
    int                         errsv;

    g_return_val_if_fail(NM_IS_PLATFORM(platform), NULL);
    g_return_val_if_fail(!error || !*error, NULL);
    g_return_val_if_fail(network_id, NULL);

    if (!nm_platform_netns_push(platform, &netns))
        return NULL;

    ndisc = g_object_new(NM_TYPE_LNDP_NDISC,
                         NM_NDISC_PLATFORM,
                         platform,
                         NM_NDISC_STABLE_TYPE,
                         (int) stable_type,
                         NM_NDISC_IFINDEX,
                         ifindex,
                         NM_NDISC_IFNAME,
                         ifname,
                         NM_NDISC_NETWORK_ID,
                         network_id,
                         NM_NDISC_ADDR_GEN_MODE,
                         (int) addr_gen_mode,
                         NM_NDISC_NODE_TYPE,
                         (int) node_type,
                         NM_NDISC_MAX_ADDRESSES,
                         max_addresses,
                         NM_NDISC_ROUTER_SOLICITATIONS,
                         router_solicitations,
                         NM_NDISC_ROUTER_SOLICITATION_INTERVAL,
                         router_solicitation_interval,
                         NM_NDISC_RA_TIMEOUT,
                         (guint) ra_timeout,
                         NULL);

    priv = NM_LNDP_NDISC_GET_PRIVATE(ndisc);

    errsv = ndp_open(&priv->ndp);

    if (errsv != 0) {
        errsv = nm_errno_native(errsv);
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    "failure creating libndp socket: %s (%d)",
                    nm_strerror_native(errsv),
                    errsv);
        g_object_unref(ndisc);
        return NULL;
    }
    return ndisc;
}

static void
dispose(GObject *object)
{
    NMNDisc *ndisc = NM_NDISC(object);

    _cleanup(ndisc);

    G_OBJECT_CLASS(nm_lndp_ndisc_parent_class)->dispose(object);
}

static void
nm_lndp_ndisc_class_init(NMLndpNDiscClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);
    NMNDiscClass *ndisc_class  = NM_NDISC_CLASS(klass);

    object_class->dispose = dispose;
    ndisc_class->start    = start;
    ndisc_class->stop     = stop;
    ndisc_class->send_rs  = send_rs;
    ndisc_class->send_ra  = send_ra;
}
