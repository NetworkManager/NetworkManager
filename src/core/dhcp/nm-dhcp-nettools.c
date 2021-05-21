/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2014 - 2019 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <net/if_arp.h>

#include "nm-glib-aux/nm-dedup-multi.h"
#include "nm-std-aux/unaligned.h"
#include "nm-glib-aux/nm-str-buf.h"

#include "nm-utils.h"
#include "nm-config.h"
#include "nm-dhcp-utils.h"
#include "nm-dhcp-options.h"
#include "nm-core-utils.h"
#include "NetworkManagerUtils.h"
#include "platform/nm-platform.h"
#include "nm-dhcp-client-logging.h"
#include "n-dhcp4/src/n-dhcp4.h"
#include "systemd/nm-sd-utils-shared.h"
#include "systemd/nm-sd-utils-dhcp.h"

/*****************************************************************************/

#define NM_TYPE_DHCP_NETTOOLS (nm_dhcp_nettools_get_type())
#define NM_DHCP_NETTOOLS(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DHCP_NETTOOLS, NMDhcpNettools))
#define NM_DHCP_NETTOOLS_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DHCP_NETTOOLS, NMDhcpNettoolsClass))
#define NM_IS_DHCP_NETTOOLS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DHCP_NETTOOLS))
#define NM_IS_DHCP_NETTOOLS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DHCP_NETTOOLS))
#define NM_DHCP_NETTOOLS_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DHCP_NETTOOLS, NMDhcpNettoolsClass))

typedef struct _NMDhcpNettools      NMDhcpNettools;
typedef struct _NMDhcpNettoolsClass NMDhcpNettoolsClass;

/*****************************************************************************/

typedef struct {
    NDhcp4Client *     client;
    NDhcp4ClientProbe *probe;
    NDhcp4ClientLease *lease;
    GSource *          event_source;
    char *             lease_file;
} NMDhcpNettoolsPrivate;

struct _NMDhcpNettools {
    NMDhcpClient          parent;
    NMDhcpNettoolsPrivate _priv;
};

struct _NMDhcpNettoolsClass {
    NMDhcpClientClass parent;
};

G_DEFINE_TYPE(NMDhcpNettools, nm_dhcp_nettools, NM_TYPE_DHCP_CLIENT)

#define NM_DHCP_NETTOOLS_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDhcpNettools, NM_IS_DHCP_NETTOOLS)

/*****************************************************************************/

static void
set_error_nettools(GError **error, int r, const char *message)
{
    /* the error code returned from n_dhcp4_* API is either a negative
     * errno, or a positive internal error code. Generate different messages
     * for these. */
    if (r < 0)
        nm_utils_error_set_errno(error, r, "%s: %s", message);
    else
        nm_utils_error_set(error, r, "%s (code %d)", message, r);
}

static inline int
_client_lease_query(NDhcp4ClientLease *lease,
                    uint8_t            option,
                    const uint8_t **   datap,
                    size_t *           n_datap)
{
    return n_dhcp4_client_lease_query(lease, option, (guint8 **) datap, n_datap);
}

/*****************************************************************************/

#define DHCP_MAX_FQDN_LENGTH 255

/*****************************************************************************/

static gboolean
lease_option_consume_route(const uint8_t **datap,
                           size_t *        n_datap,
                           gboolean        classless,
                           in_addr_t *     destp,
                           uint8_t *       plenp,
                           in_addr_t *     gatewayp)
{
    in_addr_t      dest;
    in_addr_t      gateway;
    const uint8_t *data   = *datap;
    size_t         n_data = *n_datap;
    uint8_t        plen;

    if (classless) {
        uint8_t bytes;

        if (!nm_dhcp_lease_data_consume(&data, &n_data, &plen, sizeof(plen)))
            return FALSE;

        if (plen > 32)
            return FALSE;

        bytes = plen == 0 ? 0 : ((plen - 1) / 8) + 1;

        dest = 0;
        if (!nm_dhcp_lease_data_consume(&data, &n_data, &dest, bytes))
            return FALSE;
    } else {
        if (!nm_dhcp_lease_data_consume_in_addr(&data, &n_data, &dest))
            return FALSE;

        plen = _nm_utils_ip4_get_default_prefix0(dest);
        if (plen == 0)
            return FALSE;
    }

    dest = nm_utils_ip4_address_clear_host_address(dest, plen);

    if (!nm_dhcp_lease_data_consume_in_addr(&data, &n_data, &gateway))
        return FALSE;

    *destp    = dest;
    *plenp    = plen;
    *gatewayp = gateway;
    *datap    = data;
    *n_datap  = n_data;
    return TRUE;
}

/*****************************************************************************/

static gboolean
lease_parse_address(NDhcp4ClientLease *lease,
                    NMIP4Config *      ip4_config,
                    GHashTable *       options,
                    GError **          error)
{
    struct in_addr a_address;
    in_addr_t      a_netmask;
    struct in_addr a_next_server;
    guint32        a_plen;
    guint64        nettools_lifetime;
    guint32        a_lifetime;
    guint32        a_timestamp;
    guint64        a_expiry;
    const guint8 * l_data;
    gsize          l_data_len;
    int            r;

    n_dhcp4_client_lease_get_yiaddr(lease, &a_address);
    if (a_address.s_addr == INADDR_ANY) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_UNKNOWN,
                                   "could not get address from lease");
        return FALSE;
    }

    n_dhcp4_client_lease_get_lifetime(lease, &nettools_lifetime);

    if (nettools_lifetime == G_MAXUINT64) {
        a_timestamp = 0;
        a_lifetime  = NM_PLATFORM_LIFETIME_PERMANENT;
        a_expiry    = G_MAXUINT64;
    } else {
        guint64 nettools_basetime;
        guint64 lifetime;
        gint64  ts;

        n_dhcp4_client_lease_get_basetime(lease, &nettools_basetime);

        /* usually we shouldn't assert against external libraries like n-dhcp4.
         * Here we still do it... it seems safe enough. */
        nm_assert(nettools_basetime > 0);
        nm_assert(nettools_lifetime >= nettools_basetime);
        nm_assert(((nettools_lifetime - nettools_basetime) % NM_UTILS_NSEC_PER_SEC) == 0);
        nm_assert((nettools_lifetime - nettools_basetime) / NM_UTILS_NSEC_PER_SEC <= G_MAXUINT32);

        if (nettools_lifetime <= nettools_basetime) {
            /* A lease time of 0 is allowed on some dhcp servers, so, let's accept it. */
            lifetime = 0;
        } else {
            lifetime = nettools_lifetime - nettools_basetime;

            /* we "ceil" the value to the next second. In practice, we don't expect any sub-second values
             * from n-dhcp4 anyway, so this should have no effect. */
            lifetime += NM_UTILS_NSEC_PER_SEC - 1;
        }

        ts = nm_utils_monotonic_timestamp_from_boottime(nettools_basetime, 1);

        /* the timestamp must be positive, because we only started nettools DHCP client
         * after obtaining the first monotonic timestamp. Hence, the lease must have been
         * received afterwards. */
        nm_assert(ts >= NM_UTILS_NSEC_PER_SEC);

        a_timestamp = ts / NM_UTILS_NSEC_PER_SEC;
        a_lifetime  = NM_MIN(lifetime / NM_UTILS_NSEC_PER_SEC, NM_PLATFORM_LIFETIME_PERMANENT - 1);
        a_expiry    = time(NULL)
                   + ((lifetime - (nm_utils_clock_gettime_nsec(CLOCK_BOOTTIME) - nettools_basetime))
                      / NM_UTILS_NSEC_PER_SEC);
    }

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_SUBNET_MASK, &l_data, &l_data_len);
    if (r != 0 || !nm_dhcp_lease_data_parse_in_addr(l_data, l_data_len, &a_netmask)) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_UNKNOWN,
                                   "could not get netmask from lease");
        return FALSE;
    }

    a_plen = nm_utils_ip4_netmask_to_prefix(a_netmask);

    nm_dhcp_option_add_option_in_addr(options,
                                      AF_INET,
                                      NM_DHCP_OPTION_DHCP4_NM_IP_ADDRESS,
                                      a_address.s_addr);
    nm_dhcp_option_add_option_in_addr(options,
                                      AF_INET,
                                      NM_DHCP_OPTION_DHCP4_SUBNET_MASK,
                                      a_netmask);

    nm_dhcp_option_add_option_u64(options,
                                  AF_INET,
                                  NM_DHCP_OPTION_DHCP4_IP_ADDRESS_LEASE_TIME,
                                  (guint64) a_lifetime);

    if (a_expiry != G_MAXUINT64) {
        nm_dhcp_option_add_option_u64(options, AF_INET, NM_DHCP_OPTION_DHCP4_NM_EXPIRY, a_expiry);
    }

    n_dhcp4_client_lease_get_siaddr(lease, &a_next_server);
    if (a_next_server.s_addr != INADDR_ANY) {
        nm_dhcp_option_add_option_in_addr(options,
                                          AF_INET,
                                          NM_DHCP_OPTION_DHCP4_NM_NEXT_SERVER,
                                          a_next_server.s_addr);
    }

    nm_ip4_config_add_address(ip4_config,
                              &((const NMPlatformIP4Address){
                                  .address      = a_address.s_addr,
                                  .peer_address = a_address.s_addr,
                                  .plen         = a_plen,
                                  .addr_source  = NM_IP_CONFIG_SOURCE_DHCP,
                                  .timestamp    = a_timestamp,
                                  .lifetime     = a_lifetime,
                                  .preferred    = a_lifetime,
                              }));

    return TRUE;
}

static void
lease_parse_address_list(NDhcp4ClientLease *      lease,
                         NMIP4Config *            ip4_config,
                         NMDhcpOptionDhcp4Options option,
                         GHashTable *             options,
                         NMStrBuf *               sbuf)
{
    const guint8 *l_data;
    gsize         l_data_len;
    int           r;

    r = _client_lease_query(lease, option, &l_data, &l_data_len);
    if (r != 0)
        return;

    if (l_data_len == 0 || l_data_len % 4 != 0)
        return;

    nm_str_buf_reset(sbuf);

    for (; l_data_len > 0; l_data_len -= 4, l_data += 4) {
        char            addr_str[NM_UTILS_INET_ADDRSTRLEN];
        const in_addr_t addr = unaligned_read_ne32(l_data);

        nm_str_buf_append_required_delimiter(sbuf, ' ');
        nm_str_buf_append(sbuf, _nm_utils_inet4_ntop(addr, addr_str));

        switch (option) {
        case NM_DHCP_OPTION_DHCP4_DOMAIN_NAME_SERVER:
            if (addr == 0 || nm_ip4_addr_is_localhost(addr)) {
                /* Skip localhost addresses, like also networkd does.
                 * See https://github.com/systemd/systemd/issues/4524. */
                continue;
            }
            nm_ip4_config_add_nameserver(ip4_config, addr);
            break;
        case NM_DHCP_OPTION_DHCP4_NIS_SERVERS:
            nm_ip4_config_add_nis_server(ip4_config, addr);
            break;
        case NM_DHCP_OPTION_DHCP4_NETBIOS_NAMESERVER:
            nm_ip4_config_add_wins(ip4_config, addr);
            break;
        case NM_DHCP_OPTION_DHCP4_NTP_SERVER:
            break;
        default:
            nm_assert_not_reached();
        }
    }

    nm_dhcp_option_add_option(options, AF_INET, option, nm_str_buf_get_str(sbuf));
}

static void
lease_parse_routes(NDhcp4ClientLease *lease,
                   NMIP4Config *      ip4_config,
                   GHashTable *       options,
                   guint32            route_table,
                   guint32            route_metric,
                   NMStrBuf *         sbuf)
{
    char          dest_str[NM_UTILS_INET_ADDRSTRLEN];
    char          gateway_str[NM_UTILS_INET_ADDRSTRLEN];
    in_addr_t     dest;
    in_addr_t     gateway;
    uint8_t       plen;
    guint32       m;
    gboolean      has_router_from_classless = FALSE;
    gboolean      has_classless             = FALSE;
    guint32       default_route_metric      = route_metric;
    const guint8 *l_data;
    gsize         l_data_len;
    int           r;
    guint         i;

    for (i = 0; i < 2; i++) {
        const guint8 option_code = (i == 0) ? NM_DHCP_OPTION_DHCP4_CLASSLESS_STATIC_ROUTE
                                            : NM_DHCP_OPTION_DHCP4_PRIVATE_CLASSLESS_STATIC_ROUTE;

        if (_client_lease_query(lease, option_code, &l_data, &l_data_len) != 0)
            continue;

        nm_str_buf_reset(sbuf);
        while (lease_option_consume_route(&l_data, &l_data_len, TRUE, &dest, &plen, &gateway)) {
            _nm_utils_inet4_ntop(dest, dest_str);
            _nm_utils_inet4_ntop(gateway, gateway_str);

            nm_str_buf_append_required_delimiter(sbuf, ' ');
            nm_str_buf_append_printf(sbuf, "%s/%d %s", dest_str, (int) plen, gateway_str);

            if (has_classless) {
                /* Ignore private option if the standard one is present */
                continue;
            }

            if (plen == 0) {
                /* if there are multiple default routes, we add them with differing
                 * metrics. */
                m = default_route_metric;
                if (default_route_metric < G_MAXUINT32)
                    default_route_metric++;

                has_router_from_classless = TRUE;
            } else {
                m = route_metric;
            }

            nm_ip4_config_add_route(
                ip4_config,
                &((const NMPlatformIP4Route){
                    .network       = dest,
                    .plen          = plen,
                    .gateway       = gateway,
                    .rt_source     = NM_IP_CONFIG_SOURCE_DHCP,
                    .metric        = m,
                    .table_coerced = nm_platform_route_table_coerce(route_table),
                }),
                NULL);
        }

        has_classless = TRUE;
        nm_dhcp_option_add_option(options, AF_INET, option_code, nm_str_buf_get_str(sbuf));
    }

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_STATIC_ROUTE, &l_data, &l_data_len);
    if (r == 0) {
        nm_str_buf_reset(sbuf);

        while (lease_option_consume_route(&l_data, &l_data_len, FALSE, &dest, &plen, &gateway)) {
            _nm_utils_inet4_ntop(dest, dest_str);
            _nm_utils_inet4_ntop(gateway, gateway_str);

            nm_str_buf_append_required_delimiter(sbuf, ' ');
            nm_str_buf_append_printf(sbuf, "%s/%d %s", dest_str, (int) plen, gateway_str);

            if (has_classless) {
                /* RFC 3443: if the DHCP server returns both a Classless Static Routes
                 * option and a Static Routes option, the DHCP client MUST ignore the
                 * Static Routes option. */
                continue;
            }

            if (plen == 0) {
                /* for option 33 (static route), RFC 2132 says:
                 *
                 * The default route (0.0.0.0) is an illegal destination for a static
                 * route. */
                continue;
            }

            nm_ip4_config_add_route(
                ip4_config,
                &((const NMPlatformIP4Route){
                    .network       = dest,
                    .plen          = plen,
                    .gateway       = gateway,
                    .rt_source     = NM_IP_CONFIG_SOURCE_DHCP,
                    .metric        = route_metric,
                    .table_coerced = nm_platform_route_table_coerce(route_table),
                }),
                NULL);
        }

        nm_dhcp_option_add_option(options,
                                  AF_INET,
                                  NM_DHCP_OPTION_DHCP4_STATIC_ROUTE,
                                  nm_str_buf_get_str(sbuf));
    }

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_ROUTER, &l_data, &l_data_len);
    if (r == 0) {
        nm_str_buf_reset(sbuf);

        while (nm_dhcp_lease_data_consume_in_addr(&l_data, &l_data_len, &gateway)) {
            nm_str_buf_append_required_delimiter(sbuf, ' ');
            nm_str_buf_append(sbuf, _nm_utils_inet4_ntop(gateway, gateway_str));

            if (gateway == 0) {
                /* silently skip 0.0.0.0 */
                continue;
            }

            if (has_router_from_classless) {
                /* If the DHCP server returns both a Classless Static Routes option and a
                 * Router option, the DHCP client MUST ignore the Router option [RFC 3442].
                 *
                 * Be more lenient and ignore the Router option only if Classless Static
                 * Routes contain a default gateway (as other DHCP backends do).
                 */
                continue;
            }

            /* if there are multiple default routes, we add them with differing
             * metrics. */
            m = default_route_metric;
            if (default_route_metric < G_MAXUINT32)
                default_route_metric++;

            nm_ip4_config_add_route(
                ip4_config,
                &((const NMPlatformIP4Route){
                    .rt_source     = NM_IP_CONFIG_SOURCE_DHCP,
                    .gateway       = gateway,
                    .table_coerced = nm_platform_route_table_coerce(route_table),
                    .metric        = m,
                }),
                NULL);
        }

        nm_dhcp_option_add_option(options,
                                  AF_INET,
                                  NM_DHCP_OPTION_DHCP4_ROUTER,
                                  nm_str_buf_get_str(sbuf));
    }
}

static void
lease_parse_search_domains(NDhcp4ClientLease *lease, NMIP4Config *ip4_config, GHashTable *options)
{
    gs_strfreev char **domains = NULL;
    const guint8 *     l_data;
    gsize              l_data_len;
    guint              i;
    int                r;

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_DOMAIN_SEARCH_LIST, &l_data, &l_data_len);
    if (r != 0)
        return;

    domains = nm_dhcp_lease_data_parse_search_list(l_data, l_data_len);

    if (!domains || !domains[0])
        return;

    for (i = 0; domains[i]; i++)
        nm_ip4_config_add_search(ip4_config, domains[i]);

    nm_dhcp_option_take_option(options,
                               AF_INET,
                               NM_DHCP_OPTION_DHCP4_DOMAIN_SEARCH_LIST,
                               g_strjoinv(" ", domains));
}

static void
lease_parse_private_options(NDhcp4ClientLease *lease, GHashTable *options)
{
    int i;

    for (i = NM_DHCP_OPTION_DHCP4_PRIVATE_224; i <= NM_DHCP_OPTION_DHCP4_PRIVATE_254; i++) {
        gs_free char *option_string = NULL;
        const guint8 *l_data;
        gsize         l_data_len;
        int           r;

        /* We manage private options 249 (private classless static route) and 252 (wpad) in a special
         * way, so skip them as we here just manage all (the other) private options as raw data */
        if (NM_IN_SET(i,
                      NM_DHCP_OPTION_DHCP4_PRIVATE_CLASSLESS_STATIC_ROUTE,
                      NM_DHCP_OPTION_DHCP4_PRIVATE_PROXY_AUTODISCOVERY))
            continue;

        r = _client_lease_query(lease, i, &l_data, &l_data_len);
        if (r)
            continue;

        option_string = nm_utils_bin2hexstr_full(l_data, l_data_len, ':', FALSE, NULL);
        nm_dhcp_option_take_option(options, AF_INET, i, g_steal_pointer(&option_string));
    }
}

static NMIP4Config *
lease_to_ip4_config(NMDedupMultiIndex *multi_idx,
                    const char *       iface,
                    int                ifindex,
                    NDhcp4ClientLease *lease,
                    guint32            route_table,
                    guint32            route_metric,
                    GHashTable **      out_options,
                    GError **          error)
{
    nm_auto_str_buf NMStrBuf sbuf           = NM_STR_BUF_INIT(0, FALSE);
    gs_unref_object NMIP4Config *ip4_config = NULL;
    gs_unref_hashtable GHashTable *options  = NULL;
    const guint8 *                 l_data;
    gsize                          l_data_len;
    const char *                   v_str;
    guint16                        v_u16;
    gboolean                       v_bool;
    in_addr_t                      v_inaddr;
    struct in_addr                 v_inaddr_s;
    int                            r;

    g_return_val_if_fail(lease != NULL, NULL);

    ip4_config = nm_ip4_config_new(multi_idx, ifindex);
    options    = nm_dhcp_option_create_options_dict();

    if (!lease_parse_address(lease, ip4_config, options, error))
        return NULL;

    r = n_dhcp4_client_lease_get_server_identifier(lease, &v_inaddr_s);
    if (r == 0) {
        nm_dhcp_option_add_option_in_addr(options,
                                          AF_INET,
                                          NM_DHCP_OPTION_DHCP4_SERVER_ID,
                                          v_inaddr_s.s_addr);
    }

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_BROADCAST, &l_data, &l_data_len);
    if (r == 0 && nm_dhcp_lease_data_parse_in_addr(l_data, l_data_len, &v_inaddr)) {
        nm_dhcp_option_add_option_in_addr(options,
                                          AF_INET,
                                          NM_DHCP_OPTION_DHCP4_BROADCAST,
                                          v_inaddr);
    }

    lease_parse_routes(lease, ip4_config, options, route_table, route_metric, &sbuf);

    lease_parse_address_list(lease,
                             ip4_config,
                             NM_DHCP_OPTION_DHCP4_DOMAIN_NAME_SERVER,
                             options,
                             &sbuf);

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_DOMAIN_NAME, &l_data, &l_data_len);
    if (r == 0 && nm_dhcp_lease_data_parse_cstr(l_data, l_data_len, &l_data_len)) {
        gs_free const char **domains = NULL;

        nm_str_buf_reset(&sbuf);
        nm_str_buf_append_len0(&sbuf, (const char *) l_data, l_data_len);

        /* Multiple domains sometimes stuffed into option 15 "Domain Name". */
        domains = nm_utils_strsplit_set(nm_str_buf_get_str(&sbuf), " ");

        nm_str_buf_reset(&sbuf);
        if (domains) {
            gsize i;

            for (i = 0; domains[i]; i++) {
                gs_free char *s = NULL;

                s = nm_dhcp_lease_data_parse_domain_validate(domains[i]);
                if (!s)
                    continue;

                nm_str_buf_append_required_delimiter(&sbuf, ' ');
                nm_str_buf_append(&sbuf, s);
                nm_ip4_config_add_domain(ip4_config, s);
            }
        }

        if (sbuf.len > 0) {
            nm_dhcp_option_add_option(options,
                                      AF_INET,
                                      NM_DHCP_OPTION_DHCP4_DOMAIN_NAME,
                                      nm_str_buf_get_str(&sbuf));
        }
    }

    lease_parse_search_domains(lease, ip4_config, options);

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_INTERFACE_MTU, &l_data, &l_data_len);
    if (r == 0 && nm_dhcp_lease_data_parse_mtu(l_data, l_data_len, &v_u16)) {
        nm_dhcp_option_add_option_u64(options, AF_INET, NM_DHCP_OPTION_DHCP4_INTERFACE_MTU, v_u16);
        nm_ip4_config_set_mtu(ip4_config, v_u16, NM_IP_CONFIG_SOURCE_DHCP);
    }

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_VENDOR_SPECIFIC, &l_data, &l_data_len);
    v_bool =
        (r == 0) && memmem(l_data, l_data_len, "ANDROID_METERED", NM_STRLEN("ANDROID_METERED"));
    nm_ip4_config_set_metered(ip4_config, v_bool);

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_HOST_NAME, &l_data, &l_data_len);
    if (r == 0) {
        gs_free char *s = NULL;

        if (nm_dhcp_lease_data_parse_domain(l_data, l_data_len, &s)) {
            nm_dhcp_option_add_option(options, AF_INET, NM_DHCP_OPTION_DHCP4_HOST_NAME, s);
        }
    }

    lease_parse_address_list(lease, ip4_config, NM_DHCP_OPTION_DHCP4_NTP_SERVER, options, &sbuf);

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_ROOT_PATH, &l_data, &l_data_len);
    if (r == 0 && nm_dhcp_lease_data_parse_cstr(l_data, l_data_len, &l_data_len)) {
        /* https://tools.ietf.org/html/rfc2132#section-3.19
         *
         *   The path is formatted as a character string consisting of
         *   characters from the NVT ASCII character set.
         *
         * We still accept any character set and backslash escape it! */
        if (l_data_len == 0) {
            /* "Its minimum length is 1." */
        } else {
            nm_dhcp_option_add_option_utf8safe_escape(options,
                                                      AF_INET,
                                                      NM_DHCP_OPTION_DHCP4_ROOT_PATH,
                                                      l_data,
                                                      l_data_len);
        }
    }

    r = _client_lease_query(lease,
                            NM_DHCP_OPTION_DHCP4_PRIVATE_PROXY_AUTODISCOVERY,
                            &l_data,
                            &l_data_len);
    if (r == 0 && nm_dhcp_lease_data_parse_cstr(l_data, l_data_len, &l_data_len)) {
        /* https://tools.ietf.org/html/draft-ietf-wrec-wpad-01#section-4.4.1
         *
         * We reject NUL characters inside the string (except trailing NULs).
         * Otherwise, we allow any encoding and backslash-escape the result to
         * UTF-8. */
        nm_dhcp_option_add_option_utf8safe_escape(options,
                                                  AF_INET,
                                                  NM_DHCP_OPTION_DHCP4_PRIVATE_PROXY_AUTODISCOVERY,
                                                  l_data,
                                                  l_data_len);
    }

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_NIS_DOMAIN, &l_data, &l_data_len);
    if (r == 0 && nm_dhcp_lease_data_parse_cstr(l_data, l_data_len, &l_data_len)) {
        gs_free char *to_free = NULL;

        /* https://tools.ietf.org/html/rfc2132#section-8.1 */

        v_str = nm_utils_buf_utf8safe_escape((char *) l_data, l_data_len, 0, &to_free);

        nm_dhcp_option_add_option(options, AF_INET, NM_DHCP_OPTION_DHCP4_NIS_DOMAIN, v_str ?: "");
        nm_ip4_config_set_nis_domain(ip4_config, v_str ?: "");
    }

    lease_parse_address_list(lease, ip4_config, NM_DHCP_OPTION_DHCP4_NIS_SERVERS, options, &sbuf);

    lease_parse_address_list(lease,
                             ip4_config,
                             NM_DHCP_OPTION_DHCP4_NETBIOS_NAMESERVER,
                             options,
                             &sbuf);

    lease_parse_private_options(lease, options);

    NM_SET_OUT(out_options, g_steal_pointer(&options));
    return g_steal_pointer(&ip4_config);
}

/*****************************************************************************/

static void
lease_save(NMDhcpNettools *self, NDhcp4ClientLease *lease, const char *lease_file)
{
    struct in_addr           a_address;
    nm_auto_str_buf NMStrBuf sbuf = NM_STR_BUF_INIT(NM_UTILS_GET_NEXT_REALLOC_SIZE_104, FALSE);
    char                     addr_str[NM_UTILS_INET_ADDRSTRLEN];
    gs_free_error GError *error = NULL;

    nm_assert(lease);
    nm_assert(lease_file);

    n_dhcp4_client_lease_get_yiaddr(lease, &a_address);
    if (a_address.s_addr == INADDR_ANY)
        return;

    nm_str_buf_append(&sbuf, "# This is private data. Do not parse.\n");
    nm_str_buf_append_printf(&sbuf,
                             "ADDRESS=%s\n",
                             _nm_utils_inet4_ntop(a_address.s_addr, addr_str));

    if (!g_file_set_contents(lease_file, nm_str_buf_get_str_unsafe(&sbuf), sbuf.len, &error))
        _LOGW("error saving lease to %s: %s", lease_file, error->message);
}

static void
bound4_handle(NMDhcpNettools *self, NDhcp4ClientLease *lease, gboolean extended)
{
    NMDhcpNettoolsPrivate *priv             = NM_DHCP_NETTOOLS_GET_PRIVATE(self);
    const char *           iface            = nm_dhcp_client_get_iface(NM_DHCP_CLIENT(self));
    gs_unref_object NMIP4Config *ip4_config = NULL;
    gs_unref_hashtable GHashTable *options  = NULL;
    GError *                       error    = NULL;

    _LOGT("lease available (%s)", extended ? "extended" : "new");

    ip4_config = lease_to_ip4_config(nm_dhcp_client_get_multi_idx(NM_DHCP_CLIENT(self)),
                                     iface,
                                     nm_dhcp_client_get_ifindex(NM_DHCP_CLIENT(self)),
                                     lease,
                                     nm_dhcp_client_get_route_table(NM_DHCP_CLIENT(self)),
                                     nm_dhcp_client_get_route_metric(NM_DHCP_CLIENT(self)),
                                     &options,
                                     &error);
    if (!ip4_config) {
        _LOGW("%s", error->message);
        g_clear_error(&error);
        nm_dhcp_client_set_state(NM_DHCP_CLIENT(self), NM_DHCP_STATE_FAIL, NULL, NULL);
        return;
    }

    nm_dhcp_option_add_requests_to_options(options, AF_INET);
    lease_save(self, lease, priv->lease_file);

    nm_dhcp_client_set_state(NM_DHCP_CLIENT(self),
                             extended ? NM_DHCP_STATE_EXTENDED : NM_DHCP_STATE_BOUND,
                             NM_IP_CONFIG_CAST(ip4_config),
                             options);
}

static void
dhcp4_event_handle(NMDhcpNettools *self, NDhcp4ClientEvent *event)
{
    NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE(self);
    struct in_addr         server_id;
    char                   addr_str[INET_ADDRSTRLEN];
    int                    r;

    _LOGT("client event %d", event->event);

    switch (event->event) {
    case N_DHCP4_CLIENT_EVENT_OFFER:
        r = n_dhcp4_client_lease_get_server_identifier(event->offer.lease, &server_id);
        if (r) {
            _LOGW("selecting lease failed: %d", r);
            return;
        }

        if (nm_dhcp_client_server_id_is_rejected(NM_DHCP_CLIENT(self), &server_id)) {
            _LOGD("server-id %s is in the reject-list, ignoring",
                  nm_utils_inet_ntop(AF_INET, &server_id, addr_str));
            return;
        }

        r = n_dhcp4_client_lease_select(event->offer.lease);
        if (r) {
            _LOGW("selecting lease failed: %d", r);
            return;
        }
        break;
    case N_DHCP4_CLIENT_EVENT_RETRACTED:
    case N_DHCP4_CLIENT_EVENT_EXPIRED:
        nm_dhcp_client_set_state(NM_DHCP_CLIENT(self), NM_DHCP_STATE_EXPIRE, NULL, NULL);
        break;
    case N_DHCP4_CLIENT_EVENT_CANCELLED:
        nm_dhcp_client_set_state(NM_DHCP_CLIENT(self), NM_DHCP_STATE_FAIL, NULL, NULL);
        break;
    case N_DHCP4_CLIENT_EVENT_GRANTED:
        priv->lease = n_dhcp4_client_lease_ref(event->granted.lease);
        bound4_handle(self, event->granted.lease, FALSE);
        break;
    case N_DHCP4_CLIENT_EVENT_EXTENDED:
        bound4_handle(self, event->extended.lease, TRUE);
        break;
    case N_DHCP4_CLIENT_EVENT_DOWN:
        /* ignore down events, they are purely informational */
        break;
    case N_DHCP4_CLIENT_EVENT_LOG:
    {
        NMLogLevel nm_level;

        nm_level = nm_log_level_from_syslog(event->log.level);
        if (nm_logging_enabled(nm_level, LOGD_DHCP4)) {
            nm_log(nm_level,
                   LOGD_DHCP4,
                   NULL,
                   NULL,
                   "dhcp4 (%s): %s",
                   nm_dhcp_client_get_iface(NM_DHCP_CLIENT(self)),
                   event->log.message);
        }
    } break;
    default:
        _LOGW("unhandled DHCP event %d", event->event);
        break;
    }
}

static gboolean
dhcp4_event_cb(int fd, GIOCondition condition, gpointer user_data)
{
    NMDhcpNettools *       self = user_data;
    NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE(self);
    NDhcp4ClientEvent *    event;
    int                    r;

    r = n_dhcp4_client_dispatch(priv->client);
    if (r < 0) {
        /* FIXME: if any operation (e.g. send()) fails during the
         * dispatch, n-dhcp4 returns an error without arming timers
         * or progressing state, so the only reasonable thing to do
         * is to move to failed state so that the client will be
         * restarted. Ideally n-dhcp4 should retry failed operations
         * a predefined number of times (possibly infinite).
         */
        _LOGE("error %d dispatching events", r);
        nm_clear_g_source_inst(&priv->event_source);
        nm_dhcp_client_set_state(NM_DHCP_CLIENT(self), NM_DHCP_STATE_FAIL, NULL, NULL);
        return G_SOURCE_REMOVE;
    }

    while (!n_dhcp4_client_pop_event(priv->client, &event) && event) {
        dhcp4_event_handle(self, event);
    }

    return G_SOURCE_CONTINUE;
}

static gboolean
nettools_create(NMDhcpNettools *self, const char *dhcp_anycast_addr, GError **error)
{
    NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE(self);
    nm_auto(n_dhcp4_client_config_freep) NDhcp4ClientConfig *config = NULL;
    nm_auto(n_dhcp4_client_unrefp) NDhcp4Client *            client = NULL;
    GBytes *                                                 hwaddr;
    GBytes *                                                 bcast_hwaddr;
    const uint8_t *                                          hwaddr_arr;
    const uint8_t *                                          bcast_hwaddr_arr;
    gsize                                                    hwaddr_len;
    gsize                                                    bcast_hwaddr_len;
    GBytes *                                                 client_id;
    gs_unref_bytes GBytes *client_id_new = NULL;
    const uint8_t *        client_id_arr;
    size_t                 client_id_len;
    int                    r, fd, arp_type, transport;

    g_return_val_if_fail(!priv->client, FALSE);

    hwaddr = nm_dhcp_client_get_hw_addr(NM_DHCP_CLIENT(self));
    if (!hwaddr || !(hwaddr_arr = g_bytes_get_data(hwaddr, &hwaddr_len))
        || (arp_type = nm_utils_arp_type_detect_from_hwaddrlen(hwaddr_len)) < 0) {
        nm_utils_error_set_literal(error, NM_UTILS_ERROR_UNKNOWN, "invalid MAC address");
        return FALSE;
    }

    bcast_hwaddr     = nm_dhcp_client_get_broadcast_hw_addr(NM_DHCP_CLIENT(self));
    bcast_hwaddr_arr = g_bytes_get_data(bcast_hwaddr, &bcast_hwaddr_len);

    switch (arp_type) {
    case ARPHRD_ETHER:
        transport = N_DHCP4_TRANSPORT_ETHERNET;
        break;
    case ARPHRD_INFINIBAND:
        transport = N_DHCP4_TRANSPORT_INFINIBAND;
        break;
    default:
        nm_utils_error_set_literal(error, NM_UTILS_ERROR_UNKNOWN, "unsupported ARP type");
        return FALSE;
    }

    /* Note that we always set a client-id. In particular for infiniband that is necessary,
     * see https://tools.ietf.org/html/rfc4390#section-2.1 . */
    client_id = nm_dhcp_client_get_client_id(NM_DHCP_CLIENT(self));
    if (!client_id) {
        client_id_new = nm_utils_dhcp_client_id_mac(arp_type, hwaddr_arr, hwaddr_len);
        client_id     = client_id_new;
    }

    if (!(client_id_arr = g_bytes_get_data(client_id, &client_id_len)) || client_id_len < 2) {
        /* invalid client-ids are not expected. */
        nm_assert_not_reached();

        nm_utils_error_set_literal(error, NM_UTILS_ERROR_UNKNOWN, "no valid IPv4 client-id");
        return FALSE;
    }

    r = n_dhcp4_client_config_new(&config);
    if (r) {
        set_error_nettools(error, r, "failed to create client-config");
        return FALSE;
    }

    n_dhcp4_client_config_set_ifindex(config, nm_dhcp_client_get_ifindex(NM_DHCP_CLIENT(self)));
    n_dhcp4_client_config_set_transport(config, transport);
    n_dhcp4_client_config_set_mac(config, hwaddr_arr, hwaddr_len);
    n_dhcp4_client_config_set_broadcast_mac(config, bcast_hwaddr_arr, bcast_hwaddr_len);
    r = n_dhcp4_client_config_set_client_id(config,
                                            client_id_arr,
                                            NM_MIN(client_id_len, 1 + _NM_SD_MAX_CLIENT_ID_LEN));
    if (r) {
        set_error_nettools(error, r, "failed to set client-id");
        return FALSE;
    }

    r = n_dhcp4_client_new(&client, config);
    if (r) {
        set_error_nettools(error, r, "failed to create client");
        return FALSE;
    }

    priv->client = client;
    client       = NULL;

    n_dhcp4_client_set_log_level(priv->client,
                                 nm_log_level_to_syslog(nm_logging_get_level(LOGD_DHCP4)));

    n_dhcp4_client_get_fd(priv->client, &fd);

    priv->event_source =
        nm_g_unix_fd_source_new(fd, G_IO_IN, G_PRIORITY_DEFAULT, dhcp4_event_cb, self, NULL);
    g_source_attach(priv->event_source, NULL);

    return TRUE;
}

static gboolean
_accept(NMDhcpClient *client, GError **error)
{
    NMDhcpNettools *       self = NM_DHCP_NETTOOLS(client);
    NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE(self);
    int                    r;

    g_return_val_if_fail(priv->lease, FALSE);

    _LOGT("accept");

    r = n_dhcp4_client_lease_accept(priv->lease);
    if (r) {
        set_error_nettools(error, r, "failed to accept lease");
        return FALSE;
    }

    priv->lease = n_dhcp4_client_lease_unref(priv->lease);

    return TRUE;
}

static gboolean
decline(NMDhcpClient *client, const char *error_message, GError **error)
{
    NMDhcpNettools *       self = NM_DHCP_NETTOOLS(client);
    NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE(self);
    int                    r;

    g_return_val_if_fail(priv->lease, FALSE);

    _LOGT("dhcp4-client: decline");

    r = n_dhcp4_client_lease_decline(priv->lease, error_message);
    if (r) {
        set_error_nettools(error, r, "failed to decline lease");
        return FALSE;
    }

    priv->lease = n_dhcp4_client_lease_unref(priv->lease);

    return TRUE;
}

static guint8
fqdn_flags_to_wire(NMDhcpHostnameFlags flags)
{
    guint r = 0;

    /* RFC 4702 section 2.1 */
    if (flags & NM_DHCP_HOSTNAME_FLAG_FQDN_SERV_UPDATE)
        r |= (1 << 0);
    if (flags & NM_DHCP_HOSTNAME_FLAG_FQDN_ENCODED)
        r |= (1 << 2);
    if (flags & NM_DHCP_HOSTNAME_FLAG_FQDN_NO_UPDATE)
        r |= (1 << 3);

    return r;
}

static gboolean
ip4_start(NMDhcpClient *client,
          const char *  dhcp_anycast_addr,
          const char *  last_ip4_address,
          GError **     error)
{
    nm_auto(n_dhcp4_client_probe_config_freep) NDhcp4ClientProbeConfig *config = NULL;
    NMDhcpNettools *       self       = NM_DHCP_NETTOOLS(client);
    NMDhcpNettoolsPrivate *priv       = NM_DHCP_NETTOOLS_GET_PRIVATE(self);
    gs_free char *         lease_file = NULL;
    struct in_addr         last_addr  = {0};
    const char *           hostname;
    const char *           mud_url;
    GBytes *               vendor_class_identifier;
    int                    r, i;

    g_return_val_if_fail(!priv->probe, FALSE);

    if (!nettools_create(self, dhcp_anycast_addr, error))
        return FALSE;

    r = n_dhcp4_client_probe_config_new(&config);
    if (r) {
        set_error_nettools(error, r, "failed to create dhcp-client-probe-config");
        return FALSE;
    }

    /*
     * FIXME:
     * Select, or configure, a reasonable start delay, to protect poor servers being flooded.
     */
    n_dhcp4_client_probe_config_set_start_delay(config, 1);

    nm_dhcp_utils_get_leasefile_path(AF_INET,
                                     "internal",
                                     nm_dhcp_client_get_iface(client),
                                     nm_dhcp_client_get_uuid(client),
                                     &lease_file);

    if (last_ip4_address)
        inet_pton(AF_INET, last_ip4_address, &last_addr);
    else {
        /*
         * TODO: we stick to the systemd-networkd lease file format. Quite easy for now to
         * just use the functions in systemd code. Anyway, as in the end we just use the
         * ip address from all the options found in the lease, write a function that parses
         * the lease file just for the assigned address and returns it in &last_address.
         * Then drop reference to systemd-networkd structures and functions.
         */
        nm_auto(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;

        dhcp_lease_load(&lease, lease_file);
        if (lease)
            sd_dhcp_lease_get_address(lease, &last_addr);
    }

    if (last_addr.s_addr) {
        n_dhcp4_client_probe_config_set_requested_ip(config, last_addr);
        n_dhcp4_client_probe_config_set_init_reboot(config, TRUE);
    }

    /* Add requested options */
    for (i = 0; i < (int) G_N_ELEMENTS(_nm_dhcp_option_dhcp4_options); i++) {
        if (_nm_dhcp_option_dhcp4_options[i].include) {
            nm_assert(_nm_dhcp_option_dhcp4_options[i].option_num <= 255);
            n_dhcp4_client_probe_config_request_option(config,
                                                       _nm_dhcp_option_dhcp4_options[i].option_num);
        }
    }

    mud_url = nm_dhcp_client_get_mud_url(client);
    if (mud_url) {
        r = n_dhcp4_client_probe_config_append_option(config,
                                                      NM_DHCP_OPTION_DHCP4_MUD_URL,
                                                      mud_url,
                                                      strlen(mud_url));
        if (r) {
            set_error_nettools(error, r, "failed to set MUD URL");
            return FALSE;
        }
    }
    hostname = nm_dhcp_client_get_hostname(client);
    if (hostname) {
        if (nm_dhcp_client_get_use_fqdn(client)) {
            uint8_t             buffer[255];
            NMDhcpHostnameFlags flags;
            size_t              fqdn_len;

            flags     = nm_dhcp_client_get_hostname_flags(client);
            buffer[0] = fqdn_flags_to_wire(flags);
            buffer[1] = 0; /* RCODE1 (deprecated) */
            buffer[2] = 0; /* RCODE2 (deprecated) */

            if (flags & NM_DHCP_HOSTNAME_FLAG_FQDN_ENCODED) {
                r = nm_sd_dns_name_to_wire_format(hostname, buffer + 3, sizeof(buffer) - 3, FALSE);
                if (r <= 0) {
                    if (r < 0)
                        nm_utils_error_set_errno(error, r, "failed to convert DHCP FQDN: %s");
                    else
                        nm_utils_error_set(error, r, "failed to convert DHCP FQDN");
                    return FALSE;
                }
                fqdn_len = r;
            } else {
                fqdn_len = strlen(hostname);
                if (fqdn_len > sizeof(buffer) - 3) {
                    nm_utils_error_set(error, r, "failed to set DHCP FQDN: name too long");
                    return FALSE;
                }
                memcpy(buffer + 3, hostname, fqdn_len);
            }

            r = n_dhcp4_client_probe_config_append_option(config,
                                                          NM_DHCP_OPTION_DHCP4_CLIENT_FQDN,
                                                          buffer,
                                                          3 + fqdn_len);
            if (r) {
                set_error_nettools(error, r, "failed to set DHCP FQDN");
                return FALSE;
            }
        } else {
            r = n_dhcp4_client_probe_config_append_option(config,
                                                          NM_DHCP_OPTION_DHCP4_HOST_NAME,
                                                          hostname,
                                                          strlen(hostname));
            if (r) {
                set_error_nettools(error, r, "failed to set DHCP hostname");
                return FALSE;
            }
        }
    }

    vendor_class_identifier = nm_dhcp_client_get_vendor_class_identifier(client);
    if (vendor_class_identifier) {
        const void *option_data;
        gsize       option_size;

        option_data = g_bytes_get_data(vendor_class_identifier, &option_size);
        nm_assert(option_data);
        nm_assert(option_size <= 255);

        r = n_dhcp4_client_probe_config_append_option(config,
                                                      NM_DHCP_OPTION_DHCP4_VENDOR_CLASS_IDENTIFIER,
                                                      option_data,
                                                      option_size);
        if (r) {
            set_error_nettools(error, r, "failed to set vendor class identifier");
            return FALSE;
        }
    }

    g_free(priv->lease_file);
    priv->lease_file = g_steal_pointer(&lease_file);

    r = n_dhcp4_client_probe(priv->client, &priv->probe, config);
    if (r) {
        set_error_nettools(error, r, "failed to start DHCP client");
        return FALSE;
    }

    _LOGT("dhcp-client4: start %p", (gpointer) priv->client);

    nm_dhcp_client_start_timeout(client);
    return TRUE;
}

static void
stop(NMDhcpClient *client, gboolean release)
{
    NMDhcpNettools *       self = NM_DHCP_NETTOOLS(client);
    NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE(self);

    NM_DHCP_CLIENT_CLASS(nm_dhcp_nettools_parent_class)->stop(client, release);

    _LOGT("dhcp-client4: stop %p", (gpointer) priv->client);

    priv->probe = n_dhcp4_client_probe_free(priv->probe);
}

/*****************************************************************************/

static void
nm_dhcp_nettools_init(NMDhcpNettools *self)
{}

static void
dispose(GObject *object)
{
    NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE(object);

    nm_clear_g_free(&priv->lease_file);
    nm_clear_g_source_inst(&priv->event_source);
    nm_clear_pointer(&priv->lease, n_dhcp4_client_lease_unref);
    nm_clear_pointer(&priv->probe, n_dhcp4_client_probe_free);
    nm_clear_pointer(&priv->client, n_dhcp4_client_unref);

    G_OBJECT_CLASS(nm_dhcp_nettools_parent_class)->dispose(object);
}

static void
nm_dhcp_nettools_class_init(NMDhcpNettoolsClass *class)
{
    NMDhcpClientClass *client_class = NM_DHCP_CLIENT_CLASS(class);
    GObjectClass *     object_class = G_OBJECT_CLASS(class);

    object_class->dispose = dispose;

    client_class->ip4_start = ip4_start;
    client_class->accept    = _accept;
    client_class->decline   = decline;
    client_class->stop      = stop;
}

const NMDhcpClientFactory _nm_dhcp_client_factory_nettools = {
    .name         = "nettools",
    .get_type     = nm_dhcp_nettools_get_type,
    .experimental = TRUE,
};
