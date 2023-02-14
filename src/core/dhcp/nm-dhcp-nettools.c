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

#include "n-dhcp4/src/n-dhcp4.h"

#include "libnm-glib-aux/nm-dedup-multi.h"
#include "libnm-glib-aux/nm-io-utils.h"
#include "libnm-glib-aux/nm-str-buf.h"
#include "libnm-std-aux/unaligned.h"

#include "NetworkManagerUtils.h"
#include "libnm-platform/nm-platform.h"
#include "nm-config.h"
#include "nm-core-utils.h"
#include "nm-dhcp-client-logging.h"
#include "nm-dhcp-options.h"
#include "nm-dhcp-utils.h"
#include "nm-l3-config-data.h"
#include "nm-utils.h"

#include "libnm-systemd-shared/nm-sd-utils-shared.h"

/*****************************************************************************/

#define NM_TYPE_DHCP_NETTOOLS (nm_dhcp_nettools_get_type())
#define NM_DHCP_NETTOOLS(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DHCP_NETTOOLS, NMDhcpNettools))
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
    NDhcp4Client      *client;
    NDhcp4ClientProbe *probe;

    struct {
        NDhcp4ClientLease    *lease;
        const NML3ConfigData *lease_l3cd;
    } granted;

    GSource *pop_all_events_on_idle_source;

    GSource *event_source;
    char    *lease_file;
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

static void dhcp4_event_pop_all_events_on_idle(NMDhcpNettools *self);

/*****************************************************************************/

#define _add_option(options, option, str) \
    nm_dhcp_option_add_option((options), TRUE, AF_INET, (option), (str))

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
                    const uint8_t    **datap,
                    size_t            *n_datap)
{
    return n_dhcp4_client_lease_query(lease, option, (guint8 **) datap, n_datap);
}

/*****************************************************************************/

#define DHCP_MAX_FQDN_LENGTH 255

/*****************************************************************************/

static gboolean
lease_option_consume_route(const uint8_t **datap,
                           size_t         *n_datap,
                           gboolean        classless,
                           in_addr_t      *destp,
                           uint8_t        *plenp,
                           in_addr_t      *gatewayp)
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

        plen = nm_ip4_addr_get_default_prefix0(dest);
        if (plen == 0)
            return FALSE;
    }

    dest = nm_ip4_addr_clear_host_address(dest, plen);

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
lease_parse_address(NMDhcpNettools    *self /* for logging context only */,
                    NDhcp4ClientLease *lease,
                    NML3ConfigData    *l3cd,
                    const char        *iface,
                    GHashTable        *options,
                    in_addr_t         *out_address,
                    GError           **error)
{
    struct in_addr a_address;
    in_addr_t      a_netmask;
    struct in_addr a_next_server;
    guint32        a_plen;
    guint64        nettools_lifetime;
    guint32        a_lifetime;
    guint32        a_timestamp;
    guint64        a_expiry;
    const guint8  *l_data;
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
    if (r == N_DHCP4_E_UNSET) {
        char str1[NM_INET_ADDRSTRLEN];
        char str2[NM_INET_ADDRSTRLEN];

        /* Some DHCP servers may not set the subnet-mask (issue#1037).
         * Do the same as the dhclient plugin and use a default. */
        a_plen    = nm_ip4_addr_get_default_prefix(a_address.s_addr);
        a_netmask = nm_ip4_addr_netmask_from_prefix(a_plen);
        _LOGT("missing subnet mask (option 1). Guess %s based on IP address %s",
              nm_inet4_ntop(a_netmask, str1),
              nm_inet4_ntop(a_address.s_addr, str2));
    } else {
        if (r != 0
            || !nm_dhcp_lease_data_parse_in_addr(l_data,
                                                 l_data_len,
                                                 &a_netmask,
                                                 iface,
                                                 NM_DHCP_OPTION_DHCP4_SUBNET_MASK)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_UNKNOWN,
                                       "could not get netmask from lease");
            return FALSE;
        }
        a_plen    = nm_ip4_addr_netmask_to_prefix(a_netmask);
        a_netmask = nm_ip4_addr_netmask_from_prefix(a_plen);
    }

    nm_dhcp_option_add_option_in_addr(options,
                                      TRUE,
                                      AF_INET,
                                      NM_DHCP_OPTION_DHCP4_NM_IP_ADDRESS,
                                      a_address.s_addr);
    nm_dhcp_option_add_option_in_addr(options,
                                      TRUE,
                                      AF_INET,
                                      NM_DHCP_OPTION_DHCP4_SUBNET_MASK,
                                      a_netmask);

    nm_dhcp_option_add_option_u64(options,
                                  TRUE,
                                  AF_INET,
                                  NM_DHCP_OPTION_DHCP4_IP_ADDRESS_LEASE_TIME,
                                  (guint64) a_lifetime);

    if (a_expiry != G_MAXUINT64) {
        nm_dhcp_option_add_option_u64(options,
                                      TRUE,
                                      AF_INET,
                                      NM_DHCP_OPTION_DHCP4_NM_EXPIRY,
                                      a_expiry);
    }

    n_dhcp4_client_lease_get_siaddr(lease, &a_next_server);
    if (a_next_server.s_addr != INADDR_ANY) {
        nm_dhcp_option_add_option_in_addr(options,
                                          TRUE,
                                          AF_INET,
                                          NM_DHCP_OPTION_DHCP4_NM_NEXT_SERVER,
                                          a_next_server.s_addr);
    }

    nm_l3_config_data_add_address_4(l3cd,
                                    &((const NMPlatformIP4Address){
                                        .address      = a_address.s_addr,
                                        .peer_address = a_address.s_addr,
                                        .plen         = a_plen,
                                        .addr_source  = NM_IP_CONFIG_SOURCE_DHCP,
                                        .timestamp    = a_timestamp,
                                        .lifetime     = a_lifetime,
                                        .preferred    = a_lifetime,
                                    }));

    NM_SET_OUT(out_address, a_address.s_addr);

    return TRUE;
}

static void
lease_parse_address_list(NDhcp4ClientLease       *lease,
                         NML3ConfigData          *l3cd,
                         const char              *iface,
                         NMDhcpOptionDhcp4Options option,
                         GHashTable              *options,
                         NMStrBuf                *sbuf)
{
    const guint8 *l_data;
    gsize         l_data_len;
    int           r;

    r = _client_lease_query(lease, option, &l_data, &l_data_len);
    if (r != 0)
        return;

    if (l_data_len == 0 || l_data_len % 4 != 0) {
        nm_dhcp_lease_log_invalid_option(iface,
                                         AF_INET,
                                         option,
                                         "wrong option length %lu",
                                         (unsigned long) l_data_len);
        return;
    }

    nm_str_buf_reset(sbuf);

    for (; l_data_len > 0; l_data_len -= 4, l_data += 4) {
        char            addr_str[NM_INET_ADDRSTRLEN];
        const in_addr_t addr = unaligned_read_ne32(l_data);

        nm_str_buf_append_required_delimiter(sbuf, ' ');
        nm_str_buf_append(sbuf, nm_inet4_ntop(addr, addr_str));

        switch (option) {
        case NM_DHCP_OPTION_DHCP4_DOMAIN_NAME_SERVER:
            if (addr == 0 || nm_ip4_addr_is_loopback(addr)) {
                /* Skip localhost addresses, like also networkd does.
                 * See https://github.com/systemd/systemd/issues/4524. */
                nm_dhcp_lease_log_invalid_option(iface,
                                                 AF_INET,
                                                 option,
                                                 "address %s is ignored",
                                                 nm_inet4_ntop(addr, addr_str));
                continue;
            }
            nm_l3_config_data_add_nameserver_detail(l3cd, AF_INET, &addr, NULL);
            break;
        case NM_DHCP_OPTION_DHCP4_NIS_SERVERS:
            nm_l3_config_data_add_nis_server(l3cd, addr);
            break;
        case NM_DHCP_OPTION_DHCP4_NETBIOS_NAMESERVER:
            nm_l3_config_data_add_wins(l3cd, addr);
            break;
        case NM_DHCP_OPTION_DHCP4_NTP_SERVER:
            break;
        default:
            nm_assert_not_reached();
        }
    }

    _add_option(options, option, nm_str_buf_get_str(sbuf));
}

static void
lease_parse_routes(NDhcp4ClientLease *lease,
                   NML3ConfigData    *l3cd,
                   in_addr_t          lease_address,
                   GHashTable        *options,
                   NMStrBuf          *sbuf)
{
    char          dest_str[NM_INET_ADDRSTRLEN];
    char          gateway_str[NM_INET_ADDRSTRLEN];
    in_addr_t     dest;
    in_addr_t     gateway;
    uint8_t       plen;
    guint32       m;
    gboolean      has_router_from_classless   = FALSE;
    gboolean      has_classless               = FALSE;
    guint32       default_route_metric_offset = 0;
    const guint8 *l_data;
    gsize         l_data_len;
    int           r;
    guint         i;

    /* Routes can be in option 33 (static-route), 121 (classless-static-route) and 249 (a non-standard classless-static-route).
     * Option 249 (Microsoft Classless Static Route), is described here:
     * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpe/f9c19c79-1c7f-4746-b555-0c0fc523f3f9
     *
     * We will anyway parse all these 3 options and add them to the "options" hash (as distinct entries).
     * We will however also parse one of the options into the "l3cd" for configuring routing.
     * Thereby we prefer 121 over 249 over 33.
     *
     * Preferring 121 over 33 is defined by RFC 3443.
     * Preferring 121 over 249 over 33 is made up as it makes sense (the MS docs are not very clear).
     */
    for (i = 0; i < 2; i++) {
        const guint8 option_code = (i == 0) ? NM_DHCP_OPTION_DHCP4_CLASSLESS_STATIC_ROUTE
                                            : NM_DHCP_OPTION_DHCP4_PRIVATE_CLASSLESS_STATIC_ROUTE;

        if (_client_lease_query(lease, option_code, &l_data, &l_data_len) != 0)
            continue;

        nm_str_buf_reset(sbuf);
        while (lease_option_consume_route(&l_data, &l_data_len, TRUE, &dest, &plen, &gateway)) {
            nm_inet4_ntop(dest, dest_str);
            nm_inet4_ntop(gateway, gateway_str);

            nm_str_buf_append_required_delimiter(sbuf, ' ');
            nm_str_buf_append_printf(sbuf, "%s/%d %s", dest_str, (int) plen, gateway_str);

            if (has_classless) {
                /* Ignore private option if the standard one is present */
                continue;
            }

            if (plen == 0) {
                /* if there are multiple default routes, we add them with differing
                 * metrics. */
                m                         = default_route_metric_offset++;
                has_router_from_classless = TRUE;
            } else
                m = 0;

            nm_l3_config_data_add_route_4(l3cd,
                                          &((const NMPlatformIP4Route){
                                              .rt_source     = NM_IP_CONFIG_SOURCE_DHCP,
                                              .network       = dest,
                                              .plen          = plen,
                                              .gateway       = gateway,
                                              .pref_src      = lease_address,
                                              .table_any     = TRUE,
                                              .table_coerced = 0,
                                              .metric_any    = TRUE,
                                              .metric        = m,
                                          }));
        }

        has_classless = TRUE;
        _add_option(options, option_code, nm_str_buf_get_str(sbuf));
    }

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_STATIC_ROUTE, &l_data, &l_data_len);
    if (r == 0) {
        nm_str_buf_reset(sbuf);

        while (lease_option_consume_route(&l_data, &l_data_len, FALSE, &dest, &plen, &gateway)) {
            nm_inet4_ntop(dest, dest_str);
            nm_inet4_ntop(gateway, gateway_str);

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

            nm_l3_config_data_add_route_4(l3cd,
                                          &((const NMPlatformIP4Route){
                                              .rt_source     = NM_IP_CONFIG_SOURCE_DHCP,
                                              .network       = dest,
                                              .plen          = plen,
                                              .gateway       = gateway,
                                              .pref_src      = lease_address,
                                              .table_any     = TRUE,
                                              .table_coerced = 0,
                                              .metric_any    = TRUE,
                                              .metric        = 0,
                                          }));
        }

        _add_option(options, NM_DHCP_OPTION_DHCP4_STATIC_ROUTE, nm_str_buf_get_str(sbuf));
    }

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_ROUTER, &l_data, &l_data_len);
    if (r == 0) {
        nm_str_buf_reset(sbuf);

        while (nm_dhcp_lease_data_consume_in_addr(&l_data, &l_data_len, &gateway)) {
            nm_str_buf_append_required_delimiter(sbuf, ' ');
            nm_str_buf_append(sbuf, nm_inet4_ntop(gateway, gateway_str));

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
            m = default_route_metric_offset++;

            nm_l3_config_data_add_route_4(l3cd,
                                          &((const NMPlatformIP4Route){
                                              .rt_source     = NM_IP_CONFIG_SOURCE_DHCP,
                                              .gateway       = gateway,
                                              .pref_src      = lease_address,
                                              .table_any     = TRUE,
                                              .table_coerced = 0,
                                              .metric_any    = TRUE,
                                              .metric        = m,
                                          }));
        }

        _add_option(options, NM_DHCP_OPTION_DHCP4_ROUTER, nm_str_buf_get_str(sbuf));
    }
}

static void
lease_parse_search_domains(NDhcp4ClientLease *lease,
                           NML3ConfigData    *l3cd,
                           const char        *iface,
                           GHashTable        *options)
{
    gs_strfreev char **domains = NULL;
    const guint8      *l_data;
    gsize              l_data_len;
    guint              i;
    int                r;

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_DOMAIN_SEARCH_LIST, &l_data, &l_data_len);
    if (r != 0)
        return;

    domains = nm_dhcp_lease_data_parse_search_list(l_data,
                                                   l_data_len,
                                                   iface,
                                                   AF_INET,
                                                   NM_DHCP_OPTION_DHCP4_DOMAIN_SEARCH_LIST);

    if (!domains || !domains[0])
        return;

    for (i = 0; domains[i]; i++)
        nm_l3_config_data_add_search(l3cd, AF_INET, domains[i]);

    nm_dhcp_option_take_option(options,
                               TRUE,
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
        nm_dhcp_option_take_option(options, TRUE, AF_INET, i, g_steal_pointer(&option_string));
    }
}

static NML3ConfigData *
lease_to_ip4_config(NMDhcpNettools *self, NDhcp4ClientLease *lease, GError **error)
{
    const char                             *iface;
    nm_auto_str_buf NMStrBuf                sbuf    = NM_STR_BUF_INIT(0, FALSE);
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd    = NULL;
    gs_unref_hashtable GHashTable          *options = NULL;
    const guint8                           *l_data;
    gsize                                   l_data_len;
    const char                             *v_str;
    guint16                                 v_u16;
    in_addr_t                               v_inaddr;
    in_addr_t                               lease_address;
    struct in_addr                          v_inaddr_s;
    int                                     r;

    nm_assert(lease);

    iface = nm_dhcp_client_get_iface(NM_DHCP_CLIENT(self));

    l3cd = nm_dhcp_client_create_l3cd(NM_DHCP_CLIENT(self));

    options = nm_dhcp_client_create_options_dict(NM_DHCP_CLIENT(self), TRUE);

    if (!lease_parse_address(self, lease, l3cd, iface, options, &lease_address, error))
        return NULL;

    r = n_dhcp4_client_lease_get_server_identifier(lease, &v_inaddr_s);
    if (r == 0) {
        nm_dhcp_option_add_option_in_addr(options,
                                          TRUE,
                                          AF_INET,
                                          NM_DHCP_OPTION_DHCP4_SERVER_ID,
                                          v_inaddr_s.s_addr);
    }

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_BROADCAST, &l_data, &l_data_len);
    if (r == 0
        && nm_dhcp_lease_data_parse_in_addr(l_data,
                                            l_data_len,
                                            &v_inaddr,
                                            iface,
                                            NM_DHCP_OPTION_DHCP4_BROADCAST)) {
        nm_dhcp_option_add_option_in_addr(options,
                                          TRUE,
                                          AF_INET,
                                          NM_DHCP_OPTION_DHCP4_BROADCAST,
                                          v_inaddr);
    }

    lease_parse_routes(lease, l3cd, lease_address, options, &sbuf);

    lease_parse_address_list(lease,
                             l3cd,
                             iface,
                             NM_DHCP_OPTION_DHCP4_DOMAIN_NAME_SERVER,
                             options,
                             &sbuf);

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_DOMAIN_NAME, &l_data, &l_data_len);
    if (r == 0
        && nm_dhcp_lease_data_parse_cstr(l_data,
                                         l_data_len,
                                         &l_data_len,
                                         iface,
                                         AF_INET,
                                         NM_DHCP_OPTION_DHCP4_DOMAIN_NAME)) {
        gs_free const char **domains = NULL;

        nm_str_buf_reset(&sbuf);
        nm_str_buf_append_len0(&sbuf, (const char *) l_data, l_data_len);

        /* Multiple domains sometimes stuffed into option 15 "Domain Name". */
        domains = nm_strsplit_set(nm_str_buf_get_str(&sbuf), " ");

        nm_str_buf_reset(&sbuf);
        if (domains) {
            gsize i;

            for (i = 0; domains[i]; i++) {
                gs_free char *s = NULL;

                s = nm_dhcp_lease_data_parse_domain_validate(domains[i],
                                                             iface,
                                                             AF_INET,
                                                             NM_DHCP_OPTION_DHCP4_DOMAIN_NAME);
                if (!s)
                    continue;

                nm_str_buf_append_required_delimiter(&sbuf, ' ');
                nm_str_buf_append(&sbuf, s);
                nm_l3_config_data_add_domain(l3cd, AF_INET, s);
            }
        }

        if (sbuf.len > 0) {
            _add_option(options, NM_DHCP_OPTION_DHCP4_DOMAIN_NAME, nm_str_buf_get_str(&sbuf));
        }
    }

    lease_parse_search_domains(lease, l3cd, iface, options);

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_INTERFACE_MTU, &l_data, &l_data_len);
    if (r == 0
        && nm_dhcp_lease_data_parse_mtu(l_data,
                                        l_data_len,
                                        &v_u16,
                                        iface,
                                        AF_INET,
                                        NM_DHCP_OPTION_DHCP4_INTERFACE_MTU)) {
        nm_dhcp_option_add_option_u64(options,
                                      TRUE,
                                      AF_INET,
                                      NM_DHCP_OPTION_DHCP4_INTERFACE_MTU,
                                      v_u16);
        nm_l3_config_data_set_mtu(l3cd, v_u16);
    }

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_VENDOR_SPECIFIC, &l_data, &l_data_len);
    if ((r == 0) && memmem(l_data, l_data_len, "ANDROID_METERED", NM_STRLEN("ANDROID_METERED")))
        nm_l3_config_data_set_metered(l3cd, TRUE);

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_HOST_NAME, &l_data, &l_data_len);
    if (r == 0) {
        gs_free char *s = NULL;

        if (nm_dhcp_lease_data_parse_domain(l_data,
                                            l_data_len,
                                            &s,
                                            iface,
                                            AF_INET,
                                            NM_DHCP_OPTION_DHCP4_HOST_NAME)) {
            _add_option(options, NM_DHCP_OPTION_DHCP4_HOST_NAME, s);
        }
    }

    lease_parse_address_list(lease, l3cd, iface, NM_DHCP_OPTION_DHCP4_NTP_SERVER, options, &sbuf);

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_ROOT_PATH, &l_data, &l_data_len);
    if (r == 0
        && nm_dhcp_lease_data_parse_cstr(l_data,
                                         l_data_len,
                                         &l_data_len,
                                         iface,
                                         AF_INET,
                                         NM_DHCP_OPTION_DHCP4_ROOT_PATH)) {
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
                                                      TRUE,
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
    if (r == 0
        && nm_dhcp_lease_data_parse_cstr(l_data,
                                         l_data_len,
                                         &l_data_len,
                                         iface,
                                         AF_INET,
                                         NM_DHCP_OPTION_DHCP4_PRIVATE_PROXY_AUTODISCOVERY)) {
        /* https://tools.ietf.org/html/draft-ietf-wrec-wpad-01#section-4.4.1
         *
         * We reject NUL characters inside the string (except trailing NULs).
         * Otherwise, we allow any encoding and backslash-escape the result to
         * UTF-8. */
        gs_free char *to_free = NULL;
        const char   *escaped;

        escaped = nm_utils_buf_utf8safe_escape((char *) l_data, l_data_len, 0, &to_free);
        _add_option(options, NM_DHCP_OPTION_DHCP4_PRIVATE_PROXY_AUTODISCOVERY, escaped ?: "");

        nm_l3_config_data_set_proxy_method(l3cd, NM_PROXY_CONFIG_METHOD_AUTO);
        nm_l3_config_data_set_proxy_pac_url(l3cd, escaped ?: "");
    }

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_NIS_DOMAIN, &l_data, &l_data_len);
    if (r == 0
        && nm_dhcp_lease_data_parse_cstr(l_data,
                                         l_data_len,
                                         &l_data_len,
                                         iface,
                                         AF_INET,
                                         NM_DHCP_OPTION_DHCP4_NIS_DOMAIN)) {
        gs_free char *to_free = NULL;

        /* https://tools.ietf.org/html/rfc2132#section-8.1 */

        v_str = nm_utils_buf_utf8safe_escape((char *) l_data,
                                             l_data_len,
                                             NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL,
                                             &to_free);

        _add_option(options, NM_DHCP_OPTION_DHCP4_NIS_DOMAIN, v_str ?: "");
        nm_l3_config_data_set_nis_domain(l3cd, v_str ?: "");
    }

    r = n_dhcp4_client_lease_get_file(lease, &v_str);
    if (r == 0) {
        gs_free char *to_free = NULL;

        v_str = nm_utils_buf_utf8safe_escape(v_str,
                                             -1,
                                             NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL,
                                             &to_free);
        _add_option(options, NM_DHCP_OPTION_DHCP4_NM_FILENAME, v_str ?: "");
    }

    r = _client_lease_query(lease, NM_DHCP_OPTION_DHCP4_BOOTFILE_NAME, &l_data, &l_data_len);
    if (r == 0
        && nm_dhcp_lease_data_parse_cstr(l_data,
                                         l_data_len,
                                         &l_data_len,
                                         iface,
                                         AF_INET,
                                         NM_DHCP_OPTION_DHCP4_BOOTFILE_NAME)) {
        gs_free char *to_free = NULL;

        v_str = nm_utils_buf_utf8safe_escape((char *) l_data,
                                             l_data_len,
                                             NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL,
                                             &to_free);
        _add_option(options, NM_DHCP_OPTION_DHCP4_BOOTFILE_NAME, v_str ?: "");
    }

    lease_parse_address_list(lease, l3cd, iface, NM_DHCP_OPTION_DHCP4_NIS_SERVERS, options, &sbuf);

    lease_parse_address_list(lease,
                             l3cd,
                             iface,
                             NM_DHCP_OPTION_DHCP4_NETBIOS_NAMESERVER,
                             options,
                             &sbuf);

    lease_parse_private_options(lease, options);

    nm_dhcp_option_add_requests_to_options(options, AF_INET);

    nm_l3_config_data_set_dhcp_lease_from_options(l3cd, AF_INET, g_steal_pointer(&options));

    return g_steal_pointer(&l3cd);
}

/*****************************************************************************/

static void
lease_save(NMDhcpNettools *self, NDhcp4ClientLease *lease, const char *lease_file)
{
    struct in_addr           a_address;
    nm_auto_str_buf NMStrBuf sbuf = NM_STR_BUF_INIT(NM_UTILS_GET_NEXT_REALLOC_SIZE_104, FALSE);
    char                     addr_str[NM_INET_ADDRSTRLEN];
    gs_free_error GError    *error = NULL;

    nm_assert(lease);
    nm_assert(lease_file);

    n_dhcp4_client_lease_get_yiaddr(lease, &a_address);
    if (a_address.s_addr == INADDR_ANY)
        return;

    nm_str_buf_append(&sbuf, "# This is private data. Do not parse.\n");
    nm_str_buf_append_printf(&sbuf, "ADDRESS=%s\n", nm_inet4_ntop(a_address.s_addr, addr_str));

    if (!g_file_set_contents(lease_file, nm_str_buf_get_str_unsafe(&sbuf), sbuf.len, &error))
        _LOGW("error saving lease to %s: %s", lease_file, error->message);
}

static void
bound4_handle(NMDhcpNettools *self, guint event, NDhcp4ClientLease *lease)
{
    NMDhcpNettoolsPrivate                  *priv  = NM_DHCP_NETTOOLS_GET_PRIVATE(self);
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd  = NULL;
    gs_free_error GError                   *error = NULL;

    nm_assert(NM_IN_SET(event, N_DHCP4_CLIENT_EVENT_GRANTED, N_DHCP4_CLIENT_EVENT_EXTENDED));
    nm_assert(lease);

    _LOGT("lease available (%s)", (event == N_DHCP4_CLIENT_EVENT_GRANTED) ? "granted" : "extended");

    l3cd = lease_to_ip4_config(self, lease, &error);
    if (!l3cd) {
        _LOGW("failure to parse lease: %s", error->message);

        if (event == N_DHCP4_CLIENT_EVENT_GRANTED) {
            n_dhcp4_client_lease_decline(lease, "invalid lease");
            dhcp4_event_pop_all_events_on_idle(self);
        }

        _nm_dhcp_client_notify(NM_DHCP_CLIENT(self), NM_DHCP_CLIENT_EVENT_TYPE_FAIL, NULL);
        return;
    }

    if (event == N_DHCP4_CLIENT_EVENT_GRANTED) {
        priv->granted.lease      = n_dhcp4_client_lease_ref(lease);
        priv->granted.lease_l3cd = nm_l3_config_data_ref(l3cd);
    } else
        lease_save(self, lease, priv->lease_file);

    _nm_dhcp_client_notify(NM_DHCP_CLIENT(self),
                           event == N_DHCP4_CLIENT_EVENT_GRANTED
                               ? NM_DHCP_CLIENT_EVENT_TYPE_BOUND
                               : NM_DHCP_CLIENT_EVENT_TYPE_EXTENDED,
                           l3cd);
}

static void
dhcp4_event_handle(NMDhcpNettools *self, NDhcp4ClientEvent *event)
{
    NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE(self);
    struct in_addr         server_id;
    struct in_addr         yiaddr;
    char                   addr_str[INET_ADDRSTRLEN];
    char                   addr_str2[INET_ADDRSTRLEN];
    int                    r;

    if (event->event == N_DHCP4_CLIENT_EVENT_LOG) {
        _NMLOG(nm_log_level_from_syslog(event->log.level), "event: %s", event->log.message);
        return;
    }

    if (!NM_IN_SET(event->event, N_DHCP4_CLIENT_EVENT_LOG)) {
        /* In almost all events (even those that we don't expect below), we clear
         * the currently granted lease. That is, because in GRANTED state we
         * expect to follow up with accept/decline, and that only works while
         * we are still in the same state. Transitioning away to another state
         * (on most events) will invalidate that. */
        nm_clear_pointer(&priv->granted.lease, n_dhcp4_client_lease_unref);
        nm_clear_l3cd(&priv->granted.lease_l3cd);
    }

    switch (event->event) {
    case N_DHCP4_CLIENT_EVENT_OFFER:
        r = n_dhcp4_client_lease_get_server_identifier(event->offer.lease, &server_id);
        if (r) {
            _LOGW("selecting lease failed: could not get DHCP server identifier (%d)", r);
            return;
        }

        n_dhcp4_client_lease_get_yiaddr(event->offer.lease, &yiaddr);
        if (yiaddr.s_addr == INADDR_ANY) {
            _LOGD("selecting lease failed: no yiaddr address");
            return;
        }

        if (nm_dhcp_client_server_id_is_rejected(NM_DHCP_CLIENT(self), &server_id)) {
            _LOGD("server-id %s is in the reject-list, ignoring",
                  nm_inet_ntop(AF_INET, &server_id, addr_str));
            return;
        }

        if (!_nm_dhcp_client_accept_offer(NM_DHCP_CLIENT(self), &yiaddr.s_addr)) {
            /* We don't log about this, the parent class is expected to notify about the reasons. */
            return;
        }

        _LOGT("selecting offered lease from %s for %s",
              nm_inet4_ntop(server_id.s_addr, addr_str),
              nm_inet4_ntop(yiaddr.s_addr, addr_str2));

        r = n_dhcp4_client_lease_select(event->offer.lease);

        dhcp4_event_pop_all_events_on_idle(self);

        if (r) {
            _LOGW("selecting lease failed: %d", r);
            return;
        }

        return;
    case N_DHCP4_CLIENT_EVENT_RETRACTED:
    case N_DHCP4_CLIENT_EVENT_EXPIRED:
        _nm_dhcp_client_notify(NM_DHCP_CLIENT(self), NM_DHCP_CLIENT_EVENT_TYPE_EXPIRE, NULL);
        return;
    case N_DHCP4_CLIENT_EVENT_CANCELLED:
        _nm_dhcp_client_notify(NM_DHCP_CLIENT(self), NM_DHCP_CLIENT_EVENT_TYPE_FAIL, NULL);
        return;
    case N_DHCP4_CLIENT_EVENT_GRANTED:
        bound4_handle(self, event->event, event->granted.lease);
        return;
    case N_DHCP4_CLIENT_EVENT_EXTENDED:
        bound4_handle(self, event->event, event->extended.lease);
        return;
    case N_DHCP4_CLIENT_EVENT_DOWN:
        /* ignore down events, they are purely informational */
        _LOGT("event: down (ignore)");
        return;
    default:
        _LOGE("unhandled DHCP event %d", event->event);
        nm_assert(event->event != N_DHCP4_CLIENT_EVENT_LOG);
        nm_assert_not_reached();
        return;
    }
}

static void
dhcp4_event_pop_all_events(NMDhcpNettools *self)
{
    NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE(self);
    NDhcp4ClientEvent     *event;

    while (!n_dhcp4_client_pop_event(priv->client, &event) && event)
        dhcp4_event_handle(self, event);

    nm_clear_g_source_inst(&priv->pop_all_events_on_idle_source);
}

static gboolean
dhcp4_event_pop_all_events_on_idle_cb(gpointer user_data)
{
    NMDhcpNettools        *self = user_data;
    NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->pop_all_events_on_idle_source);
    dhcp4_event_pop_all_events(self);
    return G_SOURCE_CONTINUE;
}

static void
dhcp4_event_pop_all_events_on_idle(NMDhcpNettools *self)
{
    NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE(self);

    /* For the most part, NDhcp4Client gets driven from internal, that is
     * by having events ready on the socket or the timerfd. For those
     * events, we will poll on the (epoll) FD, then let it be processed
     * by n_dhcp4_client_dispatch(), and pop the queued events.
     *
     * But certain commands (n_dhcp4_client_lease_select(), n_dhcp4_client_lease_accept(),
     * n_dhcp4_client_lease_decline()) are initiated by the user. And they tend
     * to log events. Logging is done by queuing a message, but that won't be processed,
     * unless we pop the event.
     *
     * To ensure that those logging events get popped, schedule an idle handler to do that.
     *
     * Yes, this means, that the messages only get logged later, when the idle handler
     * runs. The alternative seems even more problematic, because we don't know
     * the current call-state, and it seems dangerous to pop unexpected events.
     * E.g. we call n_dhcp4_client_lease_select() from inside the event-handler,
     * it seems wrong to call dhcp4_event_pop_all_events() in that context again.
     *
     * See-also: https://github.com/nettools/n-dhcp4/issues/34
     */

    if (!priv->pop_all_events_on_idle_source) {
        priv->pop_all_events_on_idle_source =
            nm_g_idle_add_source(dhcp4_event_pop_all_events_on_idle_cb, self);
    }
}

static gboolean
dhcp4_event_cb(int fd, GIOCondition condition, gpointer user_data)
{
    NMDhcpNettools        *self = user_data;
    NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE(self);
    int                    r;

    r = n_dhcp4_client_dispatch(priv->client);
    if (r < 0) {
        /* If any operation (e.g. send()) fails during the
         * dispatch, n-dhcp4 returns an error without arming timers
         * or progressing state, so the only reasonable thing to do
         * is to move to failed state so that the client will be
         * restarted.
         *
         * That means, n_dhcp4_client_dispatch() must not fail if it can
         * somehow workaround the problem. A failure is really fatal
         * and the client needs to be restarted.
         */
        _LOGE("error %d dispatching events", r);
        nm_clear_g_source_inst(&priv->event_source);
        _nm_dhcp_client_notify(NM_DHCP_CLIENT(self), NM_DHCP_CLIENT_EVENT_TYPE_FAIL, NULL);
        return G_SOURCE_REMOVE;
    }

    dhcp4_event_pop_all_events(self);

    return G_SOURCE_CONTINUE;
}

static gboolean
nettools_create(NMDhcpNettools *self, GBytes **out_effective_client_id, GError **error)
{
    NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE(self);
    nm_auto(n_dhcp4_client_config_freep) NDhcp4ClientConfig *config = NULL;
    nm_auto(n_dhcp4_client_unrefp) NDhcp4Client             *client = NULL;
    GBytes                                                  *hwaddr;
    GBytes                                                  *bcast_hwaddr;
    const uint8_t                                           *hwaddr_arr;
    const uint8_t                                           *bcast_hwaddr_arr;
    gsize                                                    hwaddr_len;
    gsize                                                    bcast_hwaddr_len;
    GBytes                                                  *client_id;
    gs_unref_bytes GBytes                                   *client_id_new = NULL;
    const uint8_t                                           *client_id_arr;
    size_t                                                   client_id_len;
    int                                                      r, fd, arp_type, transport;
    const NMDhcpClientConfig                                *client_config;

    client_config = nm_dhcp_client_get_config(NM_DHCP_CLIENT(self));

    g_return_val_if_fail(!priv->client, FALSE);

    /* TODO: honor nm_dhcp_client_get_anycast_address() */

    hwaddr = client_config->hwaddr;
    if (!hwaddr || !(hwaddr_arr = g_bytes_get_data(hwaddr, &hwaddr_len))
        || (arp_type = nm_utils_arp_type_detect_from_hwaddrlen(hwaddr_len)) < 0) {
        nm_utils_error_set_literal(error, NM_UTILS_ERROR_UNKNOWN, "invalid MAC address");
        return FALSE;
    }

    bcast_hwaddr     = client_config->bcast_hwaddr;
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
    client_id = client_config->client_id;
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
    n_dhcp4_client_config_set_request_broadcast(config, client_config->v4.request_broadcast);
    r = n_dhcp4_client_config_set_client_id(config,
                                            client_id_arr,
                                            NM_MIN(client_id_len, 1 + _NM_MAX_CLIENT_ID_LEN));
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

    priv->event_source = nm_g_unix_fd_add_source(fd, G_IO_IN, dhcp4_event_cb, self);

    *out_effective_client_id =
        (client_id == client_id_new) ? g_steal_pointer(&client_id_new) : g_bytes_ref(client_id);

    return TRUE;
}

static gboolean
_accept(NMDhcpClient *client, const NML3ConfigData *l3cd, GError **error)
{
    NMDhcpNettools        *self = NM_DHCP_NETTOOLS(client);
    NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE(self);
    int                    r;

    _LOGT("accept");

    g_return_val_if_fail(l3cd, FALSE);

    if (priv->granted.lease_l3cd != l3cd)
        return TRUE;

    nm_assert(priv->granted.lease);

    r = n_dhcp4_client_lease_accept(priv->granted.lease);
    if (!r)
        lease_save(self, priv->granted.lease, priv->lease_file);

    dhcp4_event_pop_all_events_on_idle(self);

    nm_clear_pointer(&priv->granted.lease, n_dhcp4_client_lease_unref);
    nm_clear_l3cd(&priv->granted.lease_l3cd);

    if (r) {
        set_error_nettools(error, r, "failed to accept lease");
        return FALSE;
    }

    return TRUE;
}

static gboolean
decline(NMDhcpClient *client, const NML3ConfigData *l3cd, const char *error_message, GError **error)
{
    NMDhcpNettools        *self = NM_DHCP_NETTOOLS(client);
    NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE(self);
    int                    r;
    nm_auto(n_dhcp4_client_lease_unrefp) NDhcp4ClientLease *lease = NULL;

    _LOGT("decline (%s)", error_message);

    g_return_val_if_fail(l3cd, FALSE);

    if (priv->granted.lease_l3cd != l3cd) {
        nm_utils_error_set(error, NM_UTILS_ERROR_UNKNOWN, "calling decline in unexpected state");
        return FALSE;
    }

    nm_assert(priv->granted.lease);

    lease = g_steal_pointer(&priv->granted.lease);
    nm_clear_l3cd(&priv->granted.lease_l3cd);

    r = n_dhcp4_client_lease_decline(lease, error_message);

    dhcp4_event_pop_all_events_on_idle(self);

    if (r) {
        set_error_nettools(error, r, "failed to decline lease");
        return FALSE;
    }

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
ip4_start(NMDhcpClient *client, GError **error)
{
    nm_auto(n_dhcp4_client_probe_config_freep) NDhcp4ClientProbeConfig *config = NULL;
    NMDhcpNettools           *self                = NM_DHCP_NETTOOLS(client);
    NMDhcpNettoolsPrivate    *priv                = NM_DHCP_NETTOOLS_GET_PRIVATE(self);
    gs_unref_bytes GBytes    *effective_client_id = NULL;
    const NMDhcpClientConfig *client_config;
    gs_free char             *lease_file = NULL;
    struct in_addr            last_addr  = {0};
    int                       r, i;

    client_config = nm_dhcp_client_get_config(client);

    g_return_val_if_fail(!priv->probe, FALSE);
    g_return_val_if_fail(client_config, FALSE);

    if (!nettools_create(self, &effective_client_id, error))
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
                                     client_config->iface,
                                     client_config->uuid,
                                     &lease_file);

    if (client_config->v4.last_address)
        inet_pton(AF_INET, client_config->v4.last_address, &last_addr);
    else {
        gs_free char *contents = NULL;
        gs_free char *s_addr   = NULL;

        nm_utils_file_get_contents(-1,
                                   lease_file,
                                   64 * 1024,
                                   NM_UTILS_FILE_GET_CONTENTS_FLAG_NONE,
                                   &contents,
                                   NULL,
                                   NULL,
                                   NULL);
        nm_parse_env_file(contents, "ADDRESS", &s_addr);
        if (s_addr)
            nm_inet_parse_bin(AF_INET, s_addr, NULL, &last_addr);
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

    if (client_config->mud_url) {
        r = n_dhcp4_client_probe_config_append_option(config,
                                                      NM_DHCP_OPTION_DHCP4_MUD_URL,
                                                      client_config->mud_url,
                                                      strlen(client_config->mud_url));
        if (r) {
            set_error_nettools(error, r, "failed to set MUD URL");
            return FALSE;
        }
    }

    if (client_config->hostname) {
        if (client_config->use_fqdn) {
            uint8_t             buffer[255];
            NMDhcpHostnameFlags flags;
            size_t              fqdn_len;

            flags     = client_config->hostname_flags;
            buffer[0] = fqdn_flags_to_wire(flags);
            buffer[1] = 0; /* RCODE1 (deprecated) */
            buffer[2] = 0; /* RCODE2 (deprecated) */

            if (flags & NM_DHCP_HOSTNAME_FLAG_FQDN_ENCODED) {
                r = nm_sd_dns_name_to_wire_format(client_config->hostname,
                                                  buffer + 3,
                                                  sizeof(buffer) - 3,
                                                  FALSE);
                if (r <= 0) {
                    if (r < 0)
                        nm_utils_error_set_errno(error, r, "failed to convert DHCP FQDN: %s");
                    else
                        nm_utils_error_set(error, r, "failed to convert DHCP FQDN");
                    return FALSE;
                }
                fqdn_len = r;
            } else {
                fqdn_len = strlen(client_config->hostname);
                if (fqdn_len > sizeof(buffer) - 3) {
                    nm_utils_error_set(error, r, "failed to set DHCP FQDN: name too long");
                    return FALSE;
                }
                memcpy(buffer + 3, client_config->hostname, fqdn_len);
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
                                                          client_config->hostname,
                                                          strlen(client_config->hostname));
            if (r) {
                set_error_nettools(error, r, "failed to set DHCP hostname");
                return FALSE;
            }
        }
    }

    if (client_config->vendor_class_identifier) {
        const void *option_data;
        gsize       option_size;

        option_data = g_bytes_get_data(client_config->vendor_class_identifier, &option_size);
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

    _LOGT("dhcp-client4: start " NM_HASH_OBFUSCATE_PTR_FMT, NM_HASH_OBFUSCATE_PTR(priv->client));

    nm_dhcp_client_set_effective_client_id(client, effective_client_id);

    return TRUE;
}

static void
stop(NMDhcpClient *client, gboolean release)
{
    NMDhcpNettools        *self = NM_DHCP_NETTOOLS(client);
    NMDhcpNettoolsPrivate *priv = NM_DHCP_NETTOOLS_GET_PRIVATE(self);

    NM_DHCP_CLIENT_CLASS(nm_dhcp_nettools_parent_class)->stop(client, release);

    _LOGT("dhcp-client4: stop " NM_HASH_OBFUSCATE_PTR_FMT, NM_HASH_OBFUSCATE_PTR(priv->client));

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
    nm_clear_g_source_inst(&priv->pop_all_events_on_idle_source);
    nm_clear_pointer(&priv->granted.lease, n_dhcp4_client_lease_unref);
    nm_clear_l3cd(&priv->granted.lease_l3cd);
    nm_clear_pointer(&priv->probe, n_dhcp4_client_probe_free);
    nm_clear_pointer(&priv->client, n_dhcp4_client_unref);

    G_OBJECT_CLASS(nm_dhcp_nettools_parent_class)->dispose(object);
}

static void
nm_dhcp_nettools_class_init(NMDhcpNettoolsClass *class)
{
    NMDhcpClientClass *client_class = NM_DHCP_CLIENT_CLASS(class);
    GObjectClass      *object_class = G_OBJECT_CLASS(class);

    object_class->dispose = dispose;

    client_class->ip4_start = ip4_start;
    client_class->accept    = _accept;
    client_class->decline   = decline;
    client_class->stop      = stop;
}

const NMDhcpClientFactory _nm_dhcp_client_factory_nettools = {
    .name         = "nettools",
    .get_type_4   = nm_dhcp_nettools_get_type,
    .undocumented = TRUE,
};
