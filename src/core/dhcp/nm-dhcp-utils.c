/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include <unistd.h>
#include <arpa/inet.h>

#include "libnm-std-aux/unaligned.h"
#include "libnm-glib-aux/nm-dedup-multi.h"
#include "libnm-glib-aux/nm-str-buf.h"
#include "libnm-systemd-shared/nm-sd-utils-shared.h"

#include "nm-dhcp-utils.h"
#include "nm-dhcp-options.h"
#include "nm-l3-config-data.h"
#include "nm-utils.h"
#include "nm-config.h"
#include "NetworkManagerUtils.h"
#include "libnm-platform/nm-platform.h"
#include "nm-dhcp-client-logging.h"
#include "libnm-core-intern/nm-core-internal.h"

/*****************************************************************************/

static gboolean
ip4_process_dhcpcd_rfc3442_routes(const char     *iface,
                                  const char     *str,
                                  NML3ConfigData *l3cd,
                                  in_addr_t       address,
                                  guint32        *out_gwaddr)
{
    gs_free const char **routes = NULL;
    const char         **r;
    gboolean             have_routes = FALSE;

    routes = nm_strsplit_set(str, " ");
    if (!routes)
        return FALSE;

    if ((NM_PTRARRAY_LEN(routes) % 2) != 0) {
        _LOG2W(LOGD_DHCP4, iface, "  classless static routes provided, but invalid");
        return FALSE;
    }

    for (r = routes; *r; r += 2) {
        char   *slash;
        int     rt_cidr = 32;
        guint32 rt_addr, rt_route;

        slash = strchr(*r, '/');
        if (slash) {
            *slash  = '\0';
            errno   = 0;
            rt_cidr = strtol(slash + 1, NULL, 10);
            if (errno || rt_cidr > 32) {
                _LOG2W(LOGD_DHCP4,
                       iface,
                       "DHCP provided invalid classless static route cidr: '%s'",
                       slash + 1);
                continue;
            }
        }
        if (inet_pton(AF_INET, *r, &rt_addr) <= 0) {
            _LOG2W(LOGD_DHCP4,
                   iface,
                   "DHCP provided invalid classless static route address: '%s'",
                   *r);
            continue;
        }
        if (inet_pton(AF_INET, *(r + 1), &rt_route) <= 0) {
            _LOG2W(LOGD_DHCP4,
                   iface,
                   "DHCP provided invalid classless static route gateway: '%s'",
                   *(r + 1));
            continue;
        }

        have_routes = TRUE;
        if (rt_cidr == 0 && rt_addr == 0) {
            /* FIXME: how to handle multiple routers? */
            *out_gwaddr = rt_route;
        } else {
            _LOG2I(LOGD_DHCP4,
                   iface,
                   "  classless static route %s/%d gw %s",
                   *r,
                   rt_cidr,
                   *(r + 1));

            nm_l3_config_data_add_route_4(
                l3cd,
                &((const NMPlatformIP4Route){
                    .rt_source  = NM_IP_CONFIG_SOURCE_DHCP,
                    .network    = nm_ip4_addr_clear_host_address(rt_addr, rt_cidr),
                    .plen       = rt_cidr,
                    .gateway    = rt_route,
                    .pref_src   = address,
                    .metric_any = TRUE,
                    .table_any  = TRUE,
                }));
        }
    }

    return have_routes;
}

static gboolean
process_dhclient_rfc3442_route(const char *const **p_octets, NMPlatformIP4Route *route)
{
    const char *const *o        = *p_octets;
    gs_free char      *next_hop = NULL;
    int                addr_len;
    int                v_plen;
    in_addr_t          tmp_addr;
    in_addr_t          v_network = 0;

    v_plen = _nm_utils_ascii_str_to_int64(*o, 10, 0, 32, -1);
    if (v_plen == -1)
        return FALSE;
    o++;

    addr_len = v_plen > 0 ? ((v_plen - 1) / 8) + 1 : 0;

    /* ensure there's at least the address + next hop left */
    if (NM_PTRARRAY_LEN(o) < addr_len + 4)
        return FALSE;

    if (v_plen > 0) {
        const char   *addr[4]  = {"0", "0", "0", "0"};
        gs_free char *str_addr = NULL;
        int           i;

        for (i = 0; i < addr_len; i++)
            addr[i] = *o++;

        str_addr = g_strjoin(".", addr[0], addr[1], addr[2], addr[3], NULL);
        if (inet_pton(AF_INET, str_addr, &tmp_addr) <= 0)
            return FALSE;
        v_network = nm_ip4_addr_clear_host_address(tmp_addr, v_plen);
    }

    next_hop = g_strjoin(".", o[0], o[1], o[2], o[3], NULL);
    o += 4;
    if (inet_pton(AF_INET, next_hop, &tmp_addr) <= 0)
        return FALSE;

    *route = (NMPlatformIP4Route){
        .network = v_network,
        .plen    = v_plen,
        .gateway = tmp_addr,
    };
    *p_octets = o;
    return TRUE;
}

static gboolean
ip4_process_dhclient_rfc3442_routes(const char     *iface,
                                    const char     *str,
                                    NML3ConfigData *l3cd,
                                    in_addr_t       address,
                                    guint32        *out_gwaddr)
{
    gs_free const char **octets = NULL;
    const char *const   *o;
    gboolean             have_routes = FALSE;

    octets = nm_strsplit_set_with_empty(str, " .");
    if (NM_PTRARRAY_LEN(octets) < 5) {
        _LOG2W(LOGD_DHCP4, iface, "ignoring invalid classless static routes '%s'", str);
        return FALSE;
    }

    o = octets;
    while (*o) {
        NMPlatformIP4Route route;

        if (!process_dhclient_rfc3442_route(&o, &route)) {
            _LOG2W(LOGD_DHCP4, iface, "ignoring invalid classless static routes");
            return have_routes;
        }

        have_routes = TRUE;
        if (!route.plen) {
            /* gateway passed as classless static route */
            *out_gwaddr = route.gateway;
        } else {
            char b1[INET_ADDRSTRLEN];
            char b2[INET_ADDRSTRLEN];

            /* normal route */
            route.rt_source     = NM_IP_CONFIG_SOURCE_DHCP;
            route.pref_src      = address;
            route.table_any     = TRUE;
            route.table_coerced = 0;
            route.metric_any    = TRUE;
            route.metric        = 0;

            nm_l3_config_data_add_route_4(l3cd, &route);

            _LOG2I(LOGD_DHCP4,
                   iface,
                   "  classless static route %s/%d gw %s",
                   nm_inet4_ntop(route.network, b1),
                   route.plen,
                   nm_inet4_ntop(route.gateway, b2));
        }
    }

    return have_routes;
}

static gboolean
ip4_process_classless_routes(const char     *iface,
                             GHashTable     *options,
                             NML3ConfigData *l3cd,
                             in_addr_t       address,
                             guint32        *out_gwaddr)
{
    const char *str, *p;

    g_return_val_if_fail(options != NULL, FALSE);
    g_return_val_if_fail(l3cd != NULL, FALSE);

    *out_gwaddr = 0;

    /* dhcpd/dhclient in Fedora has support for rfc3442 implemented using a
     * slightly different format:
     *
     * option classless-static-routes = array of (destination-descriptor ip-address);
     *
     * which results in:
     *
     * 0 192.168.0.113 25.129.210.177.132 192.168.0.113 7.2 10.34.255.6
     *
     * dhcpcd supports classless static routes natively and uses this same
     * option identifier with the following format:
     *
     * 192.168.10.0/24 192.168.1.1 10.0.0.0/8 10.17.66.41
     */
    str = g_hash_table_lookup(options, "classless_static_routes");

    /* dhclient doesn't have actual support for rfc3442 classless static routes
     * upstream.  Thus, people resort to defining the option in dhclient.conf
     * and using arbitrary formats like so:
     *
     * option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;
     *
     * See https://lists.isc.org/pipermail/dhcp-users/2008-December/007629.html
     */
    if (!str)
        str = g_hash_table_lookup(options, "rfc3442_classless_static_routes");

    /* Microsoft version; same as rfc3442 but with a different option # (249) */
    if (!str)
        str = g_hash_table_lookup(options, "ms_classless_static_routes");

    if (nm_str_is_empty(str))
        return FALSE;

    p = str;
    while (*p) {
        if (!g_ascii_isdigit(*p) && (*p != ' ') && (*p != '.') && (*p != '/')) {
            _LOG2W(LOGD_DHCP4, iface, "ignoring invalid classless static routes '%s'", str);
            return FALSE;
        }
        p++;
    };

    if (strchr(str, '/')) {
        /* dhcpcd format */
        return ip4_process_dhcpcd_rfc3442_routes(iface, str, l3cd, address, out_gwaddr);
    }

    return ip4_process_dhclient_rfc3442_routes(iface, str, l3cd, address, out_gwaddr);
}

static void
process_classful_routes(const char     *iface,
                        GHashTable     *options,
                        NML3ConfigData *l3cd,
                        in_addr_t       address)
{
    gs_free const char **searches = NULL;
    const char         **s;
    const char          *str;

    str = g_hash_table_lookup(options, "static_routes");
    if (!str)
        return;

    searches = nm_strsplit_set(str, " ");
    if (!searches)
        return;

    if ((NM_PTRARRAY_LEN(searches) % 2) != 0) {
        _LOG2I(LOGD_DHCP4, iface, "  static routes provided, but invalid");
        return;
    }

    for (s = searches; *s; s += 2) {
        char               sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
        NMPlatformIP4Route route;
        guint32            rt_addr, rt_route;

        if (inet_pton(AF_INET, *s, &rt_addr) <= 0) {
            _LOG2W(LOGD_DHCP4, iface, "DHCP provided invalid static route address: '%s'", *s);
            continue;
        }
        if (inet_pton(AF_INET, *(s + 1), &rt_route) <= 0) {
            _LOG2W(LOGD_DHCP4, iface, "DHCP provided invalid static route gateway: '%s'", *(s + 1));
            continue;
        }

        // FIXME: ensure the IP address and route are sane

        route = (NMPlatformIP4Route){
            .network = rt_addr,
        };

        /* RFC 2132, updated by RFC 3442:
         * The Static Routes option (option 33) does not provide a subnet mask
         * for each route - it is assumed that the subnet mask is implicit in
         * whatever network number is specified in each route entry */
        route.plen = nm_ip4_addr_get_default_prefix(rt_addr);
        if (rt_addr & ~nm_ip4_addr_netmask_from_prefix(route.plen)) {
            /* RFC 943: target not "this network"; using host routing */
            route.plen = 32;
        }
        route.gateway       = rt_route;
        route.pref_src      = address;
        route.rt_source     = NM_IP_CONFIG_SOURCE_DHCP;
        route.table_any     = TRUE;
        route.table_coerced = 0;
        route.metric_any    = TRUE;
        route.metric        = 0;

        route.network = nm_ip4_addr_clear_host_address(route.network, route.plen);

        nm_l3_config_data_add_route_4(l3cd, &route);

        _LOG2I(LOGD_DHCP4,
               iface,
               "  static route %s",
               nm_platform_ip4_route_to_string(&route, sbuf, sizeof(sbuf)));
    }
}

static void
process_domain_search(int addr_family, const char *iface, const char *str, NML3ConfigData *l3cd)
{
    gs_free const char **searches  = NULL;
    gs_free char        *unescaped = NULL;
    NMLogDomain          logd      = NM_IS_IPv4(addr_family) ? LOGD_DHCP4 : LOGD_DHCP6;
    const char         **s;
    char                *p;
    int                  i;

    g_return_if_fail(str != NULL);
    nm_assert(l3cd);

    unescaped = g_strdup(str);

    p = unescaped;
    do {
        p = strstr(p, "\\032");
        if (!p)
            break;

        /* Clear the escaped space with real spaces */
        for (i = 0; i < 4; i++)
            *p++ = ' ';
    } while (*p++);

    if (strchr(unescaped, '\\')) {
        _LOG2W(logd, iface, "  invalid domain search: '%s'", unescaped);
        return;
    }

    searches = nm_strsplit_set(unescaped, " ");
    for (s = searches; searches && *s; s++) {
        _LOG2I(logd, iface, "  domain search '%s'", *s);
        nm_l3_config_data_add_search(l3cd, addr_family, *s);
    }
}

NML3ConfigData *
nm_dhcp_utils_ip4_config_from_options(NMDedupMultiIndex *multi_idx,
                                      int                ifindex,
                                      const char        *iface,
                                      GHashTable        *options)
{
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
    guint32                                 tmp_addr;
    in_addr_t                               addr;
    NMPlatformIP4Address                    address;
    char                                   *str         = NULL;
    gboolean                                gateway_has = FALSE;
    guint32                                 gateway     = 0;
    guint8                                  plen        = 0;
    char                                    sbuf[NM_INET_ADDRSTRLEN];
    guint32                                 now;

    g_return_val_if_fail(options != NULL, NULL);

    l3cd = nm_l3_config_data_new(multi_idx, ifindex, NM_IP_CONFIG_SOURCE_DHCP);

    now = nm_utils_get_monotonic_timestamp_sec();

    address = (NMPlatformIP4Address){
        .timestamp = now,
    };

    str = g_hash_table_lookup(options, "ip_address");
    if (!str || !nm_inet_parse_bin(AF_INET, str, NULL, &addr))
        return NULL;
    if (addr == INADDR_ANY)
        return NULL;

    _LOG2I(LOGD_DHCP4, iface, "  address %s", str);

    str = g_hash_table_lookup(options, "subnet_mask");
    if (str && (inet_pton(AF_INET, str, &tmp_addr) > 0)) {
        plen = nm_ip4_addr_netmask_to_prefix(tmp_addr);
        _LOG2I(LOGD_DHCP4, iface, "  plen %d (%s)", plen, str);
    } else {
        /* Get default netmask for the IP according to appropriate class. */
        plen = nm_ip4_addr_get_default_prefix(addr);
        _LOG2I(LOGD_DHCP4, iface, "  plen %d (default)", plen);
    }

    nm_platform_ip4_address_set_addr(&address, addr, plen);

    /* Routes: if the server returns classless static routes, we MUST ignore
     * the 'static_routes' option.
     */
    if (!ip4_process_classless_routes(iface, options, l3cd, address.address, &gateway))
        process_classful_routes(iface, options, l3cd, address.address);

    if (gateway) {
        _LOG2I(LOGD_DHCP4, iface, "  gateway %s", nm_inet4_ntop(gateway, sbuf));
        gateway_has = TRUE;
    } else {
        /* If the gateway wasn't provided as a classless static route with a
         * subnet length of 0, try to find it using the old-style 'routers' option.
         */
        str = g_hash_table_lookup(options, "routers");
        if (str) {
            gs_free const char **routers = nm_strsplit_set(str, " ");
            const char         **s;

            for (s = routers; *s; s++) {
                /* FIXME: how to handle multiple routers? */
                if (inet_pton(AF_INET, *s, &gateway) > 0) {
                    _LOG2I(LOGD_DHCP4, iface, "  gateway %s", *s);
                    gateway_has = TRUE;
                    break;
                } else
                    _LOG2W(LOGD_DHCP4, iface, "ignoring invalid gateway '%s'", *s);
            }
        }
    }

    if (gateway_has) {
        const NMPlatformIP4Route r = {
            .rt_source     = NM_IP_CONFIG_SOURCE_DHCP,
            .gateway       = gateway,
            .pref_src      = address.address,
            .table_any     = TRUE,
            .table_coerced = 0,
            .metric_any    = TRUE,
            .metric        = 0,
        };

        nm_l3_config_data_add_route_4(l3cd, &r);
    }

    str = g_hash_table_lookup(options, "dhcp_lease_time");
    if (str) {
        address.lifetime = address.preferred = strtoul(str, NULL, 10);
        _LOG2I(LOGD_DHCP4, iface, "  lease time %u", address.lifetime);
    }

    address.addr_source = NM_IP_CONFIG_SOURCE_DHCP;

    nm_l3_config_data_add_address_4(l3cd, &address);

    str = g_hash_table_lookup(options, "host_name");
    if (str)
        _LOG2I(LOGD_DHCP4, iface, "  hostname '%s'", str);

    str = g_hash_table_lookup(options, "domain_name_servers");
    if (str) {
        gs_free const char **dns = nm_strsplit_set(str, " ");
        const char         **s;

        for (s = dns; dns && *s; s++) {
            if (inet_pton(AF_INET, *s, &tmp_addr) > 0) {
                if (tmp_addr) {
                    nm_l3_config_data_add_nameserver_detail(l3cd, AF_INET, &tmp_addr, NULL);
                    _LOG2I(LOGD_DHCP4, iface, "  nameserver '%s'", *s);
                }
            } else
                _LOG2W(LOGD_DHCP4, iface, "ignoring invalid nameserver '%s'", *s);
        }
    }

    str = g_hash_table_lookup(options, "domain_name");
    if (str) {
        gs_free const char **domains = nm_strsplit_set(str, " ");
        const char         **s;

        for (s = domains; domains && *s; s++) {
            _LOG2I(LOGD_DHCP4, iface, "  domain name '%s'", *s);
            nm_l3_config_data_add_domain(l3cd, AF_INET, *s);
        }
    }

    str = g_hash_table_lookup(options, "domain_search");
    if (str)
        process_domain_search(AF_INET, iface, str, l3cd);

    str = g_hash_table_lookup(options, "netbios_name_servers");
    if (str) {
        gs_free const char **nbns = nm_strsplit_set(str, " ");
        const char         **s;

        for (s = nbns; nbns && *s; s++) {
            if (inet_pton(AF_INET, *s, &tmp_addr) > 0) {
                if (tmp_addr) {
                    nm_l3_config_data_add_wins(l3cd, tmp_addr);
                    _LOG2I(LOGD_DHCP4, iface, "  wins '%s'", *s);
                }
            } else
                _LOG2W(LOGD_DHCP4, iface, "ignoring invalid WINS server '%s'", *s);
        }
    }

    str = g_hash_table_lookup(options, "interface_mtu");
    if (str) {
        int int_mtu;

        errno   = 0;
        int_mtu = strtol(str, NULL, 10);
        if (NM_IN_SET(errno, EINVAL, ERANGE))
            return NULL;

        if (int_mtu > 576)
            nm_l3_config_data_set_mtu(l3cd, int_mtu);
    }

    str = g_hash_table_lookup(options, "nis_domain");
    if (str) {
        _LOG2I(LOGD_DHCP4, iface, "  NIS domain '%s'", str);
        nm_l3_config_data_add_domain(l3cd, AF_INET, str);
    }

    str = g_hash_table_lookup(options, "nis_servers");
    if (str) {
        gs_free const char **nis = nm_strsplit_set(str, " ");
        const char         **s;

        for (s = nis; nis && *s; s++) {
            if (inet_pton(AF_INET, *s, &tmp_addr) > 0) {
                if (tmp_addr) {
                    nm_l3_config_data_add_nis_server(l3cd, tmp_addr);
                    _LOG2I(LOGD_DHCP4, iface, "  nis '%s'", *s);
                }
            } else
                _LOG2W(LOGD_DHCP4, iface, "ignoring invalid NIS server '%s'", *s);
        }
    }

    str = g_hash_table_lookup(options, "vendor_encapsulated_options");
    if (str && strstr(str, "ANDROID_METERED"))
        nm_l3_config_data_set_metered(l3cd, TRUE);

    str = g_hash_table_lookup(options, "wpad");
    if (str) {
        nm_l3_config_data_set_proxy_method(l3cd, NM_PROXY_CONFIG_METHOD_AUTO);
        nm_l3_config_data_set_proxy_pac_url(l3cd, str);
    }

    return g_steal_pointer(&l3cd);
}

/*****************************************************************************/

NMPlatformIP6Address
nm_dhcp_utils_ip6_prefix_from_options(GHashTable *options)
{
    gs_strfreev char   **split_addr = NULL;
    NMPlatformIP6Address address    = {
        0,
    };
    struct in6_addr tmp_addr;
    char           *str = NULL;
    int             prefix;

    g_return_val_if_fail(options != NULL, address);

    str = g_hash_table_lookup(options, "ip6_prefix");
    if (!str)
        return address;

    split_addr = g_strsplit(str, "/", 2);
    if (split_addr[0] == NULL && split_addr[1] == NULL) {
        nm_log_warn(LOGD_DHCP6, "DHCP returned prefix without length '%s'", str);
        return address;
    }

    if (!inet_pton(AF_INET6, split_addr[0], &tmp_addr)) {
        nm_log_warn(LOGD_DHCP6, "DHCP returned invalid prefix '%s'", str);
        return address;
    }

    prefix = _nm_utils_ascii_str_to_int64(split_addr[1], 10, 0, 128, -1);
    if (prefix < 0) {
        nm_log_warn(LOGD_DHCP6, "DHCP returned prefix with invalid length '%s'", str);
        return address;
    }

    address.address     = tmp_addr;
    address.addr_source = NM_IP_CONFIG_SOURCE_DHCP;
    address.plen        = prefix;
    address.timestamp   = nm_utils_get_monotonic_timestamp_sec();

    str = g_hash_table_lookup(options, "max_life");
    if (str)
        address.lifetime = strtoul(str, NULL, 10);

    str = g_hash_table_lookup(options, "preferred_life");
    if (str)
        address.preferred = strtoul(str, NULL, 10);

    return address;
}

NML3ConfigData *
nm_dhcp_utils_ip6_config_from_options(NMDedupMultiIndex *multi_idx,
                                      int                ifindex,
                                      const char        *iface,
                                      GHashTable        *options,
                                      gboolean           info_only)
{
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
    struct in6_addr                         tmp_addr;
    NMPlatformIP6Address                    address;
    char                                   *str = NULL;
    guint32                                 now;

    g_return_val_if_fail(options != NULL, NULL);

    now = nm_utils_get_monotonic_timestamp_sec();

    address = (NMPlatformIP6Address){
        .plen      = 128,
        .timestamp = now,
    };

    l3cd = nm_l3_config_data_new(multi_idx, ifindex, NM_IP_CONFIG_SOURCE_DHCP);

    str = g_hash_table_lookup(options, "max_life");
    if (str) {
        address.lifetime = strtoul(str, NULL, 10);
        _LOG2I(LOGD_DHCP6, iface, "  valid_lft %u", address.lifetime);
    }

    str = g_hash_table_lookup(options, "preferred_life");
    if (str) {
        address.preferred = strtoul(str, NULL, 10);
        _LOG2I(LOGD_DHCP6, iface, "  preferred_lft %u", address.preferred);
    }

    if (!info_only) {
        str = g_hash_table_lookup(options, "ip6_address");
        if (!str) {
            /* No address in Managed mode is a hard error */
            return NULL;
        }

        if (!inet_pton(AF_INET6, str, &tmp_addr)) {
            _LOG2W(LOGD_DHCP6, iface, "(%s): DHCP returned invalid address '%s'", iface, str);
            return NULL;
        }

        address.address     = tmp_addr;
        address.addr_source = NM_IP_CONFIG_SOURCE_DHCP;
        nm_l3_config_data_add_address_6(l3cd, &address);
        _LOG2I(LOGD_DHCP6, iface, "  address %s", str);
    }

    str = g_hash_table_lookup(options, "host_name");
    if (str)
        _LOG2I(LOGD_DHCP6, iface, "  hostname '%s'", str);

    str = g_hash_table_lookup(options, "dhcp6_name_servers");
    if (str) {
        gs_free const char **dns = nm_strsplit_set(str, " ");
        const char         **s;

        for (s = dns; dns && *s; s++) {
            if (inet_pton(AF_INET6, *s, &tmp_addr) > 0) {
                if (!IN6_IS_ADDR_UNSPECIFIED(&tmp_addr)) {
                    nm_l3_config_data_add_nameserver_detail(l3cd, AF_INET6, &tmp_addr, NULL);
                    _LOG2I(LOGD_DHCP6, iface, "  nameserver '%s'", *s);
                }
            } else
                _LOG2W(LOGD_DHCP6, iface, "ignoring invalid nameserver '%s'", *s);
        }
    }

    str = g_hash_table_lookup(options, "dhcp6_domain_search");
    if (str)
        process_domain_search(AF_INET6, iface, str, l3cd);

    return g_steal_pointer(&l3cd);
}

char *
nm_dhcp_utils_duid_to_string(GBytes *duid)
{
    gconstpointer data;
    gsize         len;

    g_return_val_if_fail(duid, NULL);

    data = g_bytes_get_data(duid, &len);
    return nm_utils_bin2hexstr_full(data, len, ':', FALSE, NULL);
}

/**
 * nm_dhcp_utils_client_id_string_to_bytes:
 * @client_id: the client ID string
 *
 * Accepts either a hex string ("aa:bb:cc") representing a binary client ID
 * (the first byte is assumed to be the 'type' field per RFC 2132 section 9.14),
 * or a string representing a non-hardware-address client ID, in which case
 * the 'type' field is set to 0.
 *
 * Returns: the binary client ID suitable for sending over the wire
 * to the DHCP server.
 */
GBytes *
nm_dhcp_utils_client_id_string_to_bytes(const char *client_id)
{
    GBytes *bytes = NULL;
    guint   len;
    char   *c;

    g_return_val_if_fail(client_id && client_id[0], NULL);

    /* Try as hex encoded */
    if (strchr(client_id, ':')) {
        bytes = nm_utils_hexstr2bin(client_id);

        /* the result must be at least two bytes long,
         * because @client_id contains a delimiter
         * but nm_utils_hexstr2bin() does not allow
         * leading nor trailing delimiters. */
        nm_assert(!bytes || g_bytes_get_size(bytes) >= 2);
    }
    if (!bytes) {
        /* Fall back to string */
        len  = strlen(client_id);
        c    = g_malloc(len + 1);
        c[0] = 0; /* type: non-hardware address per RFC 2132 section 9.14 */
        memcpy(c + 1, client_id, len);
        bytes = g_bytes_new_take(c, len + 1);
    }

    return bytes;
}

/**
 * nm_dhcp_utils_get_leasefile_path:
 * @addr_family: the IP address family
 * @plugin_name: the name of the plugin part of the lease file name
 * @iface: the interface name to which the lease relates to
 * @uuid: uuid of the connection to which the lease relates to
 * @out_leasefile_path: will store the computed lease file path
 *
 * Constructs the lease file name on the basis of the calling plugin,
 * interface name and connection uuid. Then returns in @out_leasefile_path
 * the full path of the lease filename.
 *
 * Returns: TRUE if the lease file already exists, FALSE otherwise.
 */
gboolean
nm_dhcp_utils_get_leasefile_path(int         addr_family,
                                 const char *plugin_name,
                                 const char *iface,
                                 const char *uuid,
                                 char      **out_leasefile_path)
{
    gs_free char *rundir_path   = NULL;
    gs_free char *statedir_path = NULL;

    rundir_path = g_strdup_printf(NMRUNDIR "/%s%s-%s-%s.lease",
                                  plugin_name,
                                  addr_family == AF_INET6 ? "6" : "",
                                  uuid,
                                  iface);

    if (g_file_test(rundir_path, G_FILE_TEST_EXISTS)) {
        *out_leasefile_path = g_steal_pointer(&rundir_path);
        return TRUE;
    }

    statedir_path = g_strdup_printf(NMSTATEDIR "/%s%s-%s-%s.lease",
                                    plugin_name,
                                    addr_family == AF_INET6 ? "6" : "",
                                    uuid,
                                    iface);

    if (g_file_test(statedir_path, G_FILE_TEST_EXISTS)) {
        *out_leasefile_path = g_steal_pointer(&statedir_path);
        return TRUE;
    }

    if (nm_config_get_configure_and_quit(nm_config_get()) == NM_CONFIG_CONFIGURE_AND_QUIT_INITRD)
        *out_leasefile_path = g_steal_pointer(&rundir_path);
    else
        *out_leasefile_path = g_steal_pointer(&statedir_path);
    return FALSE;
}

gboolean
nm_dhcp_utils_merge_new_dhcp6_lease(const NML3ConfigData  *l3cd_old,
                                    const NML3ConfigData  *l3cd_new,
                                    const NML3ConfigData **out_l3cd_merged)
{
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd_merged = NULL;
    const NMPlatformIP6Address             *addr;
    NMDhcpLease                            *lease_old;
    NMDhcpLease                            *lease_new;
    NMDedupMultiIter                        iter;
    const char                             *start;
    const char                             *iaid;

    nm_assert(out_l3cd_merged && !*out_l3cd_merged);

    if (!l3cd_old)
        return FALSE;
    if (!l3cd_new)
        return FALSE;

    lease_new = nm_l3_config_data_get_dhcp_lease(l3cd_new, AF_INET6);
    if (!lease_new)
        return FALSE;

    lease_old = nm_l3_config_data_get_dhcp_lease(l3cd_old, AF_INET6);
    if (!lease_old)
        return FALSE;

    start = nm_dhcp_lease_lookup_option(lease_new, "life_starts");
    if (!start)
        return FALSE;
    iaid = nm_dhcp_lease_lookup_option(lease_new, "iaid");
    if (!iaid)
        return FALSE;

    if (!nm_streq0(start, nm_dhcp_lease_lookup_option(lease_old, "life_starts")))
        return FALSE;
    if (!nm_streq0(iaid, nm_dhcp_lease_lookup_option(lease_old, "iaid")))
        return FALSE;

    /* If the server sends multiple IPv6 addresses, we receive a state
     * changed event for each of them. Use the event ID to merge IPv6
     * addresses from the same transaction into a single configuration.
     **/

    l3cd_merged = nm_l3_config_data_new_clone(l3cd_old, 0);

    nm_l3_config_data_iter_ip6_address_for_each (&iter, l3cd_new, &addr)
        nm_l3_config_data_add_address_6(l3cd_merged, addr);

    /* FIXME(l3cfg): Note that we keep the original NMDhcpLease. All we take from the new lease are the
     * addresses. Maybe this is not right and we should merge the leases too?? */
    nm_l3_config_data_set_dhcp_lease(l3cd_merged, AF_INET6, lease_old);

    *out_l3cd_merged = nm_l3_config_data_ref_and_seal(g_steal_pointer(&l3cd_merged));
    return TRUE;
}

/*****************************************************************************/

void
nm_dhcp_lease_log_invalid_option(const char *iface,
                                 int         addr_family,
                                 guint       option,
                                 const char *fmt,
                                 ...)
{
    const char   *option_name;
    gs_free char *msg = NULL;
    va_list       ap;

    option_name = nm_dhcp_option_request_string(addr_family, option);

    va_start(ap, fmt);
    msg = g_strdup_vprintf(fmt, ap);
    va_end(ap);

    _LOG2I(NM_IS_IPv4(addr_family) ? LOGD_DHCP4 : LOGD_DHCP6,
           iface,
           "error parsing DHCP option %d (%s)%s%s",
           option,
           option_name,
           msg ? ": " : "",
           msg ?: "");
}

gboolean
nm_dhcp_lease_data_parse_u16(const guint8 *data,
                             gsize         n_data,
                             uint16_t     *out_val,
                             const char   *iface,
                             int           addr_family,
                             guint         option)
{
    if (n_data != 2) {
        nm_dhcp_lease_log_invalid_option(iface,
                                         addr_family,
                                         option,
                                         "invalid option length %lu",
                                         (unsigned long) n_data);
        return FALSE;
    }

    *out_val = unaligned_read_be16(data);
    return TRUE;
}

gboolean
nm_dhcp_lease_data_parse_mtu(const guint8 *data,
                             gsize         n_data,
                             uint16_t     *out_val,
                             const char   *iface,
                             int           addr_family,
                             guint         option)
{
    uint16_t mtu;

    if (!nm_dhcp_lease_data_parse_u16(data, n_data, &mtu, iface, addr_family, option))
        return FALSE;

    if (mtu < 68) {
        /* https://tools.ietf.org/html/rfc2132#section-5.1:
         *
         * The minimum legal value for the MTU is 68. */
        nm_dhcp_lease_log_invalid_option(iface,
                                         addr_family,
                                         option,
                                         "value %u is smaller than 68",
                                         mtu);
        return FALSE;
    }

    *out_val = mtu;
    return TRUE;
}

gboolean
nm_dhcp_lease_data_parse_cstr(const guint8 *data,
                              gsize         n_data,
                              gsize        *out_new_len,
                              const char   *iface,
                              int           addr_family,
                              guint         option)
{
    /* WARNING: this function only validates that the string does not contain
     * NUL characters (and ignores trailing NULs). It does not check character
     * encoding! */

    while (n_data > 0 && data[n_data - 1] == '\0')
        n_data--;

    if (n_data > 0) {
        if (memchr(data, '\0', n_data)) {
            /* we accept trailing NUL, but none in between.
             *
             * https://tools.ietf.org/html/rfc2132#section-2
             * https://github.com/systemd/systemd/issues/1337 */
            nm_dhcp_lease_log_invalid_option(iface,
                                             addr_family,
                                             option,
                                             "string contains embedded NUL");
            return FALSE;
        }
    }

    NM_SET_OUT(out_new_len, n_data);
    return TRUE;
}

char *
nm_dhcp_lease_data_parse_domain_validate(const char *str,
                                         const char *iface,
                                         int         addr_family,
                                         guint       option)
{
    gs_free char *s = NULL;

    s = nm_sd_dns_name_normalize(str);
    if (!s)
        goto err;

    if (nm_str_is_empty(s) || (s[0] == '.' && s[1] == '\0')) {
        /* root domains are not allowed. */
        goto err;
    }

    if (nm_utils_is_localhost(s))
        goto err;

    if (!g_utf8_validate(s, -1, NULL)) {
        /* the result must be valid UTF-8. */
        goto err;
    }

    return g_steal_pointer(&s);
err:
    nm_dhcp_lease_log_invalid_option(iface,
                                     addr_family,
                                     option,
                                     "'%s' is not a valid DNS domain",
                                     str);
    return NULL;
}

gboolean
nm_dhcp_lease_data_parse_domain(const guint8 *data,
                                gsize         n_data,
                                char        **out_val,
                                const char   *iface,
                                int           addr_family,
                                guint         option)
{
    gs_free char *str1_free = NULL;
    const char   *str1;
    gs_free char *s = NULL;

    /* this is mostly the same as systemd's lease_parse_domain(). */

    if (!nm_dhcp_lease_data_parse_cstr(data, n_data, &n_data, iface, addr_family, option))
        return FALSE;

    if (n_data == 0) {
        /* empty domains are rejected. See
         * https://tools.ietf.org/html/rfc2132#section-3.14
         * https://tools.ietf.org/html/rfc2132#section-3.17
         *
         *   Its minimum length is 1.
         *
         * Note that this is *after* we potentially stripped trailing NULs.
         */
        nm_dhcp_lease_log_invalid_option(iface, addr_family, option, "empty value");
        return FALSE;
    }

    str1 = nm_strndup_a(300, (char *) data, n_data, &str1_free);

    s = nm_dhcp_lease_data_parse_domain_validate(str1, iface, addr_family, option);
    if (!s)
        return FALSE;

    *out_val = g_steal_pointer(&s);
    return TRUE;
}

gboolean
nm_dhcp_lease_data_parse_in_addr(const guint8 *data,
                                 gsize         n_data,
                                 in_addr_t    *out_val,
                                 const char   *iface,
                                 guint         option)
{
    /* - option 1, https://tools.ietf.org/html/rfc2132#section-3.3
     * - option 28, https://tools.ietf.org/html/rfc2132#section-5.3
     */

    /* Some DHCP servers send duplicate options, and we concatenate them
     * according to RFC 3396 section 7. Therefore, it's possible that a
     * option carrying a IPv4 address has a length > 4.
     */
    if (n_data < 4) {
        nm_dhcp_lease_log_invalid_option(iface,
                                         AF_INET,
                                         option,
                                         "invalid address length %lu",
                                         (unsigned long) n_data);
        return FALSE;
    }

    *out_val = unaligned_read_ne32(data);
    return TRUE;
}

/*****************************************************************************/

static gboolean
lease_option_print_label(NMStrBuf *sbuf, size_t n_label, const uint8_t **datap, size_t *n_datap)
{
    gsize i;

    for (i = 0; i < n_label; ++i) {
        uint8_t c = 0;

        if (!nm_dhcp_lease_data_consume(datap, n_datap, &c, sizeof(c)))
            return FALSE;

        switch (c) {
        case 'a' ... 'z':
        case 'A' ... 'Z':
        case '0' ... '9':
        case '-':
        case '_':
            nm_str_buf_append_c(sbuf, c);
            break;
        case '.':
        case '\\':
            nm_str_buf_append_c(sbuf, '\\', c);
            break;
        default:
            nm_str_buf_append_printf(sbuf, "\\%3d", c);
        }
    }

    return TRUE;
}

static char *
lease_option_print_domain_name(const uint8_t  *cache,
                               size_t         *n_cachep,
                               const uint8_t **datap,
                               size_t         *n_datap,
                               gboolean       *invalid)
{
    nm_auto_str_buf NMStrBuf sbuf = NM_STR_BUF_INIT(NM_UTILS_GET_NEXT_REALLOC_SIZE_40, FALSE);
    const uint8_t           *domain;
    size_t                   n_domain;
    size_t                   n_cache   = *n_cachep;
    const uint8_t          **domainp   = datap;
    size_t                  *n_domainp = n_datap;
    gboolean                 first     = TRUE;
    uint8_t                  c;

    NM_SET_OUT(invalid, FALSE);

    /*
     * We are given two adjacent memory regions. The @cache contains alreday parsed
     * domain names, and the @datap contains the remaining data to parse.
     *
     * A domain name is formed from a sequence of labels. Each label start with
     * a length byte, where the two most significant bits are unset. A zero-length
     * label indicates the end of the domain name.
     *
     * Alternatively, a label can be followed by an offset (indicated by the two
     * most significant bits being set in the next byte that is read). The offset
     * is an offset into the cache, where the next label of the domain name can
     * be found.
     *
     * Note, that each time a jump to an offset is performed, the size of the
     * cache shrinks, so this is guaranteed to terminate.
     */
    if (cache + n_cache != *datap) {
        NM_SET_OUT(invalid, TRUE);
        return NULL;
    }

    for (;;) {
        if (!nm_dhcp_lease_data_consume(domainp, n_domainp, &c, sizeof(c)))
            return NULL;

        switch (c & 0xC0) {
        case 0x00: /* label length */
        {
            size_t n_label = c;

            if (n_label == 0) {
                /*
                 * We reached the final label of the domain name. Adjust
                 * the cache to include the consumed data, and return.
                 */
                *n_cachep = *datap - cache;
                return nm_str_buf_finalize(&sbuf, NULL);
            }

            if (!first)
                nm_str_buf_append_c(&sbuf, '.');
            else
                first = FALSE;

            if (!lease_option_print_label(&sbuf, n_label, domainp, n_domainp)) {
                NM_SET_OUT(invalid, TRUE);
                return NULL;
            }

            break;
        }
        case 0xC0: /* back pointer */
        {
            size_t offset = (c & 0x3F) << 16;

            /*
             * The offset is given as two bytes (in big endian), where the
             * two high bits are masked out.
             */

            if (!nm_dhcp_lease_data_consume(domainp, n_domainp, &c, sizeof(c))) {
                NM_SET_OUT(invalid, TRUE);
                return NULL;
            }

            offset += c;

            if (offset >= n_cache) {
                NM_SET_OUT(invalid, TRUE);
                return NULL;
            }

            domain   = cache + offset;
            n_domain = n_cache - offset;
            n_cache  = offset;

            domainp   = &domain;
            n_domainp = &n_domain;

            break;
        }
        default:
            NM_SET_OUT(invalid, TRUE);
            return NULL;
        }
    }
}

char **
nm_dhcp_lease_data_parse_search_list(const guint8 *data,
                                     gsize         n_data,
                                     const char   *iface,
                                     int           addr_family,
                                     guint         option)
{
    GPtrArray    *array   = NULL;
    const guint8 *cache   = data;
    gsize         n_cache = 0;
    guint         i       = 0;

    for (;;) {
        gs_free char *s = NULL;
        gboolean      invalid;

        s = lease_option_print_domain_name(cache, &n_cache, &data, &n_data, &invalid);
        if (!s) {
            if (iface && invalid)
                nm_dhcp_lease_log_invalid_option(iface,
                                                 addr_family,
                                                 option,
                                                 "search domain #%u is invalid",
                                                 i);
            break;
        }

        if (!array)
            array = g_ptr_array_new();

        g_ptr_array_add(array, g_steal_pointer(&s));
        i++;
    }

    if (!array)
        return NULL;

    g_ptr_array_add(array, NULL);
    return (char **) g_ptr_array_free(array, FALSE);
}
