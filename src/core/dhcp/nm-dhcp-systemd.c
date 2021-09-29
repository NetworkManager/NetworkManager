/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <net/if_arp.h>

#include "libnm-glib-aux/nm-dedup-multi.h"
#include "libnm-std-aux/unaligned.h"

#include "nm-utils.h"
#include "nm-l3-config-data.h"
#include "nm-dhcp-utils.h"
#include "nm-dhcp-options.h"
#include "nm-core-utils.h"
#include "NetworkManagerUtils.h"
#include "libnm-platform/nm-platform.h"
#include "nm-dhcp-client-logging.h"
#include "libnm-systemd-core/nm-sd.h"
#include "libnm-systemd-core/nm-sd-utils-dhcp.h"

/*****************************************************************************/

#define NM_TYPE_DHCP_SYSTEMD (nm_dhcp_systemd_get_type())
#define NM_DHCP_SYSTEMD(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DHCP_SYSTEMD, NMDhcpSystemd))
#define NM_DHCP_SYSTEMD_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DHCP_SYSTEMD, NMDhcpSystemdClass))
#define NM_IS_DHCP_SYSTEMD(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DHCP_SYSTEMD))
#define NM_IS_DHCP_SYSTEMD_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DHCP_SYSTEMD))
#define NM_DHCP_SYSTEMD_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DHCP_SYSTEMD, NMDhcpSystemdClass))

typedef struct _NMDhcpSystemd      NMDhcpSystemd;
typedef struct _NMDhcpSystemdClass NMDhcpSystemdClass;

static GType nm_dhcp_systemd_get_type(void);

/*****************************************************************************/

typedef struct {
    sd_dhcp_client * client4;
    sd_dhcp6_client *client6;
    char *           lease_file;

    guint request_count;
} NMDhcpSystemdPrivate;

struct _NMDhcpSystemd {
    NMDhcpClient         parent;
    NMDhcpSystemdPrivate _priv;
};

struct _NMDhcpSystemdClass {
    NMDhcpClientClass parent;
};

G_DEFINE_TYPE(NMDhcpSystemd, nm_dhcp_systemd, NM_TYPE_DHCP_CLIENT)

#define NM_DHCP_SYSTEMD_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDhcpSystemd, NM_IS_DHCP_SYSTEMD)

/*****************************************************************************/

static NML3ConfigData *
lease_to_ip4_config(NMDedupMultiIndex *multi_idx,
                    const char *       iface,
                    int                ifindex,
                    sd_dhcp_lease *    lease,
                    GError **          error)
{
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
    gs_unref_hashtable GHashTable *options       = NULL;
    const struct in_addr *         addr_list;
    char                           addr_str[NM_UTILS_INET_ADDRSTRLEN];
    const char *                   s;
    nm_auto_free_gstring GString *str           = NULL;
    nm_auto_free sd_dhcp_route **routes         = NULL;
    const char *const *          search_domains = NULL;
    guint16                      mtu;
    int                          i, num;
    const void *                 data;
    gsize                        data_len;
    gboolean                     has_router_from_classless = FALSE;
    gboolean                     has_classless_route       = FALSE;
    gboolean                     has_static_route          = FALSE;
    const gint32                 ts                        = nm_utils_get_monotonic_timestamp_sec();
    gint64                       ts_time                   = time(NULL);
    struct in_addr               a_address;
    struct in_addr               a_netmask;
    struct in_addr               a_next_server;
    struct in_addr               server_id;
    struct in_addr               broadcast;
    const struct in_addr *       a_router;
    guint32                      a_plen;
    guint32                      a_lifetime;
    guint32                      renewal;
    guint32                      rebinding;
    gs_free nm_sd_dhcp_option *private_options = NULL;

    nm_assert(lease != NULL);

    if (sd_dhcp_lease_get_address(lease, &a_address) < 0) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_UNKNOWN,
                                   "could not get address from lease");
        return NULL;
    }

    if (sd_dhcp_lease_get_netmask(lease, &a_netmask) < 0) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_UNKNOWN,
                                   "could not get netmask from lease");
        return NULL;
    }

    if (sd_dhcp_lease_get_lifetime(lease, &a_lifetime) < 0) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_UNKNOWN,
                                   "could not get lifetime from lease");
        return NULL;
    }

    l3cd = nm_l3_config_data_new(multi_idx, ifindex, NM_IP_CONFIG_SOURCE_DHCP);

    options = nm_dhcp_option_create_options_dict();

    _nm_utils_inet4_ntop(a_address.s_addr, addr_str);
    nm_dhcp_option_add_option(options, AF_INET, NM_DHCP_OPTION_DHCP4_NM_IP_ADDRESS, addr_str);

    a_plen = nm_utils_ip4_netmask_to_prefix(a_netmask.s_addr);
    nm_dhcp_option_add_option(options,
                              AF_INET,
                              NM_DHCP_OPTION_DHCP4_SUBNET_MASK,
                              _nm_utils_inet4_ntop(a_netmask.s_addr, addr_str));

    nm_dhcp_option_add_option_u64(options,
                                  AF_INET,
                                  NM_DHCP_OPTION_DHCP4_IP_ADDRESS_LEASE_TIME,
                                  a_lifetime);
    nm_dhcp_option_add_option_u64(options,
                                  AF_INET,
                                  NM_DHCP_OPTION_DHCP4_NM_EXPIRY,
                                  (guint64) (ts_time + a_lifetime));

    if (sd_dhcp_lease_get_next_server(lease, &a_next_server) == 0) {
        _nm_utils_inet4_ntop(a_next_server.s_addr, addr_str);
        nm_dhcp_option_add_option(options, AF_INET, NM_DHCP_OPTION_DHCP4_NM_NEXT_SERVER, addr_str);
    }

    nm_l3_config_data_add_address_4(l3cd,
                                    &((const NMPlatformIP4Address){
                                        .address      = a_address.s_addr,
                                        .peer_address = a_address.s_addr,
                                        .plen         = a_plen,
                                        .addr_source  = NM_IP_CONFIG_SOURCE_DHCP,
                                        .timestamp    = ts,
                                        .lifetime     = a_lifetime,
                                        .preferred    = a_lifetime,
                                    }));

    if (sd_dhcp_lease_get_server_identifier(lease, &server_id) >= 0) {
        _nm_utils_inet4_ntop(server_id.s_addr, addr_str);
        nm_dhcp_option_add_option(options, AF_INET, NM_DHCP_OPTION_DHCP4_SERVER_ID, addr_str);
    }

    if (sd_dhcp_lease_get_broadcast(lease, &broadcast) >= 0) {
        _nm_utils_inet4_ntop(broadcast.s_addr, addr_str);
        nm_dhcp_option_add_option(options, AF_INET, NM_DHCP_OPTION_DHCP4_BROADCAST, addr_str);
    }

    num = sd_dhcp_lease_get_dns(lease, &addr_list);
    if (num > 0) {
        nm_gstring_prepare(&str);
        for (i = 0; i < num; i++) {
            _nm_utils_inet4_ntop(addr_list[i].s_addr, addr_str);
            g_string_append(nm_gstring_add_space_delimiter(str), addr_str);

            if (addr_list[i].s_addr == 0 || nm_ip4_addr_is_localhost(addr_list[i].s_addr)) {
                /* Skip localhost addresses, like also networkd does.
                 * See https://github.com/systemd/systemd/issues/4524. */
                continue;
            }
            nm_l3_config_data_add_nameserver(l3cd, AF_INET, &addr_list[i].s_addr);
        }
        nm_dhcp_option_add_option(options,
                                  AF_INET,
                                  NM_DHCP_OPTION_DHCP4_DOMAIN_NAME_SERVER,
                                  str->str);
    }

    num = sd_dhcp_lease_get_search_domains(lease, (char ***) &search_domains);
    if (num > 0) {
        nm_gstring_prepare(&str);
        for (i = 0; i < num; i++) {
            g_string_append(nm_gstring_add_space_delimiter(str), search_domains[i]);
            nm_l3_config_data_add_search(l3cd, AF_INET, search_domains[i]);
        }
        nm_dhcp_option_add_option(options,
                                  AF_INET,
                                  NM_DHCP_OPTION_DHCP4_DOMAIN_SEARCH_LIST,
                                  str->str);
    }

    if (sd_dhcp_lease_get_domainname(lease, &s) >= 0) {
        gs_strfreev char **domains = NULL;
        char **            d;

        nm_dhcp_option_add_option(options, AF_INET, NM_DHCP_OPTION_DHCP4_DOMAIN_NAME, s);

        /* Multiple domains sometimes stuffed into option 15 "Domain Name".
         * As systemd escapes such characters, split them at \\032. */
        domains = g_strsplit(s, "\\032", 0);
        for (d = domains; *d; d++)
            nm_l3_config_data_add_domain(l3cd, AF_INET, *d);
    }

    if (sd_dhcp_lease_get_hostname(lease, &s) >= 0) {
        nm_dhcp_option_add_option(options, AF_INET, NM_DHCP_OPTION_DHCP4_HOST_NAME, s);
    }

    num = sd_dhcp_lease_get_routes(lease, &routes);
    if (num > 0) {
        nm_auto_free_gstring GString *str_classless               = NULL;
        nm_auto_free_gstring GString *str_static                  = NULL;
        guint32                       default_route_metric_offset = 0;

        for (i = 0; i < num; i++) {
            switch (sd_dhcp_route_get_option(routes[i])) {
            case NM_DHCP_OPTION_DHCP4_CLASSLESS_STATIC_ROUTE:
                has_classless_route = TRUE;
                break;
            case NM_DHCP_OPTION_DHCP4_STATIC_ROUTE:
                has_static_route = TRUE;
                break;
            }
        }

        if (has_classless_route)
            str_classless = g_string_sized_new(30);
        if (has_static_route)
            str_static = g_string_sized_new(30);

        for (i = 0; i < num; i++) {
            char           network_net_str[NM_UTILS_INET_ADDRSTRLEN];
            char           gateway_str[NM_UTILS_INET_ADDRSTRLEN];
            guint8         r_plen;
            struct in_addr r_network;
            struct in_addr r_gateway;
            in_addr_t      network_net;
            int            option;
            guint32        m;

            option = sd_dhcp_route_get_option(routes[i]);
            if (!NM_IN_SET(option,
                           NM_DHCP_OPTION_DHCP4_CLASSLESS_STATIC_ROUTE,
                           NM_DHCP_OPTION_DHCP4_STATIC_ROUTE))
                continue;

            if (sd_dhcp_route_get_destination(routes[i], &r_network) < 0)
                continue;
            if (sd_dhcp_route_get_destination_prefix_length(routes[i], &r_plen) < 0 || r_plen > 32)
                continue;
            if (sd_dhcp_route_get_gateway(routes[i], &r_gateway) < 0)
                continue;

            network_net = nm_utils_ip4_address_clear_host_address(r_network.s_addr, r_plen);
            _nm_utils_inet4_ntop(network_net, network_net_str);
            _nm_utils_inet4_ntop(r_gateway.s_addr, gateway_str);

            g_string_append_printf(
                nm_gstring_add_space_delimiter(option == NM_DHCP_OPTION_DHCP4_CLASSLESS_STATIC_ROUTE
                                                   ? str_classless
                                                   : str_static),
                "%s/%d %s",
                network_net_str,
                (int) r_plen,
                gateway_str);

            if (option == NM_DHCP_OPTION_DHCP4_STATIC_ROUTE && has_classless_route) {
                /* RFC 3443: if the DHCP server returns both a Classless Static Routes
                 * option and a Static Routes option, the DHCP client MUST ignore the
                 * Static Routes option. */
                continue;
            }

            if (r_plen == 0 && option == NM_DHCP_OPTION_DHCP4_STATIC_ROUTE) {
                /* for option 33 (static route), RFC 2132 says:
                 *
                 * The default route (0.0.0.0) is an illegal destination for a static
                 * route. */
                continue;
            }

            if (r_plen == 0) {
                /* if there are multiple default routes, we add them with differing
                 * metrics. */
                m                         = default_route_metric_offset++;
                has_router_from_classless = TRUE;
            } else
                m = 0;

            nm_l3_config_data_add_route_4(l3cd,
                                          &((const NMPlatformIP4Route){
                                              .network       = network_net,
                                              .plen          = r_plen,
                                              .gateway       = r_gateway.s_addr,
                                              .rt_source     = NM_IP_CONFIG_SOURCE_DHCP,
                                              .metric_any    = TRUE,
                                              .metric        = m,
                                              .table_any     = TRUE,
                                              .table_coerced = 0,
                                          }));
        }

        if (str_classless && str_classless->len > 0)
            nm_dhcp_option_add_option(options,
                                      AF_INET,
                                      NM_DHCP_OPTION_DHCP4_CLASSLESS_STATIC_ROUTE,
                                      str_classless->str);
        if (str_static && str_static->len > 0)
            nm_dhcp_option_add_option(options,
                                      AF_INET,
                                      NM_DHCP_OPTION_DHCP4_STATIC_ROUTE,
                                      str_static->str);
    }

    num = sd_dhcp_lease_get_router(lease, &a_router);
    if (num > 0) {
        guint32 default_route_metric_offset = 0;

        nm_gstring_prepare(&str);
        for (i = 0; i < num; i++) {
            guint32 m;

            s = _nm_utils_inet4_ntop(a_router[i].s_addr, addr_str);
            g_string_append(nm_gstring_add_space_delimiter(str), s);

            if (a_router[i].s_addr == 0) {
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
                                              .gateway       = a_router[i].s_addr,
                                              .table_any     = TRUE,
                                              .table_coerced = 0,
                                              .metric_any    = TRUE,
                                              .metric        = m,
                                          }));
        }
        nm_dhcp_option_add_option(options, AF_INET, NM_DHCP_OPTION_DHCP4_ROUTER, str->str);
    }

    if (sd_dhcp_lease_get_mtu(lease, &mtu) >= 0 && mtu) {
        nm_dhcp_option_add_option_u64(options, AF_INET, NM_DHCP_OPTION_DHCP4_INTERFACE_MTU, mtu);
        nm_l3_config_data_set_mtu(l3cd, mtu);
    }

    num = sd_dhcp_lease_get_ntp(lease, &addr_list);
    if (num > 0) {
        nm_gstring_prepare(&str);
        for (i = 0; i < num; i++) {
            _nm_utils_inet4_ntop(addr_list[i].s_addr, addr_str);
            g_string_append(nm_gstring_add_space_delimiter(str), addr_str);
        }
        nm_dhcp_option_add_option(options, AF_INET, NM_DHCP_OPTION_DHCP4_NTP_SERVER, str->str);
    }

    if (sd_dhcp_lease_get_root_path(lease, &s) >= 0) {
        nm_dhcp_option_add_option(options, AF_INET, NM_DHCP_OPTION_DHCP4_ROOT_PATH, s);
    }

    if (sd_dhcp_lease_get_t1(lease, &renewal) >= 0) {
        nm_dhcp_option_add_option_u64(options,
                                      AF_INET,
                                      NM_DHCP_OPTION_DHCP4_RENEWAL_T1_TIME,
                                      renewal);
    }

    if (sd_dhcp_lease_get_t2(lease, &rebinding) >= 0) {
        nm_dhcp_option_add_option_u64(options,
                                      AF_INET,
                                      NM_DHCP_OPTION_DHCP4_REBINDING_T2_TIME,
                                      rebinding);
    }

    if (sd_dhcp_lease_get_timezone(lease, &s) >= 0) {
        nm_dhcp_option_add_option(options, AF_INET, NM_DHCP_OPTION_DHCP4_NEW_TZDB_TIMEZONE, s);
    }

    if (sd_dhcp_lease_get_vendor_specific(lease, &data, &data_len) >= 0) {
        if (!!memmem(data, data_len, "ANDROID_METERED", NM_STRLEN("ANDROID_METERED")))
            nm_l3_config_data_set_metered(l3cd, TRUE);
    }

    num = nm_sd_dhcp_lease_get_private_options(lease, &private_options);
    if (num > 0) {
        for (i = 0; i < num; i++) {
            guint8        code       = private_options[i].code;
            const guint8 *l_data     = private_options[i].data;
            gsize         l_data_len = private_options[i].data_len;
            char *        option_string;

            if (code == NM_DHCP_OPTION_DHCP4_PRIVATE_PROXY_AUTODISCOVERY) {
                if (nm_dhcp_lease_data_parse_cstr(l_data, l_data_len, &l_data_len)) {
                    gs_free char *to_free = NULL;
                    const char *  escaped;

                    escaped =
                        nm_utils_buf_utf8safe_escape((char *) l_data, l_data_len, 0, &to_free);
                    nm_dhcp_option_add_option(options,
                                              AF_INET,
                                              NM_DHCP_OPTION_DHCP4_PRIVATE_PROXY_AUTODISCOVERY,
                                              escaped ?: "");

                    nm_l3_config_data_set_proxy_method(l3cd, NM_PROXY_CONFIG_METHOD_AUTO);
                    nm_l3_config_data_set_proxy_pac_url(l3cd, escaped ?: "");
                }
                continue;
            }
            if (code == NM_DHCP_OPTION_DHCP4_PRIVATE_CLASSLESS_STATIC_ROUTE) {
                /* nettools and dhclient parse option 249 (Microsoft Classless Static Route)
                 * as fallback for routes and ignores them from private options.
                 *
                 * The systemd plugin does not, and for consistency with nettools we
                 * also don't expose it as private option either. */
                continue;
            }

            option_string = nm_utils_bin2hexstr_full(l_data, l_data_len, ':', FALSE, NULL);
            nm_dhcp_option_take_option(options, AF_INET, code, option_string);
        }
    }

    nm_dhcp_option_add_requests_to_options(options, AF_INET);

    nm_l3_config_data_set_dhcp_lease_from_options(l3cd, AF_INET, g_steal_pointer(&options));

    return g_steal_pointer(&l3cd);
}

/*****************************************************************************/

static void
bound4_handle(NMDhcpSystemd *self, gboolean extended)
{
    NMDhcpSystemdPrivate *  priv                 = NM_DHCP_SYSTEMD_GET_PRIVATE(self);
    const char *            iface                = nm_dhcp_client_get_iface(NM_DHCP_CLIENT(self));
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
    gs_unref_hashtable GHashTable *options       = NULL;
    sd_dhcp_lease *                lease         = NULL;
    GError *                       error         = NULL;

    if (sd_dhcp_client_get_lease(priv->client4, &lease) < 0 || !lease) {
        _LOGW("no lease!");
        nm_dhcp_client_set_state(NM_DHCP_CLIENT(self), NM_DHCP_STATE_FAIL, NULL);
        return;
    }

    _LOGD("lease available");

    l3cd = lease_to_ip4_config(nm_dhcp_client_get_multi_idx(NM_DHCP_CLIENT(self)),
                               iface,
                               nm_dhcp_client_get_ifindex(NM_DHCP_CLIENT(self)),
                               lease,
                               &error);
    if (!l3cd) {
        _LOGW("%s", error->message);
        g_clear_error(&error);
        nm_dhcp_client_set_state(NM_DHCP_CLIENT(self), NM_DHCP_STATE_FAIL, NULL);
        return;
    }

    dhcp_lease_save(lease, priv->lease_file);

    nm_dhcp_client_set_state(NM_DHCP_CLIENT(self),
                             extended ? NM_DHCP_STATE_EXTENDED : NM_DHCP_STATE_BOUND,
                             l3cd);
}

static int
dhcp_event_cb(sd_dhcp_client *client, int event, gpointer user_data)
{
    NMDhcpSystemd *       self = NM_DHCP_SYSTEMD(user_data);
    NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE(self);
    char                  addr_str[INET_ADDRSTRLEN];
    sd_dhcp_lease *       lease = NULL;
    struct in_addr        addr;
    int                   r;

    nm_assert(priv->client4 == client);

    _LOGD("client event %d", event);

    switch (event) {
    case SD_DHCP_CLIENT_EVENT_EXPIRED:
        nm_dhcp_client_set_state(NM_DHCP_CLIENT(user_data), NM_DHCP_STATE_EXPIRE, NULL);
        break;
    case SD_DHCP_CLIENT_EVENT_STOP:
        nm_dhcp_client_set_state(NM_DHCP_CLIENT(user_data), NM_DHCP_STATE_FAIL, NULL);
        break;
    case SD_DHCP_CLIENT_EVENT_RENEW:
    case SD_DHCP_CLIENT_EVENT_IP_CHANGE:
        bound4_handle(self, TRUE);
        break;
    case SD_DHCP_CLIENT_EVENT_IP_ACQUIRE:
        bound4_handle(self, FALSE);
        break;
    case SD_DHCP_CLIENT_EVENT_SELECTING:
        r = sd_dhcp_client_get_lease(priv->client4, &lease);
        if (r < 0)
            return r;
        r = sd_dhcp_lease_get_server_identifier(lease, &addr);
        if (r < 0)
            return r;
        if (nm_dhcp_client_server_id_is_rejected(NM_DHCP_CLIENT(user_data), &addr)) {
            _LOGD("server-id %s is in the reject-list, ignoring",
                  nm_utils_inet_ntop(AF_INET, &addr, addr_str));
            return -ENOMSG;
        }
        break;
    case SD_DHCP_CLIENT_EVENT_TRANSIENT_FAILURE:
        break;
    default:
        _LOGW("unhandled DHCP event %d", event);
        break;
    }

    return 0;
}

static gboolean
ip4_start(NMDhcpClient *client, GError **error)
{
    nm_auto(sd_dhcp_client_unrefp) sd_dhcp_client *sd_client = NULL;
    NMDhcpSystemd *                                self      = NM_DHCP_SYSTEMD(client);
    NMDhcpSystemdPrivate *                         priv      = NM_DHCP_SYSTEMD_GET_PRIVATE(self);
    const NMDhcpClientConfig *                     client_config;
    gs_free char *                                 lease_file = NULL;
    GBytes *                                       hwaddr;
    const uint8_t *                                hwaddr_arr;
    gsize                                          hwaddr_len;
    int                                            arp_type;
    GBytes *                                       client_id;
    gs_unref_bytes GBytes *client_id_new = NULL;
    GBytes *               vendor_class_identifier;
    const uint8_t *        client_id_arr;
    size_t                 client_id_len;
    struct in_addr         last_addr = {0};
    const char *           hostname;
    const char *           mud_url;
    int                    r, i;
    GBytes *               bcast_hwaddr;
    const uint8_t *        bcast_hwaddr_arr;
    gsize                  bcast_hwaddr_len;

    g_return_val_if_fail(!priv->client4, FALSE);
    g_return_val_if_fail(!priv->client6, FALSE);

    client_config = nm_dhcp_client_get_config(client);

    /* TODO: honor nm_dhcp_client_get_anycast_address() */

    r = sd_dhcp_client_new(&sd_client, FALSE);
    if (r < 0) {
        nm_utils_error_set_errno(error, r, "failed to create dhcp-client: %s");
        return FALSE;
    }

    _LOGT("dhcp-client4: set " NM_HASH_OBFUSCATE_PTR_FMT, NM_HASH_OBFUSCATE_PTR(sd_client));

    r = sd_dhcp_client_attach_event(sd_client, NULL, 0);
    if (r < 0) {
        nm_utils_error_set_errno(error, r, "failed to attach event: %s");
        return FALSE;
    }

    hwaddr = client_config->hwaddr;
    if (!hwaddr || !(hwaddr_arr = g_bytes_get_data(hwaddr, &hwaddr_len))
        || (arp_type = nm_utils_arp_type_detect_from_hwaddrlen(hwaddr_len)) < 0) {
        nm_utils_error_set_literal(error, NM_UTILS_ERROR_UNKNOWN, "invalid MAC address");
        return FALSE;
    }

    bcast_hwaddr_arr = NULL;
    bcast_hwaddr     = client_config->bcast_hwaddr;
    if (bcast_hwaddr) {
        bcast_hwaddr_arr = g_bytes_get_data(bcast_hwaddr, &bcast_hwaddr_len);
        if (bcast_hwaddr_len != hwaddr_len)
            bcast_hwaddr_arr = NULL;
    }

    r = sd_dhcp_client_set_mac(sd_client,
                               hwaddr_arr,
                               bcast_hwaddr_arr,
                               hwaddr_len,
                               (guint16) arp_type);
    if (r < 0) {
        nm_utils_error_set_errno(error, r, "failed to set MAC address: %s");
        return FALSE;
    }

    r = sd_dhcp_client_set_ifindex(sd_client, nm_dhcp_client_get_ifindex(client));
    if (r < 0) {
        nm_utils_error_set_errno(error, r, "failed to set ifindex: %s");
        return FALSE;
    }

    nm_dhcp_utils_get_leasefile_path(AF_INET,
                                     "internal",
                                     client_config->iface,
                                     client_config->uuid,
                                     &lease_file);

    if (client_config->v4.last_address)
        inet_pton(AF_INET, client_config->v4.last_address, &last_addr);
    else {
        nm_auto(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;

        dhcp_lease_load(&lease, lease_file);
        if (lease)
            sd_dhcp_lease_get_address(lease, &last_addr);
    }

    r = sd_dhcp_client_set_request_broadcast(sd_client, client_config->v4.request_broadcast);
    nm_assert(r >= 0);

    if (last_addr.s_addr) {
        r = sd_dhcp_client_set_request_address(sd_client, &last_addr);
        if (r < 0) {
            nm_utils_error_set_errno(error, r, "failed to set last IPv4 address: %s");
            return FALSE;
        }
    }

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

    /* Note that we always set a client-id. In particular for infiniband that is necessary,
     * see https://tools.ietf.org/html/rfc4390#section-2.1 . */
    r = sd_dhcp_client_set_client_id(sd_client,
                                     client_id_arr[0],
                                     client_id_arr + 1,
                                     NM_MIN(client_id_len - 1, _NM_MAX_CLIENT_ID_LEN));
    if (r < 0) {
        nm_utils_error_set_errno(error, r, "failed to set IPv4 client-id: %s");
        return FALSE;
    }

    /* Add requested options */
    for (i = 0; i < (int) G_N_ELEMENTS(_nm_dhcp_option_dhcp4_options); i++) {
        if (_nm_dhcp_option_dhcp4_options[i].include) {
            nm_assert(_nm_dhcp_option_dhcp4_options[i].option_num <= 255);
            r = sd_dhcp_client_set_request_option(sd_client,
                                                  _nm_dhcp_option_dhcp4_options[i].option_num);
            nm_assert(r >= 0 || r == -EEXIST);
        }
    }

    hostname = client_config->hostname;
    if (hostname) {
        /* FIXME: sd-dhcp decides which hostname/FQDN option to send (12 or 81)
         * only based on whether the hostname has a domain part or not. At the
         * moment there is no way to force one or another.
         */
        r = sd_dhcp_client_set_hostname(sd_client, hostname);
        if (r < 0) {
            nm_utils_error_set_errno(error, r, "failed to set DHCP hostname: %s");
            return FALSE;
        }
    }

    mud_url = client_config->mud_url;
    if (mud_url) {
        r = sd_dhcp_client_set_mud_url(sd_client, mud_url);
        if (r < 0) {
            nm_utils_error_set_errno(error, r, "failed to set DHCP MUDURL: %s");
            return FALSE;
        }
    }

    vendor_class_identifier = client_config->vendor_class_identifier;
    if (vendor_class_identifier) {
        const char *option_data;
        gsize       len;

        option_data = g_bytes_get_data(vendor_class_identifier, &len);
        nm_assert(option_data);
        nm_assert(len <= 255);

        option_data = nm_strndup_a(300, option_data, len, NULL);

        r = sd_dhcp_client_set_vendor_class_identifier(sd_client, option_data);
        if (r < 0) {
            nm_utils_error_set_errno(error, r, "failed to set DHCP vendor class identifier: %s");
            return FALSE;
        }
    }

    r = sd_dhcp_client_set_callback(sd_client, dhcp_event_cb, client);
    if (r < 0) {
        nm_utils_error_set_errno(error, r, "failed to set callback: %s");
        return FALSE;
    }

    priv->client4 = g_steal_pointer(&sd_client);

    g_free(priv->lease_file);
    priv->lease_file = g_steal_pointer(&lease_file);

    nm_dhcp_client_set_effective_client_id(client, client_id);

    r = sd_dhcp_client_start(priv->client4);
    if (r < 0) {
        sd_dhcp_client_set_callback(priv->client4, NULL, NULL);
        nm_clear_pointer(&priv->client4, sd_dhcp_client_unref);
        nm_utils_error_set_errno(error, r, "failed to start DHCP client: %s");
        return FALSE;
    }

    nm_dhcp_client_start_timeout(client);
    return TRUE;
}

static NML3ConfigData *
lease_to_ip6_config(NMDedupMultiIndex *multi_idx,
                    const char *       iface,
                    int                ifindex,
                    sd_dhcp6_lease *   lease,
                    gboolean           info_only,
                    gint32             ts,
                    GError **          error)
{
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
    gs_unref_hashtable GHashTable *options       = NULL;
    struct in6_addr                tmp_addr;
    const struct in6_addr *        dns;
    uint32_t                       lft_pref, lft_valid;
    char                           addr_str[NM_UTILS_INET_ADDRSTRLEN];
    char **                        domains;
    const char *                   s;
    nm_auto_free_gstring GString *str               = NULL;
    gboolean                      has_any_addresses = FALSE;
    int                           num, i;

    nm_assert(lease);

    l3cd = nm_l3_config_data_new(multi_idx, ifindex, NM_IP_CONFIG_SOURCE_DHCP);

    options = nm_dhcp_option_create_options_dict();

    sd_dhcp6_lease_reset_address_iter(lease);
    nm_gstring_prepare(&str);
    while (sd_dhcp6_lease_get_address(lease, &tmp_addr, &lft_pref, &lft_valid) >= 0) {
        const NMPlatformIP6Address address = {
            .plen        = 128,
            .address     = tmp_addr,
            .timestamp   = ts,
            .lifetime    = lft_valid,
            .preferred   = lft_pref,
            .addr_source = NM_IP_CONFIG_SOURCE_DHCP,
        };

        nm_l3_config_data_add_address_6(l3cd, &address);

        _nm_utils_inet6_ntop(&tmp_addr, addr_str);
        g_string_append(nm_gstring_add_space_delimiter(str), addr_str);

        has_any_addresses = TRUE;
    }

    if (str->len) {
        nm_dhcp_option_add_option(options, AF_INET6, NM_DHCP_OPTION_DHCP6_NM_IP_ADDRESS, str->str);
    }

    if (!info_only && !has_any_addresses) {
        g_set_error_literal(error,
                            NM_MANAGER_ERROR,
                            NM_MANAGER_ERROR_FAILED,
                            "no address received in managed mode");
        return NULL;
    }

    num = sd_dhcp6_lease_get_dns(lease, &dns);
    if (num > 0) {
        nm_gstring_prepare(&str);
        for (i = 0; i < num; i++) {
            _nm_utils_inet6_ntop(&dns[i], addr_str);
            g_string_append(nm_gstring_add_space_delimiter(str), addr_str);
            nm_l3_config_data_add_nameserver(l3cd, AF_INET6, &dns[i]);
        }
        nm_dhcp_option_add_option(options, AF_INET6, NM_DHCP_OPTION_DHCP6_DNS_SERVERS, str->str);
    }

    num = sd_dhcp6_lease_get_domains(lease, &domains);
    if (num > 0) {
        nm_gstring_prepare(&str);
        for (i = 0; i < num; i++) {
            g_string_append(nm_gstring_add_space_delimiter(str), domains[i]);
            nm_l3_config_data_add_search(l3cd, AF_INET6, domains[i]);
        }
        nm_dhcp_option_add_option(options, AF_INET6, NM_DHCP_OPTION_DHCP6_DOMAIN_LIST, str->str);
    }

    if (sd_dhcp6_lease_get_fqdn(lease, &s) >= 0) {
        nm_dhcp_option_add_option(options, AF_INET6, NM_DHCP_OPTION_DHCP6_FQDN, s);
    }

    nm_l3_config_data_set_dhcp_lease_from_options(l3cd, AF_INET6, g_steal_pointer(&options));

    return g_steal_pointer(&l3cd);
}

static void
bound6_handle(NMDhcpSystemd *self)
{
    NMDhcpSystemdPrivate *    priv  = NM_DHCP_SYSTEMD_GET_PRIVATE(self);
    const gint32              ts    = nm_utils_get_monotonic_timestamp_sec();
    const char *              iface = nm_dhcp_client_get_iface(NM_DHCP_CLIENT(self));
    const NMDhcpClientConfig *client_config;
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
    gs_free_error GError *error                  = NULL;
    NMPlatformIP6Address  prefix                 = {0};
    sd_dhcp6_lease *      lease                  = NULL;

    client_config = nm_dhcp_client_get_config(NM_DHCP_CLIENT(self));

    if (sd_dhcp6_client_get_lease(priv->client6, &lease) < 0 || !lease) {
        _LOGW(" no lease!");
        nm_dhcp_client_set_state(NM_DHCP_CLIENT(self), NM_DHCP_STATE_FAIL, NULL);
        return;
    }

    _LOGD("lease available");

    l3cd = lease_to_ip6_config(nm_dhcp_client_get_multi_idx(NM_DHCP_CLIENT(self)),
                               iface,
                               nm_dhcp_client_get_ifindex(NM_DHCP_CLIENT(self)),
                               lease,
                               client_config->v6.info_only,
                               ts,
                               &error);

    if (!l3cd) {
        _LOGW("%s", error->message);
        nm_dhcp_client_set_state(NM_DHCP_CLIENT(self), NM_DHCP_STATE_FAIL, NULL);
        return;
    }

    nm_dhcp_client_set_state(NM_DHCP_CLIENT(self), NM_DHCP_STATE_BOUND, l3cd);

    sd_dhcp6_lease_reset_pd_prefix_iter(lease);
    while (!sd_dhcp6_lease_get_pd(lease,
                                  &prefix.address,
                                  &prefix.plen,
                                  &prefix.preferred,
                                  &prefix.lifetime)) {
        prefix.timestamp = ts;
        nm_dhcp_client_emit_ipv6_prefix_delegated(NM_DHCP_CLIENT(self), &prefix);
    }
}

static void
dhcp6_event_cb(sd_dhcp6_client *client, int event, gpointer user_data)
{
    NMDhcpSystemd *       self = NM_DHCP_SYSTEMD(user_data);
    NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE(self);

    nm_assert(priv->client6 == client);

    _LOGD("client event %d", event);

    switch (event) {
    case SD_DHCP6_CLIENT_EVENT_RETRANS_MAX:
        nm_dhcp_client_set_state(NM_DHCP_CLIENT(user_data), NM_DHCP_STATE_TIMEOUT, NULL);
        break;
    case SD_DHCP6_CLIENT_EVENT_RESEND_EXPIRE:
    case SD_DHCP6_CLIENT_EVENT_STOP:
        nm_dhcp_client_set_state(NM_DHCP_CLIENT(user_data), NM_DHCP_STATE_FAIL, NULL);
        break;
    case SD_DHCP6_CLIENT_EVENT_IP_ACQUIRE:
    case SD_DHCP6_CLIENT_EVENT_INFORMATION_REQUEST:
        bound6_handle(self);
        break;
    default:
        _LOGW("unhandled event %d", event);
        break;
    }
}

static gboolean
ip6_start(NMDhcpClient *client, GError **error)
{
    NMDhcpSystemd *                                  self      = NM_DHCP_SYSTEMD(client);
    NMDhcpSystemdPrivate *                           priv      = NM_DHCP_SYSTEMD_GET_PRIVATE(self);
    nm_auto(sd_dhcp6_client_unrefp) sd_dhcp6_client *sd_client = NULL;
    const NMDhcpClientConfig *                       client_config;
    const char *                                     hostname;
    const char *                                     mud_url;
    int                                              r, i;
    const guint8 *                                   duid_arr;
    gsize                                            duid_len;
    GBytes *                                         duid;

    g_return_val_if_fail(!priv->client4, FALSE);
    g_return_val_if_fail(!priv->client6, FALSE);

    client_config = nm_dhcp_client_get_config(client);

    /* TODO: honor nm_dhcp_client_get_anycast_address() */

    duid = nm_dhcp_client_get_effective_client_id(client);
    if (!duid || !(duid_arr = g_bytes_get_data(duid, &duid_len)) || duid_len < 2) {
        nm_utils_error_set_literal(error, NM_UTILS_ERROR_UNKNOWN, "missing DUID");
        g_return_val_if_reached(FALSE);
    }

    r = sd_dhcp6_client_new(&sd_client);
    if (r < 0) {
        nm_utils_error_set_errno(error, r, "failed to create dhcp-client: %s");
        return FALSE;
    }

    _LOGT("dhcp-client6: set %p", sd_client);

    if (client_config->v6.info_only) {
        sd_dhcp6_client_set_address_request(sd_client, 0);
        if (client_config->v6.needed_prefixes == 0)
            sd_dhcp6_client_set_information_request(sd_client, 1);
    }

    r = sd_dhcp6_client_set_iaid(sd_client, client_config->v6.iaid);
    if (r < 0) {
        nm_utils_error_set_errno(error, r, "failed to set IAID: %s");
        return FALSE;
    }

    r = sd_dhcp6_client_set_duid(sd_client,
                                 unaligned_read_be16(&duid_arr[0]),
                                 &duid_arr[2],
                                 duid_len - 2);
    if (r < 0) {
        nm_utils_error_set_errno(error, r, "failed to set DUID: %s");
        return FALSE;
    }

    r = sd_dhcp6_client_attach_event(sd_client, NULL, 0);
    if (r < 0) {
        nm_utils_error_set_errno(error, r, "failed to attach event: %s");
        return FALSE;
    }

    r = sd_dhcp6_client_set_ifindex(sd_client, nm_dhcp_client_get_ifindex(client));
    if (r < 0) {
        nm_utils_error_set_errno(error, r, "failed to set ifindex: %s");
        return FALSE;
    }

    /* Add requested options */
    for (i = 0; i < (int) G_N_ELEMENTS(_nm_dhcp_option_dhcp6_options); i++) {
        if (_nm_dhcp_option_dhcp6_options[i].include) {
            r = sd_dhcp6_client_set_request_option(sd_client,
                                                   _nm_dhcp_option_dhcp6_options[i].option_num);
            nm_assert(r >= 0 || r == -EEXIST);
        }
    }

    mud_url = client_config->mud_url;
    if (mud_url) {
        r = sd_dhcp6_client_set_request_mud_url(sd_client, mud_url);
        if (r < 0) {
            nm_utils_error_set_errno(error, r, "failed to set mud-url: %s");
            return FALSE;
        }
    }

    if (client_config->v6.needed_prefixes > 0) {
        if (client_config->v6.needed_prefixes > 1)
            _LOGW("dhcp-client6: only one prefix request is supported");
        /* FIXME: systemd-networkd API only allows to request a
         * single prefix */
        r = sd_dhcp6_client_set_prefix_delegation(sd_client, TRUE);
        if (r < 0) {
            nm_utils_error_set_errno(error, r, "failed to enable prefix delegation: %s");
            return FALSE;
        }
    }

    r = sd_dhcp6_client_set_local_address(sd_client, client_config->v6.ll_addr);
    if (r < 0) {
        nm_utils_error_set_errno(error, r, "failed to set local address: %s");
        return FALSE;
    }

    hostname = client_config->hostname;
    r        = sd_dhcp6_client_set_fqdn(sd_client, hostname);
    if (r < 0) {
        nm_utils_error_set_errno(error, r, "failed to set DHCP hostname: %s");
        return FALSE;
    }

    r = sd_dhcp6_client_set_callback(sd_client, dhcp6_event_cb, client);
    if (r < 0) {
        nm_utils_error_set_errno(error, r, "failed to set callback: %s");
        return FALSE;
    }

    priv->client6 = g_steal_pointer(&sd_client);

    r = sd_dhcp6_client_start(priv->client6);
    if (r < 0) {
        sd_dhcp6_client_set_callback(priv->client6, NULL, NULL);
        nm_clear_pointer(&priv->client6, sd_dhcp6_client_unref);
        nm_utils_error_set_errno(error, r, "failed to start client: %s");
        return FALSE;
    }

    nm_dhcp_client_start_timeout(client);
    return TRUE;
}

static void
stop(NMDhcpClient *client, gboolean release)
{
    NMDhcpSystemd *       self = NM_DHCP_SYSTEMD(client);
    NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE(self);
    int                   r    = 0;

    NM_DHCP_CLIENT_CLASS(nm_dhcp_systemd_parent_class)->stop(client, release);

    _LOGT("dhcp-client%d: stop %p",
          priv->client4 ? '4' : '6',
          priv->client4 ? (gpointer) priv->client4 : (gpointer) priv->client6);

    if (priv->client4) {
        sd_dhcp_client_set_callback(priv->client4, NULL, NULL);
        r = sd_dhcp_client_stop(priv->client4);
    } else if (priv->client6) {
        sd_dhcp6_client_set_callback(priv->client6, NULL, NULL);
        r = sd_dhcp6_client_stop(priv->client6);
    }

    if (r)
        _LOGW("failed to stop client (%d)", r);
}

/*****************************************************************************/

static void
nm_dhcp_systemd_init(NMDhcpSystemd *self)
{}

static void
dispose(GObject *object)
{
    NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE(object);

    nm_clear_g_free(&priv->lease_file);

    if (priv->client4) {
        sd_dhcp_client_stop(priv->client4);
        sd_dhcp_client_unref(priv->client4);
        priv->client4 = NULL;
    }

    if (priv->client6) {
        sd_dhcp6_client_stop(priv->client6);
        sd_dhcp6_client_unref(priv->client6);
        priv->client6 = NULL;
    }

    G_OBJECT_CLASS(nm_dhcp_systemd_parent_class)->dispose(object);
}

static void
nm_dhcp_systemd_class_init(NMDhcpSystemdClass *sdhcp_class)
{
    NMDhcpClientClass *client_class = NM_DHCP_CLIENT_CLASS(sdhcp_class);
    GObjectClass *     object_class = G_OBJECT_CLASS(sdhcp_class);

    object_class->dispose = dispose;

    client_class->ip4_start = ip4_start;
    client_class->ip6_start = ip6_start;
    client_class->stop      = stop;
}

const NMDhcpClientFactory _nm_dhcp_client_factory_systemd = {
    .name         = "systemd",
    .get_type_4   = nm_dhcp_systemd_get_type,
    .get_type_6   = nm_dhcp_systemd_get_type,
    .undocumented = TRUE,
};

/*****************************************************************************/

const NMDhcpClientFactory _nm_dhcp_client_factory_internal = {
    .name       = "internal",
    .get_type_4 = nm_dhcp_nettools_get_type,
    .get_type_6 = nm_dhcp_systemd_get_type,
};
