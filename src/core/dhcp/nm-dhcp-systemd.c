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

/*****************************************************************************/

#define NM_TYPE_DHCP_SYSTEMD (nm_dhcp_systemd_get_type())
#define NM_DHCP_SYSTEMD(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DHCP_SYSTEMD, NMDhcpSystemd))
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
    sd_dhcp6_client *client6;
    char            *lease_file;

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
lease_to_ip6_config(NMDhcpSystemd *self, sd_dhcp6_lease *lease, gint32 ts, GError **error)
{
    const NMDhcpClientConfig               *config;
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd    = NULL;
    gs_unref_hashtable GHashTable          *options = NULL;
    struct in6_addr                         tmp_addr;
    const struct in6_addr                  *dns;
    char                                    addr_str[NM_INET_ADDRSTRLEN];
    char                                    iaid_buf[NM_DHCP_IAID_TO_HEXSTR_BUF_LEN];
    char                                  **domains;
    char                                  **ntp_fqdns;
    const struct in6_addr                  *ntp_addrs;
    const char                             *s;
    nm_auto_free_gstring GString           *str = NULL;
    int                                     num, i;

    nm_assert(lease);

    config = nm_dhcp_client_get_config(NM_DHCP_CLIENT(self));

    l3cd = nm_dhcp_client_create_l3cd(NM_DHCP_CLIENT(self));

    options = nm_dhcp_client_create_options_dict(NM_DHCP_CLIENT(self), TRUE);

    nm_dhcp_option_add_option(options,
                              TRUE,
                              AF_INET6,
                              NM_DHCP_OPTION_DHCP6_NM_IAID,
                              nm_dhcp_iaid_to_hexstr(config->v6.iaid, iaid_buf));

    if (!config->v6.info_only) {
        gboolean has_any_addresses = FALSE;
        uint32_t lft_pref;
        uint32_t lft_valid;

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

            nm_inet6_ntop(&tmp_addr, addr_str);
            g_string_append(nm_gstring_add_space_delimiter(str), addr_str);

            has_any_addresses = TRUE;
        }

        if (str->len) {
            nm_dhcp_option_add_option(options,
                                      TRUE,
                                      AF_INET6,
                                      NM_DHCP_OPTION_DHCP6_NM_IP_ADDRESS,
                                      str->str);
        }

        if (!has_any_addresses) {
            g_set_error_literal(error,
                                NM_MANAGER_ERROR,
                                NM_MANAGER_ERROR_FAILED,
                                "no address received in managed mode");
            return NULL;
        }
    }

    num = sd_dhcp6_lease_get_dns(lease, &dns);
    if (num > 0) {
        nm_gstring_prepare(&str);
        for (i = 0; i < num; i++) {
            nm_inet6_ntop(&dns[i], addr_str);
            g_string_append(nm_gstring_add_space_delimiter(str), addr_str);
            nm_l3_config_data_add_nameserver_detail(l3cd, AF_INET6, &dns[i], NULL);
        }
        nm_dhcp_option_add_option(options,
                                  TRUE,
                                  AF_INET6,
                                  NM_DHCP_OPTION_DHCP6_DNS_SERVERS,
                                  str->str);
    }

    {
        struct in6_addr prefix;
        uint8_t         prefix_len;

        nm_gstring_prepare(&str);
        sd_dhcp6_lease_reset_pd_prefix_iter(lease);
        while (!sd_dhcp6_lease_get_pd(lease, &prefix, &prefix_len, NULL, NULL)) {
            nm_gstring_add_space_delimiter(str);
            nm_inet6_ntop(&prefix, addr_str);
            g_string_append_printf(str, "%s/%u", addr_str, prefix_len);
        }
        if (str->len > 0) {
            nm_dhcp_option_add_option(options,
                                      TRUE,
                                      AF_INET6,
                                      NM_DHCP_OPTION_DHCP6_IA_PD,
                                      str->str);
        }
    }

    num = sd_dhcp6_lease_get_domains(lease, &domains);
    if (num > 0) {
        nm_gstring_prepare(&str);
        for (i = 0; i < num; i++) {
            g_string_append(nm_gstring_add_space_delimiter(str), domains[i]);
            nm_l3_config_data_add_search(l3cd, AF_INET6, domains[i]);
        }
        nm_dhcp_option_add_option(options,
                                  TRUE,
                                  AF_INET6,
                                  NM_DHCP_OPTION_DHCP6_DOMAIN_LIST,
                                  str->str);
    }

    if (sd_dhcp6_lease_get_fqdn(lease, &s) >= 0) {
        nm_dhcp_option_add_option(options, TRUE, AF_INET6, NM_DHCP_OPTION_DHCP6_FQDN, s);
    }

    /* RFC 5908, section 4 states: "This option MUST include one, and only
     * one, time source suboption." It is not clear why systemd chose to
     * return array of addresses and FQDNs. Given there seem to be no
     * technical obstacles to including multiple options, let's just
     * pass on whatever systemd tells us.
     */
    nm_gstring_prepare(&str);
    num = sd_dhcp6_lease_get_ntp_fqdn(lease, &ntp_fqdns);
    if (num > 0) {
        for (i = 0; i < num; i++) {
            g_string_append(nm_gstring_add_space_delimiter(str), ntp_fqdns[i]);
        }
    }
    num = sd_dhcp6_lease_get_ntp_addrs(lease, &ntp_addrs);
    if (num > 0) {
        for (i = 0; i < num; i++) {
            nm_inet6_ntop(&ntp_addrs[i], addr_str);
            g_string_append(nm_gstring_add_space_delimiter(str), addr_str);
        }
    }
    if (str->len) {
        nm_dhcp_option_add_option(options,
                                  TRUE,
                                  AF_INET6,
                                  NM_DHCP_OPTION_DHCP6_NTP_SERVER,
                                  str->str);
    }

    nm_l3_config_data_set_dhcp_lease_from_options(l3cd, AF_INET6, g_steal_pointer(&options));

    return g_steal_pointer(&l3cd);
}

static void
bound6_handle(NMDhcpSystemd *self)
{
    NMDhcpSystemdPrivate                   *priv   = NM_DHCP_SYSTEMD_GET_PRIVATE(self);
    const gint32                            ts     = nm_utils_get_monotonic_timestamp_sec();
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd   = NULL;
    gs_free_error GError                   *error  = NULL;
    NMPlatformIP6Address                    prefix = {0};
    sd_dhcp6_lease                         *lease  = NULL;

    if (sd_dhcp6_client_get_lease(priv->client6, &lease) < 0 || !lease) {
        _LOGW(" no lease!");
        _nm_dhcp_client_notify(NM_DHCP_CLIENT(self), NM_DHCP_CLIENT_EVENT_TYPE_FAIL, NULL);
        return;
    }

    _LOGD("lease available");

    l3cd = lease_to_ip6_config(self, lease, ts, &error);

    if (!l3cd) {
        _LOGW("%s", error->message);
        _nm_dhcp_client_notify(NM_DHCP_CLIENT(self), NM_DHCP_CLIENT_EVENT_TYPE_FAIL, NULL);
        return;
    }

    _nm_dhcp_client_notify(NM_DHCP_CLIENT(self), NM_DHCP_CLIENT_EVENT_TYPE_BOUND, l3cd);

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
    NMDhcpSystemd        *self = NM_DHCP_SYSTEMD(user_data);
    NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE(self);

    nm_assert(priv->client6 == client);

    _LOGD("client event %d", event);

    switch (event) {
    case SD_DHCP6_CLIENT_EVENT_RETRANS_MAX:
        _nm_dhcp_client_notify(NM_DHCP_CLIENT(user_data), NM_DHCP_CLIENT_EVENT_TYPE_TIMEOUT, NULL);
        break;
    case SD_DHCP6_CLIENT_EVENT_RESEND_EXPIRE:
    case SD_DHCP6_CLIENT_EVENT_STOP:
        _nm_dhcp_client_notify(NM_DHCP_CLIENT(user_data), NM_DHCP_CLIENT_EVENT_TYPE_FAIL, NULL);
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
ip6_start(NMDhcpClient *client, const struct in6_addr *ll_addr, GError **error)
{
    NMDhcpSystemd                                   *self      = NM_DHCP_SYSTEMD(client);
    NMDhcpSystemdPrivate                            *priv      = NM_DHCP_SYSTEMD_GET_PRIVATE(self);
    nm_auto(sd_dhcp6_client_unrefp) sd_dhcp6_client *sd_client = NULL;
    const NMDhcpClientConfig                        *client_config;
    const char                                      *hostname;
    const char                                      *mud_url;
    int                                              r, i;
    const guint8                                    *duid_arr;
    gsize                                            duid_len;
    GBytes                                          *duid;
    gboolean                                         prefix_delegation;

    g_return_val_if_fail(!priv->client6, FALSE);

    client_config = nm_dhcp_client_get_config(client);

    /* TODO: honor nm_dhcp_client_get_anycast_address() */

    duid = client_config->client_id;
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

    sd_dhcp6_client_set_address_request(sd_client, !client_config->v6.info_only);
    sd_dhcp6_client_set_information_request(sd_client,
                                            client_config->v6.info_only
                                                && client_config->v6.needed_prefixes == 0);

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

    prefix_delegation = FALSE;
    if (client_config->v6.needed_prefixes > 0) {
        if (client_config->v6.needed_prefixes > 1) {
            /* FIXME: systemd-networkd API only allows to request a
             * single prefix */
            _LOGW("dhcp-client6: only one prefix request is supported");
        }
        prefix_delegation = TRUE;
        if (client_config->v6.pd_hint_length > 0) {
            r = sd_dhcp6_client_set_prefix_delegation_hint(sd_client,
                                                           client_config->v6.pd_hint_length,
                                                           &client_config->v6.pd_hint_addr);
            if (r < 0) {
                nm_utils_error_set_errno(error, r, "failed to set prefix delegation hint: %s");
                return FALSE;
            }
        }
    }
    r = sd_dhcp6_client_set_prefix_delegation(sd_client, prefix_delegation);
    if (r < 0) {
        nm_utils_error_set_errno(error, r, "failed to enable prefix delegation: %s");
        return FALSE;
    }

    r = sd_dhcp6_client_set_local_address(sd_client, ll_addr);
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

    nm_dhcp_client_set_effective_client_id(client, duid);

    return TRUE;
}

static void
stop(NMDhcpClient *client, gboolean release)
{
    NMDhcpSystemd        *self = NM_DHCP_SYSTEMD(client);
    NMDhcpSystemdPrivate *priv = NM_DHCP_SYSTEMD_GET_PRIVATE(self);
    int                   r    = 0;

    NM_DHCP_CLIENT_CLASS(nm_dhcp_systemd_parent_class)->stop(client, release);

    _LOGT("dhcp-client6: stop");

    if (!priv->client6)
        return;

    sd_dhcp6_client_set_callback(priv->client6, NULL, NULL);
    r = sd_dhcp6_client_stop(priv->client6);
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
    GObjectClass      *object_class = G_OBJECT_CLASS(sdhcp_class);

    object_class->dispose = dispose;

    client_class->ip6_start = ip6_start;
    client_class->stop      = stop;
}

const NMDhcpClientFactory _nm_dhcp_client_factory_systemd = {
    .name         = "systemd",
    .get_type_4   = nm_dhcp_nettools_get_type,
    .get_type_6   = nm_dhcp_systemd_get_type,
    .undocumented = TRUE,
};

/*****************************************************************************/

const NMDhcpClientFactory _nm_dhcp_client_factory_internal = {
    .name       = "internal",
    .get_type_4 = nm_dhcp_nettools_get_type,
    .get_type_6 = nm_dhcp_systemd_get_type,
};
