/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2024 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-initrd-generator.h"

#if WITH_NBFT

#include <libnvme.h>

#include "libnm-log-core/nm-logging.h"
#include "libnm-core-intern/nm-core-internal.h"

/*****************************************************************************/

#define _NMLOG(level, domain, ...) \
    nm_log((level),                \
           (domain),               \
           NULL,                   \
           NULL,                   \
           "nbft-reader: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__) _NM_UTILS_MACRO_REST(__VA_ARGS__))

/*****************************************************************************/

static inline gboolean
is_valid_addr(int family, const char *addr)
{
    return (addr && strlen(addr) > 0 && !nm_streq(addr, "0.0.0.0") && !nm_streq(addr, "::")
            && nm_utils_ipaddr_valid(family, addr));
}

static NMConnection *
parse_hfi(struct nbft_info_hfi *hfi, int iface_idx, char **hostname)
{
    gs_unref_object NMConnection         *connection;
    NMSetting                            *s_connection;
    NMSetting                            *s_wired;
    gs_free char                         *hwaddr = NULL;
    gs_free char                         *ifname = NULL;
    gs_unref_object NMSetting            *s_ip4  = NULL;
    gs_unref_object NMSetting            *s_ip6  = NULL;
    nm_auto_unref_ip_address NMIPAddress *ipaddr = NULL;
    gs_free_error GError                 *error  = NULL;
    int                                   family = AF_UNSPEC;
    NMIPAddr                              addr_bin;

    /* Pre-checks */
    if (!nm_inet_parse_bin_full(family, FALSE, hfi->tcp_info.ipaddr, &family, &addr_bin)) {
        _LOGW(LOGD_CORE, "NBFT: Malformed IP address: '%s'", hfi->tcp_info.ipaddr);
        return NULL;
    }

    ifname = g_strdup_printf("NBFT connection %d", iface_idx);
    hwaddr = g_strdup_printf("%02x:%02x:%02x:%02x:%02x:%02x",
                             hfi->tcp_info.mac_addr[0],
                             hfi->tcp_info.mac_addr[1],
                             hfi->tcp_info.mac_addr[2],
                             hfi->tcp_info.mac_addr[3],
                             hfi->tcp_info.mac_addr[4],
                             hfi->tcp_info.mac_addr[5]);

    /* Create new connection */
    connection = nm_simple_connection_new();

    s_connection = nm_setting_connection_new();
    g_object_set(s_connection,
                 NM_SETTING_CONNECTION_TYPE,
                 NM_SETTING_WIRED_SETTING_NAME,
                 NM_SETTING_CONNECTION_ID,
                 ifname,
                 NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY,
                 NMI_AUTOCONNECT_PRIORITY_FIRMWARE,
                 NULL);
    nm_connection_add_setting(connection, s_connection);

    /* MAC address */
    s_wired = nm_setting_wired_new();
    g_object_set(s_wired, NM_SETTING_WIRED_MAC_ADDRESS, hwaddr, NULL);
    nm_connection_add_setting(connection, s_wired);

    /* TODO: hfi->tcp_info.vlan */

    /* IP addresses */
    s_ip4 = nm_setting_ip4_config_new();
    s_ip6 = nm_setting_ip6_config_new();

    switch (family) {
    /* IPv4 */
    case AF_INET:
        g_object_set(s_ip6,
                     NM_SETTING_IP_CONFIG_METHOD,
                     NM_SETTING_IP6_CONFIG_METHOD_DISABLED,
                     NULL);
        if (is_valid_addr(AF_INET, hfi->tcp_info.dhcp_server_ipaddr)) {
            g_object_set(s_ip4,
                         NM_SETTING_IP_CONFIG_METHOD,
                         NM_SETTING_IP4_CONFIG_METHOD_AUTO,
                         NULL);
            if (hfi->tcp_info.host_name && strlen(hfi->tcp_info.host_name) > 0) {
                g_object_set(s_ip4,
                             NM_SETTING_IP_CONFIG_DHCP_HOSTNAME,
                             hfi->tcp_info.host_name,
                             NULL);
            }
        } else {
            g_object_set(s_ip4,
                         NM_SETTING_IP_CONFIG_METHOD,
                         NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
                         NULL);
            ipaddr = nm_ip_address_new_binary(AF_INET,
                                              &addr_bin,
                                              hfi->tcp_info.subnet_mask_prefix,
                                              &error);
            if (!ipaddr) {
                _LOGW(LOGD_CORE,
                      "Cannot parse IP %s/%u: %s",
                      hfi->tcp_info.ipaddr,
                      hfi->tcp_info.subnet_mask_prefix,
                      error->message);
                return NULL;
            }
            nm_setting_ip_config_add_address(NM_SETTING_IP_CONFIG(s_ip4), ipaddr);
            if (is_valid_addr(AF_INET, hfi->tcp_info.gateway_ipaddr)) {
                g_object_set(s_ip4,
                             NM_SETTING_IP_CONFIG_GATEWAY,
                             hfi->tcp_info.gateway_ipaddr,
                             NULL);
            }
            if (is_valid_addr(AF_INET, hfi->tcp_info.primary_dns_ipaddr)) {
                nm_setting_ip_config_add_dns(NM_SETTING_IP_CONFIG(s_ip4),
                                             hfi->tcp_info.primary_dns_ipaddr);
            }
            if (is_valid_addr(AF_INET, hfi->tcp_info.secondary_dns_ipaddr)) {
                nm_setting_ip_config_add_dns(NM_SETTING_IP_CONFIG(s_ip4),
                                             hfi->tcp_info.secondary_dns_ipaddr);
            }
        }
        break;

    /* IPv6 */
    case AF_INET6:
        g_object_set(s_ip4,
                     NM_SETTING_IP_CONFIG_METHOD,
                     NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
                     NULL);
        if (is_valid_addr(AF_INET6, hfi->tcp_info.dhcp_server_ipaddr)) {
            g_object_set(s_ip6,
                         NM_SETTING_IP_CONFIG_METHOD,
                         NM_SETTING_IP6_CONFIG_METHOD_AUTO,
                         NULL);
            if (hfi->tcp_info.host_name && strlen(hfi->tcp_info.host_name) > 0) {
                g_object_set(s_ip6,
                             NM_SETTING_IP_CONFIG_DHCP_HOSTNAME,
                             hfi->tcp_info.host_name,
                             NULL);
            }
        } else {
            g_object_set(s_ip6,
                         NM_SETTING_IP_CONFIG_METHOD,
                         NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
                         NULL);
            /* FIXME: buggy firmware implementations may report prefix=0 for v6 addresses,
             *        reported as https://github.com/timberland-sig/edk2/issues/37
             */
            ipaddr = nm_ip_address_new_binary(AF_INET6,
                                              &addr_bin,
                                              hfi->tcp_info.subnet_mask_prefix,
                                              &error);
            if (!ipaddr) {
                _LOGW(LOGD_CORE,
                      "Cannot parse IP %s/%u: %s",
                      hfi->tcp_info.ipaddr,
                      prefix,
                      error->message);
                return NULL;
            }
            nm_setting_ip_config_add_address(NM_SETTING_IP_CONFIG(s_ip6), ipaddr);
            if (is_valid_addr(AF_INET6, hfi->tcp_info.gateway_ipaddr)) {
                g_object_set(s_ip6,
                             NM_SETTING_IP_CONFIG_GATEWAY,
                             hfi->tcp_info.gateway_ipaddr,
                             NULL);
            }
            if (is_valid_addr(AF_INET6, hfi->tcp_info.primary_dns_ipaddr)) {
                nm_setting_ip_config_add_dns(NM_SETTING_IP_CONFIG(s_ip6),
                                             hfi->tcp_info.primary_dns_ipaddr);
            }
            if (is_valid_addr(AF_INET6, hfi->tcp_info.secondary_dns_ipaddr)) {
                nm_setting_ip_config_add_dns(NM_SETTING_IP_CONFIG(s_ip6),
                                             hfi->tcp_info.secondary_dns_ipaddr);
            }
        }
        break;
    default:
        g_warn_if_reached();
    }

    nm_connection_add_setting(connection, g_steal_pointer(&s_ip4));
    nm_connection_add_setting(connection, g_steal_pointer(&s_ip6));

    /* Hostname */
    if (hfi->tcp_info.host_name && strlen(hfi->tcp_info.host_name) > 0) {
        g_free(*hostname);
        *hostname = g_strdup(hfi->tcp_info.host_name);
    }

    /* TODO: translate the following HFI struct members?
     *         hfi->tcp_info.pci_sbdf
     *         hfi->tcp_info.ip_origin
     *         hfi->tcp_info.dhcp_server_ipaddr
     *         hfi->tcp_info.this_hfi_is_default_route
     *         hfi->tcp_info.dhcp_override
     */

    if (!nm_connection_normalize(connection, NULL, NULL, &error)) {
        _LOGW(LOGD_CORE, "Generated an invalid connection: %s", error->message);
        return NULL;
    }
    return g_steal_pointer(&connection);
}

NMConnection **
nmi_nbft_reader_parse(const char *sysfs_dir, char **hostname)
{
    GPtrArray            *a;
    gs_free char         *path  = NULL;
    gs_free_error GError *error = NULL;
    GDir                 *dir;
    const char           *entry_name;
    int                   idx = 1;

    g_return_val_if_fail(sysfs_dir != NULL, NULL);
    path = g_build_filename(sysfs_dir, "firmware", "acpi", "tables", NULL);

    dir = g_dir_open(path, 0, NULL);
    if (!dir)
        return NULL;

    a = g_ptr_array_new();

    while ((entry_name = g_dir_read_name(dir))) {
        gs_free char          *entry_path = NULL;
        struct nbft_info      *nbft;
        struct nbft_info_hfi **hfi;
        int                    ret;

        if (!g_str_has_prefix(entry_name, "NBFT"))
            continue;

        entry_path = g_build_filename(path, entry_name, NULL);
        ret        = nvme_nbft_read(&nbft, entry_path);
        if (ret) {
            _LOGW(LOGD_CORE, "Error parsing NBFT table %s: %m", entry_path);
            continue;
        }

        for (hfi = nbft->hfi_list; hfi && *hfi; hfi++, idx++) {
            NMConnection *connection;

            if (!nm_streq((*hfi)->transport, "tcp")) {
                _LOGW(LOGD_CORE,
                      "NBFT table %s, HFI descriptor %d: unsupported transport type '%s'",
                      entry_path,
                      (*hfi)->index,
                      (*hfi)->transport);
                continue;
            }

            connection = parse_hfi(*hfi, idx, hostname);
            if (connection)
                g_ptr_array_add(a, connection);
        }

        nvme_nbft_free(nbft);
    }

    g_dir_close(dir);
    g_ptr_array_add(a, NULL); /* trailing NULL-delimiter */
    return (NMConnection **) g_ptr_array_free(a, FALSE);
}

#else /* WITH_NBFT */

NMConnection **
nmi_nbft_reader_parse(const char *sysfs_dir, char **hostname)
{
    return NULL;
}

#endif
