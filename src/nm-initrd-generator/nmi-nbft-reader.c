/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2024 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-initrd-generator.h"

#if WITH_NBFT

#if WITH_NBFT_LIBNVME3
/*
 * libnvme.h of libnvme 3 pulls in the whole command set, but not the NBFT
 * parser.  Include only what is needed here.
 */
#include <nvme/lib.h>
#include <nvme/nbft.h>
#else
#include <libnvme.h>
#endif
#include <dlfcn.h>

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

/*
 * libnvme is loaded at runtime, so that the initrd generator works without
 * it when there is no NBFT. libnvme 3 (nvme-cli 3) renamed the library
 * (libnvme3.so.1), its API, which takes a library context, and the NBFT
 * structures, and reports the HFI Transport Flags (HFITFLAGS) as they are
 * instead of single members for some of them. NM is built for one of the
 * two and loads that one.
 */
#if WITH_NBFT_LIBNVME3

typedef struct libnbft_info nmi_nbft_info;
typedef struct libnbft_hfi  nmi_nbft_hfi;

#define LIBNVME_SONAME "libnvme3.so.1"

static struct libnvme_global_ctx *(*_nvme_create_global_ctx)(void);
static void (*_nvme_free_global_ctx)(struct libnvme_global_ctx *ctx);
static int (*_nvme_read_nbft)(struct libnvme_global_ctx *ctx,
                              struct libnbft_info      **nbft,
                              const char                *filename);
static void (*_nvme_free_nbft)(struct libnvme_global_ctx *ctx, struct libnbft_info *nbft);
static struct libnvme_global_ctx *_nvme_ctx;

static gboolean
hfi_dhcp_override(nmi_nbft_hfi *hfi)
{
    return NM_FLAGS_HAS(hfi->tcp_info.flags, NBFT_HFI_INFO_TCP_DHCP_OVERRIDE);
}

static gboolean
nbft_lib_resolve(void *handle)
{
#if HAVE_DLVSYM
    _nvme_create_global_ctx = dlvsym(handle, "libnvme_create_global_ctx", "LIBNVME_3");
    _nvme_free_global_ctx   = dlvsym(handle, "libnvme_free_global_ctx", "LIBNVME_3");
    _nvme_read_nbft         = dlvsym(handle, "libnvmf_read_nbft", "LIBNVMF_3");
    _nvme_free_nbft         = dlvsym(handle, "libnvmf_free_nbft", "LIBNVMF_3");
#else
    /* no dlvsym() in musl */
    _nvme_create_global_ctx = dlsym(handle, "libnvme_create_global_ctx");
    _nvme_free_global_ctx   = dlsym(handle, "libnvme_free_global_ctx");
    _nvme_read_nbft         = dlsym(handle, "libnvmf_read_nbft");
    _nvme_free_nbft         = dlsym(handle, "libnvmf_free_nbft");
#endif
    if (!_nvme_create_global_ctx || !_nvme_free_global_ctx || !_nvme_read_nbft || !_nvme_free_nbft)
        return FALSE;

    _nvme_ctx = _nvme_create_global_ctx();
    return _nvme_ctx != NULL;
}

static void
nbft_lib_unload(void *handle)
{
    if (_nvme_ctx) {
        _nvme_free_global_ctx(_nvme_ctx);
        _nvme_ctx = NULL;
    }
    dlclose(handle);
}

static int
nbft_read(nmi_nbft_info **nbft, const char *filename)
{
    return _nvme_read_nbft(_nvme_ctx, nbft, filename);
}

static void
nbft_free(nmi_nbft_info *nbft)
{
    _nvme_free_nbft(_nvme_ctx, nbft);
}

#else /* WITH_NBFT_LIBNVME3 */

typedef struct nbft_info     nmi_nbft_info;
typedef struct nbft_info_hfi nmi_nbft_hfi;

#define LIBNVME_SONAME "libnvme.so.1"

static int (*_nvme_nbft_read)(struct nbft_info **nbft, const char *filename);
static void (*_nvme_nbft_free)(struct nbft_info *nbft);

static gboolean
hfi_dhcp_override(nmi_nbft_hfi *hfi)
{
    return hfi->tcp_info.dhcp_override;
}

static gboolean
nbft_lib_resolve(void *handle)
{
#if HAVE_DLVSYM
    _nvme_nbft_read = dlvsym(handle, "nvme_nbft_read", "LIBNVME_1_5");
    _nvme_nbft_free = dlvsym(handle, "nvme_nbft_free", "LIBNVME_1_5");
#else
    /* no dlvsym() in musl */
    _nvme_nbft_read = dlsym(handle, "nvme_nbft_read");
    _nvme_nbft_free = dlsym(handle, "nvme_nbft_free");
#endif
    return _nvme_nbft_read && _nvme_nbft_free;
}

static void
nbft_lib_unload(void *handle)
{
    dlclose(handle);
}

static int
nbft_read(nmi_nbft_info **nbft, const char *filename)
{
    /* libnvme 1 returns 1 and sets errno, libnvme 3 returns -errno */
    if (_nvme_nbft_read(nbft, filename))
        return -errno;
    return 0;
}

static void
nbft_free(nmi_nbft_info *nbft)
{
    _nvme_nbft_free(nbft);
}

#endif /* WITH_NBFT_LIBNVME3 */

static void *
load_libnvme(void)
{
    void *handle;

    handle = dlopen(LIBNVME_SONAME, RTLD_LAZY);
    if (!handle) {
        _LOGW(LOGD_CORE, "NBFT: failed to load %s: %s", LIBNVME_SONAME, dlerror());
        return NULL;
    }

    if (!nbft_lib_resolve(handle)) {
        _LOGW(LOGD_CORE, "NBFT: failed to initialize %s", LIBNVME_SONAME);
        nbft_lib_unload(handle);
        return NULL;
    }
    return handle;
}

static char *
format_conn_name(const char *table_name, nmi_nbft_hfi *hfi, gboolean is_vlan)
{
    if (is_vlan) {
        nm_assert(hfi->tcp_info.vlan > 0);
        return g_strdup_printf("%s connection HFI %d VLAN %d",
                               table_name,
                               hfi->index,
                               hfi->tcp_info.vlan);
    } else
        return g_strdup_printf("%s connection HFI %d", table_name, hfi->index);
}

static NMConnection *
find_conn_for_wired_mac(GPtrArray *a, const char *hwaddr)
{
    guint i;

    for (i = 0; i < a->len; i++) {
        NMConnection   *con = a->pdata[i];
        NMSettingWired *s_wired;

        if (!nm_connection_is_type(con, NM_SETTING_WIRED_SETTING_NAME))
            continue;
        s_wired = nm_connection_get_setting_wired(con);
        if (!s_wired)
            continue;
        if (nm_streq(hwaddr, nm_setting_wired_get_mac_address(s_wired)))
            return con;
    }
    return NULL;
}

static gboolean
hfi_is_dhcp(nmi_nbft_hfi *hfi, int family)
{
    /* There are several flags that may indicate the HFI is set for DHCP
     * per NVM Express® Boot Specification, Revision 1.3. libnvme 1 only
     * exposes the DHCP Override (DHCPO) flag of the HFI Transport Flags
     * (HFITFLAGS), and the IP Origin (IPORIG) value; libnvme 3 has all
     * flags, of which DHCPO is the one used here.
     *
     * The bit 03 of the HFI Transport Flags (HFITFLAGS) is about an advanced
     * stateless mechanism - IPv6-SLAAC and IPv6-ND, stating that "the DHCP
     * Override bit shall be cleared to 0, and the IP Origin field shall
     * be cleared to 0". This nm-initrd-generator will ignore this flag,
     * expecting an IP address to be provided by the usual HFI fields
     * just like in a static adressing case.
     *
     * DHCP Override (DHCPO): "The HFI information was populated by
     * consuming the DHCP on this interface."
     *
     * IP Origin (IPORIG): "If set to 3h (IpPrefixOriginDhcp), then the
     * IP Address was acquired through DHCP, and the IP Address specified
     * in this HFI should not be reused by the OS."
     */
    return hfi_dhcp_override(hfi) || hfi->tcp_info.ip_origin == 3 /* IpPrefixOriginDhcp */
           || is_valid_addr(family, hfi->tcp_info.dhcp_server_ipaddr);
}

static NMConnection *
create_wired_conn(nmi_nbft_hfi *hfi, const char *conn_name, const char *hwaddr, gboolean is_vlan)
{
    NMConnection *connection;
    NMSetting    *s_connection;
    NMSetting    *s_wired;

    connection = nm_simple_connection_new();

    s_connection = nm_setting_connection_new();
    g_object_set(s_connection,
                 NM_SETTING_CONNECTION_TYPE,
                 is_vlan ? NM_SETTING_VLAN_SETTING_NAME : NM_SETTING_WIRED_SETTING_NAME,
                 NM_SETTING_CONNECTION_ID,
                 conn_name,
                 NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY,
                 NMI_AUTOCONNECT_PRIORITY_FIRMWARE,
                 NULL);
    nm_connection_add_setting(connection, s_connection);

    if (hwaddr) {
        /* MAC address */
        s_wired = nm_setting_wired_new();
        g_object_set(s_wired, NM_SETTING_WIRED_MAC_ADDRESS, hwaddr, NULL);
        nm_connection_add_setting(connection, s_wired);
    }

    return connection;
}

static void
parse_hfi(GPtrArray *a, nmi_nbft_hfi *hfi, const char *table_name, char **hostname)
{
    gs_unref_object NMConnection         *connection = NULL;
    NMConnection                         *parent_connection;
    NMSetting                            *s_vlan;
    gs_free char                         *hwaddr    = NULL;
    gs_free char                         *conn_name = NULL;
    gs_unref_object NMSetting            *s_ip4     = NULL;
    gs_unref_object NMSetting            *s_ip6     = NULL;
    NMSettingConnection                  *s_con     = NULL;
    nm_auto_unref_ip_address NMIPAddress *ipaddr    = NULL;
    const char                           *parent_uuid;
    guint                                 prefix;
    gs_free_error GError                 *error  = NULL;
    int                                   family = AF_UNSPEC;
    NMIPAddr                              addr_bin;

    /* Pre-checks */
    if (!nm_inet_parse_bin_full(family, FALSE, hfi->tcp_info.ipaddr, &family, &addr_bin)) {
        _LOGW(LOGD_CORE, "NBFT: Malformed IP address: '%s'", hfi->tcp_info.ipaddr);
        return;
    }

    /* MAC address */
    hwaddr = g_strdup_printf("%02X:%02X:%02X:%02X:%02X:%02X",
                             hfi->tcp_info.mac_addr[0],
                             hfi->tcp_info.mac_addr[1],
                             hfi->tcp_info.mac_addr[2],
                             hfi->tcp_info.mac_addr[3],
                             hfi->tcp_info.mac_addr[4],
                             hfi->tcp_info.mac_addr[5]);

    /* First check if we need VLANs */
    if (hfi->tcp_info.vlan > 0) {
        parent_connection = find_conn_for_wired_mac(a, hwaddr);
        if (!parent_connection) {
            /* Create new parent wired connection */
            conn_name         = format_conn_name(table_name, hfi, FALSE);
            parent_connection = create_wired_conn(hfi, conn_name, hwaddr, FALSE);

            s_ip4 = nm_setting_ip4_config_new();
            s_ip6 = nm_setting_ip6_config_new();
            g_object_set(s_ip4,
                         NM_SETTING_IP_CONFIG_METHOD,
                         NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
                         NULL);
            g_object_set(s_ip6,
                         NM_SETTING_IP_CONFIG_METHOD,
                         NM_SETTING_IP6_CONFIG_METHOD_DISABLED,
                         NULL);
            nm_connection_add_setting(parent_connection, g_steal_pointer(&s_ip4));
            nm_connection_add_setting(parent_connection, g_steal_pointer(&s_ip6));

            if (!nm_connection_normalize(parent_connection, NULL, NULL, &error)) {
                _LOGW(LOGD_CORE, "Generated an invalid connection: %s", error->message);
                g_object_unref(parent_connection);
                return;
            }
            g_ptr_array_add(a, parent_connection);
            nm_clear_g_free(&conn_name);
        }

        conn_name  = format_conn_name(table_name, hfi, TRUE);
        connection = create_wired_conn(hfi, conn_name, NULL, TRUE);

        s_vlan = nm_setting_vlan_new();
        g_object_set(s_vlan, NM_SETTING_VLAN_ID, hfi->tcp_info.vlan, NULL);
        s_con = nm_connection_get_setting_connection(parent_connection);
        nm_assert(s_con);
        parent_uuid = nm_setting_connection_get_uuid(s_con);
        g_object_set(s_vlan, NM_SETTING_VLAN_PARENT, parent_uuid, NULL);
        nm_connection_add_setting(connection, s_vlan);
    } else {
        /* No VLANS */
        conn_name  = format_conn_name(table_name, hfi, FALSE);
        connection = create_wired_conn(hfi, conn_name, hwaddr, FALSE);
    }

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
        if (hfi_is_dhcp(hfi, family)) {
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
                return;
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
        if (hfi_is_dhcp(hfi, family)) {
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
            prefix = hfi->tcp_info.subnet_mask_prefix;
            if (prefix == 0) {
                /* Buggy firmware implementations may report prefix=0 for v6 addresses,
                 * let's fall back to /64.
                 */
                _LOGW(LOGD_CORE,
                      "NBFT: Invalid IPv6 prefix %d, using /64 as a fallback.",
                      hfi->tcp_info.subnet_mask_prefix);
                prefix = 64;
            }
            ipaddr = nm_ip_address_new_binary(AF_INET6, &addr_bin, prefix, &error);
            if (!ipaddr) {
                _LOGW(LOGD_CORE,
                      "Cannot parse IP %s/%u: %s",
                      hfi->tcp_info.ipaddr,
                      prefix,
                      error->message);
                return;
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
     *         the default route and DHCP override flags (libnvme 1:
     *         this_hfi_is_default_route, dhcp_override; libnvme 3: flags)
     */

    if (!nm_connection_normalize(connection, NULL, NULL, &error)) {
        _LOGW(LOGD_CORE, "Generated an invalid connection: %s", error->message);
        return;
    }

    g_ptr_array_add(a, g_steal_pointer(&connection));
}

NMConnection **
nmi_nbft_reader_parse(const char *sysfs_dir, char **hostname)
{
    nm_auto_unref_ptrarray GPtrArray *a     = NULL;
    gs_free char                     *path  = NULL;
    gs_free_error GError             *error = NULL;
    GDir                             *dir;
    void                             *libnvme_handle = NULL;
    const char                       *entry_name;

    g_return_val_if_fail(sysfs_dir != NULL, NULL);
    path = g_build_filename(sysfs_dir, "firmware", "acpi", "tables", NULL);

    dir = g_dir_open(path, 0, NULL);
    if (!dir)
        return NULL;

    a = g_ptr_array_new();

    while ((entry_name = g_dir_read_name(dir))) {
        gs_free char  *entry_path = NULL;
        nmi_nbft_info *nbft;
        nmi_nbft_hfi **hfi;
        int            ret;

        if (!g_str_has_prefix(entry_name, "NBFT"))
            continue;

        /* attempt to load libnvme only on the first table match, saving some I/O */
        if (!libnvme_handle && !(libnvme_handle = load_libnvme())) {
            g_dir_close(dir);
            return NULL;
        }

        entry_path = g_build_filename(path, entry_name, NULL);
        ret        = nbft_read(&nbft, entry_path);
        if (ret) {
            _LOGW(LOGD_CORE,
                  "Error parsing NBFT table %s: %s",
                  entry_path,
                  nm_strerror_native(-ret));
            continue;
        }

        for (hfi = nbft->hfi_list; hfi && *hfi; hfi++) {
            if (!nm_streq((*hfi)->transport, "tcp")) {
                _LOGW(LOGD_CORE,
                      "NBFT table %s, HFI descriptor %d: unsupported transport type '%s'",
                      entry_path,
                      (*hfi)->index,
                      (*hfi)->transport);
                continue;
            }
            parse_hfi(a, *hfi, entry_name, hostname);
        }

        nbft_free(nbft);
    }

    g_dir_close(dir);
    if (libnvme_handle)
        nbft_lib_unload(libnvme_handle);
    g_ptr_array_add(a, NULL); /* trailing NULL-delimiter */
    return (NMConnection **) g_ptr_array_free(g_steal_pointer(&a), FALSE);
}

#else /* WITH_NBFT */

NMConnection **
nmi_nbft_reader_parse(const char *sysfs_dir, char **hostname)
{
    return NULL;
}

#endif
