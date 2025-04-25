/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include <linux/if_ether.h>
#include <linux/if_infiniband.h>

#include "libnm-glib-aux/nm-uuid.h"
#include "libnm-log-core/nm-logging.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "nm-initrd-generator.h"

/*****************************************************************************/

#define _NMLOG(level, domain, ...)                               \
    nm_log((level),                                              \
           (domain),                                             \
           NULL,                                                 \
           NULL,                                                 \
           "cmdline-reader: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__) \
               _NM_UTILS_MACRO_REST(__VA_ARGS__))

/*****************************************************************************/

typedef struct {
    GHashTable   *hash;
    GPtrArray    *array;
    GPtrArray    *vlan_parents;
    GHashTable   *explicit_ip_connections;
    NMConnection *bootdev_connection; /* connection for bootdev=$ifname */
    NMConnection *default_connection; /* connection not bound to any ifname */
    char         *hostname;
    GHashTable   *znet_ifnames;
    GPtrArray    *global_dns;
    char         *dns_backend;
    char         *dns_resolve_mode;

    /* Parameters to be set for all connections */
    gboolean ignore_auto_dns;
    int      dhcp_timeout;
    char    *dhcp4_vci;
    char    *dhcp_dscp;

    gint64 carrier_timeout_sec;
} Reader;

static Reader *
reader_new(void)
{
    Reader *reader;

    reader  = g_slice_new(Reader);
    *reader = (Reader) {
        .hash = g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, g_object_unref),
        .explicit_ip_connections =
            g_hash_table_new_full(nm_direct_hash, NULL, g_object_unref, NULL),
        .vlan_parents = g_ptr_array_new_with_free_func(g_free),
        .array        = g_ptr_array_new(),
        .znet_ifnames = g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, g_free),
    };

    return reader;
}

static GHashTable *
reader_destroy(Reader *reader, gboolean free_hash)
{
    gs_unref_hashtable GHashTable *hash = NULL;

    g_ptr_array_unref(reader->array);
    g_ptr_array_unref(reader->vlan_parents);
    nm_clear_pointer(&reader->global_dns, g_ptr_array_unref);
    g_hash_table_unref(reader->explicit_ip_connections);
    hash = g_steal_pointer(&reader->hash);
    nm_clear_g_free(&reader->hostname);
    g_hash_table_unref(reader->znet_ifnames);
    nm_clear_g_free(&reader->dhcp4_vci);
    nm_clear_g_free(&reader->dhcp_dscp);
    nm_clear_g_free(&reader->dns_backend);
    nm_clear_g_free(&reader->dns_resolve_mode);
    nm_g_slice_free(reader);
    if (!free_hash)
        return g_steal_pointer(&hash);
    return NULL;
}

static NMConnection *
reader_add_connection(Reader *reader, const char *name, NMConnection *connection_take)
{
    char *name_dup;

    name_dup = g_strdup(name);
    if (g_hash_table_insert(reader->hash, name_dup, connection_take))
        g_ptr_array_add(reader->array, name_dup);

    return connection_take;
}

/* Returns a new connection owned by the reader */
static NMConnection *
reader_create_connection(Reader                  *reader,
                         const char              *basename,
                         const char              *id,
                         const char              *ifname,
                         const char              *mac,
                         const char              *type_name,
                         int                      autoconnect_priority,
                         NMConnectionMultiConnect multi_connect)
{
    NMConnection *connection;
    NMSetting    *setting;

    connection = reader_add_connection(reader, basename, nm_simple_connection_new());

    /* Start off assuming dynamic IP configurations. */

    setting = nm_setting_ip4_config_new();
    nm_connection_add_setting(connection, setting);
    g_object_set(setting,
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_AUTO,
                 NM_SETTING_IP_CONFIG_MAY_FAIL,
                 TRUE,
                 NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS,
                 reader->ignore_auto_dns,
                 NM_SETTING_IP_CONFIG_DHCP_TIMEOUT,
                 reader->dhcp_timeout,
                 NM_SETTING_IP4_CONFIG_DHCP_VENDOR_CLASS_IDENTIFIER,
                 reader->dhcp4_vci,
                 NM_SETTING_IP_CONFIG_DHCP_DSCP,
                 reader->dhcp_dscp,
                 NM_SETTING_IP_CONFIG_REQUIRED_TIMEOUT,
                 NMI_IP_REQUIRED_TIMEOUT_MSEC,
                 NULL);

    setting = nm_setting_ip6_config_new();
    nm_connection_add_setting(connection, setting);
    g_object_set(setting,
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_AUTO,
                 NM_SETTING_IP_CONFIG_MAY_FAIL,
                 TRUE,
                 NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE,
                 (int) NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT_OR_EUI64,
                 NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS,
                 reader->ignore_auto_dns,
                 NM_SETTING_IP_CONFIG_DHCP_TIMEOUT,
                 reader->dhcp_timeout,
                 NULL);

    setting = nm_setting_connection_new();
    nm_connection_add_setting(connection, setting);
    g_object_set(setting,
                 NM_SETTING_CONNECTION_ID,
                 id,
                 NM_SETTING_CONNECTION_UUID,
                 nm_uuid_generate_random_str_a(),
                 NM_SETTING_CONNECTION_INTERFACE_NAME,
                 ifname,
                 NM_SETTING_CONNECTION_TYPE,
                 type_name,
                 NM_SETTING_CONNECTION_MULTI_CONNECT,
                 multi_connect,
                 NM_SETTING_CONNECTION_AUTOCONNECT_RETRIES,
                 1,
                 NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY,
                 autoconnect_priority,
                 NULL);

    if (nm_streq0(type_name, NM_SETTING_INFINIBAND_SETTING_NAME)) {
        setting = nm_setting_infiniband_new();
        nm_connection_add_setting(connection, setting);
        g_object_set(setting, NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram", NULL);
    }

    if (mac) {
        if (nm_streq0(type_name, NM_SETTING_INFINIBAND_SETTING_NAME)) {
            setting = (NMSetting *) nm_connection_get_setting_infiniband(connection);
            g_object_set(setting, NM_SETTING_INFINIBAND_MAC_ADDRESS, mac, NULL);
        } else {
            setting = nm_setting_wired_new();
            nm_connection_add_setting(connection, setting);
            g_object_set(setting, NM_SETTING_WIRED_MAC_ADDRESS, mac, NULL);
        }
    }

    return connection;
}

static NMConnection *
reader_get_default_connection(Reader *reader)
{
    NMConnection *con;

    if (!reader->default_connection) {
        con = reader_create_connection(reader,
                                       "default_connection",
                                       "Wired Connection",
                                       NULL,
                                       NULL,
                                       NM_SETTING_WIRED_SETTING_NAME,
                                       NMI_AUTOCONNECT_PRIORITY_CMDLINE,
                                       NM_CONNECTION_MULTI_CONNECT_MULTIPLE);
        nm_connection_add_setting(con, nm_setting_wired_new());
        reader->default_connection = con;
    }
    return reader->default_connection;
}

static NMConnection *
reader_get_connection(Reader     *reader,
                      const char *iface_spec,
                      const char *type_name,
                      gboolean    create_if_missing)
{
    NMConnection *connection = NULL;
    NMSetting    *setting;
    const char   *ifname = NULL;
    gs_free char *mac    = NULL;

    if (iface_spec) {
        if (nm_utils_is_valid_iface_name(iface_spec, NULL))
            ifname = iface_spec;
        else {
            mac = nm_utils_hwaddr_canonical(iface_spec, -1);
            if (!mac)
                _LOGW(LOGD_CORE, "invalid interface '%s'", iface_spec);
        }
    }

    if (!ifname && !mac) {
        NMConnection        *candidate;
        NMSettingConnection *s_con;
        guint                i;

        /*
         * If ifname was not given, we'll match the connection by type.
         * If the type was not given either, then we're happy with any connection but ports.
         * This is so that things like "bond=bond0:eth1,eth2 nameserver=1.3.3.7 end up
         * slapping the nameserver to the most reasonable connection (bond0).
         */
        for (i = 0; i < reader->array->len; i++) {
            candidate = g_hash_table_lookup(reader->hash, reader->array->pdata[i]);
            s_con     = nm_connection_get_setting_connection(candidate);

            if (type_name == NULL && nm_setting_connection_get_controller(s_con) == NULL) {
                connection = candidate;
                break;
            }

            if (type_name != NULL
                && nm_streq(nm_setting_connection_get_connection_type(s_con), type_name)) {
                connection = candidate;
                break;
            }
        }
    } else
        connection = g_hash_table_lookup(reader->hash, (gpointer) ifname ?: mac);

    if (!connection) {
        if (!create_if_missing)
            return NULL;

        if (!type_name) {
            if (NM_STR_HAS_PREFIX(ifname, "ib")
                || (mac && nm_utils_hwaddr_valid(mac, INFINIBAND_ALEN)))
                type_name = NM_SETTING_INFINIBAND_SETTING_NAME;
            else
                type_name = NM_SETTING_WIRED_SETTING_NAME;
        }

        connection = reader_create_connection(reader,
                                              ifname ?: mac,
                                              ifname ?: (mac ?: "Wired Connection"),
                                              ifname,
                                              mac,
                                              type_name,
                                              NMI_AUTOCONNECT_PRIORITY_CMDLINE,
                                              NM_CONNECTION_MULTI_CONNECT_SINGLE);
    }
    setting = (NMSetting *) nm_connection_get_setting_connection(connection);

    if (type_name) {
        g_object_set(setting, NM_SETTING_CONNECTION_TYPE, type_name, NULL);
        if (!nm_connection_get_setting_by_name(connection, type_name)) {
            setting = g_object_new(nm_setting_lookup_type(type_name), NULL);
            nm_connection_add_setting(connection, setting);
        }
    }

    return connection;
}

static char *
get_word(char **argument, const char separator)
{
    char *word;
    int   nest = 0;
    char *last_ch;
    char *first_close = NULL;

    if (*argument == NULL)
        return NULL;

    word = last_ch = *argument;

    while (**argument != '\0') {
        if (nest == 0 && **argument == separator) {
            **argument = '\0';
            (*argument)++;
            break;
        }
        if (**argument == '[') {
            nest++;
        } else if (nest && **argument == ']') {
            nest--;
            if (!first_close && nest == 0)
                first_close = *argument;
        }

        last_ch = *argument;
        (*argument)++;
    }

    /* If the word is surrounded with the nesting symbols [], strip them so we return
     * the inner content only.
     * If there were nesting symbols but embracing only part of the inner content, don't
     * remove them. Example:
     *    Remove [] in get_word("[fc08::1]:other_token", ":")
     *    Don't remove [] in get_word("ip6=[fc08::1]:other_token", ":")
     */
    if (*word == '[' && *last_ch == ']' && last_ch == first_close) {
        word++;
        *last_ch = '\0';
    }

    return *word ? word : NULL;
}

static void
connection_set(NMConnection *connection,
               const char   *setting_name,
               const char   *property,
               const char   *value)
{
    NMSetting                             *setting;
    GType                                  setting_type;
    nm_auto_unref_gtypeclass GObjectClass *object_class = NULL;
    GParamSpec                            *spec;

    setting_type = nm_setting_lookup_type(setting_name);
    object_class = g_type_class_ref(setting_type);
    spec         = g_object_class_find_property(object_class, property);
    nm_assert(spec);

    setting = nm_connection_get_setting_by_name(connection, setting_name);
    if (!setting) {
        setting = g_object_new(setting_type, NULL);
        nm_connection_add_setting(connection, setting);
    }

    if (G_IS_PARAM_SPEC_UINT(spec)) {
        guint v;

        v = _nm_utils_ascii_str_to_int64(value, 10, 0, G_MAXUINT, 0);
        if (errno || !nm_g_object_set_property_uint(G_OBJECT(setting), property, v, NULL)) {
            _LOGW(LOGD_CORE,
                  "Could not set property '%s.%s' to '%s'",
                  setting_name,
                  property,
                  value);
        }
    } else if (G_IS_PARAM_SPEC_STRING(spec))
        g_object_set(setting, property, value, NULL);
    else
        _LOGW(LOGD_CORE, "Don't know how to set '%s' of %s", property, setting_name);
}

static void
reader_read_all_connections_from_fw(Reader *reader, const char *sysfs_dir)
{
    gs_unref_hashtable GHashTable *ibft = NULL;
    NMConnection                  *dt_connection;
    const char                    *mac;
    GHashTable                    *nic;
    const char                    *index;
    GError                        *error = NULL;
    guint                          i, length;
    gs_free const char           **keys = NULL;

    ibft = nmi_ibft_read(sysfs_dir);
    keys = nm_strdict_get_keys(ibft, TRUE, &length);

    for (i = 0; i < length; i++) {
        gs_unref_object NMConnection *connection = NULL;
        gs_free char                 *name       = NULL;

        mac        = keys[i];
        nic        = g_hash_table_lookup(ibft, mac);
        connection = nm_simple_connection_new();
        index      = g_hash_table_lookup(nic, "index");
        if (!index) {
            _LOGW(LOGD_CORE, "Ignoring an iBFT entry without an index");
            continue;
        }

        if (!nmi_ibft_update_connection_from_nic(connection, nic, &error)) {
            _LOGW(LOGD_CORE, "Unable to merge iBFT configuration: %s", error->message);
            g_error_free(error);
            continue;
        }

        name = g_strdup_printf("ibft%s", index);
        reader_add_connection(reader, name, g_steal_pointer(&connection));
    }

    dt_connection = nmi_dt_reader_parse(sysfs_dir);
    if (dt_connection)
        reader_add_connection(reader, "ofw", dt_connection);
}

#define _strv_is_same_unordered(strv, ...) \
    nm_strv_is_same_unordered(NM_CAST_STRV_CC(strv), -1, NM_MAKE_STRV(__VA_ARGS__), -1)

static void
_strv_remove(const char **strv, const char *needle)
{
    gssize idx;
    gsize  len;
    gsize  i;

    idx = nm_strv_find_first(strv, -1, needle);
    if (idx < 0)
        return;

    /* Remove element at idx, by shifting the remaining ones
     * (including the terminating NULL). */
    len = NM_PTRARRAY_LEN(strv);
    for (i = idx; i < len; i++)
        strv[i] = strv[i + 1];
}

static const char *
_parse_ip_method(const char *kind)
{
    const char *const KINDS[] = {
        "none",
        "dhcp",
        "dhcp6",
        "link6",
        "auto",
        "ibft",
    };
    gs_free char        *kind_to_free = NULL;
    gs_free const char **strv         = NULL;
    gsize                i;

    kind = nm_strstrip_avoid_copy_a(300, kind, &kind_to_free);

    if (nm_str_is_empty(kind)) {
        /* Dracut defaults empty/missing to "dhcp". We treat them differently, as it
         * depends on whether we have IP addresses too.
         * https://github.com/dracutdevs/dracut/blob/3cc9f1c10c67dcdb5254e0eb69f19e9ab22abf20/modules.d/35network-legacy/parse-ip-opts.sh#L62 */
        return "auto";
    }

    for (i = 0; i < G_N_ELEMENTS(KINDS); i++) {
        if (nm_streq(kind, KINDS[i]))
            return KINDS[i];
    }

    /* the following are (currently) treated as aliases. */
    if (nm_streq(kind, "fw"))
        return "ibft";
    if (nm_streq(kind, "single-dhcp"))
        return "dhcp";
    if (nm_streq(kind, "off"))
        return "none";
    if (nm_streq(kind, "auto6"))
        return "dhcp6";
    if (NM_IN_STRSET(kind, "on", "any"))
        return "auto";

    if (!strchr(kind, ','))
        return NULL;

    /* dracut also supports combinations, separated by comma. We don't
     * support arbitrary combinations, but accept specific subsets. */
    strv = nm_strsplit_set_full(kind, ",", NM_STRSPLIT_SET_FLAGS_STRSTRIP);
    if (!strv)
        return NULL;

    /* first normalize the strv array by replacing all entries by their
     * normalized kind. */
    for (i = 0; strv[i]; i++) {
        strv[i] = _parse_ip_method(strv[i]);
        if (!strv[i]) {
            /* Unknown key. Not recognized.  */
            return NULL;
        }
    }

    /* sort list and remove duplicates. */
    nm_strv_sort(strv, -1);
    nm_strv_cleanup_const(strv, TRUE, TRUE);

    if (nm_strv_contains(strv, -1, "auto")) {
        /* if "auto" is present, then "dhcp4", "dhcp6", and "local6" is implied. */
        _strv_remove(strv, "dhcp4");
        _strv_remove(strv, "dhcp6");
        _strv_remove(strv, "local6");
    } else if (nm_strv_contains(strv, -1, "dhcp6")) {
        /* if "dhcp6" is present, then "local6" is implied. */
        _strv_remove(strv, "local6");
    }

    if (strv[0] && !strv[1]) {
        /* there is only one value left. It's good. */
        return strv[0];
    }

    /* only certain combinations are allowed... those are listed
     * and mapped to a canonical value.
     */
    if (_strv_is_same_unordered(strv, "dhcp", "dhcp6"))
        return "dhcp4+auto6";
    /* For the moment, this maps to "auto". This might be revisited
     * in the future to add new kinds like "dhcp+local6"
     */
    if (_strv_is_same_unordered(strv, "dhcp", "local6"))
        return "auto";

    /* undetected. */
    return NULL;
}

static void
reader_parse_ip(Reader *reader, const char *sysfs_dir, char *argument)
{
    NMConnection                  *connection;
    NMSettingConnection           *s_con;
    NMSettingIPConfig             *s_ip4 = NULL, *s_ip6 = NULL;
    gs_unref_hashtable GHashTable *ibft = NULL;
    char                          *tmp;
    const char                    *tmp2;
    const char                    *tmp3;
    const char                    *kind;
    const char                    *client_ip                  = NULL;
    const char                    *peer                       = NULL;
    const char                    *gateway_ip                 = NULL;
    const char                    *netmask                    = NULL;
    const char                    *client_hostname            = NULL;
    const char                    *iface_spec                 = NULL;
    const char                    *mtu                        = NULL;
    const char                    *macaddr                    = NULL;
    int                            client_ip_family           = AF_UNSPEC;
    int                            client_ip_prefix           = -1;
    gboolean                       clear_ip4_required_timeout = TRUE;
    const char                    *dns[2]                     = {
        NULL,
        NULL,
    };
    int dns_addr_family[2] = {
        AF_UNSPEC,
        AF_UNSPEC,
    };
    int     i;
    GError *error = NULL;

    if (!*argument)
        return;

    tmp = get_word(&argument, ':');
    if (!*argument) {
        /* ip={dhcp|on|any|dhcp6|auto6|link6|ibft} */
        kind = _parse_ip_method(tmp);
        if (!kind) {
            /* invalid method. We treat it as "auto". */
            kind = "auto";
        }
    } else {
        tmp2 = get_word(&argument, ':');
        if (!nm_str_is_empty(tmp2) && (tmp3 = _parse_ip_method(tmp2))) {
            /* <ifname>:{none|off|dhcp|on|any|dhcp6|auto|auto6|link6|ibft} */
            iface_spec = tmp;
            kind       = tmp3;
        } else {
            /* <client-IP>:[<peer>]:<gateway-IP>:<netmask>:<client_hostname>:<kind> */

            /* note: split here address and prefix to normalize IPs defined as
             * [dead::beef]/64. Latter parsing would fail due to the '[]'. */
            client_ip = get_word(&tmp, '/');

            if (client_ip) {
                client_ip_family = get_ip_address_family(client_ip, FALSE);
                if (client_ip_family == AF_UNSPEC) {
                    _LOGW(LOGD_CORE, "Invalid IP address '%s'.", client_ip);
                    return;
                }
            }

            if (!nm_str_is_empty(tmp)) {
                gboolean is_ipv4 = client_ip_family == AF_INET;

                client_ip_prefix = _nm_utils_ascii_str_to_int64(tmp, 10, 0, is_ipv4 ? 32 : 128, -1);
            }

            peer            = tmp2;
            gateway_ip      = get_word(&argument, ':');
            netmask         = get_word(&argument, ':');
            client_hostname = get_word(&argument, ':');
            iface_spec      = get_word(&argument, ':');
            tmp2            = get_word(&argument, ':');
            kind            = _parse_ip_method(tmp2);
            if (!kind) {
                /* invalid method. We treat that as "auto". */
                kind = "auto";
            }
        }

        if (client_hostname && !nm_hostname_is_valid(client_hostname, FALSE))
            client_hostname = NULL;

        if (client_hostname) {
            g_free(reader->hostname);
            reader->hostname = g_strdup(client_hostname);
        }

        tmp                = get_word(&argument, ':');
        dns_addr_family[0] = get_ip_address_family(tmp, FALSE);
        if (dns_addr_family[0] != AF_UNSPEC) {
            dns[0] = tmp;
            dns[1] = get_word(&argument, ':');
            if (dns[1]) {
                dns_addr_family[1] = get_ip_address_family(dns[1], FALSE);
                if (dns_addr_family[1] == AF_UNSPEC)
                    _LOGW(LOGD_CORE, "Ignoring invalid DNS server: '%s'.", dns[1]);
                if (*argument)
                    _LOGW(LOGD_CORE, "Ignoring extra: '%s'.", argument);
            }
        } else {
            mtu     = tmp;
            macaddr = argument;
        }
    }

    if (iface_spec == NULL && nm_streq(kind, "ibft")) {
        reader_read_all_connections_from_fw(reader, sysfs_dir);
        return;
    }

    /* Parsing done, construct the NMConnection. */
    if (iface_spec)
        connection = reader_get_connection(reader, iface_spec, NULL, TRUE);
    else
        connection = reader_get_default_connection(reader);

    g_hash_table_add(reader->explicit_ip_connections, g_object_ref(connection));

    s_con = nm_connection_get_setting_connection(connection);
    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    s_ip6 = nm_connection_get_setting_ip6_config(connection);

    if (netmask && *netmask) {
        gboolean is_ipv4 = client_ip_family == AF_INET;
        NMIPAddr addr;

        if (is_ipv4 && nm_inet_parse_bin(AF_INET, netmask, NULL, &addr))
            client_ip_prefix = nm_ip4_addr_netmask_to_prefix(addr.addr4);
        else
            client_ip_prefix = _nm_utils_ascii_str_to_int64(netmask, 10, 0, is_ipv4 ? 32 : 128, -1);

        if (client_ip_prefix == -1)
            _LOGW(LOGD_CORE, "Invalid IP mask: %s", netmask);
    }

    /* Static IP configuration might be present. */
    if (client_ip && *client_ip) {
        NMIPAddress *address = NULL;
        NMIPAddr     addr;

        if (nm_inet_parse_bin(client_ip_family, client_ip, NULL, &addr)) {
            if (client_ip_prefix == -1) {
                switch (client_ip_family) {
                case AF_INET:
                    client_ip_prefix = nm_ip4_addr_get_default_prefix(addr.addr4);
                    break;
                case AF_INET6:
                    client_ip_prefix = 64;
                    break;
                }
            }

            address = nm_ip_address_new_binary(client_ip_family,
                                               &addr.addr_ptr,
                                               client_ip_prefix,
                                               &error);
            if (!address) {
                _LOGW(LOGD_CORE, "Invalid address '%s': %s", client_ip, error->message);
                g_clear_error(&error);
            }
        } else
            nm_assert_not_reached();

        if (address) {
            /* We don't want to have multiple devices up with the
             * same static address. */
            g_object_set(s_con,
                         NM_SETTING_CONNECTION_MULTI_CONNECT,
                         NM_CONNECTION_MULTI_CONNECT_SINGLE,
                         NULL);
            switch (client_ip_family) {
            case AF_INET:
                g_object_set(s_ip4,
                             NM_SETTING_IP_CONFIG_METHOD,
                             NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
                             NM_SETTING_IP_CONFIG_MAY_FAIL,
                             FALSE,
                             NULL);
                nm_setting_ip_config_add_address(s_ip4, address);
                break;
            case AF_INET6:
                g_object_set(s_ip6,
                             NM_SETTING_IP_CONFIG_METHOD,
                             NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
                             NM_SETTING_IP_CONFIG_MAY_FAIL,
                             FALSE,
                             NULL);
                nm_setting_ip_config_add_address(s_ip6, address);
                break;
            default:
                nm_assert_not_reached();
                break;
            }
            nm_ip_address_unref(address);
        }
    }

    /* Dynamic IP configuration configured explicitly. */
    if (nm_streq(kind, "none")) {
        if (nm_setting_ip_config_get_num_addresses(s_ip6) == 0) {
            g_object_set(s_ip6,
                         NM_SETTING_IP_CONFIG_METHOD,
                         NM_SETTING_IP6_CONFIG_METHOD_DISABLED,
                         NULL);
        }
        if (nm_setting_ip_config_get_num_addresses(s_ip4) == 0) {
            g_object_set(s_ip4,
                         NM_SETTING_IP_CONFIG_METHOD,
                         NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
                         NULL);
        }
    } else if (nm_streq(kind, "dhcp")) {
        g_object_set(s_ip4,
                     NM_SETTING_IP_CONFIG_METHOD,
                     NM_SETTING_IP4_CONFIG_METHOD_AUTO,
                     NM_SETTING_IP_CONFIG_MAY_FAIL,
                     FALSE,
                     NULL);
        if (nm_setting_ip_config_get_num_addresses(s_ip6) == 0) {
            g_object_set(s_ip6,
                         NM_SETTING_IP_CONFIG_METHOD,
                         NM_SETTING_IP6_CONFIG_METHOD_AUTO,
                         NULL);
        }
    } else if (nm_streq(kind, "dhcp6")) {
        g_object_set(s_ip6,
                     NM_SETTING_IP_CONFIG_METHOD,
                     NM_SETTING_IP6_CONFIG_METHOD_AUTO,
                     NM_SETTING_IP_CONFIG_MAY_FAIL,
                     FALSE,
                     NULL);
        if (nm_setting_ip_config_get_num_addresses(s_ip4) == 0) {
            g_object_set(s_ip4,
                         NM_SETTING_IP_CONFIG_METHOD,
                         NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
                         NULL);
        }
    } else if (nm_streq(kind, "dhcp4+auto6")) {
        /* Both DHCPv4 and IPv6 autoconf are enabled, and
         * each of them is tried for at least IP_REQUIRED_TIMEOUT_MSEC,
         * even if the other one completes before.
         */
        clear_ip4_required_timeout = FALSE;
        g_object_set(s_ip6,
                     NM_SETTING_IP_CONFIG_REQUIRED_TIMEOUT,
                     NMI_IP_REQUIRED_TIMEOUT_MSEC,
                     NULL);
    } else if (nm_streq(kind, "link6")) {
        g_object_set(s_ip6,
                     NM_SETTING_IP_CONFIG_METHOD,
                     NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
                     NM_SETTING_IP_CONFIG_MAY_FAIL,
                     FALSE,
                     NULL);
        if (nm_setting_ip_config_get_num_addresses(s_ip4) == 0) {
            g_object_set(s_ip4,
                         NM_SETTING_IP_CONFIG_METHOD,
                         NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
                         NULL);
        }
    } else if (nm_streq(kind, "ibft")) {
        NMSettingWired *s_wired;
        const char     *mac = NULL;
        const char     *ifname;
        gs_free char   *mac_free     = NULL;
        gs_free char   *address_path = NULL;
        GHashTable     *nic          = NULL;

        if ((s_wired = nm_connection_get_setting_wired(connection))
            && (mac = nm_setting_wired_get_mac_address(s_wired))) {
            /* got mac from the connection */
        } else if ((ifname = nm_connection_get_interface_name(connection))) {
            /* read it from sysfs */
            address_path = g_build_filename(sysfs_dir, "class", "net", ifname, "address", NULL);
            if (g_file_get_contents(address_path, &mac_free, NULL, &error)) {
                g_strchomp(mac_free);
                mac = mac_free;
            } else {
                _LOGW(LOGD_CORE, "Can't get a MAC address for %s: %s", ifname, error->message);
                g_clear_error(&error);
            }
        }

        if (mac) {
            gs_free char *mac_up = NULL;

            mac_up = g_ascii_strup(mac, -1);
            ibft   = nmi_ibft_read(sysfs_dir);
            nic    = g_hash_table_lookup(ibft, mac_up);
            if (!nic)
                _LOGW(LOGD_CORE, "No iBFT NIC for %s (%s)", iface_spec, mac_up);
        }

        if (nic) {
            if (!nmi_ibft_update_connection_from_nic(connection, nic, &error)) {
                _LOGW(LOGD_CORE, "Unable to merge iBFT configuration: %s", error->message);
                g_clear_error(&error);
            }
        }
    } else {
        nm_assert(nm_streq(kind, "auto"));
        clear_ip4_required_timeout = FALSE;
    }

    if (clear_ip4_required_timeout)
        g_object_set(s_ip4, NM_SETTING_IP_CONFIG_REQUIRED_TIMEOUT, -1, NULL);

    if (peer && *peer)
        _LOGW(LOGD_CORE, "Ignoring peer: %s (not implemented)\n", peer);

    if (gateway_ip && *gateway_ip) {
        switch (get_ip_address_family(gateway_ip, FALSE)) {
        case AF_INET:
            g_object_set(s_ip4, NM_SETTING_IP_CONFIG_GATEWAY, gateway_ip, NULL);
            break;
        case AF_INET6:
            g_object_set(s_ip6, NM_SETTING_IP_CONFIG_GATEWAY, gateway_ip, NULL);
            break;
        default:
            _LOGW(LOGD_CORE, "Invalid gateway: %s", gateway_ip);
            break;
        }
    }

    if (client_hostname && *client_hostname) {
        g_object_set(s_ip4, NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, client_hostname, NULL);
        g_object_set(s_ip6, NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, client_hostname, NULL);
    }

    for (i = 0; i < 2; i++) {
        if (dns_addr_family[i] == AF_UNSPEC)
            break;
        nm_assert(nm_inet_is_valid(dns_addr_family[i], dns[i]));
        nm_setting_ip_config_add_dns(NM_IS_IPv4(dns_addr_family[i]) ? s_ip4 : s_ip6, dns[i]);
    }

    if (mtu && *mtu)
        connection_set(connection, NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_MTU, mtu);

    if (macaddr && *macaddr)
        connection_set(connection,
                       NM_SETTING_WIRED_SETTING_NAME,
                       NM_SETTING_WIRED_CLONED_MAC_ADDRESS,
                       macaddr);
}

static void
reader_parse_controller(Reader     *reader,
                        char       *argument,
                        const char *type_name,
                        const char *default_name)
{
    NMConnection        *connection;
    NMSettingConnection *s_con;
    gs_free char        *controller_to_free = NULL;
    const char          *controller;
    char                *ports;
    const char          *port;
    char                *opts;
    const char          *mtu = NULL;

    controller = get_word(&argument, ':');
    if (!controller)
        controller = controller_to_free = g_strdup_printf("%s0", default_name ?: type_name);
    ports = get_word(&argument, ':');

    connection = reader_get_connection(reader, controller, type_name, TRUE);
    s_con      = nm_connection_get_setting_connection(connection);
    controller = nm_setting_connection_get_uuid(s_con);

    if (nm_streq(type_name, NM_SETTING_BRIDGE_SETTING_NAME)) {
        NMSettingBridge *s_bridge = nm_connection_get_setting_bridge(connection);

        /* Avoid the forwarding delay */
        g_object_set(s_bridge, NM_SETTING_BRIDGE_STP, FALSE, NULL);
    } else if (nm_streq(type_name, NM_SETTING_BOND_SETTING_NAME)) {
        NMSettingBond *s_bond = nm_connection_get_setting_bond(connection);

        opts = get_word(&argument, ':');
        while (opts && *opts) {
            gs_free_error GError             *error = NULL;
            char                             *tmp;
            const char                       *opt_name;
            char                             *opt;
            const char                       *opt_value;
            nm_auto_unref_ptrarray GPtrArray *opt_values     = g_ptr_array_new();
            gs_free char                     *opt_normalized = NULL;

            opt_name = get_word(&opts, '=');
            opt      = get_word(&opts, ',');

            /* Normalize: convert ';' to ',' and remove '[]' from IPv6 addresses */
            tmp = opt;
            while ((opt_value = get_word(&tmp, ';')))
                g_ptr_array_add(opt_values, (gpointer) opt_value);
            g_ptr_array_add(opt_values, NULL);
            opt_normalized = g_strjoinv(",", (char **) opt_values->pdata);

            if (!_nm_setting_bond_validate_option(opt_name, opt_normalized, &error)) {
                _LOGW(LOGD_CORE,
                      "Ignoring invalid bond option: %s%s%s = %s%s%s: %s",
                      NM_PRINT_FMT_QUOTE_STRING(opt_name),
                      NM_PRINT_FMT_QUOTE_STRING(opt),
                      error->message);
                continue;
            }
            nm_setting_bond_add_option(s_bond, opt_name, opt_normalized);
        }

        mtu = get_word(&argument, ':');
    }

    if (mtu)
        connection_set(connection, NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_MTU, mtu);

    do {
        port = get_word(&ports, ',');
        if (port == NULL)
            port = "eth0";

        connection = reader_get_connection(reader, port, NULL, TRUE);
        s_con      = nm_connection_get_setting_connection(connection);
        g_object_set(s_con,
                     NM_SETTING_CONNECTION_PORT_TYPE,
                     type_name,
                     NM_SETTING_CONNECTION_CONTROLLER,
                     controller,
                     NULL);
    } while (ports && *ports != '\0');

    if (argument && *argument)
        _LOGW(LOGD_CORE, "Ignoring extra: '%s'.", argument);
}

static void
reader_add_routes(Reader *reader, GPtrArray *array)
{
    guint i;

    for (i = 0; i < array->len; i++) {
        NMConnection         *connection = NULL;
        const char           *net;
        const char           *gateway;
        const char           *interface;
        int                   family       = AF_UNSPEC;
        NMIPAddr              net_addr     = {};
        NMIPAddr              gateway_addr = {};
        int                   net_prefix   = -1;
        NMIPRoute            *route;
        NMSettingIPConfig    *s_ip;
        char                 *argument;
        gs_free_error GError *error = NULL;

        argument  = array->pdata[i];
        net       = get_word(&argument, ':');
        gateway   = get_word(&argument, ':');
        interface = get_word(&argument, ':');

        if (interface)
            connection = reader_get_connection(reader, interface, NULL, TRUE);
        if (!connection)
            connection = reader->bootdev_connection;
        if (!connection)
            connection = reader_get_connection(reader, interface, NULL, FALSE);
        if (!connection)
            connection = reader_get_default_connection(reader);

        if (net && *net) {
            if (!nm_inet_parse_with_prefix_bin(family, net, &family, &net_addr, &net_prefix)) {
                _LOGW(LOGD_CORE, "Unrecognized address: %s", net);
                continue;
            }
        }

        if (gateway && *gateway) {
            if (!nm_inet_parse_bin(family, gateway, &family, &gateway_addr)) {
                _LOGW(LOGD_CORE, "Unrecognized address: %s", gateway);
                continue;
            }
        }

        switch (family) {
        case AF_INET:
            s_ip = nm_connection_get_setting_ip4_config(connection);
            if (net_prefix == -1)
                net_prefix = 32;
            break;
        case AF_INET6:
            s_ip = nm_connection_get_setting_ip6_config(connection);
            if (net_prefix == -1)
                net_prefix = 128;
            break;
        default:
            _LOGW(LOGD_CORE, "Unknown address family: %s", net);
            continue;
        }

        route = nm_ip_route_new_binary(family,
                                       &net_addr.addr_ptr,
                                       net_prefix,
                                       &gateway_addr.addr_ptr,
                                       -1,
                                       &error);
        if (!route) {
            g_warning("Invalid route '%s via %s': %s\n", net, gateway, error->message);
            continue;
        }

        nm_setting_ip_config_add_route(s_ip, route);
        nm_ip_route_unref(route);
    }
}

static void
reader_parse_vlan(Reader *reader, char *argument)
{
    NMConnection  *connection;
    NMSettingVlan *s_vlan;
    const char    *vlan;
    const char    *phy;
    const char    *vlanid;

    vlan = get_word(&argument, ':');
    phy  = get_word(&argument, ':');

    for (vlanid = vlan + strlen(vlan); vlanid > vlan; vlanid--) {
        if (!g_ascii_isdigit(*(vlanid - 1)))
            break;
    }

    connection = reader_get_connection(reader, vlan, NM_SETTING_VLAN_SETTING_NAME, TRUE);

    s_vlan = nm_connection_get_setting_vlan(connection);
    g_object_set(s_vlan,
                 NM_SETTING_VLAN_PARENT,
                 phy,
                 NM_SETTING_VLAN_ID,
                 (guint) _nm_utils_ascii_str_to_int64(vlanid, 10, 0, G_MAXUINT, G_MAXUINT),
                 NULL);

    if (argument && *argument)
        _LOGW(LOGD_CORE, "Ignoring extra: '%s'.", argument);

    if (!nm_strv_ptrarray_contains(reader->vlan_parents, phy))
        g_ptr_array_add(reader->vlan_parents, g_strdup(phy));
}

static void
reader_parse_ib_pkey(Reader *reader, char *argument)
{
    NMConnection        *connection;
    NMSettingInfiniband *s_ib;
    char                *ifname;
    gs_free char        *parent = NULL;
    char                *pkey;
    gint64               pkey_int;

    /* At the moment we only support ib.pkey=<parent>.<pkey>;
     * in the future we want to possibly support other options:
     * ib.pkey=<parent>.<pkey>:<option>:...
     */
    ifname = get_word(&argument, ':');
    if (!ifname) {
        _LOGW(LOGD_CORE, "ib.pkey= without argument");
        return;
    }

    parent = g_strdup(ifname);
    pkey   = strchr(parent, '.');
    if (!pkey) {
        _LOGW(LOGD_CORE, "No pkey found for '%s'", ifname);
        return;
    }

    *pkey = '\0';
    pkey++;

    pkey_int = _nm_utils_ascii_str_to_int64(pkey, 16, 0, 0xFFFF, -1);
    if (pkey_int == -1) {
        _LOGW(LOGD_CORE, "Invalid pkey '%s'", pkey);
        return;
    }

    connection = reader_get_connection(reader, ifname, NM_SETTING_INFINIBAND_SETTING_NAME, TRUE);

    s_ib = nm_connection_get_setting_infiniband(connection);
    g_object_set(s_ib,
                 NM_SETTING_INFINIBAND_PARENT,
                 parent,
                 NM_SETTING_INFINIBAND_P_KEY,
                 (int) pkey_int,
                 NULL);

    if (argument && *argument)
        _LOGW(LOGD_CORE, "Ignoring extra: '%s' for ib.pkey=", argument);
}

static void
reader_parse_znet_ifname(Reader *reader, char *argument)
{
    char *ifname;

    ifname = get_word(&argument, ':');
    if (!ifname) {
        _LOGW(LOGD_CORE, "rd.znet_ifname= without argument");
        return;
    }

    if (!g_hash_table_replace(reader->znet_ifnames, g_strdup(argument), g_strdup(ifname))) {
        _LOGW(LOGD_CORE, "duplicate rd.znet_ifname for ifname=%s", ifname);
    }
}

static void
reader_parse_rd_znet(Reader *reader, char *argument, gboolean net_ifnames)
{
    const char     *nettype;
    const char     *subchannels[4] = {0, 0, 0, 0};
    const char     *tmp;
    gs_free char   *ifname          = NULL;
    gs_free char   *str_subchannels = NULL;
    const char     *prefix;
    NMConnection   *connection;
    NMSettingWired *s_wired;
    static int      count_ctc = 0;
    static int      count_eth = 0;
    int             index     = -1;

    nettype        = get_word(&argument, ',');
    subchannels[0] = get_word(&argument, ',');
    subchannels[1] = get_word(&argument, ',');

    /* Without subchannels we can't univocally match
     * a device. */
    if (!subchannels[0] || !subchannels[1])
        return;

    if (nm_streq0(nettype, "ctc")) {
        if (net_ifnames == TRUE) {
            prefix = "sl";
        } else {
            prefix = "ctc";
            index  = count_ctc++;
        }
    } else {
        subchannels[2] = get_word(&argument, ',');
        if (net_ifnames == TRUE) {
            prefix = "en";
        } else {
            prefix = "eth";
            index  = count_eth++;
        }
    }

    str_subchannels = g_strjoinv(",", (char **) subchannels);
    ifname          = g_hash_table_lookup(reader->znet_ifnames, str_subchannels);

    if (ifname) {
        ifname = g_strdup(ifname);
        g_hash_table_remove(reader->znet_ifnames, str_subchannels);
    } else if (net_ifnames == TRUE) {
        const char *bus_id;
        size_t      bus_id_len;
        size_t      bus_id_start;

        /* The following logic is taken from names_ccw() in systemd/src/udev/udev-builtin-net_id.c */
        bus_id       = subchannels[0];
        bus_id_len   = strlen(bus_id);
        bus_id_start = strspn(bus_id, ".0");
        bus_id += bus_id_start < bus_id_len ? bus_id_start : bus_id_len - 1;

        ifname = g_strdup_printf("%sc%s", prefix, bus_id);
    } else {
        nm_assert(index > -1);
        ifname = g_strdup_printf("%s%d", prefix, index);
    }

    connection = reader_get_connection(reader, ifname, NM_SETTING_WIRED_SETTING_NAME, FALSE);
    if (!connection)
        return;
    s_wired = nm_connection_get_setting_wired(connection);
    g_object_set(s_wired,
                 NM_SETTING_WIRED_S390_NETTYPE,
                 nettype,
                 NM_SETTING_WIRED_S390_SUBCHANNELS,
                 &subchannels,
                 NULL);

    while ((tmp = get_word(&argument, ',')) != NULL) {
        const char *key;
        char       *val;

        val = strchr(tmp, '=');
        if (!val) {
            /* an invalid (or empty) entry. Ignore. */
            continue;
        }

        key    = tmp;
        val[0] = '\0';
        val++;
        if (!_nm_setting_wired_is_valid_s390_option(key)
            || !_nm_setting_wired_is_valid_s390_option_value(key, val)) {
            /* Invalid setting. Silently ignore, but also ensure we
             * didn't already set it. */
            nm_setting_wired_remove_s390_option(s_wired, key);
        } else
            nm_setting_wired_add_s390_option(s_wired, key, val);
    }
}

static void
reader_parse_global_dns(Reader *reader, char *argument)
{
    if (!nm_dns_uri_parse(AF_UNSPEC, argument, NULL)) {
        _LOGW(LOGD_CORE, "rd.net.dns: invalid server '%s'", argument);
        return;
    }

    if (!reader->global_dns) {
        reader->global_dns = g_ptr_array_new_with_free_func(g_free);
    }

    g_ptr_array_add(reader->global_dns, g_strdup(argument));
}

static void
reader_parse_dns_backend(Reader *reader, const char *argument)
{
    if (!NM_IN_STRSET(argument, "none", "default", "systemd-resolved", "dnsmasq", "dnsconfd")) {
        _LOGW(LOGD_CORE, "rd.net.dns-backend: invalid value '%s'", argument);
        return;
    }

    reader->dns_backend = g_strdup(argument);
}

static void
reader_parse_dns_resolve_mode(Reader *reader, const char *argument)
{
    if (!NM_IN_STRSET(argument, "backup", "prefer", "exclusive")) {
        _LOGW(LOGD_CORE, "rd.net.dns-resolve-mode: invalid value '%s'", argument);
        return;
    }

    reader->dns_resolve_mode = g_strdup(argument);
}

static void
reader_parse_ethtool(Reader *reader, char *argument)
{
    NMConnection   *connection;
    NMSettingWired *s_wired;
    const char     *autoneg_str;
    const char     *speed_str;
    const char     *interface;
    int             autoneg;
    guint           speed;

    interface = get_word(&argument, ':');
    if (!interface) {
        _LOGW(LOGD_CORE, "rd.ethtool: interface unspecified. Ignore");
        return;
    }

    autoneg_str = get_word(&argument, ':');
    speed_str   = get_word(&argument, ':');

    autoneg = -1;
    if (autoneg_str) {
        autoneg = _nm_utils_ascii_str_to_bool(autoneg_str, -1);
        if (autoneg == -1)
            _LOGW(LOGD_CORE, "rd.ethtool: autoneg invalid. Must be boolean or empty");
    }

    speed = 0;
    if (speed_str) {
        speed = _nm_utils_ascii_str_to_int64(speed_str, 10, 0, G_MAXUINT32, 0);
        if (errno)
            _LOGW(LOGD_CORE, "rd.ethtool: speed invalid. Must be an integer or empty");
    }

    if (speed == 0 && autoneg == FALSE) {
        _LOGW(LOGD_CORE,
              "rd.ethtool: autoneg ignored. Cannot disable autoneg without setting speed");
    }

    connection = reader_get_connection(reader, interface, NM_SETTING_WIRED_SETTING_NAME, TRUE);

    if (autoneg != -1 || speed != 0) {
        if (autoneg == -1)
            autoneg = FALSE;
        s_wired = nm_connection_get_setting_wired(connection);
        g_object_set(s_wired,
                     NM_SETTING_WIRED_AUTO_NEGOTIATE,
                     (gboolean) autoneg,
                     NM_SETTING_WIRED_SPEED,
                     speed,
                     NM_SETTING_WIRED_DUPLEX,
                     speed == 0 ? NULL : "full",
                     NULL);
    }

    if (*argument)
        _LOGW(LOGD_CORE, "rd.ethtool: extra argument ignored");
}

static void
_normalize_conn(gpointer key, gpointer value, gpointer user_data)
{
    NMConnection      *connection = value;
    NMSettingIPConfig *s_ip4 = NULL, *s_ip6 = NULL;

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    if (s_ip4) {
        const char *method = nm_setting_ip_config_get_method(s_ip4);

        if (!nm_streq(method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
            g_object_set(s_ip4,
                         NM_SETTING_IP_CONFIG_DHCP_HOSTNAME,
                         NULL,
                         NM_SETTING_IP_CONFIG_DHCP_TIMEOUT,
                         NULL,
                         NM_SETTING_IP4_CONFIG_DHCP_VENDOR_CLASS_IDENTIFIER,
                         NULL,
                         NM_SETTING_IP_CONFIG_DHCP_DSCP,
                         NULL,
                         NULL);
        }
    }

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    if (s_ip6) {
        const char *method = nm_setting_ip_config_get_method(s_ip6);

        if (!nm_streq(method, NM_SETTING_IP6_CONFIG_METHOD_AUTO)
            && !nm_streq(method, NM_SETTING_IP6_CONFIG_METHOD_DHCP)) {
            g_object_set(s_ip6,
                         NM_SETTING_IP_CONFIG_DHCP_HOSTNAME,
                         NULL,
                         NM_SETTING_IP_CONFIG_DHCP_TIMEOUT,
                         NULL,
                         NULL);
        }
    }

    nm_connection_normalize(connection, NULL, NULL, NULL);
}

static void
reader_add_nameservers(Reader *reader, GPtrArray *nameservers)
{
    NMConnection      *connection;
    NMSettingIPConfig *s_ip;
    GHashTableIter     iter;
    int                addr_family;
    const char        *ns;
    guint              i;

    for (i = 0; i < nameservers->len; i++) {
        ns          = nameservers->pdata[i];
        addr_family = get_ip_address_family(ns, FALSE);
        if (addr_family == AF_UNSPEC) {
            _LOGW(LOGD_CORE, "Unknown address family: %s", ns);
            continue;
        }

        g_hash_table_iter_init(&iter, reader->hash);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &connection)) {
            switch (addr_family) {
            case AF_INET:
                s_ip = nm_connection_get_setting_ip4_config(connection);
                if (!NM_IN_STRSET(nm_setting_ip_config_get_method(s_ip),
                                  NM_SETTING_IP4_CONFIG_METHOD_AUTO,
                                  NM_SETTING_IP4_CONFIG_METHOD_MANUAL))
                    continue;
                break;
            case AF_INET6:
                s_ip = nm_connection_get_setting_ip6_config(connection);
                if (!NM_IN_STRSET(nm_setting_ip_config_get_method(s_ip),
                                  NM_SETTING_IP6_CONFIG_METHOD_AUTO,
                                  NM_SETTING_IP6_CONFIG_METHOD_DHCP,
                                  NM_SETTING_IP6_CONFIG_METHOD_MANUAL))
                    continue;
                break;
            default:
                nm_assert_not_reached();
                continue;
            }

            nm_setting_ip_config_add_dns(s_ip, ns);
        }
    }
}

static void
connection_set_needed(NMConnection *connection)
{
    NMSettingConnection *s_con;

    s_con = nm_connection_get_setting_connection(connection);
    if (!nm_streq0(nm_setting_connection_get_connection_type(s_con), NM_SETTING_WIRED_SETTING_NAME))
        return;

    g_object_set(s_con,
                 NM_SETTING_CONNECTION_WAIT_DEVICE_TIMEOUT,
                 (int) NMI_WAIT_DEVICE_TIMEOUT_MSEC,
                 NULL);
}

static void
connection_set_needed_cb(gpointer key, gpointer value, gpointer user_data)
{
    connection_set_needed(value);
}

GHashTable *
nmi_cmdline_reader_parse(const char        *etc_connections_dir,
                         const char        *sysfs_dir,
                         const char *const *argv,
                         char             **hostname,
                         gint64            *carrier_timeout_sec,
                         char            ***global_dns_servers,
                         char             **dns_backend,
                         char             **dns_resolve_mode)
{
    Reader                      *reader;
    const char                  *tag;
    gboolean                     ignore_bootif = FALSE;
    gboolean                     neednet       = FALSE;
    gs_free char                *bootif_val    = NULL;
    gs_free char                *bootdev       = NULL;
    gboolean                     net_ifnames   = TRUE;
    gs_unref_ptrarray GPtrArray *nameservers   = NULL;
    gs_unref_ptrarray GPtrArray *routes        = NULL;
    gs_unref_ptrarray GPtrArray *znets         = NULL;
    int                          i;
    guint64                      dhcp_timeout   = 90;
    guint64                      dhcp_num_tries = 1;

    reader = reader_new();

    for (i = 0; argv[i]; i++) {
        gs_free char *argument_clone = NULL;
        char         *argument;

        argument_clone = g_strdup(argv[i]);
        argument       = argument_clone;

        tag = get_word(&argument, '=');

        if (!tag) {
            /* pass */
        } else if (nm_streq(tag, "net.ifnames"))
            net_ifnames = !nm_streq(argument, "0");
        else if (nm_streq(tag, "rd.peerdns"))
            reader->ignore_auto_dns = !_nm_utils_ascii_str_to_bool(argument, TRUE);
        else if (nm_streq(tag, "rd.net.timeout.dhcp")) {
            if (nm_streq0(argument, "infinity")) {
                dhcp_timeout = G_MAXINT32;
            } else {
                dhcp_timeout =
                    _nm_utils_ascii_str_to_int64(argument, 10, 1, G_MAXINT32, dhcp_timeout);
            }
        } else if (nm_streq(tag, "rd.net.dhcp.retry")) {
            dhcp_num_tries =
                _nm_utils_ascii_str_to_int64(argument, 10, 1, G_MAXINT32, dhcp_num_tries);
        } else if (nm_streq(tag, "rd.net.dhcp.vendor-class")) {
            if (nm_utils_validate_dhcp4_vendor_class_id(argument, NULL))
                nm_strdup_reset(&reader->dhcp4_vci, argument);
        } else if (nm_streq(tag, "rd.net.dhcp.dscp")) {
            gs_free_error GError *error = NULL;

            if (nm_utils_validate_dhcp_dscp(argument, &error))
                nm_strdup_reset(&reader->dhcp_dscp, argument);
            else
                _LOGW(LOGD_CORE, "Ignoring 'rd.net.dhcp.dscp=%s': %s", argument, error->message);
        } else if (nm_streq(tag, "rd.net.timeout.carrier")) {
            reader->carrier_timeout_sec =
                _nm_utils_ascii_str_to_int64(argument, 10, 0, G_MAXINT32, 0);
        }
    }

    reader->dhcp_timeout = NM_CLAMP(dhcp_timeout * dhcp_num_tries, 1u, (guint32) G_MAXINT32);

    for (i = 0; argv[i]; i++) {
        gs_free char *argument_clone = NULL;
        char         *argument;
        char         *word;

        argument_clone = g_strdup(argv[i]);
        argument       = argument_clone;

        tag = get_word(&argument, '=');
        if (!tag) {
            /* pass */
        } else if (nm_streq(tag, "ip"))
            reader_parse_ip(reader, sysfs_dir, argument);
        else if (nm_streq(tag, "rd.route")) {
            if (!routes)
                routes = g_ptr_array_new_with_free_func(g_free);
            g_ptr_array_add(routes, g_strdup(argument));
        } else if (nm_streq(tag, "bridge"))
            reader_parse_controller(reader, argument, NM_SETTING_BRIDGE_SETTING_NAME, "br");
        else if (nm_streq(tag, "bond"))
            reader_parse_controller(reader, argument, NM_SETTING_BOND_SETTING_NAME, NULL);
        else if (nm_streq(tag, "team"))
            reader_parse_controller(reader, argument, NM_SETTING_TEAM_SETTING_NAME, NULL);
        else if (nm_streq(tag, "vlan"))
            reader_parse_vlan(reader, argument);
        else if (nm_streq(tag, "ib.pkey"))
            reader_parse_ib_pkey(reader, argument);
        else if (nm_streq(tag, "bootdev")) {
            g_free(bootdev);
            bootdev = g_strdup(argument);
        } else if (nm_streq(tag, "nameserver")) {
            word = get_word(&argument, '\0');
            if (word) {
                if (!nameservers)
                    nameservers = g_ptr_array_new_with_free_func(g_free);
                g_ptr_array_add(nameservers, g_strdup(word));
            }
            if (argument && *argument)
                _LOGW(LOGD_CORE, "Ignoring extra: '%s'.", argument);
        } else if (nm_streq(tag, "rd.iscsi.ibft") && _nm_utils_ascii_str_to_bool(argument, TRUE))
            reader_read_all_connections_from_fw(reader, sysfs_dir);
        else if (nm_streq(tag, "rd.bootif"))
            ignore_bootif = !_nm_utils_ascii_str_to_bool(argument, TRUE);
        else if (nm_streq(tag, "rd.neednet"))
            neednet = _nm_utils_ascii_str_to_bool(argument, TRUE);
        else if (nm_streq(tag, "rd.znet")) {
            if (!znets)
                znets = g_ptr_array_new_with_free_func(g_free);
            g_ptr_array_add(znets, g_strdup(argument));
        } else if (nm_streq(tag, "rd.znet_ifname")) {
            reader_parse_znet_ifname(reader, argument);
        } else if (g_ascii_strcasecmp(tag, "BOOTIF") == 0) {
            nm_clear_g_free(&bootif_val);
            bootif_val = g_strdup(argument);
        } else if (nm_streq(tag, "rd.ethtool")) {
            reader_parse_ethtool(reader, argument);
        } else if (nm_streq(tag, "rd.net.dns")) {
            reader_parse_global_dns(reader, argument);
        } else if (nm_streq(tag, "rd.net.dns-backend")) {
            reader_parse_dns_backend(reader, argument);
        } else if (nm_streq(tag, "rd.net.dns-resolve-mode")) {
            reader_parse_dns_resolve_mode(reader, argument);
        }
    }

    for (i = 0; i < reader->vlan_parents->len; i++) {
        NMConnection      *connection;
        NMSettingIPConfig *s_ip;

        /* Disable IP configuration for parent connections of VLANs,
         * unless those interfaces were explicitly configured otherwise. */

        connection = reader_get_connection(reader, reader->vlan_parents->pdata[i], NULL, TRUE);
        if (!g_hash_table_contains(reader->explicit_ip_connections, connection)) {
            s_ip = nm_connection_get_setting_ip4_config(connection);
            if (s_ip) {
                g_object_set(s_ip,
                             NM_SETTING_IP_CONFIG_METHOD,
                             NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
                             NULL);
            }

            s_ip = nm_connection_get_setting_ip6_config(connection);
            if (s_ip) {
                g_object_set(s_ip,
                             NM_SETTING_IP_CONFIG_METHOD,
                             NM_SETTING_IP6_CONFIG_METHOD_DISABLED,
                             NULL);
            }
        }
    }

    if (ignore_bootif)
        nm_clear_g_free(&bootif_val);
    if (bootif_val) {
        NMConnection   *connection;
        NMSettingWired *s_wired;
        const char     *bootif = bootif_val;
        char            prefix[4];

        if (!nm_utils_hwaddr_valid(bootif, ETH_ALEN)) {
            strncpy(prefix, bootif, 3);
            prefix[3] = '\0';

            if (NM_IN_STRSET(prefix, "01-", "01:", "00-", "00:")
                && nm_utils_hwaddr_valid(&bootif[3], ETH_ALEN)) {
                /*
                 * BOOTIF MAC address can be prefixed with a hardware type identifier.
                 * "01" stays for "wired", "00" is also accepted as it means "undefined".
                 * No others are known.
                 */
                bootif += 3;
            }
        }

        connection = reader_get_connection(reader, NULL, NM_SETTING_WIRED_SETTING_NAME, FALSE);
        if (!connection)
            connection = reader_get_default_connection(reader);

        s_wired = nm_connection_get_setting_wired(connection);

        if (nm_connection_get_interface_name(connection)
            || (nm_setting_wired_get_mac_address(s_wired)
                && !nm_utils_hwaddr_matches(nm_setting_wired_get_mac_address(s_wired),
                                            -1,
                                            bootif,
                                            -1))) {
            connection = reader_create_connection(reader,
                                                  "bootif_connection",
                                                  "BOOTIF Connection",
                                                  NULL,
                                                  bootif,
                                                  NM_SETTING_WIRED_SETTING_NAME,
                                                  NMI_AUTOCONNECT_PRIORITY_FIRMWARE,
                                                  NM_CONNECTION_MULTI_CONNECT_SINGLE);
        } else {
            g_object_set(s_wired, NM_SETTING_WIRED_MAC_ADDRESS, bootif, NULL);
        }
    }

    if (bootdev) {
        NMConnection *connection;

        connection                 = reader_get_connection(reader, bootdev, NULL, TRUE);
        reader->bootdev_connection = connection;
        connection_set_needed(connection);
    }

    if (neednet) {
        if (!(etc_connections_dir && g_file_test(etc_connections_dir, G_FILE_TEST_IS_DIR))
            && g_hash_table_size(reader->hash) == 0) {
            /* Make sure there's some connection. */
            reader_get_default_connection(reader);
        }

        g_hash_table_foreach(reader->hash, connection_set_needed_cb, NULL);
    }

    if (routes)
        reader_add_routes(reader, routes);

    if (nameservers)
        reader_add_nameservers(reader, nameservers);

    if (znets) {
        for (i = 0; i < znets->len; i++)
            reader_parse_rd_znet(reader, znets->pdata[i], net_ifnames);
    }

    if (g_hash_table_size(reader->znet_ifnames)) {
        _LOGW(LOGD_CORE, "Mismatch between rd.znet_ifname and rd.znet");
    }

    g_hash_table_foreach(reader->hash, _normalize_conn, NULL);

    NM_SET_OUT(hostname, g_steal_pointer(&reader->hostname));
    NM_SET_OUT(carrier_timeout_sec, reader->carrier_timeout_sec);
    NM_SET_OUT(dns_backend, g_steal_pointer(&reader->dns_backend));
    NM_SET_OUT(dns_resolve_mode, g_steal_pointer(&reader->dns_resolve_mode));

    if (reader->global_dns) {
        if (global_dns_servers) {
            g_ptr_array_add(reader->global_dns, NULL);
            *global_dns_servers = (char **) g_ptr_array_free(reader->global_dns, FALSE);
            reader->global_dns  = NULL;
        }
    } else {
        NM_SET_OUT(global_dns_servers, NULL);
    }

    return reader_destroy(reader, FALSE);
}
