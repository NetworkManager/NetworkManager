/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "libnm-core-intern/nm-core-internal.h"
#include "libnm-glib-aux/nm-uuid.h"

#include "nm-initrd-generator/nm-initrd-generator.h"

#include "libnm-glib-aux/nm-test-utils.h"

#define TEST_INITRD_DIR NM_BUILD_SRCDIR "/src/nm-initrd-generator/tests"

/*****************************************************************************/

#define _parse(ARGV,                                                                   \
               out_hostname,                                                           \
               out_carrier_timeout_sec,                                                \
               _out_global_dns_servers,                                                \
               _out_dns_backend,                                                       \
               _out_dns_resolve_mode)                                                  \
    ({                                                                                 \
        const char *const *const _ARGV                    = (ARGV);                    \
        char **const             _out_hostname            = (out_hostname);            \
        gint64 *const            _out_carrier_timeout_sec = (out_carrier_timeout_sec); \
        GHashTable              *_connections;                                         \
                                                                                       \
        _connections = nmi_cmdline_reader_parse(NULL,                                  \
                                                TEST_INITRD_DIR "/sysfs",              \
                                                _ARGV,                                 \
                                                _out_hostname,                         \
                                                _out_carrier_timeout_sec,              \
                                                _out_global_dns_servers,               \
                                                _out_dns_backend,                      \
                                                _out_dns_resolve_mode);                \
        g_assert(_connections);                                                        \
                                                                                       \
        _connections;                                                                  \
    })

#define _parse_cons(ARGV)                                                                   \
    ({                                                                                      \
        GHashTable   *_con_connections;                                                     \
        gs_free char *_con_hostname            = NULL;                                      \
        gint64        _con_carrier_timeout_sec = 0;                                         \
                                                                                            \
        _con_connections = _parse((ARGV),                                                   \
                                  nmtst_get_rand_bool() ? &_con_hostname : NULL,            \
                                  nmtst_get_rand_bool() ? &_con_carrier_timeout_sec : NULL, \
                                  NULL,                                                     \
                                  NULL,                                                     \
                                  NULL);                                                    \
        g_assert_cmpstr(_con_hostname, ==, NULL);                                           \
        g_assert_cmpint(_con_carrier_timeout_sec, ==, 0);                                   \
                                                                                            \
        _con_connections;                                                                   \
    })

#define _parse_con(ARGV, connection_name)                                        \
    ({                                                                           \
        gs_unref_hashtable GHashTable *_1_connections = NULL;                    \
        NMConnection                  *_1_connection;                            \
        const char *const              _1_connection_name = (connection_name);   \
                                                                                 \
        g_assert(_1_connection_name);                                            \
                                                                                 \
        _1_connections = _parse_cons((ARGV));                                    \
                                                                                 \
        g_assert_cmpint(g_hash_table_size(_1_connections), ==, 1);               \
                                                                                 \
        _1_connection = g_hash_table_lookup(_1_connections, _1_connection_name); \
        g_assert(NM_IS_CONNECTION(_1_connection));                               \
                                                                                 \
        nmtst_assert_connection_verifies_without_normalization(_1_connection);   \
                                                                                 \
        NM_CONNECTION(g_object_ref(_1_connection));                              \
    })

#define _parse_no_con(ARGV)                                        \
    G_STMT_START                                                   \
    {                                                              \
        gs_unref_hashtable GHashTable *_0_connections = NULL;      \
                                                                   \
        _0_connections = _parse_cons(ARGV);                        \
        g_assert_cmpint(g_hash_table_size(_0_connections), ==, 0); \
    }                                                              \
    G_STMT_END

/*****************************************************************************/

static void
test_auto(void)
{
    const char *const            *ARGV       = NM_MAKE_STRV("ip=auto");
    gs_unref_object NMConnection *connection = NULL;
    NMSettingConnection          *s_con;
    NMSettingWired               *s_wired;
    NMSettingIPConfig            *s_ip4;
    NMSettingIPConfig            *s_ip6;

    connection = _parse_con(ARGV, "default_connection");

    g_assert(!nm_connection_get_setting_vlan(connection));

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "Wired Connection");
    g_assert_cmpint(nm_setting_connection_get_timestamp(s_con), ==, 0);
    g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                    ==,
                    NM_CONNECTION_MULTI_CONNECT_MULTIPLE);
    g_assert_cmpint(nm_setting_connection_get_wait_device_timeout(s_con), ==, -1);

    g_assert(nm_setting_connection_get_autoconnect(s_con));
    g_assert_cmpint(nm_setting_connection_get_autoconnect_priority(s_con),
                    ==,
                    NMI_AUTOCONNECT_PRIORITY_CMDLINE);

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert(s_wired);
    g_assert(!nm_setting_wired_get_mac_address(s_wired));
    g_assert_cmpint(nm_setting_wired_get_mtu(s_wired), ==, 0);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip4), ==, 0);
    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip4), ==, 0);
    g_assert(!nm_setting_ip_config_get_gateway(s_ip4));

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip6), ==, 0);
    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip6), ==, 0);
    g_assert(!nm_setting_ip_config_get_gateway(s_ip6));
}

static void
test_dhcp_with_hostname(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV        = NM_MAKE_STRV("ip=::::host1::dhcp,dhcp6");
    NMConnection                  *connection;
    NMSettingConnection           *s_con;
    NMSettingWired                *s_wired;
    NMSettingIPConfig             *s_ip4;
    NMSettingIPConfig             *s_ip6;
    gs_free char                  *hostname            = NULL;
    gint64                         carrier_timeout_sec = 0;

    connections = _parse(ARGV, &hostname, &carrier_timeout_sec, NULL, NULL, NULL);
    g_assert_cmpint(g_hash_table_size(connections), ==, 1);
    g_assert_cmpstr(hostname, ==, "host1");
    g_assert_cmpint(carrier_timeout_sec, ==, 0);

    connection = g_hash_table_lookup(connections, "default_connection");

    nmtst_assert_connection_verifies_without_normalization(connection);

    g_assert(!nm_connection_get_setting_vlan(connection));

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "Wired Connection");
    g_assert_cmpint(nm_setting_connection_get_timestamp(s_con), ==, 0);
    g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                    ==,
                    NM_CONNECTION_MULTI_CONNECT_MULTIPLE);
    g_assert_cmpint(nm_setting_connection_get_wait_device_timeout(s_con), ==, -1);

    g_assert(nm_setting_connection_get_autoconnect(s_con));
    g_assert_cmpint(nm_setting_connection_get_autoconnect_priority(s_con),
                    ==,
                    NMI_AUTOCONNECT_PRIORITY_CMDLINE);

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert(s_wired);
    g_assert(!nm_setting_wired_get_mac_address(s_wired));
    g_assert_cmpint(nm_setting_wired_get_mtu(s_wired), ==, 0);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
}

static void
test_dhcp_with_mtu(void)
{
    const char *const *ARGV0  = NM_MAKE_STRV("ip=:dhcp6,dhcp:1499");
    const char *const *ARGV1  = NM_MAKE_STRV("ip=::::::dhcp:1499");
    const char *const *ARGV[] = {ARGV0, ARGV1};
    guint              i;

    for (i = 0; i < G_N_ELEMENTS(ARGV); i++) {
        gs_unref_object NMConnection *connection = NULL;
        NMSettingConnection          *s_con;
        NMSettingWired               *s_wired;
        NMSettingIPConfig            *s_ip4;
        NMSettingIPConfig            *s_ip6;

        connection = _parse_con(ARGV[i], "default_connection");

        s_con = nm_connection_get_setting_connection(connection);
        g_assert(s_con);
        g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                        ==,
                        NM_SETTING_WIRED_SETTING_NAME);
        g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "Wired Connection");
        g_assert_cmpint(nm_setting_connection_get_timestamp(s_con), ==, 0);
        g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                        ==,
                        NM_CONNECTION_MULTI_CONNECT_MULTIPLE);
        g_assert_cmpint(nm_setting_connection_get_wait_device_timeout(s_con), ==, -1);

        g_assert(nm_setting_connection_get_autoconnect(s_con));
        g_assert_cmpint(nm_setting_connection_get_autoconnect_priority(s_con),
                        ==,
                        NMI_AUTOCONNECT_PRIORITY_CMDLINE);

        s_wired = nm_connection_get_setting_wired(connection);
        g_assert(s_wired);
        g_assert(!nm_setting_wired_get_mac_address(s_wired));
        g_assert_cmpint(nm_setting_wired_get_mtu(s_wired), ==, 1499);

        s_ip4 = nm_connection_get_setting_ip4_config(connection);
        g_assert(s_ip4);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                        ==,
                        NM_SETTING_IP4_CONFIG_METHOD_AUTO);

        s_ip6 = nm_connection_get_setting_ip6_config(connection);
        g_assert(s_ip6);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                        ==,
                        NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    }
}

static void
test_dhcp_timeout(void)
{
    struct {
        const char *const *cmdline;
        int                timeout;
    } data[] = {
        {NM_MAKE_STRV("ip=dhcp"), 90},
        {NM_MAKE_STRV("ip=dhcp", "rd.net.timeout.dhcp=0"), 90},
        {NM_MAKE_STRV("ip=dhcp", "rd.net.timeout.dhcp=foobar"), 90},
        {NM_MAKE_STRV("ip=dhcp", "rd.net.timeout.dhcp=42"), 42},
        {NM_MAKE_STRV("ip=dhcp", "rd.net.dhcp.retry=2"), 180},
        {NM_MAKE_STRV("ip=dhcp", "rd.net.dhcp.retry=3", "rd.net.timeout.dhcp=40"), 120},
        {NM_MAKE_STRV("ip=dhcp", "rd.net.timeout.dhcp=infinity"), G_MAXINT32},
        {NM_MAKE_STRV("ip=dhcp", "rd.net.timeout.dhcp=infinity", "rd.net.dhcp.retry=100"),
         G_MAXINT32},
    };
    guint i;

    for (i = 0; i < G_N_ELEMENTS(data); i++) {
        gs_unref_object NMConnection *connection = NULL;
        NMSettingConnection          *s_con;
        NMSettingIPConfig            *s_ip4;
        NMSettingIPConfig            *s_ip6;

        connection = _parse_con(data[i].cmdline, "default_connection");

        s_con = nm_connection_get_setting_connection(connection);
        g_assert(s_con);
        g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                        ==,
                        NM_SETTING_WIRED_SETTING_NAME);
        g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "Wired Connection");
        g_assert_cmpint(nm_setting_connection_get_timestamp(s_con), ==, 0);
        g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                        ==,
                        NM_CONNECTION_MULTI_CONNECT_MULTIPLE);
        g_assert_cmpint(nm_setting_connection_get_wait_device_timeout(s_con), ==, -1);
        g_assert_cmpint(nm_setting_connection_get_autoconnect_retries(s_con), ==, 1);
        g_assert(nm_setting_connection_get_autoconnect(s_con));
        g_assert_cmpint(nm_setting_connection_get_autoconnect_priority(s_con),
                        ==,
                        NMI_AUTOCONNECT_PRIORITY_CMDLINE);

        s_ip4 = nm_connection_get_setting_ip4_config(connection);
        g_assert(s_ip4);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                        ==,
                        NM_SETTING_IP4_CONFIG_METHOD_AUTO);
        g_assert_cmpint(nm_setting_ip_config_get_dhcp_timeout(s_ip4), ==, data[i].timeout);
        g_assert_cmpint(nm_setting_ip_config_get_required_timeout(s_ip4), ==, -1);

        s_ip6 = nm_connection_get_setting_ip6_config(connection);
        g_assert(s_ip6);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                        ==,
                        NM_SETTING_IP6_CONFIG_METHOD_AUTO);
        g_assert_cmpint(nm_setting_ip_config_get_dhcp_timeout(s_ip6), ==, data[i].timeout);
        g_assert_cmpint(nm_setting_ip_config_get_required_timeout(s_ip6), ==, -1);
    }
}

static void
test_if_auto_with_mtu(void)
{
    const char *const            *ARGV       = NM_MAKE_STRV("ip=eth0:dhcp,dhcp6:1666", "=");
    gs_unref_object NMConnection *connection = NULL;
    NMSettingConnection          *s_con;
    NMSettingWired               *s_wired;
    NMSettingIPConfig            *s_ip4;
    NMSettingIPConfig            *s_ip6;

    connection = _parse_con(ARGV, "eth0");

    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth0");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpint(nm_setting_connection_get_autoconnect_retries(s_con), ==, 1);

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert(s_wired);
    g_assert_cmpint(nm_setting_wired_get_mtu(s_wired), ==, 1666);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_dhcp_timeout(s_ip4), ==, 90);
    g_assert_cmpint(nm_setting_ip_config_get_required_timeout(s_ip4),
                    ==,
                    NMI_IP_REQUIRED_TIMEOUT_MSEC);

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_required_timeout(s_ip6),
                    ==,
                    NMI_IP_REQUIRED_TIMEOUT_MSEC);
}

static void
test_if_dhcp6(void)
{
    const char *const            *ARGV       = NM_MAKE_STRV("ip=eth1:dhcp6");
    gs_unref_object NMConnection *connection = NULL;
    NMSettingIPConfig            *s_ip4;
    NMSettingIPConfig            *s_ip6;

    connection = _parse_con(ARGV, "eth1");

    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth1");

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                    ==,
                    NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip6));
}

static void
test_if_auto_with_mtu_and_mac(void)
{
    const char *const            *ARGV       = NM_MAKE_STRV("ip=eth2:auto6:2048:00:53:ef:12:34:56");
    gs_unref_object NMConnection *connection = NULL;
    NMSettingWired               *s_wired;
    NMSettingIPConfig            *s_ip4;
    NMSettingIPConfig            *s_ip6;

    connection = _parse_con(ARGV, "eth2");

    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth2");

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert(s_wired);
    g_assert_cmpint(nm_setting_wired_get_mtu(s_wired), ==, 2048);
    g_assert_cmpstr(nm_setting_wired_get_cloned_mac_address(s_wired), ==, "00:53:EF:12:34:56");

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                    ==,
                    NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
    g_assert_cmpstr(nm_setting_ip_config_get_dhcp_hostname(s_ip4), ==, NULL);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip6));
}

static void
test_if_ip4_manual(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV = NM_MAKE_STRV("ip=192.0.2.2::192.0.2.1:255.255.255.0:"
                                                       "hostname0.example.com:eth3:none:192.0.2.53",
                                           "ip=203.0.113.2::203.0.113.1:26:"
                                                       "hostname1.example.com:eth4");
    NMConnection                  *connection;
    NMSettingConnection           *s_con;
    NMSettingIPConfig             *s_ip4;
    NMSettingIPConfig             *s_ip6;
    NMIPAddress                   *ip_addr;
    gs_free char                  *hostname            = NULL;
    gint64                         carrier_timeout_sec = 0;

    connections = _parse(ARGV, &hostname, &carrier_timeout_sec, NULL, NULL, NULL);
    g_assert_cmpint(g_hash_table_size(connections), ==, 2);
    g_assert_cmpstr(hostname, ==, "hostname1.example.com");
    g_assert_cmpint(carrier_timeout_sec, ==, 0);

    connection = g_hash_table_lookup(connections, "eth3");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth3");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpint(nm_setting_connection_get_wait_device_timeout(s_con), ==, -1);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                    ==,
                    NM_SETTING_IP4_CONFIG_METHOD_MANUAL);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip4), ==, 1);
    g_assert_cmpstr(nm_setting_ip_config_get_dns(s_ip4, 0), ==, "192.0.2.53");
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip4), ==, 0);
    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip4), ==, 1);
    ip_addr = nm_setting_ip_config_get_address(s_ip4, 0);
    g_assert(ip_addr);
    g_assert_cmpstr(nm_ip_address_get_address(ip_addr), ==, "192.0.2.2");
    g_assert_cmpint(nm_ip_address_get_prefix(ip_addr), ==, 24);
    g_assert_cmpstr(nm_setting_ip_config_get_gateway(s_ip4), ==, "192.0.2.1");
    g_assert_cmpstr(nm_setting_ip_config_get_dhcp_hostname(s_ip4), ==, NULL);
    g_assert_cmpint(nm_setting_ip_config_get_required_timeout(s_ip4), ==, -1);

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                    ==,
                    NM_SETTING_IP6_CONFIG_METHOD_DISABLED);
    g_assert_cmpstr(nm_setting_ip_config_get_dhcp_hostname(s_ip6), ==, NULL);
    g_assert(nm_setting_ip_config_get_may_fail(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_required_timeout(s_ip6), ==, -1);

    connection = g_hash_table_lookup(connections, "eth4");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth4");

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                    ==,
                    NM_SETTING_IP4_CONFIG_METHOD_MANUAL);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip4), ==, 0);
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip4), ==, 0);
    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip4), ==, 1);
    ip_addr = nm_setting_ip_config_get_address(s_ip4, 0);
    g_assert(ip_addr);
    g_assert_cmpstr(nm_ip_address_get_address(ip_addr), ==, "203.0.113.2");
    g_assert_cmpint(nm_ip_address_get_prefix(ip_addr), ==, 26);
    g_assert_cmpstr(nm_setting_ip_config_get_gateway(s_ip4), ==, "203.0.113.1");
    g_assert_cmpstr(nm_setting_ip_config_get_dhcp_hostname(s_ip4), ==, NULL);

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert(nm_setting_ip_config_get_may_fail(s_ip6));
}

static void
test_if_ip4_auto(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV        = NM_MAKE_STRV("ip=172.25.1.1::172.25.1.2:24:"
                                                              "myhostname:eth0:dhcp",
                                           "rd.net.timeout.dhcp=10");
    NMConnection                  *connection;
    NMSettingConnection           *s_con;
    NMSettingIPConfig             *s_ip4;
    NMSettingIPConfig             *s_ip6;
    NMIPAddress                   *ip_addr;
    gs_free char                  *hostname            = NULL;
    gint64                         carrier_timeout_sec = 0;

    connections = _parse(ARGV, &hostname, &carrier_timeout_sec, NULL, NULL, NULL);
    g_assert_cmpint(g_hash_table_size(connections), ==, 1);
    g_assert_cmpstr(hostname, ==, "myhostname");
    g_assert_cmpint(carrier_timeout_sec, ==, 0);

    connection = g_hash_table_lookup(connections, "eth0");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth0");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpint(nm_setting_connection_get_wait_device_timeout(s_con), ==, -1);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip4), ==, 0);
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip4), ==, 0);
    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip4), ==, 1);
    g_assert_cmpint(nm_setting_ip_config_get_dhcp_timeout(s_ip4), ==, 10);
    g_assert_cmpstr(nm_setting_ip_config_get_gateway(s_ip4), ==, "172.25.1.2");
    g_assert_cmpstr(nm_setting_ip_config_get_dhcp_hostname(s_ip4), ==, "myhostname");

    ip_addr = nm_setting_ip_config_get_address(s_ip4, 0);
    g_assert(ip_addr);
    g_assert_cmpstr(nm_ip_address_get_address(ip_addr), ==, "172.25.1.1");
    g_assert_cmpint(nm_ip_address_get_prefix(ip_addr), ==, 24);

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert_cmpstr(nm_setting_ip_config_get_dhcp_hostname(s_ip6), ==, "myhostname");
    g_assert(nm_setting_ip_config_get_may_fail(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_dhcp_timeout(s_ip6), ==, 10);
    g_assert_cmpint(nm_setting_ip_config_get_required_timeout(s_ip6), ==, -1);
}

static void
test_if_ip4_manual_no_dev(void)
{
    const char *const   *ARGV = NM_MAKE_STRV("ip=192.0.2.2::192.0.2.1:24:::", "=foo");
    NMConnection        *connection;
    NMSettingConnection *s_con;
    NMSettingIPConfig   *s_ip4;
    NMSettingIPConfig   *s_ip6;
    NMIPAddress         *ip_addr;

    connection = _parse_con(ARGV, "default_connection");
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "Wired Connection");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpint(nm_setting_connection_get_wait_device_timeout(s_con), ==, -1);
    g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                    ==,
                    NM_CONNECTION_MULTI_CONNECT_SINGLE);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                    ==,
                    NM_SETTING_IP4_CONFIG_METHOD_MANUAL);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip4), ==, 0);
    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip4), ==, 1);
    ip_addr = nm_setting_ip_config_get_address(s_ip4, 0);
    g_assert(ip_addr);
    g_assert_cmpstr(nm_ip_address_get_address(ip_addr), ==, "192.0.2.2");
    g_assert_cmpint(nm_ip_address_get_prefix(ip_addr), ==, 24);
    g_assert_cmpstr(nm_setting_ip_config_get_gateway(s_ip4), ==, "192.0.2.1");

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert(nm_setting_ip_config_get_may_fail(s_ip6));
}

static void
test_if_ip6_manual(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV = NM_MAKE_STRV("ip=[2001:0db8::02]/56::[2001:0db8::01]::"
                                                       "hostname0.example.com:eth4::[2001:0db8::53]");
    NMConnection                  *connection;
    NMSettingIPConfig             *s_ip4;
    NMSettingIPConfig             *s_ip6;
    NMIPAddress                   *ip_addr;
    gs_free char                  *hostname            = NULL;
    gint64                         carrier_timeout_sec = 0;

    connections = _parse(ARGV, &hostname, &carrier_timeout_sec, NULL, NULL, NULL);
    g_assert_cmpint(g_hash_table_size(connections), ==, 1);
    g_assert_cmpstr(hostname, ==, "hostname0.example.com");
    g_assert_cmpint(carrier_timeout_sec, ==, 0);

    connection = g_hash_table_lookup(connections, "eth4");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth4");

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    g_assert_cmpstr(nm_setting_ip_config_get_dhcp_hostname(s_ip4), ==, "hostname0.example.com");

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                    ==,
                    NM_SETTING_IP6_CONFIG_METHOD_MANUAL);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip6), ==, 1);
    g_assert_cmpstr(nm_setting_ip_config_get_dns(s_ip6, 0), ==, "2001:db8::53");
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip6), ==, 0);
    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip6), ==, 1);
    ip_addr = nm_setting_ip_config_get_address(s_ip6, 0);
    g_assert(ip_addr);
    g_assert_cmpstr(nm_ip_address_get_address(ip_addr), ==, "2001:db8::2");
    g_assert_cmpint(nm_ip_address_get_prefix(ip_addr), ==, 56);
    g_assert_cmpstr(nm_setting_ip_config_get_gateway(s_ip6), ==, "2001:db8::1");
    g_assert_cmpstr(nm_setting_ip_config_get_dhcp_hostname(s_ip6), ==, NULL);
}

static void
test_if_off(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV        = NM_MAKE_STRV("ip=off",
                                           "ip=ens3:off",
                                           "ip=10.0.0.8:::::ens4:off",
                                           "ip=[2001:DB8::8]:::::ens5:off");
    NMConnection                  *connection;
    NMSettingIPConfig             *s_ip4;
    NMSettingIPConfig             *s_ip6;
    struct {
        const char name[32];
        const char ipv4_method[32];
        const char ipv6_method[32];
    } conn_expected[] = {
        {"default_connection",
         NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
         NM_SETTING_IP6_CONFIG_METHOD_DISABLED},
        {"ens3", NM_SETTING_IP4_CONFIG_METHOD_DISABLED, NM_SETTING_IP6_CONFIG_METHOD_DISABLED},
        {"ens4", NM_SETTING_IP4_CONFIG_METHOD_MANUAL, NM_SETTING_IP6_CONFIG_METHOD_DISABLED},
        {"ens5", NM_SETTING_IP4_CONFIG_METHOD_DISABLED, NM_SETTING_IP6_CONFIG_METHOD_MANUAL},
    };
    guint i;

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, G_N_ELEMENTS(conn_expected));

    for (i = 0; i < G_N_ELEMENTS(conn_expected); i++) {
        connection = g_hash_table_lookup(connections, conn_expected[i].name);
        nmtst_assert_connection_verifies_without_normalization(connection);

        s_ip4 = nm_connection_get_setting_ip4_config(connection);
        g_assert(s_ip4);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, conn_expected[i].ipv4_method);

        s_ip6 = nm_connection_get_setting_ip6_config(connection);
        g_assert(s_ip6);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, conn_expected[i].ipv6_method);
    }
}

static void
test_if_mac_ifname(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV = NM_MAKE_STRV("ip=[2001:0db8::42]/64::[2001:0db8::01]::"
                                                       "hostname0:00-11-22-33-44-55::[2001:0db8::53]");
    NMConnection                  *connection;
    NMSettingIPConfig             *s_ip4;
    NMSettingIPConfig             *s_ip6;
    NMSettingWired                *s_wired;
    NMIPAddress                   *ip_addr;
    gs_free char                  *hostname            = NULL;
    gint64                         carrier_timeout_sec = 0;

    connections = _parse(ARGV, &hostname, &carrier_timeout_sec, NULL, NULL, NULL);
    g_assert_cmpint(g_hash_table_size(connections), ==, 1);
    g_assert_cmpstr(hostname, ==, "hostname0");
    g_assert_cmpint(carrier_timeout_sec, ==, 0);

    connection = g_hash_table_lookup(connections, "00:11:22:33:44:55");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "00:11:22:33:44:55");
    g_assert_cmpstr(nm_connection_get_interface_name(connection), ==, NULL);

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert(s_wired);
    g_assert_cmpstr(nm_setting_wired_get_mac_address(s_wired), ==, "00:11:22:33:44:55");

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    g_assert_cmpstr(nm_setting_ip_config_get_dhcp_hostname(s_ip4), ==, "hostname0");

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                    ==,
                    NM_SETTING_IP6_CONFIG_METHOD_MANUAL);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip6), ==, 1);
    g_assert_cmpstr(nm_setting_ip_config_get_dns(s_ip6, 0), ==, "2001:db8::53");
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip6), ==, 0);
    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip6), ==, 1);
    g_assert_cmpstr(nm_setting_ip_config_get_gateway(s_ip6), ==, "2001:db8::1");
    g_assert_cmpstr(nm_setting_ip_config_get_dhcp_hostname(s_ip6), ==, NULL);

    ip_addr = nm_setting_ip_config_get_address(s_ip6, 0);
    g_assert(ip_addr);
    g_assert_cmpstr(nm_ip_address_get_address(ip_addr), ==, "2001:db8::42");
    g_assert_cmpint(nm_ip_address_get_prefix(ip_addr), ==, 64);
}

static void
test_multiple_merge(void)
{
    const char *const *ARGV =
        NM_MAKE_STRV("ip=192.0.2.2/16:::::eth0", "ip=[2001:db8::2]:::56::eth0");
    gs_unref_object NMConnection *connection = NULL;
    NMSettingConnection          *s_con;
    NMSettingWired               *s_wired;
    NMSettingIPConfig            *s_ip4;
    NMSettingIPConfig            *s_ip6;
    NMIPAddress                  *ip_addr;

    connection = _parse_con(ARGV, "eth0");

    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth0");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpint(nm_setting_connection_get_wait_device_timeout(s_con), ==, -1);

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert(s_wired);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                    ==,
                    NM_SETTING_IP4_CONFIG_METHOD_MANUAL);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip4), ==, 1);
    ip_addr = nm_setting_ip_config_get_address(s_ip4, 0);
    g_assert(ip_addr);
    g_assert_cmpstr(nm_ip_address_get_address(ip_addr), ==, "192.0.2.2");
    g_assert_cmpint(nm_ip_address_get_prefix(ip_addr), ==, 16);

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                    ==,
                    NM_SETTING_IP6_CONFIG_METHOD_MANUAL);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip6), ==, 1);
    ip_addr = nm_setting_ip_config_get_address(s_ip6, 0);
    g_assert(ip_addr);
    g_assert_cmpstr(nm_ip_address_get_address(ip_addr), ==, "2001:db8::2");
    g_assert_cmpint(nm_ip_address_get_prefix(ip_addr), ==, 56);
}

static void
test_multiple_bootdev(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;

    const char *const *ARGV = NM_MAKE_STRV("nameserver=1.2.3.4",
                                           "ip=eth3:auto6",
                                           "ip=eth4:dhcp",
                                           "ip=eth5:link6",
                                           "bootdev=eth4");

    NMConnection        *connection;
    NMSettingConnection *s_con;
    NMSettingIPConfig   *s_ip4;
    NMSettingIPConfig   *s_ip6;

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 3);

    connection = g_hash_table_lookup(connections, "eth3");
    g_assert(connection);
    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpint(nm_setting_connection_get_wait_device_timeout(s_con), ==, -1);
    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);

    connection = g_hash_table_lookup(connections, "eth4");
    g_assert(connection);
    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpint(nm_setting_connection_get_wait_device_timeout(s_con),
                    ==,
                    NMI_WAIT_DEVICE_TIMEOUT_MSEC);
    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip4), ==, 1);
    g_assert_cmpstr(nm_setting_ip_config_get_dns(s_ip4, 0), ==, "1.2.3.4");

    connection = g_hash_table_lookup(connections, "eth5");
    g_assert(connection);
    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpint(nm_setting_connection_get_wait_device_timeout(s_con), ==, -1);
    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                    ==,
                    NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL);
}

static void
test_bootdev(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV        = NM_MAKE_STRV("vlan=vlan2:ens5", "bootdev=ens3");
    NMConnection                  *connection;
    NMSettingConnection           *s_con;

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 3);

    connection = g_hash_table_lookup(connections, "ens3");
    nmtst_assert_connection_verifies_without_normalization(connection);

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "ens3");
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, "ens3");
    g_assert_cmpint(nm_setting_connection_get_wait_device_timeout(s_con),
                    ==,
                    NMI_WAIT_DEVICE_TIMEOUT_MSEC);

    connection = g_hash_table_lookup(connections, "vlan2");
    nmtst_assert_connection_verifies_without_normalization(connection);

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_VLAN_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "vlan2");
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, "vlan2");

    connection = g_hash_table_lookup(connections, "ens5");
    nmtst_assert_connection_verifies_without_normalization(connection);

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "ens5");
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, "ens5");
}

static void
test_some_more(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV        = NM_MAKE_STRV("bootdev=eth1",
                                           "hail",
                                           "nameserver=[2001:DB8:3::53]",
                                           "satan",
                                           "nameserver=192.0.2.53",
                                           "worship",
                                           "doom",
                                           "rd.peerdns=0",
                                           "rd.route=[2001:DB8:3::/48]:[2001:DB8:2::1]:ens10");
    NMConnection                  *connection;
    NMSettingConnection           *s_con;
    NMSettingWired                *s_wired;
    NMSettingIPConfig             *s_ip4;
    NMSettingIPConfig             *s_ip6;
    NMIPRoute                     *ip_route;

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 2);

    connection = g_hash_table_lookup(connections, "eth1");
    nmtst_assert_connection_verifies_without_normalization(connection);

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "eth1");
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, "eth1");
    g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                    ==,
                    NM_CONNECTION_MULTI_CONNECT_SINGLE);

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert(s_wired);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    g_assert(nm_setting_ip_config_get_ignore_auto_dns(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip4), ==, 0);
    g_assert(!nm_setting_ip_config_get_gateway(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip4), ==, 1);
    g_assert_cmpstr(nm_setting_ip_config_get_dns(s_ip4, 0), ==, "192.0.2.53");

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert(nm_setting_ip_config_get_ignore_auto_dns(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip6), ==, 1);
    g_assert(!nm_setting_ip_config_get_gateway(s_ip6));
    g_assert_cmpstr(nm_setting_ip_config_get_dns(s_ip6, 0), ==, "2001:db8:3::53");

    connection = g_hash_table_lookup(connections, "ens10");
    nmtst_assert_connection_verifies_without_normalization(connection);

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "ens10");
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, "ens10");
    g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                    ==,
                    NM_CONNECTION_MULTI_CONNECT_SINGLE);

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert(s_wired);
    g_assert(!nm_setting_wired_get_mac_address(s_wired));

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip6), ==, 1);
    g_assert_cmpstr(nm_setting_ip_config_get_dns(s_ip6, 0), ==, "2001:db8:3::53");
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip6), ==, 1);
    g_assert(!nm_setting_ip_config_get_gateway(s_ip6));
    ip_route = nm_setting_ip_config_get_route(s_ip6, 0);
    g_assert_cmpstr(nm_ip_route_get_dest(ip_route), ==, "2001:db8:3::");
    g_assert_cmpint(nm_ip_route_get_family(ip_route), ==, AF_INET6);
    g_assert_cmpint(nm_ip_route_get_metric(ip_route), ==, -1);
    g_assert_cmpstr(nm_ip_route_get_next_hop(ip_route), ==, "2001:db8:2::1");
    g_assert_cmpint(nm_ip_route_get_prefix(ip_route), ==, 48);
}

static void
test_bond(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV        = NM_MAKE_STRV("rd.route=192.0.2.53::bond0",
                                           "bond=bond0:eth0,eth1:mode=balance-rr:9000",
                                           "nameserver=203.0.113.53");
    NMConnection                  *connection;
    NMSettingConnection           *s_con;
    NMSettingIPConfig             *s_ip4;
    NMSettingIPConfig             *s_ip6;
    NMSettingBond                 *s_bond;
    NMSettingWired                *s_wired;
    NMIPRoute                     *ip_route;
    const char                    *controller_uuid;

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 3);

    connection = g_hash_table_lookup(connections, "bond0");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_connection_type(connection),
                    ==,
                    NM_SETTING_BOND_SETTING_NAME);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "bond0");
    controller_uuid = nm_connection_get_uuid(connection);
    g_assert(controller_uuid);

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert(s_wired);
    g_assert_cmpint(nm_setting_wired_get_mtu(s_wired), ==, 9000);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip4), ==, 1);
    g_assert_cmpstr(nm_setting_ip_config_get_dns(s_ip4, 0), ==, "203.0.113.53");
    g_assert(!nm_setting_ip_config_get_gateway(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip4), ==, 1);
    ip_route = nm_setting_ip_config_get_route(s_ip4, 0);
    g_assert_cmpstr(nm_ip_route_get_dest(ip_route), ==, "192.0.2.53");
    g_assert_cmpint(nm_ip_route_get_family(ip_route), ==, AF_INET);
    g_assert_cmpint(nm_ip_route_get_metric(ip_route), ==, -1);
    g_assert(!nm_ip_route_get_next_hop(ip_route));
    g_assert_cmpint(nm_ip_route_get_prefix(ip_route), ==, 32);

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip6), ==, 0);
    g_assert(!nm_setting_ip_config_get_gateway(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip6), ==, 0);

    s_bond = nm_connection_get_setting_bond(connection);
    g_assert(s_bond);
    g_assert_cmpint(nm_setting_bond_get_num_options(s_bond), ==, 1);
    g_assert_cmpstr(nm_setting_bond_get_option_by_name(s_bond, "mode"), ==, "balance-rr");

    connection = g_hash_table_lookup(connections, "eth0");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth0");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "eth0");
    g_assert_cmpstr(nm_setting_connection_get_port_type(s_con), ==, NM_SETTING_BOND_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_controller(s_con), ==, controller_uuid);
    g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                    ==,
                    NM_CONNECTION_MULTI_CONNECT_SINGLE);

    connection = g_hash_table_lookup(connections, "eth1");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth1");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "eth1");
    g_assert_cmpstr(nm_setting_connection_get_port_type(s_con), ==, NM_SETTING_BOND_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_controller(s_con), ==, controller_uuid);
    g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                    ==,
                    NM_CONNECTION_MULTI_CONNECT_SINGLE);
}

static void
test_bond_ip(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV =
        NM_MAKE_STRV("bond=bond0:eth0,eth1",
                     "ip=192.168.1.1::192.168.1.254:24::bond0:none:1480:01:02:03:04:05:06",
                     "nameserver=4.8.15.16");
    NMConnection        *connection;
    NMSettingConnection *s_con;
    NMSettingIPConfig   *s_ip4;
    NMSettingIPConfig   *s_ip6;
    NMSettingWired      *s_wired;
    NMSettingBond       *s_bond;
    NMIPAddress         *ip_addr;
    const char          *controller_uuid;

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 3);

    connection = g_hash_table_lookup(connections, "bond0");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_connection_type(connection),
                    ==,
                    NM_SETTING_BOND_SETTING_NAME);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "bond0");
    controller_uuid = nm_connection_get_uuid(connection);
    g_assert(controller_uuid);

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert(s_wired);
    g_assert_cmpint(nm_setting_wired_get_mtu(s_wired), ==, 1480);
    g_assert_cmpstr(nm_setting_wired_get_cloned_mac_address(s_wired), ==, "01:02:03:04:05:06");

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                    ==,
                    NM_SETTING_IP4_CONFIG_METHOD_MANUAL);
    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip4), ==, 1);
    ip_addr = nm_setting_ip_config_get_address(s_ip4, 0);
    g_assert(ip_addr);
    g_assert_cmpstr(nm_ip_address_get_address(ip_addr), ==, "192.168.1.1");
    g_assert_cmpint(nm_ip_address_get_prefix(ip_addr), ==, 24);
    g_assert_cmpstr(nm_setting_ip_config_get_gateway(s_ip4), ==, "192.168.1.254");
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip4), ==, 1);
    g_assert_cmpstr(nm_setting_ip_config_get_dns(s_ip4, 0), ==, "4.8.15.16");
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip4), ==, 0);

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                    ==,
                    NM_SETTING_IP6_CONFIG_METHOD_DISABLED);
    g_assert_cmpstr(nm_setting_ip_config_get_dhcp_hostname(s_ip6), ==, NULL);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip6), ==, 0);
    g_assert(!nm_setting_ip_config_get_gateway(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip6), ==, 0);

    s_bond = nm_connection_get_setting_bond(connection);
    g_assert(s_bond);
    g_assert_cmpint(nm_setting_bond_get_num_options(s_bond), ==, 1);
    g_assert_cmpstr(nm_setting_bond_get_option_by_name(s_bond, "mode"), ==, "balance-rr");

    connection = g_hash_table_lookup(connections, "eth0");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth0");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "eth0");
    g_assert_cmpstr(nm_setting_connection_get_port_type(s_con), ==, NM_SETTING_BOND_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_controller(s_con), ==, controller_uuid);
    g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                    ==,
                    NM_CONNECTION_MULTI_CONNECT_SINGLE);

    connection = g_hash_table_lookup(connections, "eth1");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth1");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "eth1");
    g_assert_cmpstr(nm_setting_connection_get_port_type(s_con), ==, NM_SETTING_BOND_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_controller(s_con), ==, controller_uuid);
    g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                    ==,
                    NM_CONNECTION_MULTI_CONNECT_SINGLE);
}

static void
test_bond_ip6_option(void)
{
    /* Test that IPv6 addresses within [] are parsed fine in different positions */

    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV =
        NM_MAKE_STRV("bond=bond0:eth0,eth1:arp_interval=100,ns_ip6_target=[fc08::1]",
                     "bond=bond1:eth2,eth3:arp_interval=100,ns_ip6_target=[fc08::1]:9000",
                     "bond=bond2:eth4,eth5:ns_ip6_target=[fc08::1],arp_interval=100");
    NMConnection  *connection;
    NMSettingBond *s_bond;

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 9);

    connection = g_hash_table_lookup(connections, "bond0");
    nmtst_assert_connection_verifies_without_normalization(connection);
    s_bond = nm_connection_get_setting_bond(connection);
    g_assert(s_bond);
    g_assert_cmpint(nm_setting_bond_get_num_options(s_bond), ==, 3);
    g_assert_cmpstr(nm_setting_bond_get_option_by_name(s_bond, "ns_ip6_target"), ==, "fc08::1");

    connection = g_hash_table_lookup(connections, "bond1");
    nmtst_assert_connection_verifies_without_normalization(connection);
    s_bond = nm_connection_get_setting_bond(connection);
    g_assert(s_bond);
    g_assert_cmpint(nm_setting_bond_get_num_options(s_bond), ==, 3);
    g_assert_cmpstr(nm_setting_bond_get_option_by_name(s_bond, "ns_ip6_target"), ==, "fc08::1");

    connection = g_hash_table_lookup(connections, "bond2");
    nmtst_assert_connection_verifies_without_normalization(connection);
    s_bond = nm_connection_get_setting_bond(connection);
    g_assert(s_bond);
    g_assert_cmpint(nm_setting_bond_get_num_options(s_bond), ==, 3);
    g_assert_cmpstr(nm_setting_bond_get_option_by_name(s_bond, "ns_ip6_target"), ==, "fc08::1");
}

static void
test_bond_default(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV        = NM_MAKE_STRV("bond");
    NMConnection                  *connection;
    NMSettingConnection           *s_con;
    NMSettingIPConfig             *s_ip4;
    NMSettingIPConfig             *s_ip6;
    NMSettingBond                 *s_bond;
    const char                    *controller_uuid;

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 2);

    connection = g_hash_table_lookup(connections, "bond0");

    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_connection_type(connection),
                    ==,
                    NM_SETTING_BOND_SETTING_NAME);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "bond0");
    controller_uuid = nm_connection_get_uuid(connection);
    g_assert(controller_uuid);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip4), ==, 0);
    g_assert(!nm_setting_ip_config_get_gateway(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip4), ==, 0);

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip6), ==, 0);
    g_assert(!nm_setting_ip_config_get_gateway(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip6), ==, 0);

    s_bond = nm_connection_get_setting_bond(connection);
    g_assert(s_bond);
    g_assert_cmpint(nm_setting_bond_get_num_options(s_bond), ==, 1);
    g_assert_cmpstr(nm_setting_bond_get_option_by_name(s_bond, "mode"), ==, "balance-rr");

    connection = g_hash_table_lookup(connections, "eth0");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth0");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "eth0");
    g_assert_cmpstr(nm_setting_connection_get_port_type(s_con), ==, NM_SETTING_BOND_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_controller(s_con), ==, controller_uuid);
    g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                    ==,
                    NM_CONNECTION_MULTI_CONNECT_SINGLE);
}

static void
test_bridge(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV        = NM_MAKE_STRV("bridge=bridge0:eth0,eth1",
                                           "rd.route=192.0.2.53::bridge0",
                                           "rd.net.timeout.dhcp=10");
    NMConnection                  *connection;
    NMSettingConnection           *s_con;
    NMSettingIPConfig             *s_ip4;
    NMSettingIPConfig             *s_ip6;
    NMSettingBridge               *s_bridge;
    NMIPRoute                     *ip_route;
    const char                    *controller_uuid;

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 3);

    connection = g_hash_table_lookup(connections, "bridge0");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_connection_type(connection),
                    ==,
                    NM_SETTING_BRIDGE_SETTING_NAME);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "bridge0");
    controller_uuid = nm_connection_get_uuid(connection);
    g_assert(controller_uuid);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip4), ==, 0);
    g_assert(!nm_setting_ip_config_get_gateway(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip4), ==, 1);
    g_assert_cmpint(nm_setting_ip_config_get_dhcp_timeout(s_ip4), ==, 10);
    ip_route = nm_setting_ip_config_get_route(s_ip4, 0);
    g_assert_cmpstr(nm_ip_route_get_dest(ip_route), ==, "192.0.2.53");
    g_assert_cmpint(nm_ip_route_get_family(ip_route), ==, AF_INET);
    g_assert_cmpint(nm_ip_route_get_metric(ip_route), ==, -1);
    g_assert(!nm_ip_route_get_next_hop(ip_route));
    g_assert_cmpint(nm_ip_route_get_prefix(ip_route), ==, 32);
    g_assert_cmpint(nm_setting_ip_config_get_required_timeout(s_ip4),
                    ==,
                    NMI_IP_REQUIRED_TIMEOUT_MSEC);

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip6), ==, 0);
    g_assert(!nm_setting_ip_config_get_gateway(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip6), ==, 0);
    g_assert_cmpint(nm_setting_ip_config_get_dhcp_timeout(s_ip6), ==, 10);
    g_assert_cmpint(nm_setting_ip_config_get_required_timeout(s_ip6), ==, -1);

    s_bridge = nm_connection_get_setting_bridge(connection);
    g_assert(s_bridge);
    g_assert_cmpint(nm_setting_bridge_get_stp(s_bridge), ==, FALSE);

    connection = g_hash_table_lookup(connections, "eth0");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth0");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "eth0");
    g_assert_cmpstr(nm_setting_connection_get_port_type(s_con), ==, NM_SETTING_BRIDGE_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_controller(s_con), ==, controller_uuid);
    g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                    ==,
                    NM_CONNECTION_MULTI_CONNECT_SINGLE);

    connection = g_hash_table_lookup(connections, "eth1");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth1");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "eth1");
    g_assert_cmpstr(nm_setting_connection_get_port_type(s_con), ==, NM_SETTING_BRIDGE_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_controller(s_con), ==, controller_uuid);
    g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                    ==,
                    NM_CONNECTION_MULTI_CONNECT_SINGLE);
}

static void
test_bridge_default(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV        = NM_MAKE_STRV("bridge");
    NMConnection                  *connection;
    NMSettingConnection           *s_con;
    NMSettingIPConfig             *s_ip4;
    NMSettingIPConfig             *s_ip6;
    NMSettingBridge               *s_bridge;
    const char                    *controller_uuid;

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 2);

    connection = g_hash_table_lookup(connections, "br0");

    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_connection_type(connection),
                    ==,
                    NM_SETTING_BRIDGE_SETTING_NAME);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "br0");
    controller_uuid = nm_connection_get_uuid(connection);
    g_assert(controller_uuid);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip4), ==, 0);
    g_assert(!nm_setting_ip_config_get_gateway(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip4), ==, 0);

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip6), ==, 0);
    g_assert(!nm_setting_ip_config_get_gateway(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip6), ==, 0);

    s_bridge = nm_connection_get_setting_bridge(connection);
    g_assert(s_bridge);

    connection = g_hash_table_lookup(connections, "eth0");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth0");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "eth0");
    g_assert_cmpstr(nm_setting_connection_get_port_type(s_con), ==, NM_SETTING_BRIDGE_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_controller(s_con), ==, controller_uuid);
    g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                    ==,
                    NM_CONNECTION_MULTI_CONNECT_SINGLE);
}

static void
test_bridge_ip(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV =
        NM_MAKE_STRV("ip=bridge123:auto:1280:00:11:22:33:CA:fe",
                     "bridge=bridge123:eth0,eth1,eth2,eth3,eth4,eth5,eth6,eth7,eth8,eth9");
    NMConnection        *connection;
    NMSettingConnection *s_con;
    NMSettingIPConfig   *s_ip4;
    NMSettingIPConfig   *s_ip6;
    NMSettingWired      *s_wired;
    NMSettingBridge     *s_bridge;
    const char          *controller_uuid;
    guint                i;

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 11);

    connection = g_hash_table_lookup(connections, "bridge123");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_connection_type(connection),
                    ==,
                    NM_SETTING_BRIDGE_SETTING_NAME);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "bridge123");
    controller_uuid = nm_connection_get_uuid(connection);
    g_assert(controller_uuid);

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert(s_wired);
    g_assert_cmpint(nm_setting_wired_get_mtu(s_wired), ==, 1280);
    g_assert_cmpstr(nm_setting_wired_get_cloned_mac_address(s_wired), ==, "00:11:22:33:CA:FE");

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);

    s_bridge = nm_connection_get_setting_bridge(connection);
    g_assert(s_bridge);

    for (i = 0; i < 10; i++) {
        char ifname[16];

        nm_sprintf_buf(ifname, "eth%u", i);

        connection = g_hash_table_lookup(connections, ifname);
        nmtst_assert_connection_verifies_without_normalization(connection);
        g_assert_cmpstr(nm_connection_get_id(connection), ==, ifname);

        s_con = nm_connection_get_setting_connection(connection);
        g_assert(s_con);
        g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                        ==,
                        NM_SETTING_WIRED_SETTING_NAME);
        g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, ifname);
        g_assert_cmpstr(nm_setting_connection_get_port_type(s_con),
                        ==,
                        NM_SETTING_BRIDGE_SETTING_NAME);
        g_assert_cmpstr(nm_setting_connection_get_controller(s_con), ==, controller_uuid);
        g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                        ==,
                        NM_CONNECTION_MULTI_CONNECT_SINGLE);
    }
}

static void
test_team(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV = NM_MAKE_STRV("team=team0:eth0,eth1", "ip=team0:dhcp6");
    NMConnection                  *connection;
    NMSettingConnection           *s_con;
    NMSettingIPConfig             *s_ip4;
    NMSettingIPConfig             *s_ip6;
    NMSettingTeam                 *s_team;
    const char                    *controller_uuid;

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 3);

    connection = g_hash_table_lookup(connections, "team0");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_connection_type(connection),
                    ==,
                    NM_SETTING_TEAM_SETTING_NAME);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "team0");
    controller_uuid = nm_connection_get_uuid(connection);
    g_assert(controller_uuid);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                    ==,
                    NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
    g_assert_cmpstr(nm_setting_ip_config_get_dhcp_hostname(s_ip4), ==, NULL);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip4), ==, 0);
    g_assert(!nm_setting_ip_config_get_gateway(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip4), ==, 0);

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip6), ==, 0);
    g_assert(!nm_setting_ip_config_get_gateway(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_num_routes(s_ip6), ==, 0);

    s_team = nm_connection_get_setting_team(connection);
    g_assert(s_team);

    connection = g_hash_table_lookup(connections, "eth0");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth0");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "eth0");
    g_assert_cmpstr(nm_setting_connection_get_port_type(s_con), ==, NM_SETTING_TEAM_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_controller(s_con), ==, controller_uuid);
    g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                    ==,
                    NM_CONNECTION_MULTI_CONNECT_SINGLE);

    connection = g_hash_table_lookup(connections, "eth1");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth1");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "eth1");
    g_assert_cmpstr(nm_setting_connection_get_port_type(s_con), ==, NM_SETTING_TEAM_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_controller(s_con), ==, controller_uuid);
    g_assert_cmpint(nm_setting_connection_get_multi_connect(s_con),
                    ==,
                    NM_CONNECTION_MULTI_CONNECT_SINGLE);
}

static void
test_vlan(void)
{
    const char *const *ARGV0  = NM_MAKE_STRV("ip=eth0.100:dhcp", "vlan=eth0.100:eth0");
    const char *const *ARGV1  = NM_MAKE_STRV("vlan=eth0.100:eth0", "ip=eth0.100:dhcp");
    const char *const *ARGV[] = {ARGV0, ARGV1};
    guint              i;

    for (i = 0; i < G_N_ELEMENTS(ARGV); i++) {
        gs_unref_hashtable GHashTable *connections = NULL;
        NMConnection                  *connection;
        NMSettingIPConfig             *s_ip4;
        NMSettingIPConfig             *s_ip6;
        NMSettingVlan                 *s_vlan;

        connections = _parse_cons(ARGV[i]);
        g_assert_cmpint(g_hash_table_size(connections), ==, 2);

        /* VLAN eth0.100 */
        connection = g_hash_table_lookup(connections, "eth0.100");
        nmtst_assert_connection_verifies_without_normalization(connection);
        g_assert_cmpstr(nm_connection_get_connection_type(connection),
                        ==,
                        NM_SETTING_VLAN_SETTING_NAME);
        g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth0.100");

        s_vlan = nm_connection_get_setting_vlan(connection);
        g_assert(s_vlan);
        g_assert_cmpstr(nm_setting_vlan_get_parent(s_vlan), ==, "eth0");
        g_assert_cmpint(nm_setting_vlan_get_id(s_vlan), ==, 100);

        s_ip4 = nm_connection_get_setting_ip4_config(connection);
        g_assert(s_ip4);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                        ==,
                        NM_SETTING_IP4_CONFIG_METHOD_AUTO);

        s_ip6 = nm_connection_get_setting_ip6_config(connection);
        g_assert(s_ip6);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                        ==,
                        NM_SETTING_IP6_CONFIG_METHOD_AUTO);

        /* Ethernet eth0 */
        connection = g_hash_table_lookup(connections, "eth0");
        nmtst_assert_connection_verifies_without_normalization(connection);
        g_assert_cmpstr(nm_connection_get_connection_type(connection),
                        ==,
                        NM_SETTING_WIRED_SETTING_NAME);
        g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth0");

        s_ip4 = nm_connection_get_setting_ip4_config(connection);
        g_assert(s_ip4);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                        ==,
                        NM_SETTING_IP4_CONFIG_METHOD_DISABLED);

        s_ip6 = nm_connection_get_setting_ip6_config(connection);
        g_assert(s_ip6);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                        ==,
                        NM_SETTING_IP6_CONFIG_METHOD_DISABLED);
    }
}

static void
test_vlan_with_dhcp_on_parent(void)
{
    const char *const *ARGV0  = NM_MAKE_STRV("vlan=eth0.100:eth0", "ip=eth0:dhcp");
    const char *const *ARGV1  = NM_MAKE_STRV("ip=eth0:dhcp", "vlan=eth0.100:eth0");
    const char *const *ARGV[] = {ARGV0, ARGV1};
    guint              i;

    for (i = 0; i < G_N_ELEMENTS(ARGV); i++) {
        gs_unref_hashtable GHashTable *connections = NULL;
        NMConnection                  *connection;
        NMSettingIPConfig             *s_ip4;
        NMSettingIPConfig             *s_ip6;
        NMSettingVlan                 *s_vlan;

        connections = _parse_cons(ARGV[i]);
        g_assert_cmpint(g_hash_table_size(connections), ==, 2);

        /* VLAN eth0.100 */
        connection = g_hash_table_lookup(connections, "eth0.100");
        nmtst_assert_connection_verifies_without_normalization(connection);
        g_assert_cmpstr(nm_connection_get_connection_type(connection),
                        ==,
                        NM_SETTING_VLAN_SETTING_NAME);
        g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth0.100");

        s_ip4 = nm_connection_get_setting_ip4_config(connection);
        g_assert(s_ip4);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                        ==,
                        NM_SETTING_IP4_CONFIG_METHOD_AUTO);

        s_ip6 = nm_connection_get_setting_ip6_config(connection);
        g_assert(s_ip6);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                        ==,
                        NM_SETTING_IP6_CONFIG_METHOD_AUTO);

        s_vlan = nm_connection_get_setting_vlan(connection);
        g_assert(s_vlan);
        g_assert_cmpstr(nm_setting_vlan_get_parent(s_vlan), ==, "eth0");
        g_assert_cmpint(nm_setting_vlan_get_id(s_vlan), ==, 100);

        /* Ethernet eth0 */
        connection = g_hash_table_lookup(connections, "eth0");
        nmtst_assert_connection_verifies_without_normalization(connection);
        g_assert_cmpstr(nm_connection_get_connection_type(connection),
                        ==,
                        NM_SETTING_WIRED_SETTING_NAME);
        g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth0");

        s_ip4 = nm_connection_get_setting_ip4_config(connection);
        g_assert(s_ip4);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                        ==,
                        NM_SETTING_IP4_CONFIG_METHOD_AUTO);

        s_ip6 = nm_connection_get_setting_ip6_config(connection);
        g_assert(s_ip6);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                        ==,
                        NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    }
}

static void
test_vlan_over_bond(void)
{
    const char *const *ARGV0  = NM_MAKE_STRV("ip=1.2.3.4:::24::vlan1:none",
                                            "bond=bond2:ens3,ens4:mode=active-backup",
                                            "vlan=vlan1:bond2");
    const char *const *ARGV1  = NM_MAKE_STRV("vlan=vlan1:bond2",
                                            "ip=1.2.3.4:::24::vlan1:none",
                                            "bond=bond2:ens3,ens4:mode=active-backup");
    const char *const *ARGV2  = NM_MAKE_STRV("bond=bond2:ens3,ens4:mode=active-backup",
                                            "ip=1.2.3.4:::24::vlan1:none",
                                            "vlan=vlan1:bond2");
    const char *const *ARGV[] = {ARGV0, ARGV1, ARGV2};
    guint              i;

    for (i = 0; i < G_N_ELEMENTS(ARGV); i++) {
        gs_unref_hashtable GHashTable *connections = NULL;
        NMConnection                  *connection;
        NMSettingIPConfig             *s_ip4;
        NMSettingIPConfig             *s_ip6;
        NMSettingVlan                 *s_vlan;

        connections = _parse_cons(ARGV[i]);
        g_assert_cmpint(g_hash_table_size(connections), ==, 4);

        /* VLAN vlan1 */
        connection = g_hash_table_lookup(connections, "vlan1");
        nmtst_assert_connection_verifies_without_normalization(connection);
        g_assert_cmpstr(nm_connection_get_connection_type(connection),
                        ==,
                        NM_SETTING_VLAN_SETTING_NAME);
        g_assert_cmpstr(nm_connection_get_id(connection), ==, "vlan1");

        s_ip4 = nm_connection_get_setting_ip4_config(connection);
        g_assert(s_ip4);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                        ==,
                        NM_SETTING_IP4_CONFIG_METHOD_MANUAL);

        s_ip6 = nm_connection_get_setting_ip6_config(connection);
        g_assert(s_ip6);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                        ==,
                        NM_SETTING_IP6_CONFIG_METHOD_DISABLED);

        s_vlan = nm_connection_get_setting_vlan(connection);
        g_assert(s_vlan);
        g_assert_cmpstr(nm_setting_vlan_get_parent(s_vlan), ==, "bond2");
        g_assert_cmpint(nm_setting_vlan_get_id(s_vlan), ==, 1);

        /* Bond bond2 */
        connection = g_hash_table_lookup(connections, "bond2");
        nmtst_assert_connection_verifies_without_normalization(connection);
        g_assert_cmpstr(nm_connection_get_connection_type(connection),
                        ==,
                        NM_SETTING_BOND_SETTING_NAME);
        g_assert_cmpstr(nm_connection_get_id(connection), ==, "bond2");

        s_ip4 = nm_connection_get_setting_ip4_config(connection);
        g_assert(s_ip4);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                        ==,
                        NM_SETTING_IP4_CONFIG_METHOD_DISABLED);

        s_ip6 = nm_connection_get_setting_ip6_config(connection);
        g_assert(s_ip6);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                        ==,
                        NM_SETTING_IP6_CONFIG_METHOD_DISABLED);

        /* Ethernet ens3 and ens4 */
        connection = g_hash_table_lookup(connections, "ens3");
        g_assert(connection);
        connection = g_hash_table_lookup(connections, "ens4");
        g_assert(connection);
    }
}

static void
test_ibft_ip_dev(void)
{
    const char *const            *ARGV = NM_MAKE_STRV("ip=eth0:ibft");
    NMSettingConnection          *s_con;
    gs_unref_object NMConnection *connection    = NULL;
    const char                   *s_hwaddr      = "00:53:00:ab:00:01";
    const char                   *s_vlanid      = "666";
    const char                   *s_ipaddr      = "2001:0db8:0000:0000:0000:0000:0000:0002";
    gs_free char                 *expected_uuid = NULL;

    connection = _parse_con(ARGV, "eth0");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_VLAN_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, NULL);

    expected_uuid = nm_uuid_generate_from_strings_old("ibft",
                                                      s_hwaddr,
                                                      s_vlanid ? "V" : "v",
                                                      s_vlanid ? s_vlanid : "",
                                                      s_ipaddr ? "A" : "DHCP",
                                                      s_ipaddr ? s_ipaddr : "");

    g_assert_cmpstr(expected_uuid, ==, "16d9bd1c-e2ab-31ef-9196-860078e81a23");
    g_assert_cmpstr(nm_connection_get_uuid(connection), ==, expected_uuid);
}

static void
test_ibft_ip_dev_mac(void)
{
    const char *const            *ARGV = NM_MAKE_STRV("ip=00-53-06-66-ab-01:ibft");
    NMSettingConnection          *s_con;
    gs_unref_object NMConnection *connection = NULL;

    connection = _parse_con(ARGV, "00:53:06:66:AB:01");

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, NULL);
}

static void
_test_ibft_ip(const char *const *ARGV)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    NMConnection                  *connection;

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 2);

    connection = g_hash_table_lookup(connections, "ibft0");
    nmtst_assert_connection_verifies_without_normalization(connection);

    g_assert_cmpstr(nm_connection_get_id(connection), ==, "iBFT VLAN Connection 0");
    g_assert_cmpstr(nm_connection_get_interface_name(connection), ==, NULL);

    connection = g_hash_table_lookup(connections, "ibft2");
    nmtst_assert_connection_verifies_without_normalization(connection);
    g_assert_cmpstr(nm_connection_get_id(connection), ==, "iBFT Connection 2");
    g_assert_cmpstr(nm_connection_get_interface_name(connection), ==, NULL);
}

static void
test_ibft_ip(void)
{
    const char *const *ARGV = NM_MAKE_STRV("ip=ibft");

    _test_ibft_ip(ARGV);
}

static void
test_ibft_rd_iscsi_ibft(void)
{
    const char *const *ARGV = NM_MAKE_STRV("rd.iscsi.ibft");

    _test_ibft_ip(ARGV);
}

static void
test_ignore_extra(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV        = NM_MAKE_STRV("blabla", "extra", "lalala");

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 0);
}

static void
test_rd_znet(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const *const       ARGV =
        NM_MAKE_STRV("ip=10.11.12.13::10.11.12.1:24:foo.example.com:enc800:none",
                     "ip=slc600:dhcp",
                     "rd.znet=qeth,0.0.0800,0.0.0801,0.0.0802,layer2=0,portno=1",
                     "rd.znet=ctc,0.0.0600,0.0.0601,layer2=0,portno=0");
    NMConnection           *connection;
    NMSettingConnection    *s_con;
    NMSettingWired         *s_wired;
    const char *const      *v_subchannels;
    const NMUtilsNamedValue s390_options[] = {
        {.name = "layer2", .value_str = "0"},
        {.name = "portno", .value_str = "1"},
    };
    int           i_s390_options_keys;
    gs_free char *hostname            = NULL;
    gint64        carrier_timeout_sec = 0;

    connections = _parse(ARGV, &hostname, &carrier_timeout_sec, NULL, NULL, NULL);
    g_assert_cmpint(g_hash_table_size(connections), ==, 2);
    g_assert_cmpstr(hostname, ==, "foo.example.com");
    g_assert_cmpint(carrier_timeout_sec, ==, 0);

    connection = g_hash_table_lookup(connections, "enc800");
    g_assert(NM_IS_CONNECTION(connection));

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(NM_IS_SETTING_CONNECTION(s_con));
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "enc800");
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, "enc800");

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert(NM_IS_SETTING_WIRED(s_wired));

    v_subchannels = nm_setting_wired_get_s390_subchannels(s_wired);
    g_assert(v_subchannels);
    g_assert_cmpstr(v_subchannels[0], ==, "0.0.0800");
    g_assert_cmpstr(v_subchannels[1], ==, "0.0.0801");
    g_assert_cmpstr(v_subchannels[2], ==, "0.0.0802");
    g_assert_cmpstr(v_subchannels[3], ==, NULL);

    g_assert_cmpint(nm_setting_wired_get_num_s390_options(s_wired), ==, G_N_ELEMENTS(s390_options));
    for (i_s390_options_keys = 0; i_s390_options_keys < G_N_ELEMENTS(s390_options);
         i_s390_options_keys++) {
        const NMUtilsNamedValue *s390_option = &s390_options[i_s390_options_keys];
        const char              *k;
        const char              *v;
        const char              *v2;

        g_assert(s390_option->name);
        g_assert(s390_option->value_str);
        v = nm_setting_wired_get_s390_option_by_key(s_wired, s390_option->name);
        g_assert(v);
        g_assert_cmpstr(v, ==, s390_option->value_str);

        if (!nm_setting_wired_get_s390_option(s_wired, i_s390_options_keys, &k, &v2))
            g_assert_not_reached();
        g_assert_cmpstr(k, ==, s390_option->name);
        g_assert(v == v2);
        g_assert_cmpstr(v2, ==, s390_option->value_str);
    }

    nmtst_assert_connection_verifies_without_normalization(connection);

    connection = g_hash_table_lookup(connections, "slc600");
    g_assert(NM_IS_CONNECTION(connection));

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(NM_IS_SETTING_CONNECTION(s_con));
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "slc600");
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, "slc600");

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert(NM_IS_SETTING_WIRED(s_wired));

    v_subchannels = nm_setting_wired_get_s390_subchannels(s_wired);
    g_assert(v_subchannels);
    g_assert_cmpstr(v_subchannels[0], ==, "0.0.0600");
    g_assert_cmpstr(v_subchannels[1], ==, "0.0.0601");
    g_assert_cmpstr(v_subchannels[2], ==, NULL);

    nmtst_assert_connection_verifies_without_normalization(connection);
}

static void
test_rd_znet_legacy(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const *const       ARGV =
        NM_MAKE_STRV("ip=10.11.12.13::10.11.12.1:24:foo.example.com:eth0:none",
                     "rd.znet=qeth,0.0.0800,0.0.0801,0.0.0802,layer2=0,portno=1",
                     "rd.znet=ctc,0.0.0600,0.0.0601,layer2=0,portno=0",
                     "ip=ctc0:dhcp",
                     "net.ifnames=0");
    NMConnection        *connection;
    NMSettingConnection *s_con;
    gs_free char        *hostname            = NULL;
    gint64               carrier_timeout_sec = 0;

    connections = _parse(ARGV, &hostname, &carrier_timeout_sec, NULL, NULL, NULL);
    g_assert_cmpint(g_hash_table_size(connections), ==, 2);
    g_assert_cmpstr(hostname, ==, "foo.example.com");
    g_assert_cmpint(carrier_timeout_sec, ==, 0);

    connection = g_hash_table_lookup(connections, "eth0");
    g_assert(NM_IS_CONNECTION(connection));

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(NM_IS_SETTING_CONNECTION(s_con));
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "eth0");
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, "eth0");

    nmtst_assert_connection_verifies_without_normalization(connection);

    connection = g_hash_table_lookup(connections, "ctc0");
    g_assert(NM_IS_CONNECTION(connection));

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(NM_IS_SETTING_CONNECTION(s_con));
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "ctc0");
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, "ctc0");

    nmtst_assert_connection_verifies_without_normalization(connection);
}

static void
test_rd_znet_no_ip(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const *const       ARGV =
        NM_MAKE_STRV("rd.znet=qeth,0.0.0800,0.0.0801,0.0.0802,layer2=0,portno=1");

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 0);
}

static void
test_rd_znet_malformed(void)
{
    const char *const *const ARGV0  = NM_MAKE_STRV("rd.znet=");
    const char *const *const ARGV1  = NM_MAKE_STRV("rd.znet=,");
    const char *const *const ARGV2  = NM_MAKE_STRV("rd.znet=foobar");
    const char *const *const ARGV3  = NM_MAKE_STRV("rd.znet=qeth,0.0.0800,,,layer2=0,portno=1");
    const char *const *const ARGV[] = {ARGV0, ARGV1, ARGV2, ARGV3};
    guint                    i;

    for (i = 0; i < G_N_ELEMENTS(ARGV); i++) {
        gs_unref_hashtable GHashTable *connections = NULL;

        connections = _parse_cons(ARGV[i]);
        g_assert_cmpint(g_hash_table_size(connections), ==, 0);
    }
}

static void
test_rd_znet_ifnames(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const *const       ARGV =
        NM_MAKE_STRV("rd.znet_ifname=zeth1:0.0.0600,0.0.0601",
                     "rd.znet=qeth,0.0.0800,0.0.0801,0.0.0802,layer2=0,portno=1,foo",
                     "rd.znet=ctc,0.0.0600,0.0.0601",
                     "rd.znet_ifname=zeth0:0.0.0800,0.0.0801,0.0.0802",
                     "ip=zeth0:dhcp",
                     "ip=zeth1:dhcp");
    NMConnection        *connection;
    NMSettingConnection *s_con;
    NMSettingWired      *s_wired;
    gs_free char        *hostname            = NULL;
    gint64               carrier_timeout_sec = 0;
    const char *const   *v_subchannels;

    connections = _parse(ARGV, &hostname, &carrier_timeout_sec, NULL, NULL, NULL);
    g_assert_cmpint(g_hash_table_size(connections), ==, 2);

    connection = g_hash_table_lookup(connections, "zeth0");
    g_assert(NM_IS_CONNECTION(connection));

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(NM_IS_SETTING_CONNECTION(s_con));
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "zeth0");
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, "zeth0");

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert_cmpstr(nm_setting_wired_get_s390_nettype(s_wired), ==, "qeth");
    g_assert(s_wired);

    v_subchannels = nm_setting_wired_get_s390_subchannels(s_wired);
    g_assert(v_subchannels);
    g_assert_cmpstr(v_subchannels[0], ==, "0.0.0800");
    g_assert_cmpstr(v_subchannels[1], ==, "0.0.0801");
    g_assert_cmpstr(v_subchannels[2], ==, "0.0.0802");
    g_assert_cmpstr(v_subchannels[3], ==, NULL);

    nmtst_assert_connection_verifies_without_normalization(connection);

    connection = g_hash_table_lookup(connections, "zeth1");
    g_assert(NM_IS_CONNECTION(connection));

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(NM_IS_SETTING_CONNECTION(s_con));
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "zeth1");
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, "zeth1");

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert_cmpstr(nm_setting_wired_get_s390_nettype(s_wired), ==, "ctc");
    g_assert(s_wired);

    v_subchannels = nm_setting_wired_get_s390_subchannels(s_wired);
    g_assert(v_subchannels);
    g_assert_cmpstr(v_subchannels[0], ==, "0.0.0600");
    g_assert_cmpstr(v_subchannels[1], ==, "0.0.0601");
    g_assert_cmpstr(v_subchannels[2], ==, NULL);

    nmtst_assert_connection_verifies_without_normalization(connection);
}

static void
test_bootif_ip(void)
{
    const char *const            *ARGV       = NM_MAKE_STRV("BOOTIF=00:53:AB:cd:02:03", "ip=dhcp");
    gs_unref_object NMConnection *connection = NULL;
    NMSettingWired               *s_wired;
    NMSettingIPConfig            *s_ip4;
    NMSettingIPConfig            *s_ip6;

    connection = _parse_con(ARGV, "default_connection");

    g_assert_cmpstr(nm_connection_get_id(connection), ==, "Wired Connection");

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert_cmpstr(nm_setting_wired_get_mac_address(s_wired), ==, "00:53:AB:CD:02:03");
    g_assert(s_wired);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));
    g_assert(!nm_setting_ip_config_get_may_fail(s_ip4));

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip6));
}

static void
test_neednet_no_args(void)
{
    const char *const            *ARGV       = NM_MAKE_STRV("rd.neednet");
    gs_unref_object NMConnection *connection = NULL;
    NMSettingWired               *s_wired;
    NMSettingIPConfig            *s_ip4;
    NMSettingIPConfig            *s_ip6;

    connection = _parse_con(ARGV, "default_connection");

    g_assert_cmpstr(nm_connection_get_id(connection), ==, "Wired Connection");

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert(s_wired);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    g_assert(nm_setting_ip_config_get_may_fail(s_ip4));
    g_assert_cmpint(nm_setting_ip_config_get_required_timeout(s_ip4),
                    ==,
                    NMI_IP_REQUIRED_TIMEOUT_MSEC);

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert(nm_setting_ip_config_get_may_fail(s_ip6));
    g_assert_cmpint(nm_setting_ip_config_get_required_timeout(s_ip6), ==, -1);
}

static void
test_neednet_args(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV        = NM_MAKE_STRV("rd.neednet",
                                           "ip=eno1:dhcp",
                                           "ip=172.25.1.100::172.25.1.1:24::eno2",
                                           "bridge=br0:eno3");
    NMConnection                  *connection;
    NMSettingConnection           *s_con;

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 4);

    connection = g_hash_table_lookup(connections, "eno1");
    nmtst_assert_connection_verifies_without_normalization(connection);
    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, "eno1");
    g_assert_cmpint(nm_setting_connection_get_wait_device_timeout(s_con),
                    ==,
                    NMI_WAIT_DEVICE_TIMEOUT_MSEC);

    connection = g_hash_table_lookup(connections, "eno2");
    nmtst_assert_connection_verifies_without_normalization(connection);
    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, "eno2");
    g_assert_cmpint(nm_setting_connection_get_wait_device_timeout(s_con),
                    ==,
                    NMI_WAIT_DEVICE_TIMEOUT_MSEC);

    connection = g_hash_table_lookup(connections, "eno3");
    nmtst_assert_connection_verifies_without_normalization(connection);
    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, "eno3");
    g_assert_cmpint(nm_setting_connection_get_wait_device_timeout(s_con),
                    ==,
                    NMI_WAIT_DEVICE_TIMEOUT_MSEC);

    connection = g_hash_table_lookup(connections, "br0");
    nmtst_assert_connection_verifies_without_normalization(connection);
    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, "br0");
    g_assert_cmpint(nm_setting_connection_get_wait_device_timeout(s_con), ==, -1);
}

static void
test_bootif_no_ip(void)
{
    const char *const            *ARGV       = NM_MAKE_STRV("BOOTIF=00:53:AB:cd:02:03");
    gs_unref_object NMConnection *connection = NULL;
    NMSettingWired               *s_wired;
    NMSettingIPConfig            *s_ip4;
    NMSettingIPConfig            *s_ip6;

    connection = _parse_con(ARGV, "default_connection");

    g_assert_cmpstr(nm_connection_get_id(connection), ==, "Wired Connection");

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert_cmpstr(nm_setting_wired_get_mac_address(s_wired), ==, "00:53:AB:CD:02:03");
    g_assert(s_wired);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    g_assert(nm_setting_ip_config_get_may_fail(s_ip4));

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert(nm_setting_ip_config_get_may_fail(s_ip6));
}

static void
test_bootif_hwtype(void)
{
    const char *const *ARGV0  = NM_MAKE_STRV("ip=eth0:dhcp", "BOOTIF=01-00-53-AB-cd-02-03");
    const char *const *ARGV1  = NM_MAKE_STRV("ip=eth0:dhcp", "BOOTIF=00-00-53-Ab-cD-02-03");
    const char *const *ARGV[] = {ARGV0, ARGV1};
    guint              i;

    for (i = 0; i < G_N_ELEMENTS(ARGV); i++) {
        gs_unref_hashtable GHashTable *connections = NULL;
        NMConnection                  *connection;
        NMSettingWired                *s_wired;
        NMSettingIPConfig             *s_ip4;
        NMSettingIPConfig             *s_ip6;

        connections = _parse_cons(ARGV[i]);
        g_assert_cmpint(g_hash_table_size(connections), ==, 2);

        connection = g_hash_table_lookup(connections, "eth0");
        nmtst_assert_connection_verifies_without_normalization(connection);
        g_assert_cmpstr(nm_connection_get_id(connection), ==, "eth0");

        s_wired = nm_connection_get_setting_wired(connection);
        g_assert(!nm_setting_wired_get_mac_address(s_wired));
        g_assert(s_wired);

        s_ip4 = nm_connection_get_setting_ip4_config(connection);
        g_assert(s_ip4);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                        ==,
                        NM_SETTING_IP4_CONFIG_METHOD_AUTO);
        g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));
        g_assert(!nm_setting_ip_config_get_may_fail(s_ip4));

        s_ip6 = nm_connection_get_setting_ip6_config(connection);
        g_assert(s_ip6);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                        ==,
                        NM_SETTING_IP6_CONFIG_METHOD_AUTO);
        g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip6));

        connection = g_hash_table_lookup(connections, "bootif_connection");
        nmtst_assert_connection_verifies_without_normalization(connection);
        g_assert_cmpstr(nm_connection_get_id(connection), ==, "BOOTIF Connection");

        s_wired = nm_connection_get_setting_wired(connection);
        g_assert_cmpstr(nm_setting_wired_get_mac_address(s_wired), ==, "00:53:AB:CD:02:03");
        g_assert(s_wired);

        s_ip4 = nm_connection_get_setting_ip4_config(connection);
        g_assert(s_ip4);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                        ==,
                        NM_SETTING_IP4_CONFIG_METHOD_AUTO);
        g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip4));
        g_assert(nm_setting_ip_config_get_may_fail(s_ip4));

        s_ip6 = nm_connection_get_setting_ip6_config(connection);
        g_assert(s_ip6);
        g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                        ==,
                        NM_SETTING_IP6_CONFIG_METHOD_AUTO);
        g_assert(!nm_setting_ip_config_get_ignore_auto_dns(s_ip6));
        g_assert(nm_setting_ip_config_get_may_fail(s_ip6));
    }
}

/* Check that nameservers are assigned to all existing
 * connections that support the specific IPv4/IPv6 address
 * family.
 */
static void
test_nameserver(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const             *ARGV =
        NM_MAKE_STRV("nameserver=1.1.1.1",
                     "ip=eth0:dhcp",
                     "ip=eth1:auto6",
                     "ip=10.11.12.13::10.11.12.1:24:foo.example.com:eth2:none",
                     "nameserver=1.0.0.1",
                     "nameserver=[2606:4700:4700::1111]");
    NMConnection      *connection;
    NMSettingIPConfig *s_ip;
    gs_free char      *hostname            = NULL;
    gint64             carrier_timeout_sec = 0;

    connections = _parse(ARGV, &hostname, &carrier_timeout_sec, NULL, NULL, NULL);
    g_assert_cmpint(g_hash_table_size(connections), ==, 3);
    g_assert_cmpstr(hostname, ==, "foo.example.com");
    g_assert_cmpint(carrier_timeout_sec, ==, 0);

    connection = g_hash_table_lookup(connections, "eth0");
    nmtst_assert_connection_verifies_without_normalization(connection);

    s_ip = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip);
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip), ==, 2);
    g_assert_cmpstr(nm_setting_ip_config_get_dns(s_ip, 0), ==, "1.1.1.1");
    g_assert_cmpstr(nm_setting_ip_config_get_dns(s_ip, 1), ==, "1.0.0.1");

    connection = g_hash_table_lookup(connections, "eth1");
    nmtst_assert_connection_verifies_without_normalization(connection);

    s_ip = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip);
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip), ==, 1);
    g_assert_cmpstr(nm_setting_ip_config_get_dns(s_ip, 0), ==, "2606:4700:4700::1111");

    connection = g_hash_table_lookup(connections, "eth2");
    nmtst_assert_connection_verifies_without_normalization(connection);

    s_ip = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip);
    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip), ==, 2);
    g_assert_cmpstr(nm_setting_ip_config_get_dns(s_ip, 0), ==, "1.1.1.1");
    g_assert_cmpstr(nm_setting_ip_config_get_dns(s_ip, 1), ==, "1.0.0.1");
}

static void
test_bootif_off(void)
{
    gs_unref_hashtable GHashTable *connections = NULL;
    const char *const *ARGV = NM_MAKE_STRV("BOOTIF=01-00-53-AB-cd-02-03", "rd.bootif=0");

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 0);
}

static void
test_dhcp_vendor_class_id(void)
{
    const char *const            *ARGV;
    gs_unref_object NMConnection *connection = NULL;
    NMSettingIP4Config           *s_ip4;
    gs_free char                 *vci_long          = NULL;
    char                          vci_arg_long[512] = {0};

    ARGV       = NM_MAKE_STRV("rd.net.dhcp.vendor-class=testvci", "ip=eno1:dhcp");
    connection = _parse_con(ARGV, "eno1");
    s_ip4      = NM_SETTING_IP4_CONFIG(nm_connection_get_setting_ip4_config(connection));
    g_assert_cmpstr(nm_setting_ip4_config_get_dhcp_vendor_class_identifier(s_ip4), ==, "testvci");

    g_clear_object(&connection);

    ARGV       = NM_MAKE_STRV("rd.net.dhcp.vendor-class", "ip=eno1:dhcp");
    connection = _parse_con(ARGV, "eno1");
    s_ip4      = NM_SETTING_IP4_CONFIG(nm_connection_get_setting_ip4_config(connection));
    g_assert(nm_setting_ip4_config_get_dhcp_vendor_class_identifier(s_ip4) == NULL);

    g_clear_object(&connection);

    memset(vci_arg_long, 'A', 400);
    vci_long   = g_strdup_printf("rd.net.dhcp.vendor-class=%s", vci_arg_long);
    ARGV       = NM_MAKE_STRV(vci_long, "ip=eno1:dhcp");
    connection = _parse_con(ARGV, "eno1");
    s_ip4      = NM_SETTING_IP4_CONFIG(nm_connection_get_setting_ip4_config(connection));
    g_assert(nm_setting_ip4_config_get_dhcp_vendor_class_identifier(s_ip4) == NULL);
}

static void
test_dhcp_dscp(void)
{
    const char *const            *ARGV;
    gs_unref_object NMConnection *connection = NULL;
    NMSettingIPConfig            *s_ip4;

    ARGV       = NM_MAKE_STRV("rd.net.dhcp.dscp=CS4", "ip=eno1:dhcp");
    connection = _parse_con(ARGV, "eno1");
    s_ip4      = NM_SETTING_IP_CONFIG(nm_connection_get_setting_ip4_config(connection));
    g_assert_cmpstr(nm_setting_ip_config_get_dhcp_dscp(s_ip4), ==, "CS4");

    g_clear_object(&connection);

    ARGV       = NM_MAKE_STRV("rd.net.dhcp.dscp=CS0", "ip=eno1:dhcp");
    connection = _parse_con(ARGV, "eno1");
    s_ip4      = NM_SETTING_IP_CONFIG(nm_connection_get_setting_ip4_config(connection));
    g_assert_cmpstr(nm_setting_ip_config_get_dhcp_dscp(s_ip4), ==, "CS0");

    g_clear_object(&connection);

    ARGV       = NM_MAKE_STRV("ip=eno1:dhcp");
    connection = _parse_con(ARGV, "eno1");
    s_ip4      = NM_SETTING_IP_CONFIG(nm_connection_get_setting_ip4_config(connection));
    g_assert_cmpstr(nm_setting_ip_config_get_dhcp_dscp(s_ip4), ==, NULL);
}

static void
test_infiniband_iface(void)
{
    const char *const            *ARGV       = NM_MAKE_STRV("ip=ib1:dhcp");
    gs_unref_object NMConnection *connection = NULL;
    NMSettingInfiniband          *s_ib;

    connection = _parse_con(ARGV, "ib1");

    g_assert_cmpstr(nm_connection_get_connection_type(connection),
                    ==,
                    NM_SETTING_INFINIBAND_SETTING_NAME);
    s_ib = nm_connection_get_setting_infiniband(connection);
    g_assert(s_ib);
}

static void
test_infiniband_mac(void)
{
    const char *const *ARGV =
        NM_MAKE_STRV("ip=00-11-22-33-44-55-66-77-88-99-aa-bb-cc-dd-ee-ff-00-11-22-33:dhcp");
    gs_unref_object NMConnection *connection = NULL;
    NMSettingInfiniband          *s_ib;

    connection = _parse_con(ARGV, "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33");

    g_assert_cmpstr(nm_connection_get_connection_type(connection),
                    ==,
                    NM_SETTING_INFINIBAND_SETTING_NAME);
    g_assert_cmpstr(nm_connection_get_interface_name(connection), ==, NULL);
    s_ib = nm_connection_get_setting_infiniband(connection);
    g_assert(s_ib);
    g_assert_cmpstr(nm_setting_infiniband_get_mac_address(s_ib),
                    ==,
                    "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33");
}

static void
test_infiniband_pkey(void)
{
    const char *const *const       ARGV = NM_MAKE_STRV("ib.pkey=ib0.8004", "ip=ib0.8004:dhcp");
    gs_unref_hashtable GHashTable *connections = NULL;
    NMConnection                  *connection;
    NMSettingInfiniband           *s_ib;
    NMSettingIPConfig             *s_ip4;
    NMSettingIPConfig             *s_ip6;

    connections = _parse_cons(ARGV);
    g_assert_cmpint(g_hash_table_size(connections), ==, 1);

    connection = g_hash_table_lookup(connections, "ib0.8004");
    g_assert_cmpstr(nm_connection_get_connection_type(connection),
                    ==,
                    NM_SETTING_INFINIBAND_SETTING_NAME);
    g_assert_cmpstr(nm_connection_get_interface_name(connection), ==, "ib0.8004");

    s_ib = nm_connection_get_setting_infiniband(connection);
    g_assert(s_ib);
    g_assert_cmpint(nm_setting_infiniband_get_p_key(s_ib), ==, 0x8004);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    g_assert(!nm_setting_ip_config_get_may_fail(s_ip4));

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
    g_assert(nm_setting_ip_config_get_may_fail(s_ip6));
}

static void
test_carrier_timeout(void)
{
    gs_unref_hashtable GHashTable *connections         = NULL;
    const char *const             *ARGV                = NM_MAKE_STRV("rd.net.timeout.carrier=20");
    gs_free char                  *hostname            = NULL;
    gint64                         carrier_timeout_sec = 0;

    connections = _parse(ARGV, &hostname, &carrier_timeout_sec, NULL, NULL, NULL);
    g_assert_cmpint(g_hash_table_size(connections), ==, 0);
    g_assert_cmpstr(hostname, ==, NULL);
    g_assert_cmpint(carrier_timeout_sec, ==, 20);
}

static void
test_global_dns(void)
{
    gs_unref_hashtable GHashTable *connections        = NULL;
    const char *const             *ARGV               = NM_MAKE_STRV("rd.net.dns=dns+tls://8.8.8.8",
                                           "rd.net.dns=1.1.1.1",
                                           "rd.net.dns=foobar",
                                           "rd.net.dns=dns+tls://[fd01::1]:35#name",
                                           "rd.net.dns-backend=dnsconfd",
                                           "rd.net.dns-resolve-mode=exclusive");
    gs_free char                  *hostname           = NULL;
    gs_strfreev char             **global_dns_servers = NULL;
    gs_free char                  *dns_backend        = NULL;
    gs_free char                  *dns_resolve_mode   = NULL;
    gint64                         carrier_timeout_sec = 0;

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.net.dns: invalid server 'foobar'");
    connections = _parse(ARGV,
                         &hostname,
                         &carrier_timeout_sec,
                         &global_dns_servers,
                         &dns_backend,
                         &dns_resolve_mode);
    g_test_assert_expected_messages();

    g_assert_cmpint(g_hash_table_size(connections), ==, 0);
    g_assert_cmpstr(hostname, ==, NULL);
    g_assert_cmpint(carrier_timeout_sec, ==, 0);
    g_assert(global_dns_servers != NULL);
    g_assert_cmpstr(global_dns_servers[0], ==, "dns+tls://8.8.8.8");
    g_assert_cmpstr(global_dns_servers[1], ==, "1.1.1.1");
    g_assert_cmpstr(global_dns_servers[2], ==, "dns+tls://[fd01::1]:35#name");
    g_assert_cmpstr(global_dns_servers[3], ==, NULL);
    g_assert_cmpstr(dns_backend, ==, "dnsconfd");
    g_assert_cmpstr(dns_resolve_mode, ==, "exclusive");
}

#define _ethtool_check_inval(arg)                                 \
    G_STMT_START                                                  \
    {                                                             \
        gs_unref_hashtable GHashTable *_connections2 = NULL;      \
                                                                  \
        _connections2 = _parse_cons(NM_MAKE_STRV(arg));           \
                                                                  \
        g_test_assert_expected_messages();                        \
                                                                  \
        g_assert_cmpint(g_hash_table_size(_connections2), ==, 0); \
    }                                                             \
    G_STMT_END

#define _ethtool_check_v(strv, autoneg, speed)                                                     \
    G_STMT_START                                                                                   \
    {                                                                                              \
        gs_unref_object NMConnection *_connection = NULL;                                          \
        NMSettingWired               *_s_wired;                                                    \
        typeof(speed)                 _speed = speed;                                              \
                                                                                                   \
        _connection = _parse_con(strv, "eth0");                                                    \
                                                                                                   \
        g_test_assert_expected_messages();                                                         \
                                                                                                   \
        g_assert(nm_connection_get_setting_connection(_connection));                               \
        g_assert(nm_connection_is_type(_connection, NM_SETTING_WIRED_SETTING_NAME));               \
        g_assert(nm_connection_get_setting_ip4_config(_connection));                               \
        g_assert(nm_connection_get_setting_ip6_config(_connection));                               \
        _s_wired = nm_connection_get_setting_wired(_connection);                                   \
        g_assert(NM_IS_SETTING_WIRED(_s_wired));                                                   \
                                                                                                   \
        g_assert_cmpint(nm_setting_wired_get_auto_negotiate(_s_wired), ==, (autoneg));             \
        g_assert_cmpint(nm_setting_wired_get_speed(_s_wired), ==, _speed);                         \
        g_assert_cmpstr(nm_setting_wired_get_duplex(_s_wired), ==, (_speed == 0 ? NULL : "full")); \
    }                                                                                              \
    G_STMT_END

#define _ethtool_check(arg, autoneg, speed) \
    _ethtool_check_v(NM_MAKE_STRV("" arg ""), (autoneg), (speed))

static void
test_rd_ethtool(void)
{
    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: interface unspecified. Ignore");
    _ethtool_check_inval("rd.ethtool=");

    _ethtool_check("rd.ethtool=eth0", FALSE, 0);

    _ethtool_check("rd.ethtool=eth0:", FALSE, 0);

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: interface unspecified. Ignore");
    _ethtool_check_inval("rd.ethtool=::");

    _ethtool_check("rd.ethtool=eth0:on", TRUE, 0);
    _ethtool_check("rd.ethtool=eth0:on:", TRUE, 0);
    _ethtool_check("rd.ethtool=eth0:on::", TRUE, 0);
    _ethtool_check("rd.ethtool=eth0:on:0:", TRUE, 0);

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: autoneg ignored. Cannot disable autoneg "
                         "without setting speed");
    _ethtool_check("rd.ethtool=eth0:off", FALSE, 0);

    _ethtool_check("rd.ethtool=eth0:true", TRUE, 0);

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: autoneg ignored. Cannot disable autoneg "
                         "without setting speed");
    _ethtool_check("rd.ethtool=eth0:false", FALSE, 0);

    _ethtool_check("rd.ethtool=eth0:1", TRUE, 0);

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: autoneg ignored. Cannot disable autoneg "
                         "without setting speed");
    _ethtool_check("rd.ethtool=eth0:0", FALSE, 0);

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: autoneg invalid. Must be boolean or empty");
    _ethtool_check("rd.ethtool=eth0:randomstring", FALSE, 0);

    _ethtool_check("rd.ethtool=eth0::", FALSE, 0);

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: speed invalid. Must be an integer or empty");
    _ethtool_check("rd.ethtool=eth0::astring", FALSE, 0);

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: speed invalid. Must be an integer or empty");
    _ethtool_check("rd.ethtool=eth0::1000000000000000000000000000000000000", FALSE, 0);

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: speed invalid. Must be an integer or empty");
    _ethtool_check("rd.ethtool=eth0::0.67", FALSE, 0);

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: speed invalid. Must be an integer or empty");
    _ethtool_check("rd.ethtool=eth0::-23", FALSE, 0);

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: speed invalid. Must be an integer or empty");
    _ethtool_check("rd.ethtool=eth0::-23:", FALSE, 0);

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: speed invalid. Must be an integer or empty");
    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: extra argument ignored");
    _ethtool_check("rd.ethtool=eth0::-23::", FALSE, 0);

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: speed invalid. Must be an integer or empty");
    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: extra argument ignored");
    _ethtool_check("rd.ethtool=eth0::-23::foo", FALSE, 0);

    _ethtool_check("rd.ethtool=eth0:1:10", TRUE, 10);

    _ethtool_check("rd.ethtool=eth0::100", FALSE, 100);

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: extra argument ignored");
    _ethtool_check("rd.ethtool=eth0:::bogus", FALSE, 0);

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: extra argument ignored");
    _ethtool_check("rd.ethtool=eth0::10:bogus", FALSE, 10);

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: extra argument ignored");
    _ethtool_check("rd.ethtool=eth0:on:100:bogus", TRUE, 100);

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: interface unspecified. Ignore");
    _ethtool_check_inval("rd.ethtool=:::");

    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: autoneg ignored. Cannot disable autoneg "
                         "without setting speed");
    _ethtool_check_v(NM_MAKE_STRV("rd.ethtool=eth0:off:0", "rd.ethtool=eth0:on"), TRUE, 0);
    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: autoneg ignored. Cannot disable autoneg "
                         "without setting speed");
    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: autoneg ignored. Cannot disable autoneg "
                         "without setting speed");
    _ethtool_check_v(NM_MAKE_STRV("rd.ethtool=eth0:off:0", "rd.ethtool=eth0:off"), FALSE, 0);
    _ethtool_check_v(NM_MAKE_STRV("rd.ethtool=eth0:on:0", "rd.ethtool=eth0:on"), TRUE, 0);
    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: autoneg ignored. Cannot disable autoneg "
                         "without setting speed");
    _ethtool_check_v(NM_MAKE_STRV("rd.ethtool=eth0:on:0", "rd.ethtool=eth0:off"), FALSE, 0);
    _ethtool_check_v(NM_MAKE_STRV("rd.ethtool=eth0:off:100", "rd.ethtool=eth0:on"), TRUE, 0);
    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: autoneg ignored. Cannot disable autoneg "
                         "without setting speed");
    _ethtool_check_v(NM_MAKE_STRV("rd.ethtool=eth0:off:100", "rd.ethtool=eth0:off"), FALSE, 0);
    _ethtool_check_v(NM_MAKE_STRV("rd.ethtool=eth0:on:100", "rd.ethtool=eth0:on"), TRUE, 0);
    NMTST_EXPECT_NM_WARN("cmdline-reader: rd.ethtool: autoneg ignored. Cannot disable autoneg "
                         "without setting speed");
    _ethtool_check_v(NM_MAKE_STRV("rd.ethtool=eth0:on:100", "rd.ethtool=eth0:off"), FALSE, 0);
    _ethtool_check_v(NM_MAKE_STRV("rd.ethtool=eth0:off:100", "rd.ethtool=eth0:"), FALSE, 100);
}

/*****************************************************************************/

static void
test_plain_equal_char(void)
{
    _parse_no_con(NM_MAKE_STRV("="));
    _parse_no_con(NM_MAKE_STRV("=foo"));
    _parse_no_con(NM_MAKE_STRV("BOOT_IMAGE=(hd0,msdos2)/boot/vmlinuz-5.13.10-100.fc33.x86_64",
                               "root=UUID=ff252b4a-8294-4961-abcb-74c8fc868db7",
                               "ro",
                               "rhgb",
                               "quiet",
                               "pci",
                               "=",
                               "nomsi,",
                               "noaer"));
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init_assert_logging(&argc, &argv, "INFO", "DEFAULT");

    g_test_add_func("/initrd/cmdline/auto", test_auto);
    g_test_add_func("/initrd/cmdline/dhcp_with_hostname", test_dhcp_with_hostname);
    g_test_add_func("/initrd/cmdline/dhcp_with_mtu", test_dhcp_with_mtu);
    g_test_add_func("/initrd/cmdline/dhcp_timeout", test_dhcp_timeout);
    g_test_add_func("/initrd/cmdline/if_auto_with_mtu", test_if_auto_with_mtu);
    g_test_add_func("/initrd/cmdline/if_dhcp6", test_if_dhcp6);
    g_test_add_func("/initrd/cmdline/if_auto_with_mtu_and_mac", test_if_auto_with_mtu_and_mac);
    g_test_add_func("/initrd/cmdline/if_ip4_manual", test_if_ip4_manual);
    g_test_add_func("/initrd/cmdline/if_ip4_auto", test_if_ip4_auto);
    g_test_add_func("/initrd/cmdline/if_ip4_manual_no_dev", test_if_ip4_manual_no_dev);
    g_test_add_func("/initrd/cmdline/if_ip6_manual", test_if_ip6_manual);
    g_test_add_func("/initrd/cmdline/if_mac_ifname", test_if_mac_ifname);
    g_test_add_func("/initrd/cmdline/if_off", test_if_off);
    g_test_add_func("/initrd/cmdline/multiple/merge", test_multiple_merge);
    g_test_add_func("/initrd/cmdline/multiple/bootdev", test_multiple_bootdev);
    g_test_add_func("/initrd/cmdline/nameserver", test_nameserver);
    g_test_add_func("/initrd/cmdline/some_more", test_some_more);
    g_test_add_func("/initrd/cmdline/bootdev", test_bootdev);
    g_test_add_func("/initrd/cmdline/bond", test_bond);
    g_test_add_func("/initrd/cmdline/bond/ip", test_bond_ip);
    g_test_add_func("/initrd/cmdline/bond/ip6-option", test_bond_ip6_option);
    g_test_add_func("/initrd/cmdline/bond/default", test_bond_default);
    g_test_add_func("/initrd/cmdline/team", test_team);
    g_test_add_func("/initrd/cmdline/vlan", test_vlan);
    g_test_add_func("/initrd/cmdline/vlan/dhcp-on-parent", test_vlan_with_dhcp_on_parent);
    g_test_add_func("/initrd/cmdline/vlan/over-bond", test_vlan_over_bond);
    g_test_add_func("/initrd/cmdline/bridge", test_bridge);
    g_test_add_func("/initrd/cmdline/bridge/default", test_bridge_default);
    g_test_add_func("/initrd/cmdline/bridge/ip", test_bridge_ip);
    g_test_add_func("/initrd/cmdline/ibft/ip_dev", test_ibft_ip_dev);
    g_test_add_func("/initrd/cmdline/ibft/ip_dev_mac", test_ibft_ip_dev_mac);
    g_test_add_func("/initrd/cmdline/ibft/ip", test_ibft_ip);
    g_test_add_func("/initrd/cmdline/ibft/rd_iscsi_ibft", test_ibft_rd_iscsi_ibft);
    g_test_add_func("/initrd/cmdline/ignore_extra", test_ignore_extra);
    g_test_add_func("/initrd/cmdline/rd_znet", test_rd_znet);
    g_test_add_func("/initrd/cmdline/rd_znet/legacy", test_rd_znet_legacy);
    g_test_add_func("/initrd/cmdline/rd_znet/no_ip", test_rd_znet_no_ip);
    g_test_add_func("/initrd/cmdline/rd_znet/empty", test_rd_znet_malformed);
    g_test_add_func("/initrd/cmdline/rd_znet/ifnames", test_rd_znet_ifnames);
    g_test_add_func("/initrd/cmdline/bootif/ip", test_bootif_ip);
    g_test_add_func("/initrd/cmdline/bootif/no_ip", test_bootif_no_ip);
    g_test_add_func("/initrd/cmdline/bootif/hwtype", test_bootif_hwtype);
    g_test_add_func("/initrd/cmdline/bootif/off", test_bootif_off);
    g_test_add_func("/initrd/cmdline/neednet/no_args", test_neednet_no_args);
    g_test_add_func("/initrd/cmdline/neednet/args", test_neednet_args);
    g_test_add_func("/initrd/cmdline/dhcp/vendor_class_id", test_dhcp_vendor_class_id);
    g_test_add_func("/initrd/cmdline/dhcp/dscp", test_dhcp_dscp);
    g_test_add_func("/initrd/cmdline/infiniband/iface", test_infiniband_iface);
    g_test_add_func("/initrd/cmdline/infiniband/mac", test_infiniband_mac);
    g_test_add_func("/initrd/cmdline/infiniband/pkey", test_infiniband_pkey);
    g_test_add_func("/initrd/cmdline/carrier_timeout", test_carrier_timeout);
    g_test_add_func("/initrd/cmdline/rd_ethtool", test_rd_ethtool);
    g_test_add_func("/initrd/cmdline/plain_equal_char", test_plain_equal_char);
    g_test_add_func("/initrd/cmdline/global_dns", test_global_dns);

    return g_test_run();
}
