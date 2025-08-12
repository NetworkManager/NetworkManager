/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2025 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "libnm-core-intern/nm-core-internal.h"
#include "libnm-glib-aux/nm-test-utils.h"

#include "nm-initrd-generator/nm-initrd-generator.h"

#define TEST_INITRD_DIR NM_BUILD_SRCDIR "/src/nm-initrd-generator/tests"

/*****************************************************************************/

static NMConnection *
find_connection_for_mac(NMConnection **nbft_connections, const char *expected_mac, guint32 vlan_id)
{
    NMConnection  **c;
    NMSettingWired *s_wired;
    NMSettingVlan  *s_vlan;
    const char     *mac_address;

    for (c = nbft_connections; c && *c; c++) {
        s_wired = nm_connection_get_setting_wired(*c);
        g_assert(s_wired);
        mac_address = nm_setting_wired_get_mac_address(s_wired);
        g_assert(mac_address);
        if (!nm_utils_hwaddr_matches(mac_address, -1, expected_mac, -1))
            continue;
        s_vlan = nm_connection_get_setting_vlan(*c);
        if (vlan_id > 0) {
            if (!s_vlan)
                continue;
            if (nm_setting_vlan_get_id(s_vlan) != vlan_id)
                continue;
        } else if (s_vlan)
            continue;
        return *c;
    }

    return NULL;
}

static void
verify_connection(NMConnection *c, const char *expected_mac, guint32 expected_vlan_id)
{
    NMSettingConnection *s_con;
    NMSettingWired      *s_wired;
    NMSettingVlan       *s_vlan;
    const char          *mac_address;

    nmtst_assert_connection_verifies_without_normalization(c);

    s_con = nm_connection_get_setting_connection(c);
    g_assert(s_con);

    g_assert(g_str_has_prefix(nm_setting_connection_get_id(s_con), "NBFT"));
    g_assert_cmpstr(nm_setting_connection_get_interface_name(s_con), ==, NULL);
    g_assert(nm_setting_connection_get_autoconnect_priority(s_con)
             == NMI_AUTOCONNECT_PRIORITY_FIRMWARE);

    s_wired = nm_connection_get_setting_wired(c);
    g_assert(s_wired);
    mac_address = nm_setting_wired_get_mac_address(s_wired);
    g_assert(mac_address);
    g_assert(nm_utils_hwaddr_matches(mac_address, -1, expected_mac, -1));

    if (expected_vlan_id > 0) {
        g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                        ==,
                        NM_SETTING_VLAN_SETTING_NAME);
        s_vlan = nm_connection_get_setting_vlan(c);
        g_assert(s_vlan);
        g_assert_cmpint(nm_setting_vlan_get_id(s_vlan), ==, expected_vlan_id);
        g_assert_cmpstr(nm_setting_vlan_get_parent(s_vlan), ==, NULL);
    } else {
        g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                        ==,
                        NM_SETTING_WIRED_SETTING_NAME);
    }
}

static void
verify_ipv4(NMConnection *c, const char *addr, int mask, const char *gateway)
{
    NMSettingIPConfig *s_ip4;
    NMIPAddress       *ip4_addr;

    s_ip4 = nm_connection_get_setting_ip4_config(c);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                    ==,
                    NM_SETTING_IP4_CONFIG_METHOD_MANUAL);

    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip4), ==, 0);

    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip4), ==, 1);
    ip4_addr = nm_setting_ip_config_get_address(s_ip4, 0);
    g_assert(ip4_addr);
    g_assert_cmpstr(nm_ip_address_get_address(ip4_addr), ==, addr);
    g_assert_cmpint(nm_ip_address_get_prefix(ip4_addr), ==, mask);

    g_assert_cmpstr(nm_setting_ip_config_get_gateway(s_ip4), ==, gateway);
}

static void
verify_ipv4_dhcp(NMConnection *c)
{
    NMSettingIPConfig *s_ip4;

    s_ip4 = nm_connection_get_setting_ip4_config(c);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
}

static void
verify_ipv4_disabled(NMConnection *c)
{
    NMSettingIPConfig *s_ip4;

    s_ip4 = nm_connection_get_setting_ip4_config(c);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                    ==,
                    NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
}

static void
verify_ipv6(NMConnection *c, const char *addr, int prefix, const char *gateway)
{
    NMSettingIPConfig *s_ip6;
    NMIPAddress       *ip6_addr;

    s_ip6 = nm_connection_get_setting_ip6_config(c);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                    ==,
                    NM_SETTING_IP6_CONFIG_METHOD_MANUAL);

    g_assert_cmpint(nm_setting_ip_config_get_num_dns(s_ip6), ==, 0);

    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip6), ==, 1);
    ip6_addr = nm_setting_ip_config_get_address(s_ip6, 0);
    g_assert(ip6_addr);
    g_assert_cmpstr(nm_ip_address_get_address(ip6_addr), ==, addr);
    g_assert_cmpint(nm_ip_address_get_prefix(ip6_addr), ==, prefix);

    g_assert_cmpstr(nm_setting_ip_config_get_gateway(s_ip6), ==, gateway);
}

static void
verify_ipv6_auto(NMConnection *c)
{
    NMSettingIPConfig *s_ip6;

    s_ip6 = nm_connection_get_setting_ip6_config(c);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
}

static void
verify_ipv6_disabled(NMConnection *c)
{
    NMSettingIPConfig *s_ip6;

    s_ip6 = nm_connection_get_setting_ip6_config(c);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                    ==,
                    NM_SETTING_IP6_CONFIG_METHOD_DISABLED);
}

static int
count_nm_conn(NMConnection **connections)
{
    int cnt;

    for (cnt = 0; connections && *connections; connections++, cnt++)
        ;

    return cnt;
}

static void
free_connections(NMConnection **connections)
{
    NMConnection **c;

    for (c = connections; c && *c; c++)
        g_object_unref(*c);
    g_free(connections);
}

static void
test_read_nbft_ipv4_static(void)
{
    NMConnection **nbft_connections;
    NMConnection  *connection;
    const char    *expected_mac_address;
    gs_free char  *hostname = NULL;

    nbft_connections = nmi_nbft_reader_parse(TEST_INITRD_DIR "/nbft-ipv4-static", &hostname);
    g_assert_nonnull(hostname);
    g_assert_cmpint(count_nm_conn(nbft_connections), ==, 6);

    /* NBFT-multi HFI 1 */
    expected_mac_address = "52:54:00:72:c5:ae";
    connection           = find_connection_for_mac(nbft_connections, expected_mac_address, 0);
    verify_connection(connection, expected_mac_address, 0);
    verify_ipv4(connection, "192.168.122.158", 24, "192.168.122.1");
    verify_ipv6_disabled(connection);

    /* NBFT-multi HFI 2 */
    expected_mac_address = "52:54:00:72:c5:af";
    connection           = find_connection_for_mac(nbft_connections, expected_mac_address, 0);
    verify_connection(connection, expected_mac_address, 0);
    verify_ipv4_dhcp(connection);
    verify_ipv6_disabled(connection);

    /* NBFT-Dell.PowerEdge.R660-fw1.5.5-mpath+discovery HFI 1 */
    expected_mac_address = "00:62:0b:cb:eb:70";
    connection           = find_connection_for_mac(nbft_connections, expected_mac_address, 0);
    verify_connection(connection, expected_mac_address, 0);
    verify_ipv4(connection, "172.18.240.1", 24, NULL);
    verify_ipv6_disabled(connection);

    /* NBFT-Dell.PowerEdge.R660-fw1.5.5-mpath+discovery HFI 2 */
    expected_mac_address = "00:62:0b:cb:eb:71";
    connection           = find_connection_for_mac(nbft_connections, expected_mac_address, 0);
    verify_connection(connection, expected_mac_address, 0);
    verify_ipv4(connection, "172.18.230.2", 24, NULL);
    verify_ipv6_disabled(connection);

    /* NBFT-rhpoc */
    expected_mac_address = "ea:eb:d3:58:89:58";
    connection           = find_connection_for_mac(nbft_connections, expected_mac_address, 0);
    verify_connection(connection, expected_mac_address, 0);
    verify_ipv4(connection, "192.168.101.30", 24, NULL);
    verify_ipv6_disabled(connection);

    /* NBFT-static-ipv4 */
    expected_mac_address = "52:54:00:b8:19:b9";
    connection           = find_connection_for_mac(nbft_connections, expected_mac_address, 0);
    verify_connection(connection, expected_mac_address, 0);
    verify_ipv4(connection, "192.168.49.50", 24, NULL);
    verify_ipv6_disabled(connection);

    free_connections(nbft_connections);
}

static void
test_read_nbft_ipv4_dhcp(void)
{
    NMConnection **nbft_connections;
    NMConnection  *connection;
    const char    *expected_mac_address;
    gs_free char  *hostname = NULL;

    nbft_connections = nmi_nbft_reader_parse(TEST_INITRD_DIR "/nbft-ipv4-dhcp", &hostname);
    g_assert_nonnull(hostname);
    g_assert_cmpint(count_nm_conn(nbft_connections), ==, 2);

    /* NBFT-dhcp-ipv4 */
    expected_mac_address = "52:54:00:b8:19:b9";
    connection           = find_connection_for_mac(nbft_connections, expected_mac_address, 0);
    verify_connection(connection, expected_mac_address, 0);
    verify_ipv4_dhcp(connection);
    verify_ipv6_disabled(connection);

    /* NBFT-Dell.PowerEdge.R760 */
    expected_mac_address = "b0:26:28:e8:7c:0e";
    connection           = find_connection_for_mac(nbft_connections, expected_mac_address, 0);
    verify_connection(connection, expected_mac_address, 0);
    verify_ipv4_dhcp(connection);
    verify_ipv6_disabled(connection);

    free_connections(nbft_connections);
}

static void
test_read_nbft_ipv6_static(void)
{
    NMConnection **nbft_connections;
    NMConnection  *connection;
    const char    *expected_mac_address;
    gs_free char  *hostname = NULL;

    nbft_connections = nmi_nbft_reader_parse(TEST_INITRD_DIR "/nbft-ipv6-static", &hostname);
    g_assert_nonnull(hostname);
    g_assert_cmpint(count_nm_conn(nbft_connections), ==, 1);

    /* NBFT-static-ipv6 */
    expected_mac_address = "52:54:00:9e:20:1a";
    connection           = find_connection_for_mac(nbft_connections, expected_mac_address, 0);
    verify_connection(connection, expected_mac_address, 0);
    verify_ipv6(connection, "fd09:9a46:b5c1:1fe::10", 64, NULL);
    verify_ipv4_disabled(connection);

    free_connections(nbft_connections);
}

static void
test_read_nbft_ipv6_auto(void)
{
    NMConnection **nbft_connections;
    NMConnection  *connection;
    const char    *expected_mac_address;
    gs_free char  *hostname = NULL;

    nbft_connections = nmi_nbft_reader_parse(TEST_INITRD_DIR "/nbft-ipv6-auto", &hostname);
    g_assert_nonnull(hostname);
    g_assert_cmpint(count_nm_conn(nbft_connections), ==, 3);

    /* NBFT-auto-ipv6 */
    expected_mac_address = "52:54:00:9e:20:1a";
    connection           = find_connection_for_mac(nbft_connections, expected_mac_address, 0);
    verify_connection(connection, expected_mac_address, 0);
    verify_ipv6(connection, "fd09:9a46:b5c1:1ff:5054:ff:fe9e:201a", 64, NULL);
    verify_ipv4_disabled(connection);

    /* NBFT-dhcp-ipv6 */
    expected_mac_address = "52:54:00:b8:19:b9";
    connection           = find_connection_for_mac(nbft_connections, expected_mac_address, 0);
    verify_connection(connection, expected_mac_address, 0);
    verify_ipv6_auto(connection);
    verify_ipv4_disabled(connection);

    /* NBFT-ipv6-noip+disc */
    expected_mac_address = "40:a6:b7:c0:8a:c9";
    connection           = find_connection_for_mac(nbft_connections, expected_mac_address, 0);
    verify_connection(connection, expected_mac_address, 0);
    verify_ipv6_auto(connection);
    verify_ipv4_disabled(connection);

    free_connections(nbft_connections);
}

static void
test_read_nbft_vlan(void)
{
    NMConnection **nbft_connections;
    NMConnection  *connection;
    const char    *expected_mac_address;
    gs_free char  *hostname = NULL;

    nbft_connections = nmi_nbft_reader_parse(TEST_INITRD_DIR "/nbft-vlan", &hostname);
    g_assert_cmpstr(hostname, ==, NULL);
    g_assert_cmpint(count_nm_conn(nbft_connections), ==, 4);

    /* NBFT-qemu-vlans-incomplete HFI 1 */
    expected_mac_address = "52:54:00:72:c5:ae";
    connection           = find_connection_for_mac(nbft_connections, expected_mac_address, 0);
    verify_connection(connection, expected_mac_address, 0);
    verify_ipv4(connection, "192.168.122.158", 24, "192.168.122.1");
    verify_ipv6_disabled(connection);

    /* NBFT-qemu-vlans-incomplete HFI 2 */
    expected_mac_address = "52:54:00:72:c5:af";
    connection           = find_connection_for_mac(nbft_connections, expected_mac_address, 0);
    verify_connection(connection, expected_mac_address, 0);
    verify_ipv4_disabled(connection);
    verify_ipv6_disabled(connection);

    /* NBFT-qemu-vlans-incomplete HFI 2 VLAN 11 */
    expected_mac_address = "52:54:00:72:c5:af";
    connection           = find_connection_for_mac(nbft_connections, expected_mac_address, 11);
    verify_connection(connection, expected_mac_address, 11);
    verify_ipv4(connection, "192.168.124.58", 24, NULL);
    verify_ipv6_disabled(connection);

    /* NBFT-qemu-vlans-incomplete HFI 2 VLAN 12 */
    expected_mac_address = "52:54:00:72:c5:af";
    connection           = find_connection_for_mac(nbft_connections, expected_mac_address, 12);
    verify_connection(connection, expected_mac_address, 12);
    verify_ipv4(connection, "192.168.125.58", 24, NULL);
    verify_ipv6_disabled(connection);

    free_connections(nbft_connections);
}

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init_assert_logging(&argc, &argv, "INFO", "DEFAULT");

    g_test_add_func("/initrd/nbft/ipv4-static", test_read_nbft_ipv4_static);
    g_test_add_func("/initrd/nbft/ipv4-dhcp", test_read_nbft_ipv4_dhcp);
    g_test_add_func("/initrd/nbft/ipv6-static", test_read_nbft_ipv6_static);
    g_test_add_func("/initrd/nbft/ipv6-auto", test_read_nbft_ipv6_auto);
    g_test_add_func("/initrd/nbft/vlan", test_read_nbft_vlan);

    return g_test_run();
}
