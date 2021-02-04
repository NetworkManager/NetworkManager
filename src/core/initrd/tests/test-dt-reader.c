/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2014 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"

#include "../nm-initrd-generator.h"

#include "nm-test-utils-core.h"

#define TEST_INITRD_DIR NM_BUILD_SRCDIR "/src/core/initrd/tests"

/*****************************************************************************/

static void
test_read_dt_ofw(void)
{
    NMConnection *       connection;
    NMSettingConnection *s_con;
    NMSettingWired *     s_wired;
    NMSettingIPConfig *  s_ip4;
    NMSettingIPConfig *  s_ip6;
    const char *         mac_address;

    connection = nmi_dt_reader_parse(TEST_INITRD_DIR "/sysfs-dt");
    g_assert(connection);
    nmtst_assert_connection_verifies(connection);

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "OpenFirmware Connection");
    g_assert_cmpint(nm_setting_connection_get_timestamp(s_con), ==, 0);
    g_assert(nm_setting_connection_get_autoconnect(s_con));

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert(s_wired);
    mac_address = nm_setting_wired_get_mac_address(s_wired);
    g_assert(mac_address);
    g_assert(nm_utils_hwaddr_matches(mac_address, -1, "ac:7f:3e:e5:d8:d8", -1));
    g_assert(!nm_setting_wired_get_duplex(s_wired));
    g_assert_cmpint(nm_setting_wired_get_speed(s_wired), ==, 0);
    g_assert_cmpint(nm_setting_wired_get_mtu(s_wired), ==, 0);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
    g_assert_cmpstr(nm_setting_ip_config_get_dhcp_hostname(s_ip4), ==, "demiurge");

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);

    g_object_unref(connection);
}

static void
test_read_dt_slof(void)
{
    NMConnection *       connection;
    NMSettingConnection *s_con;
    NMSettingWired *     s_wired;
    NMSettingIPConfig *  s_ip4;
    NMSettingIPConfig *  s_ip6;
    NMIPAddress *        ip4_addr;

    connection = nmi_dt_reader_parse(TEST_INITRD_DIR "/sysfs-dt-tftp");
    g_assert(connection);
    nmtst_assert_connection_verifies(connection);

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    g_assert_cmpstr(nm_setting_connection_get_connection_type(s_con),
                    ==,
                    NM_SETTING_WIRED_SETTING_NAME);
    g_assert_cmpstr(nm_setting_connection_get_id(s_con), ==, "OpenFirmware Connection");
    g_assert_cmpint(nm_setting_connection_get_timestamp(s_con), ==, 0);
    g_assert(nm_setting_connection_get_autoconnect(s_con));

    s_wired = nm_connection_get_setting_wired(connection);
    g_assert(s_wired);
    g_assert(!nm_setting_wired_get_mac_address(s_wired));
    g_assert_cmpstr(nm_setting_wired_get_duplex(s_wired), ==, "half");
    g_assert_cmpint(nm_setting_wired_get_speed(s_wired), ==, 10);
    g_assert_cmpint(nm_setting_wired_get_mtu(s_wired), ==, 0);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    g_assert(s_ip4);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip4),
                    ==,
                    NM_SETTING_IP4_CONFIG_METHOD_MANUAL);

    g_assert_cmpint(nm_setting_ip_config_get_num_addresses(s_ip4), ==, 1);
    ip4_addr = nm_setting_ip_config_get_address(s_ip4, 0);
    g_assert(ip4_addr);
    g_assert_cmpstr(nm_ip_address_get_address(ip4_addr), ==, "192.168.32.2");
    g_assert_cmpint(nm_ip_address_get_prefix(ip4_addr), ==, 16);

    g_assert_cmpstr(nm_setting_ip_config_get_gateway(s_ip4), ==, "192.168.32.1");

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    g_assert(s_ip6);
    g_assert_cmpstr(nm_setting_ip_config_get_method(s_ip6),
                    ==,
                    NM_SETTING_IP6_CONFIG_METHOD_DISABLED);

    g_object_unref(connection);
}

static void
test_read_dt_none(void)
{
    NMConnection *connection;

    connection = nmi_dt_reader_parse(TEST_INITRD_DIR "/sysfs");
    g_assert(!connection);
}

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init_assert_logging(&argc, &argv, "INFO", "DEFAULT");

    g_test_add_func("/initrd/dt/ofw", test_read_dt_ofw);
    g_test_add_func("/initrd/dt/slof", test_read_dt_slof);
    g_test_add_func("/initrd/dt/none", test_read_dt_none);

    return g_test_run();
}
