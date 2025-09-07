/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "src/core/nm-default-daemon.h"

#include "nm-netns.h"
#include "nm-test-utils-core.h"

static void
test_ip_reservation_shared4(void)
{
    gs_unref_object NMPlatform *platform = NULL;
    gs_unref_object NMNetns    *netns    = NULL;
    NMNetnsIPReservation       *res[256];
    NMNetnsIPReservation       *res1;
    NMNetnsIPReservation       *res2;
    char                        buf[NM_INET_ADDRSTRLEN];
    guint                       i;

    platform = g_object_ref(NM_PLATFORM_GET);
    netns    = nm_netns_new(platform);

    /* Allocate addresses from 10.42.0.1 to 10.42.255.1 */
    for (i = 0; i < 256; i++) {
        res[i] = nm_netns_ip_reservation_get(netns, NM_NETNS_IP_RESERVATION_TYPE_SHARED4);
        g_snprintf(buf, sizeof(buf), "10.42.%u.1", i);
        nmtst_assert_ip4_address(res[i]->addr, buf);
        g_assert_cmpint(res[i]->_ref_count, ==, 1);
    }

    /* Release an address and get it back */
    nm_netns_ip_reservation_release(res[139]);
    res[139] = nm_netns_ip_reservation_get(netns, NM_NETNS_IP_RESERVATION_TYPE_SHARED4);
    nmtst_assert_ip4_address(res[139]->addr, "10.42.139.1");

    /* Reuse 10.42.255.1 once */
    NMTST_EXPECT_NM_ERROR("netns[*]: shared-ip4: ran out of IP addresses. Reuse 10.42.255.1/24");
    res1 = nm_netns_ip_reservation_get(netns, NM_NETNS_IP_RESERVATION_TYPE_SHARED4);
    g_test_assert_expected_messages();
    nmtst_assert_ip4_address(res1->addr, "10.42.255.1");
    g_assert_cmpint(res1->_ref_count, ==, 2);

    /* Reuse 10.42.255.1 twice */
    res2 = nm_netns_ip_reservation_get(netns, NM_NETNS_IP_RESERVATION_TYPE_SHARED4);
    g_assert(res2 == res1);
    nmtst_assert_ip4_address(res1->addr, "10.42.255.1");
    g_assert_cmpint(res2->_ref_count, ==, 3);

    /* Release all */
    nm_netns_ip_reservation_release(res1);
    nm_netns_ip_reservation_release(res2);
    for (i = 0; i < 256; i++) {
        nm_netns_ip_reservation_release(res[i]);
    }
}

static void
test_ip_reservation_clat(void)
{
    gs_unref_object NMPlatform *platform = NULL;
    gs_unref_object NMNetns    *netns    = NULL;
    NMNetnsIPReservation       *res[8];
    NMNetnsIPReservation       *res1;
    char                        buf[NM_INET_ADDRSTRLEN];
    guint                       i;

    platform = g_object_ref(NM_PLATFORM_GET);
    netns    = nm_netns_new(platform);

    /* Allocate addresses 192.0.0.{5,6,7,0,1,2,3,4} */
    for (i = 0; i < 8; i++) {
        res[i] = nm_netns_ip_reservation_get(netns, NM_NETNS_IP_RESERVATION_TYPE_CLAT);
        g_snprintf(buf, sizeof(buf), "192.0.0.%u", (i + 5) % 8);
        nmtst_assert_ip4_address(res[i]->addr, buf);
        g_assert_cmpint(res[i]->_ref_count, ==, 1);
    }

    /* Release an address and get it back */
    nm_netns_ip_reservation_release(res[2]);
    res[2] = nm_netns_ip_reservation_get(netns, NM_NETNS_IP_RESERVATION_TYPE_CLAT);
    nmtst_assert_ip4_address(res[2]->addr, "192.0.0.7");

    /* No reuse */
    NMTST_EXPECT_NM_ERROR("netns[*]: clat: ran out of IP addresses");
    res1 = nm_netns_ip_reservation_get(netns, NM_NETNS_IP_RESERVATION_TYPE_CLAT);
    g_test_assert_expected_messages();
    g_assert_null(res1);

    /* Release all */
    for (i = 0; i < 8; i++) {
        nm_netns_ip_reservation_release(res[i]);
    }
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init_with_logging(&argc, &argv, NULL, "ALL");
    nm_linux_platform_setup();

    g_test_add_func("/netns/ip_reservation/shared4", test_ip_reservation_shared4);
    g_test_add_func("/netns/ip_reservation/clat", test_ip_reservation_clat);

    return g_test_run();
}
