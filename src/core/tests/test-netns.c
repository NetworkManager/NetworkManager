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

static void
test_nexthop_id_reservation(void)
{
    gs_unref_object NMPlatform *platform = NULL;
    gs_unref_object NMNetns    *netns    = NULL;
    gconstpointer               tag1     = GINT_TO_POINTER(1234);
    gconstpointer               tag2     = GINT_TO_POINTER(5678);
    const guint32               id_nm    = NM_NEXTHOP_ID_NM_OWNED_BIT | 1u;
    gboolean                    res;
    guint                       i;

    platform = g_object_ref(NM_PLATFORM_GET);
    netns    = nm_netns_new(platform);

    for (i = 1; i < 10; i++) {
        res = nm_netns_nexthop_id_reserve(netns, i, tag1);
        g_assert_true(res);
    }
    for (i = 10; i < 20; i++) {
        res = nm_netns_nexthop_id_reserve(netns, i, tag2);
        g_assert_true(res);
    }

    /* idempotency */
    for (i = 1; i < 10; i++) {
        res = nm_netns_nexthop_id_reserve(netns, i, tag1);
        g_assert_true(res);
    }
    for (i = 10; i < 20; i++) {
        res = nm_netns_nexthop_id_reserve(netns, i, tag2);
        g_assert_true(res);
    }

    /* collisions */
    for (i = 1; i < 10; i++) {
        res = nm_netns_nexthop_id_reserve(netns, i, tag2);
        g_assert_false(res);
    }
    for (i = 10; i < 20; i++) {
        res = nm_netns_nexthop_id_reserve(netns, i, tag1);
        g_assert_false(res);
    }

    for (i = 1; i < 30; i++) {
        res = nm_netns_nexthop_id_is_reserved(netns, i);
        g_assert_cmpint(res, ==, (i < 20));
    }

    nm_netns_nexthop_id_release(netns, 5, tag1);
    nm_netns_nexthop_id_release(netns, 15, tag2);

    g_assert_false(nm_netns_nexthop_id_is_reserved(netns, 5));
    g_assert_false(nm_netns_nexthop_id_is_reserved(netns, 15));
    g_assert_true(nm_netns_nexthop_id_is_reserved(netns, 1));
    g_assert_true(nm_netns_nexthop_id_is_reserved(netns, 10));

    /* releasing an ID that is not reserved does nothing */
    nm_netns_nexthop_id_release(netns, 5, tag1);
    nm_netns_nexthop_id_release(netns, 25, tag1);
    g_assert_false(nm_netns_nexthop_id_is_reserved(netns, 5));
    g_assert_false(nm_netns_nexthop_id_is_reserved(netns, 25));

    for (i = 1; i < 10; i++) {
        res = nm_netns_nexthop_id_reserve(netns, i, tag1);
        g_assert_true(res);
    }
    for (i = 10; i < 20; i++) {
        res = nm_netns_nexthop_id_reserve(netns, i, tag2);
        g_assert_true(res);
    }

    nm_netns_nexthop_id_release_all(netns, tag2);
    for (i = 1; i < 30; i++) {
        res = nm_netns_nexthop_id_is_reserved(netns, i);
        g_assert_cmpint(res, ==, (i < 10));
    }

    nm_netns_nexthop_id_release_all(netns, tag1);
    for (i = 1; i < 30; i++) {
        res = nm_netns_nexthop_id_is_reserved(netns, i);
        g_assert_false(res);
    }

    /* IDs with the high bit set and the full 32-bit range */
    g_assert_true(nm_netns_nexthop_id_reserve(netns, id_nm, tag1));
    g_assert_true(nm_netns_nexthop_id_reserve(netns, G_MAXUINT32, tag2));
    g_assert_true(nm_netns_nexthop_id_is_reserved(netns, id_nm));
    g_assert_true(nm_netns_nexthop_id_is_reserved(netns, G_MAXUINT32));
    g_assert_false(nm_netns_nexthop_id_is_reserved(netns, 1));
    g_assert_false(nm_netns_nexthop_id_is_reserved(netns, (NM_NEXTHOP_ID_NM_OWNED_BIT - 1u)));
    g_assert_false(nm_netns_nexthop_id_reserve(netns, id_nm, tag2));
    g_assert_false(nm_netns_nexthop_id_reserve(netns, G_MAXUINT32, tag1));

    nm_netns_nexthop_id_release(netns, G_MAXUINT32, tag2);
    g_assert_false(nm_netns_nexthop_id_is_reserved(netns, G_MAXUINT32));
    g_assert_true(nm_netns_nexthop_id_is_reserved(netns, id_nm));

    nm_netns_nexthop_id_release_all(netns, tag1);
    g_assert_false(nm_netns_nexthop_id_is_reserved(netns, id_nm));

    /* releasing an ID after release_all() does nothing */
    nm_netns_nexthop_id_release(netns, id_nm, tag1);
    g_assert_false(nm_netns_nexthop_id_is_reserved(netns, id_nm));
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

    g_test_add_func("/netns/nexthop_id_reservation", test_nexthop_id_reservation);

    return g_test_run();
}
