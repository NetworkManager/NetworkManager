/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "src/core/nm-default-daemon.h"

#include "nm-netns.h"
#include "nm-test-utils-core.h"

static void
test_shared_ip(void)
{
    gs_unref_object NMPlatform *platform = NULL;
    gs_unref_object NMNetns    *netns    = NULL;
    NMNetnsSharedIPHandle      *handles[256];
    NMNetnsSharedIPHandle      *handle1;
    NMNetnsSharedIPHandle      *handle2;
    char                        buf[NM_INET_ADDRSTRLEN];
    guint                       i;

    platform = g_object_ref(NM_PLATFORM_GET);
    netns    = nm_netns_new(platform);

    /* Allocate addresses from 10.42.0.1 to 10.42.255.1 */
    for (i = 0; i < 256; i++) {
        handles[i] = nm_netns_shared_ip_reserve(netns);
        g_snprintf(buf, sizeof(buf), "10.42.%u.1", i);
        nmtst_assert_ip4_address(handles[i]->addr, buf);
        g_assert_cmpint(handles[i]->_ref_count, ==, 1);
    }

    /* Release an address and get it back */
    nm_netns_shared_ip_release(handles[139]);
    handles[139] = nm_netns_shared_ip_reserve(netns);
    nmtst_assert_ip4_address(handles[139]->addr, "10.42.139.1");

    /* Reuse 10.42.255.1 once */
    NMTST_EXPECT_NM_ERROR(
        "netns[*]: shared-ip4: ran out of shared IP addresses. Reuse 10.42.255.1/24");
    handle1 = nm_netns_shared_ip_reserve(netns);
    g_test_assert_expected_messages();
    nmtst_assert_ip4_address(handle1->addr, "10.42.255.1");
    g_assert_cmpint(handle1->_ref_count, ==, 2);

    /* Reuse 10.42.255.1 twice */
    handle2 = nm_netns_shared_ip_reserve(netns);
    g_assert(handle2 == handle1);
    nmtst_assert_ip4_address(handle1->addr, "10.42.255.1");
    g_assert_cmpint(handle2->_ref_count, ==, 3);

    /* Release all */
    nm_netns_shared_ip_release(handle1);
    nm_netns_shared_ip_release(handle2);
    for (i = 0; i < 256; i++) {
        nm_netns_shared_ip_release(handles[i]);
    }
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init_with_logging(&argc, &argv, NULL, "ALL");
    nm_linux_platform_setup();

    g_test_add_func("/netns/shared_ip", test_shared_ip);

    return g_test_run();
}
