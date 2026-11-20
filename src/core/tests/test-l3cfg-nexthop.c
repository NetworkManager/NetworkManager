/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "src/core/nm-default-daemon.h"

#include <linux/if.h>

#include "nm-l3cfg.h"
#include "nm-l3-config-data.h"
#include "nm-netns.h"
#include "platform/nm-fake-platform.h"

#include "nm-test-utils-core.h"

/*****************************************************************************/

/* A nexthop that looks like it was created by NM (see
 * nm_platform_ip_nexthop_is_nm_owned()). */
#define ID_NM(n) (NM_NEXTHOP_ID_NM_OWNED_BIT | (n))

typedef struct {
    NMPlatform *platform;
    NMNetns    *netns;
    NML3Cfg    *l3cfg;
    int         ifindex;
} TestFixture;

static void
_fixture_setup(TestFixture *f)
{
    f->platform = NM_PLATFORM_GET;
    f->ifindex  = nm_platform_link_get_ifindex(f->platform, "eth0");
    g_assert_cmpint(f->ifindex, >, 0);

    f->netns = nm_netns_new(f->platform);
    f->l3cfg = nm_netns_l3cfg_acquire(f->netns, f->ifindex);
    g_assert(NM_IS_L3CFG(f->l3cfg));
}

static void
_fixture_teardown(TestFixture *f)
{
    nm_l3cfg_remove_config_all(f->l3cfg, f);
    nm_l3cfg_commit(f->l3cfg, NM_L3_CFG_COMMIT_TYPE_REAPPLY);
    g_clear_object(&f->l3cfg);
    g_clear_object(&f->netns);

    /* Remove the nexthops that the l3cfg didn't own. */
    g_assert(nm_platform_ip_nexthop_flush(f->platform, AF_INET6, f->ifindex));
}

static void
_nexthop_add_external(TestFixture *f, guint32 id, NMIPConfigSource source)
{
    NMPObject obj;

    nmp_object_stackinit(&obj, NMP_OBJECT_TYPE_IP6_NEXTHOP, NULL);
    obj.ip6_nexthop.id        = id;
    obj.ip6_nexthop.ifindex   = f->ifindex;
    obj.ip6_nexthop.nh_source = source;
    g_assert_cmpint(nm_platform_ip_nexthop_add(f->platform, NMP_NLM_FLAG_ADD, &obj, NULL), ==, 0);
}

/* Configures the l3cfg with nexthops with the given (zero terminated) IDs,
 * each referenced by a route. Nexthops with ID_NM() are created with source
 * NDISC, like ndisc does; the other ones with source USER. */
static void
_set_config(TestFixture *f, const guint32 *ids)
{
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
    guint                                   i;

    l3cd = nm_l3_config_data_new(nm_netns_get_multi_idx(f->netns),
                                 f->ifindex,
                                 NM_IP_CONFIG_SOURCE_USER);

    for (i = 0; ids[i]; i++) {
        const guint32 id = ids[i];

        nm_l3_config_data_add_nexthop_6(
            l3cd,
            &((const NMPlatformIP6NextHop) {
                .id        = id,
                .ifindex   = f->ifindex,
                .nh_source = NM_FLAGS_ALL(id, NM_NEXTHOP_ID_NM_OWNED_BIT)
                                 ? NM_IP_CONFIG_SOURCE_NDISC
                                 : NM_IP_CONFIG_SOURCE_USER,
            }));
        nm_l3_config_data_add_route_6(
            l3cd,
            NM_PLATFORM_IP6_ROUTE_INIT(.ifindex   = f->ifindex,
                                       .network   = {{{0x20, 0x01, 0x0d, 0xb8, 0, i + 1}}},
                                       .plen      = 64,
                                       .metric    = 100,
                                       .nhid      = id,
                                       .rt_source = NM_IP_CONFIG_SOURCE_USER, ));
    }

    nm_l3cfg_add_config(f->l3cfg,
                        f,
                        TRUE,
                        l3cd,
                        0,
                        0,
                        0,
                        NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP4,
                        NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6,
                        0,
                        0,
                        NM_DNS_PRIORITY_DEFAULT_NORMAL,
                        NM_DNS_PRIORITY_DEFAULT_NORMAL,
                        NM_L3_ACD_DEFEND_TYPE_ALWAYS,
                        0,
                        NM_L3CFG_CONFIG_FLAGS_NONE,
                        NM_L3_CONFIG_MERGE_FLAGS_NONE);
}

#define set_config(f, ...) _set_config((f), ((const guint32[]) {__VA_ARGS__, 0}))

/* Asserts that the nexthops of the interface in platform have exactly the
 * given (zero terminated, sorted) IDs. */
static void
_assert_platform(TestFixture *f, const guint32 *ids)
{
    gs_unref_ptrarray GPtrArray *nexthops = NULL;
    guint                        n;
    guint                        i;

    nexthops = nm_platform_ip_nexthop_dump(f->platform, AF_INET6, f->ifindex);
    g_assert(nexthops);

    for (n = 0; ids[n]; n++)
        ;
    g_assert_cmpuint(nexthops->len, ==, n);
    for (i = 0; i < n; i++)
        g_assert_cmpuint(NMP_OBJECT_CAST_IP_NEXTHOP(nexthops->pdata[i])->id, ==, ids[i]);
}

#define assert_platform(f, ...) _assert_platform((f), ((const guint32[]) {__VA_ARGS__, 0}))

/*****************************************************************************/

static void
test_update_reapply(void)
{
    TestFixture f = {};

    _fixture_setup(&f);

    /* An external nexthop, never touched, and a stale nexthop from a
     * previous run of NM. */
    _nexthop_add_external(&f, 100, NM_IP_CONFIG_SOURCE_USER);
    _nexthop_add_external(&f, ID_NM(200), NM_IP_CONFIG_SOURCE_NDISC);
    assert_platform(&f, 100, ID_NM(200));

    /* On update, only the nexthops configured by this l3cfg are pruned. */
    set_config(&f, 50, ID_NM(1));
    nm_l3cfg_commit(f.l3cfg, NM_L3_CFG_COMMIT_TYPE_UPDATE);
    assert_platform(&f, 50, 100, ID_NM(1), ID_NM(200));

    /* On reapply, the stale nexthop is pruned too. */
    nm_l3cfg_commit(f.l3cfg, NM_L3_CFG_COMMIT_TYPE_REAPPLY);
    assert_platform(&f, 50, 100, ID_NM(1));

    /* A configured nexthop is pruned on update, even if it doesn't look like
     * one created by NM. */
    set_config(&f, ID_NM(1));
    nm_l3cfg_commit(f.l3cfg, NM_L3_CFG_COMMIT_TYPE_UPDATE);
    assert_platform(&f, 100, ID_NM(1));

    /* ... and on reapply. */
    set_config(&f, 50, ID_NM(1));
    nm_l3cfg_commit(f.l3cfg, NM_L3_CFG_COMMIT_TYPE_UPDATE);
    assert_platform(&f, 50, 100, ID_NM(1));
    nm_l3cfg_remove_config_all(f.l3cfg, &f);
    nm_l3cfg_commit(f.l3cfg, NM_L3_CFG_COMMIT_TYPE_REAPPLY);
    assert_platform(&f, 100);

    _fixture_teardown(&f);
}

static void
test_delete_failed(void)
{
    TestFixture f = {};

    _fixture_setup(&f);

    set_config(&f, 50, ID_NM(1));
    nm_l3cfg_commit(f.l3cfg, NM_L3_CFG_COMMIT_TYPE_UPDATE);
    assert_platform(&f, 50, ID_NM(1));

    /* The deletion fails, the nexthop stays in the kernel. */
    nm_fake_platform_set_nexthop_delete_fail(f.platform, TRUE);
    set_config(&f, ID_NM(1));
    nm_l3cfg_commit(f.l3cfg, NM_L3_CFG_COMMIT_TYPE_UPDATE);
    assert_platform(&f, 50, ID_NM(1));

    /* The nexthop is still tracked after another failed attempt. */
    nm_l3cfg_commit(f.l3cfg, NM_L3_CFG_COMMIT_TYPE_UPDATE);
    assert_platform(&f, 50, ID_NM(1));

    /* The next update retries and succeeds. */
    nm_fake_platform_set_nexthop_delete_fail(f.platform, FALSE);
    nm_l3cfg_commit(f.l3cfg, NM_L3_CFG_COMMIT_TYPE_UPDATE);
    assert_platform(&f, ID_NM(1));

    _fixture_teardown(&f);
}

static void
test_blocked(void)
{
    TestFixture         f = {};
    NML3CfgBlockHandle *block;

    _fixture_setup(&f);

    set_config(&f, 50, ID_NM(1));
    nm_l3cfg_commit(f.l3cfg, NM_L3_CFG_COMMIT_TYPE_UPDATE);
    assert_platform(&f, 50, ID_NM(1));

    /* While pruning is blocked, nothing is removed, and the nexthops that are
     * no longer configured are not forgotten. */
    block = nm_l3cfg_block_obj_pruning(f.l3cfg, AF_INET6);
    set_config(&f, ID_NM(2));
    nm_l3cfg_commit(f.l3cfg, NM_L3_CFG_COMMIT_TYPE_UPDATE);
    assert_platform(&f, 50, ID_NM(1), ID_NM(2));
    nm_l3cfg_commit(f.l3cfg, NM_L3_CFG_COMMIT_TYPE_REAPPLY);
    assert_platform(&f, 50, ID_NM(1), ID_NM(2));

    /* Once unblocked, they are pruned. */
    nm_l3cfg_unblock_obj_pruning(block);
    nm_l3cfg_commit(f.l3cfg, NM_L3_CFG_COMMIT_TYPE_UPDATE);
    assert_platform(&f, ID_NM(2));

    _fixture_teardown(&f);
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    int ifindex;

    nmtst_init_with_logging(&argc, &argv, NULL, "DEFAULT");

    nm_fake_platform_setup();

    ifindex = nm_platform_link_get_ifindex(NM_PLATFORM_GET, "eth0");
    g_assert_cmpint(nm_platform_link_change_flags(NM_PLATFORM_GET, ifindex, IFF_UP, TRUE), ==, 0);

    g_test_add_func("/l3cfg/nexthop/update-reapply", test_update_reapply);
    g_test_add_func("/l3cfg/nexthop/delete-failed", test_delete_failed);
    g_test_add_func("/l3cfg/nexthop/blocked", test_blocked);

    return g_test_run();
}
