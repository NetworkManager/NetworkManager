/* SPDX-License-Identifier: LGPL-2.1+ */

#include "nm-default.h"

#include "nm-l3cfg.h"
#include "nm-netns.h"
#include "platform/nm-platform.h"

#include "platform/tests/test-common.h"

/*****************************************************************************/

typedef struct {
    int                test_idx;
    NMPlatform *       platform;
    NMNetns *          netns;
    NMDedupMultiIndex *multiidx;
    const char *       ifname0;
    const char *       ifname1;
    NMPLinkAddress     hwaddr0;
    NMPLinkAddress     hwaddr1;
    int                ifindex0;
    int                ifindex1;
} TestFixture1;

static const TestFixture1 *
_test_fixture_1_setup(TestFixture1 *f, int test_idx)
{
    const NMPlatformLink *l0;
    const NMPlatformLink *l1;

    g_assert_cmpint(test_idx, >, 0);
    g_assert_cmpint(f->test_idx, ==, 0);

    f->test_idx = test_idx;

    f->ifname0 = "nm-test-veth0";
    f->ifname1 = "nm-test-veth1";

    f->platform = g_object_ref(NM_PLATFORM_GET);
    f->multiidx = nm_dedup_multi_index_ref(nm_platform_get_multi_idx(f->platform));
    f->netns    = nm_netns_new(f->platform);

    l0 = nmtstp_link_veth_add(f->platform, -1, f->ifname0, f->ifname1);
    l1 = nmtstp_link_get_typed(f->platform, -1, f->ifname1, NM_LINK_TYPE_VETH);

    f->ifindex0 = l0->ifindex;
    f->hwaddr0  = l0->l_address;

    f->ifindex1 = l1->ifindex;
    f->hwaddr1  = l1->l_address;

    g_assert(nm_platform_link_set_up(f->platform, f->ifindex0, NULL));
    g_assert(nm_platform_link_set_up(f->platform, f->ifindex1, NULL));

    return f;
}

static void
_test_fixture_1_teardown(TestFixture1 *f)
{
    g_assert(f);

    if (f->test_idx == 0)
        return;

    _LOGD("test teatdown");

    nmtstp_link_delete(f->platform, -1, f->ifindex0, f->ifname0, TRUE);
    g_assert(!nm_platform_link_get(f->platform, f->ifindex0));
    g_assert(!nm_platform_link_get(f->platform, f->ifindex1));
    g_assert(!nm_platform_link_get_by_ifname(f->platform, f->ifname0));
    g_assert(!nm_platform_link_get_by_ifname(f->platform, f->ifname1));

    g_object_unref(f->netns);
    g_object_unref(f->platform);
    nm_dedup_multi_index_unref(f->multiidx);

    *f = (TestFixture1){
        .test_idx = 0,
    };
}

/*****************************************************************************/

typedef enum {
    TEST_L3CFG_NOTIFY_TYPE_NONE,
    TEST_L3CFG_NOTIFY_TYPE_IDLE_ASSERT_NO_SIGNAL,
    TEST_L3CFG_NOTIFY_TYPE_COMMIT_1,
    TEST_L3CFG_NOTIFY_TYPE_WAIT_FOR_ACD_READY_1,
} TestL3cfgNotifyType;

typedef struct {
    const TestFixture1 *f;

    TestL3cfgNotifyType notify_type;
    guint               post_commit_event_count;
    guint               general_event_count;
    union {
        struct {
            int  cb_count;
            bool expected_probe_result : 1;
        } wait_for_acd_ready_1;
    } notify_data;
} TestL3cfgData;

static void
_test_l3cfg_data_set_notify_type(TestL3cfgData *tdata, TestL3cfgNotifyType notify_type)
{
    g_assert(tdata);

    tdata->notify_type             = notify_type;
    tdata->post_commit_event_count = 0;
    tdata->general_event_count     = 0;
    memset(&tdata->notify_data, 0, sizeof(tdata->notify_data));
}

static void
_test_l3cfg_signal_notify(NML3Cfg *                      l3cfg,
                          int                            notify_type_i,
                          const NML3ConfigNotifyPayload *payload,
                          TestL3cfgData *                tdata)
{
    NML3ConfigNotifyType l3_notify_type = notify_type_i;

    g_assert(NM_IS_L3CFG(l3cfg));
    g_assert(tdata);
    g_assert((!!payload)
             == NM_IN_SET(l3_notify_type,
                          NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE,
                          NM_L3_CONFIG_NOTIFY_TYPE_ACD_COMPLETED));

    if (l3_notify_type == NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE)
        g_assert(payload->platform_change_on_idle.obj_type_flags != 0u);

    switch (tdata->notify_type) {
    case TEST_L3CFG_NOTIFY_TYPE_NONE:
        g_assert_not_reached();
        break;
    case TEST_L3CFG_NOTIFY_TYPE_IDLE_ASSERT_NO_SIGNAL:
        if (l3_notify_type == NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE)
            return;
        g_assert_not_reached();
        return;
    case TEST_L3CFG_NOTIFY_TYPE_COMMIT_1:
        g_assert_cmpint(tdata->post_commit_event_count, ==, 0);
        switch (l3_notify_type) {
        case NM_L3_CONFIG_NOTIFY_TYPE_POST_COMMIT:
            tdata->post_commit_event_count++;
            return;
        case NM_L3_CONFIG_NOTIFY_TYPE_ACD_COMPLETED:
            switch (tdata->f->test_idx) {
            case 2:
                nmtst_assert_ip4_address(payload->acd_completed.addr, "192.167.133.45");
                g_assert(payload->acd_completed.probe_result);
                g_assert(tdata->general_event_count == 0);
                tdata->general_event_count++;
                return;
            default:
                g_assert_not_reached();
                return;
            }
        default:
            g_assert_not_reached();
            return;
        }
    case TEST_L3CFG_NOTIFY_TYPE_WAIT_FOR_ACD_READY_1:
        if (l3_notify_type == NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE)
            return;
        if (l3_notify_type == NM_L3_CONFIG_NOTIFY_TYPE_ACD_COMPLETED) {
            g_assert(tdata->notify_data.wait_for_acd_ready_1.cb_count == 0);
            tdata->notify_data.wait_for_acd_ready_1.cb_count++;
            return;
        }
        if (l3_notify_type == NM_L3_CONFIG_NOTIFY_TYPE_POST_COMMIT) {
            g_assert(tdata->notify_data.wait_for_acd_ready_1.cb_count == 1);
            tdata->notify_data.wait_for_acd_ready_1.cb_count++;
            nmtstp_platform_ip_addresses_assert(tdata->f->platform,
                                                tdata->f->ifindex0,
                                                TRUE,
                                                TRUE,
                                                TRUE,
                                                "192.167.133.45",
                                                "1:2:3:4::45");
            return;
        }
        g_assert_not_reached();
        return;
    }

    g_assert_not_reached();
}

static void
test_l3cfg(gconstpointer test_data)
{
    nm_auto(_test_fixture_1_teardown) TestFixture1 test_fixture = {};
    const TestFixture1 *                           f;
    NML3CfgCommitTypeHandle *                      commit_type_1;
    NML3CfgCommitTypeHandle *                      commit_type_2;
    gs_unref_object NML3Cfg *l3cfg0                           = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd_a           = NULL;
    guint32                                  acd_timeout_msec = 0;
    TestL3cfgData                            tdata_stack      = {
        .f = NULL,
    };
    TestL3cfgData *const tdata = &tdata_stack;

    _LOGD("test start (/l3cfg/%d)", GPOINTER_TO_INT(test_data));

    if (nmtst_test_quick()) {
        gs_free char *msg =
            g_strdup_printf("Skipping test: don't run long running test %s (NMTST_DEBUG=slow)\n",
                            g_get_prgname() ?: "test-l3cfg");

        g_test_skip(msg);
        return;
    }

    f = _test_fixture_1_setup(&test_fixture, GPOINTER_TO_INT(test_data));

    tdata->f = f;

    l3cfg0 = nm_netns_access_l3cfg(f->netns, f->ifindex0);
    g_assert(NM_IS_L3CFG(l3cfg0));

    g_signal_connect(l3cfg0, NM_L3CFG_SIGNAL_NOTIFY, G_CALLBACK(_test_l3cfg_signal_notify), tdata);

    commit_type_1 = nm_l3cfg_commit_type_register(l3cfg0, NM_L3_CFG_COMMIT_TYPE_UPDATE, NULL);

    if ((nmtst_get_rand_uint32() % 4u) != 0) {
        commit_type_2 =
            nm_l3cfg_commit_type_register(l3cfg0,
                                          nmtst_rand_select(NM_L3_CFG_COMMIT_TYPE_NONE,
                                                            NM_L3_CFG_COMMIT_TYPE_ASSUME,
                                                            NM_L3_CFG_COMMIT_TYPE_UPDATE),
                                          NULL);
    } else
        commit_type_2 = NULL;

    switch (f->test_idx) {
    case 1:
        break;
    case 2:
    case 3:
    {
        nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;

        l3cd = nm_l3_config_data_new(f->multiidx, f->ifindex0);

        nm_l3_config_data_add_address_4(
            l3cd,
            NM_PLATFORM_IP4_ADDRESS_INIT(.address      = nmtst_inet4_from_string("192.167.133.45"),
                                         .peer_address = nmtst_inet4_from_string("192.167.133.45"),
                                         .plen         = 24, ));

        nm_l3_config_data_add_address_6(
            l3cd,
            NM_PLATFORM_IP6_ADDRESS_INIT(.address = *nmtst_inet6_from_string("1:2:3:4::45"),
                                         .plen    = 64, ));

        if (nmtst_get_rand_bool())
            nm_l3_config_data_seal(l3cd);
        l3cd_a = g_steal_pointer(&l3cd);
        break;
    }
    }

    acd_timeout_msec = (f->test_idx == 3) ? 2000u : 0u;

    if (l3cd_a) {
        nm_l3cfg_add_config(l3cfg0,
                            GINT_TO_POINTER('a'),
                            nmtst_get_rand_bool(),
                            l3cd_a,
                            'a',
                            0,
                            0,
                            NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP4,
                            NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6,
                            0,
                            0,
                            acd_timeout_msec,
                            NM_L3_CONFIG_MERGE_FLAGS_NONE);
    }

    nm_l3_config_data_log(nm_l3cfg_get_combined_l3cd(l3cfg0, FALSE),
                          "test",
                          "platform-test: l3cfg0: ",
                          LOGL_DEBUG,
                          LOGD_PLATFORM);

    _test_l3cfg_data_set_notify_type(tdata, TEST_L3CFG_NOTIFY_TYPE_COMMIT_1);
    nm_l3cfg_platform_commit(l3cfg0, NM_L3_CFG_COMMIT_TYPE_REAPPLY);
    g_assert_cmpint(tdata->post_commit_event_count, ==, 1);
    _test_l3cfg_data_set_notify_type(tdata, TEST_L3CFG_NOTIFY_TYPE_NONE);

    nmtstp_platform_ip_addresses_assert(tdata->f->platform,
                                        tdata->f->ifindex0,
                                        TRUE,
                                        TRUE,
                                        TRUE,
                                        NM_IN_SET(f->test_idx, 2) ? "192.167.133.45" : NULL,
                                        NM_IN_SET(f->test_idx, 2, 3) ? "1:2:3:4::45" : NULL);

    if (NM_IN_SET(f->test_idx, 1, 2)) {
        _test_l3cfg_data_set_notify_type(tdata, TEST_L3CFG_NOTIFY_TYPE_IDLE_ASSERT_NO_SIGNAL);
        _LOGT("poll 1 start");
        nmtst_main_context_iterate_until(NULL, nmtst_get_rand_uint32() % 5000u, FALSE);
        _LOGT("poll 1 end");
        _test_l3cfg_data_set_notify_type(tdata, TEST_L3CFG_NOTIFY_TYPE_NONE);
    }

    if (NM_IN_SET(f->test_idx, 3)) {
        _test_l3cfg_data_set_notify_type(tdata, TEST_L3CFG_NOTIFY_TYPE_WAIT_FOR_ACD_READY_1);
        tdata->notify_data.wait_for_acd_ready_1.expected_probe_result = TRUE;
        _LOGT("poll 2 start");
        nmtst_main_context_iterate_until(NULL, 2500u + (nmtst_get_rand_uint32() % 4000u), FALSE);
        _LOGT("poll 2 end");
        g_assert_cmpint(tdata->notify_data.wait_for_acd_ready_1.cb_count, ==, 2);
        _test_l3cfg_data_set_notify_type(tdata, TEST_L3CFG_NOTIFY_TYPE_NONE);
    }

    g_signal_handlers_disconnect_by_func(l3cfg0, G_CALLBACK(_test_l3cfg_signal_notify), tdata);

    nm_l3cfg_commit_type_unregister(l3cfg0, commit_type_1);
    nm_l3cfg_commit_type_unregister(l3cfg0, commit_type_2);

    if ((nmtst_get_rand_uint32() % 3) == 0)
        _test_fixture_1_teardown(&test_fixture);

    nm_l3cfg_remove_config_all(l3cfg0, GINT_TO_POINTER('a'), FALSE);

    if ((nmtst_get_rand_uint32() % 3) == 0)
        _test_fixture_1_teardown(&test_fixture);

    _LOGD("test end (/l3cfg/%d)", f->test_idx);
}

/*****************************************************************************/

NMTstpSetupFunc const _nmtstp_setup_platform_func = nm_linux_platform_setup;

void
_nmtstp_init_tests(int *argc, char ***argv)
{
    nmtst_init_with_logging(argc, argv, NULL, "ALL");
}

void
_nmtstp_setup_tests(void)
{
    g_test_add_data_func("/l3cfg/1", GINT_TO_POINTER(1), test_l3cfg);
    g_test_add_data_func("/l3cfg/2", GINT_TO_POINTER(2), test_l3cfg);
    g_test_add_data_func("/l3cfg/3", GINT_TO_POINTER(3), test_l3cfg);
}
