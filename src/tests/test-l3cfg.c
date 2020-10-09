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

    bool has_addr4_101 : 1;
    bool add_addr4_101 : 1;

    guint32           acd_timeout_msec_a;
    NML3AcdDefendType acd_defend_type_a;

    TestL3cfgNotifyType notify_type;
    guint               post_commit_event_count;
    guint               general_event_count;
    guint               general_event_flags;
    union {
        struct {
            int  cb_count;
            bool expected_probe_result : 1;
            bool acd_event_ready_45 : 1;
            bool acd_event_ready_101 : 1;
        } wait_for_acd_ready_1;
    } notify_result;
} TestL3cfgData;

static void
_test_l3cfg_data_set_notify_type(TestL3cfgData *tdata, TestL3cfgNotifyType notify_type)
{
    g_assert(tdata);

    tdata->notify_type             = notify_type;
    tdata->post_commit_event_count = 0;
    tdata->general_event_count     = 0;
    tdata->general_event_flags     = 0;
    memset(&tdata->notify_result, 0, sizeof(tdata->notify_result));
}

static void
_test_l3cfg_signal_notify(NML3Cfg *                   l3cfg,
                          const NML3ConfigNotifyData *notify_data,
                          TestL3cfgData *             tdata)
{
    guint i;

    g_assert(NM_IS_L3CFG(l3cfg));
    g_assert(tdata);
    g_assert(notify_data);
    g_assert(_NM_INT_NOT_NEGATIVE(notify_data->notify_type));
    g_assert(notify_data->notify_type < _NM_L3_CONFIG_NOTIFY_TYPE_NUM);

    if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE)
        g_assert(notify_data->platform_change_on_idle.obj_type_flags != 0u);
    else if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE) {
        g_assert(NMP_OBJECT_IS_VALID(notify_data->platform_change.obj));
        g_assert(notify_data->platform_change.change_type != 0);
    } else if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_ACD_EVENT) {
        g_assert_cmpint(notify_data->acd_event.info.n_track_infos, >=, 1);
        g_assert(notify_data->acd_event.info.track_infos);
        for (i = 0; i < notify_data->acd_event.info.n_track_infos; i++) {
            const NML3AcdAddrTrackInfo *ti = &notify_data->acd_event.info.track_infos[i];

            nm_assert(NMP_OBJECT_GET_TYPE(ti->obj) == NMP_OBJECT_TYPE_IP4_ADDRESS);
            nm_assert(NMP_OBJECT_CAST_IP4_ADDRESS(ti->obj)->address
                      == notify_data->acd_event.info.addr);
            nm_assert(NM_IS_L3_CONFIG_DATA(ti->l3cd));
            nm_assert(ti->tag);
        }
    }

    switch (tdata->notify_type) {
    case TEST_L3CFG_NOTIFY_TYPE_NONE:
        g_assert_not_reached();
        break;
    case TEST_L3CFG_NOTIFY_TYPE_IDLE_ASSERT_NO_SIGNAL:
        if (NM_IN_SET(notify_data->notify_type,
                      NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE,
                      NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE))
            return;
        g_assert_not_reached();
        return;
    case TEST_L3CFG_NOTIFY_TYPE_COMMIT_1:
        g_assert_cmpint(tdata->post_commit_event_count, ==, 0);
        switch (notify_data->notify_type) {
        case NM_L3_CONFIG_NOTIFY_TYPE_POST_COMMIT:
            tdata->post_commit_event_count++;
            return;
        case NM_L3_CONFIG_NOTIFY_TYPE_ACD_EVENT:
            switch (tdata->f->test_idx) {
            case 2:
            case 3:
                nmtst_assert_ip4_address(notify_data->acd_event.info.addr, "192.168.133.45");
                if (tdata->f->test_idx == 2)
                    g_assert(notify_data->acd_event.info.state == NM_L3_ACD_ADDR_STATE_DEFENDING);
                else
                    g_assert(notify_data->acd_event.info.state == NM_L3_ACD_ADDR_STATE_PROBING);
                g_assert(tdata->general_event_count == 0);
                tdata->general_event_count++;
                return;
            case 4:
                if (notify_data->acd_event.info.addr == nmtst_inet4_from_string("192.168.133.45")) {
                    g_assert(!NM_FLAGS_HAS(tdata->general_event_flags, 0x1u));
                    tdata->general_event_flags |= 0x1u;
                    g_assert(notify_data->acd_event.info.state == NM_L3_ACD_ADDR_STATE_PROBING);
                    tdata->general_event_count++;
                } else if (notify_data->acd_event.info.addr
                           == nmtst_inet4_from_string("192.168.133.101")) {
                    g_assert(!NM_FLAGS_HAS(tdata->general_event_flags, 0x4u));
                    tdata->general_event_flags |= 0x4u;
                    g_assert(notify_data->acd_event.info.state == NM_L3_ACD_ADDR_STATE_PROBING);
                    tdata->general_event_count++;
                } else
                    g_assert_not_reached();
                return;
            default:
                g_assert_not_reached();
                return;
            }
        case NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE:
            return;
        default:
            g_assert_not_reached();
            return;
        }
    case TEST_L3CFG_NOTIFY_TYPE_WAIT_FOR_ACD_READY_1:
    {
        int num_acd_completed_events =
            1 + 2 + (tdata->add_addr4_101 ? (tdata->has_addr4_101 ? 1 : 3) : 0);

        if (NM_IN_SET(notify_data->notify_type,
                      NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE,
                      NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE))
            return;
        if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_ACD_EVENT) {
            if (notify_data->acd_event.info.addr == nmtst_inet4_from_string("192.168.133.45")) {
                g_assert(NM_IN_SET(notify_data->acd_event.info.state,
                                   NM_L3_ACD_ADDR_STATE_READY,
                                   NM_L3_ACD_ADDR_STATE_DEFENDING));
                tdata->notify_result.wait_for_acd_ready_1.acd_event_ready_45 = TRUE;
            } else if (notify_data->acd_event.info.addr
                       == nmtst_inet4_from_string("192.168.133.101")) {
                if (tdata->has_addr4_101) {
                    g_assert(
                        NM_IN_SET(notify_data->acd_event.info.state, NM_L3_ACD_ADDR_STATE_USED));
                } else {
                    g_assert(NM_IN_SET(notify_data->acd_event.info.state,
                                       NM_L3_ACD_ADDR_STATE_READY,
                                       NM_L3_ACD_ADDR_STATE_DEFENDING));
                    tdata->notify_result.wait_for_acd_ready_1.acd_event_ready_101 = TRUE;
                }
            } else
                g_assert_not_reached();

            g_assert_cmpint(tdata->notify_result.wait_for_acd_ready_1.cb_count,
                            <,
                            num_acd_completed_events);
            tdata->notify_result.wait_for_acd_ready_1.cb_count++;
            return;
        }
        if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_POST_COMMIT) {
            g_assert_cmpint(tdata->notify_result.wait_for_acd_ready_1.cb_count, >, 0);
            g_assert_cmpint(tdata->notify_result.wait_for_acd_ready_1.cb_count,
                            <,
                            num_acd_completed_events);
            tdata->notify_result.wait_for_acd_ready_1.cb_count++;
            nmtstp_platform_ip_addresses_assert(
                tdata->f->platform,
                tdata->f->ifindex0,
                TRUE,
                TRUE,
                TRUE,
                tdata->notify_result.wait_for_acd_ready_1.acd_event_ready_45 ? "192.168.133.45"
                                                                             : NULL,
                tdata->notify_result.wait_for_acd_ready_1.acd_event_ready_101 ? "192.168.133.101"
                                                                              : NULL,
                "1:2:3:4::45");
            return;
        }
        g_assert_not_reached();
        return;
    }
    }

    g_assert_not_reached();
}

static void
test_l3cfg(gconstpointer test_data)
{
    const int                                      TEST_IDX = GPOINTER_TO_INT(test_data);
    const guint32                                  ACD_TIMEOUT_BASE_MSEC = 1000;
    nm_auto(_test_fixture_1_teardown) TestFixture1 test_fixture          = {};
    const TestFixture1 *                           f;
    NML3CfgCommitTypeHandle *                      commit_type_1;
    NML3CfgCommitTypeHandle *                      commit_type_2;
    gs_unref_object NML3Cfg *l3cfg0                      = NULL;
    nm_auto_unref_l3cd const NML3ConfigData *l3cd_a      = NULL;
    TestL3cfgData                            tdata_stack = {
        .f = NULL,
    };
    TestL3cfgData *const tdata = &tdata_stack;

    _LOGD("test start (/l3cfg/%d)", TEST_IDX);

    if (nmtst_test_quick()) {
        gs_free char *msg =
            g_strdup_printf("Skipping test: don't run long running test %s (NMTST_DEBUG=slow)\n",
                            g_get_prgname() ?: "test-l3cfg");

        g_test_skip(msg);
        return;
    }

    f = _test_fixture_1_setup(&test_fixture, TEST_IDX);

    tdata->f             = f;
    tdata->has_addr4_101 = (f->test_idx == 4 && nmtst_get_rand_bool());
    tdata->add_addr4_101 = (f->test_idx == 4 && nmtst_get_rand_bool());

    tdata->acd_timeout_msec_a = NM_IN_SET(f->test_idx, 3, 4) ? ACD_TIMEOUT_BASE_MSEC : 0u;
    tdata->acd_defend_type_a  = NM_IN_SET(f->test_idx, 4)
                                    ? nmtst_rand_select(NM_L3_ACD_DEFEND_TYPE_NEVER,
                                                       NM_L3_ACD_DEFEND_TYPE_ONCE,
                                                       NM_L3_ACD_DEFEND_TYPE_ALWAYS)
                                    : NM_L3_ACD_DEFEND_TYPE_NEVER;

    if (tdata->has_addr4_101) {
        nmtstp_ip4_address_add(f->platform,
                               -1,
                               f->ifindex1,
                               nmtst_inet4_from_string("192.168.133.101"),
                               24,
                               nmtst_inet4_from_string("192.168.133.101"),
                               100000,
                               0,
                               0,
                               NULL);
    }

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
    case 4:
    {
        nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;

        l3cd = nm_l3_config_data_new(f->multiidx, f->ifindex0);

        nm_l3_config_data_add_address_4(
            l3cd,
            NM_PLATFORM_IP4_ADDRESS_INIT(.address      = nmtst_inet4_from_string("192.168.133.45"),
                                         .peer_address = nmtst_inet4_from_string("192.168.133.45"),
                                         .plen         = 24, ));

        if (tdata->add_addr4_101) {
            nm_l3_config_data_add_address_4(
                l3cd,
                NM_PLATFORM_IP4_ADDRESS_INIT(.address = nmtst_inet4_from_string("192.168.133.101"),
                                             .peer_address =
                                                 nmtst_inet4_from_string("192.168.133.101"),
                                             .plen = 24, ));
        }

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

    nm_l3_config_data_log(l3cd_a, "l3cd_a", "platform-test: l3cd_a: ", LOGL_DEBUG, LOGD_PLATFORM);

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
                            tdata->acd_defend_type_a,
                            tdata->acd_timeout_msec_a,
                            NM_L3_CONFIG_MERGE_FLAGS_NONE);
    }

    nm_l3_config_data_log(nm_l3cfg_get_combined_l3cd(l3cfg0, FALSE),
                          "test",
                          "platform-test: l3cfg0: ",
                          LOGL_DEBUG,
                          LOGD_PLATFORM);

    _test_l3cfg_data_set_notify_type(tdata, TEST_L3CFG_NOTIFY_TYPE_COMMIT_1);
    nm_l3cfg_commit(l3cfg0, NM_L3_CFG_COMMIT_TYPE_REAPPLY);
    g_assert_cmpint(tdata->post_commit_event_count, ==, 1);
    _test_l3cfg_data_set_notify_type(tdata, TEST_L3CFG_NOTIFY_TYPE_NONE);

    nmtstp_platform_ip_addresses_assert(tdata->f->platform,
                                        tdata->f->ifindex0,
                                        TRUE,
                                        TRUE,
                                        TRUE,
                                        NM_IN_SET(f->test_idx, 2) ? "192.168.133.45" : NULL,
                                        NM_IN_SET(f->test_idx, 2, 3, 4) ? "1:2:3:4::45" : NULL);

    if (NM_IN_SET(f->test_idx, 1, 2)) {
        _test_l3cfg_data_set_notify_type(tdata, TEST_L3CFG_NOTIFY_TYPE_IDLE_ASSERT_NO_SIGNAL);
        _LOGT("poll 1 start");
        nmtst_main_context_iterate_until(NULL,
                                         nmtst_get_rand_uint32() % (ACD_TIMEOUT_BASE_MSEC * 5u),
                                         FALSE);
        _LOGT("poll 1 end");
        _test_l3cfg_data_set_notify_type(tdata, TEST_L3CFG_NOTIFY_TYPE_NONE);
    }

    if (NM_IN_SET(f->test_idx, 3, 4)) {
        _test_l3cfg_data_set_notify_type(tdata, TEST_L3CFG_NOTIFY_TYPE_WAIT_FOR_ACD_READY_1);
        tdata->notify_result.wait_for_acd_ready_1.expected_probe_result = TRUE;
        _LOGT("poll 2 start");
        nmtst_main_context_iterate_until(
            NULL,
            ACD_TIMEOUT_BASE_MSEC * 3u / 2u
                + (nmtst_get_rand_uint32() % (2u * ACD_TIMEOUT_BASE_MSEC)),
            FALSE);
        _LOGT("poll 2 end");
        g_assert_cmpint(tdata->notify_result.wait_for_acd_ready_1.cb_count,
                        ==,
                        1 + 2 + (tdata->add_addr4_101 ? (tdata->has_addr4_101 ? 1 : 3) : 0));
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

    _LOGD("test end (/l3cfg/%d)", TEST_IDX);
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
    g_test_add_data_func("/l3cfg/4", GINT_TO_POINTER(4), test_l3cfg);
}
