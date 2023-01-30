/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "src/core/nm-default-daemon.h"

#include "nm-compat-headers/linux/if_addr.h"

#include "nm-l3cfg.h"
#include "nm-l3-ipv4ll.h"
#include "nm-l3-ipv6ll.h"
#include "nm-netns.h"
#include "libnm-platform/nm-platform.h"

#include "platform/tests/test-common.h"

/*****************************************************************************/

static NML3Cfg *
_netns_access_l3cfg(NMNetns *netns, int ifindex)
{
    NML3Cfg *l3cfg;

    g_assert(NM_IS_NETNS(netns));
    g_assert(ifindex > 0);

    g_assert(!nm_netns_l3cfg_get(netns, ifindex));

    l3cfg = nm_netns_l3cfg_acquire(netns, ifindex);
    g_assert(NM_IS_L3CFG(l3cfg));
    return l3cfg;
}

/*****************************************************************************/

typedef struct {
    int                test_idx;
    NMPlatform        *platform;
    NMNetns           *netns;
    NMDedupMultiIndex *multiidx;
    const char        *ifname0;
    const char        *ifname1;
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
    const NMEtherAddr     addr0 = NM_ETHER_ADDR_INIT(0xAA, 0xAA, test_idx, 0x00, 0x00, 0x00);
    const NMEtherAddr     addr1 = NM_ETHER_ADDR_INIT(0xAA, 0xAA, test_idx, 0x00, 0x00, 0x11);

    g_assert_cmpint(test_idx, >, 0);
    g_assert_cmpint(f->test_idx, ==, 0);

    f->test_idx = test_idx;

    f->ifname0 = "nm-test-veth0";
    f->ifname1 = "nm-test-veth1";

    f->platform = g_object_ref(NM_PLATFORM_GET);
    f->multiidx = nm_dedup_multi_index_ref(nm_platform_get_multi_idx(f->platform));
    f->netns    = nm_netns_new(f->platform);

    nmtstp_link_veth_add(f->platform, -1, f->ifname0, f->ifname1);

    l0 = nmtstp_link_get_typed(f->platform, -1, f->ifname0, NM_LINK_TYPE_VETH);
    l1 = nmtstp_link_get_typed(f->platform, -1, f->ifname1, NM_LINK_TYPE_VETH);

    f->ifindex0 = l0->ifindex;
    f->ifindex1 = l1->ifindex;

    g_assert_cmpint(nm_platform_link_set_address(f->platform, f->ifindex0, &addr0, sizeof(addr0)),
                    ==,
                    0);
    g_assert_cmpint(nm_platform_link_set_address(f->platform, f->ifindex1, &addr1, sizeof(addr1)),
                    ==,
                    0);

    l0 = nmtstp_link_get_typed(f->platform, f->ifindex0, f->ifname0, NM_LINK_TYPE_VETH);
    l1 = nmtstp_link_get_typed(f->platform, f->ifindex1, f->ifname1, NM_LINK_TYPE_VETH);

    f->hwaddr0 = l0->l_address;
    f->hwaddr1 = l1->l_address;

    g_assert(nm_platform_link_change_flags(f->platform, f->ifindex0, IFF_UP, TRUE) >= 0);
    g_assert(nm_platform_link_change_flags(f->platform, f->ifindex1, IFF_UP, TRUE) >= 0);

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
    guint               pre_commit_event_count;
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
    tdata->pre_commit_event_count  = 0;
    tdata->post_commit_event_count = 0;
    tdata->general_event_count     = 0;
    tdata->general_event_flags     = 0;
    memset(&tdata->notify_result, 0, sizeof(tdata->notify_result));
}

static void
_test_l3cfg_signal_notify(NML3Cfg                    *l3cfg,
                          const NML3ConfigNotifyData *notify_data,
                          TestL3cfgData              *tdata)
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
    } else if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_L3CD_CHANGED) {
        g_assert(!notify_data->l3cd_changed.l3cd_old
                 || NM_IS_L3_CONFIG_DATA(notify_data->l3cd_changed.l3cd_old));
        g_assert(!notify_data->l3cd_changed.l3cd_new
                 || NM_IS_L3_CONFIG_DATA(notify_data->l3cd_changed.l3cd_new));
        return;
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
        case NM_L3_CONFIG_NOTIFY_TYPE_PRE_COMMIT:
            g_assert_cmpint(tdata->pre_commit_event_count, ==, 0);
            tdata->pre_commit_event_count++;
            return;
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
                      NM_L3_CONFIG_NOTIFY_TYPE_PRE_COMMIT,
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
    const TestFixture1                            *f;
    NML3CfgCommitTypeHandle                       *commit_type_1;
    NML3CfgCommitTypeHandle                       *commit_type_2;
    gs_unref_object NML3Cfg                       *l3cfg0      = NULL;
    nm_auto_unref_l3cd const NML3ConfigData       *l3cd_a      = NULL;
    TestL3cfgData                                  tdata_stack = {
                                         .f = NULL,
    };
    TestL3cfgData *const tdata = &tdata_stack;

    _LOGD("test start (/l3cfg/%d)", TEST_IDX);

    /* FIXME: https://bugzilla.redhat.com/show_bug.cgi?id=2165141 */
    g_test_skip("Skip: this test is currently known to fail (rhbz#2165141)");
    return;

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

    l3cfg0 = _netns_access_l3cfg(f->netns, f->ifindex0);

    g_signal_connect(l3cfg0, NM_L3CFG_SIGNAL_NOTIFY, G_CALLBACK(_test_l3cfg_signal_notify), tdata);

    commit_type_1 =
        nm_l3cfg_commit_type_register(l3cfg0, NM_L3_CFG_COMMIT_TYPE_UPDATE, NULL, "test1");

    if (!nmtst_get_rand_one_case_in(4)) {
        commit_type_2 = nm_l3cfg_commit_type_register(
            l3cfg0,
            nmtst_rand_select(NM_L3_CFG_COMMIT_TYPE_NONE, NM_L3_CFG_COMMIT_TYPE_UPDATE),
            NULL,
            "test2");
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

        l3cd = nm_l3_config_data_new(f->multiidx, f->ifindex0, NM_IP_CONFIG_SOURCE_UNKNOWN);

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
            NM_PLATFORM_IP6_ADDRESS_INIT(.address = nmtst_inet6_from_string("1:2:3:4::45"),
                                         .plen    = 64, ));

        if (nmtst_get_rand_one_case_in(2))
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
                            NM_DNS_PRIORITY_DEFAULT_NORMAL,
                            NM_DNS_PRIORITY_DEFAULT_NORMAL,
                            tdata->acd_defend_type_a,
                            tdata->acd_timeout_msec_a,
                            NM_L3CFG_CONFIG_FLAGS_NONE,
                            NM_L3_CONFIG_MERGE_FLAGS_NONE);
    }

    nm_l3_config_data_log(nm_l3cfg_get_combined_l3cd(l3cfg0, FALSE),
                          "test",
                          "platform-test: l3cfg0: ",
                          LOGL_DEBUG,
                          LOGD_PLATFORM);

    _test_l3cfg_data_set_notify_type(tdata, TEST_L3CFG_NOTIFY_TYPE_COMMIT_1);
    nm_l3cfg_commit(l3cfg0, NM_L3_CFG_COMMIT_TYPE_REAPPLY);
    g_assert_cmpint(tdata->pre_commit_event_count, ==, 1);
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

    if (nmtst_get_rand_one_case_in(3))
        _test_fixture_1_teardown(&test_fixture);

    nm_l3cfg_remove_config_all(l3cfg0, GINT_TO_POINTER('a'));

    if (nmtst_get_rand_one_case_in(3))
        _test_fixture_1_teardown(&test_fixture);

    _LOGD("test end (/l3cfg/%d)", TEST_IDX);
}

/*****************************************************************************/

#define L3IPV4LL_ACD_TIMEOUT_MSEC 1500u

typedef struct {
    const TestFixture1      *f;
    NML3CfgCommitTypeHandle *l3cfg_commit_type_1;
    guint                    acd_timeout_msec;
    NML3IPv4LL              *l3ipv4ll;
    bool                     has_addr4_101;
    gint8                    ready_seen;
    gint8                    addr_commit;
    in_addr_t                addr_commit_addr;
    bool                     add_conflict_checked : 1;
    bool                     add_conflict_done;
} TestL3IPv4LLData;

static gconstpointer
TEST_L3_IPV4LL_TAG(const TestL3IPv4LLData *tdata, guint offset)
{
    return (&(((const char *) tdata)[offset]));
}

static void
_test_l3_ipv4ll_maybe_add_addr_4(const TestL3IPv4LLData *tdata,
                                 int                     ifindex,
                                 guint                   one_case_in_num,
                                 bool                   *has_addr,
                                 const char             *addr)
{
    if (has_addr) {
        if (*has_addr || !nmtst_get_rand_one_case_in(one_case_in_num))
            return;
        *has_addr = TRUE;
    }

    if (ifindex == 0)
        ifindex = tdata->f->ifindex0;

    g_assert_cmpint(ifindex, >, 0);

    _LOGT("add test address: %s on ifindex=%d", addr, ifindex);

    nmtstp_ip4_address_add(tdata->f->platform,
                           -1,
                           ifindex,
                           nmtst_inet4_from_string(addr),
                           24,
                           nmtst_inet4_from_string(addr),
                           100000,
                           0,
                           0,
                           NULL);
}

static void
_test_l3_ipv4ll_signal_notify(NML3Cfg                    *l3cfg,
                              const NML3ConfigNotifyData *notify_data,
                              TestL3IPv4LLData           *tdata)
{
    char sbuf_addr[NM_INET_ADDRSTRLEN];

    g_assert(NM_IS_L3CFG(l3cfg));
    g_assert(tdata);
    g_assert(notify_data);
    g_assert(_NM_INT_NOT_NEGATIVE(notify_data->notify_type));
    g_assert(notify_data->notify_type < _NM_L3_CONFIG_NOTIFY_TYPE_NUM);

    if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_IPV4LL_EVENT) {
        g_assert(tdata->l3ipv4ll == notify_data->ipv4ll_event.ipv4ll);
        g_assert(NM_IN_SET(tdata->ready_seen, 0, 1));
        g_assert(NM_IN_SET(tdata->addr_commit, 0, 1));

        if (nm_l3_ipv4ll_get_state(tdata->l3ipv4ll) == NM_L3_IPV4LL_STATE_READY) {
            g_assert_cmpint(tdata->ready_seen, ==, 0);
            g_assert_cmpint(tdata->addr_commit, ==, 0);
            tdata->ready_seen++;

            if (tdata->f->test_idx == 2 && nmtst_get_rand_bool()) {
                tdata->addr_commit++;
                tdata->addr_commit_addr = nm_l3_ipv4ll_get_addr(tdata->l3ipv4ll);
                g_assert(nm_ip4_addr_is_link_local(tdata->addr_commit_addr));
                _LOGT("add address %s that passed ACD",
                      nm_inet4_ntop(tdata->addr_commit_addr, sbuf_addr));
                if (!nm_l3cfg_add_config(nm_l3_ipv4ll_get_l3cfg(tdata->l3ipv4ll),
                                         TEST_L3_IPV4LL_TAG(tdata, 1),
                                         nmtst_get_rand_bool(),
                                         nm_l3_ipv4ll_get_l3cd(tdata->l3ipv4ll),
                                         NM_L3CFG_CONFIG_PRIORITY_IPV4LL,
                                         0,
                                         0,
                                         104,
                                         105,
                                         0,
                                         0,
                                         NM_DNS_PRIORITY_DEFAULT_NORMAL,
                                         NM_DNS_PRIORITY_DEFAULT_NORMAL,
                                         NM_L3_ACD_DEFEND_TYPE_ONCE,
                                         nmtst_get_rand_bool() ? tdata->acd_timeout_msec : 0u,
                                         NM_L3CFG_CONFIG_FLAGS_NONE,
                                         NM_L3_CONFIG_MERGE_FLAGS_NONE))
                    g_assert_not_reached();
                nm_l3cfg_commit_on_idle_schedule(nm_l3_ipv4ll_get_l3cfg(tdata->l3ipv4ll),
                                                 NM_L3_CFG_COMMIT_TYPE_AUTO);

                tdata->l3cfg_commit_type_1 =
                    nm_l3cfg_commit_type_register(nm_l3_ipv4ll_get_l3cfg(tdata->l3ipv4ll),
                                                  NM_L3_CFG_COMMIT_TYPE_UPDATE,
                                                  tdata->l3cfg_commit_type_1,
                                                  "test");
            }
        } else if (nm_l3_ipv4ll_get_state(tdata->l3ipv4ll) != NM_L3_IPV4LL_STATE_DEFENDING
                   && tdata->ready_seen > 0) {
            g_assert_cmpint(tdata->ready_seen, ==, 1);
            tdata->ready_seen--;
            if (tdata->addr_commit > 0) {
                g_assert_cmpint(tdata->addr_commit, ==, 1);
                tdata->addr_commit--;
                g_assert(nm_ip4_addr_is_link_local(tdata->addr_commit_addr));
                _LOGT("remove address %s that previously passed ACD",
                      nm_inet4_ntop(tdata->addr_commit_addr, sbuf_addr));
                if (!nm_l3cfg_remove_config_all(nm_l3_ipv4ll_get_l3cfg(tdata->l3ipv4ll),
                                                TEST_L3_IPV4LL_TAG(tdata, 1)))
                    g_assert_not_reached();
                nm_l3cfg_commit_on_idle_schedule(nm_l3_ipv4ll_get_l3cfg(tdata->l3ipv4ll),
                                                 NM_L3_CFG_COMMIT_TYPE_AUTO);
                nm_l3cfg_commit_type_unregister(nm_l3_ipv4ll_get_l3cfg(tdata->l3ipv4ll),
                                                g_steal_pointer(&tdata->l3cfg_commit_type_1));
            }
        }
        return;
    }
}

static void
test_l3_ipv4ll(gconstpointer test_data)
{
    const int                                      TEST_IDX     = GPOINTER_TO_INT(test_data);
    nm_auto(_test_fixture_1_teardown) TestFixture1 test_fixture = {};
    const TestFixture1                            *f;
    gs_unref_object NML3Cfg                       *l3cfg0      = NULL;
    TestL3IPv4LLData                               tdata_stack = {
                                      .f = NULL,
    };
    TestL3IPv4LLData *const                                      tdata          = &tdata_stack;
    NMTstpAcdDefender                                           *acd_defender_1 = NULL;
    NMTstpAcdDefender                                           *acd_defender_2 = NULL;
    nm_auto_unref_l3ipv4ll NML3IPv4LL                           *l3ipv4ll       = NULL;
    gint64                                                       start_time_msec;
    gint64                                                       total_poll_time_msec;
    nm_auto_remove_l3ipv4ll_registration NML3IPv4LLRegistration *l3ipv4ll_reg = NULL;
    char                                                         sbuf_addr[NM_INET_ADDRSTRLEN];

    _LOGD("test start (/l3-ipv4ll/%d)", TEST_IDX);

    if (nmtst_test_quick()) {
        gs_free char *msg =
            g_strdup_printf("Skipping test: don't run long running test %s (NMTST_DEBUG=slow)\n",
                            g_get_prgname() ?: "test-l3-ipv4ll");

        g_test_skip(msg);
        return;
    }

    f = _test_fixture_1_setup(&test_fixture, TEST_IDX);

    tdata->f = f;

    if (tdata->f->test_idx == 1)
        tdata->acd_timeout_msec = 0;
    else
        tdata->acd_timeout_msec = L3IPV4LL_ACD_TIMEOUT_MSEC;

    _test_l3_ipv4ll_maybe_add_addr_4(tdata, 0, 4, &tdata->has_addr4_101, "192.168.133.101");

    l3cfg0 = _netns_access_l3cfg(f->netns, f->ifindex0);

    g_signal_connect(l3cfg0,
                     NM_L3CFG_SIGNAL_NOTIFY,
                     G_CALLBACK(_test_l3_ipv4ll_signal_notify),
                     tdata);

    l3ipv4ll = nm_l3_ipv4ll_new(l3cfg0);

    tdata->l3ipv4ll = l3ipv4ll;

    g_assert_cmpint(nm_l3_ipv4ll_get_ifindex(l3ipv4ll), ==, f->ifindex0);
    g_assert_cmpint(nm_l3_ipv4ll_get_state(l3ipv4ll), ==, NM_L3_IPV4LL_STATE_DISABLED);
    g_assert_cmpint(nm_l3_ipv4ll_get_addr(l3ipv4ll), ==, 0u);

    if (tdata->f->test_idx == 1) {
        if (nmtst_get_rand_one_case_in(2))
            l3ipv4ll_reg = nm_l3_ipv4ll_register_new(l3ipv4ll, tdata->acd_timeout_msec);
    } else
        l3ipv4ll_reg = nm_l3_ipv4ll_register_new(l3ipv4ll, tdata->acd_timeout_msec);

    g_assert(tdata->acd_timeout_msec == 0 || l3ipv4ll_reg);
    g_assert(!l3ipv4ll_reg || l3ipv4ll == nm_l3_ipv4ll_register_get_instance(l3ipv4ll_reg));

    if (tdata->acd_timeout_msec == 0) {
        g_assert_cmpint(nm_l3_ipv4ll_get_state(l3ipv4ll), ==, NM_L3_IPV4LL_STATE_DISABLED);
        g_assert_cmpint(nm_l3_ipv4ll_get_addr(l3ipv4ll), ==, 0u);
    } else {
        g_assert_cmpint(nm_l3_ipv4ll_get_state(l3ipv4ll), ==, NM_L3_IPV4LL_STATE_PROBING);
        if (f->test_idx == 1) {
            g_assert_cmpint(nm_l3_ipv4ll_get_addr(l3ipv4ll),
                            ==,
                            nmtst_inet4_from_string("169.254.30.158"));
        } else {
            g_assert_cmpint(nm_l3_ipv4ll_get_addr(l3ipv4ll),
                            ==,
                            nmtst_inet4_from_string("169.254.17.45"));
        }
        g_assert(nm_l3_ipv4ll_get_l3cd(l3ipv4ll));
    }

    _test_l3_ipv4ll_maybe_add_addr_4(tdata, 0, 4, &tdata->has_addr4_101, "192.168.133.101");

    if (tdata->f->test_idx == 2 && nmtst_get_rand_one_case_in(3)) {
        in_addr_t a = nm_l3_ipv4ll_get_addr(l3ipv4ll);

        g_assert(nm_ip4_addr_is_link_local(a));
        _test_l3_ipv4ll_maybe_add_addr_4(tdata,
                                         tdata->f->ifindex1,
                                         2,
                                         &tdata->add_conflict_done,
                                         nm_inet4_ntop(a, sbuf_addr));
        g_assert_cmpint(tdata->f->hwaddr1.len, ==, sizeof(NMEtherAddr));
        acd_defender_2 =
            nmtstp_acd_defender_new(tdata->f->ifindex1, a, &tdata->f->hwaddr1.ether_addr);
    }

    start_time_msec = nm_utils_get_monotonic_timestamp_msec();
    total_poll_time_msec =
        (L3IPV4LL_ACD_TIMEOUT_MSEC * 3 / 2) + (nmtst_get_rand_uint32() % L3IPV4LL_ACD_TIMEOUT_MSEC);
    _LOGT("poll 1 start (wait %" G_GINT64_FORMAT " msec)", total_poll_time_msec);
    while (TRUE) {
        gint64 next_timeout_msec;

        next_timeout_msec =
            start_time_msec + total_poll_time_msec - nm_utils_get_monotonic_timestamp_msec();
        if (next_timeout_msec <= 0)
            break;

        next_timeout_msec = NM_MIN(next_timeout_msec, nmtst_get_rand_uint32() % 1000u);
        nmtst_main_context_iterate_until(NULL, next_timeout_msec, FALSE);
        _LOGT("poll 1 intermezzo");

        _test_l3_ipv4ll_maybe_add_addr_4(tdata,
                                         0,
                                         1 + total_poll_time_msec / 1000,
                                         &tdata->has_addr4_101,
                                         "192.168.133.101");

        if (tdata->addr_commit == 1 && !tdata->add_conflict_checked) {
            tdata->add_conflict_checked = TRUE;
            _test_l3_ipv4ll_maybe_add_addr_4(tdata,
                                             tdata->f->ifindex1,
                                             2,
                                             &tdata->add_conflict_done,
                                             nm_inet4_ntop(tdata->addr_commit_addr, sbuf_addr));
            if (tdata->add_conflict_done)
                total_poll_time_msec += L3IPV4LL_ACD_TIMEOUT_MSEC / 2;
            g_assert_cmpint(tdata->f->hwaddr1.len, ==, sizeof(NMEtherAddr));
            acd_defender_2 = nmtstp_acd_defender_new(tdata->f->ifindex1,
                                                     tdata->addr_commit_addr,
                                                     &tdata->f->hwaddr1.ether_addr);
        }
    }
    _LOGT("poll 1 end");

    if (tdata->addr_commit || nmtst_get_rand_bool()) {
        nm_l3cfg_remove_config_all(nm_l3_ipv4ll_get_l3cfg(l3ipv4ll), TEST_L3_IPV4LL_TAG(tdata, 1));
    }

    nmtstp_acd_defender_destroy(g_steal_pointer(&acd_defender_1));
    nmtstp_acd_defender_destroy(g_steal_pointer(&acd_defender_2));

    nm_l3cfg_commit_type_unregister(l3cfg0, g_steal_pointer(&tdata->l3cfg_commit_type_1));

    g_signal_handlers_disconnect_by_func(l3cfg0, G_CALLBACK(_test_l3_ipv4ll_signal_notify), tdata);
}

/*****************************************************************************/

#define _LLADDR_TEST1 "fe80::dd5a:8a44:48bc:3ad"
#define _LLADDR_TEST2 "fe80::878b:938e:46f9:4807"

typedef struct {
    const TestFixture1 *f;
    NML3Cfg            *l3cfg0;
    NML3IPv6LL         *l3ipv6ll;
    int                 step;
    int                 ipv6ll_callback_step;
    bool                steps_done : 1;
    const NMPObject    *lladdr0;
} TestL3IPv6LLData;

static const NMPlatformIP6Address *
_test_l3_ipv6ll_find_lladdr(TestL3IPv6LLData *tdata, int ifindex)
{
    const NMPlatformIP6Address *found = NULL;
    NMDedupMultiIter            iter;
    const NMPObject            *obj;
    NMPLookup                   lookup;

    g_assert(tdata);

    nmp_lookup_init_object_by_ifindex(&lookup, NMP_OBJECT_TYPE_IP6_ADDRESS, ifindex);
    nm_platform_iter_obj_for_each (&iter, tdata->f->platform, &lookup, &obj) {
        const NMPlatformIP6Address *a = NMP_OBJECT_CAST_IP6_ADDRESS(obj);

        if (!IN6_IS_ADDR_LINKLOCAL(&a->address))
            continue;

        if (!found)
            found = a;
        else
            g_assert_not_reached();
    }

    return found;
}

static const NMPObject *
_test_l3_ipv6ll_find_lladdr_wait(TestL3IPv6LLData *tdata, int ifindex)
{
    const NMPObject *obj = NULL;

    nmtst_main_context_iterate_until_assert(NULL, 3000, ({
                                                const NMPlatformIP6Address *a;

                                                a = _test_l3_ipv6ll_find_lladdr(tdata, ifindex);
                                                if (a
                                                    && !NM_FLAGS_HAS(a->n_ifa_flags,
                                                                     IFA_F_TENTATIVE))
                                                    obj = NMP_OBJECT_UP_CAST(a);
                                                obj;
                                            }));

    return obj;
}

static const NMPlatformIP6Address *
_test_l3_ipv6ll_find_inet6(TestL3IPv6LLData *tdata, const struct in6_addr *addr)
{
    const NMPlatformIP6Address *a;

    a = nmtstp_platform_ip6_address_find(nm_l3cfg_get_platform(tdata->l3cfg0),
                                         nmtst_get_rand_bool() ? 0 : tdata->f->ifindex0,
                                         addr);
    if (a) {
        g_assert_cmpint(a->ifindex, ==, tdata->f->ifindex0);
        g_assert_cmpmem(addr, sizeof(*addr), &a->address, sizeof(a->address));
    }

    g_assert(a
             == nm_platform_ip6_address_get(nm_l3cfg_get_platform(tdata->l3cfg0),
                                            tdata->f->ifindex0,
                                            addr));

    return a;
}

static void
_test_l3_ipv6ll_signal_notify(NML3Cfg                    *l3cfg,
                              const NML3ConfigNotifyData *notify_data,
                              TestL3IPv6LLData           *tdata)
{
    g_assert_cmpint(tdata->step, >=, 1);
    g_assert_cmpint(tdata->step, <=, 2);
}

static void
_test_l3_ipv6ll_callback_changed(NML3IPv6LL            *ipv6ll,
                                 NML3IPv6LLState        state,
                                 const struct in6_addr *lladdr,
                                 gpointer               user_data)
{
    TestL3IPv6LLData           *tdata = user_data;
    int                         step  = tdata->ipv6ll_callback_step++;
    const NMPlatformIP6Address *a1;

    g_assert_cmpint(tdata->step, ==, 1);
    g_assert(!tdata->steps_done);

    switch (step) {
    case 0:
        if (NM_IN_SET(tdata->f->test_idx, 1, 2, 4)) {
            g_assert_cmpint(state, ==, NM_L3_IPV6LL_STATE_DAD_IN_PROGRESS);
            g_assert_cmpstr(nmtst_inet6_to_string(lladdr), ==, _LLADDR_TEST1);
        } else if (NM_IN_SET(tdata->f->test_idx, 3)) {
            g_assert_cmpint(state, ==, NM_L3_IPV6LL_STATE_READY);
            g_assert(
                IN6_ARE_ADDR_EQUAL(lladdr, &NMP_OBJECT_CAST_IP6_ADDRESS(tdata->lladdr0)->address));
            tdata->steps_done = TRUE;
        } else
            g_assert_not_reached();
        break;
    case 1:
        if (NM_IN_SET(tdata->f->test_idx, 1, 2)) {
            g_assert_cmpint(state, ==, NM_L3_IPV6LL_STATE_READY);
            g_assert_cmpstr(nmtst_inet6_to_string(lladdr), ==, _LLADDR_TEST1);
            a1 = _test_l3_ipv6ll_find_inet6(tdata, lladdr);
            g_assert(a1);
            g_assert(!NM_FLAGS_HAS(a1->n_ifa_flags, IFA_F_TENTATIVE));
            tdata->steps_done = TRUE;
        } else if (NM_IN_SET(tdata->f->test_idx, 4)) {
            g_assert_cmpint(state, ==, NM_L3_IPV6LL_STATE_DAD_IN_PROGRESS);
            g_assert_cmpstr(nmtst_inet6_to_string(lladdr), ==, _LLADDR_TEST2);
        } else
            g_assert_not_reached();
        break;
    case 2:
        if (NM_IN_SET(tdata->f->test_idx, 4)) {
            g_assert_cmpint(state, ==, NM_L3_IPV6LL_STATE_READY);
            g_assert_cmpstr(nmtst_inet6_to_string(lladdr), ==, _LLADDR_TEST2);
            a1 = _test_l3_ipv6ll_find_inet6(tdata, lladdr);
            g_assert(a1);
            g_assert(!NM_FLAGS_HAS(a1->n_ifa_flags, IFA_F_TENTATIVE));
            tdata->steps_done = TRUE;
        } else
            g_assert_not_reached();
        break;
    default:
        g_assert_not_reached();
    }
}

static void
test_l3_ipv6ll(gconstpointer test_data)
{
    NMTST_UTILS_HOST_ID_CONTEXT("l3-ipv6ll");
    const int                                      TEST_IDX     = GPOINTER_TO_INT(test_data);
    nm_auto(_test_fixture_1_teardown) TestFixture1 test_fixture = {};
    gs_unref_object NML3Cfg                       *l3cfg0       = NULL;
    TestL3IPv6LLData                               tdata_stack  = {
                                       .step       = 0,
                                       .steps_done = FALSE,
    };
    TestL3IPv6LLData *const tdata = &tdata_stack;
    char                    sbuf1[NM_UTILS_TO_STRING_BUFFER_SIZE];
    int                     r;

    _LOGD("test start (/l3-ipv6ll/%d)", TEST_IDX);

    if (nmtst_test_quick()) {
        gs_free char *msg =
            g_strdup_printf("Skipping test: don't run long running test %s (NMTST_DEBUG=slow)\n",
                            g_get_prgname() ?: "test-l3-ipv6ll");

        g_test_skip(msg);
        return;
    }

    tdata->f = _test_fixture_1_setup(&test_fixture, TEST_IDX);

    if (NM_IN_SET(tdata->f->test_idx, 4)) {
        _LOGD("add conflicting IPv6LL on other interface...");
        r = nm_platform_link_change_flags(tdata->f->platform, tdata->f->ifindex1, IFF_UP, FALSE);
        g_assert_cmpint(r, >=, 0);

        r = nm_platform_link_set_inet6_addr_gen_mode(tdata->f->platform,
                                                     tdata->f->ifindex1,
                                                     NM_IN6_ADDR_GEN_MODE_NONE);
        g_assert_cmpint(r, >=, 0);

        r = nm_platform_link_change_flags(tdata->f->platform, tdata->f->ifindex1, IFF_UP, TRUE);
        g_assert_cmpint(r, >=, 0);

        nmtstp_ip6_address_add(tdata->f->platform,
                               -1,
                               tdata->f->ifindex1,
                               nmtst_inet6_from_string(_LLADDR_TEST1),
                               64,
                               in6addr_any,
                               NM_PLATFORM_LIFETIME_PERMANENT,
                               NM_PLATFORM_LIFETIME_PERMANENT,
                               0);

        _LOGD("wait for IPv6 LL address...");
        tdata->lladdr0 =
            nmp_object_ref(_test_l3_ipv6ll_find_lladdr_wait(tdata, tdata->f->ifindex1));
    } else if (NM_IN_SET(tdata->f->test_idx, 2, 3)) {
        _LOGD("wait for IPv6 LL address...");
        tdata->lladdr0 =
            nmp_object_ref(_test_l3_ipv6ll_find_lladdr_wait(tdata, tdata->f->ifindex0));
    }

    if (tdata->lladdr0) {
        _LOGD("got IPv6 LL address %s",
              nmp_object_to_string(tdata->lladdr0,
                                   NMP_OBJECT_TO_STRING_PUBLIC,
                                   sbuf1,
                                   sizeof(sbuf1)));
    }

    l3cfg0        = _netns_access_l3cfg(tdata->f->netns, tdata->f->ifindex0);
    tdata->l3cfg0 = l3cfg0;

    g_signal_connect(tdata->l3cfg0,
                     NM_L3CFG_SIGNAL_NOTIFY,
                     G_CALLBACK(_test_l3_ipv6ll_signal_notify),
                     tdata);

    tdata->l3ipv6ll = nm_l3_ipv6ll_new_stable_privacy(tdata->l3cfg0,
                                                      NM_IN_SET(tdata->f->test_idx, 3),
                                                      NM_UTILS_STABLE_TYPE_UUID,
                                                      tdata->f->ifname0,
                                                      "b6a5b934-c649-43dc-a524-3dfdb74f9419",
                                                      0,
                                                      _test_l3_ipv6ll_callback_changed,
                                                      tdata);

    g_assert(nm_l3_ipv6ll_get_l3cfg(tdata->l3ipv6ll) == tdata->l3cfg0);
    g_assert_cmpint(nm_l3_ipv6ll_get_ifindex(tdata->l3ipv6ll), ==, tdata->f->ifindex0);

    tdata->step = 1;
    nmtst_main_context_iterate_until_assert(NULL, 7000, tdata->steps_done);

    g_assert_cmpint(tdata->step, ==, 1);
    if (NM_IN_SET(tdata->f->test_idx, 3))
        g_assert_cmpint(tdata->ipv6ll_callback_step, ==, 1);
    else if (NM_IN_SET(tdata->f->test_idx, 4))
        g_assert_cmpint(tdata->ipv6ll_callback_step, ==, 3);
    else
        g_assert_cmpint(tdata->ipv6ll_callback_step, ==, 2);
    g_assert(tdata->steps_done);

    tdata->step = 2;
    nmtst_main_context_iterate_until(NULL, nmtst_get_rand_uint32() % 1000, FALSE);

    g_assert_cmpint(tdata->step, ==, 2);
    if (NM_IN_SET(tdata->f->test_idx, 3))
        g_assert_cmpint(tdata->ipv6ll_callback_step, ==, 1);
    else if (NM_IN_SET(tdata->f->test_idx, 4))
        g_assert_cmpint(tdata->ipv6ll_callback_step, ==, 3);
    else
        g_assert_cmpint(tdata->ipv6ll_callback_step, ==, 2);
    g_assert(tdata->steps_done);
    g_assert(tdata->steps_done);

    tdata->step       = 0;
    tdata->steps_done = FALSE;

    g_signal_handlers_disconnect_by_func(tdata->l3cfg0,
                                         G_CALLBACK(_test_l3_ipv6ll_signal_notify),
                                         tdata);

    nm_l3_ipv6ll_destroy(tdata->l3ipv6ll);

    nm_clear_nmp_object(&tdata->lladdr0);
}

/*****************************************************************************/

NMTstpSetupFunc const _nmtstp_setup_platform_func = nm_linux_platform_setup;

void
_nmtstp_init_tests(int *argc, char ***argv)
{
    nmtst_init_with_logging(argc, argv, "ERR", "ALL");
}

void
_nmtstp_setup_tests(void)
{
    g_test_add_data_func("/l3cfg/1", GINT_TO_POINTER(1), test_l3cfg);
    g_test_add_data_func("/l3cfg/2", GINT_TO_POINTER(2), test_l3cfg);
    g_test_add_data_func("/l3cfg/3", GINT_TO_POINTER(3), test_l3cfg);
    g_test_add_data_func("/l3cfg/4", GINT_TO_POINTER(4), test_l3cfg);
    g_test_add_data_func("/l3-ipv4ll/1", GINT_TO_POINTER(1), test_l3_ipv4ll);
    g_test_add_data_func("/l3-ipv4ll/2", GINT_TO_POINTER(2), test_l3_ipv4ll);
    g_test_add_data_func("/l3-ipv6ll/1", GINT_TO_POINTER(1), test_l3_ipv6ll);
    g_test_add_data_func("/l3-ipv6ll/2", GINT_TO_POINTER(2), test_l3_ipv6ll);
    g_test_add_data_func("/l3-ipv6ll/3", GINT_TO_POINTER(3), test_l3_ipv6ll);
    g_test_add_data_func("/l3-ipv6ll/4", GINT_TO_POINTER(4), test_l3_ipv6ll);
}
