/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "src/core/nm-default-daemon.h"

#include <linux/pkt_sched.h>

#include "nm-test-utils-core.h"
#include "platform/nmp-object.h"
#include "nm-platform/nmp-netns.h"
#include "nm-platform/nm-platform-utils.h"
#include "test-common.h"

static NMPObject *
qdisc_new(int ifindex, const char *kind, guint32 parent)
{
    NMPObject *obj;

    obj        = nmp_object_new(NMP_OBJECT_TYPE_QDISC, NULL);
    obj->qdisc = (NMPlatformQdisc){
        .ifindex = ifindex,
        .kind    = kind,
        .parent  = parent,
    };

    return obj;
}

static GPtrArray *
qdiscs_lookup(int ifindex)
{
    NMPLookup lookup;

    return nm_platform_lookup_clone(NM_PLATFORM_GET,
                                    nmp_lookup_init_object(&lookup, NMP_OBJECT_TYPE_QDISC, ifindex),
                                    NULL,
                                    NULL);
}

static void
test_qdisc1(void)
{
    int               ifindex;
    gs_unref_ptrarray GPtrArray *known = NULL;
    gs_unref_ptrarray GPtrArray *plat  = NULL;
    NMPObject *                  obj;
    NMPlatformQdisc *            qdisc;

    ifindex = nm_platform_link_get_ifindex(NM_PLATFORM_GET, DEVICE_NAME);
    g_assert_cmpint(ifindex, >, 0);

    nmtstp_run_command("tc qdisc del dev %s root", DEVICE_NAME);
    nmtstp_run_command_check("tc qdisc add dev %s root sfq", DEVICE_NAME);

    nmtstp_wait_for_signal(NM_PLATFORM_GET, 0);

    known = g_ptr_array_new_with_free_func((GDestroyNotify) nmp_object_unref);
    g_ptr_array_add(known, qdisc_new(ifindex, "fq_codel", TC_H_ROOT));
    g_ptr_array_add(known, qdisc_new(ifindex, "ingress", TC_H_INGRESS));

    g_assert(nm_platform_qdisc_sync(NM_PLATFORM_GET, ifindex, known));
    plat = qdiscs_lookup(ifindex);
    g_assert(plat);
    g_assert_cmpint(plat->len, ==, 2);

    obj   = plat->pdata[0];
    qdisc = NMP_OBJECT_CAST_QDISC(obj);
    g_assert_cmpint(qdisc->parent, ==, TC_H_ROOT);
    g_assert_cmpstr(qdisc->kind, ==, "fq_codel");

    obj   = plat->pdata[1];
    qdisc = NMP_OBJECT_CAST_QDISC(obj);
    g_assert_cmpint(qdisc->parent, ==, TC_H_INGRESS);
    g_assert_cmpstr(qdisc->kind, ==, "ingress");
}

static void
test_qdisc_fq_codel(void)
{
    int               ifindex;
    gs_unref_ptrarray GPtrArray *known = NULL;
    gs_unref_ptrarray GPtrArray *plat  = NULL;
    NMPObject *                  obj;
    NMPlatformQdisc *            qdisc;

    ifindex = nm_platform_link_get_ifindex(NM_PLATFORM_GET, DEVICE_NAME);
    g_assert_cmpint(ifindex, >, 0);

    nmtstp_run_command("tc qdisc del dev %s root", DEVICE_NAME);

    nmtstp_wait_for_signal(NM_PLATFORM_GET, 0);

    known                       = g_ptr_array_new_with_free_func((GDestroyNotify) nmp_object_unref);
    obj                         = qdisc_new(ifindex, "fq_codel", TC_H_ROOT);
    obj->qdisc.handle           = TC_H_MAKE(0x8142 << 16, 0);
    obj->qdisc.fq_codel.limit   = 2048;
    obj->qdisc.fq_codel.flows   = 64;
    obj->qdisc.fq_codel.quantum = 1000;
    g_ptr_array_add(known, obj);

    g_assert(nm_platform_qdisc_sync(NM_PLATFORM_GET, ifindex, known));
    plat = qdiscs_lookup(ifindex);
    g_assert(plat);
    g_assert_cmpint(plat->len, ==, 1);

    obj   = plat->pdata[0];
    qdisc = NMP_OBJECT_CAST_QDISC(obj);
    g_assert_cmpstr(qdisc->kind, ==, "fq_codel");
    g_assert_cmpint(qdisc->handle, ==, TC_H_MAKE(0x8142 << 16, 0));
    g_assert_cmpint(qdisc->parent, ==, TC_H_ROOT);
    g_assert_cmpint(qdisc->fq_codel.limit, ==, 2048);
    g_assert_cmpint(qdisc->fq_codel.flows, ==, 64);
    g_assert_cmpint(qdisc->fq_codel.quantum, ==, 1000);
}

static void
test_qdisc_sfq(void)
{
    int               ifindex;
    gs_unref_ptrarray GPtrArray *known = NULL;
    gs_unref_ptrarray GPtrArray *plat  = NULL;
    NMPObject *                  obj;
    NMPlatformQdisc *            qdisc;

    ifindex = nm_platform_link_get_ifindex(NM_PLATFORM_GET, DEVICE_NAME);
    g_assert_cmpint(ifindex, >, 0);

    nmtstp_run_command("tc qdisc del dev %s root", DEVICE_NAME);

    nmtstp_wait_for_signal(NM_PLATFORM_GET, 0);

    known             = g_ptr_array_new_with_free_func((GDestroyNotify) nmp_object_unref);
    obj               = qdisc_new(ifindex, "sfq", TC_H_ROOT);
    obj->qdisc.handle = TC_H_MAKE(0x8143 << 16, 0);
    obj->qdisc.sfq.perturb_period = 10;
    obj->qdisc.sfq.quantum        = 1540;
    obj->qdisc.sfq.flows          = 256;
    g_ptr_array_add(known, obj);

    g_assert(nm_platform_qdisc_sync(NM_PLATFORM_GET, ifindex, known));
    plat = qdiscs_lookup(ifindex);
    g_assert(plat);
    g_assert_cmpint(plat->len, ==, 1);

    obj   = plat->pdata[0];
    qdisc = NMP_OBJECT_CAST_QDISC(obj);
    g_assert_cmpstr(qdisc->kind, ==, "sfq");
    g_assert_cmpint(qdisc->handle, ==, TC_H_MAKE(0x8143 << 16, 0));
    g_assert_cmpint(qdisc->parent, ==, TC_H_ROOT);
    g_assert_cmpint(qdisc->sfq.perturb_period, ==, 10);
    g_assert_cmpint(qdisc->sfq.quantum, ==, 1540);
    g_assert_cmpint(qdisc->sfq.flows, ==, 256);
}

static void
test_qdisc_tbf(void)
{
    int               ifindex;
    gs_unref_ptrarray GPtrArray *known = NULL;
    gs_unref_ptrarray GPtrArray *plat  = NULL;
    NMPObject *                  obj;
    NMPlatformQdisc *            qdisc;

    ifindex = nm_platform_link_get_ifindex(NM_PLATFORM_GET, DEVICE_NAME);
    g_assert_cmpint(ifindex, >, 0);

    nmtstp_run_command("tc qdisc del dev %s root", DEVICE_NAME);

    nmtstp_wait_for_signal(NM_PLATFORM_GET, 0);

    known                = g_ptr_array_new_with_free_func((GDestroyNotify) nmp_object_unref);
    obj                  = qdisc_new(ifindex, "tbf", TC_H_ROOT);
    obj->qdisc.handle    = TC_H_MAKE(0x8143 << 16, 0);
    obj->qdisc.tbf.rate  = 1000000;
    obj->qdisc.tbf.burst = 2000;
    obj->qdisc.tbf.limit = 3000;
    g_ptr_array_add(known, obj);

    obj               = qdisc_new(ifindex, "sfq", TC_H_MAKE(0x8143 << 16, 0));
    obj->qdisc.handle = TC_H_MAKE(0x8005 << 16, 0);
    g_ptr_array_add(known, obj);

    g_assert(nm_platform_qdisc_sync(NM_PLATFORM_GET, ifindex, known));
    plat = qdiscs_lookup(ifindex);
    g_assert(plat);
    g_assert_cmpint(plat->len, ==, 2);

    obj   = plat->pdata[0];
    qdisc = NMP_OBJECT_CAST_QDISC(obj);
    g_assert_cmpstr(qdisc->kind, ==, "tbf");
    g_assert_cmpint(qdisc->handle, ==, TC_H_MAKE(0x8143 << 16, 0));
    g_assert_cmpint(qdisc->parent, ==, TC_H_ROOT);
    g_assert_cmpint(qdisc->tbf.rate, ==, 1000000);
    g_assert_cmpint(qdisc->tbf.burst, ==, 2000);
    g_assert_cmpint(qdisc->tbf.limit, ==, 3000);

    obj   = plat->pdata[1];
    qdisc = NMP_OBJECT_CAST_QDISC(obj);
    g_assert_cmpstr(qdisc->kind, ==, "sfq");
    g_assert_cmpint(qdisc->parent, ==, TC_H_MAKE(0x8143 << 16, 0));
    g_assert_cmpint(qdisc->handle, ==, TC_H_MAKE(0x8005 << 16, 0));
}

/*****************************************************************************/

NMTstpSetupFunc const _nmtstp_setup_platform_func = SETUP;

void
_nmtstp_init_tests(int *argc, char ***argv)
{
    nmtst_init_with_logging(argc, argv, NULL, "ALL");
}

void
_nmtstp_setup_tests(void)
{
    if (nmtstp_is_root_test()) {
        nmtstp_env1_add_test_func("/link/qdisc/1", test_qdisc1, TRUE);
        nmtstp_env1_add_test_func("/link/qdisc/fq_codel", test_qdisc_fq_codel, TRUE);
        nmtstp_env1_add_test_func("/link/qdisc/sfq", test_qdisc_sfq, TRUE);
        nmtstp_env1_add_test_func("/link/qdisc/tbf", test_qdisc_tbf, TRUE);
    }
}
