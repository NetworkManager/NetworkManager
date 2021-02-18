/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include <net/if.h>
#include <byteswap.h>

/* need math.h for isinf() and INFINITY. No need to link with -lm */
#include <math.h>

#include "NetworkManagerUtils.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "nm-core-utils.h"
#include "systemd/nm-sd-utils-core.h"

#include "dns/nm-dns-manager.h"
#include "nm-connectivity.h"

#include "nm-test-utils-core.h"

/* Reference implementation for nm_utils_ip6_address_clear_host_address.
 * Taken originally from set_address_masked(), src/ndisc/nm-lndp-ndisc.c
 **/
static void
ip6_address_clear_host_address_reference(struct in6_addr *dst, struct in6_addr *src, guint8 plen)
{
    guint nbytes = plen / 8;
    guint nbits  = plen % 8;

    g_return_if_fail(plen <= 128);
    g_assert(src);
    g_assert(dst);

    if (plen >= 128)
        *dst = *src;
    else {
        memset(dst, 0, sizeof(*dst));
        memcpy(dst, src, nbytes);
        dst->s6_addr[nbytes] = (src->s6_addr[nbytes] & (0xFF << (8 - nbits)));
    }
}

static void
_randomize_in6_addr(struct in6_addr *addr, GRand *r)
{
    int i;

    for (i = 0; i < 4; i++)
        ((guint32 *) addr)[i] = g_rand_int(r);
}

static void
test_nm_utils_ip6_address_clear_host_address(void)
{
    GRand *r = g_rand_new();
    int    plen, i;

    g_rand_set_seed(r, 0);

    for (plen = 0; plen <= 128; plen++) {
        for (i = 0; i < 50; i++) {
            struct in6_addr addr_src, addr_ref;
            struct in6_addr addr1, addr2;

            _randomize_in6_addr(&addr_src, r);
            _randomize_in6_addr(&addr_ref, r);
            _randomize_in6_addr(&addr1, r);
            _randomize_in6_addr(&addr2, r);

            addr1 = addr_src;
            ip6_address_clear_host_address_reference(&addr_ref, &addr1, plen);

            _randomize_in6_addr(&addr1, r);
            _randomize_in6_addr(&addr2, r);
            addr1 = addr_src;
            nm_utils_ip6_address_clear_host_address(&addr2, &addr1, plen);
            g_assert_cmpint(memcmp(&addr1, &addr_src, sizeof(struct in6_addr)), ==, 0);
            g_assert_cmpint(memcmp(&addr2, &addr_ref, sizeof(struct in6_addr)), ==, 0);

            /* test for self assignment/inplace update. */
            _randomize_in6_addr(&addr1, r);
            addr1 = addr_src;
            nm_utils_ip6_address_clear_host_address(&addr1, &addr1, plen);
            g_assert_cmpint(memcmp(&addr1, &addr_ref, sizeof(struct in6_addr)), ==, 0);
        }
    }

    g_rand_free(r);
}

/*****************************************************************************/

static void
test_logging_domains(void)
{
    const char *s;

    s = nm_logging_all_domains_to_string();
    g_assert(s && s[0]);
}

/*****************************************************************************/

static void
test_logging_error(void)
{
    gs_free_error GError *error = NULL;
    gboolean              success;

    g_assert_cmpint(NM_MANAGER_ERROR, ==, _NM_MANAGER_ERROR);
    G_STATIC_ASSERT_EXPR(NM_MANAGER_ERROR_UNKNOWN_LOG_LEVEL == _NM_MANAGER_ERROR_UNKNOWN_LOG_LEVEL);
    G_STATIC_ASSERT_EXPR(NM_MANAGER_ERROR_UNKNOWN_LOG_DOMAIN
                         == _NM_MANAGER_ERROR_UNKNOWN_LOG_DOMAIN);

    success = nm_logging_setup("bogus", "ALL", NULL, &error);
    nmtst_assert_no_success(success, error);
    g_assert_cmpint(error->domain, ==, NM_MANAGER_ERROR);
    g_assert_cmpint(error->code, ==, NM_MANAGER_ERROR_UNKNOWN_LOG_LEVEL);
    nm_clear_pointer(&error, g_error_free);

    success = nm_logging_setup("debug", "bogus", NULL, &error);
    nmtst_assert_no_success(success, error);
    g_assert_cmpint(error->domain, ==, NM_MANAGER_ERROR);
    g_assert_cmpint(error->code, ==, NM_MANAGER_ERROR_UNKNOWN_LOG_DOMAIN);
    nm_clear_pointer(&error, g_error_free);
}

/*****************************************************************************/

static void
_test_same_prefix(const char *a1, const char *a2, guint8 plen)
{
    struct in6_addr a = *nmtst_inet6_from_string(a1);
    struct in6_addr b = *nmtst_inet6_from_string(a2);

    g_assert(nm_utils_ip6_address_same_prefix(&a, &b, plen));
}

static void
test_nm_utils_ip6_address_same_prefix(void)
{
    guint       n, i;
    const guint N = 100;
    union {
        guint8          ptr[sizeof(struct in6_addr)];
        struct in6_addr val;
    } a, b, addrmask, addrmask_bit;
    guint8 plen;

    /* test#1 */
    for (n = 0; n < N; n++) {
        gboolean is_same = n < N / 2;
        gboolean result;

        nmtst_rand_buf(NULL, a.ptr, sizeof(a));
        nmtst_rand_buf(NULL, b.ptr, sizeof(b));
again_plen:
        plen = nmtst_get_rand_uint32() % 129;
        if (!is_same && NM_IN_SET(plen, 0, 128))
            goto again_plen;

        if (plen < 128) {
            for (i = 0; (i + 1) * 8 <= plen; i++)
                b.ptr[i] = a.ptr[i];
            if (plen % 8) {
                guint8 mask;

                g_assert(i < sizeof(a));
                mask     = ~((1 << (8 - (plen % 8))) - 1);
                b.ptr[i] = (a.ptr[i] & mask) | (b.ptr[i] & ~mask);
                if (!is_same) {
                    mask     = (1 << (8 - (plen % 8)));
                    b.ptr[i] = (b.ptr[i] & ~mask) | ~(b.ptr[i] & mask);
                }
            } else if (!is_same) {
                g_assert(i > 0);

                b.ptr[i - 1] = (b.ptr[i - 1] & ~0x1) | ~(b.ptr[i - 1] & 0x1);
            }
        } else
            b = a;

        result = nm_utils_ip6_address_same_prefix(&a.val, &b.val, plen);
        g_assert(result == is_same);
        g_assert(NM_IN_SET(result, TRUE, FALSE));
    }

    /* test#2 */
    for (n = 0; n < N; n++) {
        nmtst_rand_buf(NULL, a.ptr, sizeof(a));
        nmtst_rand_buf(NULL, b.ptr, sizeof(b));
        plen = nmtst_get_rand_uint32() % 129;

        memset(addrmask.ptr, 0xFF, sizeof(addrmask));
        nm_utils_ip6_address_clear_host_address(&addrmask.val, &addrmask.val, plen);

        for (i = 0; i < sizeof(a); i++)
            b.ptr[i] = (a.ptr[i] & addrmask.ptr[i]) | (b.ptr[i] & ~addrmask.ptr[i]);

        g_assert(nm_utils_ip6_address_same_prefix(&a.val, &b.val, plen) == TRUE);
    }

    /* test#3 */
    for (n = 0; n < N; n++) {
        gboolean reached = FALSE;

        nmtst_rand_buf(NULL, a.ptr, sizeof(a));
        nmtst_rand_buf(NULL, b.ptr, sizeof(b));
        plen = nmtst_get_rand_uint32() % 129;

        if (!plen)
            continue;

        memset(addrmask.ptr, 0xFF, sizeof(addrmask));
        nm_utils_ip6_address_clear_host_address(&addrmask.val, &addrmask.val, plen);

        memset(addrmask_bit.ptr, 0xFF, sizeof(addrmask_bit));
        nm_utils_ip6_address_clear_host_address(&addrmask_bit.val, &addrmask_bit.val, plen - 1);

        for (i = 0; i < sizeof(a); i++)
            b.ptr[i] = (a.ptr[i] & addrmask.ptr[i]) | (b.ptr[i] & ~addrmask.ptr[i]);

        /* flip the last bit. */
        for (i = 0; i < sizeof(a); i++) {
            guint8 mask = addrmask.ptr[i] ^ addrmask_bit.ptr[i];
            if (mask) {
                g_assert(!reached);
                g_assert(nm_utils_is_power_of_two(mask));
                reached  = TRUE;
                b.ptr[i] = (b.ptr[i] & ~mask) | ~(b.ptr[i] & mask);
            }
        }
        g_assert(reached);

        g_assert(nm_utils_ip6_address_same_prefix(&a.val, &b.val, plen) == FALSE);
    }

    /* test#4 */
    _test_same_prefix("::", "::1", 10);
    _test_same_prefix("abcd::", "abcd::1", 10);
}

/*****************************************************************************/

static void
test_nm_utils_log_connection_diff(void)
{
    NMConnection *connection;
    NMConnection *connection2;

    /* if logging is disabled (the default), nm_utils_log_connection_diff() returns
     * early without doing anything. Hence, in the normal testing, this test does nothing.
     * It only gets interesting, when run verbosely with NMTST_DEBUG=debug ... */

    nm_log(LOGL_DEBUG, LOGD_CORE, NULL, NULL, "START TEST test_nm_utils_log_connection_diff...");

    connection = nm_simple_connection_new();
    nm_connection_add_setting(connection, nm_setting_connection_new());
    nm_utils_log_connection_diff(connection, NULL, LOGL_DEBUG, LOGD_CORE, "test1", ">>> ", NULL);

    nm_connection_add_setting(connection, nm_setting_wired_new());
    nm_utils_log_connection_diff(connection, NULL, LOGL_DEBUG, LOGD_CORE, "test2", ">>> ", NULL);

    connection2 = nm_simple_connection_new_clone(connection);
    nm_utils_log_connection_diff(connection,
                                 connection2,
                                 LOGL_DEBUG,
                                 LOGD_CORE,
                                 "test3",
                                 ">>> ",
                                 NULL);

    g_object_set(nm_connection_get_setting_connection(connection),
                 NM_SETTING_CONNECTION_ID,
                 "id",
                 NM_SETTING_CONNECTION_UUID,
                 "uuid",
                 NULL);
    g_object_set(nm_connection_get_setting_connection(connection2),
                 NM_SETTING_CONNECTION_ID,
                 "id2",
                 NM_SETTING_CONNECTION_MASTER,
                 "master2",
                 NULL);
    nm_utils_log_connection_diff(connection,
                                 connection2,
                                 LOGL_DEBUG,
                                 LOGD_CORE,
                                 "test4",
                                 ">>> ",
                                 NULL);

    nm_connection_add_setting(connection, nm_setting_802_1x_new());
    nm_utils_log_connection_diff(connection,
                                 connection2,
                                 LOGL_DEBUG,
                                 LOGD_CORE,
                                 "test5",
                                 ">>> ",
                                 NULL);

    g_object_set(nm_connection_get_setting_802_1x(connection),
                 NM_SETTING_802_1X_PASSWORD,
                 "id2",
                 NM_SETTING_802_1X_PASSWORD_FLAGS,
                 NM_SETTING_SECRET_FLAG_NOT_SAVED,
                 NULL);
    nm_utils_log_connection_diff(connection, NULL, LOGL_DEBUG, LOGD_CORE, "test6", ">>> ", NULL);
    nm_utils_log_connection_diff(connection,
                                 connection2,
                                 LOGL_DEBUG,
                                 LOGD_CORE,
                                 "test7",
                                 ">>> ",
                                 NULL);
    nm_utils_log_connection_diff(connection2,
                                 connection,
                                 LOGL_DEBUG,
                                 LOGD_CORE,
                                 "test8",
                                 ">>> ",
                                 NULL);

    g_clear_object(&connection);
    g_clear_object(&connection2);

    connection =
        nmtst_create_minimal_connection("id-vpn-1", NULL, NM_SETTING_VPN_SETTING_NAME, NULL);
    nm_utils_log_connection_diff(connection,
                                 NULL,
                                 LOGL_DEBUG,
                                 LOGD_CORE,
                                 "test-vpn-1",
                                 ">>> ",
                                 NULL);

    g_clear_object(&connection);
}

/*****************************************************************************/

static void
do_test_sysctl_ip_conf(int addr_family, const char *iface, const char *property)
{
    char        path[NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE];
    const char *pp;

    pp = nm_utils_sysctl_ip_conf_path(addr_family, path, iface, property);
    g_assert(pp == path);
    g_assert(path[0] == '/');

    g_assert(nm_utils_sysctl_ip_conf_is_path(addr_family, path, iface, property));
    g_assert(nm_utils_sysctl_ip_conf_is_path(addr_family, path, NULL, property));
}

static void
test_nm_utils_sysctl_ip_conf_path(void)
{
    do_test_sysctl_ip_conf(AF_INET6, "a", "mtu");
    do_test_sysctl_ip_conf(AF_INET6, "eth0", "mtu");
    do_test_sysctl_ip_conf(AF_INET6, "e23456789012345", "mtu");
}

/*****************************************************************************/

static NMConnection *
_match_connection_new(void)
{
    NMConnection *       connection;
    NMSettingConnection *s_con;
    NMSettingWired *     s_wired;
    NMSettingIPConfig *  s_ip4, *s_ip6;
    char *               uuid;

    connection = nm_simple_connection_new();

    s_con = (NMSettingConnection *) nm_setting_connection_new();
    nm_connection_add_setting(connection, (NMSetting *) s_con);
    uuid = nm_utils_uuid_generate();
    g_object_set(G_OBJECT(s_con),
                 NM_SETTING_CONNECTION_ID,
                 "blahblah",
                 NM_SETTING_CONNECTION_UUID,
                 uuid,
                 NM_SETTING_CONNECTION_TYPE,
                 NM_SETTING_WIRED_SETTING_NAME,
                 NM_SETTING_CONNECTION_AUTOCONNECT,
                 FALSE,
                 NULL);
    g_free(uuid);

    s_wired = (NMSettingWired *) nm_setting_wired_new();
    nm_connection_add_setting(connection, (NMSetting *) s_wired);

    s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new();
    nm_connection_add_setting(connection, (NMSetting *) s_ip4);
    g_object_set(G_OBJECT(s_ip4),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_AUTO,
                 NULL);

    s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new();
    nm_connection_add_setting(connection, (NMSetting *) s_ip6);
    g_object_set(G_OBJECT(s_ip6),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP6_CONFIG_METHOD_AUTO,
                 NULL);

    return connection;
}

static NMConnection *
_match_connection(GSList *      connections,
                  NMConnection *original,
                  gboolean      device_has_carrier,
                  gint64        default_v4_metric,
                  gint64        default_v6_metric)
{
    gs_free NMConnection **list = NULL;
    guint                  i, len;

    len = g_slist_length(connections);
    g_assert(len < 10);

    list = g_malloc((len + 1) * sizeof(NMConnection *));
    for (i = 0; i < len; i++, connections = connections->next) {
        g_assert(connections);
        g_assert(connections->data);
        list[i] = connections->data;
    }
    list[i] = NULL;

    return nm_utils_match_connection(list,
                                     original,
                                     FALSE,
                                     device_has_carrier,
                                     default_v4_metric,
                                     default_v6_metric,
                                     NULL,
                                     NULL);
}

static void
test_connection_match_basic(void)
{
    NMConnection *     orig, *copy, *matched;
    GSList *           connections = NULL;
    NMSettingIPConfig *s_ip4;

    orig        = _match_connection_new();
    copy        = nm_simple_connection_new_clone(orig);
    connections = g_slist_append(connections, copy);

    matched = _match_connection(connections, orig, TRUE, 0, 0);
    g_assert(matched == copy);

    /* Now change a material property like IPv4 method and ensure matching fails */
    s_ip4 = nm_connection_get_setting_ip4_config(orig);
    g_assert(s_ip4);
    g_object_set(G_OBJECT(s_ip4),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL,
                 NULL);
    matched = _match_connection(connections, orig, TRUE, 0, 0);
    g_assert(matched == NULL);

    g_slist_free(connections);
    g_object_unref(orig);
    g_object_unref(copy);
}

static void
test_connection_match_ip6_method(void)
{
    NMConnection *     orig, *copy, *matched;
    GSList *           connections = NULL;
    NMSettingIPConfig *s_ip6;

    orig        = _match_connection_new();
    copy        = nm_simple_connection_new_clone(orig);
    connections = g_slist_append(connections, copy);

    /* Check that if the generated connection is IPv6 method=link-local, and the
     * candidate is both method=auto and may-faily=true, that the candidate is
     * matched.
     */
    s_ip6 = nm_connection_get_setting_ip6_config(orig);
    g_assert(s_ip6);
    g_object_set(G_OBJECT(s_ip6),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
                 NULL);

    s_ip6 = nm_connection_get_setting_ip6_config(copy);
    g_assert(s_ip6);
    g_object_set(G_OBJECT(s_ip6),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP6_CONFIG_METHOD_AUTO,
                 NM_SETTING_IP_CONFIG_MAY_FAIL,
                 TRUE,
                 NULL);

    matched = _match_connection(connections, orig, TRUE, 0, 0);
    g_assert(matched == copy);

    g_slist_free(connections);
    g_object_unref(orig);
    g_object_unref(copy);
}

static void
test_connection_match_ip6_method_ignore(void)
{
    NMConnection *     orig, *copy, *matched;
    GSList *           connections = NULL;
    NMSettingIPConfig *s_ip6;

    orig        = _match_connection_new();
    copy        = nm_simple_connection_new_clone(orig);
    connections = g_slist_append(connections, copy);

    /* Check that if the generated connection is IPv6 method=link-local, and the
     * candidate is method=ignore, that the candidate is matched.
     */
    s_ip6 = nm_connection_get_setting_ip6_config(orig);
    g_assert(s_ip6);
    g_object_set(G_OBJECT(s_ip6),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
                 NULL);

    s_ip6 = nm_connection_get_setting_ip6_config(copy);
    g_assert(s_ip6);
    g_object_set(G_OBJECT(s_ip6),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
                 NULL);

    matched = _match_connection(connections, orig, TRUE, 0, 0);
    g_assert(matched == copy);

    g_slist_free(connections);
    g_object_unref(orig);
    g_object_unref(copy);
}

static void
test_connection_match_ip6_method_ignore_auto(void)
{
    NMConnection *     orig, *copy, *matched;
    GSList *           connections = NULL;
    NMSettingIPConfig *s_ip6;

    orig        = _match_connection_new();
    copy        = nm_simple_connection_new_clone(orig);
    connections = g_slist_append(connections, copy);

    /* Check that if the generated connection is IPv6 method=auto, and the
     * candidate is method=ignore, that the candidate is matched.
     */
    s_ip6 = nm_connection_get_setting_ip6_config(orig);
    g_assert(s_ip6);
    g_object_set(G_OBJECT(s_ip6),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP6_CONFIG_METHOD_AUTO,
                 NULL);

    s_ip6 = nm_connection_get_setting_ip6_config(copy);
    g_assert(s_ip6);
    g_object_set(G_OBJECT(s_ip6),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
                 NULL);

    matched = _match_connection(connections, orig, TRUE, 0, 0);
    g_assert(matched == copy);

    g_slist_free(connections);
    g_object_unref(orig);
    g_object_unref(copy);
}

static void
test_connection_match_ip4_method(void)
{
    NMConnection *     orig, *copy, *matched;
    GSList *           connections = NULL;
    NMSettingIPConfig *s_ip4;

    orig        = _match_connection_new();
    copy        = nm_simple_connection_new_clone(orig);
    connections = g_slist_append(connections, copy);

    /* Check that if the generated connection is IPv4 method=disabled, and the
     * candidate is both method=auto and may-faily=true, and the device has no
     * carrier that the candidate is matched.
     */
    s_ip4 = nm_connection_get_setting_ip4_config(orig);
    g_assert(s_ip4);
    g_object_set(G_OBJECT(s_ip4),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
                 NULL);

    s_ip4 = nm_connection_get_setting_ip4_config(copy);
    g_assert(s_ip4);
    g_object_set(G_OBJECT(s_ip4),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_AUTO,
                 NM_SETTING_IP_CONFIG_MAY_FAIL,
                 TRUE,
                 NULL);

    matched = _match_connection(connections, orig, FALSE, 0, 0);
    g_assert(matched == copy);

    /* Ensure when carrier=true matching fails */
    matched = _match_connection(connections, orig, TRUE, 0, 0);
    g_assert(matched == NULL);

    g_slist_free(connections);
    g_object_unref(orig);
    g_object_unref(copy);
}

static void
test_connection_match_interface_name(void)
{
    NMConnection *       orig, *copy, *matched;
    GSList *             connections = NULL;
    NMSettingConnection *s_con;

    orig        = _match_connection_new();
    copy        = nm_simple_connection_new_clone(orig);
    connections = g_slist_append(connections, copy);

    /* Check that if the generated connection has an interface name and the
     * candidate's interface name is NULL, that the candidate is matched.
     */
    s_con = nm_connection_get_setting_connection(orig);
    g_assert(s_con);
    g_object_set(G_OBJECT(s_con), NM_SETTING_CONNECTION_INTERFACE_NAME, "em1", NULL);

    s_con = nm_connection_get_setting_connection(copy);
    g_assert(s_con);
    g_object_set(G_OBJECT(s_con), NM_SETTING_CONNECTION_INTERFACE_NAME, NULL, NULL);

    matched = _match_connection(connections, orig, TRUE, 0, 0);
    g_assert(matched == copy);

    g_slist_free(connections);
    g_object_unref(orig);
    g_object_unref(copy);
}

static void
test_connection_match_wired(void)
{
    NMConnection *  orig, *copy, *matched;
    GSList *        connections = NULL;
    NMSettingWired *s_wired;
    char *          subchan_arr[] = {"0.0.8000", "0.0.8001", "0.0.8002", NULL};
    const char *    mac           = "52:54:00:ab:db:23";

    orig        = _match_connection_new();
    copy        = nm_simple_connection_new_clone(orig);
    connections = g_slist_append(connections, copy);

    s_wired = nm_connection_get_setting_wired(orig);
    g_assert(s_wired);
    g_object_set(G_OBJECT(s_wired),
                 NM_SETTING_WIRED_PORT,
                 "tp", /* port is not compared */
                 NM_SETTING_WIRED_MAC_ADDRESS,
                 mac, /* we allow MAC address just in one connection */
                 NM_SETTING_WIRED_S390_SUBCHANNELS,
                 subchan_arr,
                 NM_SETTING_WIRED_S390_NETTYPE,
                 "qeth",
                 NULL);

    s_wired = nm_connection_get_setting_wired(copy);
    g_assert(s_wired);
    g_object_set(G_OBJECT(s_wired),
                 NM_SETTING_WIRED_S390_SUBCHANNELS,
                 subchan_arr,
                 NM_SETTING_WIRED_S390_NETTYPE,
                 "qeth",
                 NULL);

    matched = _match_connection(connections, orig, TRUE, 0, 0);
    g_assert(matched == copy);

    g_slist_free(connections);
    g_object_unref(orig);
    g_object_unref(copy);
}

static void
test_connection_match_wired2(void)
{
    NMConnection *  orig, *copy, *matched;
    GSList *        connections = NULL;
    NMSettingWired *s_wired;
    const char *    mac = "52:54:00:ab:db:23";

    orig    = _match_connection_new();
    s_wired = nm_connection_get_setting_wired(orig);
    g_assert(s_wired);
    g_object_set(G_OBJECT(s_wired),
                 NM_SETTING_WIRED_PORT,
                 "tp", /* port is not compared */
                 NM_SETTING_WIRED_MAC_ADDRESS,
                 mac, /* we allow MAC address just in one connection */
                 NULL);

    copy        = nm_simple_connection_new_clone(orig);
    connections = g_slist_append(connections, copy);

    /* Check that if the generated connection do not have wired setting
     * and s390 properties in the existing connection's setting are default,
     * the connections match. It can happen if assuming VLAN devices. */
    nm_connection_remove_setting(orig, NM_TYPE_SETTING_WIRED);

    matched = _match_connection(connections, orig, TRUE, 0, 0);
    g_assert(matched == copy);

    g_slist_free(connections);
    g_object_unref(orig);
    g_object_unref(copy);
}

static void
test_connection_match_cloned_mac(void)
{
    NMConnection *  orig, *exact, *fuzzy, *matched;
    GSList *        connections = NULL;
    NMSettingWired *s_wired;

    orig = _match_connection_new();

    fuzzy       = nm_simple_connection_new_clone(orig);
    connections = g_slist_append(connections, fuzzy);
    s_wired     = nm_connection_get_setting_wired(orig);
    g_assert(s_wired);
    g_object_set(G_OBJECT(s_wired), NM_SETTING_WIRED_CLONED_MAC_ADDRESS, "52:54:00:ab:db:23", NULL);

    matched = _match_connection(connections, orig, TRUE, 0, 0);
    g_assert(matched == fuzzy);

    exact       = nm_simple_connection_new_clone(orig);
    connections = g_slist_append(connections, exact);
    s_wired     = nm_connection_get_setting_wired(exact);
    g_assert(s_wired);
    g_object_set(G_OBJECT(s_wired), NM_SETTING_WIRED_CLONED_MAC_ADDRESS, "52:54:00:ab:db:23", NULL);

    matched = _match_connection(connections, orig, TRUE, 0, 0);
    g_assert(matched == exact);

    g_object_set(G_OBJECT(s_wired), NM_SETTING_WIRED_CLONED_MAC_ADDRESS, "52:54:00:ab:db:24", NULL);

    matched = _match_connection(connections, orig, TRUE, 0, 0);
    g_assert(matched == fuzzy);

    g_slist_free(connections);
    g_object_unref(orig);
    g_object_unref(fuzzy);
    g_object_unref(exact);
}

static void
test_connection_no_match_ip4_addr(void)
{
    NMConnection *     orig, *copy, *matched;
    GSList *           connections = NULL;
    NMSettingIPConfig *s_ip4, *s_ip6;
    NMIPAddress *      nm_addr;
    GError *           error = NULL;

    orig        = _match_connection_new();
    copy        = nm_simple_connection_new_clone(orig);
    connections = g_slist_append(connections, copy);

    /* Check that if we have two differences, ipv6.method (exception we allow) and
     * ipv4.addresses (which is fatal), we don't match the connections.
     */
    s_ip6 = nm_connection_get_setting_ip6_config(orig);
    g_assert(s_ip6);
    g_object_set(G_OBJECT(s_ip6),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
                 NULL);

    s_ip6 = nm_connection_get_setting_ip6_config(copy);
    g_assert(s_ip6);
    g_object_set(G_OBJECT(s_ip6),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
                 NULL);

    s_ip4 = nm_connection_get_setting_ip4_config(orig);
    g_assert(s_ip4);
    g_object_set(G_OBJECT(s_ip4),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
                 NM_SETTING_IP_CONFIG_GATEWAY,
                 "1.1.1.254",
                 NULL);
    nm_addr = nm_ip_address_new(AF_INET, "1.1.1.4", 24, &error);
    g_assert_no_error(error);
    nm_setting_ip_config_add_address(s_ip4, nm_addr);
    nm_ip_address_unref(nm_addr);

    s_ip4 = nm_connection_get_setting_ip4_config(copy);
    g_assert(s_ip4);
    g_object_set(G_OBJECT(s_ip4),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
                 NM_SETTING_IP_CONFIG_GATEWAY,
                 "2.2.2.254",
                 NULL);
    nm_addr = nm_ip_address_new(AF_INET, "2.2.2.4", 24, &error);
    g_assert_no_error(error);
    nm_setting_ip_config_add_address(s_ip4, nm_addr);
    nm_ip_address_unref(nm_addr);

    matched = _match_connection(connections, orig, TRUE, 0, 0);
    g_assert(matched != copy);

    g_slist_free(connections);
    g_object_unref(orig);
    g_object_unref(copy);
}

static void
test_connection_no_match_vlan(void)
{
    NMConnection *       orig, *copy, *matched;
    GSList *             connections = NULL;
    NMSettingConnection *s_con;
    NMSettingVlan *      s_vlan_orig, *s_vlan_copy;
    char *               uuid;

    orig  = nm_simple_connection_new();
    s_con = (NMSettingConnection *) nm_setting_connection_new();
    nm_connection_add_setting(orig, (NMSetting *) s_con);
    uuid = nm_utils_uuid_generate();
    g_object_set(G_OBJECT(s_con),
                 NM_SETTING_CONNECTION_ID,
                 "vlan-test",
                 NM_SETTING_CONNECTION_UUID,
                 uuid,
                 NM_SETTING_CONNECTION_TYPE,
                 NM_SETTING_VLAN_SETTING_NAME,
                 NM_SETTING_CONNECTION_AUTOCONNECT,
                 FALSE,
                 NULL);
    g_free(uuid);
    nm_connection_add_setting(orig, nm_setting_vlan_new());

    copy        = nm_simple_connection_new_clone(orig);
    connections = g_slist_append(connections, copy);

    /* Check that the connections do not match if VLAN flags differ */
    s_vlan_orig = nm_connection_get_setting_vlan(orig);
    g_assert(s_vlan_orig);
    g_object_set(G_OBJECT(s_vlan_orig), NM_SETTING_VLAN_FLAGS, NM_VLAN_FLAG_REORDER_HEADERS, NULL);

    s_vlan_copy = nm_connection_get_setting_vlan(copy);
    g_assert(s_vlan_copy);
    g_object_set(G_OBJECT(s_vlan_copy), NM_SETTING_VLAN_FLAGS, 0, NULL);

    matched = _match_connection(connections, orig, TRUE, 0, 0);
    g_assert(matched != copy);

    /* Check that the connections do not match if VLAN priorities differ */
    g_object_set(G_OBJECT(s_vlan_orig), NM_SETTING_VLAN_FLAGS, 0, NULL);
    nm_setting_vlan_add_priority_str(s_vlan_orig, NM_VLAN_INGRESS_MAP, "1:3");

    g_object_set(G_OBJECT(s_vlan_copy), NM_SETTING_VLAN_FLAGS, 0, NULL);
    nm_setting_vlan_add_priority_str(s_vlan_copy, NM_VLAN_INGRESS_MAP, "4:2");

    matched = _match_connection(connections, orig, TRUE, 0, 0);
    g_assert(matched != copy);

    g_slist_free(connections);
    g_object_unref(orig);
    g_object_unref(copy);
}

static void
test_connection_match_ip4_routes1(void)
{
    gs_unref_object NMConnection *orig = NULL, *copy = NULL;
    NMConnection *                matched;
    nm_auto_free_slist GSList *connections = NULL;
    NMSettingIPConfig *        s_ip4;

    orig = _match_connection_new();

    s_ip4 = nm_connection_get_setting_ip4_config(orig);
    g_assert(s_ip4);
    g_object_set(G_OBJECT(s_ip4),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
                 NULL);

    nmtst_setting_ip_config_add_address(s_ip4, "10.0.0.1", 8);

    /* Clone connection */
    copy        = nm_simple_connection_new_clone(orig);
    connections = g_slist_append(connections, copy);

    /* Set routes on original connection */
    nmtst_setting_ip_config_add_route(s_ip4, "172.25.16.0", 24, "10.0.0.2", -1);
    nmtst_setting_ip_config_add_route(s_ip4, "172.25.17.0", 24, "10.0.0.3", 20);

    /* Set single route on cloned connection */
    s_ip4 = nm_connection_get_setting_ip4_config(copy);
    g_assert(s_ip4);
    nmtst_setting_ip_config_add_route(s_ip4, "172.25.17.0", 24, "10.0.0.3", 20);

    /* Try to match the connections */
    matched = _match_connection(connections, orig, FALSE, 100, 0);
    g_assert(matched == NULL);
}

static void
test_connection_match_ip4_routes2(void)
{
    gs_unref_object NMConnection *orig = NULL, *copy = NULL;
    NMConnection *                matched;
    nm_auto_free_slist GSList *connections = NULL;
    NMSettingIPConfig *        s_ip4;

    orig = _match_connection_new();

    s_ip4 = nm_connection_get_setting_ip4_config(orig);
    g_assert(s_ip4);
    g_object_set(G_OBJECT(s_ip4),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
                 NULL);

    nmtst_setting_ip_config_add_address(s_ip4, "10.0.0.1", 8);

    /* Clone connection */
    copy        = nm_simple_connection_new_clone(orig);
    connections = g_slist_append(connections, copy);

    /* Set routes on original connection */
    nmtst_setting_ip_config_add_route(s_ip4, "172.25.16.0", 24, "10.0.0.2", -1);
    nmtst_setting_ip_config_add_route(s_ip4, "172.25.17.0", 24, "10.0.0.3", 20);

    /* Set routes on cloned connection, changing order and using explicit metrics */
    s_ip4 = nm_connection_get_setting_ip4_config(copy);
    g_assert(s_ip4);
    nmtst_setting_ip_config_add_route(s_ip4, "172.25.17.0", 24, "10.0.0.3", 20);
    nmtst_setting_ip_config_add_route(s_ip4, "172.25.16.0", 24, "10.0.0.2", 100);

    /* Try to match the connections using different default metrics */
    matched = _match_connection(connections, orig, FALSE, 100, 0);
    g_assert(matched == copy);
    matched = _match_connection(connections, orig, FALSE, 500, 0);
    g_assert(matched == NULL);
}

static void
test_connection_match_ip6_routes(void)
{
    gs_unref_object NMConnection *orig = NULL, *copy = NULL;
    NMConnection *                matched;
    nm_auto_free_slist GSList *connections = NULL;
    NMSettingIPConfig *        s_ip6;

    orig = _match_connection_new();

    s_ip6 = nm_connection_get_setting_ip6_config(orig);
    g_assert(s_ip6);
    g_object_set(G_OBJECT(s_ip6),
                 NM_SETTING_IP_CONFIG_METHOD,
                 NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
                 NULL);

    nmtst_setting_ip_config_add_address(s_ip6, "fd01::15", 64);

    /* Clone connection */
    copy        = nm_simple_connection_new_clone(orig);
    connections = g_slist_append(connections, copy);

    /* Set routes on original connection */
    nmtst_setting_ip_config_add_route(s_ip6, "2001:db8:a:b:0:0:0:0", 64, "fd01::16", -1);

    /* Set routes on cloned connection */
    s_ip6 = nm_connection_get_setting_ip6_config(copy);
    g_assert(s_ip6);
    nmtst_setting_ip_config_add_route(s_ip6, "2001:db8:a:b:0:0:0:0", 64, "fd01::16", 50);

    /* Try to match the connections */
    matched = _match_connection(connections, orig, FALSE, 0, 100);
    g_assert(matched == NULL);
    matched = _match_connection(connections, orig, FALSE, 0, 50);
    g_assert(matched == copy);
}

#define do_test_wildcard_match_eval(str, ...) \
    nm_wildcard_match_check(str, (const char *const[]){__VA_ARGS__}, NM_NARG(__VA_ARGS__))

#define do_test_wildcard_match(str, result, ...) \
    g_assert(do_test_wildcard_match_eval(str, __VA_ARGS__) == result)

static void
test_wildcard_match(void)
{
    do_test_wildcard_match("foobar", TRUE);

    do_test_wildcard_match("foo", TRUE, "foo", "bar", "baz");
    do_test_wildcard_match("bar", TRUE, "foo", "bar", "baz");
    do_test_wildcard_match("baz", TRUE, "foo", "bar", "baz");
    do_test_wildcard_match("aaa", FALSE, "foo", "bar", "baz");
    do_test_wildcard_match("", FALSE, "foo", "bar", "baz");

    do_test_wildcard_match("ens1", TRUE, "ens1*");
    do_test_wildcard_match("ens10", TRUE, "ens1*");
    do_test_wildcard_match("ens11", TRUE, "ens1*");
    do_test_wildcard_match("ens12", TRUE, "ens1*");
    do_test_wildcard_match("eth0", FALSE, "ens1*");
    do_test_wildcard_match("ens", FALSE, "ens1*");

    do_test_wildcard_match("ens1*", TRUE, "ens1\\*");
    do_test_wildcard_match("ens1", FALSE, "ens1\\*");
    do_test_wildcard_match("ens10", FALSE, "ens1\\*");

    do_test_wildcard_match("abcd", TRUE, "ab??");
    do_test_wildcard_match("ab", FALSE, "ab??");

    do_test_wildcard_match("ab??", TRUE, "ab\\?\\?");
    do_test_wildcard_match("abcd", FALSE, "ab\\?\\?");

    do_test_wildcard_match("ens10", TRUE, "ens1*", "!ens11");
    do_test_wildcard_match("ens11", FALSE, "ens1*", "!ens11");
    do_test_wildcard_match("ens12", TRUE, "ens1*", "!ens11");

    do_test_wildcard_match("a", FALSE, "!a", "!b");
    do_test_wildcard_match("b", FALSE, "!a", "!b");
    do_test_wildcard_match("c", TRUE, "!a", "!b");
    do_test_wildcard_match("!a", TRUE, "!a", "!b");

    do_test_wildcard_match("!net", TRUE, "\\!net");
    do_test_wildcard_match("net", FALSE, "\\!net");
    do_test_wildcard_match("ens10", FALSE, "\\!net");
    do_test_wildcard_match("\\!net", FALSE, "\\!net");

    do_test_wildcard_match("eth0", FALSE, "*eth?", "!veth*", "!*0");
    do_test_wildcard_match("eth1", TRUE, "*eth?", "!veth*", "!*0");
    do_test_wildcard_match("myeth0", FALSE, "*eth?", "!veth*", "!*0");
    do_test_wildcard_match("myeth2", TRUE, "*eth?", "!veth*", "!*0");
    do_test_wildcard_match("veth0", FALSE, "*eth?", "!veth*", "!*0");
    do_test_wildcard_match("veth1", FALSE, "*eth?", "!veth*", "!*0");
    do_test_wildcard_match("dummy1", FALSE, "*eth?", "!veth*", "!*0");

    do_test_wildcard_match("a", TRUE, "!!a");
    do_test_wildcard_match("b", TRUE, "!!a");
    do_test_wildcard_match("!a", FALSE, "!!a");

    do_test_wildcard_match("\\", TRUE, "\\\\\\");
    do_test_wildcard_match("\\\\", FALSE, "\\\\");
    do_test_wildcard_match("", FALSE, "\\\\");

    do_test_wildcard_match("\\a", TRUE, "\\\\\\a");
    do_test_wildcard_match("b", TRUE, "&!a");
    do_test_wildcard_match("a", FALSE, "&!a");
    do_test_wildcard_match("!a", TRUE, "&\\!a");
    do_test_wildcard_match("!a", TRUE, "|\\!a");
    do_test_wildcard_match("!a", TRUE, "\\!a");

    do_test_wildcard_match("name", FALSE, "name[123]");
    do_test_wildcard_match("name1", TRUE, "name[123]");
    do_test_wildcard_match("name2", TRUE, "name[123]");
    do_test_wildcard_match("name3", TRUE, "name[123]");
    do_test_wildcard_match("name4", FALSE, "name[123]");

    if (do_test_wildcard_match_eval("[a]", "\\[a\\]") != TRUE) {
#if defined(__GLIBC__)
        do_test_wildcard_match("[a]", TRUE, "\\[a\\]");
        g_assert_not_reached();
#endif
        /* It seems musl's fnmatch() does not like such ranges. */
        g_test_skip("libc does not support ranges with fnmatch()!!");
    }

    do_test_wildcard_match("aa", FALSE, "!a*");
    do_test_wildcard_match("aa", FALSE, "&!a*");
    do_test_wildcard_match("aa", FALSE, "|!a*");
    do_test_wildcard_match("aa", FALSE, "&!a*", "aa");
    do_test_wildcard_match("aa", TRUE, "|!a*", "aa");
}

static NMConnection *
_create_connection_autoconnect(const char *id, gboolean autoconnect, int autoconnect_priority)
{
    NMConnection *       c;
    NMSettingConnection *s_con;

    c = nmtst_create_minimal_connection(id, NULL, NM_SETTING_WIRED_SETTING_NAME, &s_con);
    g_object_set(s_con,
                 NM_SETTING_CONNECTION_AUTOCONNECT,
                 autoconnect,
                 NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY,
                 autoconnect_priority,
                 NULL);
    nmtst_connection_normalize(c);
    return c;
}

static int
_cmp_autoconnect_priority_p_with_data(gconstpointer pa, gconstpointer pb, gpointer user_data)
{
    return nm_utils_cmp_connection_by_autoconnect_priority(*((NMConnection **) pa),
                                                           *((NMConnection **) pb));
}

static void
_test_connection_sort_autoconnect_priority_one(NMConnection **list, gboolean shuffle)
{
    int               i, j;
    int               count                  = 0;
    gs_unref_ptrarray GPtrArray *connections = g_ptr_array_new();

    while (list[count])
        count++;
    g_assert(count > 1);

    /* copy the list of connections over to @connections and shuffle. */
    for (i = 0; i < count; i++)
        g_ptr_array_add(connections, list[i]);
    if (shuffle) {
        for (i = count - 1; i > 0; i--) {
            j = g_rand_int(nmtst_get_rand()) % (i + 1);
            NM_SWAP(&connections->pdata[i], &connections->pdata[j]);
        }
    }

    /* sort it... */
    g_ptr_array_sort_with_data(connections, _cmp_autoconnect_priority_p_with_data, NULL);

    for (i = 0; i < count; i++) {
        if (list[i] == connections->pdata[i])
            continue;
        if (shuffle
            && nm_utils_cmp_connection_by_autoconnect_priority(list[i], connections->pdata[i]) == 0)
            continue;
        g_message(
            "After sorting, the order of connections is not as expected!! Offending index: %d",
            i);
        for (j = 0; j < count; j++)
            g_message("  %3d:  %p/%-20s - %p/%-20s",
                      j,
                      list[j],
                      nm_connection_get_id(list[j]),
                      connections->pdata[j],
                      nm_connection_get_id(connections->pdata[j]));
        g_assert_not_reached();
    }
}

static void
_test_connection_sort_autoconnect_priority_free(NMConnection **list)
{
    while (*list) {
        g_object_unref(*list);
        *list = NULL;
    }
}

static void
test_connection_sort_autoconnect_priority(void)
{
    NMConnection *c1[] = {
        _create_connection_autoconnect("AC/100", TRUE, 100),
        _create_connection_autoconnect("AC/100", TRUE, 100),
        _create_connection_autoconnect("AC/99", TRUE, 99),
        _create_connection_autoconnect("AC/0", TRUE, 0),
        _create_connection_autoconnect("AC/0", TRUE, 0),
        _create_connection_autoconnect("AC/-1", TRUE, -1),
        _create_connection_autoconnect("AC/-3", TRUE, -3),
        _create_connection_autoconnect("ac/0", FALSE, 0),
        _create_connection_autoconnect("ac/0", FALSE, 0),
        _create_connection_autoconnect("ac/1", FALSE, 1),
        _create_connection_autoconnect("ac/-1", FALSE, -1),
        _create_connection_autoconnect("ac/1", FALSE, 1),
        _create_connection_autoconnect("ac/0", FALSE, 0),
        NULL,
    };
    NMConnection *c2[] = {
        _create_connection_autoconnect("AC/100", TRUE, 100),
        _create_connection_autoconnect("AC/99", TRUE, 99),
        _create_connection_autoconnect("AC/0", TRUE, 0),
        _create_connection_autoconnect("AC/-1", TRUE, -1),
        _create_connection_autoconnect("AC/-3", TRUE, -3),
        _create_connection_autoconnect("ac/0", FALSE, 0),
        NULL,
    };

    _test_connection_sort_autoconnect_priority_one(c1, FALSE);
    _test_connection_sort_autoconnect_priority_one(c2, FALSE);
    _test_connection_sort_autoconnect_priority_one(c1, TRUE);
    _test_connection_sort_autoconnect_priority_one(c2, TRUE);

    _test_connection_sort_autoconnect_priority_free(c1);
    _test_connection_sort_autoconnect_priority_free(c2);
}

/*****************************************************************************/

#define MATCH_S390   "S390:"
#define MATCH_DRIVER "DRIVER:"

static NMMatchSpecMatchType
_test_match_spec_device(const GSList *specs, const char *match_str)
{
    if (match_str && g_str_has_prefix(match_str, MATCH_S390))
        return nm_match_spec_device(specs,
                                    NULL,
                                    NULL,
                                    NULL,
                                    NULL,
                                    NULL,
                                    &match_str[NM_STRLEN(MATCH_S390)],
                                    NULL);
    if (match_str && g_str_has_prefix(match_str, MATCH_DRIVER)) {
        gs_free char *s = g_strdup(&match_str[NM_STRLEN(MATCH_DRIVER)]);
        char *        t;

        t = strchr(s, '|');
        if (t) {
            t[0] = '\0';
            t++;
        }
        return nm_match_spec_device(specs, NULL, NULL, s, t, NULL, NULL, NULL);
    }
    return nm_match_spec_device(specs, match_str, NULL, NULL, NULL, NULL, NULL, NULL);
}

static void
_do_test_match_spec_device(const char *       spec_str,
                           const char *const *matches,
                           const char *const *no_matches,
                           const char *const *neg_matches)
{
    GSList *           specs, *specs_randperm = NULL, *specs_resplit, *specs_i, *specs_j;
    guint              i;
    gs_free char *     specs_joined = NULL;
    const char *       s;
    static const char *no_matches_default[] = {"e",
                                               "em",
                                               "em*",
                                               "em\\",
                                               "em\\*",
                                               "em\\1",
                                               "em\\11",
                                               "em\\2",
                                               "em1",
                                               "em11",
                                               "em2",
                                               "=em*",
                                               NULL};

    g_assert(spec_str);

    specs = nm_match_spec_split(spec_str);

    /* assert that split(join(specs)) == specs */
    specs_joined  = nm_match_spec_join(specs);
    specs_resplit = nm_match_spec_split(specs_joined);
    specs_i       = specs;
    specs_j       = specs_resplit;
    while (specs_i && specs_j && g_strcmp0(specs_i->data, specs_j->data) == 0) {
        specs_i = specs_i->next;
        specs_j = specs_j->next;
    }
    g_assert(!specs_i);
    g_assert(!specs_j);
    g_slist_free_full(specs_resplit, g_free);

    /* also check the matches in the random order. They must yield the same result because
     * matches are inclusive -- except "except:" which always wins. */
    specs_randperm = nmtst_rand_perm_gslist(NULL, g_slist_copy(specs));

    for (i = 0; matches && matches[i]; i++) {
        g_assert(_test_match_spec_device(specs, matches[i]) == NM_MATCH_SPEC_MATCH);
        g_assert(_test_match_spec_device(specs_randperm, matches[i]) == NM_MATCH_SPEC_MATCH);
    }
    for (i = 0; neg_matches && neg_matches[i]; i++) {
        g_assert(_test_match_spec_device(specs, neg_matches[i]) == NM_MATCH_SPEC_NEG_MATCH);
        g_assert(_test_match_spec_device(specs_randperm, neg_matches[i])
                 == NM_MATCH_SPEC_NEG_MATCH);
    }
    for (i = 0; no_matches && no_matches[i]; i++) {
        g_assert(_test_match_spec_device(specs, no_matches[i]) == NM_MATCH_SPEC_NO_MATCH);
        g_assert(_test_match_spec_device(specs_randperm, no_matches[i]) == NM_MATCH_SPEC_NO_MATCH);
    }
    if (!no_matches) {
        for (i = 0; (s = no_matches_default[i]); i++) {
            if ((matches && g_strv_contains(matches, s))
                || (neg_matches && g_strv_contains(neg_matches, s)))
                continue;
            g_assert(_test_match_spec_device(specs, s) == NM_MATCH_SPEC_NO_MATCH);
            g_assert(_test_match_spec_device(specs_randperm, s) == NM_MATCH_SPEC_NO_MATCH);
        }
    }

    g_slist_free(specs_randperm);
    g_slist_free_full(specs, g_free);
}

static void
test_match_spec_device(void)
{
    _do_test_match_spec_device("em1", NM_MAKE_STRV("em1"), NULL, NULL);
    _do_test_match_spec_device("em1,em2", NM_MAKE_STRV("em1", "em2"), NULL, NULL);
    _do_test_match_spec_device("em1,em2,interface-name:em2",
                               NM_MAKE_STRV("em1", "em2"),
                               NULL,
                               NULL);
    _do_test_match_spec_device("interface-name:em1", NM_MAKE_STRV("em1"), NULL, NULL);
    _do_test_match_spec_device("interface-name:em*",
                               NM_MAKE_STRV("em",
                                            "em*",
                                            "em\\",
                                            "em\\*",
                                            "em\\1",
                                            "em\\11",
                                            "em\\2",
                                            "em1",
                                            "em11",
                                            "em2",
                                            "em3"),
                               NULL,
                               NULL);
    _do_test_match_spec_device("interface-name:em\\*",
                               NM_MAKE_STRV("em\\", "em\\*", "em\\1", "em\\11", "em\\2"),
                               NULL,
                               NULL);
    _do_test_match_spec_device("interface-name:~em\\*",
                               NM_MAKE_STRV("em\\", "em\\*", "em\\1", "em\\11", "em\\2"),
                               NULL,
                               NULL);
    _do_test_match_spec_device("except:*", NULL, NM_MAKE_STRV(NULL), NM_MAKE_STRV("a"));
    _do_test_match_spec_device("interface-name:=em*", NM_MAKE_STRV("em*"), NULL, NULL);
    _do_test_match_spec_device(
        "interface-name:em*,except:interface-name:em1*",
        NM_MAKE_STRV("em", "em*", "em\\", "em\\*", "em\\1", "em\\11", "em\\2", "em2", "em3"),
        NULL,
        NM_MAKE_STRV("em1", "em11"));
    _do_test_match_spec_device("interface-name:em*,except:interface-name:=em*",
                               NM_MAKE_STRV("em",
                                            "em\\",
                                            "em\\*",
                                            "em\\1",
                                            "em\\11",
                                            "em\\2",
                                            "em1",
                                            "em11",
                                            "em2",
                                            "em3"),
                               NULL,
                               NM_MAKE_STRV("em*"));
    _do_test_match_spec_device("except:interface-name:em*",
                               NM_MAKE_STRV("", "eth", "eth1", "e1"),
                               NM_MAKE_STRV(NULL),
                               NM_MAKE_STRV("em",
                                            "em\\",
                                            "em\\*",
                                            "em\\1",
                                            "em\\11",
                                            "em\\2",
                                            "em1",
                                            "em11",
                                            "em2",
                                            "em3"));
    _do_test_match_spec_device("aa,bb,cc\\,dd,e,,",
                               NM_MAKE_STRV("aa", "bb", "cc,dd", "e"),
                               NULL,
                               NULL);
    _do_test_match_spec_device("aa;bb;cc\\;dd;e,;",
                               NM_MAKE_STRV("aa", "bb", "cc;dd", "e"),
                               NULL,
                               NULL);
    _do_test_match_spec_device("interface-name:em\\;1,em\\,2,\\,,\\\\,,em\\\\x",
                               NM_MAKE_STRV("em;1", "em,2", ",", "\\", "em\\x"),
                               NULL,
                               NULL);
    _do_test_match_spec_device("\\s\\s,\\sinterface-name:a,\\s,",
                               NM_MAKE_STRV("  ", " ", " interface-name:a"),
                               NULL,
                               NULL);
    _do_test_match_spec_device(" aa ;  bb   ; cc\\;dd  ;e , ; \t\\t  , ",
                               NM_MAKE_STRV("aa", "bb", "cc;dd", "e", "\t"),
                               NULL,
                               NULL);

    _do_test_match_spec_device("s390-subchannels:0.0.1000\\,0.0.1001",
                               NM_MAKE_STRV(MATCH_S390 "0.0.1000",
                                            MATCH_S390 "0.0.1000,deadbeef",
                                            MATCH_S390 "0.0.1000,0.0.1001",
                                            MATCH_S390 "0.0.1000,0.0.1002"),
                               NM_MAKE_STRV(MATCH_S390 "0.0.1001"),
                               NULL);
    _do_test_match_spec_device("*,except:s390-subchannels:0.0.1000\\,0.0.1001",
                               NULL,
                               NM_MAKE_STRV(NULL),
                               NM_MAKE_STRV(MATCH_S390 "0.0.1000",
                                            MATCH_S390 "0.0.1000,deadbeef",
                                            MATCH_S390 "0.0.1000,0.0.1001",
                                            MATCH_S390 "0.0.1000,0.0.1002"));

    _do_test_match_spec_device("driver:DRV",
                               NM_MAKE_STRV(MATCH_DRIVER "DRV", MATCH_DRIVER "DRV|1.6"),
                               NM_MAKE_STRV(MATCH_DRIVER "DR", MATCH_DRIVER "DR*"),
                               NULL);
    _do_test_match_spec_device(
        "driver:DRV//",
        NM_MAKE_STRV(MATCH_DRIVER "DRV/"),
        NM_MAKE_STRV(MATCH_DRIVER "DRV/|1.6", MATCH_DRIVER "DR", MATCH_DRIVER "DR*"),
        NULL);
    _do_test_match_spec_device("driver:DRV//*",
                               NM_MAKE_STRV(MATCH_DRIVER "DRV/", MATCH_DRIVER "DRV/|1.6"),
                               NM_MAKE_STRV(MATCH_DRIVER "DR", MATCH_DRIVER "DR*"),
                               NULL);
    _do_test_match_spec_device("driver:DRV//1.5*",
                               NM_MAKE_STRV(MATCH_DRIVER "DRV/|1.5", MATCH_DRIVER "DRV/|1.5.2"),
                               NM_MAKE_STRV(MATCH_DRIVER "DRV/",
                                            MATCH_DRIVER "DRV/|1.6",
                                            MATCH_DRIVER "DR",
                                            MATCH_DRIVER "DR*"),
                               NULL);
}

/*****************************************************************************/

static void
_do_test_match_spec_config(const char *         file,
                           int                  line,
                           const char *         spec_str,
                           guint                version,
                           guint                v_maj,
                           guint                v_min,
                           guint                v_mic,
                           NMMatchSpecMatchType expected)
{
    GSList *             specs;
    NMMatchSpecMatchType match_result;
    guint                c_maj, c_min, c_mic;

    g_assert_cmpint(version, ==, nm_encode_version(v_maj, v_min, v_mic));

    nm_decode_version(version, &c_maj, &c_min, &c_mic);
    g_assert_cmpint(c_maj, ==, c_maj);
    g_assert_cmpint(c_min, ==, c_min);
    g_assert_cmpint(c_mic, ==, c_mic);

    specs = nm_match_spec_split(spec_str);

    match_result = nm_match_spec_config(specs, version, NULL);

    if (expected != match_result)
        g_error("%s:%d: failed comparing \"%s\" with %u.%u.%u. Expected %d, but got %d",
                file,
                line,
                spec_str,
                v_maj,
                v_min,
                v_mic,
                (int) expected,
                (int) match_result);

    if (g_slist_length(specs) == 1 && !g_str_has_prefix(specs->data, "except:")) {
        /* there is only one spec in the list... test that we match except: */
        char *               sss    = g_strdup_printf("except:%s", (char *) specs->data);
        GSList *             specs2 = g_slist_append(NULL, sss);
        NMMatchSpecMatchType match_result2;

        match_result2 = nm_match_spec_config(specs2, version, NULL);
        if (match_result == NM_MATCH_SPEC_NO_MATCH)
            g_assert_cmpint(match_result2, ==, NM_MATCH_SPEC_MATCH);
        else
            g_assert_cmpint(match_result2, ==, NM_MATCH_SPEC_NEG_MATCH);

        g_slist_free_full(specs2, g_free);
    }

    g_slist_free_full(specs, g_free);
}
#define do_test_match_spec_config(spec, v_maj, v_min, v_mic, expected)       \
    _do_test_match_spec_config(__FILE__,                                     \
                               __LINE__,                                     \
                               ("" spec),                                    \
                               NM_ENCODE_VERSION((v_maj), (v_min), (v_mic)), \
                               (v_maj),                                      \
                               (v_min),                                      \
                               (v_mic),                                      \
                               (expected))

static void
test_match_spec_config(void)
{
    do_test_match_spec_config("", 1, 2, 3, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version:1.2.3", 1, 2, 2, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version:1.2.3", 1, 2, 3, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version:1.2.3", 1, 2, 4, NM_MATCH_SPEC_NO_MATCH);

    do_test_match_spec_config("nm-version:1.2", 1, 1, 2, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version:1.2", 1, 2, 0, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version:1.2", 1, 2, 2, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version:1.2", 1, 2, 3, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version:1.2", 1, 2, 4, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version:1.2", 1, 3, 0, NM_MATCH_SPEC_NO_MATCH);

    do_test_match_spec_config("nm-version-min:1.2.3", 0, 2, 30, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version-min:1.2.3", 1, 1, 1, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version-min:1.2.3", 1, 2, 2, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version-min:1.2.3", 1, 2, 3, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-min:1.2.3", 1, 2, 5, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-min:1.2.3", 1, 3, 0, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version-min:1.2.3", 1, 3, 30, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version-min:1.2.3", 1, 4, 30, NM_MATCH_SPEC_NO_MATCH);

    do_test_match_spec_config("nm-version-min:1.2", 0, 2, 30, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version-min:1.2", 1, 1, 1, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version-min:1.2", 1, 2, 0, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-min:1.2", 1, 2, 3, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-min:1.2", 1, 2, 5, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-min:1.2", 1, 3, 0, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-min:1.2", 1, 3, 30, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-min:1.2", 1, 4, 30, NM_MATCH_SPEC_MATCH);

    do_test_match_spec_config("nm-version-min:1", 0, 2, 30, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version-min:1", 1, 1, 1, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-min:1", 1, 2, 0, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-min:1", 1, 2, 3, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-min:1", 1, 2, 5, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-min:1", 1, 3, 0, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-min:1", 1, 3, 30, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-min:1", 1, 4, 30, NM_MATCH_SPEC_MATCH);

    do_test_match_spec_config("nm-version-max:1.2.3", 0, 2, 30, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version-max:1.2.3", 1, 1, 1, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version-max:1.2.3", 1, 2, 0, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-max:1.2.3", 1, 2, 1, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-max:1.2.3", 1, 2, 2, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-max:1.2.3", 1, 2, 3, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-max:1.2.3", 1, 2, 5, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version-max:1.2.3", 1, 3, 0, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version-max:1.2.3", 1, 3, 30, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version-max:1.2.3", 1, 4, 30, NM_MATCH_SPEC_NO_MATCH);

    do_test_match_spec_config("nm-version-max:1.2", 0, 2, 30, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version-max:1.2", 1, 1, 1, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-max:1.2", 1, 2, 0, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-max:1.2", 1, 2, 3, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-max:1.2", 1, 2, 5, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-max:1.2", 1, 3, 0, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version-max:1.2", 1, 3, 30, NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config("nm-version-max:1.2", 1, 4, 30, NM_MATCH_SPEC_NO_MATCH);

    do_test_match_spec_config("nm-version-max:1", 0, 2, 30, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-max:1", 1, 1, 1, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-max:1", 1, 2, 0, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-max:1", 1, 2, 3, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-max:1", 1, 2, 5, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-max:1", 1, 3, 0, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-max:1", 1, 3, 30, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-max:1", 1, 4, 30, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-max:1", 2, 4, 30, NM_MATCH_SPEC_NO_MATCH);

    do_test_match_spec_config("except:nm-version:1.4.8", 1, 6, 0, NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config("nm-version-min:1.6,except:nm-version:1.4.8",
                              1,
                              6,
                              0,
                              NM_MATCH_SPEC_MATCH);

    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        2,
        0,
        NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        2,
        0,
        NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        2,
        15,
        NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        2,
        16,
        NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        2,
        17,
        NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        2,
        20,
        NM_MATCH_SPEC_MATCH);

    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        3,
        0,
        NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        4,
        0,
        NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        4,
        5,
        NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        4,
        6,
        NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        4,
        7,
        NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        4,
        8,
        NM_MATCH_SPEC_NEG_MATCH);
    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        4,
        9,
        NM_MATCH_SPEC_MATCH);

    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        5,
        0,
        NM_MATCH_SPEC_NO_MATCH);
    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        6,
        0,
        NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        6,
        5,
        NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        7,
        7,
        NM_MATCH_SPEC_MATCH);
    do_test_match_spec_config(
        "nm-version-min:1.6,nm-version-min:1.4.6,nm-version-min:1.2.16,except:nm-version:1.4.8",
        1,
        8,
        8,
        NM_MATCH_SPEC_MATCH);
}

/*****************************************************************************/

static void
test_nm_utils_strbuf_append(void)
{
#define BUF_ORIG "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define STR_ORIG "abcdefghijklmnopqrstuvwxyz"
    int  buf_len;
    int  rep;
    char buf[NM_STRLEN(BUF_ORIG) + 1];
    char str[NM_STRLEN(BUF_ORIG) + 1];

#define _strbuf_append(buf, len, format, ...)                           \
    G_STMT_START                                                        \
    {                                                                   \
        char **       _buf = (buf);                                     \
        gsize *       _len = (len);                                     \
        const char *  _str_iter;                                        \
        gs_free char *_str = NULL;                                      \
                                                                        \
        switch (nmtst_get_rand_uint32() % 4) {                          \
        case 0:                                                         \
            nm_utils_strbuf_append(_buf, _len, (format), __VA_ARGS__);  \
            break;                                                      \
        case 1:                                                         \
            _str = g_strdup_printf((format), __VA_ARGS__);              \
            nm_utils_strbuf_append_str(_buf, _len, _str);               \
            break;                                                      \
        case 2:                                                         \
            _str = g_strdup_printf((format), __VA_ARGS__);              \
            nm_utils_strbuf_append_bin(_buf, _len, _str, strlen(_str)); \
            break;                                                      \
        case 3:                                                         \
            _str = g_strdup_printf((format), __VA_ARGS__);              \
            if (!_str[0])                                               \
                nm_utils_strbuf_append_str(_buf, _len, _str);           \
            for (_str_iter = _str; _str_iter[0]; _str_iter++)           \
                nm_utils_strbuf_append_c(_buf, _len, _str_iter[0]);     \
            break;                                                      \
        }                                                               \
    }                                                                   \
    G_STMT_END

#define _strbuf_append_str(buf, len, str)                                          \
    G_STMT_START                                                                   \
    {                                                                              \
        char **     _buf = (buf);                                                  \
        gsize *     _len = (len);                                                  \
        const char *_str = (str);                                                  \
                                                                                   \
        switch (nmtst_get_rand_uint32() % 4) {                                     \
        case 0:                                                                    \
            nm_utils_strbuf_append(_buf, _len, "%s", _str ?: "");                  \
            break;                                                                 \
        case 1:                                                                    \
            nm_utils_strbuf_append_str(_buf, _len, _str);                          \
            break;                                                                 \
        case 2:                                                                    \
            nm_utils_strbuf_append_bin(_buf, _len, _str, _str ? strlen(_str) : 0); \
            break;                                                                 \
        case 3:                                                                    \
            if (!_str || !_str[0])                                                 \
                nm_utils_strbuf_append_str(_buf, _len, _str);                      \
            for (; _str && _str[0]; _str++)                                        \
                nm_utils_strbuf_append_c(_buf, _len, _str[0]);                     \
            break;                                                                 \
        }                                                                          \
    }                                                                              \
    G_STMT_END

#define _strbuf_append_c(buf, len, ch)                                   \
    G_STMT_START                                                         \
    {                                                                    \
        char **_buf = (buf);                                             \
        gsize *_len = (len);                                             \
        char   _ch  = (ch);                                              \
                                                                         \
        switch (nmtst_get_rand_uint32() % 4) {                           \
        case 0:                                                          \
            nm_utils_strbuf_append(_buf, _len, "%c", _ch);               \
            break;                                                       \
        case 1:                                                          \
            nm_utils_strbuf_append_str(_buf, _len, ((char[2]){_ch, 0})); \
            break;                                                       \
        case 2:                                                          \
            nm_utils_strbuf_append_bin(_buf, _len, &_ch, 1);             \
            break;                                                       \
        case 3:                                                          \
            nm_utils_strbuf_append_c(_buf, _len, _ch);                   \
            break;                                                       \
        }                                                                \
    }                                                                    \
    G_STMT_END

    for (buf_len = 0; buf_len < 10; buf_len++) {
        for (rep = 0; rep < 50; rep++) {
            const int s_len = nmtst_get_rand_uint32() % (sizeof(str) - 5);
            char *    t_buf;
            gsize     t_len;
            int       test_mode;

            strcpy(str, STR_ORIG);
            str[s_len] = '\0';

            g_assert_cmpint(str[sizeof(str) - 1], ==, '\0');
            g_assert_cmpint(strlen(str), ==, s_len);

            strcpy(buf, BUF_ORIG);

            t_buf = buf;
            t_len = buf_len;

            test_mode = nmtst_get_rand_uint32() % 5;

            switch (test_mode) {
            case 0:
                if (s_len == 1) {
                    _strbuf_append_c(&t_buf, &t_len, str[0]);
                    break;
                }
                /* fall-through */
            case 1:
                _strbuf_append_str(&t_buf, &t_len, str);
                break;
            case 2:
                if (s_len == 1) {
                    _strbuf_append(&t_buf, &t_len, "%c", str[0]);
                    break;
                }
                /* fall-through */
            case 3:
                _strbuf_append(&t_buf, &t_len, "%s", str);
                break;
            case 4:
                g_snprintf(t_buf, t_len, "%s", str);
                if (t_len > 0 && strlen(str) >= buf_len && (nmtst_get_rand_uint32() % 2)) {
                    /* the string was truncated by g_snprintf(). That means, at the last position in the
                     * buffer is now NUL.
                     * Replace the NUL by the actual character, and check that nm_utils_strbuf_seek_end()
                     * does the right thing: NUL terminate the buffer and seek past the end of the buffer. */
                    g_assert_cmpmem(t_buf, t_len - 1, str, t_len - 1);
                    g_assert(t_buf[t_len - 1] == '\0');
                    g_assert(str[t_len - 1] != '\0');
                    t_buf[t_len - 1] = str[t_len - 1];
                    nm_utils_strbuf_seek_end(&t_buf, &t_len);
                    g_assert(t_len == 0);
                    g_assert(t_buf == &buf[buf_len]);
                    g_assert(t_buf[-1] == '\0');
                } else {
                    nm_utils_strbuf_seek_end(&t_buf, &t_len);
                    if (buf_len > 0 && strlen(str) + 1 > buf_len) {
                        /* the buffer was truncated by g_snprintf() above.
                         *
                         * But nm_utils_strbuf_seek_end() does not recognize that and returns
                         * a remaining length of 1.
                         *
                         * Note that other nm_utils_strbuf_append*() functions recognize
                         * truncation, and properly set the remaining length to zero.
                         * As the assertions below check for the behavior of nm_utils_strbuf_append*(),
                         * we assert here that nm_utils_strbuf_seek_end() behaved as expected, and then
                         * adjust t_buf/t_len according to the "is-truncated" case. */
                        g_assert(t_len == 1);
                        g_assert(t_buf == &buf[buf_len - 1]);
                        g_assert(t_buf[0] == '\0');
                        t_len = 0;
                        t_buf++;
                    }
                }
                break;
            }

            /* Assert that the source-buffer is unmodified. */
            g_assert_cmpint(str[s_len], ==, '\0');
            str[s_len] = STR_ORIG[s_len];
            g_assert(!memcmp(str, STR_ORIG, sizeof(str)));
            str[s_len] = '\0';

            g_assert_cmpint(t_len, >=, 0);
            g_assert_cmpint(t_len, <=, buf_len);
            g_assert(t_buf >= buf);

            /* Assert what was written to the destination buffer. */
            switch (buf_len) {
            case 0:
                g_assert_cmpint(t_len, ==, 0);
                g_assert(t_buf == buf);
                g_assert(!memcmp(buf, BUF_ORIG, sizeof(buf)));
                break;
            case 1:
                if (s_len == 0) {
                    g_assert_cmpint(t_len, ==, 1);
                    g_assert(t_buf == buf);
                    g_assert(buf[0] == '\0');
                    g_assert(!memcmp(&buf[1], &BUF_ORIG[1], sizeof(buf) - 1));
                } else {
                    g_assert_cmpint(t_len, ==, 0);
                    g_assert(t_buf == &buf[1]);
                    g_assert(buf[0] == '\0');
                    g_assert(!memcmp(&buf[1], &BUF_ORIG[1], sizeof(buf) - 1));
                }
                break;
            default:
                if (s_len == 0) {
                    g_assert_cmpint(t_len, ==, buf_len);
                    g_assert(t_buf == buf);
                    g_assert(buf[0] == '\0');
                    g_assert(!memcmp(&buf[1], &BUF_ORIG[1], sizeof(buf) - 1));
                } else if (buf_len <= s_len) {
                    g_assert_cmpint(t_len, ==, 0);
                    g_assert(t_buf == &buf[buf_len]);
                    g_assert(!memcmp(buf, STR_ORIG, buf_len - 1));
                    g_assert(buf[buf_len - 1] == '\0');
                    g_assert(!memcmp(&buf[buf_len], &BUF_ORIG[buf_len], sizeof(buf) - buf_len));
                } else {
                    g_assert_cmpint(t_len, >, 0);
                    g_assert_cmpint(buf_len - t_len, ==, s_len);
                    g_assert_cmpint(strlen(buf), ==, s_len);
                    g_assert(t_buf == &buf[s_len]);
                    g_assert(!memcmp(buf, STR_ORIG, s_len));
                    g_assert(buf[s_len] == '\0');
                    g_assert(
                        !memcmp(&buf[s_len + 1], &BUF_ORIG[s_len + 1], sizeof(buf) - s_len - 1));
                }
                break;
            }
        }
    }
}

/*****************************************************************************/

static void
test_duplicate_decl_specifier(void)
{
    /* We're intentionally assigning values to static arrays v_const
     * and v_result without using it afterwards just so that valgrind
     * doesn't complain about the leak. */
    NM_PRAGMA_WARNING_DISABLE("-Wunused-but-set-variable")

    /* have some static variables, so that the result is certainly not optimized out. */
    static const int v_const[1]  = {1};
    static int       v_result[1] = {};
    const int        v2          = 3;

    /* Test that we don't get a compiler warning about duplicate const specifier.
     * C99 allows that and it can easily happen in macros. */

#define TEST_MAX(a, b)            \
    ({                            \
        const typeof(a) _a = (a); \
        const typeof(b) _b = (b); \
                                  \
        (_a > _b ? _a : _b);      \
    })

    v_result[0] = TEST_MAX(v_const[0], nmtst_get_rand_uint32() % 5) + v2;

    NM_PRAGMA_WARNING_REENABLE
}

static void
test_reverse_dns_ip4(void)
{
    guint32    addr;
    GPtrArray *domains = g_ptr_array_new_full(8, g_free);

    inet_pton(AF_INET, "7.2.3.0", &addr);
    nm_utils_get_reverse_dns_domains_ip_4(addr, 27, domains);
    g_assert_cmpuint(domains->len, ==, 32);
    g_assert_cmpstr(domains->pdata[0], ==, "0.3.2.7.in-addr.arpa");
    g_assert_cmpstr(domains->pdata[31], ==, "31.3.2.7.in-addr.arpa");

    g_ptr_array_set_size(domains, 0);

    inet_pton(AF_INET, "10.155.16.0", &addr);
    nm_utils_get_reverse_dns_domains_ip_4(addr, 22, domains);
    g_assert_cmpuint(domains->len, ==, 4);
    g_assert_cmpstr(domains->pdata[0], ==, "16.155.10.in-addr.arpa");
    g_assert_cmpstr(domains->pdata[1], ==, "17.155.10.in-addr.arpa");
    g_assert_cmpstr(domains->pdata[2], ==, "18.155.10.in-addr.arpa");
    g_assert_cmpstr(domains->pdata[3], ==, "19.155.10.in-addr.arpa");

    g_ptr_array_set_size(domains, 0);

    inet_pton(AF_INET, "4.5.6.7", &addr);
    nm_utils_get_reverse_dns_domains_ip_4(addr, 32, domains);
    g_assert_cmpuint(domains->len, ==, 1);
    g_assert_cmpstr(domains->pdata[0], ==, "7.6.5.4.in-addr.arpa");

    g_ptr_array_set_size(domains, 0);

    inet_pton(AF_INET, "4.5.6.7", &addr);
    nm_utils_get_reverse_dns_domains_ip_4(addr, 8, domains);
    g_assert_cmpuint(domains->len, ==, 1);
    g_assert_cmpstr(domains->pdata[0], ==, "4.in-addr.arpa");

    g_ptr_array_set_size(domains, 0);

    inet_pton(AF_INET, "4.180.6.7", &addr);
    nm_utils_get_reverse_dns_domains_ip_4(addr, 9, domains);
    g_assert_cmpuint(domains->len, ==, 128);
    g_assert_cmpstr(domains->pdata[0], ==, "128.4.in-addr.arpa");
    g_assert_cmpstr(domains->pdata[1], ==, "129.4.in-addr.arpa");
    g_assert_cmpstr(domains->pdata[127], ==, "255.4.in-addr.arpa");

    g_ptr_array_set_size(domains, 0);

    inet_pton(AF_INET, "172.16.0.0", &addr);
    nm_utils_get_reverse_dns_domains_ip_4(addr, 12, domains);
    g_assert_cmpuint(domains->len, ==, 16);
    g_assert_cmpstr(domains->pdata[0], ==, "16.172.in-addr.arpa");
    g_assert_cmpstr(domains->pdata[1], ==, "17.172.in-addr.arpa");
    g_assert_cmpstr(domains->pdata[14], ==, "30.172.in-addr.arpa");
    g_assert_cmpstr(domains->pdata[15], ==, "31.172.in-addr.arpa");

    g_ptr_array_set_size(domains, 0);

    inet_pton(AF_INET, "1.2.3.4", &addr);
    nm_utils_get_reverse_dns_domains_ip_4(addr, 0, domains);
    g_assert_cmpuint(domains->len, ==, 0);

    g_ptr_array_unref(domains);
}

static void
test_reverse_dns_ip6(void)
{
    struct in6_addr addr;
    GPtrArray *     domains = g_ptr_array_new_full(8, g_free);

    inet_pton(AF_INET6, "1234::56", &addr);
    nm_utils_get_reverse_dns_domains_ip_6(&addr, 16, domains);
    g_assert_cmpuint(domains->len, ==, 1);
    g_assert_cmpstr(domains->pdata[0], ==, "4.3.2.1.ip6.arpa");

    g_ptr_array_set_size(domains, 0);

    inet_pton(AF_INET6, "1234::56", &addr);
    nm_utils_get_reverse_dns_domains_ip_6(&addr, 17, domains);
    g_assert_cmpuint(domains->len, ==, 8);
    g_assert_cmpstr(domains->pdata[0], ==, "0.4.3.2.1.ip6.arpa");
    g_assert_cmpstr(domains->pdata[1], ==, "1.4.3.2.1.ip6.arpa");
    g_assert_cmpstr(domains->pdata[7], ==, "7.4.3.2.1.ip6.arpa");

    g_ptr_array_set_size(domains, 0);

    inet_pton(AF_INET6, "2001:db8::", &addr);
    nm_utils_get_reverse_dns_domains_ip_6(&addr, 29, domains);
    g_assert_cmpuint(domains->len, ==, 8);
    g_assert_cmpstr(domains->pdata[0], ==, "8.b.d.0.1.0.0.2.ip6.arpa");
    g_assert_cmpstr(domains->pdata[1], ==, "9.b.d.0.1.0.0.2.ip6.arpa");
    g_assert_cmpstr(domains->pdata[7], ==, "f.b.d.0.1.0.0.2.ip6.arpa");

    g_ptr_array_set_size(domains, 0);

    inet_pton(AF_INET6, "0123:4567:89ab:cdef::", &addr);
    nm_utils_get_reverse_dns_domains_ip_6(&addr, 63, domains);
    g_assert_cmpuint(domains->len, ==, 2);
    g_assert_cmpstr(domains->pdata[0], ==, "e.e.d.c.b.a.9.8.7.6.5.4.3.2.1.0.ip6.arpa");
    g_assert_cmpstr(domains->pdata[1], ==, "f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.0.ip6.arpa");

    g_ptr_array_set_size(domains, 0);

    inet_pton(AF_INET6, "fec0:1234:5678:9ab0::", &addr);
    nm_utils_get_reverse_dns_domains_ip_6(&addr, 61, domains);
    g_assert_cmpuint(domains->len, ==, 8);
    g_assert_cmpstr(domains->pdata[0], ==, "0.b.a.9.8.7.6.5.4.3.2.1.0.c.e.f.ip6.arpa");
    g_assert_cmpstr(domains->pdata[7], ==, "7.b.a.9.8.7.6.5.4.3.2.1.0.c.e.f.ip6.arpa");

    g_ptr_array_set_size(domains, 0);

    inet_pton(AF_INET6, "0123:4567:89ab:cdee::", &addr);
    nm_utils_get_reverse_dns_domains_ip_6(&addr, 0, domains);
    g_assert_cmpuint(domains->len, ==, 0);

    g_ptr_array_unref(domains);
}

/*****************************************************************************/

static void
do_test_stable_id_parse(const char *      stable_id,
                        NMUtilsStableType expected_stable_type,
                        const char *      expected_generated)
{
    gs_free char *    generated = NULL;
    NMUtilsStableType stable_type;

    if (expected_stable_type == NM_UTILS_STABLE_TYPE_GENERATED)
        g_assert(expected_generated);
    else
        g_assert(!expected_generated);

    if (expected_stable_type == NM_UTILS_STABLE_TYPE_UUID)
        g_assert(!stable_id);
    else
        g_assert(stable_id);

    stable_type =
        nm_utils_stable_id_parse(stable_id, "_DEVICE", "_MAC", "_BOOT", "_CONNECTION", &generated);

    g_assert_cmpint(expected_stable_type, ==, stable_type);

    if (stable_type == NM_UTILS_STABLE_TYPE_GENERATED) {
        g_assert_cmpstr(expected_generated, ==, generated);
        g_assert(generated);
    } else
        g_assert(!generated);
}

static void
test_stable_id_parse(void)
{
#define _parse_stable_id(stable_id) \
    do_test_stable_id_parse("" stable_id "", NM_UTILS_STABLE_TYPE_STABLE_ID, NULL)
#define _parse_generated(stable_id, expected_generated)     \
    do_test_stable_id_parse("" stable_id "",                \
                            NM_UTILS_STABLE_TYPE_GENERATED, \
                            "" expected_generated "")
#define _parse_random(stable_id) \
    do_test_stable_id_parse("" stable_id "", NM_UTILS_STABLE_TYPE_RANDOM, NULL)
    do_test_stable_id_parse(NULL, NM_UTILS_STABLE_TYPE_UUID, NULL);
    _parse_stable_id("");
    _parse_stable_id("a");
    _parse_stable_id("a$");
    _parse_stable_id("a$x");
    _parse_stable_id(" ${a$x");
    _parse_stable_id("${");
    _parse_stable_id("${=");
    _parse_stable_id("${a");
    _parse_stable_id("${a$x");
    _parse_stable_id("a$$");
    _parse_stable_id("a$$x");
    _parse_stable_id("a$${CONNECTION}");
    _parse_stable_id("a$${CONNECTION}x");
    _parse_generated("${CONNECTION}", "${CONNECTION}=11{_CONNECTION}");
    _parse_generated("${${CONNECTION}", "${${CONNECTION}=11{_CONNECTION}");
    _parse_generated("${CONNECTION}x", "${CONNECTION}=11{_CONNECTION}x");
    _parse_generated("x${CONNECTION}", "x${CONNECTION}=11{_CONNECTION}");
    _parse_generated("${BOOT}x", "${BOOT}=5{_BOOT}x");
    _parse_generated("x${BOOT}", "x${BOOT}=5{_BOOT}");
    _parse_generated("x${BOOT}${CONNECTION}", "x${BOOT}=5{_BOOT}${CONNECTION}=11{_CONNECTION}");
    _parse_generated("xX${BOOT}yY${CONNECTION}zZ",
                     "xX${BOOT}=5{_BOOT}yY${CONNECTION}=11{_CONNECTION}zZ");
    _parse_generated("${MAC}x", "${MAC}=4{_MAC}x");
    _parse_random("${RANDOM}");
    _parse_random(" ${RANDOM}");
    _parse_random("${BOOT}${RANDOM}");
}

/*****************************************************************************/

static void
test_stable_id_generated_complete(void)
{
#define ASSERT(str, expected)                              \
    G_STMT_START                                           \
    {                                                      \
        gs_free char *_s = NULL;                           \
                                                           \
        _s = nm_utils_stable_id_generated_complete((str)); \
        g_assert_cmpstr((expected), ==, _s);               \
    }                                                      \
    G_STMT_END

    ASSERT("", "2jmj7l5rSw0yVb/vlWAYkK/YBwk");
    ASSERT("a", "hvfkN/qlp/zhXR3cuerq6jd2Z7g");
    ASSERT("password", "W6ph5Mm5Pz8GgiULbPgzG37mj9g");
#undef ASSERT
}

/*****************************************************************************/

static void
test_nm_utils_exp10(void)
{
#define FLOAT_CMP(a, b)                     \
    G_STMT_START                            \
    {                                       \
        double _a = (a);                    \
        double _b = (b);                    \
                                            \
        if (isinf(_b))                      \
            g_assert(isinf(_a));            \
        else if (_b >= 0.0 && _b <= 0.0)    \
            g_assert(_a - _b < G_MINFLOAT); \
        else {                              \
            double _x = (_a) - (_b);        \
            g_assert(_b > 0.0);             \
            if (_x < 0.0)                   \
                _x = -_x;                   \
            g_assert(_x / _b < 1E-10);      \
        }                                   \
    }                                       \
    G_STMT_END

    FLOAT_CMP(nm_utils_exp10(G_MININT16), 0.0);
    FLOAT_CMP(nm_utils_exp10(-310), 0.0);
    FLOAT_CMP(nm_utils_exp10(-309), 0.0);
    FLOAT_CMP(nm_utils_exp10(-308), 1e-308);
    FLOAT_CMP(nm_utils_exp10(-307), 1e-307);
    FLOAT_CMP(nm_utils_exp10(-1), 1e-1);
    FLOAT_CMP(nm_utils_exp10(-2), 1e-2);
    FLOAT_CMP(nm_utils_exp10(0), 1e0);
    FLOAT_CMP(nm_utils_exp10(1), 1e1);
    FLOAT_CMP(nm_utils_exp10(2), 1e2);
    FLOAT_CMP(nm_utils_exp10(3), 1e3);
    FLOAT_CMP(nm_utils_exp10(4), 1e4);
    FLOAT_CMP(nm_utils_exp10(5), 1e5);
    FLOAT_CMP(nm_utils_exp10(6), 1e6);
    FLOAT_CMP(nm_utils_exp10(7), 1e7);
    FLOAT_CMP(nm_utils_exp10(122), 1e122);
    FLOAT_CMP(nm_utils_exp10(200), 1e200);
    FLOAT_CMP(nm_utils_exp10(307), 1e307);
    FLOAT_CMP(nm_utils_exp10(308), 1e308);
    FLOAT_CMP(nm_utils_exp10(309), INFINITY);
    FLOAT_CMP(nm_utils_exp10(310), INFINITY);
    FLOAT_CMP(nm_utils_exp10(G_MAXINT16), INFINITY);
}

/*****************************************************************************/

static void
test_utils_file_is_in_path(void)
{
    g_assert(!nm_utils_file_is_in_path("/", "/"));
    g_assert(!nm_utils_file_is_in_path("//", "/"));
    g_assert(!nm_utils_file_is_in_path("/a/", "/"));
    g_assert(nm_utils_file_is_in_path("/a", "/"));
    g_assert(nm_utils_file_is_in_path("///a", "/"));
    g_assert(nm_utils_file_is_in_path("//b/a", "/b//"));
    g_assert(nm_utils_file_is_in_path("//b///a", "/b//"));
    g_assert(!nm_utils_file_is_in_path("//b///a/", "/b//"));
    g_assert(!nm_utils_file_is_in_path("//b///a/", "/b/a/"));
    g_assert(!nm_utils_file_is_in_path("//b///a", "/b/a/"));
    g_assert(nm_utils_file_is_in_path("//b///a/.", "/b/a/"));
    g_assert(nm_utils_file_is_in_path("//b///a/..", "/b/a/"));
}

/*****************************************************************************/

#define _TEST_RC(searches, nameservers, options, expected)                          \
    G_STMT_START                                                                    \
    {                                                                               \
        const char *const *const _searches    = (searches);                         \
        const char *const *const _nameservers = (nameservers);                      \
        const char *const *const _options     = (options);                          \
        gs_free char *           _content     = NULL;                               \
                                                                                    \
        _content = nmtst_dns_create_resolv_conf(_searches, _nameservers, _options); \
        g_assert_cmpstr(_content, ==, expected);                                    \
    }                                                                               \
    G_STMT_END

static void
test_dns_create_resolv_conf(void)
{
    _TEST_RC(NM_MAKE_STRV("a"),
             NULL,
             NULL,
             "# Generated by NetworkManager\n"
             "search a\n"
             "");

    _TEST_RC(NM_MAKE_STRV("a", "b.com"),
             NM_MAKE_STRV("192.168.55.1", "192.168.56.1"),
             NM_MAKE_STRV("opt1", "opt2"),
             "# Generated by NetworkManager\n"
             "search a b.com\n"
             "nameserver 192.168.55.1\n"
             "nameserver 192.168.56.1\n"
             "options opt1 opt2\n"
             "");

    _TEST_RC(NM_MAKE_STRV("a2x456789.b2x456789.c2x456789.d2x456789.e2x456789.f2x456789.g2x456789."
                          "h2x456789.i2x456789.j2x4567890",
                          "a2y456789.b2y456789.c2y456789.d2y456789.e2y456789.f2y456789.g2y456789."
                          "h2y456789.i2y456789.j2y4567890",
                          "a2z456789.b2z456789.c2z456789.d2z456789.e2z456789.f2z456789.g2z456789."
                          "h2z456789.i2z456789.j2z4567890"),
             NULL,
             NULL,
             "# Generated by NetworkManager\n"
             "search "
             "a2x456789.b2x456789.c2x456789.d2x456789.e2x456789.f2x456789.g2x456789.h2x456789."
             "i2x456789.j2x4567890 "
             "a2y456789.b2y456789.c2y456789.d2y456789.e2y456789.f2y456789.g2y456789.h2y456789."
             "i2y456789.j2y4567890                                                        "
             "a2z456789.b2z456789.c2z456789.d2z456789.e2z456789.f2z456789.g2z456789.h2z456789."
             "i2z456789.j2z4567890\n"
             "");
}

/*****************************************************************************/

static void
test_machine_id_read(void)
{
    NMUuid        machine_id_sd;
    const NMUuid *machine_id;
    char          machine_id_str[33];
    gpointer      logstate;

    logstate = nmtst_logging_disable(FALSE);
    /* If you run this test as root, without a valid /etc/machine-id,
     * the code will try to get the secret-key. That is a bit ugly,
     * but no real problem. */
    machine_id = nm_utils_machine_id_bin();
    nmtst_logging_reenable(logstate);

    g_assert(machine_id);
    g_assert(nm_utils_bin2hexstr_full(machine_id, sizeof(NMUuid), '\0', FALSE, machine_id_str)
             == machine_id_str);
    g_assert(strlen(machine_id_str) == 32);
    g_assert_cmpstr(machine_id_str, ==, nm_utils_machine_id_str());

    /* double check with systemd's implementation... */
    if (!nm_sd_utils_id128_get_machine(&machine_id_sd)) {
        /* if systemd failed to read /etc/machine-id, the file likely
         * is invalid. Our machine-id is fake, and we have nothing to
         * compare against. */

        /* NOTE: this test will fail, if you don't have /etc/machine-id,
         * but a valid "LOCALSTATEDIR/lib/dbus/machine-id" file.
         * Just don't do that. */
        g_assert(nm_utils_machine_id_is_fake());
    } else {
        g_assert(!nm_utils_machine_id_is_fake());
        g_assert_cmpmem(&machine_id_sd, sizeof(NMUuid), machine_id, 16);
    }
}

/*****************************************************************************/

static void
test_nm_utils_dhcp_client_id_systemd_node_specific(gconstpointer test_data)
{
    const int     TEST_IDX     = GPOINTER_TO_INT(test_data);
    const guint8  HASH_KEY[16] = {0x80,
                                 0x11,
                                 0x8c,
                                 0xc2,
                                 0xfe,
                                 0x4a,
                                 0x03,
                                 0xee,
                                 0x3e,
                                 0xd6,
                                 0x0c,
                                 0x6f,
                                 0x36,
                                 0x39,
                                 0x14,
                                 0x09};
    const guint16 duid_type_en = htons(2);
    const guint32 systemd_pen  = htonl(43793);
    const struct {
        NMUuid      machine_id;
        const char *ifname;
        guint64     ifname_hash_1;
        guint32     iaid_ifname;
        guint64     duid_id;
    } d_array[] = {
        [0] =
            {
                .machine_id.uuid = {0xcb,
                                    0xc2,
                                    0x2e,
                                    0x47,
                                    0x41,
                                    0x8e,
                                    0x40,
                                    0x2a,
                                    0xa7,
                                    0xb3,
                                    0x0d,
                                    0xea,
                                    0x92,
                                    0x83,
                                    0x94,
                                    0xef},
                .ifname          = "lo",
                .ifname_hash_1   = 0x7297085c2b12c911llu,
                .iaid_ifname     = htobe32(0x5985c14du),
                .duid_id         = htobe64(0x3d769bb2c14d29e1u),
            },
        [1] =
            {
                .machine_id.uuid = {0x11,
                                    0x4e,
                                    0xb4,
                                    0xda,
                                    0xd3,
                                    0x22,
                                    0x4a,
                                    0xff,
                                    0x9f,
                                    0xc3,
                                    0x30,
                                    0x83,
                                    0x38,
                                    0xa0,
                                    0xeb,
                                    0xb7},
                .ifname          = "eth0",
                .ifname_hash_1   = 0x9e1cb083b54cd7b6llu,
                .iaid_ifname     = htobe32(0x2b506735u),
                .duid_id         = htobe64(0x551572e0f2a2a10fu),
            },
    };
    int                 i;
    typeof(d_array[0]) *d = &d_array[TEST_IDX];
    gint64              u64;
    gint32              u32;

    /* the test already hard-codes the expected values iaid_ifname and duid_id
     * above. Still, redo the steps to derive them from the ifname/machine-id
     * and double check. */
    u64 = c_siphash_hash(HASH_KEY, (const guint8 *) d->ifname, strlen(d->ifname));
    g_assert_cmpint(u64, ==, d->ifname_hash_1);
    u32 = be32toh((u64 & 0xffffffffu) ^ (u64 >> 32));
    g_assert_cmpint(u32, ==, d->iaid_ifname);

    u64 = htole64(c_siphash_hash(HASH_KEY, (const guint8 *) &d->machine_id, sizeof(d->machine_id)));
    g_assert_cmpint(u64, ==, d->duid_id);

    for (i = 0; i < 2; i++) {
        const gboolean legacy_unstable_byteorder = (i != 0);
        gs_unref_bytes GBytes *client_id         = NULL;
        const guint8 *         cid;
        guint32                iaid = d->iaid_ifname;
        guint32                tmp;

        tmp = nm_utils_create_dhcp_iaid(legacy_unstable_byteorder,
                                        (const guint8 *) d->ifname,
                                        strlen(d->ifname));
        client_id =
            nm_utils_dhcp_client_id_systemd_node_specific_full(tmp,
                                                               (const guint8 *) &d->machine_id,
                                                               sizeof(d->machine_id));

        g_assert(client_id);
        g_assert_cmpint(g_bytes_get_size(client_id), ==, 19);
        cid = g_bytes_get_data(client_id, NULL);
        g_assert_cmpint(cid[0], ==, 255);
#if __BYTE_ORDER == __BIG_ENDIAN
        if (legacy_unstable_byteorder) {
            /* on non-little endian, the legacy behavior is to have the bytes
             * swapped. */
            iaid = bswap_32(iaid);
        }
#endif
        g_assert_cmpmem(&cid[1], 4, &iaid, sizeof(iaid));
        g_assert_cmpmem(&cid[5], 2, &duid_type_en, sizeof(duid_type_en));
        g_assert_cmpmem(&cid[7], 4, &systemd_pen, sizeof(systemd_pen));
        g_assert_cmpmem(&cid[11], 8, &d->duid_id, sizeof(d->duid_id));

        g_assert_cmpint(iaid,
                        ==,
                        htonl(nm_utils_create_dhcp_iaid(legacy_unstable_byteorder,
                                                        (const guint8 *) d->ifname,
                                                        strlen(d->ifname))));
    }
}

/*****************************************************************************/

static void
_kernel_cmdline_match(gboolean           expected_match,
                      const char *const *proc_cmdline,
                      const char *const *patterns)
{
    gs_free_error GError *error   = NULL;
    GError **             p_error = nmtst_get_rand_bool() ? &error : NULL;
    gboolean              match;

    nm_assert(proc_cmdline);
    nm_assert(patterns);

    match = nm_utils_kernel_cmdline_match_check(proc_cmdline,
                                                patterns,
                                                NM_PTRARRAY_LEN(patterns),
                                                p_error);
    if (expected_match)
        nmtst_assert_success(match, error);
    else {
        g_assert(!p_error || error);
        g_assert(!match);
    }
}

static void
test_kernel_cmdline_match_check(void)
{
    _kernel_cmdline_match(TRUE, NM_MAKE_STRV(""), NM_MAKE_STRV(""));
    _kernel_cmdline_match(FALSE, NM_MAKE_STRV(""), NM_MAKE_STRV("a"));
    _kernel_cmdline_match(TRUE, NM_MAKE_STRV("a"), NM_MAKE_STRV("a"));
    _kernel_cmdline_match(TRUE, NM_MAKE_STRV("a=b"), NM_MAKE_STRV("a"));
    _kernel_cmdline_match(TRUE, NM_MAKE_STRV("a=b", "b"), NM_MAKE_STRV("a", "b"));
    _kernel_cmdline_match(TRUE, NM_MAKE_STRV("a=b", "b"), NM_MAKE_STRV("&a", "&b"));
    _kernel_cmdline_match(FALSE, NM_MAKE_STRV("a=b", "bc"), NM_MAKE_STRV("&a", "&b"));
    _kernel_cmdline_match(FALSE, NM_MAKE_STRV("a=b", "b"), NM_MAKE_STRV("&a", "&b", "c"));
    _kernel_cmdline_match(TRUE, NM_MAKE_STRV("a=b", "b"), NM_MAKE_STRV("&a", "&b", "b", "c"));
    _kernel_cmdline_match(TRUE, NM_MAKE_STRV("a=b", "b", "c=dd"), NM_MAKE_STRV("&a", "&b", "c"));
    _kernel_cmdline_match(FALSE, NM_MAKE_STRV("a", "b"), NM_MAKE_STRV("a", "&c"));
    _kernel_cmdline_match(TRUE, NM_MAKE_STRV("a", "b"), NM_MAKE_STRV("a", "|\\c"));
}

/*****************************************************************************/

static void
test_connectivity_state_cmp(void)
{
    NMConnectivityState a;

#define _cmp(a, b, cmp)                                                \
    G_STMT_START                                                       \
    {                                                                  \
        const NMConnectivityState _a   = (a);                          \
        const NMConnectivityState _b   = (b);                          \
        const int                 _cmp = (cmp);                        \
                                                                       \
        g_assert(NM_IN_SET(_cmp, -1, 0, 1));                           \
        g_assert_cmpint(nm_connectivity_state_cmp(_a, _b), ==, _cmp);  \
        g_assert_cmpint(nm_connectivity_state_cmp(_b, _a), ==, -_cmp); \
    }                                                                  \
    G_STMT_END

    for (a = NM_CONNECTIVITY_UNKNOWN; a <= NM_CONNECTIVITY_FULL; a++)
        _cmp(a, a, 0);

    _cmp(NM_CONNECTIVITY_UNKNOWN, NM_CONNECTIVITY_UNKNOWN, 0);
    _cmp(NM_CONNECTIVITY_UNKNOWN, NM_CONNECTIVITY_NONE, -1);
    _cmp(NM_CONNECTIVITY_UNKNOWN, NM_CONNECTIVITY_LIMITED, -1);
    _cmp(NM_CONNECTIVITY_UNKNOWN, NM_CONNECTIVITY_PORTAL, -1);
    _cmp(NM_CONNECTIVITY_UNKNOWN, NM_CONNECTIVITY_FULL, -1);

    _cmp(NM_CONNECTIVITY_NONE, NM_CONNECTIVITY_UNKNOWN, 1);
    _cmp(NM_CONNECTIVITY_NONE, NM_CONNECTIVITY_NONE, 0);
    _cmp(NM_CONNECTIVITY_NONE, NM_CONNECTIVITY_LIMITED, -1);
    _cmp(NM_CONNECTIVITY_NONE, NM_CONNECTIVITY_PORTAL, -1);
    _cmp(NM_CONNECTIVITY_NONE, NM_CONNECTIVITY_FULL, -1);

    _cmp(NM_CONNECTIVITY_LIMITED, NM_CONNECTIVITY_UNKNOWN, 1);
    _cmp(NM_CONNECTIVITY_LIMITED, NM_CONNECTIVITY_NONE, 1);
    _cmp(NM_CONNECTIVITY_LIMITED, NM_CONNECTIVITY_LIMITED, 0);
    _cmp(NM_CONNECTIVITY_LIMITED, NM_CONNECTIVITY_PORTAL, -1);
    _cmp(NM_CONNECTIVITY_LIMITED, NM_CONNECTIVITY_FULL, -1);

    _cmp(NM_CONNECTIVITY_PORTAL, NM_CONNECTIVITY_UNKNOWN, 1);
    _cmp(NM_CONNECTIVITY_PORTAL, NM_CONNECTIVITY_NONE, 1);
    _cmp(NM_CONNECTIVITY_PORTAL, NM_CONNECTIVITY_LIMITED, 1);
    _cmp(NM_CONNECTIVITY_PORTAL, NM_CONNECTIVITY_PORTAL, 0);
    _cmp(NM_CONNECTIVITY_PORTAL, NM_CONNECTIVITY_FULL, -1);

    _cmp(NM_CONNECTIVITY_FULL, NM_CONNECTIVITY_UNKNOWN, 1);
    _cmp(NM_CONNECTIVITY_FULL, NM_CONNECTIVITY_NONE, 1);
    _cmp(NM_CONNECTIVITY_FULL, NM_CONNECTIVITY_LIMITED, 1);
    _cmp(NM_CONNECTIVITY_FULL, NM_CONNECTIVITY_PORTAL, 1);
    _cmp(NM_CONNECTIVITY_FULL, NM_CONNECTIVITY_FULL, 0);

#undef _cmp
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init_with_logging(&argc, &argv, NULL, "ALL");

    g_test_add_func("/general/test_logging_domains", test_logging_domains);
    g_test_add_func("/general/test_logging_error", test_logging_error);

    g_test_add_func("/general/nm_utils_strbuf_append", test_nm_utils_strbuf_append);

    g_test_add_func("/general/nm_utils_ip6_address_clear_host_address",
                    test_nm_utils_ip6_address_clear_host_address);
    g_test_add_func("/general/nm_utils_ip6_address_same_prefix",
                    test_nm_utils_ip6_address_same_prefix);
    g_test_add_func("/general/nm_utils_log_connection_diff", test_nm_utils_log_connection_diff);

    g_test_add_func("/general/nm_utils_sysctl_ip_conf_path", test_nm_utils_sysctl_ip_conf_path);

    g_test_add_func("/general/exp10", test_nm_utils_exp10);

    g_test_add_func("/general/connection-match/basic", test_connection_match_basic);
    g_test_add_func("/general/connection-match/ip6-method", test_connection_match_ip6_method);
    g_test_add_func("/general/connection-match/ip6-method-ignore",
                    test_connection_match_ip6_method_ignore);
    g_test_add_func("/general/connection-match/ip6-method-ignore-auto",
                    test_connection_match_ip6_method_ignore_auto);
    g_test_add_func("/general/connection-match/ip4-method", test_connection_match_ip4_method);
    g_test_add_func("/general/connection-match/con-interface-name",
                    test_connection_match_interface_name);
    g_test_add_func("/general/connection-match/wired", test_connection_match_wired);
    g_test_add_func("/general/connection-match/wired2", test_connection_match_wired2);
    g_test_add_func("/general/connection-match/cloned_mac", test_connection_match_cloned_mac);
    g_test_add_func("/general/connection-match/no-match-ip4-addr",
                    test_connection_no_match_ip4_addr);
    g_test_add_func("/general/connection-match/no-match-vlan", test_connection_no_match_vlan);
    g_test_add_func("/general/connection-match/routes/ip4/1", test_connection_match_ip4_routes1);
    g_test_add_func("/general/connection-match/routes/ip4/2", test_connection_match_ip4_routes2);
    g_test_add_func("/general/connection-match/routes/ip6", test_connection_match_ip6_routes);

    g_test_add_func("/general/wildcard-match", test_wildcard_match);

    g_test_add_func("/general/connection-sort/autoconnect-priority",
                    test_connection_sort_autoconnect_priority);

    g_test_add_func("/general/match-spec/device", test_match_spec_device);
    g_test_add_func("/general/match-spec/config", test_match_spec_config);
    g_test_add_func("/general/duplicate_decl_specifier", test_duplicate_decl_specifier);

    g_test_add_func("/general/reverse_dns/ip4", test_reverse_dns_ip4);
    g_test_add_func("/general/reverse_dns/ip6", test_reverse_dns_ip6);

    g_test_add_func("/general/stable-id/parse", test_stable_id_parse);
    g_test_add_func("/general/stable-id/generated-complete", test_stable_id_generated_complete);

    g_test_add_func("/general/machine-id/read", test_machine_id_read);

    g_test_add_func("/general/test_utils_file_is_in_path", test_utils_file_is_in_path);

    g_test_add_func("/general/test_dns_create_resolv_conf", test_dns_create_resolv_conf);

    g_test_add_data_func("/general/nm_utils_dhcp_client_id_systemd_node_specific/0",
                         GINT_TO_POINTER(0),
                         test_nm_utils_dhcp_client_id_systemd_node_specific);
    g_test_add_data_func("/general/nm_utils_dhcp_client_id_systemd_node_specific/1",
                         GINT_TO_POINTER(1),
                         test_nm_utils_dhcp_client_id_systemd_node_specific);

    g_test_add_func("/core/general/test_connectivity_state_cmp", test_connectivity_state_cmp);
    g_test_add_func("/core/general/test_kernel_cmdline_match_check",
                    test_kernel_cmdline_match_check);

    return g_test_run();
}
