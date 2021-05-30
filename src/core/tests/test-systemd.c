/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2016 Red Hat, Inc.
 */

#include "libnm-systemd-core/nm-default-systemd-core.h"

#include "libnm-systemd-core/nm-sd.h"
#include "libnm-systemd-shared/nm-sd-utils-shared.h"

#include "libnm-glib-aux/nm-test-utils.h"

/*****************************************************************************/

static void
test_dhcp_create(void)
{
    sd_dhcp_client *client4 = NULL;
    int             r;

    r = sd_dhcp_client_new(&client4, FALSE);
    g_assert(r == 0);
    g_assert(client4);

    if (/* never true */ client4 == (gpointer) &r) {
        /* we don't want to call this, but ensure that the linker
         * includes all these symbols. */
        sd_dhcp_client_start(client4);
    }

    sd_dhcp_client_unref(client4);
}

/*****************************************************************************/

static void
test_lldp_create(void)
{
    sd_lldp *lldp = NULL;
    int      r;

    r = sd_lldp_new(&lldp);
    g_assert(r == 0);
    g_assert(lldp);

    sd_lldp_unref(lldp);
}

/*****************************************************************************/

typedef struct {
    GMainLoop *      mainloop;
    sd_event_source *event_source;
} TestSdEventData;

static int
_test_sd_event_timeout_cb(sd_event_source *s, uint64_t usec, void *userdata)
{
    TestSdEventData *user_data = userdata;

    g_assert(user_data);
    g_assert(user_data->mainloop);
    g_assert(user_data->event_source);

    user_data->event_source = sd_event_source_unref(user_data->event_source);
    g_main_loop_quit(user_data->mainloop);
    return 0;
}

static void
test_sd_event(void)
{
    int repeat;

    for (repeat = 0; repeat < 2; repeat++) {
        guint           sd_id = 0;
        int             r;
        int             i, n;
        sd_event *      other_events[3] = {NULL}, *event = NULL;
        TestSdEventData user_data = {0};

        g_assert_cmpint(sd_event_default(NULL), ==, 0);

        for (i = 0, n = (nmtst_get_rand_uint32() % (G_N_ELEMENTS(other_events) + 1)); i < n; i++) {
            r = sd_event_default(&other_events[i]);
            g_assert(r >= 0 && other_events[i]);
        }

        sd_id = nm_sd_event_attach_default();

        r = sd_event_default(&event);
        g_assert(r >= 0 && event);

        r = sd_event_add_time(event,
                              &user_data.event_source,
                              CLOCK_MONOTONIC,
                              1,
                              0,
                              _test_sd_event_timeout_cb,
                              &user_data);
        g_assert(r >= 0 && user_data.event_source);

        user_data.mainloop = g_main_loop_new(NULL, FALSE);
        g_main_loop_run(user_data.mainloop);
        g_main_loop_unref(user_data.mainloop);

        g_assert(!user_data.event_source);

        event = sd_event_unref(event);
        for (i = 0, n = (nmtst_get_rand_uint32() % (G_N_ELEMENTS(other_events) + 1)); i < n; i++)
            other_events[i] = sd_event_unref(other_events[i]);
        nm_clear_g_source(&sd_id);
        for (i = 0, n = G_N_ELEMENTS(other_events); i < n; i++)
            other_events[i] = sd_event_unref(other_events[i]);

        g_assert_cmpint(sd_event_default(NULL), ==, 0);
    }
}

/*****************************************************************************/

static void
test_path_equal(void)
{
#define _path_equal_check(path, expected)                \
    G_STMT_START                                         \
    {                                                    \
        const char *  _path0    = (path);                \
        const char *  _expected = (expected);            \
        gs_free char *_path     = g_strdup(_path0);      \
        const char *  _path_result;                      \
                                                         \
        _path_result = nm_sd_utils_path_simplify(_path); \
        g_assert(_path_result == _path);                 \
        g_assert_cmpstr(_path, ==, _expected);           \
    }                                                    \
    G_STMT_END

    _path_equal_check("", "");
    _path_equal_check(".", ".");
    _path_equal_check("..", "..");
    _path_equal_check("/..", "/..");
    _path_equal_check("//..", "/..");
    _path_equal_check("/.", "/");
    _path_equal_check("./", ".");
    _path_equal_check("./.", ".");
    _path_equal_check(".///.", ".");
    _path_equal_check(".///./", ".");
    _path_equal_check(".////", ".");
    _path_equal_check("//..//foo/", "/../foo");
    _path_equal_check("///foo//./bar/.", "/foo/bar");
    _path_equal_check(".//./foo//./bar/.", "foo/bar");
}

/*****************************************************************************/

static void
_test_unbase64char(char ch, gboolean maybe_invalid)
{
    int r;

    r = nm_sd_utils_unbase64char(ch, FALSE);

    if (ch == '=') {
        g_assert(!maybe_invalid);
        g_assert_cmpint(r, <, 0);
        g_assert_cmpint(nm_sd_utils_unbase64char(ch, TRUE), ==, G_MAXINT);
    } else {
        g_assert_cmpint(r, ==, nm_sd_utils_unbase64char(ch, TRUE));
        if (r >= 0)
            g_assert_cmpint(r, <=, 255);
        if (!maybe_invalid)
            g_assert_cmpint(r, >=, 0);
    }
}

static void
_test_unbase64mem_mem(const char *base64, const guint8 *expected_arr, gsize expected_len)
{
    gs_free char *expected_base64 = NULL;
    int           r;
    nm_auto_free guint8 *exp2_arr = NULL;
    nm_auto_free guint8 *exp3_arr = NULL;
    gsize                exp2_len;
    gsize                exp3_len;
    gsize                i;

    expected_base64 = g_base64_encode(expected_arr, expected_len);

    for (i = 0; expected_base64[i]; i++)
        _test_unbase64char(expected_base64[i], FALSE);

    r = nm_sd_utils_unbase64mem(expected_base64,
                                strlen(expected_base64),
                                TRUE,
                                &exp2_arr,
                                &exp2_len);
    g_assert_cmpint(r, ==, 0);
    g_assert_cmpmem(expected_arr, expected_len, exp2_arr, exp2_len);

    if (!nm_streq(base64, expected_base64)) {
        r = nm_sd_utils_unbase64mem(base64, strlen(base64), TRUE, &exp3_arr, &exp3_len);
        g_assert_cmpint(r, ==, 0);
        g_assert_cmpmem(expected_arr, expected_len, exp3_arr, exp3_len);
    }
}

#define _test_unbase64mem(base64, expected_str) \
    _test_unbase64mem_mem(base64, (const guint8 *) "" expected_str "", NM_STRLEN(expected_str))

static void
_test_unbase64mem_inval(const char *base64)
{
    gs_free guint8 *exp_arr = NULL;
    gsize           exp_len = 0;
    int             r;

    r = nm_sd_utils_unbase64mem(base64, strlen(base64), TRUE, &exp_arr, &exp_len);
    g_assert_cmpint(r, <, 0);
    g_assert(!exp_arr);
    g_assert(exp_len == 0);
}

static void
test_nm_sd_utils_unbase64mem(void)
{
    gs_free char *rnd_base64 = NULL;
    guint8        rnd_buf[30];
    guint         i, rnd_len;

    _test_unbase64mem("", "");
    _test_unbase64mem("  ", "");
    _test_unbase64mem(" Y Q == ", "a");
    _test_unbase64mem(" Y   WJjZGV mZ 2g = ", "abcdefgh");
    _test_unbase64mem_inval(" Y   %WJjZGV mZ 2g = ");
    _test_unbase64mem_inval(" Y   %WJjZGV mZ 2g = a");
    _test_unbase64mem("YQ==", "a");
    _test_unbase64mem_inval("YQ==a");

    rnd_len = nmtst_get_rand_uint32() % sizeof(rnd_buf);
    for (i = 0; i < rnd_len; i++)
        rnd_buf[i] = nmtst_get_rand_uint32() % 256;
    rnd_base64 = g_base64_encode(rnd_buf, rnd_len);
    _test_unbase64mem_mem(rnd_base64, rnd_buf, rnd_len);

    _test_unbase64char('=', FALSE);
    for (i = 0; i < 10; i++) {
        char ch = nmtst_get_rand_uint32() % 256;

        if (ch != '=')
            _test_unbase64char(ch, TRUE);
    }
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init(&argc, &argv, TRUE);

    g_test_add_func("/systemd/dhcp/create", test_dhcp_create);
    g_test_add_func("/systemd/lldp/create", test_lldp_create);
    g_test_add_func("/systemd/sd-event", test_sd_event);
    g_test_add_func("/systemd/test_path_equal", test_path_equal);
    g_test_add_func("/systemd/test_nm_sd_utils_unbase64mem", test_nm_sd_utils_unbase64mem);

    return g_test_run();
}
