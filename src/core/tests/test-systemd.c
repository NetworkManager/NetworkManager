/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2016 Red Hat, Inc.
 */

#include "libnm-systemd-core/nm-default-systemd-core.h"

#include "libnm-systemd-core/nm-sd.h"
#include "libnm-systemd-shared/nm-sd-utils-shared.h"

#include "libnm-glib-aux/nm-test-utils.h"

/*****************************************************************************/

typedef struct {
    GMainLoop       *mainloop;
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
        sd_event       *other_events[3] = {NULL}, *event = NULL;
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

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init(&argc, &argv, TRUE);

    g_test_add_func("/systemd/sd-event", test_sd_event);

    return g_test_run();
}
