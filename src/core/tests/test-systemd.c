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

static void
test_http_url_is_valid_https(void)
{
    /* CVE-2026-10805: connection.mud-url is pasted verbatim into the dhclient
     * config inside a quoted string ("send mudurl \"%s\";"). This function
     * gates the property at verify() time, so it must reject characters that
     * break out of the quotes or inject config syntax. */
#define _assert_valid(url)   g_assert(nm_sd_http_url_is_valid_https("" url))
#define _assert_invalid(url) g_assert(!nm_sd_http_url_is_valid_https("" url))

    _assert_valid("https://example.com/mud.json");
    _assert_valid("https://example.com");
    _assert_valid("https://example.com/a?b=c&d=e#frag");
    _assert_valid("https://[2001:db8::1]/x");
    _assert_valid("https://user@example.com/~p/(a)*,;=+!$'");
    _assert_valid("https://user:pass@example.com/p%20q?x=%2F");

    _assert_invalid("http://example.com");
    _assert_invalid("ftp://example.com");
    _assert_invalid("example.com");
    _assert_invalid("");
    _assert_invalid("https://");

    _assert_invalid("https://example.com/\""); /* breaks out of the quoted string */
    _assert_invalid("https://example.com/\\"); /* escapes the following char */
    _assert_invalid("https://example.com/\n");
    _assert_invalid("https://example.com/\t");
    _assert_invalid("https://example.com/a\x01b");
    _assert_invalid("https://example.com/\xc3\xa4"); /* non-ASCII */

#undef _assert_valid
#undef _assert_invalid
}

/*****************************************************************************/

static gpointer
_test_check_skip_thread_func(gpointer user_data)
{
    /* Wait a little so the main thread is likely blocked inside poll()
     * (which releases the GMainContext lock).  Then attach a source with
     * poll fds to the default context.  g_source_attach() calls
     * g_main_context_add_poll_unlocked() which sets context->poll_changed
     * and wakes up the poll via g_wakeup_signal().
     *
     * When the main thread re-enters g_main_context_check_unlocked() and
     * sees poll_changed, it returns immediately without calling any
     * source's check() callback -- including sd_event's. */
    GSource *source;
    GPollFD  pollfd;
    int      pipefd[2];

    g_usleep(G_USEC_PER_SEC / 10);

    g_assert(pipe(pipefd) == 0);

    source         = g_source_new((GSourceFuncs *) &(const GSourceFuncs) {0}, sizeof(GSource));
    pollfd.fd      = pipefd[0];
    pollfd.events  = G_IO_IN;
    pollfd.revents = 0;
    g_source_add_poll(source, &pollfd);
    g_source_attach(source, NULL);
    g_source_destroy(source);
    g_source_unref(source);

    nm_close(pipefd[0]);
    nm_close(pipefd[1]);

    return NULL;
}

static void
test_sd_event_check_skip(void)
{
    /* Regression test for sd_event GSource check() being skipped.
     *
     * The sd_event GSource adapter (nm-sd.c) wraps sd_event in prepare/
     * check/dispatch callbacks that advance an internal state machine:
     *   prepare  -> sd_event_prepare()  (INITIAL -> ARMED)
     *   check    -> sd_event_wait()     (ARMED   -> INITIAL | PENDING)
     *   dispatch -> sd_event_dispatch() (PENDING -> INITIAL)
     *
     * GLib releases the GMainContext lock during poll().  If another thread
     * attaches a source with poll fds at that moment, it sets
     * context->poll_changed.  When g_main_context_check_unlocked() sees
     * this flag, it bails out immediately without calling any source's
     * check().  The sd_event stays in ARMED state, and the next prepare()
     * hits assert(state == INITIAL).
     *
     * This is exactly what happens when GIO creates a GDBusProxy on the
     * default main context from a non-main thread (e.g. during
     * connectivity checks): the D-Bus socket source attachment races
     * with the main thread's event loop.
     *
     * Reproduce by blocking the main thread in poll() and having a helper
     * thread attach a source with a poll fd. */
    GSource *sd_source nm_auto_destroy_and_unref_gsource = NULL;
    GThread           *thread;
    int                i;

    {
        guint sd_id;

        sd_id     = nm_sd_event_attach_default();
        sd_source = g_main_context_find_source_by_id(NULL, sd_id);
        g_assert(sd_source);
        g_source_ref(sd_source);
    }

    for (i = 0; i < 5; i++) {
        thread = g_thread_new("check-skip", _test_check_skip_thread_func, NULL);

        /* Blocking iteration: the main thread enters poll() with the context
         * lock released.  The helper thread's g_source_attach() sets
         * poll_changed and wakes us up. */
        g_main_context_iteration(NULL, TRUE);

        g_thread_join(thread);

        /* Non-blocking iteration: sd_event is still ARMED from the previous
         * iteration where check() was skipped.  Without the fix, this
         * crashes in sd_event_prepare(). */
        g_main_context_iteration(NULL, FALSE);
    }
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init(&argc, &argv, TRUE);

    g_test_add_func("/systemd/sd-event", test_sd_event);
    g_test_add_func("/systemd/sd-event/check-skip", test_sd_event_check_skip);
    g_test_add_func("/systemd/http-url-is-valid-https", test_http_url_is_valid_https);

    return g_test_run();
}
