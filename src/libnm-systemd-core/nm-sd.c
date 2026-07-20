/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2014 - 2016 Red Hat, Inc.
 */

#include "libnm-systemd-core/nm-default-systemd-core.h"

#include "nm-sd.h"

#include "sd-event.h"

/*****************************************************************************
 * Integrating sd_event into glib. Taken and adjusted from
 * https://www.freedesktop.org/software/systemd/man/sd_event_get_fd.html
 *****************************************************************************/

typedef struct SDEventSource {
    GSource   source;
    GPollFD   pollfd;
    sd_event *event;
} SDEventSource;

static gboolean
event_prepare(GSource *source, int *timeout_)
{
    sd_event *event = ((SDEventSource *) source)->event;

    /* GLib does not guarantee that check() is always called between two
     * consecutive prepare() invocations. For example, if another thread
     * attaches/removes a source with poll fds to this GMainContext while
     * the main thread is inside poll(), context->poll_changed is set and
     * g_main_context_check_unlocked() returns immediately without calling
     * any source's check(). A similar skip can happen due to priority-
     * based filtering.
     *
     * If check() was skipped, the sd_event is still in SD_EVENT_ARMED
     * state.  Return FALSE to let the normal poll() -> check() -> dispatch()
     * path complete the cycle: the sd_event's epoll fd is already armed from
     * the previous sd_event_prepare(), so poll() will wake correctly and
     * event_check() will call sd_event_wait() to advance the state machine. */
    if (sd_event_get_state(event) == SD_EVENT_ARMED)
        return FALSE;

    return sd_event_prepare(event) > 0;
}

static gboolean
event_check(GSource *source)
{
    return sd_event_wait(((SDEventSource *) source)->event, 0) > 0;
}

static gboolean
event_dispatch(GSource *source, GSourceFunc callback, gpointer user_data)
{
    return sd_event_dispatch(((SDEventSource *) source)->event) > 0;
}

static void
event_finalize(GSource *source)
{
    SDEventSource *s = (SDEventSource *) source;

    sd_event_unref(s->event);
}

static SDEventSource *
event_create_source(sd_event *event)
{
    static const GSourceFuncs event_funcs = {
        .prepare  = event_prepare,
        .check    = event_check,
        .dispatch = event_dispatch,
        .finalize = event_finalize,
    };
    SDEventSource *source;
    gboolean       is_default_event = FALSE;
    int            r;

    if (!event) {
        is_default_event = TRUE;
        r                = sd_event_default(&event);
        if (r < 0)
            g_return_val_if_reached(NULL);
    }

    source = (SDEventSource *) g_source_new((GSourceFuncs *) &event_funcs, sizeof(SDEventSource));

    source->event = is_default_event ? g_steal_pointer(&event) : sd_event_ref(event);

    source->pollfd = (GPollFD) {
        .fd     = sd_event_get_fd(source->event),
        .events = G_IO_IN | G_IO_HUP | G_IO_ERR,
    };

    g_source_add_poll(&source->source, &source->pollfd);

    return source;
}

static guint
event_attach(sd_event *event, GMainContext *context)
{
    SDEventSource *source;
    guint          id;

    source = event_create_source(event);

    g_return_val_if_fail(source, 0);

    id = g_source_attach((GSource *) source, context);
    g_source_unref((GSource *) source);

    nm_assert(id != 0);
    return id;
}

guint
nm_sd_event_attach_default(void)
{
    return event_attach(NULL, NULL);
}

/*****************************************************************************/

/* ensure that defines in nm-sd.h correspond to the internal defines. */

#include "nm-sd-adapt-core.h"

/*****************************************************************************/
