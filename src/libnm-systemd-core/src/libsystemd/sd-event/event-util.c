/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nm-sd-adapt-core.h"

#include <errno.h>

#include "event-source.h"
#include "event-util.h"
#include "fd-util.h"
#include "log.h"
#include "string-util.h"

int event_reset_time(
                sd_event *e,
                sd_event_source **s,
                clockid_t clock,
                uint64_t usec,
                uint64_t accuracy,
                sd_event_time_handler_t callback,
                void *userdata,
                int64_t priority,
                const char *description,
                bool force_reset) {

        bool created = false;
        int enabled, r;
        clockid_t c;

        assert(e);
        assert(s);

        if (*s) {
                if (!force_reset) {
                        r = sd_event_source_get_enabled(*s, &enabled);
                        if (r < 0)
                                return log_debug_errno(r, "sd-event: Failed to query whether event source \"%s\" is enabled or not: %m",
                                                       strna((*s)->description ?: description));

                        if (enabled != SD_EVENT_OFF)
                                return 0;
                }

                r = sd_event_source_get_time_clock(*s, &c);
                if (r < 0)
                        return log_debug_errno(r, "sd-event: Failed to get clock id of event source \"%s\": %m", strna((*s)->description ?: description));

                if (c != clock)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "sd-event: Current clock id %i of event source \"%s\" is different from specified one %i.",
                                               (int)c,
                                               strna((*s)->description ? : description),
                                               (int)clock);

                r = sd_event_source_set_time(*s, usec);
                if (r < 0)
                        return log_debug_errno(r, "sd-event: Failed to set time for event source \"%s\": %m", strna((*s)->description ?: description));

                r = sd_event_source_set_time_accuracy(*s, accuracy);
                if (r < 0)
                        return log_debug_errno(r, "sd-event: Failed to set accuracy for event source \"%s\": %m", strna((*s)->description ?: description));

                /* callback function is not updated, as we do not have sd_event_source_set_time_callback(). */

                (void) sd_event_source_set_userdata(*s, userdata);

                r = sd_event_source_set_enabled(*s, SD_EVENT_ONESHOT);
                if (r < 0)
                        return log_debug_errno(r, "sd-event: Failed to enable event source \"%s\": %m", strna((*s)->description ?: description));
        } else {
                r = sd_event_add_time(e, s, clock, usec, accuracy, callback, userdata);
                if (r < 0)
                        return log_debug_errno(r, "sd-event: Failed to create timer event \"%s\": %m", strna(description));

                created = true;
        }

        r = sd_event_source_set_priority(*s, priority);
        if (r < 0)
                return log_debug_errno(r, "sd-event: Failed to set priority for event source \"%s\": %m", strna((*s)->description ?: description));

        if (description) {
                r = sd_event_source_set_description(*s, description);
                if (r < 0)
                        return log_debug_errno(r, "sd-event: Failed to set description for event source \"%s\": %m", description);
        }

        return created;
}

int event_reset_time_relative(
                sd_event *e,
                sd_event_source **s,
                clockid_t clock,
                uint64_t usec,
                uint64_t accuracy,
                sd_event_time_handler_t callback,
                void *userdata,
                int64_t priority,
                const char *description,
                bool force_reset) {

        usec_t usec_now;
        int r;

        assert(e);

        r = sd_event_now(e, clock, &usec_now);
        if (r < 0)
                return log_debug_errno(r, "sd-event: Failed to get the current time: %m");

        return event_reset_time(e, s, clock, usec_add(usec_now, usec), accuracy, callback, userdata, priority, description, force_reset);
}

int event_source_disable(sd_event_source *s) {
        if (!s)
                return 0;

        return sd_event_source_set_enabled(s, SD_EVENT_OFF);
}

int event_source_is_enabled(sd_event_source *s) {
        if (!s)
                return false;

        return sd_event_source_get_enabled(s, NULL);
}

#if 0 /* NM_IGNORED */
int event_add_time_change(sd_event *e, sd_event_source **ret, sd_event_io_handler_t callback, void *userdata) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        assert(e);

        /* Allocates an IO event source that gets woken up whenever the clock changes. Needs to be recreated on each event */

        fd = time_change_fd();
        if (fd < 0)
                return fd;

        r = sd_event_add_io(e, &s, fd, EPOLLIN, callback, userdata);
        if (r < 0)
                return r;

        r = sd_event_source_set_io_fd_own(s, true);
        if (r < 0)
                return r;

        TAKE_FD(fd);

        r = sd_event_source_set_description(s, "time-change");
        if (r < 0)
                return r;

        if (ret)
                *ret = TAKE_PTR(s);
        else {
                r = sd_event_source_set_floating(s, true);
                if (r < 0)
                        return r;
        }

        return 0;
}
#endif /* NM_IGNORED */
