/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-time-utils.h"

#include "nm-logging-fwd.h"

/*****************************************************************************/

typedef struct {
    /* the offset to the native clock, in seconds. */
    gint64    offset_sec;
    clockid_t clk_id;
} GlobalState;

static const GlobalState *volatile p_global_state;

static const GlobalState *
_t_init_global_state(void)
{
    static GlobalState global_state = {};
    static gsize       init_once    = 0;
    const GlobalState *p;
    clockid_t          clk_id;
    struct timespec    tp;
    gint64             offset_sec;
    int                r;

    clk_id = CLOCK_BOOTTIME;
    r      = clock_gettime(clk_id, &tp);
    if (r == -1 && errno == EINVAL) {
        clk_id = CLOCK_MONOTONIC;
        r      = clock_gettime(clk_id, &tp);
    }

    /* The only failure we tolerate is that CLOCK_BOOTTIME is not supported.
     * Other than that, we rely on kernel to not fail on this. */
    g_assert(r == 0);
    g_assert(tp.tv_nsec >= 0 && tp.tv_nsec < NM_UTILS_NSEC_PER_SEC);

    /* Calculate an offset for the time stamp.
     *
     * We always want positive values, because then we can initialize
     * a timestamp with 0 and be sure, that it will be less then any
     * value nm_utils_get_monotonic_timestamp_*() might return.
     * For this to be true also for nm_utils_get_monotonic_timestamp_sec() at
     * early boot, we have to shift the timestamp to start counting at
     * least from 1 second onward.
     *
     * Another advantage of shifting is, that this way we make use of the whole 31 bit
     * range of signed int, before the time stamp for nm_utils_get_monotonic_timestamp_sec()
     * wraps (~68 years).
     **/
    offset_sec = (-((gint64) tp.tv_sec)) + 1;

    if (!g_once_init_enter(&init_once)) {
        /* there was a race. We expect the pointer to be fully initialized now. */
        p = g_atomic_pointer_get(&p_global_state);
        g_assert(p);
        return p;
    }

    global_state.offset_sec = offset_sec;
    global_state.clk_id     = clk_id;
    p                       = &global_state;
    g_atomic_pointer_set(&p_global_state, p);
    g_once_init_leave(&init_once, 1);

    _nm_utils_monotonic_timestamp_initialized(&tp, p->offset_sec, p->clk_id == CLOCK_BOOTTIME);

    return p;
}

#define _t_get_global_state()                         \
    ({                                                \
        const GlobalState *_p;                        \
                                                      \
        _p = g_atomic_pointer_get(&p_global_state);   \
        (G_LIKELY(_p) ? _p : _t_init_global_state()); \
    })

#define _t_clock_gettime_eval(p, tp)                                          \
    ({                                                                        \
        struct timespec *const   _tp = (tp);                                  \
        const GlobalState *const _p2 = (p);                                   \
        int                      _r;                                          \
                                                                              \
        nm_assert(_tp);                                                       \
                                                                              \
        _r = clock_gettime(_p2->clk_id, _tp);                                 \
                                                                              \
        nm_assert(_r == 0);                                                   \
        nm_assert(_tp->tv_nsec >= 0 && _tp->tv_nsec < NM_UTILS_NSEC_PER_SEC); \
                                                                              \
        _p2;                                                                  \
    })

#define _t_clock_gettime(tp) _t_clock_gettime_eval(_t_get_global_state(), tp);

/*****************************************************************************/

/**
 * nm_utils_get_monotonic_timestamp_nsec:
 *
 * Returns: a monotonically increasing time stamp in nanoseconds,
 * starting at an unspecified offset. See clock_gettime(), %CLOCK_BOOTTIME.
 *
 * The returned value will start counting at an undefined point
 * in the past and will always be positive.
 *
 * All the nm_utils_get_monotonic_timestamp_*sec functions return the same
 * timestamp but in different scales (nsec, usec, msec, sec).
 **/
gint64
nm_utils_get_monotonic_timestamp_nsec(void)
{
    const GlobalState *p;
    struct timespec    tp;

    p = _t_clock_gettime(&tp);

    /* Although the result will always be positive, we return a signed
     * integer, which makes it easier to calculate time differences (when
     * you want to subtract signed values).
     **/
    return (((gint64) tp.tv_sec) + p->offset_sec) * NM_UTILS_NSEC_PER_SEC + tp.tv_nsec;
}

/**
 * nm_utils_get_monotonic_timestamp_usec:
 *
 * Returns: a monotonically increasing time stamp in microseconds,
 * starting at an unspecified offset. See clock_gettime(), %CLOCK_BOOTTIME.
 *
 * The returned value will start counting at an undefined point
 * in the past and will always be positive.
 *
 * All the nm_utils_get_monotonic_timestamp_*sec functions return the same
 * timestamp but in different scales (nsec, usec, msec, sec).
 **/
gint64
nm_utils_get_monotonic_timestamp_usec(void)
{
    const GlobalState *p;
    struct timespec    tp;

    p = _t_clock_gettime(&tp);

    /* Although the result will always be positive, we return a signed
     * integer, which makes it easier to calculate time differences (when
     * you want to subtract signed values).
     **/
    return (((gint64) tp.tv_sec) + p->offset_sec) * ((gint64) G_USEC_PER_SEC)
           + (tp.tv_nsec / (NM_UTILS_NSEC_PER_SEC / G_USEC_PER_SEC));
}

/**
 * nm_utils_get_monotonic_timestamp_msec:
 *
 * Returns: a monotonically increasing time stamp in milliseconds,
 * starting at an unspecified offset. See clock_gettime(), %CLOCK_BOOTTIME.
 *
 * The returned value will start counting at an undefined point
 * in the past and will always be positive.
 *
 * All the nm_utils_get_monotonic_timestamp_*sec functions return the same
 * timestamp but in different scales (nsec, usec, msec, sec).
 **/
gint64
nm_utils_get_monotonic_timestamp_msec(void)
{
    const GlobalState *p;
    struct timespec    tp;

    p = _t_clock_gettime(&tp);

    /* Although the result will always be positive, we return a signed
     * integer, which makes it easier to calculate time differences (when
     * you want to subtract signed values).
     **/
    return (((gint64) tp.tv_sec) + p->offset_sec) * ((gint64) 1000)
           + (tp.tv_nsec / (NM_UTILS_NSEC_PER_SEC / 1000));
}

/**
 * nm_utils_get_monotonic_timestamp_sec:
 *
 * Returns: nm_utils_get_monotonic_timestamp_msec() in seconds (throwing
 * away sub second parts). The returned value will always be positive.
 *
 * This value wraps after roughly 68 years which should be fine for any
 * practical purpose.
 *
 * All the nm_utils_get_monotonic_timestamp_*sec functions return the same
 * timestamp but in different scales (nsec, usec, msec, sec).
 **/
gint32
nm_utils_get_monotonic_timestamp_sec(void)
{
    const GlobalState *p;
    struct timespec    tp;

    p = _t_clock_gettime(&tp);

    return (((gint64) tp.tv_sec) + p->offset_sec);
}

/**
 * nm_utils_monotonic_timestamp_as_boottime:
 * @timestamp: the monotonic-timestamp that should be converted into CLOCK_BOOTTIME.
 * @timestamp_nsec_per_tick: How many nanoseconds make one unit of @timestamp? E.g. if
 *   @timestamp is in unit seconds, pass %NM_UTILS_NSEC_PER_SEC; if @timestamp is
 *   in nanoseconds, pass 1; if @timestamp is in milliseconds, pass %NM_UTILS_NSEC_PER_SEC/1000.
 *   This must be a multiple of 10, and between 1 and %NM_UTILS_NSEC_PER_SEC.
 *
 * Returns: the monotonic-timestamp as CLOCK_BOOTTIME, as returned by clock_gettime().
 *   The unit is the same as the passed in @timestamp based on @timestamp_nsec_per_tick.
 *   E.g. if you passed @timestamp in as seconds, it will return boottime in seconds.
 *
 *   Note that valid monotonic-timestamps are always positive numbers (counting roughly since
 *   the application is running). However, it might make sense to calculate a timestamp from
 *   before the application was running, hence negative @timestamp is allowed. The result
 *   in that case might also be a negative timestamp (in CLOCK_BOOTTIME), which would indicate
 *   that the timestamp lies in the past before the machine was booted.
 *
 * On older kernels that don't support CLOCK_BOOTTIME, the returned time is instead CLOCK_MONOTONIC.
 **/
gint64
nm_utils_monotonic_timestamp_as_boottime(gint64 timestamp, gint64 timestamp_nsec_per_tick)
{
    const GlobalState *p;
    gint64             offset;

    /* only support nsec-per-tick being a multiple of 10. */
    g_return_val_if_fail(timestamp_nsec_per_tick == 1
                             || (timestamp_nsec_per_tick > 0
                                 && timestamp_nsec_per_tick <= NM_UTILS_NSEC_PER_SEC
                                 && timestamp_nsec_per_tick % 10 == 0),
                         -1);

    /* if the caller didn't yet ever fetch a monotonic-timestamp, he cannot pass any meaningful
     * value (because he has no idea what these timestamps would be). That would be a bug. */
    nm_assert(g_atomic_pointer_get(&p_global_state));

    p = _t_get_global_state();

    nm_assert(p->offset_sec <= 0);

    /* calculate the offset of monotonic-timestamp to boottime. offset_s is <= 1. */
    offset = p->offset_sec * (NM_UTILS_NSEC_PER_SEC / timestamp_nsec_per_tick);

    nm_assert(offset <= 0 && offset > G_MININT64);

    /* check for overflow (note that offset is non-positive). */
    g_return_val_if_fail(timestamp < G_MAXINT64 + offset, G_MAXINT64);

    return timestamp - offset;
}

/**
 * nm_utils_monotonic_timestamp_from_boottime:
 * @boottime: the timestamp from CLOCK_BOOTTIME (or CLOCK_MONOTONIC, if
 *   kernel does not support CLOCK_BOOTTIME and monotonic timestamps are based
 *   on CLOCK_MONOTONIC).
 * @timestamp_nsec_per_tick: the scale in which @boottime is. If @boottime is in
 *   nano seconds, this should be 1. If it is in milli seconds, this should be
 *   %NM_UTILS_NSEC_PER_SEC/1000, etc.
 *
 * Returns: the same timestamp in monotonic timestamp scale.
 *
 * Note that commonly monotonic timestamps are positive. But they may not
 * be positive in this case. That's when boottime is taken from a time before
 * the monotonic timestamps started counting. So, that means a zero or negative
 * value is still a valid timestamp.
 *
 * This is the inverse of nm_utils_monotonic_timestamp_as_boottime().
 */
gint64
nm_utils_monotonic_timestamp_from_boottime(guint64 boottime, gint64 timestamp_nsec_per_tick)
{
    const GlobalState *p;
    gint64             offset;

    /* only support nsec-per-tick being a multiple of 10. */
    g_return_val_if_fail(timestamp_nsec_per_tick == 1
                             || (timestamp_nsec_per_tick > 0
                                 && timestamp_nsec_per_tick <= NM_UTILS_NSEC_PER_SEC
                                 && timestamp_nsec_per_tick % 10 == 0),
                         -1);

    p = _t_get_global_state();

    nm_assert(p->offset_sec <= 0);

    /* calculate the offset of monotonic-timestamp to boottime. offset_s is <= 1. */
    offset = p->offset_sec * (NM_UTILS_NSEC_PER_SEC / timestamp_nsec_per_tick);

    nm_assert(offset <= 0 && offset > G_MININT64);

    /* check for overflow (note that offset is non-positive). */
    g_return_val_if_fail(boottime < G_MAXINT64, G_MAXINT64);

    return (gint64) boottime + offset;
}

gint64
nm_utils_clock_gettime_nsec(clockid_t clockid)
{
    struct timespec tp;

    if (clock_gettime(clockid, &tp) != 0)
        return -NM_ERRNO_NATIVE(errno);
    return nm_utils_timespec_to_nsec(&tp);
}

gint64
nm_utils_clock_gettime_msec(clockid_t clockid)
{
    struct timespec tp;

    if (clock_gettime(clockid, &tp) != 0)
        return -NM_ERRNO_NATIVE(errno);
    return nm_utils_timespec_to_msec(&tp);
}
