/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_TIME_UTILS_H__
#define __NM_TIME_UTILS_H__

#include <time.h>

_nm_always_inline static inline gint64
_nm_utils_timespec_to_xsec(const struct timespec *ts, gint64 xsec_per_sec)
{
    nm_assert(ts);

    if (ts->tv_sec < 0 || ts->tv_nsec < 0)
        return G_MAXINT64;

    if (ts->tv_sec > ((guint64) G_MAXINT64) || ts->tv_nsec > ((guint64) G_MAXINT64)
        || ts->tv_sec >= (G_MAXINT64 - ((gint64) ts->tv_nsec)) / xsec_per_sec)
        return G_MAXINT64;

    return (((gint64) ts->tv_sec) * xsec_per_sec)
           + (((gint64) ts->tv_nsec) / (NM_UTILS_NSEC_PER_SEC / xsec_per_sec));
}

static inline gint64
nm_utils_timespec_to_nsec(const struct timespec *ts)
{
    return _nm_utils_timespec_to_xsec(ts, NM_UTILS_NSEC_PER_SEC);
}

static inline gint64
nm_utils_timespec_to_usec(const struct timespec *ts)
{
    return _nm_utils_timespec_to_xsec(ts, NM_UTILS_USEC_PER_SEC);
}

static inline gint64
nm_utils_timespec_to_msec(const struct timespec *ts)
{
    return _nm_utils_timespec_to_xsec(ts, NM_UTILS_MSEC_PER_SEC);
}

gint64 nm_utils_get_monotonic_timestamp_nsec(void);
gint64 nm_utils_get_monotonic_timestamp_usec(void);
gint64 nm_utils_get_monotonic_timestamp_msec(void);
gint32 nm_utils_get_monotonic_timestamp_sec(void);

gint64 nm_utils_monotonic_timestamp_as_boottime(gint64 timestamp, gint64 timestamp_ticks_per_nsec);
gint64 nm_utils_monotonic_timestamp_from_boottime(guint64 boottime, gint64 timestamp_nsec_per_tick);

static inline gint64
nm_utils_get_monotonic_timestamp_nsec_cached(gint64 *cache_now)
{
    return (*cache_now) ?: (*cache_now = nm_utils_get_monotonic_timestamp_nsec());
}

static inline gint64
nm_utils_get_monotonic_timestamp_usec_cached(gint64 *cache_now)
{
    return (*cache_now) ?: (*cache_now = nm_utils_get_monotonic_timestamp_usec());
}

static inline gint64
nm_utils_get_monotonic_timestamp_msec_cached(gint64 *cache_now)
{
    return (*cache_now) ?: (*cache_now = nm_utils_get_monotonic_timestamp_msec());
}

static inline gint32
nm_utils_get_monotonic_timestamp_sec_cached(gint32 *cache_now)
{
    return (*cache_now) ?: (*cache_now = nm_utils_get_monotonic_timestamp_sec());
}

gint64 nm_utils_clock_gettime_nsec(clockid_t clockid);
gint64 nm_utils_clock_gettime_usec(clockid_t clockid);
gint64 nm_utils_clock_gettime_msec(clockid_t clockid);

gint64 nm_time_map_clock(gint64 from, gint64 from_base, gint64 to_base);

#endif /* __NM_TIME_UTILS_H__ */
