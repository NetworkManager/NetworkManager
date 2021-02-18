/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_TIME_UTILS_H__
#define __NM_TIME_UTILS_H__

#include <time.h>

static inline gint64
nm_utils_timespec_to_nsec(const struct timespec *ts)
{
    return (((gint64) ts->tv_sec) * ((gint64) NM_UTILS_NSEC_PER_SEC)) + ((gint64) ts->tv_nsec);
}

static inline gint64
nm_utils_timespec_to_msec(const struct timespec *ts)
{
    return (((gint64) ts->tv_sec) * ((gint64) 1000))
           + (((gint64) ts->tv_nsec) / ((gint64) NM_UTILS_NSEC_PER_SEC / 1000));
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
nm_utils_get_monotonic_timestamp_msec_cached(gint64 *cache_now)
{
    return (*cache_now) ?: (*cache_now = nm_utils_get_monotonic_timestamp_msec());
}

gint64 nm_utils_clock_gettime_nsec(clockid_t clockid);
gint64 nm_utils_clock_gettime_msec(clockid_t clockid);

#endif /* __NM_TIME_UTILS_H__ */
