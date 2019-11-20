// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_TIME_UTILS_H__
#define __NM_TIME_UTILS_H__

#include <time.h>

static inline gint64
nm_utils_timespec_to_ns (const struct timespec *ts)
{
	return   (((gint64) ts->tv_sec) * ((gint64) NM_UTILS_NS_PER_SECOND))
	       +  ((gint64) ts->tv_nsec);
}

static inline gint64
nm_utils_timespec_to_ms (const struct timespec *ts)
{
	return   (((gint64) ts->tv_sec)  * ((gint64) 1000))
	       + (((gint64) ts->tv_nsec) / ((gint64) NM_UTILS_NS_PER_SECOND / 1000));
}

gint64 nm_utils_get_monotonic_timestamp_ns (void);
gint64 nm_utils_get_monotonic_timestamp_us (void);
gint64 nm_utils_get_monotonic_timestamp_ms (void);
gint32 nm_utils_get_monotonic_timestamp_s (void);
gint64 nm_utils_monotonic_timestamp_as_boottime (gint64 timestamp, gint64 timestamp_ticks_per_ns);
gint64 nm_utils_monotonic_timestamp_from_boottime (guint64 boottime, gint64 timestamp_ns_per_tick);

static inline gint64
nm_utils_get_monotonic_timestamp_ns_cached (gint64 *cache_now)
{
	return    (*cache_now)
	       ?: (*cache_now = nm_utils_get_monotonic_timestamp_ns ());
}

gint64 nm_utils_clock_gettime_ns (clockid_t clockid);
gint64 nm_utils_clock_gettime_ms (clockid_t clockid);

#endif /* __NM_TIME_UTILS_H__ */
