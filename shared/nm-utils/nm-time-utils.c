/* NetworkManager -- Network link manager
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-time-utils.h"

/*****************************************************************************/

static gint64 monotonic_timestamp_offset_sec;
static int monotonic_timestamp_clock_mode = 0;

static void
monotonic_timestamp_get (struct timespec *tp)
{
	int clock_mode = 0;
	int err = 0;

	switch (monotonic_timestamp_clock_mode) {
	case 0:
		/* the clock is not yet initialized (first run) */
		err = clock_gettime (CLOCK_BOOTTIME, tp);
		if (err == -1 && errno == EINVAL) {
			clock_mode = 2;
			err = clock_gettime (CLOCK_MONOTONIC, tp);
		} else
			clock_mode = 1;
		break;
	case 1:
		/* default, return CLOCK_BOOTTIME */
		err = clock_gettime (CLOCK_BOOTTIME, tp);
		break;
	case 2:
		/* fallback, return CLOCK_MONOTONIC. Kernels prior to 2.6.39
		 * (released on 18 May, 2011) don't support CLOCK_BOOTTIME. */
		err = clock_gettime (CLOCK_MONOTONIC, tp);
		break;
	}

	g_assert (err == 0); (void)err;
	g_assert (tp->tv_nsec >= 0 && tp->tv_nsec < NM_UTILS_NS_PER_SECOND);

	if (G_LIKELY (clock_mode == 0))
		return;

	/* Calculate an offset for the time stamp.
	 *
	 * We always want positive values, because then we can initialize
	 * a timestamp with 0 and be sure, that it will be less then any
	 * value nm_utils_get_monotonic_timestamp_*() might return.
	 * For this to be true also for nm_utils_get_monotonic_timestamp_s() at
	 * early boot, we have to shift the timestamp to start counting at
	 * least from 1 second onward.
	 *
	 * Another advantage of shifting is, that this way we make use of the whole 31 bit
	 * range of signed int, before the time stamp for nm_utils_get_monotonic_timestamp_s()
	 * wraps (~68 years).
	 **/
	monotonic_timestamp_offset_sec = (- ((gint64) tp->tv_sec)) + 1;
	monotonic_timestamp_clock_mode = clock_mode;

	_nm_utils_monotonic_timestamp_initialized (tp, monotonic_timestamp_offset_sec, clock_mode == 1);
}

/**
 * nm_utils_get_monotonic_timestamp_ns:
 *
 * Returns: a monotonically increasing time stamp in nanoseconds,
 * starting at an unspecified offset. See clock_gettime(), %CLOCK_BOOTTIME.
 *
 * The returned value will start counting at an undefined point
 * in the past and will always be positive.
 *
 * All the nm_utils_get_monotonic_timestamp_*s functions return the same
 * timestamp but in different scales (nsec, usec, msec, sec).
 **/
gint64
nm_utils_get_monotonic_timestamp_ns (void)
{
	struct timespec tp = { 0 };

	monotonic_timestamp_get (&tp);

	/* Although the result will always be positive, we return a signed
	 * integer, which makes it easier to calculate time differences (when
	 * you want to subtract signed values).
	 **/
	return (((gint64) tp.tv_sec) + monotonic_timestamp_offset_sec) * NM_UTILS_NS_PER_SECOND +
	       tp.tv_nsec;
}

/**
 * nm_utils_get_monotonic_timestamp_us:
 *
 * Returns: a monotonically increasing time stamp in microseconds,
 * starting at an unspecified offset. See clock_gettime(), %CLOCK_BOOTTIME.
 *
 * The returned value will start counting at an undefined point
 * in the past and will always be positive.
 *
 * All the nm_utils_get_monotonic_timestamp_*s functions return the same
 * timestamp but in different scales (nsec, usec, msec, sec).
 **/
gint64
nm_utils_get_monotonic_timestamp_us (void)
{
	struct timespec tp = { 0 };

	monotonic_timestamp_get (&tp);

	/* Although the result will always be positive, we return a signed
	 * integer, which makes it easier to calculate time differences (when
	 * you want to subtract signed values).
	 **/
	return (((gint64) tp.tv_sec) + monotonic_timestamp_offset_sec) * ((gint64) G_USEC_PER_SEC) +
	       (tp.tv_nsec / (NM_UTILS_NS_PER_SECOND/G_USEC_PER_SEC));
}

/**
 * nm_utils_get_monotonic_timestamp_ms:
 *
 * Returns: a monotonically increasing time stamp in milliseconds,
 * starting at an unspecified offset. See clock_gettime(), %CLOCK_BOOTTIME.
 *
 * The returned value will start counting at an undefined point
 * in the past and will always be positive.
 *
 * All the nm_utils_get_monotonic_timestamp_*s functions return the same
 * timestamp but in different scales (nsec, usec, msec, sec).
 **/
gint64
nm_utils_get_monotonic_timestamp_ms (void)
{
	struct timespec tp = { 0 };

	monotonic_timestamp_get (&tp);

	/* Although the result will always be positive, we return a signed
	 * integer, which makes it easier to calculate time differences (when
	 * you want to subtract signed values).
	 **/
	return (((gint64) tp.tv_sec) + monotonic_timestamp_offset_sec) * ((gint64) 1000) +
	       (tp.tv_nsec / (NM_UTILS_NS_PER_SECOND/1000));
}

/**
 * nm_utils_get_monotonic_timestamp_s:
 *
 * Returns: nm_utils_get_monotonic_timestamp_ms() in seconds (throwing
 * away sub second parts). The returned value will always be positive.
 *
 * This value wraps after roughly 68 years which should be fine for any
 * practical purpose.
 *
 * All the nm_utils_get_monotonic_timestamp_*s functions return the same
 * timestamp but in different scales (nsec, usec, msec, sec).
 **/
gint32
nm_utils_get_monotonic_timestamp_s (void)
{
	struct timespec tp = { 0 };

	monotonic_timestamp_get (&tp);
	return (((gint64) tp.tv_sec) + monotonic_timestamp_offset_sec);
}

/**
 * nm_utils_monotonic_timestamp_as_boottime:
 * @timestamp: the monotonic-timestamp that should be converted into CLOCK_BOOTTIME.
 * @timestamp_ns_per_tick: How many nano seconds make one unit of @timestamp? E.g. if
 * @timestamp is in unit seconds, pass %NM_UTILS_NS_PER_SECOND; @timestamp in nano
 * seconds, pass 1; @timestamp in milli seconds, pass %NM_UTILS_NS_PER_SECOND/1000; etc.
 *
 * Returns: the monotonic-timestamp as CLOCK_BOOTTIME, as returned by clock_gettime().
 * The unit is the same as the passed in @timestamp basd on @timestamp_ns_per_tick.
 * E.g. if you passed @timestamp in as seconds, it will return boottime in seconds.
 * If @timestamp is a non-positive, it returns -1. Note that a (valid) monotonic-timestamp
 * is always positive.
 *
 * On older kernels that don't support CLOCK_BOOTTIME, the returned time is instead CLOCK_MONOTONIC.
 **/
gint64
nm_utils_monotonic_timestamp_as_boottime (gint64 timestamp, gint64 timestamp_ns_per_tick)
{
	gint64 offset;

	/* only support ns-per-tick being a multiple of 10. */
	g_return_val_if_fail (timestamp_ns_per_tick == 1
	                      || (timestamp_ns_per_tick > 0 &&
	                          timestamp_ns_per_tick <= NM_UTILS_NS_PER_SECOND &&
	                          timestamp_ns_per_tick % 10 == 0),
	                      -1);

	/* Check that the timestamp is in a valid range. */
	g_return_val_if_fail (timestamp >= 0, -1);

	/* if the caller didn't yet ever fetch a monotonic-timestamp, he cannot pass any meaningful
	 * value (because he has no idea what these timestamps would be). That would be a bug. */
	g_return_val_if_fail (monotonic_timestamp_clock_mode != 0, -1);

	/* calculate the offset of monotonic-timestamp to boottime. offset_s is <= 1. */
	offset = monotonic_timestamp_offset_sec * (NM_UTILS_NS_PER_SECOND / timestamp_ns_per_tick);

	/* check for overflow. */
	g_return_val_if_fail (offset > 0 || timestamp < G_MAXINT64 + offset, G_MAXINT64);

	return timestamp - offset;
}


