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

#ifndef __NM_TIME_UTILS_H__
#define __NM_TIME_UTILS_H__

gint64 nm_utils_get_monotonic_timestamp_ns (void);
gint64 nm_utils_get_monotonic_timestamp_us (void);
gint64 nm_utils_get_monotonic_timestamp_ms (void);
gint32 nm_utils_get_monotonic_timestamp_s (void);
gint64 nm_utils_monotonic_timestamp_as_boottime (gint64 timestamp, gint64 timestamp_ticks_per_ns);

static inline gint64
nm_utils_get_monotonic_timestamp_ns_cached (gint64 *cache_now)
{
	return    (*cache_now)
	       ?: (*cache_now = nm_utils_get_monotonic_timestamp_ns ());
}

struct timespec;

/* this function must be implemented to handle the notification when
 * the first monotonic-timestamp is fetched. */
extern void _nm_utils_monotonic_timestamp_initialized (const struct timespec *tp,
                                                       gint64 offset_sec,
                                                       gboolean is_boottime);

#endif /* __NM_TIME_UTILS_H__ */
