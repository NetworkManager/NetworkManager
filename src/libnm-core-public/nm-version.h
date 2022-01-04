/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2011, 2015 Red Hat, Inc.
 */

#ifndef NM_VERSION_H
#define NM_VERSION_H

#include <glib.h>

#include "nm-version-macros.h"

/* Deprecation / Availability macros */

#if !defined(NM_VERSION_MIN_REQUIRED) || (NM_VERSION_MIN_REQUIRED == 0)
#undef NM_VERSION_MIN_REQUIRED
#define NM_VERSION_MIN_REQUIRED (NM_API_VERSION)
#endif

#if !defined(NM_VERSION_MAX_ALLOWED) || (NM_VERSION_MAX_ALLOWED == 0)
#undef NM_VERSION_MAX_ALLOWED
#define NM_VERSION_MAX_ALLOWED (NM_API_VERSION)
#endif

/* sanity checks */
#if NM_VERSION_MIN_REQUIRED > NM_API_VERSION
#error "NM_VERSION_MIN_REQUIRED must be <= NM_API_VERSION"
#endif
#if NM_VERSION_MAX_ALLOWED < NM_VERSION_MIN_REQUIRED
#error "NM_VERSION_MAX_ALLOWED must be >= NM_VERSION_MIN_REQUIRED"
#endif
#if NM_VERSION_MIN_REQUIRED < NM_VERSION_0_9_8
#error "NM_VERSION_MIN_REQUIRED must be >= NM_VERSION_0_9_8"
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_0_9_10
#define NM_DEPRECATED_IN_0_9_10        G_DEPRECATED
#define NM_DEPRECATED_IN_0_9_10_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_0_9_10
#define NM_DEPRECATED_IN_0_9_10_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_0_9_10
#define NM_AVAILABLE_IN_0_9_10 G_UNAVAILABLE(0.9, 10)
#else
#define NM_AVAILABLE_IN_0_9_10
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_0
#define NM_DEPRECATED_IN_1_0        G_DEPRECATED
#define NM_DEPRECATED_IN_1_0_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_0
#define NM_DEPRECATED_IN_1_0_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_0
#define NM_AVAILABLE_IN_1_0 G_UNAVAILABLE(1, 0)
#else
#define NM_AVAILABLE_IN_1_0
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_2
#define NM_DEPRECATED_IN_1_2        G_DEPRECATED
#define NM_DEPRECATED_IN_1_2_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_2
#define NM_DEPRECATED_IN_1_2_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_2
#define NM_AVAILABLE_IN_1_2 G_UNAVAILABLE(1, 2)
#else
#define NM_AVAILABLE_IN_1_2
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_4
#define NM_DEPRECATED_IN_1_4        G_DEPRECATED
#define NM_DEPRECATED_IN_1_4_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_4
#define NM_DEPRECATED_IN_1_4_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_4
#define NM_AVAILABLE_IN_1_4 G_UNAVAILABLE(1, 4)
#else
#define NM_AVAILABLE_IN_1_4
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_6
#define NM_DEPRECATED_IN_1_6        G_DEPRECATED
#define NM_DEPRECATED_IN_1_6_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_6
#define NM_DEPRECATED_IN_1_6_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_6
#define NM_AVAILABLE_IN_1_6 G_UNAVAILABLE(1, 6)
#else
#define NM_AVAILABLE_IN_1_6
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_8
#define NM_DEPRECATED_IN_1_8        G_DEPRECATED
#define NM_DEPRECATED_IN_1_8_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_8
#define NM_DEPRECATED_IN_1_8_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_8
#define NM_AVAILABLE_IN_1_8 G_UNAVAILABLE(1, 8)
#else
#define NM_AVAILABLE_IN_1_8
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_10
#define NM_DEPRECATED_IN_1_10        G_DEPRECATED
#define NM_DEPRECATED_IN_1_10_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_10
#define NM_DEPRECATED_IN_1_10_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_10
#define NM_AVAILABLE_IN_1_10 G_UNAVAILABLE(1, 10)
#else
#define NM_AVAILABLE_IN_1_10
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_12
#define NM_DEPRECATED_IN_1_12        G_DEPRECATED
#define NM_DEPRECATED_IN_1_12_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_12
#define NM_DEPRECATED_IN_1_12_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_12
#define NM_AVAILABLE_IN_1_12 G_UNAVAILABLE(1, 12)
#else
#define NM_AVAILABLE_IN_1_12
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_14
#define NM_DEPRECATED_IN_1_14        G_DEPRECATED
#define NM_DEPRECATED_IN_1_14_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_14
#define NM_DEPRECATED_IN_1_14_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_14
#define NM_AVAILABLE_IN_1_14 G_UNAVAILABLE(1, 14)
#else
#define NM_AVAILABLE_IN_1_14
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_16
#define NM_DEPRECATED_IN_1_16        G_DEPRECATED
#define NM_DEPRECATED_IN_1_16_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_16
#define NM_DEPRECATED_IN_1_16_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_16
#define NM_AVAILABLE_IN_1_16 G_UNAVAILABLE(1, 16)
#else
#define NM_AVAILABLE_IN_1_16
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_18
#define NM_DEPRECATED_IN_1_18        G_DEPRECATED
#define NM_DEPRECATED_IN_1_18_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_18
#define NM_DEPRECATED_IN_1_18_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_18
#define NM_AVAILABLE_IN_1_18 G_UNAVAILABLE(1, 18)
#else
#define NM_AVAILABLE_IN_1_18
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_20
#define NM_DEPRECATED_IN_1_20        G_DEPRECATED
#define NM_DEPRECATED_IN_1_20_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_20
#define NM_DEPRECATED_IN_1_20_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_20
#define NM_AVAILABLE_IN_1_20 G_UNAVAILABLE(1, 20)
#else
#define NM_AVAILABLE_IN_1_20
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_22
#define NM_DEPRECATED_IN_1_22        G_DEPRECATED
#define NM_DEPRECATED_IN_1_22_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_22
#define NM_DEPRECATED_IN_1_22_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_22
#define NM_AVAILABLE_IN_1_22 G_UNAVAILABLE(1, 22)
#else
#define NM_AVAILABLE_IN_1_22
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_24
#define NM_DEPRECATED_IN_1_24        G_DEPRECATED
#define NM_DEPRECATED_IN_1_24_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_24
#define NM_DEPRECATED_IN_1_24_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_24
#define NM_AVAILABLE_IN_1_24 G_UNAVAILABLE(1, 24)
#else
#define NM_AVAILABLE_IN_1_24
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_26
#define NM_DEPRECATED_IN_1_26        G_DEPRECATED
#define NM_DEPRECATED_IN_1_26_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_26
#define NM_DEPRECATED_IN_1_26_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_26
#define NM_AVAILABLE_IN_1_26 G_UNAVAILABLE(1, 26)
#else
#define NM_AVAILABLE_IN_1_26
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_28
#define NM_DEPRECATED_IN_1_28        G_DEPRECATED
#define NM_DEPRECATED_IN_1_28_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_28
#define NM_DEPRECATED_IN_1_28_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_28
#define NM_AVAILABLE_IN_1_28 G_UNAVAILABLE(1, 28)
#else
#define NM_AVAILABLE_IN_1_28
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_30
#define NM_DEPRECATED_IN_1_30        G_DEPRECATED
#define NM_DEPRECATED_IN_1_30_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_30
#define NM_DEPRECATED_IN_1_30_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_30
#define NM_AVAILABLE_IN_1_30 G_UNAVAILABLE(1, 30)
#else
#define NM_AVAILABLE_IN_1_30
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_32
#define NM_DEPRECATED_IN_1_32        G_DEPRECATED
#define NM_DEPRECATED_IN_1_32_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_32
#define NM_DEPRECATED_IN_1_32_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_32
#define NM_AVAILABLE_IN_1_32 G_UNAVAILABLE(1, 32)
#else
#define NM_AVAILABLE_IN_1_32
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_34
#define NM_DEPRECATED_IN_1_34        G_DEPRECATED
#define NM_DEPRECATED_IN_1_34_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_34
#define NM_DEPRECATED_IN_1_34_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_34
#define NM_AVAILABLE_IN_1_34 G_UNAVAILABLE(1, 34)
#else
#define NM_AVAILABLE_IN_1_34
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_36
#define NM_DEPRECATED_IN_1_36        G_DEPRECATED
#define NM_DEPRECATED_IN_1_36_FOR(f) G_DEPRECATED_FOR(f)
#else
#define NM_DEPRECATED_IN_1_36
#define NM_DEPRECATED_IN_1_36_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_36
#define NM_AVAILABLE_IN_1_36 G_UNAVAILABLE(1, 36)
#else
#define NM_AVAILABLE_IN_1_36
#endif

/*
 * Synchronous API for calling D-Bus in libnm is deprecated. See
 * https://developer.gnome.org/libnm/stable/usage.html#sync-api
 *
 * Note that "deprecated" here does not really mean that the API is going
 * to be removed. We don't break API. Just comment that it is awkward and
 * discouraged. The user may:
 *
 *   - continue to use this API. It's deprecated, awkward and discouraged,
 *     but if it works for you, that's fine.
 *
 *   - use asynchronous API. That's the only sensible way to use D-Bus.
 *     If libnm lacks a certain asynchronous counterpart, it should be
 *     added.
 *
 *   - use GDBusConnection directly. There really isn't anything wrong
 *     with D-Bus or GDBusConnection. This deprecated API is just a wrapper
 *     around g_dbus_connection_call_sync(). You may call it directly
 *     without feeling dirty.
 *
 * The API is marked as deprecated since 1.22, however the macro only starts
 * complaining in 1.24. That's intentional, because in 1.22 the asynchronous
 * alternative was not yet available.
 */
#define _NM_DEPRECATED_SYNC_METHOD            NM_DEPRECATED_IN_1_24
#define _NM_DEPRECATED_SYNC_WRITABLE_PROPERTY /* NM_DEPRECATED_IN_1_22 */

#endif /* NM_VERSION_H */
