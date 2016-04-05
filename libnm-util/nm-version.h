/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2011 Red Hat, Inc.
 */

#ifndef NM_VERSION_H
#define NM_VERSION_H

#include <glib.h>

#include <nm-version-macros.h>

/* Deprecation / Availability macros */

#if !defined (NM_VERSION_MIN_REQUIRED) || (NM_VERSION_MIN_REQUIRED == 0)
# undef NM_VERSION_MIN_REQUIRED
# define NM_VERSION_MIN_REQUIRED (NM_VERSION_CUR_STABLE)
#endif

#if !defined (NM_VERSION_MAX_ALLOWED) || (NM_VERSION_MAX_ALLOWED == 0)
# undef NM_VERSION_MAX_ALLOWED
# define NM_VERSION_MAX_ALLOWED (NM_VERSION_CUR_STABLE)
#endif

/* sanity checks */
#if NM_VERSION_MIN_REQUIRED > NM_VERSION_NEXT_STABLE
#error "NM_VERSION_MIN_REQUIRED must be <= NM_VERSION_NEXT_STABLE"
#endif
#if NM_VERSION_MAX_ALLOWED < NM_VERSION_MIN_REQUIRED
#error "NM_VERSION_MAX_ALLOWED must be >= NM_VERSION_MIN_REQUIRED"
#endif
#if NM_VERSION_MIN_REQUIRED < NM_VERSION_0_9_8
#error "NM_VERSION_MIN_REQUIRED must be >= NM_VERSION_0_9_8"
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_0_9_10
# define NM_DEPRECATED_IN_0_9_10        G_DEPRECATED
# define NM_DEPRECATED_IN_0_9_10_FOR(f) G_DEPRECATED_FOR(f)
#else
# define NM_DEPRECATED_IN_0_9_10
# define NM_DEPRECATED_IN_0_9_10_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_0_9_10
# define NM_AVAILABLE_IN_0_9_10         G_UNAVAILABLE(0.9,10)
#else
# define NM_AVAILABLE_IN_0_9_10
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_0
# define NM_DEPRECATED_IN_1_0           G_DEPRECATED
# define NM_DEPRECATED_IN_1_0_FOR(f)    G_DEPRECATED_FOR(f)
#else
# define NM_DEPRECATED_IN_1_0
# define NM_DEPRECATED_IN_1_0_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_0
# define NM_AVAILABLE_IN_1_0            G_UNAVAILABLE(1,0)
#else
# define NM_AVAILABLE_IN_1_0
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_2
# define NM_DEPRECATED_IN_1_2           G_DEPRECATED
# define NM_DEPRECATED_IN_1_2_FOR(f)    G_DEPRECATED_FOR(f)
#else
# define NM_DEPRECATED_IN_1_2
# define NM_DEPRECATED_IN_1_2_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_2
# define NM_AVAILABLE_IN_1_2            G_UNAVAILABLE(1,2)
#else
# define NM_AVAILABLE_IN_1_2
#endif

#if NM_VERSION_MIN_REQUIRED >= NM_VERSION_1_4
# define NM_DEPRECATED_IN_1_4           G_DEPRECATED
# define NM_DEPRECATED_IN_1_4_FOR(f)    G_DEPRECATED_FOR(f)
#else
# define NM_DEPRECATED_IN_1_4
# define NM_DEPRECATED_IN_1_4_FOR(f)
#endif

#if NM_VERSION_MAX_ALLOWED < NM_VERSION_1_4
# define NM_AVAILABLE_IN_1_4            G_UNAVAILABLE(1,4)
#else
# define NM_AVAILABLE_IN_1_4
#endif

#endif  /* NM_VERSION_H */
