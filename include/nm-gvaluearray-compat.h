/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NM_GVALUEARRAY_COMPAT_H
#define NM_GVALUEARRAY_COMPAT_H

#include <glib.h>

#define g_value_array_get_type() \
  G_GNUC_EXTENSION ({ \
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
    g_value_array_get_type (); \
    G_GNUC_END_IGNORE_DEPRECATIONS \
  })

#define g_value_array_get_nth(value_array, index_) \
  G_GNUC_EXTENSION ({ \
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
    g_value_array_get_nth (value_array, index_); \
    G_GNUC_END_IGNORE_DEPRECATIONS \
  })

#define g_value_array_new(n_prealloced) \
  G_GNUC_EXTENSION ({ \
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
    g_value_array_new (n_prealloced); \
    G_GNUC_END_IGNORE_DEPRECATIONS \
  })

#define g_value_array_free(value_array) \
  G_GNUC_EXTENSION ({ \
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
    g_value_array_free (value_array); \
    G_GNUC_END_IGNORE_DEPRECATIONS \
  })

#define g_value_array_copy(value_array) \
  G_GNUC_EXTENSION ({ \
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
    g_value_array_copy (value_array); \
    G_GNUC_END_IGNORE_DEPRECATIONS \
  })

#define g_value_array_prepend(value_array, value) \
  G_GNUC_EXTENSION ({ \
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
    g_value_array_prepend (value_array, value); \
    G_GNUC_END_IGNORE_DEPRECATIONS \
  })

#define g_value_array_append(value_array, value) \
  G_GNUC_EXTENSION ({ \
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
    g_value_array_append (value_array, value); \
    G_GNUC_END_IGNORE_DEPRECATIONS \
  })

#define g_value_array_insert(value_array, index_, value) \
  G_GNUC_EXTENSION ({ \
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
    g_value_array_insert (value_array, index_, value); \
    G_GNUC_END_IGNORE_DEPRECATIONS \
  })

#define g_value_array_remove(value_array, index_) \
  G_GNUC_EXTENSION ({ \
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
    g_value_array_remove (value_array, index_); \
    G_GNUC_END_IGNORE_DEPRECATIONS \
  })

#define g_value_array_sort(value_array, compare_func) \
  G_GNUC_EXTENSION ({ \
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
    g_value_array_sort (value_array, compare_func); \
    G_GNUC_END_IGNORE_DEPRECATIONS \
  })

#define g_value_array_sort_with_data(value_array, compare_func, user_data) \
  G_GNUC_EXTENSION ({ \
    G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
    g_value_array_sort_with_data (value_array, compare_func, user_data); \
    G_GNUC_END_IGNORE_DEPRECATIONS \
  })

#endif  /* NM_GVALUEARRAY_COMPAT_H */
