/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2012 Colin Walters <walters@verbum.org>
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
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "config.h"

#include "gsystem-local-alloc.h"

void
gs_local_free (void *loc)
{
  void **location = loc;
  if (location)
    g_free (*location);
}

#define _gs_local_free(type, function) do {           \
    void **location = loc;                            \
    if (location)                                     \
      {                                               \
        type *value = *location;                      \
        if (value)                                    \
          function (value);                           \
      }                                               \
  } while (0)

void
gs_local_obj_unref (void *loc)
{
  _gs_local_free(GObject, g_object_unref);
}

void
gs_local_variant_unref (void *loc)
{
  _gs_local_free(GVariant, g_variant_unref);
}

void
gs_local_ptrarray_unref (void *loc)
{
  _gs_local_free(GPtrArray, g_ptr_array_unref);
}

void
gs_local_hashtable_unref (void *loc)
{
  _gs_local_free(GHashTable, g_hash_table_unref);
}
