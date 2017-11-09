/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2018 Red Hat, Inc.
 */

#ifndef __NM_JANSSON_H__
#define __NM_JANSSON_H__

/* you need to include at least "config.h" first, possibly "nm-default.h". */

#if WITH_JANSSON

#include <jansson.h>

/* Added in Jansson v2.3 (released Jan 27 2012) */
#ifndef json_object_foreach
#define json_object_foreach(object, key, value) \
    for(key = json_object_iter_key(json_object_iter(object)); \
        key && (value = json_object_iter_value(json_object_key_to_iter(key))); \
        key = json_object_iter_key(json_object_iter_next(object, json_object_key_to_iter(key))))
#endif

/* Added in Jansson v2.4 (released Sep 23 2012), but travis.ci has v2.2. */
#ifndef json_boolean
#define json_boolean(val) ((val) ? json_true() : json_false())
#endif

/* Added in Jansson v2.5 (released Sep 19 2013), but travis.ci has v2.2. */
#ifndef json_array_foreach
#define json_array_foreach(array, index, value) \
	for (index = 0; \
	     index < json_array_size(array) && (value = json_array_get(array, index)); \
	     index++)
#endif

/* Added in Jansson v2.8 */
#ifndef json_object_foreach_safe
#define json_object_foreach_safe(object, n, key, value) \
    for (key = json_object_iter_key (json_object_iter (object)), \
         n = json_object_iter_next (object, json_object_iter_at (object, key)); \
         key && (value = json_object_iter_value (json_object_iter_at (object, key))); \
         key = json_object_iter_key (n), \
         n = json_object_iter_next (object, json_object_iter_at (object, key)))
#endif

#endif /* WITH_JANSON */

#endif  /* __NM_JANSSON_H__ */
