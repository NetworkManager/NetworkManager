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

/* Added in Jansson v2.7 */
#ifndef json_boolean_value
#define json_boolean_value json_is_true
#endif

/* Added in Jansson v2.8 */
#ifndef json_object_foreach_safe
#define json_object_foreach_safe(object, n, key, value)     \
    for (key = json_object_iter_key(json_object_iter(object)), \
             n = json_object_iter_next(object, json_object_key_to_iter(key)); \
         key && (value = json_object_iter_value(json_object_key_to_iter(key))); \
         key = json_object_iter_key(n), \
             n = json_object_iter_next(object, json_object_key_to_iter(key)))
#endif

NM_AUTO_DEFINE_FCN0 (json_t *, _nm_auto_decref_json, json_decref)
#define nm_auto_decref_json nm_auto(_nm_auto_decref_json)

#endif /* WITH_JANSON */

#endif  /* __NM_JANSSON_H__ */
