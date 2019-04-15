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
 * Copyright 2017, 2018 Red Hat, Inc.
 */
#ifndef __NM_JSON_H__
#define __NM_JSON_H__

gboolean nm_jansson_load (void);

#ifndef NM_JANSSON_C
#define json_object_iter_value  (*_nm_jansson_json_object_iter_value)
#define json_object_key_to_iter (*_nm_jansson_json_object_key_to_iter)
#define json_integer            (*_nm_jansson_json_integer)
#define json_object_del         (*_nm_jansson_json_object_del)
#define json_array_get          (*_nm_jansson_json_array_get)
#define json_array_size         (*_nm_jansson_json_array_size)
#define json_array_append_new   (*_nm_jansson_json_array_append_new)
#define json_string             (*_nm_jansson_json_string)
#define json_object_iter_next   (*_nm_jansson_json_object_iter_next)
#define json_loads              (*_nm_jansson_json_loads)
#define json_dumps              (*_nm_jansson_json_dumps)
#define json_object_iter_key    (*_nm_jansson_json_object_iter_key)
#define json_object             (*_nm_jansson_json_object)
#define json_object_get         (*_nm_jansson_json_object_get)
#define json_array              (*_nm_jansson_json_array)
#define json_false              (*_nm_jansson_json_false)
#define json_delete             (*_nm_jansson_json_delete)
#define json_true               (*_nm_jansson_json_true)
#define json_object_size        (*_nm_jansson_json_object_size)
#define json_object_set_new     (*_nm_jansson_json_object_set_new)
#define json_object_iter        (*_nm_jansson_json_object_iter)
#define json_integer_value      (*_nm_jansson_json_integer_value)
#define json_string_value       (*_nm_jansson_json_string_value)

#include "nm-glib-aux/nm-jansson.h"
#endif

#endif /* __NM_JSON_H__ */
