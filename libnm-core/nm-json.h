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

#define json_array              nm_json_array
#define json_array_append_new   nm_json_array_append_new
#define json_array_get          nm_json_array_get
#define json_array_size         nm_json_array_size
#define json_delete             nm_json_delete
#define json_dumps              nm_json_dumps
#define json_false              nm_json_false
#define json_integer            nm_json_integer
#define json_integer_value      nm_json_integer_value
#define json_loads              nm_json_loads
#define json_object             nm_json_object
#define json_object_del         nm_json_object_del
#define json_object_get         nm_json_object_get
#define json_object_iter        nm_json_object_iter
#define json_object_iter_key    nm_json_object_iter_key
#define json_object_iter_next   nm_json_object_iter_next
#define json_object_iter_value  nm_json_object_iter_value
#define json_object_key_to_iter nm_json_object_key_to_iter
#define json_object_set_new     nm_json_object_set_new
#define json_object_size        nm_json_object_size
#define json_string             nm_json_string
#define json_string_value       nm_json_string_value
#define json_true               nm_json_true

#include "nm-utils/nm-jansson.h"

typedef struct {
	gboolean loaded;
	json_t     *(*nm_json_array)              (void);
	int         (*nm_json_array_append_new)   (json_t *json, json_t *value);
	json_t     *(*nm_json_array_get)          (const json_t *json, size_t index);
	size_t      (*nm_json_array_size)         (const json_t *json);
	void        (*nm_json_delete)             (json_t *json);
	char       *(*nm_json_dumps)              (const json_t *json, size_t flags);
	json_t     *(*nm_json_false)              (void);
	json_t     *(*nm_json_integer)            (json_int_t value);
	json_int_t  (*nm_json_integer_value)      (const json_t *json);
	json_t     *(*nm_json_loads)              (const char *string, size_t flags, json_error_t *error);
	json_t     *(*nm_json_object)             (void);
	int         (*nm_json_object_del)         (json_t *json, const char *key);
	json_t     *(*nm_json_object_get)         (const json_t *json, const char *key);
	void       *(*nm_json_object_iter)        (json_t *json);
	const char *(*nm_json_object_iter_key)    (void *iter);
	void       *(*nm_json_object_iter_next)   (json_t *json, void *iter);
	json_t     *(*nm_json_object_iter_value)  (void *);
	void       *(*nm_json_object_key_to_iter) (const char *key);
	int         (*nm_json_object_set_new)     (json_t *json, const char *key, json_t *value);
	size_t      (*nm_json_object_size)        (const json_t *json);
	json_t     *(*nm_json_string)             (const char *value);
	const char *(*nm_json_string_value)       (const json_t *json);
	json_t     *(*nm_json_true)               (void);
} NMJsonVt;

const NMJsonVt *nm_json_vt (void);

static inline gboolean
nm_json_init (const NMJsonVt **out_vt)
{
	const NMJsonVt *vt;

	vt = nm_json_vt ();
	NM_SET_OUT (out_vt, vt);
	return vt->loaded;
}

#define nm_json_boolean(vt, val) \
	((val) ? (vt)->nm_json_true () : (vt)->nm_json_false ())

static inline void
nm_json_decref (const NMJsonVt *vt, json_t *json)
{
	if(json && json->refcount != (size_t)-1 && --json->refcount == 0)
		vt->nm_json_delete (json);
}

/*****************************************************************************/

/* the following are implemented as pure macros in jansson.h.
 * They can be used directly, however, add a nm_json* variant,
 * to make it explict we don't accidentally use jansson ABI. */

#define nm_json_is_boolean(json)                json_is_boolean (json)
#define nm_json_is_integer(json)                json_is_integer (json)
#define nm_json_is_string(json)                 json_is_string (json)
#define nm_json_is_object(json)                 json_is_object (json)
#define nm_json_is_array(json)                  json_is_array (json)
#define nm_json_is_true(json)                   json_is_true (json)
#define nm_json_boolean_value(json)             json_boolean_value (json)
#define nm_json_array_foreach(a, b, c)          json_array_foreach (a, b, c)
#define nm_json_object_foreach(a, b, c)         json_object_foreach (a, b, c)
#define nm_json_object_foreach_safe(a, b, c, d) json_object_foreach_safe (a, b, c, d)

#endif /* __NM_JSON_H__ */
