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

#include "nm-default.h"

#include "nm-json.h"

#include <dlfcn.h>

typedef struct {
	NMJsonVt vt;
	void *dl_handle;
} JsonVt;

static JsonVt *
json_vt (void)
{
	JsonVt *vt = NULL;
	void *handle;

	vt = g_new0 (JsonVt, 1);

	handle = dlopen (JANSSON_SONAME, RTLD_LAZY | RTLD_LOCAL | RTLD_NODELETE | RTLD_DEEPBIND);
	if (!handle)
		return vt;

#define TRY_BIND_SYMBOL(symbol) \
	G_STMT_START { \
		void *_sym = dlsym (handle, "json" #symbol); \
		\
		if (!_sym) \
			goto fail_symbol; \
		vt->vt.nm_json ## symbol = _sym; \
	} G_STMT_END

	TRY_BIND_SYMBOL (_array);
	TRY_BIND_SYMBOL (_array_append_new);
	TRY_BIND_SYMBOL (_array_get);
	TRY_BIND_SYMBOL (_array_size);
	TRY_BIND_SYMBOL (_delete);
	TRY_BIND_SYMBOL (_dumps);
	TRY_BIND_SYMBOL (_false);
	TRY_BIND_SYMBOL (_integer);
	TRY_BIND_SYMBOL (_integer_value);
	TRY_BIND_SYMBOL (_loads);
	TRY_BIND_SYMBOL (_object);
	TRY_BIND_SYMBOL (_object_del);
	TRY_BIND_SYMBOL (_object_get);
	TRY_BIND_SYMBOL (_object_iter);
	TRY_BIND_SYMBOL (_object_iter_key);
	TRY_BIND_SYMBOL (_object_iter_next);
	TRY_BIND_SYMBOL (_object_iter_value);
	TRY_BIND_SYMBOL (_object_key_to_iter);
	TRY_BIND_SYMBOL (_object_set_new);
	TRY_BIND_SYMBOL (_object_size);
	TRY_BIND_SYMBOL (_string);
	TRY_BIND_SYMBOL (_string_value);
	TRY_BIND_SYMBOL (_true);

	vt->vt.loaded = TRUE;
	vt->dl_handle = handle;
	return vt;

fail_symbol:
	dlclose (&handle);
	memset (vt, 0, sizeof (*vt));
	return vt;
}

const NMJsonVt *
nm_json_vt (void)
{
	static JsonVt *vt_ptr = NULL;
	JsonVt *vt;

	vt = g_atomic_pointer_get (&vt_ptr);
	if (G_LIKELY (vt))
		goto out;

	vt = json_vt ();
	if (!g_atomic_pointer_compare_and_exchange (&vt_ptr, NULL, vt)) {
		if (vt->dl_handle)
			dlclose (vt->dl_handle);
		g_free (vt);
		vt = g_atomic_pointer_get (&vt_ptr);
		goto out;
	}

out:
	nm_assert (vt && vt == g_atomic_pointer_get (&vt_ptr));
	return &vt->vt;
}

#define DEF_FCN(name, rval, args_t, args_v) \
rval name args_t \
{ \
	const NMJsonVt *vt = nm_json_vt (); \
	\
	nm_assert (vt && vt->loaded && vt->name); \
	nm_assert (vt->name != name); \
	return (vt->name) args_v; \
}

#define DEF_VOI(name, args_t, args_v) \
void name args_t \
{ \
	const NMJsonVt *vt = nm_json_vt (); \
	\
	nm_assert (vt && vt->loaded && vt->name); \
	nm_assert (vt->name != name); \
	(vt->name) args_v; \
}

DEF_FCN (nm_json_array,              json_t *,     (void), ());
DEF_FCN (nm_json_array_append_new,   int,          (json_t *json, json_t *value), (json, value));
DEF_FCN (nm_json_array_get,          json_t *,     (const json_t *json, size_t index), (json, index));
DEF_FCN (nm_json_array_size,         size_t,       (const json_t *json), (json));
DEF_VOI (nm_json_delete,                           (json_t *json), (json));
DEF_FCN (nm_json_dumps,              char *,       (const json_t *json, size_t flags), (json, flags));
DEF_FCN (nm_json_false,              json_t *,     (void), ());
DEF_FCN (nm_json_integer,            json_t *,     (json_int_t value),              (value));
DEF_FCN (nm_json_integer_value,      json_int_t,   (const json_t *json), (json));
DEF_FCN (nm_json_loads,              json_t *,     (const char *string, size_t flags, json_error_t *error), (string, flags, error));
DEF_FCN (nm_json_object,             json_t *,     (void), ());
DEF_FCN (nm_json_object_del,         int,          (json_t *json, const char *key), (json, key));
DEF_FCN (nm_json_object_get,         json_t *,     (const json_t *json, const char *key), (json, key));
DEF_FCN (nm_json_object_iter,        void *,       (json_t *json), (json));
DEF_FCN (nm_json_object_iter_key,    const char *, (void *iter), (iter));
DEF_FCN (nm_json_object_iter_next,   void *,       (json_t *json, void *iter), (json, iter));
DEF_FCN (nm_json_object_iter_value,  json_t *,     (void *iter),                    (iter));
DEF_FCN (nm_json_object_key_to_iter, void *,       (const char *key),               (key));
DEF_FCN (nm_json_object_set_new,     int,          (json_t *json, const char *key, json_t *value), (json, key, value));
DEF_FCN (nm_json_object_size,        size_t,       (const json_t *json), (json));
DEF_FCN (nm_json_string,             json_t *,     (const char *value), (value));
DEF_FCN (nm_json_string_value,       const char *, (const json_t *json), (json));
DEF_FCN (nm_json_true,               json_t *,     (void), ());
