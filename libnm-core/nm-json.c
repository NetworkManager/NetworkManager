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
		typeof (symbol) (*_sym) = dlsym (handle, #symbol); \
		\
		if (!_sym) \
			goto fail_symbol; \
		vt->vt.nm_##symbol = _sym; \
	} G_STMT_END

	TRY_BIND_SYMBOL (json_array);
	TRY_BIND_SYMBOL (json_array_append_new);
	TRY_BIND_SYMBOL (json_array_get);
	TRY_BIND_SYMBOL (json_array_size);
	TRY_BIND_SYMBOL (json_delete);
	TRY_BIND_SYMBOL (json_dumps);
	TRY_BIND_SYMBOL (json_false);
	TRY_BIND_SYMBOL (json_integer);
	TRY_BIND_SYMBOL (json_integer_value);
	TRY_BIND_SYMBOL (json_loads);
	TRY_BIND_SYMBOL (json_object);
	TRY_BIND_SYMBOL (json_object_del);
	TRY_BIND_SYMBOL (json_object_get);
	TRY_BIND_SYMBOL (json_object_iter);
	TRY_BIND_SYMBOL (json_object_iter_at);
	TRY_BIND_SYMBOL (json_object_iter_key);
	TRY_BIND_SYMBOL (json_object_iter_next);
	TRY_BIND_SYMBOL (json_object_iter_value);
#if JANSSON_VERSION_HEX >= 0x020300
	TRY_BIND_SYMBOL (json_object_key_to_iter);
#endif
	TRY_BIND_SYMBOL (json_object_set_new);
	TRY_BIND_SYMBOL (json_object_size);
	TRY_BIND_SYMBOL (json_string);
	TRY_BIND_SYMBOL (json_string_value);
	TRY_BIND_SYMBOL (json_true);

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
