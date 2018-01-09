// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2017, 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-json.h"

#include <dlfcn.h>

typedef struct {
	NMJsonVt vt;
	void *dl_handle;
} NMJsonVtInternal;

static NMJsonVtInternal *
_nm_json_vt_internal_load (void)
{
	NMJsonVtInternal *v;
	void *handle = NULL;
	int mode;

	v = g_new0 (NMJsonVtInternal, 1);

#ifndef JANSSON_SONAME
#define JANSSON_SONAME ""
#endif

	mode = RTLD_LAZY | RTLD_LOCAL | RTLD_NODELETE | RTLD_DEEPBIND;
#if defined (ASAN_BUILD)
	/* Address sanitizer is incompatible with RTLD_DEEPBIND. */
	mode &= ~RTLD_DEEPBIND;
#endif

	if (strlen (JANSSON_SONAME) > 0)
		handle = dlopen (JANSSON_SONAME, mode);

	if (!handle)
		return v;

#define TRY_BIND_SYMBOL(symbol) \
	G_STMT_START { \
		void *_sym = dlsym (handle, #symbol); \
		\
		if (!_sym) \
			goto fail_symbol; \
		v->vt.nm_ ## symbol = _sym; \
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
	TRY_BIND_SYMBOL (json_object_iter_key);
	TRY_BIND_SYMBOL (json_object_iter_next);
	TRY_BIND_SYMBOL (json_object_iter_value);
	TRY_BIND_SYMBOL (json_object_key_to_iter);
	TRY_BIND_SYMBOL (json_object_set_new);
	TRY_BIND_SYMBOL (json_object_size);
	TRY_BIND_SYMBOL (json_string);
	TRY_BIND_SYMBOL (json_string_value);
	TRY_BIND_SYMBOL (json_true);

	v->vt.loaded = TRUE;
	v->dl_handle = handle;
	return v;

fail_symbol:
	dlclose (&handle);
	*v = (NMJsonVtInternal) { };
	return v;
}

const NMJsonVt *_nm_json_vt_ptr = NULL;

const NMJsonVt *
_nm_json_vt_init (void)
{
	NMJsonVtInternal *v;

again:
	v = g_atomic_pointer_get ((gpointer *) &_nm_json_vt_ptr);
	if (G_UNLIKELY (!v)) {
		v = _nm_json_vt_internal_load ();
		if (!g_atomic_pointer_compare_and_exchange ((gpointer *) &_nm_json_vt_ptr, NULL, v)) {
			if (v->dl_handle)
				dlclose (v->dl_handle);
			g_free (v);
			goto again;
		}

		/* we transfer ownership. */
	}

	nm_assert (v && v == g_atomic_pointer_get ((gpointer *) &_nm_json_vt_ptr));
	return &v->vt;
}

const NMJsonVt *
nmtst_json_vt_reset (gboolean loaded)
{
	NMJsonVtInternal *v_old;
	NMJsonVtInternal *v;

	v_old = g_atomic_pointer_get ((gpointer *) &_nm_json_vt_ptr);

	if (!loaded) {
		/* load a fake instance for testing. */
		v = g_new0 (NMJsonVtInternal, 1);
	} else
		v = _nm_json_vt_internal_load ();

	if (!g_atomic_pointer_compare_and_exchange ((gpointer *) &_nm_json_vt_ptr, v_old, v))
		g_assert_not_reached ();

	if (v_old) {
		if (v_old->dl_handle)
			dlclose (v_old->dl_handle);
		g_free ((gpointer *) v_old);
	}

	return v->vt.loaded ? &v->vt : NULL;
}
