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
		void *_sym = dlsym (handle, "json" #symbol); \
		\
		if (!_sym) \
			goto fail_symbol; \
		v->vt.nm_json ## symbol = _sym; \
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
