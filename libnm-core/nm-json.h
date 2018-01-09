// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2017, 2018 Red Hat, Inc.
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

#include "nm-glib-aux/nm-jansson.h"

typedef struct {
	gboolean loaded;
	char       *(*nm_json_dumps)              (const json_t *json, size_t flags);
	const char *(*nm_json_object_iter_key)    (void *iter);
	const char *(*nm_json_string_value)       (const json_t *json);
	int         (*nm_json_array_append_new)   (json_t *json, json_t *value);
	int         (*nm_json_object_del)         (json_t *json, const char *key);
	int         (*nm_json_object_set_new)     (json_t *json, const char *key, json_t *value);
	json_int_t  (*nm_json_integer_value)      (const json_t *json);
	json_t     *(*nm_json_array)              (void);
	json_t     *(*nm_json_array_get)          (const json_t *json, size_t index);
	json_t     *(*nm_json_false)              (void);
	json_t     *(*nm_json_integer)            (json_int_t value);
	json_t     *(*nm_json_loads)              (const char *string, size_t flags, json_error_t *error);
	json_t     *(*nm_json_object)             (void);
	json_t     *(*nm_json_object_get)         (const json_t *json, const char *key);
	json_t     *(*nm_json_object_iter_value)  (void *);
	json_t     *(*nm_json_string)             (const char *value);
	json_t     *(*nm_json_true)               (void);
	size_t      (*nm_json_array_size)         (const json_t *json);
	size_t      (*nm_json_object_size)        (const json_t *json);
	void        (*nm_json_delete)             (json_t *json);
	void       *(*nm_json_object_iter)        (json_t *json);
	void       *(*nm_json_object_iter_next)   (json_t *json, void *iter);
	void       *(*nm_json_object_key_to_iter) (const char *key);
} NMJsonVt;

extern const NMJsonVt *_nm_json_vt_ptr;

const NMJsonVt *_nm_json_vt_init (void);

static inline const NMJsonVt *
_nm_json_vt (void)
{
	const NMJsonVt *vt;

	vt = g_atomic_pointer_get ((gpointer *) &_nm_json_vt_ptr);
	if (G_UNLIKELY (!vt)) {
		vt = _nm_json_vt_init ();
		nm_assert (vt);
	}
	return vt;
}

static inline const NMJsonVt *
nm_json_vt (void)
{
	const NMJsonVt *vt;

	vt = _nm_json_vt();
	return vt->loaded ? vt : NULL;
}

static inline const NMJsonVt *
nm_json_vt_assert (void)
{
	const NMJsonVt *vt;

	vt = _nm_json_vt();
	nm_assert (vt->loaded);
	return vt;
}

const NMJsonVt *nmtst_json_vt_reset (gboolean loaded);

#endif /* __NM_JSON_H__ */
