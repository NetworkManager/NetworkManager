/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 - 2019 Red Hat, Inc.
 */

#ifndef __NM_JSON_AUX_H__
#define __NM_JSON_AUX_H__

#include "nm-value-type.h"

/*****************************************************************************/

static inline GString *
nm_json_gstr_append_delimiter(GString *gstr)
{
    g_string_append(gstr, ", ");
    return gstr;
}

void nm_json_gstr_append_string_len(GString *gstr, const char *str, gsize n);

void nm_json_gstr_append_string(GString *gstr, const char *str);

static inline void
nm_json_gstr_append_bool(GString *gstr, gboolean v)
{
    g_string_append(gstr, v ? "true" : "false");
}

static inline void
nm_json_gstr_append_int64(GString *gstr, gint64 v)
{
    g_string_append_printf(gstr, "%" G_GINT64_FORMAT, v);
}

void nm_json_gstr_append_obj_name(GString *gstr, const char *key, char start_container);

/*****************************************************************************/

#define NM_JSON_REJECT_DUPLICATES 0x1

typedef enum {
    NM_JSON_OBJECT,
    NM_JSON_ARRAY,
    NM_JSON_STRING,
    NM_JSON_INTEGER,
    NM_JSON_REAL,
    NM_JSON_TRUE,
    NM_JSON_FALSE,
    NM_JSON_NULL,
} nm_json_type;

typedef struct nm_json_t {
    nm_json_type    type;
    volatile size_t refcount;
} nm_json_t;

typedef long long nm_json_int_t;

#define NM_JSON_ERROR_TEXT_LENGTH   160
#define NM_JSON_ERROR_SOURCE_LENGTH 80

typedef struct nm_json_error_t {
    int  line;
    int  column;
    int  position;
    char source[NM_JSON_ERROR_SOURCE_LENGTH];
    char text[NM_JSON_ERROR_TEXT_LENGTH];
} nm_json_error_t;

typedef struct {
    gboolean loaded;
    char *(*nm_json_dumps)(const nm_json_t *json, size_t flags);
    const char *(*nm_json_object_iter_key)(void *iter);
    const char *(*nm_json_string_value)(const nm_json_t *json);
    int (*nm_json_array_append_new)(nm_json_t *json, nm_json_t *value);
    int (*nm_json_object_del)(nm_json_t *json, const char *key);
    int (*nm_json_object_set_new)(nm_json_t *json, const char *key, nm_json_t *value);
    nm_json_int_t (*nm_json_integer_value)(const nm_json_t *json);
    nm_json_t *(*nm_json_array)(void);
    nm_json_t *(*nm_json_array_get)(const nm_json_t *json, size_t index);
    nm_json_t *(*nm_json_false)(void);
    nm_json_t *(*nm_json_integer)(nm_json_int_t value);
    nm_json_t *(*nm_json_loads)(const char *string, size_t flags, nm_json_error_t *error);
    nm_json_t *(*nm_json_object)(void);
    nm_json_t *(*nm_json_object_get)(const nm_json_t *json, const char *key);
    nm_json_t *(*nm_json_object_iter_value)(void *);
    nm_json_t *(*nm_json_string)(const char *value);
    nm_json_t *(*nm_json_true)(void);
    size_t (*nm_json_array_size)(const nm_json_t *json);
    size_t (*nm_json_object_size)(const nm_json_t *json);
    void (*nm_json_delete)(nm_json_t *json);
    void *(*nm_json_object_iter)(nm_json_t *json);
    void *(*nm_json_object_iter_next)(nm_json_t *json, void *iter);
    void *(*nm_json_object_key_to_iter)(const char *key);
} NMJsonVt;

extern const NMJsonVt *_nm_json_vt_ptr;

const NMJsonVt *_nm_json_vt_init(void);

static inline const NMJsonVt *
_nm_json_vt(void)
{
    const NMJsonVt *vt;

    vt = g_atomic_pointer_get((gpointer *) &_nm_json_vt_ptr);
    if (G_UNLIKELY(!vt)) {
        vt = _nm_json_vt_init();
        nm_assert(vt);
    }
    return vt;
}

static inline const NMJsonVt *
nm_json_vt(void)
{
    const NMJsonVt *vt;

    vt = _nm_json_vt();
    return vt->loaded ? vt : NULL;
}

static inline const NMJsonVt *
nm_json_vt_assert(void)
{
    const NMJsonVt *vt;

    vt = _nm_json_vt();
    nm_assert(vt->loaded);
    return vt;
}

const NMJsonVt *nmtst_json_vt_reset(gboolean loaded);

/*****************************************************************************/

#define nm_json_boolean(vt, val) ((val) ? (vt)->nm_json_true() : (vt)->nm_json_false())

static inline void
nm_json_decref(const NMJsonVt *vt, nm_json_t *json)
{
    /* Our ref-counting is not threadsafe, unlike libjansson's. But we never
     * share one json_t instance between threads, and if we would, we would very likely
     * wrap a mutex around it. */
    if (json && json->refcount != (size_t) -1 && --json->refcount == 0)
        vt->nm_json_delete(json);
}

static inline void
_nm_auto_decref_json(nm_json_t **p_json)
{
    if (*p_json && (*p_json)->refcount != (size_t) -1 && --(*p_json)->refcount == 0)
        nm_json_vt()->nm_json_delete(*p_json);
}

#define nm_auto_decref_json nm_auto(_nm_auto_decref_json)

/*****************************************************************************/

/* the following are implemented as pure macros in jansson.h.
 * They can be used directly, however, add a nm_json* variant,
 * to make it explict we don't accidentally use jansson ABI. */

#define nm_json_typeof(json)     ((json)->type)
#define nm_json_is_object(json)  ((json) && nm_json_typeof(json) == NM_JSON_OBJECT)
#define nm_json_is_array(json)   ((json) && nm_json_typeof(json) == NM_JSON_ARRAY)
#define nm_json_is_string(json)  ((json) && nm_json_typeof(json) == NM_JSON_STRING)
#define nm_json_is_integer(json) ((json) && nm_json_typeof(json) == NM_JSON_INTEGER)
#define nm_json_is_real(json)    ((json) && nm_json_typeof(json) == NM_JSON_REAL)
#define nm_json_is_number(json)  (nm_json_is_integer(json) || nm_json_is_real(json))
#define nm_json_is_true(json)    ((json) && nm_json_typeof(json) == NM_JSON_TRUE)
#define nm_json_is_false(json)   ((json) && nm_json_typeof(json) == NM_JSON_FALSE)
#define nm_json_boolean_value    nm_json_is_true
#define nm_json_is_boolean(json) (nm_json_is_true(json) || nm_json_is_false(json))
#define nm_json_is_null(json)    ((json) && nm_json_typeof(json) == NM_JSON_NULL)

#define nm_json_array_foreach(vt, array, index, value)                                           \
    for (index = 0;                                                                              \
         index < vt->nm_json_array_size(array) && (value = vt->nm_json_array_get(array, index)); \
         index++)

#define nm_json_object_foreach(vt, object, key, value)                                        \
    for (key = vt->nm_json_object_iter_key(vt->nm_json_object_iter(object));                  \
         key && (value = vt->nm_json_object_iter_value(vt->nm_json_object_key_to_iter(key))); \
         key = vt->nm_json_object_iter_key(                                                   \
             vt->nm_json_object_iter_next(object, vt->nm_json_object_key_to_iter(key))))

/*****************************************************************************/

static inline int
nm_jansson_json_as_bool(const nm_json_t *elem, bool *out_val)
{
    if (!elem)
        return 0;

    if (!nm_json_is_boolean(elem))
        return -EINVAL;

    NM_SET_OUT(out_val, nm_json_boolean_value(elem));
    return 1;
}

static inline int
nm_jansson_json_as_int32(const NMJsonVt *vt, const nm_json_t *elem, gint32 *out_val)
{
    nm_json_int_t v;

    if (!elem)
        return 0;

    if (!nm_json_is_integer(elem))
        return -EINVAL;

    v = vt->nm_json_integer_value(elem);
    if (v < (gint64) G_MININT32 || v > (gint64) G_MAXINT32)
        return -ERANGE;

    NM_SET_OUT(out_val, v);
    return 1;
}

static inline int
nm_jansson_json_as_int(const NMJsonVt *vt, const nm_json_t *elem, int *out_val)
{
    nm_json_int_t v;

    if (!elem)
        return 0;

    if (!nm_json_is_integer(elem))
        return -EINVAL;

    v = vt->nm_json_integer_value(elem);
    if (v < (gint64) G_MININT || v > (gint64) G_MAXINT)
        return -ERANGE;

    NM_SET_OUT(out_val, v);
    return 1;
}

static inline int
nm_jansson_json_as_string(const NMJsonVt *vt, const nm_json_t *elem, const char **out_val)
{
    if (!elem)
        return 0;

    if (!nm_json_is_string(elem))
        return -EINVAL;

    NM_SET_OUT(out_val, vt->nm_json_string_value(elem));
    return 1;
}

/*****************************************************************************/

#ifdef NM_VALUE_TYPE_DEFINE_FUNCTIONS

static inline void
nm_value_type_to_json(NMValueType value_type, GString *gstr, gconstpointer p_field)
{
    nm_assert(p_field);
    nm_assert(gstr);

    switch (value_type) {
    case NM_VALUE_TYPE_BOOL:
        nm_json_gstr_append_bool(gstr, *((const bool *) p_field));
        return;
    case NM_VALUE_TYPE_INT32:
        nm_json_gstr_append_int64(gstr, *((const gint32 *) p_field));
        return;
    case NM_VALUE_TYPE_INT:
        nm_json_gstr_append_int64(gstr, *((const int *) p_field));
        return;
    case NM_VALUE_TYPE_STRING:
        nm_json_gstr_append_string(gstr, *((const char *const *) p_field));
        return;
    case NM_VALUE_TYPE_UNSPEC:
        break;
    }
    nm_assert_not_reached();
}

static inline gboolean
nm_value_type_from_json(const NMJsonVt * vt,
                        NMValueType      value_type,
                        const nm_json_t *elem,
                        gpointer         out_val)
{
    switch (value_type) {
    case NM_VALUE_TYPE_BOOL:
        return (nm_jansson_json_as_bool(elem, out_val) > 0);
    case NM_VALUE_TYPE_INT32:
        return (nm_jansson_json_as_int32(vt, elem, out_val) > 0);
    case NM_VALUE_TYPE_INT:
        return (nm_jansson_json_as_int(vt, elem, out_val) > 0);

    /* warning: this overwrites/leaks the previous value. You better have *out_val
     * point to uninitialized memory or NULL. */
    case NM_VALUE_TYPE_STRING:
        return (nm_jansson_json_as_string(vt, elem, out_val) > 0);

    case NM_VALUE_TYPE_UNSPEC:
        break;
    }
    nm_assert_not_reached();
    return FALSE;
}

#endif /* NM_VALUE_TYPE_DEFINE_FUNCTIONS */

#endif /* __NM_JSON_AUX_H__ */
