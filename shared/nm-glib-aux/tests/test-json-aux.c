/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nm-glib-aux/nm-default-glib-i18n-prog.h"

#include <jansson.h>

#include "nm-glib-aux/nm-json-aux.h"

#include "nm-utils/nm-test-utils.h"

/*****************************************************************************/

static void
test_jansson(void)
{
    const NMJsonVt *    vt;
    nm_auto_decref_json nm_json_t *js1 = NULL;
    nm_auto_decref_json nm_json_t *js2 = NULL;

#define _ASSERT_FIELD(type1, type2, field)                                                        \
    G_STMT_START                                                                                  \
    {                                                                                             \
        G_STATIC_ASSERT_EXPR(sizeof(((type1 *) NULL)->field) == sizeof(((type2 *) NULL)->field)); \
        G_STATIC_ASSERT_EXPR(G_STRUCT_OFFSET(type1, field) == G_STRUCT_OFFSET(type2, field));     \
    }                                                                                             \
    G_STMT_END

    G_STATIC_ASSERT_EXPR(NM_JSON_REJECT_DUPLICATES == JSON_REJECT_DUPLICATES);

    G_STATIC_ASSERT_EXPR(sizeof(nm_json_type) == sizeof(json_type));

    G_STATIC_ASSERT_EXPR((int) NM_JSON_OBJECT == JSON_OBJECT);
    G_STATIC_ASSERT_EXPR((int) NM_JSON_ARRAY == JSON_ARRAY);
    G_STATIC_ASSERT_EXPR((int) NM_JSON_STRING == JSON_STRING);
    G_STATIC_ASSERT_EXPR((int) NM_JSON_INTEGER == JSON_INTEGER);
    G_STATIC_ASSERT_EXPR((int) NM_JSON_REAL == JSON_REAL);
    G_STATIC_ASSERT_EXPR((int) NM_JSON_TRUE == JSON_TRUE);
    G_STATIC_ASSERT_EXPR((int) NM_JSON_FALSE == JSON_FALSE);
    G_STATIC_ASSERT_EXPR((int) NM_JSON_NULL == JSON_NULL);

    G_STATIC_ASSERT_EXPR(sizeof(nm_json_int_t) == sizeof(json_int_t));

    G_STATIC_ASSERT_EXPR(sizeof(nm_json_t) == sizeof(json_t));
    _ASSERT_FIELD(nm_json_t, json_t, refcount);
    _ASSERT_FIELD(nm_json_t, json_t, type);

    G_STATIC_ASSERT_EXPR(NM_JSON_ERROR_TEXT_LENGTH == JSON_ERROR_TEXT_LENGTH);
    G_STATIC_ASSERT_EXPR(NM_JSON_ERROR_SOURCE_LENGTH == JSON_ERROR_SOURCE_LENGTH);

    G_STATIC_ASSERT_EXPR(sizeof(nm_json_error_t) == sizeof(json_error_t));
    _ASSERT_FIELD(nm_json_error_t, json_error_t, line);
    _ASSERT_FIELD(nm_json_error_t, json_error_t, column);
    _ASSERT_FIELD(nm_json_error_t, json_error_t, position);
    _ASSERT_FIELD(nm_json_error_t, json_error_t, source);
    _ASSERT_FIELD(nm_json_error_t, json_error_t, text);

    vt = nm_json_vt();

    g_assert(vt);
    g_assert(vt->loaded);

    js1 = vt->nm_json_loads("{ \"a\": 5 }", 0, NULL);
    g_assert(js1);
    nm_json_decref(vt, g_steal_pointer(&js1));

    js2 = vt->nm_json_loads("{ \"a\": 6 }", 0, NULL);
    g_assert(js2);

#define CHECK_FCN(vt, fcn, nm_type, js_type)             \
    G_STMT_START                                         \
    {                                                    \
        const NMJsonVt *const _vt     = (vt);            \
        _nm_unused            nm_type = (_vt->nm_##fcn); \
        _nm_unused            js_type = (fcn);           \
                                                         \
        g_assert(_vt->nm_##fcn);                         \
        g_assert(_f_nm);                                 \
        g_assert(_f_js);                                 \
        g_assert(_f_nm == _vt->nm_##fcn);                \
    }                                                    \
    G_STMT_END

    CHECK_FCN(vt, json_array, nm_json_t * (*_f_nm)(void), json_t * (*_f_js)(void) );
    CHECK_FCN(vt,
              json_array_append_new,
              int (*_f_nm)(nm_json_t *, nm_json_t *),
              int (*_f_js)(json_t *, json_t *));
    CHECK_FCN(vt,
              json_array_get,
              nm_json_t * (*_f_nm)(const nm_json_t *, gsize),
              json_t * (*_f_js)(const json_t *, size_t));
    CHECK_FCN(vt,
              json_array_size,
              gsize(*_f_nm)(const nm_json_t *),
              size_t(*_f_js)(const json_t *));
    CHECK_FCN(vt, json_delete, void (*_f_nm)(nm_json_t *), void (*_f_js)(json_t *));
    CHECK_FCN(vt,
              json_dumps,
              char *(*_f_nm)(const nm_json_t *, gsize),
              char *(*_f_js)(const json_t *, size_t));
    CHECK_FCN(vt, json_false, nm_json_t * (*_f_nm)(void), json_t * (*_f_js)(void) );
    CHECK_FCN(vt, json_integer, nm_json_t * (*_f_nm)(nm_json_int_t), json_t * (*_f_js)(json_int_t));
    CHECK_FCN(vt,
              json_integer_value,
              nm_json_int_t(*_f_nm)(const nm_json_t *),
              json_int_t(*_f_js)(const json_t *));
    CHECK_FCN(vt,
              json_loads,
              nm_json_t * (*_f_nm)(const char *, gsize, nm_json_error_t *),
              json_t * (*_f_js)(const char *, size_t, json_error_t *) );
    CHECK_FCN(vt, json_object, nm_json_t * (*_f_nm)(void), json_t * (*_f_js)(void) );
    CHECK_FCN(vt,
              json_object_del,
              int (*_f_nm)(nm_json_t *, const char *),
              int (*_f_js)(json_t *, const char *));
    CHECK_FCN(vt,
              json_object_get,
              nm_json_t * (*_f_nm)(const nm_json_t *, const char *),
              json_t * (*_f_js)(const json_t *, const char *) );
    CHECK_FCN(vt, json_object_iter, void *(*_f_nm)(nm_json_t *), void *(*_f_js)(json_t *) );
    CHECK_FCN(vt,
              json_object_iter_key,
              const char *(*_f_nm)(void *),
              const char *(*_f_js)(void *) );
    CHECK_FCN(vt,
              json_object_iter_next,
              void *(*_f_nm)(nm_json_t *, void *),
              void *(*_f_js)(json_t *, void *) );
    CHECK_FCN(vt, json_object_iter_value, nm_json_t * (*_f_nm)(void *), json_t * (*_f_js)(void *) );
    CHECK_FCN(vt,
              json_object_key_to_iter,
              void *(*_f_nm)(const char *),
              void *(*_f_js)(const char *) );
    CHECK_FCN(vt,
              json_object_set_new,
              int (*_f_nm)(nm_json_t *, const char *, nm_json_t *),
              int (*_f_js)(json_t *, const char *, json_t *));
    CHECK_FCN(vt,
              json_object_size,
              gsize(*_f_nm)(const nm_json_t *),
              size_t(*_f_js)(const json_t *));
    CHECK_FCN(vt,
              json_string,
              nm_json_t * (*_f_nm)(const char *),
              json_t * (*_f_js)(const char *) );
    CHECK_FCN(vt,
              json_string_value,
              const char *(*_f_nm)(const nm_json_t *),
              const char *(*_f_js)(const json_t *) );
    CHECK_FCN(vt, json_true, nm_json_t * (*_f_nm)(void), json_t * (*_f_js)(void) );
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init(&argc, &argv, TRUE);

    g_test_add_func("/general/test_jansson", test_jansson);

    return g_test_run();
}
