/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 - 2019 Red Hat, Inc.
 */

#include "nm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-json-aux.h"

#include <dlfcn.h>

/*****************************************************************************/

/* If RTLD_DEEPBIND isn't available just ignore it. This can cause problems
 * with jansson, json-glib, and cjson symbols clashing (and as such crashing the
 * program). But that needs to be fixed by the json libraries, and it is by adding
 * symbol versioning in recent versions. */
#ifndef RTLD_DEEPBIND
    #define RTLD_DEEPBIND 0
#endif

/*****************************************************************************/

static void
_gstr_append_string_len(GString *gstr, const char *str, gsize len)
{
    g_string_append_c(gstr, '\"');

    while (len > 0) {
        gsize       n;
        const char *end;
        gboolean    valid;

        nm_assert(len > 0);

        valid = g_utf8_validate(str, len, &end);

        nm_assert(end && end >= str && end <= &str[len]);

        if (end > str) {
            const char *s;

            for (s = str; s < end; s++) {
                nm_assert(s[0] != '\0');

                if (s[0] < 0x20) {
                    const char *text;

                    switch (s[0]) {
                    case '\\':
                        text = "\\\\";
                        break;
                    case '\"':
                        text = "\\\"";
                        break;
                    case '\b':
                        text = "\\b";
                        break;
                    case '\f':
                        text = "\\f";
                        break;
                    case '\n':
                        text = "\\n";
                        break;
                    case '\r':
                        text = "\\r";
                        break;
                    case '\t':
                        text = "\\t";
                        break;
                    default:
                        g_string_append_printf(gstr, "\\u%04X", (guint) s[0]);
                        continue;
                    }
                    g_string_append(gstr, text);
                    continue;
                }

                if (NM_IN_SET(s[0], '\\', '\"'))
                    g_string_append_c(gstr, '\\');
                g_string_append_c(gstr, s[0]);
            }
        } else
            nm_assert(!valid);

        if (valid) {
            nm_assert(end == &str[len]);
            break;
        }

        nm_assert(end < &str[len]);

        if (end[0] == '\0') {
            /* there is a NUL byte in the string. Technically this is valid UTF-8, so we
             * encode it there. However, this will likely result in a truncated string when
             * parsing. */
            g_string_append(gstr, "\\u0000");
        } else {
            /* the character is not valid UTF-8. There is nothing we can do about it, because
             * JSON can only contain UTF-8 and even the escape sequences can only escape Unicode
             * codepoints (but not binary).
             *
             * The argument is not a string (in any known encoding), hence we cannot represent
             * it as a JSON string (which are unicode strings).
             *
             * Print an underscore instead of the invalid char :) */
            g_string_append_c(gstr, '_');
        }

        n = str - end;
        nm_assert(n < len);
        n++;
        str += n;
        len -= n;
    }

    g_string_append_c(gstr, '\"');
}

void
nm_json_gstr_append_string_len(GString *gstr, const char *str, gsize n)
{
    g_return_if_fail(gstr);

    _gstr_append_string_len(gstr, str, n);
}

void
nm_json_gstr_append_string(GString *gstr, const char *str)
{
    g_return_if_fail(gstr);

    if (!str)
        g_string_append(gstr, "null");
    else
        _gstr_append_string_len(gstr, str, strlen(str));
}

void
nm_json_gstr_append_obj_name(GString *gstr, const char *key, char start_container)
{
    g_return_if_fail(gstr);
    g_return_if_fail(key);

    nm_json_gstr_append_string(gstr, key);

    if (start_container != '\0') {
        nm_assert(NM_IN_SET(start_container, '[', '{'));
        g_string_append_printf(gstr, ": %c ", start_container);
    } else
        g_string_append(gstr, ": ");
}

/*****************************************************************************/

typedef struct {
    NMJsonVt vt;
    void *   dl_handle;
} NMJsonVtInternal;

static NMJsonVtInternal *
_nm_json_vt_internal_load(void)
{
    NMJsonVtInternal *v;
    const char *      soname;
    void *            handle;

    v = g_new0(NMJsonVtInternal, 1);

#if WITH_JANSSON && defined(JANSSON_SONAME)
    G_STATIC_ASSERT_EXPR(NM_STRLEN(JANSSON_SONAME) > 0);
    nm_assert(strlen(JANSSON_SONAME) > 0);
    soname = JANSSON_SONAME;
#elif !WITH_JANSSON && !defined(JANSSON_SONAME)
    soname = NULL;
#else
    #error "WITH_JANSON and JANSSON_SONAME are defined inconsistently."
#endif

    if (!soname)
        return v;

    handle = dlopen(soname,
                    RTLD_LAZY | RTLD_LOCAL | RTLD_NODELETE
#if !defined(ASAN_BUILD)
                        | RTLD_DEEPBIND
#endif
                        | 0);
    if (!handle)
        return v;

#define TRY_BIND_SYMBOL(symbol)              \
    G_STMT_START                             \
    {                                        \
        void *_sym = dlsym(handle, #symbol); \
                                             \
        if (!_sym)                           \
            goto fail_symbol;                \
        v->vt.nm_##symbol = _sym;            \
    }                                        \
    G_STMT_END

    TRY_BIND_SYMBOL(json_array);
    TRY_BIND_SYMBOL(json_array_append_new);
    TRY_BIND_SYMBOL(json_array_get);
    TRY_BIND_SYMBOL(json_array_size);
    TRY_BIND_SYMBOL(json_delete);
    TRY_BIND_SYMBOL(json_dumps);
    TRY_BIND_SYMBOL(json_false);
    TRY_BIND_SYMBOL(json_integer);
    TRY_BIND_SYMBOL(json_integer_value);
    TRY_BIND_SYMBOL(json_loads);
    TRY_BIND_SYMBOL(json_object);
    TRY_BIND_SYMBOL(json_object_del);
    TRY_BIND_SYMBOL(json_object_get);
    TRY_BIND_SYMBOL(json_object_iter);
    TRY_BIND_SYMBOL(json_object_iter_key);
    TRY_BIND_SYMBOL(json_object_iter_next);
    TRY_BIND_SYMBOL(json_object_iter_value);
    TRY_BIND_SYMBOL(json_object_key_to_iter);
    TRY_BIND_SYMBOL(json_object_set_new);
    TRY_BIND_SYMBOL(json_object_size);
    TRY_BIND_SYMBOL(json_string);
    TRY_BIND_SYMBOL(json_string_value);
    TRY_BIND_SYMBOL(json_true);

    v->vt.loaded = TRUE;
    v->dl_handle = handle;
    return v;

fail_symbol:
    dlclose(&handle);
    *v = (NMJsonVtInternal){};
    return v;
}

const NMJsonVt *_nm_json_vt_ptr = NULL;

const NMJsonVt *
_nm_json_vt_init(void)
{
    NMJsonVtInternal *v;

again:
    v = g_atomic_pointer_get((gpointer *) &_nm_json_vt_ptr);
    if (G_UNLIKELY(!v)) {
        v = _nm_json_vt_internal_load();
        if (!g_atomic_pointer_compare_and_exchange((gpointer *) &_nm_json_vt_ptr, NULL, v)) {
            if (v->dl_handle)
                dlclose(v->dl_handle);
            g_free(v);
            goto again;
        }

        /* we transfer ownership. */
    }

    nm_assert(v && v == g_atomic_pointer_get((gpointer *) &_nm_json_vt_ptr));
    return &v->vt;
}

const NMJsonVt *
nmtst_json_vt_reset(gboolean loaded)
{
    NMJsonVtInternal *v_old;
    NMJsonVtInternal *v;

    v_old = g_atomic_pointer_get((gpointer *) &_nm_json_vt_ptr);

    if (!loaded) {
        /* load a fake instance for testing. */
        v = g_new0(NMJsonVtInternal, 1);
    } else
        v = _nm_json_vt_internal_load();

    if (!g_atomic_pointer_compare_and_exchange((gpointer *) &_nm_json_vt_ptr, v_old, v))
        g_assert_not_reached();

    if (v_old) {
        if (v_old->dl_handle)
            dlclose(v_old->dl_handle);
        g_free((gpointer *) v_old);
    }

    return v->vt.loaded ? &v->vt : NULL;
}
