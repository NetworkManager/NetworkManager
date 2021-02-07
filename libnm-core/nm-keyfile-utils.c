/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2010 Red Hat, Inc.
 */

#include "libnm-core/nm-default-libnm-core.h"

#include "nm-keyfile-utils.h"

#include <stdlib.h>

#include "nm-glib-aux/nm-str-buf.h"

#include "nm-keyfile.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"

#include "nm-keyfile-internal.h"

/*****************************************************************************/

/**
 * nm_key_file_get_boolean:
 * @kf: the #GKeyFile
 * @group: the group
 * @key: the key
 * @default_value: the default value if the value is set or not parsable as a boolean.
 *
 * Replacement for g_key_file_get_boolean() (which uses g_key_file_parse_value_as_boolean()).
 * g_key_file_get_boolean() seems odd to me, because it accepts trailing ASCII whitespace,
 * but not leading.
 * This uses _nm_utils_ascii_str_to_bool(), which accepts trailing and leading whitespace,
 * case-insensitive words, and also strings like "on" and "off".
 * _nm_utils_ascii_str_to_bool() is our way to parse booleans from string, and we should
 * use that one consistently.
 *
 * Also, it doesn't have g_key_file_get_boolean()'s odd API to require an error argument
 * to detect parsing failures.
 *
 * Returns: either %TRUE or %FALSE if the key exists and is parsable as a boolean.
 *   Otherwise, @default_value. Sets errno to ENODATA, EINVAL or 0, depending on whether
 *   the key exists, whether the value is invalid, or success.
 */
int
nm_key_file_get_boolean(GKeyFile *kf, const char *group, const char *key, int default_value)
{
    int           v;
    gs_free char *value = NULL;

    value = g_key_file_get_value(kf, group, key, NULL);

    if (!value) {
        errno = ENODATA;
        return default_value;
    }
    v = _nm_utils_ascii_str_to_bool(value, -1);
    if (v != -1) {
        errno = 0;
        return v;
    }
    errno = EINVAL;
    return default_value;
}

/*****************************************************************************/

typedef struct {
    const char *setting;
    const char *alias;
} SettingAlias;

static const SettingAlias alias_list[] = {
    {NM_SETTING_WIRED_SETTING_NAME, "ethernet"},
    {NM_SETTING_WIRELESS_SETTING_NAME, "wifi"},
    {NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, "wifi-security"},
};

const char *
nm_keyfile_plugin_get_alias_for_setting_name(const char *setting_name)
{
    guint i;

    g_return_val_if_fail(setting_name != NULL, NULL);

    for (i = 0; i < G_N_ELEMENTS(alias_list); i++) {
        if (nm_streq(setting_name, alias_list[i].setting))
            return alias_list[i].alias;
    }
    return NULL;
}

const char *
nm_keyfile_plugin_get_setting_name_for_alias(const char *alias)
{
    guint i;

    g_return_val_if_fail(alias != NULL, NULL);

    for (i = 0; i < G_N_ELEMENTS(alias_list); i++) {
        if (nm_streq(alias, alias_list[i].alias))
            return alias_list[i].setting;
    }
    return NULL;
}

/*****************************************************************************/

char **
nm_keyfile_plugin_kf_get_string_list(GKeyFile *  kf,
                                     const char *group,
                                     const char *key,
                                     gsize *     out_length,
                                     GError **   error)
{
    char **     list;
    const char *alias;
    GError *    local = NULL;
    gsize       l;

    list = g_key_file_get_string_list(kf, group, key, &l, &local);
    if (nm_g_error_matches(local, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) {
        alias = nm_keyfile_plugin_get_alias_for_setting_name(group);
        if (alias) {
            g_clear_error(&local);
            list = g_key_file_get_string_list(kf, alias, key, &l, &local);
        }
    }
    if (local)
        g_propagate_error(error, local);
    if (!list)
        l = 0;
    NM_SET_OUT(out_length, l);
    return list;
}

guint *
nm_keyfile_plugin_kf_get_integer_list_uint(GKeyFile *  key_file,
                                           const char *group_name,
                                           const char *key,
                                           gsize *     out_length,
                                           GError **   error)
{
    GError *           key_file_error = NULL;
    gs_strfreev char **values         = NULL;
    gs_free guint *int_values         = NULL;
    gsize          i, num_ints;

    NM_SET_OUT(out_length, 0);

    g_return_val_if_fail(key_file != NULL, NULL);
    g_return_val_if_fail(group_name != NULL, NULL);
    g_return_val_if_fail(key != NULL, NULL);

    values =
        nm_keyfile_plugin_kf_get_string_list(key_file, group_name, key, &num_ints, &key_file_error);

    if (key_file_error)
        g_propagate_error(error, key_file_error);
    if (!values)
        return NULL;

    int_values = g_new(guint, num_ints);

    for (i = 0; i < num_ints; i++) {
        gint64 v;

        G_STATIC_ASSERT_EXPR(sizeof(v) > sizeof(guint));
        v = _nm_utils_ascii_str_to_int64(values[i], 10, 0, G_MAXUINT, -1);
        if (v == -1) {
            g_set_error(error,
                        G_KEY_FILE_ERROR,
                        G_KEY_FILE_ERROR_INVALID_VALUE,
                        _("Value cannot be interpreted as a list of numbers."));
            return NULL;
        }

        int_values[i] = v;
    }

    NM_SET_OUT(out_length, num_ints);
    return g_steal_pointer(&int_values);
}

void
nm_keyfile_plugin_kf_set_string_list(GKeyFile *         kf,
                                     const char *       group,
                                     const char *       key,
                                     const char *const *list,
                                     gsize              length)
{
    const char *alias;

    alias = nm_keyfile_plugin_get_alias_for_setting_name(group);
    g_key_file_set_string_list(kf, alias ?: group, key, list, length);
}

void
nm_keyfile_plugin_kf_set_integer_list_uint(GKeyFile *   kf,
                                           const char * group,
                                           const char * key,
                                           const guint *data,
                                           gsize        length)
{
    nm_auto_str_buf NMStrBuf strbuf = {};
    gsize                    i;

    g_return_if_fail(kf);
    g_return_if_fail(!length || data);
    g_return_if_fail(group && group[0]);
    g_return_if_fail(key && key[0]);

    nm_str_buf_init(&strbuf, length * 4u + 2u, FALSE);
    for (i = 0; i < length; i++)
        nm_str_buf_append_printf(&strbuf, "%u;", data[i]);
    nm_keyfile_plugin_kf_set_value(kf, group, key, nm_str_buf_get_str(&strbuf));
}

void
nm_keyfile_plugin_kf_set_integer_list_uint8(GKeyFile *    kf,
                                            const char *  group,
                                            const char *  key,
                                            const guint8 *data,
                                            gsize         length)
{
    nm_auto_str_buf NMStrBuf strbuf = {};
    gsize                    i;

    g_return_if_fail(kf);
    g_return_if_fail(!length || data);
    g_return_if_fail(group && group[0]);
    g_return_if_fail(key && key[0]);

    nm_str_buf_init(&strbuf, length * 4u + 2u, FALSE);
    for (i = 0; i < length; i++)
        nm_str_buf_append_printf(&strbuf, "%u;", (guint) data[i]);
    nm_keyfile_plugin_kf_set_value(kf, group, key, nm_str_buf_get_str(&strbuf));
}

#define DEFINE_KF_WRAPPER_GET(fcn_name, get_ctype, key_file_get_fcn)                         \
    get_ctype fcn_name(GKeyFile *kf, const char *group, const char *key, GError **error)     \
    {                                                                                        \
        get_ctype   val;                                                                     \
        const char *alias;                                                                   \
        GError *    local = NULL;                                                            \
                                                                                             \
        val = key_file_get_fcn(kf, group, key, &local);                                      \
        if (nm_g_error_matches(local, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) { \
            alias = nm_keyfile_plugin_get_alias_for_setting_name(group);                     \
            if (alias) {                                                                     \
                g_clear_error(&local);                                                       \
                val = key_file_get_fcn(kf, alias, key, &local);                              \
            }                                                                                \
        }                                                                                    \
        if (local)                                                                           \
            g_propagate_error(error, local);                                                 \
        return val;                                                                          \
    }

DEFINE_KF_WRAPPER_GET(nm_keyfile_plugin_kf_get_string, char *, g_key_file_get_string);
DEFINE_KF_WRAPPER_GET(nm_keyfile_plugin_kf_get_boolean, gboolean, g_key_file_get_boolean);
DEFINE_KF_WRAPPER_GET(nm_keyfile_plugin_kf_get_value, char *, g_key_file_get_value);

#define DEFINE_KF_WRAPPER_SET(fcn_name, set_ctype, key_file_set_fcn)                 \
    void fcn_name(GKeyFile *kf, const char *group, const char *key, set_ctype value) \
    {                                                                                \
        const char *alias;                                                           \
                                                                                     \
        alias = nm_keyfile_plugin_get_alias_for_setting_name(group);                 \
        key_file_set_fcn(kf, alias ?: group, key, value);                            \
    }

DEFINE_KF_WRAPPER_SET(nm_keyfile_plugin_kf_set_string, const char *, g_key_file_set_string);
DEFINE_KF_WRAPPER_SET(nm_keyfile_plugin_kf_set_boolean, gboolean, g_key_file_set_boolean);
DEFINE_KF_WRAPPER_SET(nm_keyfile_plugin_kf_set_value, const char *, g_key_file_set_value);

gint64
nm_keyfile_plugin_kf_get_int64(GKeyFile *  kf,
                               const char *group,
                               const char *key,
                               guint       base,
                               gint64      min,
                               gint64      max,
                               gint64      fallback,
                               GError **   error)
{
    gs_free char *s = NULL;
    int           errsv;
    gint64        v;

    s = nm_keyfile_plugin_kf_get_value(kf, group, key, error);
    if (!s) {
        errno = ENODATA;
        return fallback;
    }

    v     = _nm_utils_ascii_str_to_int64(s, base, min, max, fallback);
    errsv = errno;
    if (errsv != 0 && error) {
        g_set_error(error,
                    G_KEY_FILE_ERROR,
                    G_KEY_FILE_ERROR_INVALID_VALUE,
                    _("value is not an integer in range [%lld, %lld]"),
                    (long long) min,
                    (long long) max);
        errno = errsv;
    }
    return v;
}

char **
nm_keyfile_plugin_kf_get_keys(GKeyFile *kf, const char *group, gsize *out_length, GError **error)
{
    char **     keys;
    const char *alias;
    GError *    local = NULL;
    gsize       l;

    keys = g_key_file_get_keys(kf, group, &l, &local);
    if (nm_g_error_matches(local, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) {
        alias = nm_keyfile_plugin_get_alias_for_setting_name(group);
        if (alias) {
            g_clear_error(&local);
            keys = g_key_file_get_keys(kf, alias, &l, error ? &local : NULL);
        }
    }
    nm_assert((!local) != (!keys));
    if (!keys)
        l = 0;
    nm_assert(l == NM_PTRARRAY_LEN(keys));
    NM_SET_OUT(out_length, l);
    if (local)
        g_propagate_error(error, local);
    return keys;
}

gboolean
nm_keyfile_plugin_kf_has_key(GKeyFile *kf, const char *group, const char *key, GError **error)
{
    gboolean    has;
    const char *alias;
    GError *    local = NULL;

    has = g_key_file_has_key(kf, group, key, &local);
    if (nm_g_error_matches(local, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) {
        alias = nm_keyfile_plugin_get_alias_for_setting_name(group);
        if (alias) {
            g_clear_error(&local);
            has = g_key_file_has_key(kf, alias, key, &local);
        }
    }
    if (local)
        g_propagate_error(error, local);
    return has;
}

/*****************************************************************************/

void
_nm_keyfile_copy(GKeyFile *dst, GKeyFile *src)
{
    gs_strfreev char **groups = NULL;
    guint              g, k;

    groups = g_key_file_get_groups(src, NULL);
    for (g = 0; groups && groups[g]; g++) {
        const char *       group = groups[g];
        gs_strfreev char **keys  = NULL;

        keys = g_key_file_get_keys(src, group, NULL, NULL);
        if (!keys)
            continue;

        for (k = 0; keys[k]; k++) {
            const char *  key   = keys[k];
            gs_free char *value = NULL;

            value = g_key_file_get_value(src, group, key, NULL);
            if (value)
                g_key_file_set_value(dst, group, key, value);
            else
                g_key_file_remove_key(dst, group, key, NULL);
        }
    }
}

/*****************************************************************************/

gboolean
_nm_keyfile_a_contains_all_in_b(GKeyFile *kf_a, GKeyFile *kf_b)
{
    gs_strfreev char **groups = NULL;
    guint              i, j;

    if (kf_a == kf_b)
        return TRUE;
    if (!kf_a || !kf_b)
        return FALSE;

    groups = g_key_file_get_groups(kf_a, NULL);
    for (i = 0; groups && groups[i]; i++) {
        gs_strfreev char **keys = NULL;

        keys = g_key_file_get_keys(kf_a, groups[i], NULL, NULL);
        if (!keys)
            continue;

        for (j = 0; keys[j]; j++) {
            gs_free char *key_a = g_key_file_get_value(kf_a, groups[i], keys[j], NULL);
            gs_free char *key_b = g_key_file_get_value(kf_b, groups[i], keys[j], NULL);

            if (g_strcmp0(key_a, key_b) != 0)
                return FALSE;
        }
    }
    return TRUE;
}

static gboolean
_nm_keyfile_equals_ordered(GKeyFile *kf_a, GKeyFile *kf_b)
{
    gs_strfreev char **groups   = NULL;
    gs_strfreev char **groups_b = NULL;
    guint              i, j;

    if (kf_a == kf_b)
        return TRUE;
    if (!kf_a || !kf_b)
        return FALSE;

    groups   = g_key_file_get_groups(kf_a, NULL);
    groups_b = g_key_file_get_groups(kf_b, NULL);
    if (!groups && !groups_b)
        return TRUE;
    if (!groups || !groups_b)
        return FALSE;
    for (i = 0; groups[i] && groups_b[i] && !strcmp(groups[i], groups_b[i]); i++)
        ;
    if (groups[i] || groups_b[i])
        return FALSE;

    for (i = 0; groups[i]; i++) {
        gs_strfreev char **keys   = NULL;
        gs_strfreev char **keys_b = NULL;

        keys   = g_key_file_get_keys(kf_a, groups[i], NULL, NULL);
        keys_b = g_key_file_get_keys(kf_b, groups[i], NULL, NULL);

        if ((!keys) != (!keys_b))
            return FALSE;
        if (!keys)
            continue;

        for (j = 0; keys[j] && keys_b[j] && !strcmp(keys[j], keys_b[j]); j++)
            ;
        if (keys[j] || keys_b[j])
            return FALSE;

        for (j = 0; keys[j]; j++) {
            gs_free char *key_a = g_key_file_get_value(kf_a, groups[i], keys[j], NULL);
            gs_free char *key_b = g_key_file_get_value(kf_b, groups[i], keys[j], NULL);

            if (g_strcmp0(key_a, key_b) != 0)
                return FALSE;
        }
    }
    return TRUE;
}

gboolean
_nm_keyfile_equals(GKeyFile *kf_a, GKeyFile *kf_b, gboolean consider_order)
{
    if (!consider_order) {
        return _nm_keyfile_a_contains_all_in_b(kf_a, kf_b)
               && _nm_keyfile_a_contains_all_in_b(kf_b, kf_a);
    } else {
        return _nm_keyfile_equals_ordered(kf_a, kf_b);
    }
}

gboolean
_nm_keyfile_has_values(GKeyFile *keyfile)
{
    gs_strfreev char **groups = NULL;

    g_return_val_if_fail(keyfile, FALSE);

    groups = g_key_file_get_groups(keyfile, NULL);
    return groups && groups[0];
}

/*****************************************************************************/

static const char *
_keyfile_key_encode(const char *name, char **out_to_free)
{
    NMStrBuf str;
    gsize    len;
    gsize    i;

    nm_assert(name);
    nm_assert(out_to_free && !*out_to_free);

    /* See g_key_file_is_key_name().
     *
     * GKeyFile allows all UTF-8 characters (even non-well formed sequences),
     * except:
     *  - no empty keys
     *  - no leading/trailing ' '
     *  - no '=', '[', ']'
     *
     * We do something more strict here. All non-ASCII characters, all non-printable
     * characters, and all invalid characters are escaped with "\\XX".
     *
     * We don't escape \\, unless it is followed by two hex digits.
     */

    if (!name[0]) {
        /* empty keys are backslash encoded. Note that usually
         * \\00 is not a valid encode, the only exception is the empty
         * word. */
        return "\\00";
    }

    /* find the first character that needs escaping. */
    i = 0;
    if (name[0] != ' ') {
        for (;; i++) {
            const guchar ch = (guchar) name[i];

            if (ch == '\0')
                return name;

            if (ch < 0x20 || ch >= 127 || NM_IN_SET(ch, '=', '[', ']')
                || (ch == '\\' && g_ascii_isxdigit(name[i + 1]) && g_ascii_isxdigit(name[i + 2]))
                || (ch == ' ' && name[i + 1] == '\0'))
                break;
        }
    } else if (name[1] == '\0')
        return "\\20";

    len = i + strlen(&name[i]);
    nm_assert(len == strlen(name));

    nm_str_buf_init(&str, len + 15u, FALSE);

    if (name[0] == ' ') {
        nm_assert(i == 0);
        nm_str_buf_append(&str, "\\20");
        i = 1;
    } else
        nm_str_buf_append_len(&str, name, i);

    for (;; i++) {
        const guchar ch = (guchar) name[i];

        if (ch == '\0')
            break;

        if (ch < 0x20 || ch >= 127 || NM_IN_SET(ch, '=', '[', ']')
            || (ch == '\\' && g_ascii_isxdigit(name[i + 1]) && g_ascii_isxdigit(name[i + 2]))
            || (ch == ' ' && name[i + 1] == '\0')) {
            nm_str_buf_append_c(&str, '\\');
            nm_str_buf_append_c_hex(&str, ch, TRUE);
        } else
            nm_str_buf_append_c(&str, (char) ch);
    }

    return (*out_to_free = nm_str_buf_finalize(&str, NULL));
}

static const char *
_keyfile_key_decode(const char *key, char **out_to_free)
{
    char *out;
    gsize len;
    gsize i;
    gsize j;

    nm_assert(key);
    nm_assert(out_to_free && !*out_to_free);

    if (!key[0])
        return "";

    for (i = 0; TRUE; i++) {
        const char ch = key[i];

        if (ch == '\0')
            return key;
        if (ch == '\\' && g_ascii_isxdigit(key[i + 1]) && g_ascii_isxdigit(key[i + 2]))
            break;
    }

    len = i + strlen(&key[i]);

    if (len == 3 && nm_streq(key, "\\00"))
        return "";

    nm_assert(len == strlen(key));

    out = g_new(char, len + 1u);

    memcpy(out, key, sizeof(char) * i);

    j = i;
    for (;;) {
        const char ch = key[i];
        char       ch1, ch2;
        unsigned   v;

        if (ch == '\0')
            break;

        if (ch == '\\' && g_ascii_isxdigit((ch1 = key[i + 1]))
            && g_ascii_isxdigit((ch2 = key[i + 2]))) {
            v = (g_ascii_xdigit_value(ch1) << 4) + g_ascii_xdigit_value(ch2);
            if (v != 0) {
                out[j++] = (char) v;
                i += 3;
                continue;
            }
        }
        out[j++] = ch;
        i++;
    }

    nm_assert(j <= len);
    out[j] = '\0';
    return (*out_to_free = out);
}

/*****************************************************************************/

const char *
nm_keyfile_key_encode(const char *name, char **out_to_free)
{
    const char *key;

    key = _keyfile_key_encode(name, out_to_free);
#if NM_MORE_ASSERTS > 5
    nm_assert(key);
    nm_assert(!*out_to_free || key == *out_to_free);
    nm_assert(!*out_to_free || !nm_streq0(name, key));
    {
        gs_free char *to_free2 = NULL;
        const char *  name2;

        name2 = _keyfile_key_decode(key, &to_free2);
        /* name2, the result of encode()+decode() is identical to name.
         * That is because
         *   - encode() is a injective function.
         *   - decode() is a surjective function, however for output
         *     values of encode() is behaves injective too. */
        nm_assert(nm_streq0(name2, name));
    }
#endif
    return key;
}

const char *
nm_keyfile_key_decode(const char *key, char **out_to_free)
{
    const char *name;

    name = _keyfile_key_decode(key, out_to_free);
#if NM_MORE_ASSERTS > 5
    nm_assert(name);
    nm_assert(!*out_to_free || name == *out_to_free);
    {
        gs_free char *to_free2 = NULL;
        const char *  key2;

        key2 = _keyfile_key_encode(name, &to_free2);
        /* key2, the result of decode+encode may not be identical
         * to the original key. That is, decode() is a surjective
         * function mapping different keys to the same name.
         * However, decode() behaves injective for input that
         * are valid output of encode(). */
        nm_assert(key2);
    }
#endif
    return name;
}
