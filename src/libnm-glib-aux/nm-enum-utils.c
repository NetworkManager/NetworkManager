/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-enum-utils.h"
#include "nm-str-buf.h"

/*****************************************************************************/

#define IS_FLAGS_SEPARATOR(ch) (NM_IN_SET((ch), ' ', '\t', ',', '\n', '\r'))

static void
_ASSERT_enum_values_info(GType type, const NMUtilsEnumValueInfo *value_infos)
{
#if NM_MORE_ASSERTS > 5
    nm_auto_unref_gtypeclass GTypeClass *klass = NULL;
    gs_unref_hashtable GHashTable       *ht    = NULL;

    klass = g_type_class_ref(type);

    g_assert(G_IS_ENUM_CLASS(klass) || G_IS_FLAGS_CLASS(klass));

    if (!value_infos)
        return;

    ht = g_hash_table_new(g_str_hash, g_str_equal);

    for (; value_infos->nick; value_infos++) {
        g_assert(value_infos->nick[0]);

        /* duplicate nicks make no sense!! */
        g_assert(!g_hash_table_contains(ht, value_infos->nick));
        g_hash_table_add(ht, (gpointer) value_infos->nick);

        if (G_IS_ENUM_CLASS(klass)) {
            GEnumValue *enum_value;

            enum_value = g_enum_get_value_by_nick(G_ENUM_CLASS(klass), value_infos->nick);
            if (enum_value) {
                /* we do allow specifying the same name via @value_infos and @type.
                 * That might make sense, if @type comes from a library where older versions
                 * of the library don't yet support the value. In this case, the caller can
                 * provide the nick via @value_infos, to support the older library version.
                 * And then, when actually running against a newer library version where
                 * @type knows the nick, we have this situation.
                 *
                 * Another reason for specifying a nick both in @value_infos and @type,
                 * is to specify an alias which is not used with highest preference. For
                 * example, if you add an alias "disabled" for "none" (both numerically
                 * equal), then the first alias in @value_infos will be preferred over
                 * the name from @type. So, to still use "none" as preferred name, you may
                 * explicitly specify the "none" alias in @value_infos before "disabled".
                 *
                 * However, what never is allowed, is to use a name (nick) to re-number
                 * the value. That is, if both @value_infos and @type contain a particular
                 * nick, their numeric values must agree as well.
                 * Allowing this, would be very confusing, because the name would have a different
                 * value from the regular GLib GEnum API.
                 */
                g_assert(enum_value->value == value_infos->value);
            }
        } else {
            GFlagsValue *flags_value;

            flags_value = g_flags_get_value_by_nick(G_FLAGS_CLASS(klass), value_infos->nick);
            if (flags_value) {
                /* see ENUM case above. */
                g_assert(flags_value->value == (guint) value_infos->value);
            }
        }
    }
#endif
}

static gboolean
_is_hex_string(const char *str, gboolean allow_sign)
{
    if (allow_sign && str[0] == '-')
        str++;
    return str[0] == '0' && str[1] == 'x' && str[2]
           && NM_STRCHAR_ALL(&str[2], ch, g_ascii_isxdigit(ch));
}

static gboolean
_is_dec_string(const char *str, gboolean allow_sign)
{
    if (allow_sign && str[0] == '-')
        str++;
    return str[0] && NM_STRCHAR_ALL(&str[0], ch, g_ascii_isdigit(ch));
}

static gboolean
_enum_is_valid_enum_nick(const char *str)
{
    return str[0] && !NM_STRCHAR_ANY(str, ch, g_ascii_isspace(ch)) && !_is_dec_string(str, TRUE)
           && !_is_hex_string(str, TRUE);
}

static gboolean
_enum_is_valid_flags_nick(const char *str)
{
    return str[0] && !NM_STRCHAR_ANY(str, ch, IS_FLAGS_SEPARATOR(ch)) && !_is_dec_string(str, FALSE)
           && !_is_hex_string(str, FALSE);
}

char *
_nm_utils_enum_to_str_full(GType                       type,
                           int                         value,
                           const char                 *flags_separator,
                           const NMUtilsEnumValueInfo *value_infos)
{
    nm_auto_unref_gtypeclass GTypeClass *klass = NULL;

    _ASSERT_enum_values_info(type, value_infos);

    if (flags_separator
        && (!flags_separator[0] || NM_STRCHAR_ANY(flags_separator, ch, !IS_FLAGS_SEPARATOR(ch))))
        g_return_val_if_reached(NULL);

    klass = g_type_class_ref(type);

    if (G_IS_ENUM_CLASS(klass)) {
        GEnumValue *enum_value;

        for (; value_infos && value_infos->nick; value_infos++) {
            if (value_infos->value == value)
                return g_strdup(value_infos->nick);
        }

        enum_value = g_enum_get_value(G_ENUM_CLASS(klass), value);
        if (!enum_value || !_enum_is_valid_enum_nick(enum_value->value_nick))
            return g_strdup_printf("%d", value);
        else
            return g_strdup(enum_value->value_nick);
    } else if (G_IS_FLAGS_CLASS(klass)) {
        unsigned     uvalue          = (unsigned) value;
        gboolean     uvalue_was_zero = (uvalue == 0);
        GFlagsValue *flags_value;
        NMStrBuf     strbuf;

        flags_separator = flags_separator ?: " ";

        strbuf = NM_STR_BUF_INIT(16, FALSE);

        for (; value_infos && value_infos->nick; value_infos++) {
            nm_assert(_enum_is_valid_flags_nick(value_infos->nick));

            if (value_infos->value == 0 && !uvalue_was_zero)
                continue;

            if (uvalue == 0) {
                if (value_infos->value != 0)
                    continue;
            } else {
                if (!NM_FLAGS_ALL(uvalue, (unsigned) value_infos->value))
                    continue;
            }

            if (strbuf.len)
                nm_str_buf_append(&strbuf, flags_separator);
            nm_str_buf_append(&strbuf, value_infos->nick);
            uvalue &= ~((unsigned) value_infos->value);
            if (uvalue == 0) {
                /* we printed all flags. Done. */
                goto flags_done;
            }
        }

        do {
            flags_value = g_flags_get_first_value(G_FLAGS_CLASS(klass), uvalue);
            if (strbuf.len)
                nm_str_buf_append(&strbuf, flags_separator);
            if (!flags_value || !_enum_is_valid_flags_nick(flags_value->value_nick)) {
                if (uvalue)
                    nm_str_buf_append_printf(&strbuf, "0x%x", uvalue);
                break;
            }
            nm_str_buf_append(&strbuf, flags_value->value_nick);
            uvalue &= ~flags_value->value;
        } while (uvalue);

flags_done:
        return nm_str_buf_finalize(&strbuf, NULL);
    }

    g_return_val_if_reached(NULL);
}

static const NMUtilsEnumValueInfo *
_find_value_info(const NMUtilsEnumValueInfo *value_infos, const char *needle)
{
    if (value_infos) {
        for (; value_infos->nick; value_infos++) {
            if (nm_streq(needle, value_infos->nick))
                return value_infos;
        }
    }
    return NULL;
}

gboolean
_nm_utils_enum_from_str_full(GType                       type,
                             const char                 *str,
                             int                        *out_value,
                             char                      **err_token,
                             const NMUtilsEnumValueInfo *value_infos)
{
    nm_auto_unref_gtypeclass GTypeClass *klass     = NULL;
    gboolean                             ret       = FALSE;
    int                                  value     = 0;
    gs_free char                        *str_clone = NULL;
    char                                *s;
    gint64                               v64;
    const NMUtilsEnumValueInfo          *nick;

    g_return_val_if_fail(str, FALSE);

    _ASSERT_enum_values_info(type, value_infos);

    s = nm_strdup_maybe_a(300, nm_str_skip_leading_spaces(str), &str_clone);
    g_strchomp(s);

    klass = g_type_class_ref(type);

    if (G_IS_ENUM_CLASS(klass)) {
        GEnumValue *enum_value;

        G_STATIC_ASSERT(G_MAXINT < G_MAXINT64);
        G_STATIC_ASSERT(G_MININT > G_MININT64);

        if (s[0]) {
            if (_is_hex_string(s, TRUE)) {
                if (s[0] == '-') {
                    v64 = _nm_utils_ascii_str_to_int64(&s[3],
                                                       16,
                                                       -((gint64) G_MAXINT),
                                                       -((gint64) G_MININT),
                                                       G_MAXINT64);
                    if (v64 != G_MAXINT64) {
                        value = (int) (-v64);
                        ret   = TRUE;
                    }
                } else {
                    v64 = _nm_utils_ascii_str_to_int64(&s[2], 16, G_MININT, G_MAXINT, G_MAXINT64);
                    if (v64 != G_MAXINT64) {
                        value = (int) v64;
                        ret   = TRUE;
                    }
                }
            } else if (_is_dec_string(s, TRUE)) {
                v64 = _nm_utils_ascii_str_to_int64(s, 10, G_MININT, G_MAXINT, G_MAXINT64);
                if (v64 != G_MAXINT64) {
                    value = (int) v64;
                    ret   = TRUE;
                }
            } else if ((nick = _find_value_info(value_infos, s))) {
                value = nick->value;
                ret   = TRUE;
            } else if ((enum_value = g_enum_get_value_by_nick(G_ENUM_CLASS(klass), s))) {
                value = enum_value->value;
                ret   = TRUE;
            }
        }
    } else if (G_IS_FLAGS_CLASS(klass)) {
        GFlagsValue *flags_value;
        unsigned     uvalue = 0;

        ret = TRUE;
        while (s[0]) {
            char *s_end;

            for (s_end = s; s_end[0]; s_end++) {
                if (IS_FLAGS_SEPARATOR(s_end[0])) {
                    s_end[0] = '\0';
                    s_end++;
                    break;
                }
            }

            if (s[0]) {
                if (_is_hex_string(s, FALSE)) {
                    v64 = _nm_utils_ascii_str_to_int64(&s[2], 16, 0, G_MAXUINT, -1);
                    if (v64 == -1) {
                        ret = FALSE;
                        break;
                    }
                    uvalue |= (unsigned) v64;
                } else if (_is_dec_string(s, FALSE)) {
                    v64 = _nm_utils_ascii_str_to_int64(s, 10, 0, G_MAXUINT, -1);
                    if (v64 == -1) {
                        ret = FALSE;
                        break;
                    }
                    uvalue |= (unsigned) v64;
                } else if ((nick = _find_value_info(value_infos, s)))
                    uvalue |= (unsigned) nick->value;
                else if ((flags_value = g_flags_get_value_by_nick(G_FLAGS_CLASS(klass), s)))
                    uvalue |= flags_value->value;
                else {
                    ret = FALSE;
                    break;
                }
            }

            s = s_end;
        }

        value = (int) uvalue;
    } else
        g_return_val_if_reached(FALSE);

    NM_SET_OUT(err_token, !ret && s[0] ? g_strdup(s) : NULL);
    NM_SET_OUT(out_value, ret ? value : 0);
    return ret;
}

const char **
_nm_utils_enum_get_values(GType type, int from, int to)
{
    int        i;
    GArray    *values_full = _nm_utils_enum_get_values_full(type, from, to, NULL);
    GPtrArray *values      = g_ptr_array_sized_new(values_full->len + 1);

    for (i = 0; i < values_full->len; i++) {
        NMUtilsEnumValueInfoFull *v = &g_array_index(values_full, NMUtilsEnumValueInfoFull, i);
        g_ptr_array_add(values, (gpointer) v->nick);
    }

    g_ptr_array_add(values, NULL);
    g_array_unref(values_full);
    return (const char **) g_ptr_array_free(values, FALSE);
}

static void
_free_value_info_full(NMUtilsEnumValueInfoFull *value_info_full)
{
    g_free(value_info_full->aliases);
}

static void
_init_value_info_full(NMUtilsEnumValueInfoFull *v, bool is_flag, const char *nick, int value)
{
    char        sbuf[64];
    const char *value_str = is_flag ? g_intern_string(nm_sprintf_buf(sbuf, "0x%x", value))
                                    : g_intern_string(nm_sprintf_buf(sbuf, "%d", value));

    v->nick      = _enum_is_valid_enum_nick(nick) ? nick : value_str;
    v->aliases   = NULL;
    v->value_str = value_str;
    v->value     = value;
}

/**
 * _nm_utils_enum_get_values_full:
 * @type: the enum or flags type
 * @from: lowest value to return
 * @to:   highest value to return
 * @value_infos: (nullable): additional value aliases
 * 
 * Get the enum or flags values within the given range, putting together the
 * value, name and aliases of each of them.
 *
 * If @value_infos is NULL, no memory will be allocated and deallocated for the
 * aliases and #NMUtilsEnumValueInfoFull:aliases will be NULL in the returned
 * data.
 *
 * The caller is responsible of releasing the container, but not the contained
 * data. Only #NMUtilsEnumValueInfoFull:aliases can be stolen (and set to NULL),
 * and then the caller becomes the responsible to release it.
 * 
 * Return: (transfer container): an array of #NMUtilsEnumValueInfoFull.
 */
GArray *
_nm_utils_enum_get_values_full(GType                       type,
                               int                         from,
                               int                         to,
                               const NMUtilsEnumValueInfo *value_infos)
{
    NMUtilsEnumValueInfoFull v;
    GArray                  *array;
    int                      i;

    nm_auto_unref_gtypeclass GTypeClass *klass = g_type_class_ref(type);
    g_return_val_if_fail(G_IS_ENUM_CLASS(klass) || G_IS_FLAGS_CLASS(klass), NULL);

    _ASSERT_enum_values_info(type, value_infos);

    array = g_array_new(FALSE, FALSE, sizeof(NMUtilsEnumValueInfoFull));

    if (G_IS_ENUM_CLASS(klass)) {
        GEnumClass *enum_class = G_ENUM_CLASS(klass);

        for (i = 0; i < enum_class->n_values; i++) {
            GEnumValue *enum_val = &enum_class->values[i];

            if (enum_val->value >= from && enum_val->value <= to) {
                _init_value_info_full(&v, FALSE, enum_val->value_nick, enum_val->value);
                g_array_append_val(array, v);
            }
        }
    } else {
        GFlagsClass *flags_class = G_FLAGS_CLASS(klass);

        for (i = 0; i < flags_class->n_values; i++) {
            GFlagsValue *flags_val = &flags_class->values[i];

            if (flags_val->value >= (guint) from && flags_val->value <= (guint) to) {
                _init_value_info_full(&v, TRUE, flags_val->value_nick, flags_val->value);
                g_array_append_val(array, v);
            }
        }
    }

    if (value_infos) {
        g_array_set_clear_func(array, (GDestroyNotify) _free_value_info_full);

        for (i = 0; i < array->len; i++) {
            NMUtilsEnumValueInfoFull *vi_full = &g_array_index(array, NMUtilsEnumValueInfoFull, i);
            GPtrArray                *aliases = g_ptr_array_new();

            const NMUtilsEnumValueInfo *vi;
            for (vi = value_infos; vi && vi->nick; vi++) {
                if (vi->value == vi_full->value)
                    g_ptr_array_add(aliases, (gpointer) vi->nick);
            }

            g_ptr_array_add(aliases, NULL);
            vi_full->aliases = (const char **) g_ptr_array_free(aliases, FALSE);
        }
    }

    return array;
}
