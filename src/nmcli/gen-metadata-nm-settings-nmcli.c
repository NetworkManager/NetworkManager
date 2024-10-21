/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "libnmc-setting/nm-meta-setting-desc.h"
#include "libnmc-setting/nm-meta-setting-base.h"
#include "libnm-glib-aux/nm-enum-utils.h"
#include "libnm-core-aux-intern/nm-common-macros.h"
#include "nm-core-enum-types.h"
#include <stdarg.h>
#include <stdlib.h>

#define INDENT 4

#define prop_assert(cond, ...)        \
    G_STMT_START                      \
    if (!(cond))                      \
        _prop_log(TRUE, __VA_ARGS__); \
    G_STMT_END
#define prop_abort(...) _prop_log(TRUE, __VA_ARGS__)
#define prop_warn(...)  _prop_log(FALSE, __VA_ARGS__)

static void G_GNUC_PRINTF(3, 4)
    _prop_log(gboolean fatal, const NMMetaPropertyInfo *prop_info, const char *fmt, ...)
{
    va_list       vaargs;
    gs_free char *msg      = NULL;
    gs_free char *msg_full = NULL;

    va_start(vaargs, fmt);
    msg      = g_strdup_vprintf(fmt, vaargs);
    msg_full = g_strdup_printf("gen-metadata-nm-settings-nmcli: %s.%s (type %d): %s\n",
                               prop_info->setting_info->general->setting_name,
                               prop_info->property_name,
                               (int) prop_info->property_type->doc_format,
                               msg);
    va_end(vaargs);

    if (fatal)
        g_error("%s", msg_full);
    else
        g_warning("%s", msg_full);
}

static char *
_xml_escape_attribute(const char *value)
{
    gs_free char *s = NULL;

    s = g_markup_escape_text(value, -1);
    return g_strdup_printf("\"%s\"", s);
}

static const char *
_indent_level(guint num_spaces)
{
    static const char spaces[] = "                      ";

    nm_assert(num_spaces < G_N_ELEMENTS(spaces));
    return &spaces[G_N_ELEMENTS(spaces) - num_spaces - 1];
}

static GType
_property_get_gtype(const NMMetaPropertyInfo *prop_info)
{
    nm_auto_unref_gtypeclass NMSettingClass *setting_class =
        g_type_class_ref(prop_info->setting_info->general->get_setting_gtype());
    GParamSpec *param_spec =
        g_object_class_find_property(G_OBJECT_CLASS(setting_class), prop_info->property_name);

    if (param_spec)
        return param_spec->value_type;
    g_return_val_if_reached(G_TYPE_INVALID);
}

static char *
get_enum_format(GType g_type)
{
    if (G_TYPE_IS_FLAGS(g_type))
        return g_strdup_printf("flags (%s)", g_type_name(g_type));
    else
        return g_strdup_printf("choice (%s)", g_type_name(g_type));
}

static char *
get_mac_format(const NMMetaPropertyInfo *prop_info)
{
    const NMMetaPropertyTypData *prop_typ_data = prop_info->property_typ_data;

    if (prop_typ_data) {
        switch (prop_typ_data->subtype.mac.mode) {
        case NM_META_PROPERTY_TYPE_MAC_MODE_DEFAULT:
        case NM_META_PROPERTY_TYPE_MAC_MODE_CLONED_ETHERNET:
        case NM_META_PROPERTY_TYPE_MAC_MODE_CLONED_WIFI:
            break;
        case NM_META_PROPERTY_TYPE_MAC_MODE_INFINIBAND:
            return g_strdup("Infiniband MAC address");
        case NM_META_PROPERTY_TYPE_MAC_MODE_WPAN:
            return g_strdup("WPAN MAC address");
        default:
            prop_abort(prop_info, "unknown mode (%d)", prop_typ_data->subtype.mac.mode);
            break;
        }
    }

    return g_strdup("MAC address");
}

static char *
get_ethtool_format(const NMMetaPropertyInfo *prop_info)
{
    NMEthtoolID ethtool_id;

    prop_assert(prop_info->property_typ_data, prop_info, "missing .property_typ_data");

    ethtool_id = prop_info->property_typ_data->subtype.ethtool.ethtool_id;

    switch (nm_ethtool_id_to_type(ethtool_id)) {
    case NM_ETHTOOL_TYPE_CHANNELS:
    case NM_ETHTOOL_TYPE_COALESCE:
    case NM_ETHTOOL_TYPE_RING:
        return g_strdup("integer");
    case NM_ETHTOOL_TYPE_FEATURE:
    case NM_ETHTOOL_TYPE_PAUSE:
    case NM_ETHTOOL_TYPE_EEE:
        return g_strdup("ternary");
    case NM_ETHTOOL_TYPE_FEC:
        return g_strdup("flags (NMSettingEthtoolFecMode)");
    case NM_ETHTOOL_TYPE_UNKNOWN:
        nm_assert_not_reached();
    };

    return NULL;
}

static char *
get_multilist_format(const NMMetaPropertyInfo *prop_info)
{
    NMMetaPropertyTypeFormat item_fmt;

    if (prop_info->property_typ_data) {
        item_fmt = prop_info->property_typ_data->list_items_doc_format;

        switch (item_fmt) {
        case NM_META_PROPERTY_TYPE_FORMAT_UNDEF:
            prop_abort(prop_info, "undefined item format for multilist");
            break;
        case NM_META_PROPERTY_TYPE_FORMAT_INT:
        case NM_META_PROPERTY_TYPE_FORMAT_MTU:
            return g_strdup("list of integers");
        case NM_META_PROPERTY_TYPE_FORMAT_STRING:
            return g_strdup("list of strings");
        case NM_META_PROPERTY_TYPE_FORMAT_BOOL:
            return g_strdup("list of booleans");
        case NM_META_PROPERTY_TYPE_FORMAT_TERNARY:
            return g_strdup("list of ternaries");
        case NM_META_PROPERTY_TYPE_FORMAT_MAC:
            return g_strdup("list of MAC addresses");
        case NM_META_PROPERTY_TYPE_FORMAT_IPV4:
            return g_strdup("list of IPv4 addresses");
        case NM_META_PROPERTY_TYPE_FORMAT_IPV6:
            return g_strdup("list of IPv6 addresses");
        default:
            prop_abort(prop_info, "unsupported item format (%d)", item_fmt);
            break;
        }
    }

    return NULL;
}

static char *
get_property_format(const NMMetaPropertyInfo *prop_info)
{
    const NMMetaPropertyType *prop_type = prop_info->property_type;
    NMMetaPropertyTypeFormat  fmt       = prop_type->doc_format;

    if (!prop_type->set_fcn)
        return g_strdup("read only");

    switch (fmt) {
    case NM_META_PROPERTY_TYPE_FORMAT_INT:
    case NM_META_PROPERTY_TYPE_FORMAT_MTU:
        return g_strdup("integer");
    case NM_META_PROPERTY_TYPE_FORMAT_STRING:
        return g_strdup("string");
    case NM_META_PROPERTY_TYPE_FORMAT_ENUM:
        return get_enum_format(nm_meta_property_enum_get_type(prop_info));
    case NM_META_PROPERTY_TYPE_FORMAT_SECRET_FLAGS:
        return get_enum_format(NM_TYPE_SETTING_SECRET_FLAGS);
    case NM_META_PROPERTY_TYPE_FORMAT_DCB_FLAGS:
        return get_enum_format(NM_TYPE_SETTING_DCB_FLAGS);
    case NM_META_PROPERTY_TYPE_FORMAT_BOOL:
        return g_strdup("boolean");
    case NM_META_PROPERTY_TYPE_FORMAT_TERNARY:
        return g_strdup("ternary");
    case NM_META_PROPERTY_TYPE_FORMAT_MAC:
        return get_mac_format(prop_info);
    case NM_META_PROPERTY_TYPE_FORMAT_IPV4:
        return g_strdup("IPv4 address");
    case NM_META_PROPERTY_TYPE_FORMAT_IPV6:
        return g_strdup("IPv6 address");
    case NM_META_PROPERTY_TYPE_FORMAT_BYTES:
        return g_strdup("bytes");
    case NM_META_PROPERTY_TYPE_FORMAT_PATH:
        return g_strdup("filesystem path");
    case NM_META_PROPERTY_TYPE_FORMAT_ETHTOOL:
        return get_ethtool_format(prop_info);
    case NM_META_PROPERTY_TYPE_FORMAT_MULTILIST:
        return get_multilist_format(prop_info);
    case NM_META_PROPERTY_TYPE_FORMAT_OBJLIST:
        return g_strdup_printf("list of %s.%s objects",
                               prop_info->setting_info->general->setting_name,
                               prop_info->property_name);
    case NM_META_PROPERTY_TYPE_FORMAT_OPTIONLIST:
        return g_strdup("list of key/value options");
    case NM_META_PROPERTY_TYPE_FORMAT_DCB:
        return g_strdup("list of integers");
    case NM_META_PROPERTY_TYPE_FORMAT_DCB_BOOL:
        return g_strdup("list of booleans");
    default:
        prop_abort(prop_info, "missing .format");
        return NULL;
    }
}

#define append_vals(to, ...)                          \
    G_STMT_START                                      \
    {                                                 \
        size_t      i;                                \
        const char *from[] = {__VA_ARGS__};           \
        for (i = 0; i < NM_N_ELEMENTS(from); i++)     \
            g_ptr_array_add((to), g_strdup(from[i])); \
    }                                                 \
    G_STMT_END

static void
append_connection_types(GPtrArray *valid_values)
{
    size_t i;
    for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++) {
        /* If the setting has a priority of a base-type, it's a valid value for connection.type */
        NMSettingPriority pri =
            _nm_setting_type_get_base_type_priority(nm_meta_setting_infos[i].get_setting_gtype());
        if (pri != NM_SETTING_PRIORITY_INVALID)
            g_ptr_array_add(valid_values, g_strdup(nm_meta_setting_infos[i].setting_name));
    }
}

static void
append_int_valid_range(const NMMetaPropertyInfo *prop_info, GPtrArray *valid_values)
{
    NMMetaSignUnsignInt64 min;
    NMMetaSignUnsignInt64 max;

    nm_meta_property_int_get_range(prop_info, &min, &max);
    if (NM_IN_SET(_property_get_gtype(prop_info), G_TYPE_UINT, G_TYPE_UINT64)) {
        g_ptr_array_add(
            valid_values,
            g_strdup_printf("%" G_GUINT64_FORMAT " - %" G_GUINT64_FORMAT, min.u64, max.u64));
    } else {
        g_ptr_array_add(
            valid_values,
            g_strdup_printf("%" G_GINT64_FORMAT " - %" G_GINT64_FORMAT, min.i64, max.i64));
    }
}

static void
_append_enum_valid_values(GType                       g_type,
                          int                         min,
                          int                         max,
                          const NMUtilsEnumValueInfo *value_infos,
                          GPtrArray                  *valid_values)
{
    size_t       i;
    const char **alias;
    GString     *names  = g_string_sized_new(64);
    GArray      *values = _nm_utils_enum_get_values_full(g_type, min, max, value_infos);

    for (i = 0; i < values->len; i++) {
        NMUtilsEnumValueInfoFull *val = &nm_g_array_index(values, NMUtilsEnumValueInfoFull, i);

        g_string_assign(names, val->nick);

        if (val->aliases) {
            for (alias = val->aliases; *alias; alias++) {
                g_string_append_c(names, '/');
                g_string_append(names, *alias);
            }
        }

        g_ptr_array_add(valid_values, g_strdup_printf("%s (%s)", names->str, val->value_str));
    }

    g_string_free(names, TRUE);
    g_array_unref(values);
}

static void
append_enum_valid_values(const NMMetaPropertyInfo *prop_info, GPtrArray *valid_values)
{
    const NMMetaPropertyTypData *prop_typ_data = prop_info->property_typ_data;
    const NMUtilsEnumValueInfo  *value_infos;
    GType                        gtype;
    int                          min;
    int                          max;

    gtype = nm_meta_property_enum_get_type(prop_info);
    nm_meta_property_enum_get_range(prop_info, &min, &max);
    value_infos = prop_typ_data ? prop_typ_data->subtype.gobject_enum.value_infos : NULL;

    _append_enum_valid_values(gtype, min, max, value_infos, valid_values);
}

static void
append_ethtool_valid_values(const NMMetaPropertyInfo *prop_info, GPtrArray *valid_values)
{
    NMEthtoolID ethtool_id;

    prop_assert(prop_info->property_typ_data, prop_info, "missing .property_typ_data");

    ethtool_id = prop_info->property_typ_data->subtype.ethtool.ethtool_id;

    switch (nm_ethtool_id_to_type(ethtool_id)) {
    case NM_ETHTOOL_TYPE_CHANNELS:
    case NM_ETHTOOL_TYPE_COALESCE:
    case NM_ETHTOOL_TYPE_RING:
        g_ptr_array_add(valid_values, g_strdup_printf("0 - %u", G_MAXUINT32));
        break;
    case NM_ETHTOOL_TYPE_FEATURE:
    case NM_ETHTOOL_TYPE_PAUSE:
    case NM_ETHTOOL_TYPE_EEE:
        append_vals(valid_values, "on", "off", "ignore");
        break;
    case NM_ETHTOOL_TYPE_FEC:
        _append_enum_valid_values(NM_TYPE_SETTING_ETHTOOL_FEC_MODE,
                                  0,
                                  G_MAXUINT,
                                  NULL,
                                  valid_values);
        break;
    case NM_ETHTOOL_TYPE_UNKNOWN:
        nm_assert_not_reached();
    }
}

static void
append_dcb_valid_values(const NMMetaPropertyInfo *prop_info, GPtrArray *valid_values)
{
    guint max;
    guint other;

    prop_assert(prop_info->property_typ_data, prop_info, "missing .property_typ_data");

    max   = prop_info->property_typ_data->subtype.dcb.max;
    other = prop_info->property_typ_data->subtype.dcb.other;

    if (max != 0)
        g_ptr_array_add(valid_values, g_strdup_printf("0 - %u", max));
    if (other != 0 && (!max || other > max))
        g_ptr_array_add(valid_values, g_strdup_printf("%u", other));
}

static GPtrArray *
get_property_valid_values(const NMMetaPropertyInfo *prop_info)
{
    const NMMetaPropertyType    *prop_type     = prop_info->property_type;
    const NMMetaPropertyTypData *prop_typ_data = prop_info->property_typ_data;
    NMMetaPropertyTypeFormat     fmt           = prop_type->doc_format;
    GPtrArray                   *valid_values  = g_ptr_array_new_full(16, g_free);

    /* connection.type is generated differently */
    if (prop_info->setting_info->general->meta_type == NM_META_SETTING_TYPE_CONNECTION
        && !nm_strcmp0(prop_info->property_name, "type")) {
        append_connection_types(valid_values);
        return valid_values;
    }

    /* If it's a list, get the format of the items, but only  if we can process it
     * (prop_typ_data->subtype is of type multilist, so we can't process ints or enums) */
    if (fmt == NM_META_PROPERTY_TYPE_FORMAT_MULTILIST && prop_typ_data) {
        switch (prop_typ_data->list_items_doc_format) {
        case NM_META_PROPERTY_TYPE_FORMAT_SECRET_FLAGS:
        case NM_META_PROPERTY_TYPE_FORMAT_DCB_FLAGS:
        case NM_META_PROPERTY_TYPE_FORMAT_BOOL:
        case NM_META_PROPERTY_TYPE_FORMAT_DCB_BOOL:
        case NM_META_PROPERTY_TYPE_FORMAT_TERNARY:
        case NM_META_PROPERTY_TYPE_FORMAT_ETHTOOL:
            fmt = prop_typ_data->list_items_doc_format;
            break;
        case NM_META_PROPERTY_TYPE_FORMAT_ENUM:
            prop_warn(prop_info, "unknown enum type, can't get valid values");
            break;
        case NM_META_PROPERTY_TYPE_FORMAT_INT:
            prop_warn(prop_info, "can't check for valid range in multilists");
            break;
        default:
            /* Other types probably don't need to show "Valid values" */
            break;
        }
    }

    switch (fmt) {
    case NM_META_PROPERTY_TYPE_FORMAT_INT:
        append_int_valid_range(prop_info, valid_values);
        break;
    case NM_META_PROPERTY_TYPE_FORMAT_ENUM:
        append_enum_valid_values(prop_info, valid_values);
        break;
    case NM_META_PROPERTY_TYPE_FORMAT_SECRET_FLAGS:
        _append_enum_valid_values(NM_TYPE_SETTING_SECRET_FLAGS, 0, G_MAXUINT, NULL, valid_values);
        break;
    case NM_META_PROPERTY_TYPE_FORMAT_DCB_FLAGS:
        _append_enum_valid_values(NM_TYPE_SETTING_DCB_FLAGS, 0, G_MAXUINT, NULL, valid_values);
        break;
    case NM_META_PROPERTY_TYPE_FORMAT_BOOL:
    case NM_META_PROPERTY_TYPE_FORMAT_DCB_BOOL:
        append_vals(valid_values, "true/yes/on", "false/no/off");
        break;
    case NM_META_PROPERTY_TYPE_FORMAT_TERNARY:
        append_vals(valid_values, "true/yes/on", "false/no/off", "default/unknown");
        break;
    case NM_META_PROPERTY_TYPE_FORMAT_ETHTOOL:
        append_ethtool_valid_values(prop_info, valid_values);
        break;
    case NM_META_PROPERTY_TYPE_FORMAT_DCB:
        append_dcb_valid_values(prop_info, valid_values);
        break;
    default:
        break;
    }

    if (prop_typ_data && prop_typ_data->values_static) {
        const char *const *v;
        for (v = prop_typ_data->values_static; *v; v++)
            g_ptr_array_add(valid_values, g_strdup(*v));
    }

    return valid_values;
}

static void
append_int_special_values(const NMMetaPropertyInfo *prop_info, GPtrArray *special_values)
{
    const NMMetaPropertyTypData *prop_typ_data = prop_info->property_typ_data;

    if (prop_typ_data && prop_typ_data->subtype.gobject_int.value_infos) {
        GType                          gtype   = _property_get_gtype(prop_info);
        bool                           is_uint = NM_IN_SET(gtype, G_TYPE_UINT, G_TYPE_UINT64);
        guint                          base    = prop_typ_data->subtype.gobject_int.base;
        const NMMetaUtilsIntValueInfo *v       = prop_typ_data->subtype.gobject_int.value_infos;

        if (!(base == 0 || base == 10 || (is_uint && base == 16))) {
            if (is_uint)
                prop_abort(prop_info, "only base 10 supported for signed int");
            else
                prop_abort(prop_info, "only base 10 or 16 supported for uint");
        }

        for (; v->nick != NULL; v++) {
            char *v_str;
            if (base == 16)
                v_str = g_strdup_printf("%s (0x%" G_GINT64_MODIFIER "x)", v->nick, v->value.u64);
            else if (is_uint)
                v_str = g_strdup_printf("%s (%" G_GUINT64_FORMAT ")", v->nick, v->value.u64);
            else
                v_str = g_strdup_printf("%s (%" G_GINT64_FORMAT ")", v->nick, v->value.i64);

            g_ptr_array_add(special_values, v_str);
        }
    }
}

static GPtrArray *
get_property_special_values(const NMMetaPropertyInfo *prop_info)
{
    const NMMetaPropertyType    *prop_type      = prop_info->property_type;
    const NMMetaPropertyTypData *prop_typ_data  = prop_info->property_typ_data;
    NMMetaPropertyTypeFormat     fmt            = prop_type->doc_format;
    GPtrArray                   *special_values = g_ptr_array_new_full(16, g_free);

    switch (fmt) {
    case NM_META_PROPERTY_TYPE_FORMAT_INT:
        append_int_special_values(prop_info, special_values);
        break;
    case NM_META_PROPERTY_TYPE_FORMAT_MAC:
        if (prop_typ_data) {
            switch (prop_typ_data->subtype.mac.mode) {
            case NM_META_PROPERTY_TYPE_MAC_MODE_CLONED_ETHERNET:
            case NM_META_PROPERTY_TYPE_MAC_MODE_CLONED_WIFI:
                append_vals(special_values,
                            NM_CLONED_MAC_PRESERVE,
                            NM_CLONED_MAC_PERMANENT,
                            NM_CLONED_MAC_RANDOM,
                            NM_CLONED_MAC_STABLE);
                if (prop_typ_data->subtype.mac.mode == NM_META_PROPERTY_TYPE_MAC_MODE_CLONED_WIFI)
                    append_vals(special_values, NM_CLONED_MAC_STABLE_SSID);
                break;
            default:
                break;
            }
        }
        break;
    case NM_META_PROPERTY_TYPE_FORMAT_MTU:
        g_ptr_array_add(special_values, g_strdup("auto"));
        break;
    default:
        break;
    }

    return special_values;
}

int
main(int argc, char *argv[])
{
    int i_sett_infos;
    int i_property;

    g_print("<nm-setting-docs>\n");
    for (i_sett_infos = 0; i_sett_infos < G_N_ELEMENTS(nm_meta_setting_infos_editor);
         i_sett_infos++) {
        const NMMetaSettingInfoEditor *sett_info = &nm_meta_setting_infos_editor[i_sett_infos];
        gs_free char                  *tmp_s1    = NULL;
        gs_free char                  *tmp_s2    = NULL;

        g_print("%s<setting", _indent_level(INDENT));
        g_print(" name=%s", tmp_s1 = _xml_escape_attribute(sett_info->general->setting_name));
        if (sett_info->alias)
            g_print("\n%salias=%s",
                    _indent_level(INDENT + 9),
                    tmp_s2 = _xml_escape_attribute(sett_info->alias));
        g_print(" >\n");

        for (i_property = 0; i_property < sett_info->properties_num; i_property++) {
            const NMMetaPropertyInfo    *prop_info    = sett_info->properties[i_property];
            gs_free char                *name         = NULL;
            gs_free char                *alias        = NULL;
            gs_free char                *descr        = NULL;
            gs_free char                *fmt          = NULL;
            gs_unref_ptrarray GPtrArray *vals_arr     = NULL;
            gs_free char                *vals_str     = NULL;
            gs_unref_ptrarray GPtrArray *specials_arr = NULL;
            gs_free char                *specials_str = NULL;

            g_print("%s<property", _indent_level(2 * INDENT));
            g_print(" name=%s", name = _xml_escape_attribute(prop_info->property_name));
            if (prop_info->property_alias)
                g_print("\n%salias=%s",
                        _indent_level(2 * INDENT + 10),
                        alias = _xml_escape_attribute(prop_info->property_alias));
            if (prop_info->describe_doc) {
                /* These descriptions are used by interactive nmcli modes. For the most part,
                 * they are themselves generated (see "settings-docs.h"). Some of them are instead
                 * explicitly (manually) set.
                 *
                 * In any case, they serve little purpose outside of nmcli's interactive mode,
                 * because their formatting/wording would not be suitable.
                 *
                 * We generate this XML mainly to generate `man nm-settings-nmcli`, but the
                 * descriptions in "describe_doc" field are not suitable there.
                 *
                 * Name them something else ("<nmcli-description>") which isn't actually used. */
                g_print("\n%snmcli-description=%s",
                        _indent_level(2 * INDENT + 10),
                        descr = _xml_escape_attribute(prop_info->describe_doc));
            }

            fmt = get_property_format(prop_info);
            if (fmt)
                g_print("\n%sformat=%s",
                        _indent_level(2 * INDENT + 10),
                        _xml_escape_attribute(fmt));

            vals_arr = get_property_valid_values(prop_info);
            if (vals_arr->len) {
                g_ptr_array_add(vals_arr, NULL);
                vals_str = g_strjoinv(", ", (char **) vals_arr->pdata);
                g_print("\n%svalues=%s",
                        _indent_level(2 * INDENT + 10),
                        _xml_escape_attribute(vals_str));
            }

            specials_arr = get_property_special_values(prop_info);
            if (specials_arr->len) {
                g_ptr_array_add(specials_arr, NULL);
                specials_str = g_strjoinv(", ", (char **) specials_arr->pdata);
                g_print("\n%sspecial-values=%s",
                        _indent_level(2 * INDENT + 10),
                        _xml_escape_attribute(specials_str));
            }

            g_print(" />\n");
        }

        g_print("%s</setting>\n", _indent_level(INDENT));
    }
    g_print("</nm-setting-docs>\n");
    return 0;
}
