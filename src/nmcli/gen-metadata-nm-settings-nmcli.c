/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "libnmc-setting/nm-meta-setting-desc.h"
#include "libnmc-setting/nm-meta-setting-base.h"
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
                               prop_info->property_type->doc_format,
                               msg);
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
_get_enum_format(GType g_type)
{
    if (G_TYPE_IS_FLAGS(g_type))
        return g_strdup_printf("flags (%s)", g_type_name(g_type));
    else
        return g_strdup_printf("choice (%s)", g_type_name(g_type));
}

static char *
get_enum_format(const NMMetaPropertyInfo *prop_info)
{
    GType                        gtype         = G_TYPE_INVALID;
    const NMMetaPropertyTypData *prop_typ_data = prop_info->property_typ_data;

    if (prop_typ_data && prop_typ_data->subtype.gobject_enum.get_gtype)
        gtype = prop_typ_data->subtype.gobject_enum.get_gtype();
    else
        gtype = _property_get_gtype(prop_info);

    prop_assert(gtype != G_TYPE_INVALID, prop_info, "unknown property's enum type");

    return _get_enum_format(gtype);
}

static char *
get_mac_format(const NMMetaPropertyInfo *prop_info)
{
    const NMMetaPropertyTypData *prop_typ_data = prop_info->property_typ_data;

    if (prop_typ_data) {
        switch (prop_typ_data->subtype.mac.mode) {
        case NM_META_PROPERTY_TYPE_MAC_MODE_DEFAULT:
        case NM_META_PROPERTY_TYPE_MAC_MODE_CLONED:
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

    if (nm_ethtool_id_is_coalesce(ethtool_id) || nm_ethtool_id_is_ring(ethtool_id))
        return g_strdup("integer");
    else if (nm_ethtool_id_is_feature(ethtool_id) || nm_ethtool_id_is_pause(ethtool_id))
        return g_strdup("ternary");
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
        return get_enum_format(prop_info);
    case NM_META_PROPERTY_TYPE_FORMAT_SECRET_FLAGS:
        return _get_enum_format(NM_TYPE_SETTING_SECRET_FLAGS);
    case NM_META_PROPERTY_TYPE_FORMAT_DCB_FLAGS:
        return _get_enum_format(NM_TYPE_SETTING_DCB_FLAGS);
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
            const NMMetaPropertyInfo *prop_info = sett_info->properties[i_property];
            gs_free char             *name      = NULL;
            gs_free char             *alias     = NULL;
            gs_free char             *descr     = NULL;
            gs_free char             *fmt       = NULL;

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

            g_print(" />\n");
        }

        g_print("%s</setting>\n", _indent_level(INDENT));
    }
    g_print("</nm-setting-docs>\n");
    return 0;
}
