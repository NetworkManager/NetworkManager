/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "libnm-glib-aux/nm-str-buf.h"
#include "libnm-core-intern/nm-meta-setting-base.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "libnm-base/nm-ethtool-base.h"

#include "libnm-core-public/nm-setting-ethtool.h"

#define INDENT 4

static const char *
_xml_escape_attr(NMStrBuf *sbuf, const char *value)
{
    gs_free char *s = NULL;

    nm_str_buf_reset(sbuf);
    s = g_markup_escape_text(value, -1);
    nm_str_buf_append_c(sbuf, '"');
    nm_str_buf_append(sbuf, s);
    nm_str_buf_append_c(sbuf, '"');
    return nm_str_buf_get_str(sbuf);
}

static const char *
_indent_level(guint num_spaces)
{
    static const char spaces[] = "                      ";

    nm_assert(num_spaces < G_N_ELEMENTS(spaces));
    return &spaces[G_N_ELEMENTS(spaces) - num_spaces - 1];
}

int
main(int argc, char *argv[])
{
    nm_auto_str_buf NMStrBuf sbuf1 = NM_STR_BUF_INIT(NM_UTILS_GET_NEXT_REALLOC_SIZE_1000, FALSE);
    const NMSettInfoSetting *sett_info_settings = nmtst_sett_info_settings();
    NMMetaSettingType        meta_type;

    g_print("<!--\n"
            "  This file is generated.\n"
            "\n"
            "  This XML contains meta data of NetworkManager connection profiles.\n"
            "\n"
            "  NetworkManager's connection profiles are a bunch of settings, and this\n"
            "  contains the known properties. See also `man nm-settings-{dbus,nmcli,keyfile}`.\n"
            "\n"
            "  Note that there are different manifestations of these properties. We have them\n"
            "  on the D-Bus API (`man nm-settings-dbus`), in keyfile format (`man "
            "nm-settings-keyfile`)\n"
            "  in libnm's NMConnection and NMSetting API, and in nmcli (`man nm-settings-nmcli`).\n"
            "  There are similarities between these, but also subtle differencs. For example,\n"
            "  a property might not be shown in nmcli, or a property might be named different\n"
            "  on D-Bus or keyfile. Also, the data types may differ due to the differences of the\n"
            "  technology.\n"
            "\n"
            "  This list of properties is not directly the properties as they are in any of\n"
            "  those manifestations. Instead, it's a general idea that this property exists in\n"
            "  NetworkManager. Whether and how it is represented in nmcli or keyfile, may differ.\n"
            "  The XML however aims to provide information for various backends.\n"
            "\n"
            "  <setting> Attributes:\n"
            "   \"name\": the name of the setting.\n"
            "   \"gtype\": the typename of the NMSetting class in libnm.\n"
            "\n"
            "  <property> Attributes:\n"
            "   \"name\": the name of the property.\n"
            "   \"is-deprecated\": whether this property is deprecated.\n"
            "   \"is-secret\": whether this property is a secret.\n"
            "   \"is-secret-flags\": whether this property is a secret flags property.\n"
            "   \"dbus-type\": if this property is exposed on D-Bus. In that case, this\n"
            "       is the D-Bus type format. Also, \"name\" is the actual name of the field\n"
            "   \"dbus-deprecated\": if this property is on D-Bus and that representation is\n"
            "       deprecated. This usually means, that there is a replacement D-Bus property\n"
            "       that should be used instead.\n"
            "   \"gprop-type\": if this is a GObject property in the NMSetting class, this\n"
            "       is the GParamSpec.value_type of the property.\n"
            "   \"is-setting-option\": whether the property is implemented in libnm's NMSetting\n"
            "       via the nm_setting_option_*() API.\n"
            " -->\n");
    g_print("<nm-setting-docs>\n");
    for (meta_type = 0; meta_type < _NM_META_SETTING_TYPE_NUM; meta_type++) {
        const NMSettInfoSetting                 *sis   = &sett_info_settings[meta_type];
        const NMMetaSettingInfo                 *msi   = &nm_meta_setting_infos[meta_type];
        nm_auto_unref_gtypeclass NMSettingClass *klass = NULL;
        guint                                    prop_idx;
        GType                                    gtype;

        gtype = msi->get_setting_gtype();
        klass = g_type_class_ref(gtype);

        g_print("%s<setting", _indent_level(INDENT));
        g_print(" name=%s", _xml_escape_attr(&sbuf1, msi->setting_name));
        g_print("\n%sgtype=%s",
                _indent_level(INDENT + 9),
                _xml_escape_attr(&sbuf1, g_type_name(gtype)));
        g_print("\n%s>\n", _indent_level(INDENT + 9));

        for (prop_idx = 0; prop_idx < sis->property_infos_len; prop_idx++) {
            const NMSettInfoProperty *sip = &sis->property_infos[prop_idx];

            if (nm_streq(sip->name, NM_SETTING_NAME))
                continue;

            g_print("%s<property", _indent_level(2 * INDENT));
            g_print(" name=%s", _xml_escape_attr(&sbuf1, sip->name));
            if (sip->is_deprecated)
                g_print("\n%sis-deprecated=\"1\"", _indent_level(2 * INDENT + 10));
            if (sip->param_spec && NM_FLAGS_HAS(sip->param_spec->flags, NM_SETTING_PARAM_SECRET)) {
                g_print("\n%sis-secret=\"1\"", _indent_level(2 * INDENT + 10));
            }
            if (sip->param_spec
                && G_PARAM_SPEC_VALUE_TYPE(sip->param_spec) == NM_TYPE_SETTING_SECRET_FLAGS) {
                g_print("\n%sis-secret-flags=\"1\"", _indent_level(2 * INDENT + 10));
            }
            if (sip->property_type->dbus_type) {
                g_print("\n%sdbus-type=%s",
                        _indent_level(2 * INDENT + 10),
                        _xml_escape_attr(&sbuf1, (const char *) sip->property_type->dbus_type));
            }
            if (sip->dbus_deprecated) {
                nm_assert(sip->property_type->dbus_type);
                g_print("\n%sdbus-deprecated=\"1\"", _indent_level(2 * INDENT + 10));
            }
            if (sip->param_spec) {
                nm_assert(nm_streq(sip->name, sip->param_spec->name));
                g_print("\n%sgprop-type=%s",
                        _indent_level(2 * INDENT + 10),
                        _xml_escape_attr(&sbuf1,
                                         g_type_name(G_PARAM_SPEC_VALUE_TYPE(sip->param_spec))));
            }
            g_print("\n%s/>\n", _indent_level(2 * INDENT + 10));
        }

        if (nm_streq(msi->setting_name, NM_SETTING_ETHTOOL_SETTING_NAME)) {
            NMEthtoolID ethtool_id;

            /* NMSettingEthtool's properties are "gendata" options. They are implemented differently. */
            for (ethtool_id = _NM_ETHTOOL_ID_FIRST; ethtool_id <= _NM_ETHTOOL_ID_LAST;
                 ethtool_id++) {
                g_print("%s<property", _indent_level(2 * INDENT));
                g_print(" name=%s", _xml_escape_attr(&sbuf1, nm_ethtool_data[ethtool_id]->optname));
                g_print(
                    "\n%sdbus-type=%s",
                    _indent_level(2 * INDENT + 10),
                    _xml_escape_attr(&sbuf1,
                                     (const char *) nm_ethtool_id_get_variant_type(ethtool_id)));
                g_print("\n%sis-setting-option=\"1\"", _indent_level(2 * INDENT + 10));
                g_print("\n%s/>\n", _indent_level(2 * INDENT + 10));
            }
        }

        g_print("%s</setting>\n", _indent_level(INDENT));
    }
    g_print("</nm-setting-docs>\n");
    return 0;
}
