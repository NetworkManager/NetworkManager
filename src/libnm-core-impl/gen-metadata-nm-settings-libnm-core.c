/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "libnm-core-intern/nm-meta-setting-base.h"
#include "libnm-core-intern/nm-core-internal.h"

#define INDENT 4

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

int
main(int argc, char *argv[])
{
    const NMSettInfoSetting *sett_info_settings = nmtst_sett_info_settings();
    NMMetaSettingType        meta_type;

    g_print("<nm-setting-docs>\n");
    for (meta_type = 0; meta_type < _NM_META_SETTING_TYPE_NUM; meta_type++) {
        const NMSettInfoSetting                 *sis    = &sett_info_settings[meta_type];
        const NMMetaSettingInfo                 *msi    = &nm_meta_setting_infos[meta_type];
        nm_auto_unref_gtypeclass NMSettingClass *klass  = NULL;
        gs_free char                            *tmp_s1 = NULL;
        gs_free char                            *tmp_s2 = NULL;
        guint                                    prop_idx;
        GType                                    gtype;

        gtype = msi->get_setting_gtype();
        klass = g_type_class_ref(gtype);

        g_print("%s<setting", _indent_level(INDENT));
        g_print(" name=%s", (tmp_s1 = _xml_escape_attribute(msi->setting_name)));
        g_print(" >\n");

        for (prop_idx = 0; prop_idx < sis->property_infos_len; prop_idx++) {
            const NMSettInfoProperty *sip  = &sis->property_infos[prop_idx];
            gs_free char             *tmp2 = NULL;
            gs_free char             *tmp3 = NULL;

            g_print("%s<property", _indent_level(2 * INDENT));
            g_print(" name=%s", (tmp2 = _xml_escape_attribute(sip->name)));
            if (sip->is_deprecated)
                g_print("\n%sis-deprecated=\"1\"", _indent_level(2 * INDENT + 10));
            if (sip->property_type->dbus_type) {
                g_print(
                    "\n%sdbus-type=%s",
                    _indent_level(2 * INDENT + 10),
                    (tmp3 = _xml_escape_attribute((const char *) sip->property_type->dbus_type)));
            }
            if (sip->dbus_deprecated) {
                nm_assert(sip->property_type->dbus_type);
                g_print("\n%sdbus-deprecated=\"1\"", _indent_level(2 * INDENT + 10));
            }
            g_print(" />\n");
        }

        g_print("%s</setting>\n", _indent_level(INDENT));
    }
    g_print("</nm-setting-docs>\n");
    return 0;
}
