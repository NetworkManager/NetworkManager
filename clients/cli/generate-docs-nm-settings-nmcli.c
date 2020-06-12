// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include "nm-meta-setting-desc.h"

#define INDENT 4

static char *
_xml_escape_attribute (const char *value)
{
	gs_free char *s = NULL;

	s = g_markup_escape_text (value, -1);
	return g_strdup_printf ("\"%s\"", s);
}

static const char *
_indent_level (guint num_spaces)
{
	static const char spaces[] = "                      ";

	nm_assert (num_spaces < G_N_ELEMENTS (spaces));
	return &spaces[G_N_ELEMENTS (spaces) - num_spaces - 1];
}

int
main (int argc, char *argv[])
{
	int i_sett_infos;
	int i_property;

	g_print ("<nm-setting-docs>\n");
	for (i_sett_infos = 0; i_sett_infos < G_N_ELEMENTS (nm_meta_setting_infos_editor); i_sett_infos++) {
		const NMMetaSettingInfoEditor *sett_info = &nm_meta_setting_infos_editor[i_sett_infos];
		gs_free char *tmp_s1 = NULL;
		gs_free char *tmp_s2 = NULL;

		g_print ("%s<setting", _indent_level (INDENT));
		g_print (" name=%s", tmp_s1 = _xml_escape_attribute (sett_info->general->setting_name));
		if (sett_info->alias)
			g_print ("\n%salias=%s", _indent_level (INDENT + 9), tmp_s2 = _xml_escape_attribute (sett_info->alias));
		g_print (" >\n");

		for (i_property = 0; i_property < sett_info->properties_num; i_property++) {
			const NMMetaPropertyInfo *prop_info = sett_info->properties[i_property];
			gs_free char *tmp2 = NULL;
			gs_free char *tmp3 = NULL;
			gs_free char *tmp4 = NULL;

			g_print ("%s<property", _indent_level (2*INDENT));
			g_print (" name=%s", tmp2 = _xml_escape_attribute (prop_info->property_name));
			if (prop_info->property_alias)
				g_print ("\n%salias=%s", _indent_level (2*INDENT + 10), tmp3 = _xml_escape_attribute (prop_info->property_alias));
			if (prop_info->describe_doc)
				g_print ("\n%sdescription=%s", _indent_level (2*INDENT + 10), tmp4 = _xml_escape_attribute (prop_info->describe_doc));
			g_print (" />\n");
		}

		g_print ("%s</setting>\n", _indent_level (INDENT));
	}
	g_print ("</nm-setting-docs>\n");
	return 0;
}
