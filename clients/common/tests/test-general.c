/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "NetworkManager.h"

#include "nm-meta-setting-access.h"

#include "nm-utils/nm-test-utils.h"

/*****************************************************************************/

static void
test_client_meta_check (void)
{
	const NMMetaSettingInfoEditor *const*infos_p;
	NMMetaSettingType m;
	guint p;

	for (m = 0; m < _NM_META_SETTING_TYPE_NUM; m++) {
		const NMMetaSettingInfo *info = &nm_meta_setting_infos[m];
		GType gtype;

		g_assert (info);
		g_assert (info->meta_type == m);
		g_assert (info->setting_name);
		g_assert (info->get_setting_gtype);

		gtype = info->get_setting_gtype ();
		g_assert (gtype != NM_TYPE_SETTING);

		{
			nm_auto_unref_gtypeclass GTypeClass *gclass = g_type_class_ref (gtype);

			g_assert (G_TYPE_CHECK_CLASS_TYPE (gclass, gtype));
		}
		{
			gs_unref_object NMSetting *setting = g_object_new (gtype, NULL);

			g_assert (NM_IS_SETTING (setting));
			g_assert (G_TYPE_CHECK_INSTANCE_TYPE (setting, gtype));
			g_assert_cmpstr (nm_setting_get_name (setting), ==, info->setting_name);
		}
	}

	for (m = 0; m < _NM_META_SETTING_TYPE_NUM; m++) {
		const NMMetaSettingInfoEditor *info = &nm_meta_setting_infos_editor[m];

		g_assert (info);
		g_assert (info->meta_type == &nm_meta_type_setting_info_editor);
		g_assert (info->general);
		g_assert (info->general == &nm_meta_setting_infos[m]);

		g_assert (info->general->setting_name == info->meta_type->get_name ((const NMMetaAbstractInfo *) info));

		if (info->properties_num) {
			gs_unref_hashtable GHashTable *property_names = g_hash_table_new (g_str_hash, g_str_equal);

			g_assert (info->properties);
			for (p = 0; p < info->properties_num; p++) {
				const NMMetaPropertyInfo *pi = &info->properties[p];

				g_assert (pi->meta_type == &nm_meta_type_property_info);
				g_assert (pi->setting_info == info);
				g_assert (pi->property_name);

				g_assert (nm_g_hash_table_add (property_names, (gpointer) pi->property_name));

				g_assert (pi->property_name == pi->meta_type->get_name ((const NMMetaAbstractInfo *) pi));

				g_assert (pi->property_type);
				g_assert (pi->property_type->get_fcn);
			}
		} else
			g_assert (!info->properties);
	}

	for (m = 0; m < _NM_META_SETTING_TYPE_NUM; m++) {
		const NMMetaPropertyInfo *const*pis;
		const NMMetaSettingInfoEditor *info = &nm_meta_setting_infos_editor[m];

		pis = nm_property_infos_for_setting_type (m);
		g_assert (pis);

		for (p = 0; p < info->properties_num; p++)
			g_assert (pis[p] == &info->properties[p]);
		g_assert (!pis[p]);
	}

	for (m = 0; m < _NM_META_SETTING_TYPE_NUM; m++) {
		const NMMetaSettingInfoEditor *info = &nm_meta_setting_infos_editor[m];

		g_assert (nm_meta_setting_info_editor_find_by_name (info->general->setting_name) == info);
		g_assert (nm_meta_setting_info_editor_find_by_gtype (info->general->get_setting_gtype ()) == info);

		for (p = 0; p < info->properties_num; p++) {
			const NMMetaPropertyInfo *pi = &info->properties[p];

			g_assert (nm_meta_setting_info_editor_get_property_info (info, pi->property_name) == pi);
			g_assert (nm_meta_property_info_find_by_name (info->general->setting_name, pi->property_name) == pi);
		}
	}

	infos_p = nm_meta_setting_infos_editor_p ();
	g_assert (infos_p);
	for (m = 0; m < _NM_META_SETTING_TYPE_NUM; m++)
		g_assert (infos_p[m] == &nm_meta_setting_infos_editor[m]);
	g_assert (!infos_p[m]);
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_func ("/client/meta/check", test_client_meta_check);

	return g_test_run ();
}
