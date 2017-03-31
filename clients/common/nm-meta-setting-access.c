/* NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * Copyright 2010 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-meta-setting-access.h"

/*****************************************************************************/

const NMMetaSettingInfoEditor *
nm_meta_setting_info_editor_find_by_name (const char *setting_name)
{
	const NMMetaSettingInfo *meta_setting_info;
	const NMMetaSettingInfoEditor *setting_info;

	g_return_val_if_fail (setting_name, NULL);

	meta_setting_info = nm_meta_setting_infos_by_name (setting_name);

	if (!meta_setting_info)
		return NULL;

	g_return_val_if_fail (nm_streq0 (meta_setting_info->setting_name, setting_name), NULL);

	if (meta_setting_info->meta_type >= G_N_ELEMENTS (nm_meta_setting_infos_editor))
		return NULL;

	setting_info = &nm_meta_setting_infos_editor[meta_setting_info->meta_type];

	g_return_val_if_fail (setting_info->general == meta_setting_info, NULL);

	return setting_info;
}

const NMMetaSettingInfoEditor *
nm_meta_setting_info_editor_find_by_gtype (GType gtype)
{
	const NMMetaSettingInfo *meta_setting_info;
	const NMMetaSettingInfoEditor *setting_info;

	meta_setting_info = nm_meta_setting_infos_by_gtype (gtype);

	if (!meta_setting_info)
		return NULL;

	g_return_val_if_fail (meta_setting_info->get_setting_gtype, NULL);
	g_return_val_if_fail (meta_setting_info->get_setting_gtype () == gtype, NULL);

	if (meta_setting_info->meta_type >= G_N_ELEMENTS (nm_meta_setting_infos_editor))
		return NULL;

	setting_info = &nm_meta_setting_infos_editor[meta_setting_info->meta_type];

	g_return_val_if_fail (setting_info->general == meta_setting_info, NULL);

	return setting_info;
}

static const NMMetaSettingInfoEditor *
nm_meta_setting_info_editor_find_by_setting (NMSetting *setting)
{
	const NMMetaSettingInfoEditor *setting_info;

	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);

	setting_info = nm_meta_setting_info_editor_find_by_gtype (G_OBJECT_TYPE (setting));

	if (!setting_info)
		return NULL;

	g_return_val_if_fail (setting_info == nm_meta_setting_info_editor_find_by_name (nm_setting_get_name (setting)), NULL);

	return setting_info;
}

const NMMetaPropertyInfo *
nm_meta_setting_info_editor_get_property_info (const NMMetaSettingInfoEditor *setting_info, const char *property_name)
{
	guint i;

	g_return_val_if_fail (setting_info, NULL);
	g_return_val_if_fail (property_name, NULL);

	for (i = 0; i < setting_info->properties_num; i++) {
		if (nm_streq (setting_info->properties[i].property_name, property_name))
			return &setting_info->properties[i];
	}

	return NULL;
}

const NMMetaPropertyInfo *
nm_meta_property_info_find_by_name (const char *setting_name, const char *property_name, const NMMetaSettingInfoEditor **out_setting_info)
{
	const NMMetaSettingInfoEditor *setting_info;

	setting_info = nm_meta_setting_info_editor_find_by_name (setting_name);

	NM_SET_OUT (out_setting_info, setting_info);
	if (!setting_info)
		return NULL;
	return nm_meta_setting_info_editor_get_property_info (setting_info, property_name);
}

const NMMetaPropertyInfo *
nm_meta_property_info_find_by_setting (NMSetting *setting, const char *property_name, const NMMetaSettingInfoEditor **out_setting_info)
{
	const NMMetaSettingInfoEditor *setting_info;
	const NMMetaPropertyInfo *property_info;

	setting_info = nm_meta_setting_info_editor_find_by_setting (setting);

	NM_SET_OUT (out_setting_info, setting_info);
	if (!setting_info)
		return NULL;
	property_info = nm_meta_setting_info_editor_get_property_info (setting_info, property_name);

	nm_assert (property_info == nm_meta_property_info_find_by_name (nm_setting_get_name (setting), property_name, NULL));

	return property_info;
}
