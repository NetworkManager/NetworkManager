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

#ifndef _NM_META_SETTING_ACCESS_H__
#define _NM_META_SETTING_ACCESS_H__

#include "nm-meta-setting.h"
#include "nm-meta-setting-desc.h"

/*****************************************************************************/

const NMMetaSettingInfoEditor *nm_meta_setting_info_editor_find_by_name (const char *setting_name);
const NMMetaSettingInfoEditor *nm_meta_setting_info_editor_find_by_gtype (GType gtype);

const NMMetaPropertyInfo *nm_meta_setting_info_editor_get_property_info (const NMMetaSettingInfoEditor *setting_info,
                                                                         const char *property_name);
const NMMetaPropertyInfo *nm_meta_property_info_find_by_name (const char *setting_name,
                                                              const char *property_name);
const NMMetaPropertyInfo *nm_meta_property_info_find_by_setting (NMSetting *setting,
                                                                 const char *property_name);

/*****************************************************************************/

#endif /* _NM_META_SETTING_ACCESS_H__ */
