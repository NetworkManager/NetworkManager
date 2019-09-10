// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager
 *
 * Copyright 2010 - 2017 Red Hat, Inc.
 */

#ifndef _NM_META_SETTING_ACCESS_H__
#define _NM_META_SETTING_ACCESS_H__

#include "nm-meta-setting.h"
#include "nm-meta-setting-desc.h"

/*****************************************************************************/

NMSetting *nm_meta_setting_info_editor_new_setting (const NMMetaSettingInfoEditor *setting_info,
                                                    NMMetaAccessorSettingInitType init_type);

const NMMetaSettingInfoEditor *nm_meta_setting_info_editor_find_by_name (const char *setting_name, gboolean use_alias);
const NMMetaSettingInfoEditor *nm_meta_setting_info_editor_find_by_gtype (GType gtype);
const NMMetaSettingInfoEditor *nm_meta_setting_info_editor_find_by_setting (NMSetting *setting);

const NMMetaPropertyInfo *nm_meta_setting_info_editor_get_property_info (const NMMetaSettingInfoEditor *setting_info,
                                                                         const char *property_name);
const NMMetaPropertyInfo *nm_meta_property_info_find_by_name (const char *setting_name,
                                                              const char *property_name);
const NMMetaPropertyInfo *nm_meta_property_info_find_by_setting (NMSetting *setting,
                                                                 const char *property_name);

gboolean nm_meta_setting_info_editor_has_secrets (const NMMetaSettingInfoEditor *setting_info);

/*****************************************************************************/

const NMMetaSettingInfoEditor *const*nm_meta_setting_infos_editor_p (void);

/*****************************************************************************/

const char *nm_meta_abstract_info_get_name (const NMMetaAbstractInfo *abstract_info, gboolean for_header);

const NMMetaAbstractInfo *const*nm_meta_abstract_info_get_nested (const NMMetaAbstractInfo *abstract_info,
                                                                  guint *out_len,
                                                                  gpointer *nested_to_free);

gconstpointer nm_meta_abstract_info_get (const NMMetaAbstractInfo *abstract_info,
                                         const NMMetaEnvironment *environment,
                                         gpointer environment_user_data,
                                         gpointer target,
                                         gpointer target_data,
                                         NMMetaAccessorGetType get_type,
                                         NMMetaAccessorGetFlags get_flags,
                                         NMMetaAccessorGetOutFlags *out_flags,
                                         gboolean *out_is_default,
                                         gpointer *out_to_free);

const char *const*nm_meta_abstract_info_complete (const NMMetaAbstractInfo *abstract_info,
                                                  const NMMetaEnvironment *environment,
                                                  gpointer environment_user_data,
                                                  const NMMetaOperationContext *operation_context,
                                                  const char *text,
                                                  gboolean *out_complete_filename,
                                                  char ***out_to_free);

/*****************************************************************************/

char *nm_meta_abstract_info_get_nested_names_str (const NMMetaAbstractInfo *abstract_info, const char *name_prefix);
char *nm_meta_abstract_infos_get_names_str (const NMMetaAbstractInfo *const*fields_array, const char *name_prefix);

/*****************************************************************************/

typedef struct {
	const NMMetaAbstractInfo *info;
	const char *self_selection;
	const char *sub_selection;
	guint idx;
} NMMetaSelectionItem;

typedef struct {
	const guint num;
	const NMMetaSelectionItem items[];
} NMMetaSelectionResultList;

NMMetaSelectionResultList *nm_meta_selection_create_all (const NMMetaAbstractInfo *const* fields_array);
NMMetaSelectionResultList *nm_meta_selection_create_parse_one (const NMMetaAbstractInfo *const* fields_array,
                                                               const char *fields_prefix,
                                                               const char *fields_str,
                                                               gboolean validate_nested,
                                                               GError **error);
NMMetaSelectionResultList *nm_meta_selection_create_parse_list (const NMMetaAbstractInfo *const* fields_array,
                                                                const char *fields_str,
                                                                gboolean validate_nested,
                                                                GError **error);

#endif /* _NM_META_SETTING_ACCESS_H__ */
