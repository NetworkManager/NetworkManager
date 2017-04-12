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
nm_meta_setting_info_editor_find_by_name (const char *setting_name, gboolean use_alias)
{
	const NMMetaSettingInfo *meta_setting_info;
	const NMMetaSettingInfoEditor *setting_info;
	guint i;

	g_return_val_if_fail (setting_name, NULL);

	meta_setting_info = nm_meta_setting_infos_by_name (setting_name);
	setting_info = NULL;
	if (meta_setting_info) {
		nm_assert (nm_streq0 (meta_setting_info->setting_name, setting_name));
		if (meta_setting_info->meta_type < G_N_ELEMENTS (nm_meta_setting_infos_editor)) {
			setting_info = &nm_meta_setting_infos_editor[meta_setting_info->meta_type];
			nm_assert (setting_info->general == meta_setting_info);
		}
	}
	if (!setting_info && use_alias) {
		for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++) {
			if (nm_streq0 (nm_meta_setting_infos_editor[i].alias, setting_name)) {
				setting_info = &nm_meta_setting_infos_editor[i];
				break;
			}
		}
	}

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

const NMMetaSettingInfoEditor *
nm_meta_setting_info_editor_find_by_setting (NMSetting *setting)
{
	const NMMetaSettingInfoEditor *setting_info;

	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);

	setting_info = nm_meta_setting_info_editor_find_by_gtype (G_OBJECT_TYPE (setting));

	nm_assert (setting_info == nm_meta_setting_info_editor_find_by_name (nm_setting_get_name (setting), FALSE));
	nm_assert (!setting_info || G_TYPE_CHECK_INSTANCE_TYPE (setting, setting_info->general->get_setting_gtype ()));

	return setting_info;
}

const NMMetaPropertyInfo *
nm_meta_setting_info_editor_get_property_info (const NMMetaSettingInfoEditor *setting_info, const char *property_name)
{
	guint i;

	g_return_val_if_fail (setting_info, NULL);
	g_return_val_if_fail (property_name, NULL);

	for (i = 0; i < setting_info->properties_num; i++) {
		nm_assert (setting_info->properties[i].property_name);
		nm_assert (setting_info->properties[i].setting_info == setting_info);
		if (nm_streq (setting_info->properties[i].property_name, property_name))
			return &setting_info->properties[i];
	}

	return NULL;
}

const NMMetaPropertyInfo *
nm_meta_property_info_find_by_name (const char *setting_name, const char *property_name)
{
	const NMMetaSettingInfoEditor *setting_info;
	const NMMetaPropertyInfo *property_info;

	setting_info = nm_meta_setting_info_editor_find_by_name (setting_name, FALSE);
	if (!setting_info)
		return NULL;

	property_info = nm_meta_setting_info_editor_get_property_info (setting_info, property_name);
	if (!property_info)
		return NULL;

	nm_assert (property_info->setting_info == setting_info);

	return property_info;
}

const NMMetaPropertyInfo *
nm_meta_property_info_find_by_setting (NMSetting *setting, const char *property_name)
{
	const NMMetaSettingInfoEditor *setting_info;
	const NMMetaPropertyInfo *property_info;

	setting_info = nm_meta_setting_info_editor_find_by_setting (setting);
	if (!setting_info)
		return NULL;
	property_info = nm_meta_setting_info_editor_get_property_info (setting_info, property_name);
	if (!property_info)
		return NULL;

	nm_assert (property_info->setting_info == setting_info);
	nm_assert (property_info == nm_meta_property_info_find_by_name (nm_setting_get_name (setting), property_name));

	return property_info;
}

NMSetting *
nm_meta_setting_info_editor_new_setting (const NMMetaSettingInfoEditor *setting_info,
                                         NMMetaAccessorSettingInitType init_type)
{
	NMSetting *setting;

	g_return_val_if_fail (setting_info, NULL);

	setting = g_object_new (setting_info->general->get_setting_gtype (), NULL);

	if (   setting_info->setting_init_fcn
	    && init_type != NM_META_ACCESSOR_SETTING_INIT_TYPE_DEFAULT) {
		setting_info->setting_init_fcn (setting_info,
		                                setting,
		                                init_type);
	}

	return setting;
}

/*****************************************************************************/

/* this basically returns NMMetaSettingType.properties, but with type
 * (NMMetaPropertyInfo **) instead of (NMMetaPropertyInfo *), which is
 * required by some APIs. */
const NMMetaPropertyInfo *const*
nm_property_infos_for_setting_type (NMMetaSettingType setting_type)
{
	static const NMMetaPropertyInfo **cache[_NM_META_SETTING_TYPE_NUM] = { NULL };
	const NMMetaPropertyInfo **p;
	guint i;

	nm_assert (setting_type < _NM_META_SETTING_TYPE_NUM);
	nm_assert (setting_type == 0 || setting_type > 0);

	if (G_UNLIKELY (!(p = cache[setting_type]))) {
		const NMMetaSettingInfoEditor *setting_info = &nm_meta_setting_infos_editor[setting_type];

		p = g_new (const NMMetaPropertyInfo *, setting_info->properties_num + 1);
		for (i = 0; i < setting_info->properties_num; i++)
			p[i] = &setting_info->properties[i];
		p[i] = NULL;
		cache[setting_type] = p;
	}
	return (const NMMetaPropertyInfo *const*) p;
}

const NMMetaSettingInfoEditor *const*
nm_meta_setting_infos_editor_p (void)
{
	static const NMMetaSettingInfoEditor *cache[_NM_META_SETTING_TYPE_NUM + 1] = { NULL };
	guint i;

	if (G_UNLIKELY (!cache[0])) {
		for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++)
			cache[i] = &nm_meta_setting_infos_editor[i];
	}
	return cache;
}

/*****************************************************************************/

const char *
nm_meta_abstract_info_get_name (const NMMetaAbstractInfo *abstract_info, gboolean for_header)
{
	const char *n;

	nm_assert (abstract_info);
	nm_assert (abstract_info->meta_type);
	nm_assert (abstract_info->meta_type->get_name);
	n = abstract_info->meta_type->get_name (abstract_info, for_header);
	nm_assert (n && n[0]);
	return n;
}

const NMMetaAbstractInfo *const*
nm_meta_abstract_info_get_nested (const NMMetaAbstractInfo *abstract_info,
                                  guint *out_len,
                                  gpointer *nested_to_free)
{
	const NMMetaAbstractInfo *const*nested;
	guint l = 0;
	gs_free gpointer f = NULL;

	nm_assert (abstract_info);
	nm_assert (abstract_info->meta_type);
	nm_assert (nested_to_free && !*nested_to_free);

	if (abstract_info->meta_type->get_nested) {
		nested = abstract_info->meta_type->get_nested (abstract_info, &l, &f);
		nm_assert ((nested ? g_strv_length ((char **) nested) : 0) == l);
		if (nested && nested[0]) {
			NM_SET_OUT (out_len, l);
			*nested_to_free = g_steal_pointer (&f);
			return nested;
		}
	}
	NM_SET_OUT (out_len, 0);
	return NULL;
}

gconstpointer
nm_meta_abstract_info_get (const NMMetaAbstractInfo *abstract_info,
                           const NMMetaEnvironment *environment,
                           gpointer environment_user_data,
                           gpointer target,
                           NMMetaAccessorGetType get_type,
                           NMMetaAccessorGetFlags get_flags,
                           NMMetaAccessorGetOutFlags *out_flags,
                           gpointer *out_to_free)
{
	nm_assert (abstract_info);
	nm_assert (abstract_info->meta_type);
	nm_assert (!out_to_free || !*out_to_free);
	nm_assert (out_flags);

	*out_flags = NM_META_ACCESSOR_GET_OUT_FLAGS_NONE;

	if (!abstract_info->meta_type->get_fcn)
		g_return_val_if_reached (NULL);

	return abstract_info->meta_type->get_fcn (abstract_info,
	                                          environment,
	                                          environment_user_data,
	                                          target,
	                                          get_type,
	                                          get_flags,
	                                          out_flags,
	                                          out_to_free);
}

const char *const*
nm_meta_abstract_info_complete (const NMMetaAbstractInfo *abstract_info,
                                const NMMetaEnvironment *environment,
                                gpointer environment_user_data,
                                const NMMetaOperationContext *operation_context,
                                const char *text,
                                char ***out_to_free)
{
	const char *const*values;
	gsize i, j, text_len;

	nm_assert (abstract_info);
	nm_assert (abstract_info->meta_type);
	nm_assert (out_to_free && !*out_to_free);

	*out_to_free = NULL;

	if (!abstract_info->meta_type->complete_fcn)
		return NULL;

	values = abstract_info->meta_type->complete_fcn (abstract_info,
	                                                 environment,
	                                                 environment_user_data,
	                                                 operation_context,
	                                                 text,
	                                                 out_to_free);

	nm_assert (!*out_to_free || values == (const char *const*) *out_to_free);

	if (!text || !text[0] || !values || !values[0])
		return values;

	/* for convenience, we all the complete_fcn() implementations to
	 * ignore "text". We filter out invalid matches here. */

	text_len = strlen (text);

	if (*out_to_free) {
		char **v = *out_to_free;

		for (i =0, j = 0; v[i]; i++) {
			if (strncmp (v[i], text, text_len) != 0)
				continue;
			v[j++] = v[i];
		}
		v[j++] = NULL;
		return (const char *const*) *out_to_free;
	} else {
		const char *const*v = values;
		char **r;

		for (i = 0, j = 0; v[i]; i++) {
			if (strncmp (v[i], text, text_len) != 0)
				continue;
			j++;
		}
		if (j == i)
			return values;

		r = g_new (char *, j + 1);
		v = values;
		for (i = 0, j = 0; v[i]; i++) {
			if (strncmp (v[i], text, text_len) != 0)
				continue;
			r[j++] = g_strdup (v[i]);
		}
		r[j++] = NULL;
		return (const char *const*) (*out_to_free = r);
	}
}
