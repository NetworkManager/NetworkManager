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
		nm_assert (setting_info->properties[i]->property_name);
		nm_assert (setting_info->properties[i]->setting_info == setting_info);
		if (nm_streq (setting_info->properties[i]->property_name, property_name))
			return setting_info->properties[i];
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
                           gboolean *out_is_default,
                           gpointer *out_to_free)
{
	nm_assert (abstract_info);
	nm_assert (abstract_info->meta_type);
	nm_assert (!out_to_free || !*out_to_free);
	nm_assert (out_flags);

	*out_flags = NM_META_ACCESSOR_GET_OUT_FLAGS_NONE;
	NM_SET_OUT (out_is_default, FALSE);

	if (!abstract_info->meta_type->get_fcn)
		g_return_val_if_reached (NULL);

	return abstract_info->meta_type->get_fcn (abstract_info,
	                                          environment,
	                                          environment_user_data,
	                                          target,
	                                          get_type,
	                                          get_flags,
	                                          out_flags,
	                                          out_is_default,
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

	if (!values)
		return NULL;

	if (!values[0]) {
		nm_clear_g_free (out_to_free);
		return NULL;
	}

	if (!text || !text[0])
		return values;

	/* for convenience, we allow the complete_fcn() implementations to
	 * ignore "text". We filter out invalid matches here. */

	text_len = strlen (text);

	if (*out_to_free) {
		char **v = *out_to_free;

		for (i = 0, j = 0; v[i]; i++) {
			if (strncmp (v[i], text, text_len) != 0) {
				g_free (v[i]);
				continue;
			}
			v[j++] = v[i];
		}
		if (j)
			v[j++] = NULL;
		else {
			g_free (v);
			*out_to_free = v = NULL;
		}
		return (const char *const*) v;
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
		else if (!j)
			return NULL;

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

/*****************************************************************************/

char *
nm_meta_abstract_info_get_nested_names_str (const NMMetaAbstractInfo *abstract_info, const char *name_prefix)
{
	gs_free gpointer nested_to_free = NULL;
	guint i;
	const NMMetaAbstractInfo *const*nested;
	GString *allowed_fields;

	nested = nm_meta_abstract_info_get_nested (abstract_info, NULL, &nested_to_free);
	if (!nested)
		return NULL;

	allowed_fields = g_string_sized_new (256);

	if (!name_prefix)
		name_prefix = nm_meta_abstract_info_get_name (abstract_info, FALSE);

	for (i = 0; nested[i]; i++) {
		g_string_append_printf (allowed_fields, "%s.%s,",
		                        name_prefix, nm_meta_abstract_info_get_name (nested[i], FALSE));
	}
	g_string_truncate (allowed_fields, allowed_fields->len - 1);
	return g_string_free (allowed_fields, FALSE);
}

char *
nm_meta_abstract_infos_get_names_str (const NMMetaAbstractInfo *const*fields_array, const char *name_prefix)
{
	GString *allowed_fields;
	guint i;

	if (!fields_array || !fields_array[0])
		return NULL;

	allowed_fields = g_string_sized_new (256);
	for (i = 0; fields_array[i]; i++) {
		if (name_prefix)
			g_string_append_printf (allowed_fields, "%s.", name_prefix);
		g_string_append_printf (allowed_fields, "%s,", nm_meta_abstract_info_get_name (fields_array[i], FALSE));
	}
	g_string_truncate (allowed_fields, allowed_fields->len - 1);
	return g_string_free (allowed_fields, FALSE);
}

/*****************************************************************************/

typedef struct {
	guint idx;
	gsize self_offset_plus_1;
	gsize sub_offset_plus_1;
} OutputSelectionItem;

static NMMetaSelectionResultList *
_output_selection_pack (const NMMetaAbstractInfo *const* fields_array,
                        GArray *array,
                        GString *str)
{
	NMMetaSelectionResultList *result;
	guint i;
	guint len;

	len = array ? array->len : 0;

	/* re-organize the collected output data in one buffer that can be freed using
	 * g_free(). This makes allocation more complicated, but saves us from special
	 * handling for free. */
	result = g_malloc0 (sizeof (NMMetaSelectionResultList) + (len * sizeof (NMMetaSelectionItem)) + (str ? str->len : 0));
	*((guint *) &result->num) = len;
	if (len > 0) {
		char *pdata = &((char *) result)[sizeof (NMMetaSelectionResultList) + (len * sizeof (NMMetaSelectionItem))];

		if (str)
			memcpy (pdata, str->str, str->len);
		for (i = 0; i < len; i++) {
			const OutputSelectionItem *a = &g_array_index (array, OutputSelectionItem, i);
			NMMetaSelectionItem *p = (NMMetaSelectionItem *) &result->items[i];

			p->info = fields_array[a->idx];
			p->idx = a->idx;
			if (a->self_offset_plus_1 > 0)
				p->self_selection = &pdata[a->self_offset_plus_1 - 1];
			if (a->sub_offset_plus_1 > 0)
				p->sub_selection = &pdata[a->sub_offset_plus_1 - 1];
		}
	}

	return result;
}

static gboolean
_output_selection_select_one (const NMMetaAbstractInfo *const* fields_array,
                              const char *fields_prefix,
                              const char *fields_str,
                              gboolean validate_nested,
                              GArray **p_array,
                              GString **p_str,
                              GError **error)
{
	guint i, j;
	const char *i_name;
	const char *right;
	gboolean found = FALSE;
	const NMMetaAbstractInfo *fields_array_failure = NULL;
	gs_free char *fields_str_clone = NULL;

	nm_assert (fields_str);
	nm_assert (p_array);
	nm_assert (p_str);
	nm_assert (!error || !*error);

	right = strchr (fields_str, '.');
	if (right) {
		fields_str_clone = g_strdup (fields_str);
		fields_str_clone[right - fields_str] = '\0';
		i_name = fields_str_clone;
		right = &fields_str_clone[right - fields_str + 1];
	} else
		i_name = fields_str;

	if (!fields_array)
		goto not_found;

	for (i = 0; fields_array[i]; i++) {
		const NMMetaAbstractInfo *fi = fields_array[i];
		const NMMetaAbstractInfo *const*nested;
		gs_free gpointer nested_to_free = NULL;

		if (g_ascii_strcasecmp (i_name, nm_meta_abstract_info_get_name (fi, FALSE)) != 0)
			continue;

		if (!right || !validate_nested) {
			found = TRUE;
			break;
		}

		nested = nm_meta_abstract_info_get_nested (fi, NULL, &nested_to_free);
		if (nested) {
			for (j = 0; nested[j]; nested++) {
				if (g_ascii_strcasecmp (right, nm_meta_abstract_info_get_name (nested[j], FALSE)) == 0) {
					found = TRUE;
					break;
				}
			}
		}
		fields_array_failure = fields_array[i];
		break;
	}

	if (!found) {
not_found:
		if (   !right
		    && !fields_prefix
		    && (   !g_ascii_strcasecmp (i_name, "all")
		        || !g_ascii_strcasecmp (i_name, "common")))
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN, _("field '%s' has to be alone"), i_name);
		else {
			gs_free char *allowed_fields = NULL;

			if (fields_array_failure) {
				gs_free char *p = NULL;

				if (fields_prefix) {
					p = g_strdup_printf ("%s.%s", fields_prefix,
					                     nm_meta_abstract_info_get_name (fields_array_failure, FALSE));
				}
				allowed_fields = nm_meta_abstract_info_get_nested_names_str (fields_array_failure, p);
			} else
				allowed_fields = nm_meta_abstract_infos_get_names_str (fields_array, NULL);

			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN, _("invalid field '%s%s%s%s%s'; %s%s%s"),
			             fields_prefix ?: "", fields_prefix ? "." : "",
			             i_name, right ? "." : "", right ?: "",
			             NM_PRINT_FMT_QUOTED (allowed_fields, "allowed fields: ", allowed_fields, "", "no fields"));
		}
		return FALSE;
	}

	{
		GString *str;
		OutputSelectionItem s = {
			.idx = i,
		};

		if (!*p_str)
			*p_str = g_string_sized_new (64);
		str = *p_str;

		s.self_offset_plus_1 = str->len + 1;
		if (fields_prefix) {
			g_string_append (str, fields_prefix);
			g_string_append_c (str, '.');
		}
		g_string_append_len (str, i_name, strlen (i_name) + 1);

		if (right) {
			s.sub_offset_plus_1 = str->len + 1;
			g_string_append_len (str, right, strlen (right) + 1);
		}

		if (!*p_array)
			*p_array = g_array_new (FALSE, FALSE, sizeof (OutputSelectionItem));
		g_array_append_val (*p_array, s);
	}

	return TRUE;
}

NMMetaSelectionResultList *
nm_meta_selection_create_all (const NMMetaAbstractInfo *const* fields_array)
{
	gs_unref_array GArray *array = NULL;
	guint i;

	if (fields_array) {
		array = g_array_new (FALSE, FALSE, sizeof (OutputSelectionItem));
		for (i = 0; fields_array[i]; i++) {
			OutputSelectionItem s = {
				.idx = i,
			};

			g_array_append_val (array, s);
		}
	}

	return _output_selection_pack (fields_array, array, NULL);
}

NMMetaSelectionResultList *
nm_meta_selection_create_parse_one (const NMMetaAbstractInfo *const* fields_array,
                                    const char *fields_prefix,
                                    const char *fields_str, /* one field selector (contains no commas) and is already stripped of spaces. */
                                    gboolean validate_nested,
                                    GError **error)
{
	gs_unref_array GArray *array = NULL;
	nm_auto_free_gstring GString *str = NULL;

	g_return_val_if_fail (!error || !*error, NULL);
	nm_assert (fields_str && !strchr (fields_str, ','));

	if (!_output_selection_select_one (fields_array,
	                                   fields_prefix,
	                                   fields_str,
	                                   validate_nested,
	                                   &array,
	                                   &str,
	                                   error))
		return NULL;
	return _output_selection_pack (fields_array, array, str);

}

NMMetaSelectionResultList *
nm_meta_selection_create_parse_list (const NMMetaAbstractInfo *const* fields_array,
                                     const char *fields_prefix,
                                     const char *fields_str, /* a comma separated list of selectors */
                                     gboolean validate_nested,
                                     GError **error)
{
	gs_unref_array GArray *array = NULL;
	nm_auto_free_gstring GString *str = NULL;
	gs_free char *fields_str_clone = NULL;
	char *fields_str_cur;
	char *fields_str_next;

	g_return_val_if_fail (!error || !*error, NULL);

	if (!fields_str)
		return nm_meta_selection_create_all (fields_array);

	fields_str_clone = g_strdup (fields_str);
	for (fields_str_cur = fields_str_clone; fields_str_cur; fields_str_cur = fields_str_next) {
		fields_str_cur = nm_str_skip_leading_spaces (fields_str_cur);
		fields_str_next = strchr (fields_str_cur, ',');
		if (fields_str_next)
			*fields_str_next++ = '\0';

		g_strchomp (fields_str_cur);
		if (!fields_str_cur[0])
			continue;
		if (!_output_selection_select_one (fields_array,
		                                   fields_prefix,
		                                   fields_str_cur,
		                                   validate_nested,
		                                   &array,
		                                   &str,
		                                   error))
			return NULL;
	}

	return _output_selection_pack (fields_array, array, str);
}
