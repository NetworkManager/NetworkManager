/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2007 - 2008 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <string.h>

#include "nm-setting.h"
#include "nm-setting-connection.h"
#include "nm-utils.h"

G_DEFINE_ABSTRACT_TYPE (NMSetting, nm_setting, G_TYPE_OBJECT)

enum {
	PROP_0,
	PROP_NAME,

	PROP_LAST
};

static void
destroy_gvalue (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

GHashTable *
nm_setting_to_hash (NMSetting *setting)
{
	GHashTable *hash;
	GParamSpec **property_specs;
	guint n_property_specs;
	guint i;

	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);

	property_specs = g_object_class_list_properties (G_OBJECT_GET_CLASS (setting), &n_property_specs);
	if (!property_specs) {
		g_warning ("%s: couldn't find property specs for object of type '%s'",
		           __func__, g_type_name (G_OBJECT_TYPE (setting)));
		return NULL;
	}

	hash = g_hash_table_new_full (g_str_hash, g_str_equal,
							(GDestroyNotify) g_free,
							destroy_gvalue);

	for (i = 0; i < n_property_specs; i++) {
		GParamSpec *prop_spec = property_specs[i];

		if (prop_spec->flags & NM_SETTING_PARAM_SERIALIZE) {
			GValue *value;

			value = g_slice_new0 (GValue);
			g_value_init (value, prop_spec->value_type);
			g_object_get_property (G_OBJECT (setting), prop_spec->name, value);

			/* Don't serialize values with default values */
			if (!g_param_value_defaults (prop_spec, value))
				g_hash_table_insert (hash, g_strdup (prop_spec->name), value);
			else
				destroy_gvalue (value);
		}
	}

	g_free (property_specs);

	return hash;
}

typedef struct {
	GObjectClass *class;
	guint n_params;
	GParameter *params;
} NMSettingFromHashInfo;

static void
one_property_cb (gpointer key, gpointer val, gpointer user_data)
{
	const char *prop_name = (char *) key;
	GValue *src_value = (GValue *) val;
	NMSettingFromHashInfo *info = (NMSettingFromHashInfo *) user_data;
	GValue *dst_value = &info->params[info->n_params].value;
	GParamSpec *param_spec;

	param_spec = g_object_class_find_property (info->class, prop_name);
	if (!param_spec || !(param_spec->flags & NM_SETTING_PARAM_SERIALIZE)) {
		/* Oh, we're so nice and only warn, maybe it should be a fatal error? */
		nm_warning ("Ignorning invalid property '%s'", prop_name);
		return;
	}

	g_value_init (dst_value, G_VALUE_TYPE (src_value));
	if (g_value_transform (src_value, dst_value)) {
		info->params[info->n_params].name = prop_name;
		info->n_params++;
	} else {
		nm_warning ("Ignoring property '%s' with invalid type (%s)",
				  prop_name, G_VALUE_TYPE_NAME (src_value));
		g_value_unset (dst_value);
	}
}

NMSetting *
nm_setting_from_hash (GType setting_type,
				  GHashTable *hash)
{
	NMSetting *setting;
	NMSettingFromHashInfo info;
	int i;

	g_return_val_if_fail (G_TYPE_IS_INSTANTIATABLE (setting_type), NULL);
	g_return_val_if_fail (hash != NULL, NULL);

	info.class = g_type_class_ref (setting_type);
	info.n_params = 0;
	info.params = g_new0 (GParameter, g_hash_table_size (hash));

	g_hash_table_foreach (hash, one_property_cb, &info);

	setting = (NMSetting *) g_object_newv (setting_type, info.n_params, info.params);

	for (i = 0; i < info.n_params; i++) {
		GValue *v = &info.params[i].value;
		g_value_unset (v);
	}

	g_free (info.params);
	g_type_class_unref (info.class);

	return setting;
}

static void
duplicate_setting (NMSetting *setting,
			    const char *name,
			    const GValue *value,
			    gboolean secret,
			    gpointer user_data)
{
	GObject *dup = (GObject *) user_data;

	g_object_set_property (dup, name, value);
}

NMSetting *
nm_setting_duplicate (NMSetting *setting)
{
	GObject *dup;

	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);

	dup = g_object_new (G_OBJECT_TYPE (setting), NULL);

	g_object_freeze_notify (dup);
	nm_setting_enumerate_values (setting, duplicate_setting, dup);
	g_object_thaw_notify (dup);

	return NM_SETTING (dup);
}

const char *
nm_setting_get_name (NMSetting *setting)
{
	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);

	return setting->name;
}

gboolean
nm_setting_verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	if (NM_SETTING_GET_CLASS (setting)->verify)
		return NM_SETTING_GET_CLASS (setting)->verify (setting, all_settings, error);

	return TRUE;
}

gboolean
nm_setting_compare (NMSetting *setting,
                    NMSetting *other,
                    NMSettingCompareFlags flags)
{
	GParamSpec **property_specs;
	guint n_property_specs;
	gint different;
	guint i;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (NM_IS_SETTING (other), FALSE);

	/* First check that both have the same type */
	if (G_OBJECT_TYPE (setting) != G_OBJECT_TYPE (other))
		return FALSE;

	/* And now all properties */
	property_specs = g_object_class_list_properties (G_OBJECT_GET_CLASS (setting), &n_property_specs);
	different = FALSE;

	for (i = 0; i < n_property_specs && !different; i++) {
		GParamSpec *prop_spec = property_specs[i];
		GValue value1 = { 0 };
		GValue value2 = { 0 };

		/* Fuzzy compare ignores secrets and properties defined with the
		 * FUZZY_IGNORE flag
		 */
		if (   (flags & COMPARE_FLAGS_FUZZY)
		    && (prop_spec->flags & (NM_SETTING_PARAM_FUZZY_IGNORE | NM_SETTING_PARAM_SECRET)))
			continue;

		if (   (flags & COMPARE_FLAGS_IGNORE_ID)
		    && !strcmp (setting->name, NM_SETTING_CONNECTION_SETTING_NAME)
		    && !strcmp (prop_spec->name, NM_SETTING_CONNECTION_ID))
			continue;

		g_value_init (&value1, prop_spec->value_type);
		g_object_get_property (G_OBJECT (setting), prop_spec->name, &value1);

		g_value_init (&value2, prop_spec->value_type);
		g_object_get_property (G_OBJECT (other), prop_spec->name, &value2);

		different = g_param_values_cmp (prop_spec, &value1, &value2);

		g_value_unset (&value1);
		g_value_unset (&value2);
	}

	g_free (property_specs);

	return different == 0 ? TRUE : FALSE;
}

void
nm_setting_enumerate_values (NMSetting *setting,
					    NMSettingValueIterFn func,
					    gpointer user_data)
{
	GParamSpec **property_specs;
	guint n_property_specs;
	int i;

	g_return_if_fail (NM_IS_SETTING (setting));
	g_return_if_fail (func != NULL);

	property_specs = g_object_class_list_properties (G_OBJECT_GET_CLASS (setting), &n_property_specs);
	for (i = 0; i < n_property_specs; i++) {
		GParamSpec *prop_spec = property_specs[i];
		GValue value = { 0 };

		g_value_init (&value, G_PARAM_SPEC_VALUE_TYPE (prop_spec));
		g_object_get_property (G_OBJECT (setting), prop_spec->name, &value);
		func (setting, prop_spec->name, &value,
			 prop_spec->flags & NM_SETTING_PARAM_SECRET,
			 user_data);
		g_value_unset (&value);
	}

	g_free (property_specs);
}

void
nm_setting_clear_secrets (NMSetting *setting)
{
	GParamSpec **property_specs;
	guint n_property_specs;
	guint i;

	g_return_if_fail (NM_IS_SETTING (setting));

	property_specs = g_object_class_list_properties (G_OBJECT_GET_CLASS (setting), &n_property_specs);

	for (i = 0; i < n_property_specs; i++) {
		GParamSpec *prop_spec = property_specs[i];
		GValue value = { 0 };

		if (prop_spec->flags & NM_SETTING_PARAM_SECRET) {
			g_value_init (&value, prop_spec->value_type);
			g_param_value_set_default (prop_spec, &value);
			g_object_set_property (G_OBJECT (setting), prop_spec->name, &value);
			g_value_unset (&value);
		}
	}

	g_free (property_specs);
}

GPtrArray *
nm_setting_need_secrets (NMSetting *setting)
{
	GPtrArray *secrets = NULL;

	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);

	if (NM_SETTING_GET_CLASS (setting)->need_secrets)
		secrets = NM_SETTING_GET_CLASS (setting)->need_secrets (setting);

	return secrets;
}

static void
update_one_secret (NMSetting *setting, const char *key, GValue *value)
{
	GParamSpec *prop_spec;
	GValue transformed_value = { 0 };

	prop_spec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), key);
	if (!prop_spec) {
		nm_warning ("Ignoring invalid secret '%s'.", key);
		return;
	}

	if (!(prop_spec->flags & NM_SETTING_PARAM_SECRET)) {
		nm_warning ("Ignoring secret '%s' as it's not marked as a secret.", key);
		return;
	}

	if (g_value_type_compatible (G_VALUE_TYPE (value), G_PARAM_SPEC_VALUE_TYPE (prop_spec)))
		g_object_set_property (G_OBJECT (setting), prop_spec->name, value);
	else if (g_value_transform (value, &transformed_value)) {
		g_object_set_property (G_OBJECT (setting), prop_spec->name, &transformed_value);
		g_value_unset (&transformed_value);
	} else {
		nm_warning ("Ignoring secret property '%s' with invalid type (%s)",
		            key, G_VALUE_TYPE_NAME (value));
	}
}

static void
update_one_cb (gpointer key, gpointer val, gpointer user_data)
{
	NMSetting *setting = (NMSetting *) user_data;
	const char *secret_key = (const char *) key;
	GValue *secret_value = (GValue *) val;

	NM_SETTING_GET_CLASS (setting)->update_one_secret (setting, secret_key, secret_value);
}

void
nm_setting_update_secrets (NMSetting *setting, GHashTable *secrets)
{
	g_return_if_fail (NM_IS_SETTING (setting));
	g_return_if_fail (secrets != NULL);

	g_hash_table_foreach (secrets, update_one_cb, setting);
}

char *
nm_setting_to_string (NMSetting *setting)
{
	GString *string;
	GParamSpec **property_specs;
	guint n_property_specs;
	guint i;

	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);

	property_specs = g_object_class_list_properties (G_OBJECT_GET_CLASS (setting), &n_property_specs);
	if (!property_specs)
		return NULL;

	string = g_string_new (setting->name);
	g_string_append_c (string, '\n');

	for (i = 0; i < n_property_specs; i++) {
		GParamSpec *prop_spec = property_specs[i];
		GValue value = { 0 };
		char *value_str;
		gboolean is_serializable;
		gboolean is_default;

		g_value_init (&value, prop_spec->value_type);
		g_object_get_property (G_OBJECT (setting), prop_spec->name, &value);

		value_str = g_strdup_value_contents (&value);
		g_string_append_printf (string, "\t%s : %s", prop_spec->name, value_str);
		g_free (value_str);

		is_serializable = prop_spec->flags & NM_SETTING_PARAM_SERIALIZE;
		is_default = g_param_value_defaults (prop_spec, &value);

		if (is_serializable || is_default) {
			g_string_append (string, " (");

			if (is_serializable)
				g_string_append_c (string, 's');
			if (is_default)
				g_string_append_c (string, 'd');

			g_string_append_c (string, ')');
		}

		g_string_append_c (string, '\n');
	}

	g_free (property_specs);
	g_string_append_c (string, '\n');

	return g_string_free (string, FALSE);
}

/*****************************************************************************/

static void
nm_setting_init (NMSetting *setting)
{
}

static GObject*
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	GObject *object;
	NMSetting *setting;

	object = G_OBJECT_CLASS (nm_setting_parent_class)->constructor (type,
													    n_construct_params,
													    construct_params);
	if (!object)
		return NULL;

	setting = NM_SETTING (object);
	if (!setting->name) {
		nm_warning ("Setting name is not set.");
		g_object_unref (object);
		object = NULL;
	}

	return object;
}

static void
finalize (GObject *object)
{
	NMSetting *self = NM_SETTING (object);

	g_free (self->name);

	G_OBJECT_CLASS (nm_setting_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSetting *setting = NM_SETTING (object);

	switch (prop_id) {
	case PROP_NAME:
		g_free (setting->name);
		setting->name = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMSetting *setting = NM_SETTING (object);

	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, setting->name);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_class_init (NMSettingClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);

	/* virtual methods */
	object_class->constructor  = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	setting_class->update_one_secret = update_one_secret;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_NAME,
		 g_param_spec_string (NM_SETTING_NAME,
						  "Name",
						  "Setting's name",
						  NULL,
						  G_PARAM_READWRITE));
}
