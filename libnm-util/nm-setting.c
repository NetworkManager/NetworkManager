/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include "nm-setting.h"
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
	if (!property_specs)
		return NULL;

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

	g_return_val_if_fail (G_TYPE_IS_INSTANTIATABLE (setting_type), NULL);
	g_return_val_if_fail (hash != NULL, NULL);

	info.class = g_type_class_ref (setting_type);
	info.n_params = 0;
	info.params = g_new0 (GParameter, g_hash_table_size (hash));

	g_hash_table_foreach (hash, one_property_cb, &info);

	setting = (NMSetting *) g_object_newv (setting_type, info.n_params, info.params);

	g_free (info.params);
	g_type_class_unref (info.class);

	return setting;
}

const char *
nm_setting_get_name (NMSetting *setting)
{
	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);

	return setting->name;
}

gboolean
nm_setting_verify (NMSetting *setting, GSList *all_settings)
{
	gboolean success = TRUE;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);

	if (NM_SETTING_GET_CLASS (setting)->verify)
		success = NM_SETTING_GET_CLASS (setting)->verify (setting, all_settings);

	return success;
}

gboolean
nm_setting_compare (NMSetting *setting, NMSetting *other)
{
	GParamSpec **property_specs;
	guint n_property_specs;
	gboolean different;
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

		g_value_init (&value1, prop_spec->value_type);
		g_object_get_property (G_OBJECT (setting), prop_spec->name, &value1);

		g_value_init (&value2, prop_spec->value_type);
		g_object_get_property (G_OBJECT (setting), prop_spec->name, &value2);

		different = g_param_values_cmp (prop_spec, &value1, &value2) != 0;

		g_value_unset (&value1);
		g_value_unset (&value2);
	}

	g_free (property_specs);

	return different;
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
update_one_secret (gpointer key, gpointer val, gpointer user_data)
{
	char *secret_key = (char *) key;
	GValue *secret_value = (GValue *) val;
	NMSetting *setting = (NMSetting *) user_data;
	GParamSpec *prop_spec;
	GValue transformed_value = { 0 };

	prop_spec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), secret_key);
	if (!prop_spec) {
		nm_warning ("Ignoring invalid secret '%s'.", secret_key);
		return;
	}

	if (!(prop_spec->flags & NM_SETTING_PARAM_SECRET)) {
		nm_warning ("Ignoring secret '%s' as it's not marked as a secret.", secret_key);
		return;
	}

	if (g_value_type_compatible (G_VALUE_TYPE (secret_value), G_PARAM_SPEC_VALUE_TYPE (prop_spec)))
		g_object_set_property (G_OBJECT (setting), prop_spec->name, secret_value);
	else if (g_value_transform (secret_value, &transformed_value)) {
		g_object_set_property (G_OBJECT (setting), prop_spec->name, &transformed_value);
		g_value_unset (&transformed_value);
	} else
		nm_warning ("Ignoring secret property '%s' with invalid type (%s)",
				  secret_key, G_VALUE_TYPE_NAME (secret_value));
}

void
nm_setting_update_secrets (NMSetting *setting, GHashTable *secrets)
{
	g_return_if_fail (NM_IS_SETTING (setting));
	g_return_if_fail (secrets != NULL);

	g_hash_table_foreach (secrets, update_one_secret, setting);
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

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_NAME,
		 g_param_spec_string (NM_SETTING_NAME,
						  "Name",
						  "Setting's name",
						  NULL,
						  G_PARAM_READWRITE));
}
