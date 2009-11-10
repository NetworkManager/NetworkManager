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

/**
 * SECTION:nm-setting
 * @short_description: Describes related configuration information
 * @include: nm-setting.h
 *
 * Each #NMSetting contains properties that describe configuration that applies
 * to a specific network layer (like IPv4 or IPv6 configuration) or device type
 * (like Ethernet, or WiFi).  A collection of individual settings together
 * make up an #NMConnection. Each property is strongly typed and usually has
 * a number of allowed values.  See each #NMSetting subclass for a description
 * of properties and allowed values.
 */

/**
 * nm_setting_error_quark:
 *
 * Registers an error quark for #NMSetting if necessary.
 *
 * Returns: the error quark used for NMSetting errors.
 **/
GQuark
nm_setting_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			ENUM_ENTRY (NM_SETTING_ERROR_UNKNOWN, "UnknownError"),
			ENUM_ENTRY (NM_SETTING_ERROR_PROPERTY_NOT_FOUND, "PropertyNotFound"),
			ENUM_ENTRY (NM_SETTING_ERROR_PROPERTY_NOT_SECRET, "PropertyNotSecret"),
			ENUM_ENTRY (NM_SETTING_ERROR_PROPERTY_TYPE_MISMATCH, "PropertyTypeMismatch"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingError", values);
	}
	return etype;
}

G_DEFINE_ABSTRACT_TYPE (NMSetting, nm_setting, G_TYPE_OBJECT)

#define NM_SETTING_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING, NMSettingPrivate))

typedef struct {
	char *name;
} NMSettingPrivate;

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

/**
 * nm_setting_to_hash:
 * @setting: the #NMSetting
 *
 * Converts the #NMSetting into a #GHashTable mapping each setting property
 * name to a GValue describing that property, suitable for marshalling over
 * D-Bus or serializing.  The mapping is string:GValue.
 * 
 * Returns: a new #GHashTable describing the setting's properties
 **/
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
		nm_warning ("Ignoring invalid property '%s'", prop_name);
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

/**
 * nm_setting_new_from_hash:
 * @setting_type: the #NMSetting type which the hash contains properties for
 * @hash: the #GHashTable containing a string:GValue mapping of properties
 * that apply to the setting
 *
 * Creates a new #NMSetting object and populates that object with the properties
 * contained in the hash table, using each hash key as the property to set,
 * and each hash value as the value to set that property to.  Setting properties
 * are strongly typed, thus the GValue type of the hash value must be correct.
 * See the documentation on each #NMSetting object subclass for the correct
 * property names and value types.
 * 
 * Returns: a new #NMSetting object populated with the properties from the
 * hash table, or NULL on failure
 **/
NMSetting *
nm_setting_new_from_hash (GType setting_type,
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
                   GParamFlags flags,
                   gpointer user_data)
{
	if (flags & G_PARAM_WRITABLE)
		g_object_set_property (G_OBJECT (user_data), name, value);
}

/**
 * nm_setting_duplicate:
 * @setting: the #NMSetting to duplicate
 *
 * Duplicates a #NMSetting.
 *
 * Returns: a new #NMSetting containing the same properties and values as the
 * source #NMSetting
 **/
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

/**
 * nm_setting_get_name:
 * @setting: the #NMSetting
 *
 * Returns the type name of the #NMSetting object
 *
 * Returns: a string containing the type name of the #NMSetting object,
 * like 'ppp' or 'wireless' or 'wired'.
 **/
const char *
nm_setting_get_name (NMSetting *setting)
{
	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);

	return NM_SETTING_GET_PRIVATE (setting)->name;
}

/**
 * nm_setting_verify:
 * @setting: the #NMSetting to verify
 * @all_settings: a #GSList of all settings in the connection from which @setting
 * came
 * @error: location to store error, or %NULL
 *
 * Validates the setting.  Each setting's properties have allowed values, and
 * some are dependent on other values (hence the need for @all_settings).  The
 * returned #GError contains information about which property of the setting
 * failed validation, and in what way that property failed validation.
 *
 * Returns: %TRUE if the setting is valid, %FALSE if it is not
 **/
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

/**
 * nm_setting_compare:
 * @a: a #NMSetting
 * @b: a second #NMSetting to compare with the first
 * @flags: compare flags, e.g. %NM_SETTING_COMPARE_FLAG_EXACT
 *
 * Compares two #NMSetting objects for similarity, with comparison behavior
 * modified by a set of flags.  See the documentation for #NMSettingCompareFlags
 * for a description of each flag's behavior.
 *
 * Returns: %TRUE if the comparison succeeds, %FALSE if it does not
 **/
gboolean
nm_setting_compare (NMSetting *a,
                    NMSetting *b,
                    NMSettingCompareFlags flags)
{
	GParamSpec **property_specs;
	guint n_property_specs;
	gint different;
	guint i;

	g_return_val_if_fail (NM_IS_SETTING (a), FALSE);
	g_return_val_if_fail (NM_IS_SETTING (b), FALSE);

	/* First check that both have the same type */
	if (G_OBJECT_TYPE (a) != G_OBJECT_TYPE (b))
		return FALSE;

	/* And now all properties */
	property_specs = g_object_class_list_properties (G_OBJECT_GET_CLASS (a), &n_property_specs);
	different = FALSE;

	for (i = 0; i < n_property_specs && !different; i++) {
		GParamSpec *prop_spec = property_specs[i];
		GValue value1 = { 0 };
		GValue value2 = { 0 };

		/* Fuzzy compare ignores secrets and properties defined with the
		 * FUZZY_IGNORE flag
		 */
		if (   (flags & NM_SETTING_COMPARE_FLAG_FUZZY)
		    && (prop_spec->flags & (NM_SETTING_PARAM_FUZZY_IGNORE | NM_SETTING_PARAM_SECRET)))
			continue;

		if ((flags & NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS) && (prop_spec->flags & NM_SETTING_PARAM_SECRET))
			continue;

		if (   (flags & NM_SETTING_COMPARE_FLAG_IGNORE_ID)
			   && !strcmp (nm_setting_get_name (a), NM_SETTING_CONNECTION_SETTING_NAME)
		    && !strcmp (prop_spec->name, NM_SETTING_CONNECTION_ID))
			continue;

		g_value_init (&value1, prop_spec->value_type);
		g_object_get_property (G_OBJECT (a), prop_spec->name, &value1);

		g_value_init (&value2, prop_spec->value_type);
		g_object_get_property (G_OBJECT (b), prop_spec->name, &value2);

		different = g_param_values_cmp (prop_spec, &value1, &value2);

		g_value_unset (&value1);
		g_value_unset (&value2);
	}

	g_free (property_specs);

	return different == 0 ? TRUE : FALSE;
}

/**
 * nm_setting_enumerate_values:
 * @setting: the #NMSetting
 * @func: user-supplied function called for each property of the setting
 * @user_data: user data passed to @func at each invocation
 *
 * Iterates over each property of the #NMSetting object, calling the supplied
 * user function for each property.
 **/
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
		func (setting, prop_spec->name, &value, prop_spec->flags, user_data);
		g_value_unset (&value);
	}

	g_free (property_specs);
}

/**
 * nm_setting_clear_secrets:
 * @setting: the #NMSetting
 *
 * Resets and clears any secrets in the setting.  Secrets should be added to the
 * setting only when needed, and cleared immediately after use to prevent
 * leakage of information.
 **/
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

/**
 * nm_setting_need_secrets:
 * @setting: the #NMSetting
 *
 * Returns an array of property names for each secret which may be required
 * to make a successful connection.  The returned hints are only intended as a
 * guide to what secrets may be required, because in some circumstances, there
 * is no way to conclusively determine exactly which secrets are needed.
 *
 * Returns: a #GPtrArray containing the property names of secrets of the
 * #NMSetting which may be required; the caller owns the array
 * and must free the each array element with g_free(), as well as the array
 * itself with g_ptr_array_free()
 **/
GPtrArray *
nm_setting_need_secrets (NMSetting *setting)
{
	GPtrArray *secrets = NULL;

	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);

	if (NM_SETTING_GET_CLASS (setting)->need_secrets)
		secrets = NM_SETTING_GET_CLASS (setting)->need_secrets (setting);

	return secrets;
}

typedef struct {
	NMSetting *setting;
	GError **error;
} UpdateSecretsInfo;

static gboolean
update_one_secret (NMSetting *setting, const char *key, GValue *value, GError **error)
{
	GParamSpec *prop_spec;
	GValue transformed_value = { 0 };
	gboolean success = FALSE;

	prop_spec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), key);
	if (!prop_spec) {
		g_set_error (error,
		             NM_SETTING_ERROR,
		             NM_SETTING_ERROR_PROPERTY_NOT_FOUND,
		             "%s", key);
		return FALSE;
	}

	if (!(prop_spec->flags & NM_SETTING_PARAM_SECRET)) {
		g_set_error (error,
		             NM_SETTING_ERROR,
		             NM_SETTING_ERROR_PROPERTY_NOT_SECRET,
		             "%s", key);
		return FALSE;
	}

	if (g_value_type_compatible (G_VALUE_TYPE (value), G_PARAM_SPEC_VALUE_TYPE (prop_spec))) {
		g_object_set_property (G_OBJECT (setting), prop_spec->name, value);
		success = TRUE;
	} else if (g_value_transform (value, &transformed_value)) {
		g_object_set_property (G_OBJECT (setting), prop_spec->name, &transformed_value);
		g_value_unset (&transformed_value);
		success = TRUE;
	} else {
		g_set_error (error,
		             NM_SETTING_ERROR,
		             NM_SETTING_ERROR_PROPERTY_TYPE_MISMATCH,
		             "%s", key);
	}
	return success;
}

static void
update_one_cb (gpointer key, gpointer val, gpointer user_data)
{
	UpdateSecretsInfo *info = user_data;
	const char *secret_key = (const char *) key;
	GValue *secret_value = (GValue *) val;

	if (*(info->error) == NULL)
		NM_SETTING_GET_CLASS (info->setting)->update_one_secret (info->setting, secret_key, secret_value, info->error);
}

/**
 * nm_setting_update_secrets:
 * @setting: the #NMSetting
 * @secrets: a #GHashTable mapping string:#GValue of setting property names and
 * secrets
 * @error: location to store error, or %NULL
 *
 * Update the setting's secrets, given a hash table of secrets intended for that
 * setting (deserialized from D-Bus for example).
 * 
 * Returns: %TRUE if the secrets were successfully updated and the connection
 * is valid, %FALSE on failure or if the setting was never added to the connection
 **/
gboolean
nm_setting_update_secrets (NMSetting *setting, GHashTable *secrets, GError **error)
{
	UpdateSecretsInfo *info;
	gboolean success;

	g_return_val_if_fail (setting != NULL, FALSE);
	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (secrets != NULL, FALSE);
	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	info = g_malloc0 (sizeof (UpdateSecretsInfo));
	info->setting = setting;
	info->error = error;
	g_hash_table_foreach (secrets, update_one_cb, info);
	success = *(info->error) ? FALSE : TRUE;
	g_free (info);

	return success;
}

/**
 * nm_setting_to_string:
 * @setting: the #NMSetting
 *
 * Convert the setting into a string.  For debugging purposes ONLY, should NOT
 * be used for serialization of the setting, or machine-parsed in any way. The
 * output format is not guaranteed to be stable and may change at any time.
 *
 * Returns: an allocated string containing a textual representation of the
 * setting's properties and values (including secrets!), which the caller should
 * free with g_free()
 **/
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

	string = g_string_new (nm_setting_get_name (setting));
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
	NMSettingPrivate *priv;

	object = G_OBJECT_CLASS (nm_setting_parent_class)->constructor (type,
													    n_construct_params,
													    construct_params);
	if (!object)
		return NULL;

	priv = NM_SETTING_GET_PRIVATE (object);
	if (!priv->name) {
		nm_warning ("Setting name is not set.");
		g_object_unref (object);
		object = NULL;
	}

	return object;
}

static void
finalize (GObject *object)
{
	NMSettingPrivate *priv = NM_SETTING_GET_PRIVATE (object);

	g_free (priv->name);

	G_OBJECT_CLASS (nm_setting_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingPrivate *priv = NM_SETTING_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_NAME:
		g_free (priv->name);
		priv->name = g_value_dup_string (value);
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
		g_value_set_string (value, nm_setting_get_name (setting));
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

	g_type_class_add_private (setting_class, sizeof (NMSettingPrivate));

	/* virtual methods */
	object_class->constructor  = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	setting_class->update_one_secret = update_one_secret;

	/* Properties */

	/**
	 * NMSetting:name:
	 *
	 * The setting's name, which uniquely identifies the setting within the
	 * connection.  Each setting type has a name unique to that type, for
	 * example 'ppp' or 'wireless' or 'wired'.
	 **/
	g_object_class_install_property
		(object_class, PROP_NAME,
		 g_param_spec_string (NM_SETTING_NAME,
						  "Name",
						  "The setting's name; these names are defined by the "
						  "specification and cannot be changed after the object "
						  "has been created.  Each setting class has a name, and "
						  "all objects of that class share the same name.",
						  NULL,
						  G_PARAM_READWRITE));
}

