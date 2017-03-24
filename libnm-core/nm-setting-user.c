/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
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
 * Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-user.h"

#include "nm-setting.h"
#include "nm-setting-private.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-user
 * @short_description: Describes user properties
 *
 * The #NMSettingUser object is a #NMSetting subclass that allow to attach
 * arbitrary user data to #NMConnection objects.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMSettingUser,
	PROP_DATA,
);

typedef struct {
	GHashTable *data;
	const char **keys;
} NMSettingUserPrivate;

/**
 * NMSettingUser:
 *
 * General User Profile Settings
 */
struct _NMSettingUser {
	NMSetting parent;
	NMSettingUserPrivate _priv;
};

struct _NMSettingUserClass {
	NMSettingClass parent;
};

G_DEFINE_TYPE_WITH_CODE (NMSettingUser, nm_setting_user, NM_TYPE_SETTING,
                         _nm_register_setting (USER, 10))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_USER)

#define NM_SETTING_USER_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMSettingUser, NM_IS_SETTING_USER)

/*****************************************************************************/

static gboolean
_key_char_is_regular (char ch)
{
	/* allow words of printable characters, plus some
	 * special characters, for example to support base64 encoding. */
	return    (ch >= 'a' && ch <= 'z')
	       || (ch >= 'A' && ch <= 'Z')
	       || (ch >= '0' && ch <= '9')
	       || NM_IN_SET (ch, '-', '_', '+', '/', '=');
}

/**
 * nm_setting_user_check_key:
 * @key: the key to check
 * @error: a #GError, %NULL to ignore.
 *
 * Checks whether @key is a valid user data key. This means,
 * key is not %NULL, not too large and valid ASCII. Also,
 * only digits and numbers are allowed with a few special
 * characters. The key must contain at least one '.' and
 * look like a fully qualified DNS name.
 *
 * Since: 1.8
 *
 * Returns: %TRUE if @key is a valid user data key.
 */
gboolean
nm_setting_user_check_key (const char *key, GError **error)
{
	gsize len;
	gboolean has_dot;
	char ch;

	g_return_val_if_fail (!error || !*error, FALSE);

	if (!key || !key[0]) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("missing key"));
		return FALSE;
	}
	len = strlen (key);
	if (len > 255) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("key is too long"));
		return FALSE;
	}
	if (!g_utf8_validate (key, len, NULL)) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("key must be UTF8"));
		return FALSE;
	}

	has_dot = FALSE;
	while (TRUE) {
		ch = (key++)[0];

		/* Allow something that looks like a FQN, separating namespaces by a single '.'
		 * We want to print the keys nicely in nmcli requiring escaping.
		 *
		 * If a user really has to encode special values in the name, he may base64 encode it. */

		if (!_key_char_is_regular (ch))
			break;

		while (_key_char_is_regular (key[0]))
			key++;

		ch = key[0];
		if (ch == '\0') {
			if (!has_dot) {
				g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("key requires a '.' for a namespace"));
				return FALSE;
			}
			return TRUE;
		}

		if (ch != '.')
			break;

		has_dot = TRUE;
		ch = (++key)[0];
		if (ch == '.') {
			g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("key cannot contain \"..\""));
			return FALSE;
		}
	}
	g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
	                     _("key contains invalid characters"));
	return FALSE;
}

/**
 * nm_setting_user_check_val:
 * @val: the value to check
 * @error: a #GError, %NULL to ignore.
 *
 * Checks whether @val is a valid user data value. This means,
 * value is not %NULL, not too large and valid UTF-8.
 *
 * Since: 1.8
 *
 * Returns: %TRUE if @val is a valid user data value.
 */
gboolean
nm_setting_user_check_val (const char *val, GError **error)
{
	gsize len;

	g_return_val_if_fail (!error || !*error, FALSE);

	if (!val) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("value is missing"));
		return FALSE;
	}

	len = strlen (val);
	if (len > 8*1024) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("value is too large"));
		return FALSE;
	}

	if (!g_utf8_validate (val, len, NULL)) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("value is not valid UTF8"));
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

static GHashTable *
_create_data_hash (void)
{
	return g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
}

/**
 * nm_setting_user_get_keys:
 * @setting: the #NMSettingUser
 * @out_len: (out): the length of the returned array
 *
 * Returns: (array length=out_len) (transfer none): a
 *   %NULL-terminated array containing each key from the table.
  **/
const char *const*
nm_setting_user_get_keys (NMSettingUser *setting, guint *out_len)
{
	NMSettingUser *self = setting;
	NMSettingUserPrivate *priv;
	guint len;

	g_return_val_if_fail (NM_IS_SETTING_USER (self), NULL);

	priv = NM_SETTING_USER_GET_PRIVATE (self);

	if (priv->keys) {
		NM_SET_OUT (out_len, g_hash_table_size (priv->data));
		return priv->keys;
	}

	if (!priv->data || !g_hash_table_size (priv->data)) {
		NM_SET_OUT (out_len, 0);
		return (const char **) &priv->keys;
	}

	priv->keys = (const char **) g_hash_table_get_keys_as_array (priv->data, &len);
	g_qsort_with_data (priv->keys,
	                   len,
	                   sizeof (const char *),
	                   nm_strcmp_p_with_data,
	                   NULL);
	NM_SET_OUT (out_len, len);
	return priv->keys;
}

/*****************************************************************************/

/**
 * nm_setting_user_get_data:
 * @setting: the #NMSettingUser instance
 * @key: the key to lookup
 *
 * Since: 1.8
 *
 * Returns: (transfer none): the value associated with @key or %NULL if no such
 *   value exists.
 */
const char *
nm_setting_user_get_data (NMSettingUser *setting, const char *key)
{
	NMSettingUser *self = setting;
	NMSettingUserPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_USER (self), NULL);
	g_return_val_if_fail (key, NULL);

	priv = NM_SETTING_USER_GET_PRIVATE (self);

	if (!priv->data)
		return NULL;

	return g_hash_table_lookup (priv->data, key);
}

/**
 * nm_setting_user_set_data:
 * @setting: the #NMSettingUser instance
 * @key: the key to set
 * @val: the value to set or %NULL to clear a key.
 *
 * Since: 1.8
 *
 * Returns: %TRUE if the operation was successful. The operation
 *   can fail if @key or @val are not valid strings according
 *   to nm_setting_user_check_key() and nm_setting_user_check_val().
 */
gboolean
nm_setting_user_set_data (NMSettingUser *setting,
                          const char *key,
                          const char *val,
                          GError **error)
{
	NMSettingUser *self = setting;
	NMSettingUserPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING (self), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	if (!nm_setting_user_check_key (key, error))
		return FALSE;

	priv = NM_SETTING_USER_GET_PRIVATE (self);

	if (!val) {
		if (   priv->data
		    && g_hash_table_remove (priv->data, key)) {
			nm_clear_g_free (&priv->keys);
			_notify (self, PROP_DATA);
		}
		return TRUE;
	}

	if (!nm_setting_user_check_val (val, error))
		return FALSE;

	if (!priv->data)
		priv->data = _create_data_hash ();
	else {
		const char *key2, *val2;

		if (g_hash_table_size (priv->data) > 256) {
			/* limit the number of valid keys */
			g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("maximum number of user data entires reached"));
			return FALSE;
		}

		if (g_hash_table_lookup_extended (priv->data, key, (gpointer *) &key2, (gpointer *) &val2)) {
			if (nm_streq (val, val2))
				return TRUE;
		} else
			nm_clear_g_free (&priv->keys);
	}

	g_hash_table_insert (priv->data, g_strdup (key), g_strdup (val));
	_notify (self, PROP_DATA);
	return TRUE;
}

/*****************************************************************************/

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
	                     _("setting user-data is not yet implemented"));
	return FALSE;
}


static gboolean
compare_property (NMSetting *setting,
                  NMSetting *other,
                  const GParamSpec *prop_spec,
                  NMSettingCompareFlags flags)
{
	NMSettingUserPrivate *priv, *pri2;
	guint n;
	GHashTableIter iter;
	const char *key, *value, *valu2;

	g_return_val_if_fail (NM_IS_SETTING_USER (setting), FALSE);
	g_return_val_if_fail (NM_IS_SETTING_USER (other), FALSE);

	if (!nm_streq0 (prop_spec->name, NM_SETTING_USER_DATA))
		goto call_parent;

	priv = NM_SETTING_USER_GET_PRIVATE (NM_SETTING_USER (setting));
	pri2 = NM_SETTING_USER_GET_PRIVATE (NM_SETTING_USER (other));

	n = priv->data ? g_hash_table_size (priv->data) : 0;
	if (n != (pri2->data ? g_hash_table_size (pri2->data) : 0))
		return FALSE;
	if (n > 0) {
		g_hash_table_iter_init (&iter, priv->data);
		while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value)) {
			if (!g_hash_table_lookup_extended (pri2->data, key, NULL, (gpointer *) &valu2))
				return FALSE;
			if (!nm_streq (value, valu2))
				return FALSE;
		}
	}
	return TRUE;

call_parent:
	return NM_SETTING_CLASS (nm_setting_user_parent_class)->compare_property (setting, other, prop_spec, flags);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingUser *self = NM_SETTING_USER (object);
	NMSettingUserPrivate *priv = NM_SETTING_USER_GET_PRIVATE (self);
	GHashTableIter iter;
	GHashTable *data;
	const char *key, *val;

	switch (prop_id) {
	case PROP_DATA:
		data = _create_data_hash ();
		if (priv->data) {
			g_hash_table_iter_init (&iter, priv->data);
			while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &val))
				g_hash_table_insert (data, g_strdup (key), g_strdup (val));
		}
		g_value_take_boxed (value, data);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingUser *self = NM_SETTING_USER (object);
	NMSettingUserPrivate *priv = NM_SETTING_USER_GET_PRIVATE (self);
	GHashTableIter iter;
	GHashTable *data;
	const char *key, *val;

	switch (prop_id) {
	case PROP_DATA:
		data = g_value_get_boxed (value);
		if (!data || !g_hash_table_size (data)) {
			g_clear_pointer (&priv->data, g_hash_table_unref);
			nm_clear_g_free (&priv->keys);
			return;
		}
		g_hash_table_iter_init (&iter, priv->data);
		while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &val)) {
			if (!nm_setting_user_check_key (key, NULL))
				g_return_if_reached ();
			if (!nm_setting_user_check_val (val, NULL))
				g_return_if_reached ();
		}
		nm_clear_g_free (&priv->keys);
		if (priv->data)
			g_hash_table_remove_all (priv->data);
		else
			priv->data = _create_data_hash ();
		g_hash_table_iter_init (&iter, priv->data);
		while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &val))
			g_hash_table_insert (priv->data, (gpointer) key, (gpointer) val);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_user_init (NMSettingUser *self)
{
}

/**
 * nm_setting_user_new:
 *
 * Creates a new #NMSettingUser object with default values.
 *
 * Returns: the new empty #NMSettingUser object
 **/
NMSetting *nm_setting_user_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_USER, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingUser *self = NM_SETTING_USER (object);
	NMSettingUserPrivate *priv = NM_SETTING_USER_GET_PRIVATE (self);

	g_free (priv->keys);
	if (priv->data)
		g_hash_table_unref (priv->data);

	G_OBJECT_CLASS (nm_setting_user_parent_class)->finalize (object);
}

static void
nm_setting_user_class_init (NMSettingUserClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);

	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	setting_class->compare_property = compare_property;
	setting_class->verify = verify;

	/**
	 * NMSettingUser:data:
	 *
	 * A dictionary of key/value pairs with user data. This data is ignored by NetworkManager
	 * and can be used at the users discretion. The keys only support a strict ascii format,
	 * but the values can be arbitrary UTF8 strings up to a certain length.
	 *
	 * Type: GHashTable(utf8,utf8)
	 *
	 * Since: 1.8
	 **/
	obj_properties[PROP_DATA] =
	    g_param_spec_boxed (NM_SETTING_USER_DATA, "", "",
	                        G_TYPE_HASH_TABLE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_transform_property (setting_class, NM_SETTING_USER_DATA,
	                                      G_VARIANT_TYPE ("a{ss}"),
	                                      _nm_utils_strdict_to_dbus,
	                                      _nm_utils_strdict_from_dbus);
}
