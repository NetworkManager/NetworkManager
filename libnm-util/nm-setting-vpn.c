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
 * Copyright 2007 - 2013 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <dbus/dbus-glib.h>

#include "nm-setting-vpn.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-vpn
 * @short_description: Describes connection properties for Virtual Private Networks
 * @include: nm-setting-vpn.h
 *
 * The #NMSettingVPN object is a #NMSetting subclass that describes properties
 * necessary for connection to Virtual Private Networks.  NetworkManager uses
 * a plugin architecture to allow easier use of new VPN types, and this
 * setting abstracts the configuration for those plugins.  Since the configuration
 * options are only known to the VPN plugins themselves, the VPN configuration
 * options are stored as key/value pairs of strings rather than GObject
 * properties.
 **/

/**
 * nm_setting_vpn_error_quark:
 *
 * Registers an error quark for #NMSettingVPN if necessary.
 *
 * Returns: the error quark used for #NMSettingVPN errors.
 **/
GQuark
nm_setting_vpn_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-vpn-error-quark");
	return quark;
}

G_DEFINE_TYPE_WITH_CODE (NMSettingVPN, nm_setting_vpn, NM_TYPE_SETTING,
                         _nm_register_setting (NM_SETTING_VPN_SETTING_NAME,
                                               g_define_type_id,
                                               1,
                                               NM_SETTING_VPN_ERROR))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_VPN)

#define NM_SETTING_VPN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_VPN, NMSettingVPNPrivate))

typedef struct {
	char *service_type;

	/* username of the user requesting this connection, thus
	 * it's really only valid for user connections, and it also
	 * should never be saved out to persistent config.
	 */
	char *user_name;

	/* Whether the VPN stays up across link changes, until the user
	 * explicitly disconnects it.
	 */
	gboolean persistent;

	/* The hash table is created at setting object
	 * init time and should not be replaced.  It is
	 * a char * -> char * mapping, and both the key
	 * and value are owned by the hash table, and should
	 * be allocated with functions whose value can be
	 * freed with g_free().  Should not contain secrets.
	 */
	GHashTable *data;

	/* The hash table is created at setting object
	 * init time and should not be replaced.  It is
	 * a char * -> char * mapping, and both the key
	 * and value are owned by the hash table, and should
	 * be allocated with functions whose value can be
	 * freed with g_free().  Should contain secrets only.
	 */
	GHashTable *secrets;
} NMSettingVPNPrivate;

enum {
	PROP_0,
	PROP_SERVICE_TYPE,
	PROP_USER_NAME,
	PROP_PERSISTENT,
	PROP_DATA,
	PROP_SECRETS,

	LAST_PROP
};

/**
 * nm_setting_vpn_new:
 *
 * Creates a new #NMSettingVPN object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingVPN object
 **/
NMSetting *
nm_setting_vpn_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_VPN, NULL);
}

/**
 * nm_setting_vpn_get_service_type:
 * @setting: the #NMSettingVPN
 *
 * Returns the service name of the VPN, which identifies the specific VPN
 * plugin that should be used to connect to this VPN.
 *
 * Returns: the VPN plugin's service name
 **/
const char *
nm_setting_vpn_get_service_type (NMSettingVPN *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), NULL);

	return NM_SETTING_VPN_GET_PRIVATE (setting)->service_type;
}

/**
 * nm_setting_vpn_get_user_name:
 * @setting: the #NMSettingVPN
 *
 * Returns: the #NMSettingVPN:user-name property of the setting
 **/
const char *
nm_setting_vpn_get_user_name (NMSettingVPN *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), NULL);

	return NM_SETTING_VPN_GET_PRIVATE (setting)->user_name;
}

/**
 * nm_setting_vpn_get_persistent:
 * @setting: the #NMSettingVPN
 *
 * Returns: the #NMSettingVPN:persistent property of the setting
 **/
gboolean
nm_setting_vpn_get_persistent (NMSettingVPN *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), FALSE);

	return NM_SETTING_VPN_GET_PRIVATE (setting)->persistent;
}

/**
 * nm_setting_vpn_get_num_data_items:
 * @setting: the #NMSettingVPN
 *
 * Gets number of key/value pairs of VPN configuration data.
 *
 * Returns: the number of VPN plugin specific configuration data items
 **/
guint32
nm_setting_vpn_get_num_data_items (NMSettingVPN *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), 0);

	return g_hash_table_size (NM_SETTING_VPN_GET_PRIVATE (setting)->data);
}

/**
 * nm_setting_vpn_add_data_item:
 * @setting: the #NMSettingVPN
 * @key: a name that uniquely identifies the given value @item
 * @item: the value to be referenced by @key
 *
 * Establishes a relationship between @key and @item internally in the
 * setting which may be retrieved later.  Should not be used to store passwords
 * or other secrets, which is what nm_setting_vpn_add_secret() is for.
 **/
void
nm_setting_vpn_add_data_item (NMSettingVPN *setting,
                              const char *key,
                              const char *item)
{
	g_return_if_fail (NM_IS_SETTING_VPN (setting));
	g_return_if_fail (key != NULL);
	g_return_if_fail (strlen (key) > 0);
	g_return_if_fail (item != NULL);
	g_return_if_fail (strlen (item) > 0);

	g_hash_table_insert (NM_SETTING_VPN_GET_PRIVATE (setting)->data,
	                     g_strdup (key), g_strdup (item));
	g_object_notify (G_OBJECT (setting), NM_SETTING_VPN_DATA);
}

/**
 * nm_setting_vpn_get_data_item:
 * @setting: the #NMSettingVPN
 * @key: the name of the data item to retrieve
 *
 * Retrieves the data item of a key/value relationship previously established
 * by nm_setting_vpn_add_data_item().
 *
 * Returns: the data item, if any
 **/
const char *
nm_setting_vpn_get_data_item (NMSettingVPN *setting, const char *key)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), NULL);

	return (const char *) g_hash_table_lookup (NM_SETTING_VPN_GET_PRIVATE (setting)->data, key);
}

/**
 * nm_setting_vpn_remove_data_item:
 * @setting: the #NMSettingVPN
 * @key: the name of the data item to remove
 *
 * Deletes a key/value relationship previously established by
 * nm_setting_vpn_add_data_item().
 *
 * Returns: %TRUE if the data item was found and removed from the internal list,
 * %FALSE if it was not.
 **/
gboolean
nm_setting_vpn_remove_data_item (NMSettingVPN *setting, const char *key)
{
	gboolean found;

	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), FALSE);

	found = g_hash_table_remove (NM_SETTING_VPN_GET_PRIVATE (setting)->data, key);
	if (found)
		g_object_notify (G_OBJECT (setting), NM_SETTING_VPN_DATA);
	return found;
}

static void
foreach_item_helper (GHashTable *hash,
                     NMVPNIterFunc func,
                     gpointer user_data)
{
	GList *keys, *liter;
	GSList *copied = NULL, *siter;

	g_return_if_fail (hash != NULL);

	/* Grab keys and copy them so that the callback func can modify
	 * the hash table items if it wants to.
	 */
	keys = g_hash_table_get_keys (hash);
	for (liter = keys; liter; liter = g_list_next (liter))
		copied = g_slist_prepend (copied, g_strdup (liter->data));
	copied = g_slist_reverse (copied);
	g_list_free (keys);

	for (siter = copied; siter; siter = g_slist_next (siter)) {
		gpointer value;

		value = g_hash_table_lookup (hash, siter->data);
		func (siter->data, value, user_data);
	}

	g_slist_free_full (copied, g_free);
}

/**
 * nm_setting_vpn_foreach_data_item:
 * @setting: a #NMSettingVPN
 * @func: (scope call): an user provided function
 * @user_data: data to be passed to @func
 *
 * Iterates all data items stored in this setting.  It is safe to add, remove,
 * and modify data items inside @func, though any additions or removals made
 * during iteration will not be part of the iteration.
 */
void
nm_setting_vpn_foreach_data_item (NMSettingVPN *setting,
                                  NMVPNIterFunc func,
                                  gpointer user_data)
{
	g_return_if_fail (NM_IS_SETTING_VPN (setting));

	foreach_item_helper (NM_SETTING_VPN_GET_PRIVATE (setting)->data, func, user_data);
}

/**
 * nm_setting_vpn_get_num_secrets:
 * @setting: the #NMSettingVPN
 *
 * Gets number of VPN plugin specific secrets in the setting.
 *
 * Returns: the number of VPN plugin specific secrets
 **/
guint32
nm_setting_vpn_get_num_secrets (NMSettingVPN *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), 0);

	return g_hash_table_size (NM_SETTING_VPN_GET_PRIVATE (setting)->secrets);
}

/**
 * nm_setting_vpn_add_secret:
 * @setting: the #NMSettingVPN
 * @key: a name that uniquely identifies the given secret @secret
 * @secret: the secret to be referenced by @key
 *
 * Establishes a relationship between @key and @secret internally in the
 * setting which may be retrieved later.
 **/
void
nm_setting_vpn_add_secret (NMSettingVPN *setting,
                           const char *key,
                           const char *secret)
{
	g_return_if_fail (NM_IS_SETTING_VPN (setting));
	g_return_if_fail (key != NULL);
	g_return_if_fail (strlen (key) > 0);
	g_return_if_fail (secret != NULL);
	g_return_if_fail (strlen (secret) > 0);

	g_hash_table_insert (NM_SETTING_VPN_GET_PRIVATE (setting)->secrets,
	                     g_strdup (key), g_strdup (secret));
	g_object_notify (G_OBJECT (setting), NM_SETTING_VPN_SECRETS);
}

/**
 * nm_setting_vpn_get_secret:
 * @setting: the #NMSettingVPN
 * @key: the name of the secret to retrieve
 *
 * Retrieves the secret of a key/value relationship previously established
 * by nm_setting_vpn_add_secret().
 *
 * Returns: the secret, if any
 **/
const char *
nm_setting_vpn_get_secret (NMSettingVPN *setting, const char *key)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), NULL);

	return (const char *) g_hash_table_lookup (NM_SETTING_VPN_GET_PRIVATE (setting)->secrets, key);
}

/**
 * nm_setting_vpn_remove_secret:
 * @setting: the #NMSettingVPN
 * @key: the name of the secret to remove
 *
 * Deletes a key/value relationship previously established by
 * nm_setting_vpn_add_secret().
 *
 * Returns: %TRUE if the secret was found and removed from the internal list,
 * %FALSE if it was not.
 **/
gboolean
nm_setting_vpn_remove_secret (NMSettingVPN *setting, const char *key)
{
	gboolean found;

	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), FALSE);

	found = g_hash_table_remove (NM_SETTING_VPN_GET_PRIVATE (setting)->secrets, key);
	if (found)
		g_object_notify (G_OBJECT (setting), NM_SETTING_VPN_SECRETS);
	return found;
}

/**
 * nm_setting_vpn_foreach_secret:
 * @setting: a #NMSettingVPN
 * @func: (scope call): an user provided function
 * @user_data: data to be passed to @func
 *
 * Iterates all secrets stored in this setting.  It is safe to add, remove,
 * and modify secrets inside @func, though any additions or removals made during
 * iteration will not be part of the iteration.
 */
void
nm_setting_vpn_foreach_secret (NMSettingVPN *setting,
                               NMVPNIterFunc func,
                               gpointer user_data)
{
	g_return_if_fail (NM_IS_SETTING_VPN (setting));

	foreach_item_helper (NM_SETTING_VPN_GET_PRIVATE (setting)->secrets, func, user_data);
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingVPNPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);

	if (!priv->service_type) {
		g_set_error_literal (error,
		                     NM_SETTING_VPN_ERROR,
		                     NM_SETTING_VPN_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_VPN_SETTING_NAME, NM_SETTING_VPN_SERVICE_TYPE);
		return FALSE;
	}

	if (!strlen (priv->service_type)) {
		g_set_error_literal (error,
		                     NM_SETTING_VPN_ERROR,
		                     NM_SETTING_VPN_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_VPN_SETTING_NAME, NM_SETTING_VPN_SERVICE_TYPE);
		return FALSE;
	}

	/* default username can be NULL, but can't be zero-length */
	if (priv->user_name && !strlen (priv->user_name)) {
		g_set_error_literal (error,
		                     NM_SETTING_VPN_ERROR,
		                     NM_SETTING_VPN_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_VPN_SETTING_NAME, NM_SETTING_VPN_USER_NAME);
		return FALSE;
	}

	return TRUE;
}

static NMSettingUpdateSecretResult
update_secret_string (NMSetting *setting,
                      const char *key,
                      const char *value,
                      GError **error)
{
	NMSettingVPNPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);

	g_return_val_if_fail (key != NULL, NM_SETTING_UPDATE_SECRET_ERROR);
	g_return_val_if_fail (value != NULL, NM_SETTING_UPDATE_SECRET_ERROR);

	if (!value || !strlen (value)) {
		g_set_error (error, NM_SETTING_ERROR,
		             NM_SETTING_ERROR_PROPERTY_TYPE_MISMATCH,
		             "Secret %s was empty", key);
		return NM_SETTING_UPDATE_SECRET_ERROR;
	}

	if (g_strcmp0 (g_hash_table_lookup (priv->secrets, key), value) == 0)
		return NM_SETTING_UPDATE_SECRET_SUCCESS_UNCHANGED;

	g_hash_table_insert (priv->secrets, g_strdup (key), g_strdup (value));
	return NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED;
}

static NMSettingUpdateSecretResult
update_secret_hash (NMSetting *setting,
                    GHashTable *secrets,
                    GError **error)
{
	NMSettingVPNPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);
	GHashTableIter iter;
	const char *name, *value;
	NMSettingUpdateSecretResult result = NM_SETTING_UPDATE_SECRET_SUCCESS_UNCHANGED;

	g_return_val_if_fail (secrets != NULL, NM_SETTING_UPDATE_SECRET_ERROR);

	/* Make sure the items are valid */
	g_hash_table_iter_init (&iter, secrets);
	while (g_hash_table_iter_next (&iter, (gpointer *) &name, (gpointer *) &value)) {
		if (!name || !strlen (name)) {
			g_set_error_literal (error, NM_SETTING_ERROR,
			                     NM_SETTING_ERROR_PROPERTY_TYPE_MISMATCH,
			                     "Secret name was empty");
			return NM_SETTING_UPDATE_SECRET_ERROR;
		}

		if (!value || !strlen (value)) {
			g_set_error (error, NM_SETTING_ERROR,
			             NM_SETTING_ERROR_PROPERTY_TYPE_MISMATCH,
			             "Secret %s value was empty", name);
			return NM_SETTING_UPDATE_SECRET_ERROR;
		}
	}

	/* Now add the items to the settings' secrets list */
	g_hash_table_iter_init (&iter, secrets);
	while (g_hash_table_iter_next (&iter, (gpointer *) &name, (gpointer *) &value)) {
		if (value == NULL) {
			g_warn_if_fail (value != NULL);
			continue;
		}
		if (strlen (value) == 0) {
			g_warn_if_fail (strlen (value) > 0);
			continue;
		}

		if (g_strcmp0 (g_hash_table_lookup (priv->secrets, name), value) == 0)
			continue;

		g_hash_table_insert (priv->secrets, g_strdup (name), g_strdup (value));
		result = NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED;
	}

	return result;
}

static int
update_one_secret (NMSetting *setting, const char *key, GValue *value, GError **error)
{
	NMSettingUpdateSecretResult success = NM_SETTING_UPDATE_SECRET_ERROR;

	g_return_val_if_fail (key != NULL, NM_SETTING_UPDATE_SECRET_ERROR);
	g_return_val_if_fail (value != NULL, NM_SETTING_UPDATE_SECRET_ERROR);

	if (G_VALUE_HOLDS_STRING (value)) {
		/* Passing the string properties individually isn't correct, and won't
		 * produce the correct result, but for some reason that's how it used
		 * to be done.  So even though it's not correct, keep the code around
		 * for compatibility's sake.
		 */
		success = update_secret_string (setting, key, g_value_get_string (value), error);
	} else if (G_VALUE_HOLDS (value, DBUS_TYPE_G_MAP_OF_STRING)) {
		if (strcmp (key, NM_SETTING_VPN_SECRETS) != 0) {
			g_set_error (error, NM_SETTING_ERROR, NM_SETTING_ERROR_PROPERTY_NOT_SECRET,
			             "Property %s not a secret property", key);
		} else
			success = update_secret_hash (setting, g_value_get_boxed (value), error);
	} else
		g_set_error_literal (error, NM_SETTING_ERROR, NM_SETTING_ERROR_PROPERTY_TYPE_MISMATCH, key);

	if (success == NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED)
		g_object_notify (G_OBJECT (setting), NM_SETTING_VPN_SECRETS);

	return success;
}

static gboolean
get_secret_flags (NMSetting *setting,
                  const char *secret_name,
                  gboolean verify_secret,
                  NMSettingSecretFlags *out_flags,
                  GError **error)
{
	NMSettingVPNPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);
	gboolean success = FALSE;
	char *flags_key;
	gpointer val;
	unsigned long tmp;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	flags_key = g_strdup_printf ("%s-flags", secret_name);
	if (g_hash_table_lookup_extended (priv->data, flags_key, NULL, &val)) {
		errno = 0;
		tmp = strtoul ((const char *) val, NULL, 10);
		if ((errno == 0) && (tmp <= NM_SETTING_SECRET_FLAGS_ALL)) {
			flags = (NMSettingSecretFlags) tmp;
			success = TRUE;
		} else {
			g_set_error (error,
			             NM_SETTING_ERROR,
			             NM_SETTING_ERROR_PROPERTY_TYPE_MISMATCH,
			             _("Failed to convert '%s' value '%s' to uint"),
			             flags_key, (const char *) val);
		}
	} else {
		g_set_error (error,
		             NM_SETTING_ERROR,
		             NM_SETTING_ERROR_PROPERTY_NOT_FOUND,
		             _("Secret flags property '%s' not found"), flags_key);
	}
	g_free (flags_key);
	if (out_flags)
		*out_flags = flags;
	return success;
}

static gboolean
set_secret_flags (NMSetting *setting,
                  const char *secret_name,
                  gboolean verify_secret,
                  NMSettingSecretFlags flags,
                  GError **error)
{
	g_hash_table_insert (NM_SETTING_VPN_GET_PRIVATE (setting)->data,
	                     g_strdup_printf ("%s-flags", secret_name),
	                     g_strdup_printf ("%u", flags));
	g_object_notify (G_OBJECT (setting), NM_SETTING_VPN_SECRETS);
	return TRUE;
}

static GPtrArray *
need_secrets (NMSetting *setting)
{
	/* Assume that VPN connections need secrets since they almost always will */
	return g_ptr_array_sized_new (1);
}

static gboolean
_compare_secrets (NMSettingVPN *a,
                  NMSettingVPN *b,
                  NMSettingCompareFlags flags)
{
	GHashTable *a_secrets;
	GHashTableIter iter;
	const char *key, *val;

	a_secrets = NM_SETTING_VPN_GET_PRIVATE (a)->secrets;
	g_hash_table_iter_init (&iter, a_secrets);
	while (g_hash_table_iter_next (&iter, (gpointer) &key, (gpointer) &val)) {
		NMSettingSecretFlags a_secret_flags = NM_SETTING_SECRET_FLAG_NONE;
		NMSettingSecretFlags b_secret_flags = NM_SETTING_SECRET_FLAG_NONE;

		nm_setting_get_secret_flags (NM_SETTING (a), key, &a_secret_flags, NULL);
		nm_setting_get_secret_flags (NM_SETTING (b), key, &b_secret_flags, NULL);

		/* If the secret flags aren't the same, the settings aren't the same */
		if (a_secret_flags != b_secret_flags)
			return FALSE;

		if (   (flags & NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS)
		    && (a_secret_flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED))
			continue;

		if (   (flags & NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS)
		    && (a_secret_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
			continue;

		/* Now compare the values themselves */
		if (g_strcmp0 (val, nm_setting_vpn_get_secret (b, key)) != 0)
			return FALSE;
	}

	return TRUE;
}

static gboolean
compare_one_secret (NMSettingVPN *a,
                    NMSettingVPN *b,
                    NMSettingCompareFlags flags)
{
	if (!_compare_secrets (a, b, flags))
		return FALSE;
	if (!_compare_secrets (b, a, flags))
		return FALSE;

	return TRUE;
}

static gboolean
compare_property (NMSetting *setting,
                  NMSetting *other,
                  const GParamSpec *prop_spec,
                  NMSettingCompareFlags flags)
{
	gboolean same;

	/* We only need to treat the 'secrets' property specially */
	if (g_strcmp0 (prop_spec->name, NM_SETTING_VPN_SECRETS) != 0)
		return NM_SETTING_CLASS (nm_setting_vpn_parent_class)->compare_property (setting, other, prop_spec, flags);

	/* Compare A to B to ensure everything in A is found in B */
	same = compare_one_secret (NM_SETTING_VPN (setting), NM_SETTING_VPN (other), flags);
	if (same) {
		/* And then B to A to ensure everything in B is also found in A */
		same = compare_one_secret (NM_SETTING_VPN (other), NM_SETTING_VPN (setting), flags);
	}

	return same;
}

static gboolean
clear_secrets_with_flags (NMSetting *setting,
                          GParamSpec *pspec,
                          NMSettingClearSecretsWithFlagsFn func,
                          gpointer user_data)
{
	NMSettingVPNPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);
	GHashTableIter iter;
	const char *secret;
	gboolean changed = TRUE;

	if (priv->secrets == NULL)
		return FALSE;

	/* Iterate through secrets hash and check each entry */
	g_hash_table_iter_init (&iter, priv->secrets);
	while (g_hash_table_iter_next (&iter, (gpointer) &secret, NULL)) {
		NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

		nm_setting_get_secret_flags (setting, secret, &flags, NULL);
		if (func (setting, pspec->name, flags, user_data) == TRUE) {
			g_hash_table_iter_remove (&iter);
			changed = TRUE;
		}
	}

	if (changed)
		g_object_notify (G_OBJECT (setting), NM_SETTING_VPN_SECRETS);

	return changed;
}

static void
destroy_one_secret (gpointer data)
{
	char *secret = (char *) data;

	/* Don't leave the secret lying around in memory */
	memset (secret, 0, strlen (secret));
	g_free (secret);
}

static void
nm_setting_vpn_init (NMSettingVPN *setting)
{
	NMSettingVPNPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);

	priv->data = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	priv->secrets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, destroy_one_secret);
}

static void
finalize (GObject *object)
{
	NMSettingVPNPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (object);

	g_free (priv->service_type);
	g_free (priv->user_name);
	g_hash_table_destroy (priv->data);
	g_hash_table_destroy (priv->secrets);

	G_OBJECT_CLASS (nm_setting_vpn_parent_class)->finalize (object);
}

static void
copy_hash (gpointer key, gpointer value, gpointer user_data)
{
	g_return_if_fail (value != NULL);
	g_return_if_fail (strlen (value));
	g_hash_table_insert ((GHashTable *) user_data, g_strdup (key), g_strdup (value));
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingVPNPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (object);
	GHashTable *new_hash;

	switch (prop_id) {
	case PROP_SERVICE_TYPE:
		g_free (priv->service_type);
		priv->service_type = g_value_dup_string (value);
		break;
	case PROP_USER_NAME:
		g_free (priv->user_name);
		priv->user_name = g_value_dup_string (value);
		break;
	case PROP_PERSISTENT:
		priv->persistent = g_value_get_boolean (value);
		break;
	case PROP_DATA:
		/* Must make a deep copy of the hash table here... */
		g_hash_table_remove_all (priv->data);
		new_hash = g_value_get_boxed (value);
		if (new_hash)
			g_hash_table_foreach (new_hash, copy_hash, priv->data);
		break;
	case PROP_SECRETS:
		/* Must make a deep copy of the hash table here... */
		g_hash_table_remove_all (priv->secrets);
		new_hash = g_value_get_boxed (value);
		if (new_hash)
			g_hash_table_foreach (new_hash, copy_hash, priv->secrets);
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
	NMSettingVPN *setting = NM_SETTING_VPN (object);
	NMSettingVPNPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_SERVICE_TYPE:
		g_value_set_string (value, nm_setting_vpn_get_service_type (setting));
		break;
	case PROP_USER_NAME:
		g_value_set_string (value, nm_setting_vpn_get_user_name (setting));
		break;
	case PROP_PERSISTENT:
		g_value_set_boolean (value, priv->persistent);
		break;
	case PROP_DATA:
		g_value_set_boxed (value, priv->data);
		break;
	case PROP_SECRETS:
		g_value_set_boxed (value, priv->secrets);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_vpn_class_init (NMSettingVPNClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingVPNPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	parent_class->verify            = verify;
	parent_class->update_one_secret = update_one_secret;
	parent_class->get_secret_flags  = get_secret_flags;
	parent_class->set_secret_flags  = set_secret_flags;
	parent_class->need_secrets      = need_secrets;
	parent_class->compare_property  = compare_property;
	parent_class->clear_secrets_with_flags = clear_secrets_with_flags;

	/* Properties */
	/**
	 * NMSettingVPN:service-type:
	 *
	 * D-Bus service name of the VPN plugin that this setting uses to connect to
	 * its network.  i.e. org.freedesktop.NetworkManager.vpnc for the vpnc
	 * plugin.
	 **/
	g_object_class_install_property
		(object_class, PROP_SERVICE_TYPE,
		 g_param_spec_string (NM_SETTING_VPN_SERVICE_TYPE, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingVPN:user-name:
	 *
	 * If the VPN connection requires a user name for authentication, that name
	 * should be provided here.  If the connection is available to more than one
	 * user, and the VPN requires each user to supply a different name, then
	 * leave this property empty.  If this property is empty, NetworkManager
	 * will automatically supply the username of the user which requested the
	 * VPN connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_USER_NAME,
		 g_param_spec_string (NM_SETTING_VPN_USER_NAME, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingVPN:persistent:
	 *
	 * If the VPN service supports persistence, and this property is %TRUE,
	 * the VPN will attempt to stay connected across link changes and outages,
	 * until explicitly disconnected.
	 **/
	g_object_class_install_property
		(object_class, PROP_PERSISTENT,
		 g_param_spec_boolean (NM_SETTING_VPN_PERSISTENT, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingVPN:data:
	 *
	 * Dictionary of key/value pairs of VPN plugin specific data.  Both keys and
	 * values must be strings.
	 **/
	g_object_class_install_property
		(object_class, PROP_DATA,
		 _nm_param_spec_specialized (NM_SETTING_VPN_DATA, "", "",
		                             DBUS_TYPE_G_MAP_OF_STRING,
		                             G_PARAM_READWRITE |
		                             G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingVPN:secrets:
	 *
	 * Dictionary of key/value pairs of VPN plugin specific secrets like
	 * passwords or private keys.  Both keys and values must be strings.
	 **/
	g_object_class_install_property
		(object_class, PROP_SECRETS,
		 _nm_param_spec_specialized (NM_SETTING_VPN_SECRETS, "", "",
		                             DBUS_TYPE_G_MAP_OF_STRING,
		                             G_PARAM_READWRITE |
		                             NM_SETTING_PARAM_SECRET |
		                             G_PARAM_STATIC_STRINGS));
}
