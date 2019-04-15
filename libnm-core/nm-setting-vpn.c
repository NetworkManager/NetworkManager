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

#include "nm-setting-vpn.h"

#include <stdlib.h>

#include "nm-glib-aux/nm-secret-utils.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-vpn
 * @short_description: Describes connection properties for Virtual Private Networks
 *
 * The #NMSettingVpn object is a #NMSetting subclass that describes properties
 * necessary for connection to Virtual Private Networks.  NetworkManager uses
 * a plugin architecture to allow easier use of new VPN types, and this
 * setting abstracts the configuration for those plugins.  Since the configuration
 * options are only known to the VPN plugins themselves, the VPN configuration
 * options are stored as key/value pairs of strings rather than GObject
 * properties.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMSettingVpn,
	PROP_SERVICE_TYPE,
	PROP_USER_NAME,
	PROP_PERSISTENT,
	PROP_DATA,
	PROP_SECRETS,
	PROP_TIMEOUT,
);

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

	/* Timeout for the VPN service to establish the connection */
	guint32 timeout;
} NMSettingVpnPrivate;

G_DEFINE_TYPE (NMSettingVpn, nm_setting_vpn, NM_TYPE_SETTING)

#define NM_SETTING_VPN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_VPN, NMSettingVpnPrivate))

/*****************************************************************************/

/**
 * nm_setting_vpn_get_service_type:
 * @setting: the #NMSettingVpn
 *
 * Returns the service name of the VPN, which identifies the specific VPN
 * plugin that should be used to connect to this VPN.
 *
 * Returns: the VPN plugin's service name
 **/
const char *
nm_setting_vpn_get_service_type (NMSettingVpn *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), NULL);

	return NM_SETTING_VPN_GET_PRIVATE (setting)->service_type;
}

/**
 * nm_setting_vpn_get_user_name:
 * @setting: the #NMSettingVpn
 *
 * Returns: the #NMSettingVpn:user-name property of the setting
 **/
const char *
nm_setting_vpn_get_user_name (NMSettingVpn *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), NULL);

	return NM_SETTING_VPN_GET_PRIVATE (setting)->user_name;
}

/**
 * nm_setting_vpn_get_persistent:
 * @setting: the #NMSettingVpn
 *
 * Returns: the #NMSettingVpn:persistent property of the setting
 **/
gboolean
nm_setting_vpn_get_persistent (NMSettingVpn *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), FALSE);

	return NM_SETTING_VPN_GET_PRIVATE (setting)->persistent;
}

/**
 * nm_setting_vpn_get_num_data_items:
 * @setting: the #NMSettingVpn
 *
 * Gets number of key/value pairs of VPN configuration data.
 *
 * Returns: the number of VPN plugin specific configuration data items
 **/
guint32
nm_setting_vpn_get_num_data_items (NMSettingVpn *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), 0);

	return g_hash_table_size (NM_SETTING_VPN_GET_PRIVATE (setting)->data);
}

/**
 * nm_setting_vpn_add_data_item:
 * @setting: the #NMSettingVpn
 * @key: a name that uniquely identifies the given value @item
 * @item: the value to be referenced by @key
 *
 * Establishes a relationship between @key and @item internally in the
 * setting which may be retrieved later.  Should not be used to store passwords
 * or other secrets, which is what nm_setting_vpn_add_secret() is for.
 **/
void
nm_setting_vpn_add_data_item (NMSettingVpn *setting,
                              const char *key,
                              const char *item)
{
	g_return_if_fail (NM_IS_SETTING_VPN (setting));
	g_return_if_fail (key && key[0]);
	g_return_if_fail (item && item[0]);

	g_hash_table_insert (NM_SETTING_VPN_GET_PRIVATE (setting)->data,
	                     g_strdup (key), g_strdup (item));
	_notify (setting, PROP_DATA);
}

/**
 * nm_setting_vpn_get_data_item:
 * @setting: the #NMSettingVpn
 * @key: the name of the data item to retrieve
 *
 * Retrieves the data item of a key/value relationship previously established
 * by nm_setting_vpn_add_data_item().
 *
 * Returns: the data item, if any
 **/
const char *
nm_setting_vpn_get_data_item (NMSettingVpn *setting, const char *key)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), NULL);

	return (const char *) g_hash_table_lookup (NM_SETTING_VPN_GET_PRIVATE (setting)->data, key);
}

/**
 * nm_setting_vpn_get_data_keys:
 * @setting: the #NMSettingVpn
 * @out_length: (allow-none) (out): the length of the returned array
 *
 * Retrieves every data key inside @setting, as an array.
 *
 * Returns: (array length=out_length) (transfer container): a
 *   %NULL-terminated array containing each data key or %NULL if
 *   there are no data items.
 *
 * Since: 1.12
 */
const char **
nm_setting_vpn_get_data_keys (NMSettingVpn *setting,
                              guint *out_length)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), NULL);

	return nm_utils_strdict_get_keys (NM_SETTING_VPN_GET_PRIVATE (setting)->data,
	                                  TRUE,
	                                  out_length);
}

/**
 * nm_setting_vpn_remove_data_item:
 * @setting: the #NMSettingVpn
 * @key: the name of the data item to remove
 *
 * Deletes a key/value relationship previously established by
 * nm_setting_vpn_add_data_item().
 *
 * Returns: %TRUE if the data item was found and removed from the internal list,
 * %FALSE if it was not.
 **/
gboolean
nm_setting_vpn_remove_data_item (NMSettingVpn *setting, const char *key)
{
	gboolean found;

	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), FALSE);
	g_return_val_if_fail (key, FALSE);

	found = g_hash_table_remove (NM_SETTING_VPN_GET_PRIVATE (setting)->data, key);
	if (found)
		_notify (setting, PROP_DATA);
	return found;
}

static void
foreach_item_helper (NMSettingVpn *self,
                     gboolean is_secrets,
                     NMVpnIterFunc func,
                     gpointer user_data)
{
	NMSettingVpnPrivate *priv;
	guint len, i;
	gs_strfreev char **keys = NULL;
	GHashTable *hash;

	nm_assert (NM_IS_SETTING_VPN (self));
	nm_assert (func);

	priv = NM_SETTING_VPN_GET_PRIVATE (self);

	if (is_secrets) {
		keys = (char **) nm_setting_vpn_get_secret_keys (self, &len);
		hash = priv->secrets;
	} else {
		keys = (char **) nm_setting_vpn_get_data_keys (self, &len);
		hash = priv->data;
	}

	if (!len) {
		nm_assert (!keys);
		return;
	}

	for (i = 0; i < len; i++) {
		nm_assert (keys[i]);
		keys[i] = g_strdup (keys[i]);
	}
	nm_assert (!keys[i]);

	for (i = 0; i < len; i++) {
		const char *value;

		value = g_hash_table_lookup (hash, keys[i]);
		/* NOTE: note that we call the function with a clone of @key,
		 * not with the actual key from the dictionary.
		 *
		 * The @value on the other hand, is actually inside our dictionary,
		 * it's not a clone. However, it might be %NULL, in case the key was
		 * deleted while iterating. */
		func (keys[i], value, user_data);
	}
}

/**
 * nm_setting_vpn_foreach_data_item:
 * @setting: a #NMSettingVpn
 * @func: (scope call): an user provided function
 * @user_data: data to be passed to @func
 *
 * Iterates all data items stored in this setting.  It is safe to add, remove,
 * and modify data items inside @func, though any additions or removals made
 * during iteration will not be part of the iteration.
 */
void
nm_setting_vpn_foreach_data_item (NMSettingVpn *setting,
                                  NMVpnIterFunc func,
                                  gpointer user_data)
{
	g_return_if_fail (NM_IS_SETTING_VPN (setting));
	g_return_if_fail (func);

	foreach_item_helper (setting, FALSE, func, user_data);
}

/**
 * nm_setting_vpn_get_num_secrets:
 * @setting: the #NMSettingVpn
 *
 * Gets number of VPN plugin specific secrets in the setting.
 *
 * Returns: the number of VPN plugin specific secrets
 **/
guint32
nm_setting_vpn_get_num_secrets (NMSettingVpn *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), 0);

	return g_hash_table_size (NM_SETTING_VPN_GET_PRIVATE (setting)->secrets);
}

/**
 * nm_setting_vpn_add_secret:
 * @setting: the #NMSettingVpn
 * @key: a name that uniquely identifies the given secret @secret
 * @secret: the secret to be referenced by @key
 *
 * Establishes a relationship between @key and @secret internally in the
 * setting which may be retrieved later.
 **/
void
nm_setting_vpn_add_secret (NMSettingVpn *setting,
                           const char *key,
                           const char *secret)
{
	g_return_if_fail (NM_IS_SETTING_VPN (setting));
	g_return_if_fail (key && key[0]);
	g_return_if_fail (secret && secret[0]);

	g_hash_table_insert (NM_SETTING_VPN_GET_PRIVATE (setting)->secrets,
	                     g_strdup (key), g_strdup (secret));
	_notify (setting, PROP_SECRETS);
}

/**
 * nm_setting_vpn_get_secret:
 * @setting: the #NMSettingVpn
 * @key: the name of the secret to retrieve
 *
 * Retrieves the secret of a key/value relationship previously established
 * by nm_setting_vpn_add_secret().
 *
 * Returns: the secret, if any
 **/
const char *
nm_setting_vpn_get_secret (NMSettingVpn *setting, const char *key)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), NULL);

	return (const char *) g_hash_table_lookup (NM_SETTING_VPN_GET_PRIVATE (setting)->secrets, key);
}

/**
 * nm_setting_vpn_get_secret_keys:
 * @setting: the #NMSettingVpn
 * @out_length: (allow-none) (out): the length of the returned array
 *
 * Retrieves every secret key inside @setting, as an array.
 *
 * Returns: (array length=out_length) (transfer container): a
 *   %NULL-terminated array containing each secret key or %NULL if
 *   there are no secrets.
 *
 * Since: 1.12
 */
const char **
nm_setting_vpn_get_secret_keys (NMSettingVpn *setting,
                                guint *out_length)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), NULL);

	return nm_utils_strdict_get_keys (NM_SETTING_VPN_GET_PRIVATE (setting)->secrets,
	                                  TRUE,
	                                  out_length);
}

/**
 * nm_setting_vpn_remove_secret:
 * @setting: the #NMSettingVpn
 * @key: the name of the secret to remove
 *
 * Deletes a key/value relationship previously established by
 * nm_setting_vpn_add_secret().
 *
 * Returns: %TRUE if the secret was found and removed from the internal list,
 * %FALSE if it was not.
 **/
gboolean
nm_setting_vpn_remove_secret (NMSettingVpn *setting, const char *key)
{
	gboolean found;

	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), FALSE);
	g_return_val_if_fail (key, FALSE);

	found = g_hash_table_remove (NM_SETTING_VPN_GET_PRIVATE (setting)->secrets, key);
	if (found)
		_notify (setting, PROP_SECRETS);
	return found;
}

/**
 * nm_setting_vpn_foreach_secret:
 * @setting: a #NMSettingVpn
 * @func: (scope call): an user provided function
 * @user_data: data to be passed to @func
 *
 * Iterates all secrets stored in this setting.  It is safe to add, remove,
 * and modify secrets inside @func, though any additions or removals made during
 * iteration will not be part of the iteration.
 */
void
nm_setting_vpn_foreach_secret (NMSettingVpn *setting,
                               NMVpnIterFunc func,
                               gpointer user_data)
{
	g_return_if_fail (NM_IS_SETTING_VPN (setting));
	g_return_if_fail (func);

	foreach_item_helper (setting, TRUE, func, user_data);
}

static gboolean
aggregate (NMSetting *setting,
           int type_i,
           gpointer arg)
{
	NMSettingVpnPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);
	NMConnectionAggregateType type = type_i;
	NMSettingSecretFlags secret_flags;
	const char *key_name;
	GHashTableIter iter;

	switch (type) {

	case NM_CONNECTION_AGGREGATE_ANY_SECRETS:
		if (g_hash_table_size (priv->secrets) > 0) {
			*((gboolean *) arg) = TRUE;
			return TRUE;
		}
		return FALSE;

	case NM_CONNECTION_AGGREGATE_ANY_SYSTEM_SECRET_FLAGS:

		g_hash_table_iter_init (&iter, priv->secrets);
		while (g_hash_table_iter_next (&iter, (gpointer *) &key_name, NULL)) {
			if (!nm_setting_get_secret_flags (NM_SETTING (setting), key_name, &secret_flags, NULL))
				nm_assert_not_reached ();
			if (secret_flags == NM_SETTING_SECRET_FLAG_NONE) {
				*((gboolean *) arg) = TRUE;
				return TRUE;
			}
		}

		/* Ok, we have no secrets with system-secret flags.
		 * But do we have any secret-flags (without secrets) that indicate system secrets? */
		g_hash_table_iter_init (&iter, priv->data);
		while (g_hash_table_iter_next (&iter, (gpointer *) &key_name, NULL)) {
			gs_free char *secret_name = NULL;

			if (!g_str_has_suffix (key_name, "-flags"))
				continue;
			secret_name = g_strndup (key_name, strlen (key_name) - NM_STRLEN ("-flags"));
			if (secret_name[0] == '\0')
				continue;
			if (!nm_setting_get_secret_flags (NM_SETTING (setting), secret_name, &secret_flags, NULL))
				nm_assert_not_reached ();
			if (secret_flags == NM_SETTING_SECRET_FLAG_NONE) {
				*((gboolean *) arg) = TRUE;
				return TRUE;
			}
		}

		return FALSE;
	}

	g_return_val_if_reached (FALSE);
}

/**
 * nm_setting_vpn_get_timeout:
 * @setting: the #NMSettingVpn
 *
 * Returns: the #NMSettingVpn:timeout property of the setting
 *
 * Since: 1.2
 **/
guint32
nm_setting_vpn_get_timeout (NMSettingVpn *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), 0);

	return NM_SETTING_VPN_GET_PRIVATE (setting)->timeout;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingVpnPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);
	NMSettingConnection *s_con;

	if (!priv->service_type) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_VPN_SETTING_NAME, NM_SETTING_VPN_SERVICE_TYPE);
		return FALSE;
	}

	if (!strlen (priv->service_type)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_VPN_SETTING_NAME, NM_SETTING_VPN_SERVICE_TYPE);
		return FALSE;
	}

	/* default username can be NULL, but can't be zero-length */
	if (priv->user_name && !strlen (priv->user_name)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_VPN_SETTING_NAME, NM_SETTING_VPN_USER_NAME);
		return FALSE;
	}

	if (   connection
	    && (s_con = nm_connection_get_setting_connection (connection))
	    && nm_setting_connection_get_multi_connect (s_con) != NM_CONNECTION_MULTI_CONNECT_DEFAULT) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("cannot set connection.multi-connect for VPN setting"));
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
	NMSettingVpnPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);

	g_return_val_if_fail (key != NULL, NM_SETTING_UPDATE_SECRET_ERROR);
	g_return_val_if_fail (value != NULL, NM_SETTING_UPDATE_SECRET_ERROR);

	if (!value || !strlen (value)) {
		g_set_error (error, NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("secret was empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_VPN_SETTING_NAME, key);
		return NM_SETTING_UPDATE_SECRET_ERROR;
	}

	if (g_strcmp0 (g_hash_table_lookup (priv->secrets, key), value) == 0)
		return NM_SETTING_UPDATE_SECRET_SUCCESS_UNCHANGED;

	g_hash_table_insert (priv->secrets, g_strdup (key), g_strdup (value));
	return NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED;
}

static NMSettingUpdateSecretResult
update_secret_dict (NMSetting *setting,
                    GVariant *secrets,
                    GError **error)
{
	NMSettingVpnPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);
	GVariantIter iter;
	const char *name, *value;
	NMSettingUpdateSecretResult result = NM_SETTING_UPDATE_SECRET_SUCCESS_UNCHANGED;

	g_return_val_if_fail (secrets != NULL, NM_SETTING_UPDATE_SECRET_ERROR);

	/* Make sure the items are valid */
	g_variant_iter_init (&iter, secrets);
	while (g_variant_iter_next (&iter, "{&s&s}", &name, &value)) {
		if (!name || !strlen (name)) {
			g_set_error_literal (error, NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_SETTING,
			                     _("setting contained a secret with an empty name"));
			g_prefix_error (error, "%s: ", NM_SETTING_VPN_SETTING_NAME);
			return NM_SETTING_UPDATE_SECRET_ERROR;
		}

		if (!value || !strlen (value)) {
			g_set_error (error, NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("secret value was empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_VPN_SETTING_NAME, name);
			return NM_SETTING_UPDATE_SECRET_ERROR;
		}
	}

	/* Now add the items to the settings' secrets list */
	g_variant_iter_init (&iter, secrets);
	while (g_variant_iter_next (&iter, "{&s&s}", &name, &value)) {
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
update_one_secret (NMSetting *setting, const char *key, GVariant *value, GError **error)
{
	NMSettingUpdateSecretResult success = NM_SETTING_UPDATE_SECRET_ERROR;

	g_return_val_if_fail (key != NULL, NM_SETTING_UPDATE_SECRET_ERROR);
	g_return_val_if_fail (value != NULL, NM_SETTING_UPDATE_SECRET_ERROR);

	if (g_variant_is_of_type (value, G_VARIANT_TYPE_STRING)) {
		/* Passing the string properties individually isn't correct, and won't
		 * produce the correct result, but for some reason that's how it used
		 * to be done.  So even though it's not correct, keep the code around
		 * for compatibility's sake.
		 */
		success = update_secret_string (setting, key, g_variant_get_string (value, NULL), error);
	} else if (g_variant_is_of_type (value, G_VARIANT_TYPE ("a{ss}"))) {
		if (strcmp (key, NM_SETTING_VPN_SECRETS) != 0) {
			g_set_error_literal (error, NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_PROPERTY_NOT_SECRET,
			                     _("not a secret property"));
			g_prefix_error (error, "%s.%s ", NM_SETTING_VPN_SETTING_NAME, key);
		} else
			success = update_secret_dict (setting, value, error);
	} else {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("secret is not of correct type"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_VPN_SETTING_NAME, key);
	}

	if (success == NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED)
		_notify (NM_SETTING_VPN (setting), PROP_SECRETS);

	return success;
}

static void
for_each_secret (NMSetting *setting,
                 const char *secret_name,
                 GVariant *val,
                 gboolean remove_non_secrets,
                 _NMConnectionForEachSecretFunc callback,
                 gpointer callback_data,
                 GVariantBuilder *setting_builder)
{
	GVariantBuilder vpn_secrets_builder;
	GVariantIter vpn_secrets_iter;
	const char *vpn_secret_name;
	const char *secret;

	if (!nm_streq (secret_name, NM_SETTING_VPN_SECRETS)) {
		NM_SETTING_CLASS (nm_setting_vpn_parent_class)->for_each_secret (setting,
		                                                                 secret_name,
		                                                                 val,
		                                                                 remove_non_secrets,
		                                                                 callback,
		                                                                 callback_data,
		                                                                 setting_builder);
		return;
	}

	if (!g_variant_is_of_type (val, G_VARIANT_TYPE ("a{ss}"))) {
		/* invalid type. Silently ignore the secrets as we cannot find out the
		 * secret-flags. */
		return;
	}

	/* Iterate through each secret from the VPN dict in the overall secrets dict */
	g_variant_builder_init (&vpn_secrets_builder, G_VARIANT_TYPE ("a{ss}"));
	g_variant_iter_init (&vpn_secrets_iter, val);
	while (g_variant_iter_next (&vpn_secrets_iter, "{&s&s}", &vpn_secret_name, &secret)) {
		NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;

		/* we ignore the return value of get_secret_flags. The function may determine
		 * that this is not a secret, based on having not secret-flags and no secrets.
		 * But we have the secret at hand. We know it would be a valid secret, if we
		 * only add it to the VPN settings. */
		nm_setting_get_secret_flags (setting, vpn_secret_name, &secret_flags, NULL);

		if (callback (secret_flags, callback_data))
			g_variant_builder_add (&vpn_secrets_builder, "{ss}", vpn_secret_name, secret);
	}

	g_variant_builder_add (setting_builder, "{sv}",
	                       secret_name, g_variant_builder_end (&vpn_secrets_builder));
}

static gboolean
get_secret_flags (NMSetting *setting,
                  const char *secret_name,
                  NMSettingSecretFlags *out_flags,
                  GError **error)
{
	NMSettingVpnPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);
	gs_free char *flags_key_free = NULL;
	const char *flags_key;
	const char *flags_val;
	gint64 i64;

	flags_key = nm_construct_name_a ("%s-flags", secret_name, &flags_key_free);

	if (!g_hash_table_lookup_extended (priv->data, flags_key, NULL, (gpointer *) &flags_val)) {
		NM_SET_OUT (out_flags, NM_SETTING_SECRET_FLAG_NONE);

		/* having no secret flag for the secret is fine, as long as there
		 * is the secret itself... */
		if (!g_hash_table_contains (priv->secrets, secret_name)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_PROPERTY_NOT_SECRET,
			                     _("secret flags property not found"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_VPN_SETTING_NAME, flags_key);
			return FALSE;
		}
		return TRUE;
	}

	i64 = _nm_utils_ascii_str_to_int64 (flags_val, 10, 0, NM_SETTING_SECRET_FLAG_ALL, -1);
	if (   i64 == -1
	    || !_nm_setting_secret_flags_valid (i64)) {
		/* The flags keys is set to an unexpected value. That is a configuration
		 * error. Note that keys named "*-flags" are reserved for secrets. The user
		 * must not use this for anything but secret flags. Hence, we cannot fail
		 * to read the secret, we pretend that the secret flag is set to the default
		 * NM_SETTING_SECRET_FLAG_NONE. */
		NM_SET_OUT (out_flags, NM_SETTING_SECRET_FLAG_NONE);
		return TRUE;
	}

	NM_SET_OUT (out_flags, (NMSettingSecretFlags) i64);
	return TRUE;
}

static gboolean
set_secret_flags (NMSetting *setting,
                  const char *secret_name,
                  NMSettingSecretFlags flags,
                  GError **error)
{
	g_hash_table_insert (NM_SETTING_VPN_GET_PRIVATE (setting)->data,
	                     g_strdup_printf ("%s-flags", secret_name),
	                     g_strdup_printf ("%u", flags));
	_notify (NM_SETTING_VPN (setting), PROP_SECRETS);
	return TRUE;
}

static GPtrArray *
need_secrets (NMSetting *setting)
{
	/* Assume that VPN connections need secrets since they almost always will */
	return g_ptr_array_sized_new (1);
}

static NMTernary
compare_property_secrets (NMSettingVpn *a,
                          NMSettingVpn *b,
                          NMSettingCompareFlags flags)
{
	GHashTableIter iter;
	const char *key, *val;
	int run;

	if (NM_FLAGS_HAS (flags, NM_SETTING_COMPARE_FLAG_FUZZY))
		return NM_TERNARY_DEFAULT;
	if (NM_FLAGS_HAS (flags, NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS))
		return NM_TERNARY_DEFAULT;

	if (!b)
		return TRUE;

	for (run = 0; run < 2; run++) {
		NMSettingVpn *current_a = (run == 0) ? a : b;
		NMSettingVpn *current_b = (run == 0) ? b : a;

		g_hash_table_iter_init (&iter, NM_SETTING_VPN_GET_PRIVATE (current_a)->secrets);
		while (g_hash_table_iter_next (&iter, (gpointer) &key, (gpointer) &val)) {

			if (nm_streq0 (val, nm_setting_vpn_get_secret (current_b, key)))
				continue;
			if (!_nm_setting_should_compare_secret_property (NM_SETTING (current_a),
			                                                 NM_SETTING (current_b),
			                                                 key,
			                                                 flags))
				continue;

			return FALSE;
		}
	}

	return TRUE;
}

static NMTernary
compare_property (const NMSettInfoSetting *sett_info,
                  guint property_idx,
                  NMSetting *setting,
                  NMSetting *other,
                  NMSettingCompareFlags flags)
{
	if (nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_VPN_SECRETS)) {
		if (NM_FLAGS_HAS (flags, NM_SETTING_COMPARE_FLAG_INFERRABLE))
			return NM_TERNARY_DEFAULT;
		return compare_property_secrets (NM_SETTING_VPN (setting), NM_SETTING_VPN (other), flags);
	}

	return NM_SETTING_CLASS (nm_setting_vpn_parent_class)->compare_property (sett_info,
	                                                                         property_idx,
	                                                                         setting,
	                                                                         other,
	                                                                         flags);
}

static gboolean
clear_secrets (const NMSettInfoSetting *sett_info,
               guint property_idx,
               NMSetting *setting,
               NMSettingClearSecretsWithFlagsFn func,
               gpointer user_data)
{
	NMSettingVpnPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);
	GParamSpec *prop_spec = sett_info->property_infos[property_idx].param_spec;
	GHashTableIter iter;
	const char *secret;
	gboolean changed = TRUE;

	if (   !prop_spec
	    || !NM_FLAGS_HAS (prop_spec->flags, NM_SETTING_PARAM_SECRET))
		return FALSE;

	nm_assert (nm_streq (prop_spec->name, NM_SETTING_VPN_SECRETS));

	if (!priv->secrets)
		return FALSE;

	g_hash_table_iter_init (&iter, priv->secrets);
	while (g_hash_table_iter_next (&iter, (gpointer) &secret, NULL)) {

		if (func) {
			NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

			if (!nm_setting_get_secret_flags (setting, secret, &flags, NULL))
				nm_assert_not_reached ();

			if (!func (setting, secret, flags, user_data))
				continue;
		} else
			nm_assert (nm_setting_get_secret_flags (setting, secret, NULL, NULL));

		g_hash_table_iter_remove (&iter);
		changed = TRUE;
	}

	if (changed)
		_notify (NM_SETTING_VPN (setting), PROP_SECRETS);

	return changed;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingVpn *setting = NM_SETTING_VPN (object);
	NMSettingVpnPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);

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
		g_value_take_boxed (value, _nm_utils_copy_strdict (priv->data));
		break;
	case PROP_SECRETS:
		g_value_take_boxed (value, _nm_utils_copy_strdict (priv->secrets));
		break;
	case PROP_TIMEOUT:
		g_value_set_uint (value, nm_setting_vpn_get_timeout (setting));
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
	NMSettingVpnPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (object);

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
		g_hash_table_unref (priv->data);
		priv->data = _nm_utils_copy_strdict (g_value_get_boxed (value));
		break;
	case PROP_SECRETS:
		g_hash_table_unref (priv->secrets);
		priv->secrets = _nm_utils_copy_strdict (g_value_get_boxed (value));
		break;
	case PROP_TIMEOUT:
		priv->timeout = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_vpn_init (NMSettingVpn *setting)
{
	NMSettingVpnPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (setting);

	priv->data = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_free);
	priv->secrets = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, (GDestroyNotify) nm_free_secret);
}

/**
 * nm_setting_vpn_new:
 *
 * Creates a new #NMSettingVpn object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingVpn object
 **/
NMSetting *
nm_setting_vpn_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_VPN, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingVpnPrivate *priv = NM_SETTING_VPN_GET_PRIVATE (object);

	g_free (priv->service_type);
	g_free (priv->user_name);
	g_hash_table_destroy (priv->data);
	g_hash_table_destroy (priv->secrets);

	G_OBJECT_CLASS (nm_setting_vpn_parent_class)->finalize (object);
}

static void
nm_setting_vpn_class_init (NMSettingVpnClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);
	GArray *properties_override = _nm_sett_info_property_override_create_array ();

	g_type_class_add_private (klass, sizeof (NMSettingVpnPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	setting_class->verify            = verify;
	setting_class->update_one_secret = update_one_secret;
	setting_class->for_each_secret   = for_each_secret;
	setting_class->get_secret_flags  = get_secret_flags;
	setting_class->set_secret_flags  = set_secret_flags;
	setting_class->need_secrets      = need_secrets;
	setting_class->compare_property  = compare_property;
	setting_class->clear_secrets     = clear_secrets;
	setting_class->aggregate         = aggregate;

	/**
	 * NMSettingVpn:service-type:
	 *
	 * D-Bus service name of the VPN plugin that this setting uses to connect to
	 * its network.  i.e. org.freedesktop.NetworkManager.vpnc for the vpnc
	 * plugin.
	 **/
	obj_properties[PROP_SERVICE_TYPE] =
	    g_param_spec_string (NM_SETTING_VPN_SERVICE_TYPE, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingVpn:user-name:
	 *
	 * If the VPN connection requires a user name for authentication, that name
	 * should be provided here.  If the connection is available to more than one
	 * user, and the VPN requires each user to supply a different name, then
	 * leave this property empty.  If this property is empty, NetworkManager
	 * will automatically supply the username of the user which requested the
	 * VPN connection.
	 **/
	obj_properties[PROP_USER_NAME] =
	    g_param_spec_string (NM_SETTING_VPN_USER_NAME, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingVpn:persistent:
	 *
	 * If the VPN service supports persistence, and this property is %TRUE,
	 * the VPN will attempt to stay connected across link changes and outages,
	 * until explicitly disconnected.
	 **/
	obj_properties[PROP_PERSISTENT] =
	    g_param_spec_boolean (NM_SETTING_VPN_PERSISTENT, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingVpn:data: (type GHashTable(utf8,utf8)):
	 *
	 * Dictionary of key/value pairs of VPN plugin specific data.  Both keys and
	 * values must be strings.
	 **/
	/* ---keyfile---
	 * property: data
	 * variable: separate variables named after keys of the dictionary
	 * description: The keys of the data dictionary are used as variable names directly
	 *   under [vpn] section.
	 * example: remote=ovpn.corp.com cipher=AES-256-CBC username=joe
	 * ---end---
	 */
	obj_properties[PROP_DATA] =
	    g_param_spec_boxed (NM_SETTING_VPN_DATA, "", "",
	                        G_TYPE_HASH_TABLE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	_properties_override_add_transform (properties_override,
	                                    obj_properties[PROP_DATA],
	                                    G_VARIANT_TYPE ("a{ss}"),
	                                    _nm_utils_strdict_to_dbus,
	                                    _nm_utils_strdict_from_dbus);

	/**
	 * NMSettingVpn:secrets: (type GHashTable(utf8,utf8)):
	 *
	 * Dictionary of key/value pairs of VPN plugin specific secrets like
	 * passwords or private keys.  Both keys and values must be strings.
	 **/
	/* ---keyfile---
	 * property: secrets
	 * variable: separate variables named after keys of the dictionary
	 * description: The keys of the secrets dictionary are used as variable names directly
	 *   under [vpn-secrets] section.
	 * example: password=Popocatepetl
	 * ---end---
	 */
	obj_properties[PROP_SECRETS] =
	    g_param_spec_boxed (NM_SETTING_VPN_SECRETS, "", "",
	                        G_TYPE_HASH_TABLE,
	                        G_PARAM_READWRITE |
	                        NM_SETTING_PARAM_SECRET |
	                        G_PARAM_STATIC_STRINGS);

	_properties_override_add_transform (properties_override,
	                                    obj_properties[PROP_SECRETS],
	                                    G_VARIANT_TYPE ("a{ss}"),
	                                    _nm_utils_strdict_to_dbus,
	                                    _nm_utils_strdict_from_dbus);

	/**
	 * NMSettingVpn:timeout:
	 *
	 * Timeout for the VPN service to establish the connection. Some services
	 * may take quite a long time to connect.
	 * Value of 0 means a default timeout, which is 60 seconds (unless overridden
	 * by vpn.timeout in configuration file). Values greater than zero mean
	 * timeout in seconds.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_TIMEOUT] =
	    g_param_spec_uint (NM_SETTING_VPN_TIMEOUT, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit_full (setting_class, NM_META_SETTING_TYPE_VPN,
	                               NULL, properties_override);
}
