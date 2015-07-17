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

#include "config.h"

#include <glib/gi18n-lib.h>
#include <string.h>
#include "nm-default.h"
#include "nm-connection.h"
#include "nm-connection-private.h"
#include "nm-utils.h"
#include "nm-setting-private.h"
#include "nm-core-internal.h"

/**
 * SECTION:nm-connection
 * @short_description: Describes a connection to specific network or provider
 *
 * An #NMConnection describes all the settings and configuration values that
 * are necessary to configure network devices for operation on a specific
 * network.  Connections are the fundamental operating object for
 * NetworkManager; no device is connected without a #NMConnection, or
 * disconnected without having been connected with a #NMConnection.
 *
 * Each #NMConnection contains a list of #NMSetting objects usually referenced
 * by name (using nm_connection_get_setting_by_name()) or by type (with
 * nm_connection_get_setting()).  The settings describe the actual parameters
 * with which the network devices are configured, including device-specific
 * parameters (MTU, SSID, APN, channel, rate, etc) and IP-level parameters
 * (addresses, routes, addressing methods, etc).
 *
 */

typedef struct {
	NMConnection *self;

	GHashTable *settings;

	/* D-Bus path of the connection, if any */
	char *path;
} NMConnectionPrivate;

static NMConnectionPrivate *nm_connection_get_private (NMConnection *connection);
#define NM_CONNECTION_GET_PRIVATE(o) (nm_connection_get_private ((NMConnection *)o))

G_DEFINE_INTERFACE (NMConnection, nm_connection, G_TYPE_OBJECT)

enum {
	SECRETS_UPDATED,
	SECRETS_CLEARED,
	CHANGED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


static NMSettingVerifyResult _nm_connection_verify (NMConnection *connection, GError **error);


/*************************************************************/

static void
setting_changed_cb (NMSetting *setting,
                    GParamSpec *pspec,
                    NMConnection *self)
{
	g_signal_emit (self, signals[CHANGED], 0);
}

static gboolean
_setting_release (gpointer key, gpointer value, gpointer user_data)
{
	g_signal_handlers_disconnect_by_func (user_data, setting_changed_cb, value);
	return TRUE;
}

static void
_nm_connection_add_setting (NMConnection *connection, NMSetting *setting)
{
	NMConnectionPrivate *priv = NM_CONNECTION_GET_PRIVATE (connection);
	const char *name = G_OBJECT_TYPE_NAME (setting);
	NMSetting *s_old;

	if ((s_old = g_hash_table_lookup (priv->settings, (gpointer) name)))
		g_signal_handlers_disconnect_by_func (s_old, setting_changed_cb, connection);
	g_hash_table_insert (priv->settings, (gpointer) name, setting);
	/* Listen for property changes so we can emit the 'changed' signal */
	g_signal_connect (setting, "notify", (GCallback) setting_changed_cb, connection);
}

/**
 * nm_connection_add_setting:
 * @connection: a #NMConnection
 * @setting: (transfer full): the #NMSetting to add to the connection object
 *
 * Adds a #NMSetting to the connection, replacing any previous #NMSetting of the
 * same name which has previously been added to the #NMConnection.  The
 * connection takes ownership of the #NMSetting object and does not increase
 * the setting object's reference count.
 **/
void
nm_connection_add_setting (NMConnection *connection, NMSetting *setting)
{
	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (NM_IS_SETTING (setting));

	_nm_connection_add_setting (connection, setting);
	g_signal_emit (connection, signals[CHANGED], 0);
}

/**
 * nm_connection_remove_setting:
 * @connection: a #NMConnection
 * @setting_type: the #GType of the setting object to remove
 *
 * Removes the #NMSetting with the given #GType from the #NMConnection.  This
 * operation dereferences the #NMSetting object.
 **/
void
nm_connection_remove_setting (NMConnection *connection, GType setting_type)
{
	NMConnectionPrivate *priv;
	NMSetting *setting;
	const char *setting_name;

	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (g_type_is_a (setting_type, NM_TYPE_SETTING));

	priv = NM_CONNECTION_GET_PRIVATE (connection);
	setting_name = g_type_name (setting_type);
	setting = g_hash_table_lookup (priv->settings, setting_name);
	if (setting) {
		g_signal_handlers_disconnect_by_func (setting, setting_changed_cb, connection);
		g_hash_table_remove (priv->settings, setting_name);
		g_signal_emit (connection, signals[CHANGED], 0);
	}
}

/**
 * nm_connection_get_setting:
 * @connection: a #NMConnection
 * @setting_type: the #GType of the setting object to return
 *
 * Gets the #NMSetting with the given #GType, if one has been previously added
 * to the #NMConnection.
 *
 * Returns: (transfer none): the #NMSetting, or %NULL if no setting of that type was previously
 * added to the #NMConnection
 **/
NMSetting *
nm_connection_get_setting (NMConnection *connection, GType setting_type)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (g_type_is_a (setting_type, NM_TYPE_SETTING), NULL);

	return (NMSetting *) g_hash_table_lookup (NM_CONNECTION_GET_PRIVATE (connection)->settings,
	                                          g_type_name (setting_type));
}

/**
 * nm_connection_get_setting_by_name:
 * @connection: a #NMConnection
 * @name: a setting name
 *
 * Gets the #NMSetting with the given name, if one has been previously added
 * the #NMConnection.
 *
 * Returns: (transfer none): the #NMSetting, or %NULL if no setting with that name was previously
 * added to the #NMConnection
 **/
NMSetting *
nm_connection_get_setting_by_name (NMConnection *connection, const char *name)
{
	GType type;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (name != NULL, NULL);

	type = nm_setting_lookup_type (name);

	return type ? nm_connection_get_setting (connection, type) : NULL;
}

static gboolean
validate_permissions_type (GVariant *variant, GError **error)
{
	GVariant *s_con;
	GVariant *permissions;
	gboolean valid = TRUE;

	/* Ensure the connection::permissions item (if present) is the correct
	 * type, otherwise the g_object_set() will throw a warning and ignore the
	 * error, leaving us with no permissions.
	 */
	s_con = g_variant_lookup_value (variant, NM_SETTING_CONNECTION_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
	if (!s_con)
		return TRUE;

	permissions = g_variant_lookup_value (s_con, NM_SETTING_CONNECTION_PERMISSIONS, NULL);
	if (permissions) {
		if (!g_variant_is_of_type (permissions, G_VARIANT_TYPE_STRING_ARRAY)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("wrong type; should be a list of strings."));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_PERMISSIONS);
			valid = FALSE;
		}
		g_variant_unref (permissions);
	}

	g_variant_unref (s_con);
	return valid;
}

/**
 * nm_connection_replace_settings:
 * @connection: a #NMConnection
 * @new_settings: a #GVariant of type %NM_VARIANT_TYPE_CONNECTION, with the new settings
 * @error: location to store error, or %NULL
 *
 * Replaces @connection's settings with @new_settings (which must be
 * syntactically valid, and describe a known type of connection, but does not
 * need to result in a connection that passes nm_connection_verify()).
 *
 * Returns: %TRUE if connection was updated, %FALSE if @new_settings could not
 *   be deserialized (in which case @connection will be unchanged).
 **/
gboolean
nm_connection_replace_settings (NMConnection *connection,
                                GVariant *new_settings,
                                GError **error)
{
	NMConnectionPrivate *priv;
	GVariantIter iter;
	const char *setting_name;
	GVariant *setting_dict;
	GSList *settings = NULL, *s;
	gboolean changed;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (g_variant_is_of_type (new_settings, NM_VARIANT_TYPE_CONNECTION), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	priv = NM_CONNECTION_GET_PRIVATE (connection);

	if (!validate_permissions_type (new_settings, error))
		return FALSE;

	g_variant_iter_init (&iter, new_settings);
	while (g_variant_iter_next (&iter, "{&s@a{sv}}", &setting_name, &setting_dict)) {
		NMSetting *setting;
		GType type;

		type = nm_setting_lookup_type (setting_name);
		if (type == G_TYPE_INVALID) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_SETTING,
			                     _("unknown setting name"));
			g_prefix_error (error, "%s: ", setting_name);
			g_variant_unref (setting_dict);
			g_slist_free_full (settings, g_object_unref);
			return FALSE;
		}

		setting = _nm_setting_new_from_dbus (type, setting_dict, new_settings, error);
		g_variant_unref (setting_dict);

		if (!setting) {
			g_slist_free_full (settings, g_object_unref);
			return FALSE;
		}

		settings = g_slist_prepend (settings, setting);
	}

	if (g_hash_table_size (priv->settings) > 0) {
		g_hash_table_foreach_remove (priv->settings, _setting_release, connection);
		changed = TRUE;
	} else
		changed = (settings != NULL);

	for (s = settings; s; s = s->next)
		_nm_connection_add_setting (connection, s->data);

	g_slist_free (settings);

	if (changed)
		g_signal_emit (connection, signals[CHANGED], 0);
	return TRUE;
}

/**
 * nm_connection_replace_settings_from_connection:
 * @connection: a #NMConnection
 * @new_connection: a #NMConnection to replace the settings of @connection with
 *
 * Deep-copies the settings of @new_connection and replaces the settings of @connection
 * with the copied settings.
 **/
void
nm_connection_replace_settings_from_connection (NMConnection *connection,
                                                NMConnection *new_connection)
{
	NMConnectionPrivate *priv, *new_priv;
	GHashTableIter iter;
	NMSetting *setting;
	gboolean changed;

	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (NM_IS_CONNECTION (new_connection));

	/* When 'connection' and 'new_connection' are the same object simply return
	 * in order not to destroy 'connection'.
	 */
	if (connection == new_connection)
		return;

	/* No need to validate permissions like nm_connection_replace_settings()
	 * since we're dealing with an NMConnection which has already done that.
	 */

	priv = NM_CONNECTION_GET_PRIVATE (connection);
	new_priv = NM_CONNECTION_GET_PRIVATE (new_connection);

	if ((changed = g_hash_table_size (priv->settings) > 0))
		g_hash_table_foreach_remove (priv->settings, _setting_release, connection);

	if (g_hash_table_size (new_priv->settings)) {
		g_hash_table_iter_init (&iter, new_priv->settings);
		while (g_hash_table_iter_next (&iter, NULL, (gpointer) &setting))
			_nm_connection_add_setting (connection, nm_setting_duplicate (setting));
		changed = TRUE;
	}

	if (changed)
		g_signal_emit (connection, signals[CHANGED], 0);
}

/**
 * nm_connection_clear_settings:
 * @connection: a #NMConnection
 *
 * Deletes all of @connection's settings.
 **/
void
nm_connection_clear_settings (NMConnection *connection)
{
	NMConnectionPrivate *priv;

	g_return_if_fail (NM_IS_CONNECTION (connection));

	priv = NM_CONNECTION_GET_PRIVATE (connection);

	if (g_hash_table_size (priv->settings) > 0) {
		g_hash_table_foreach_remove (priv->settings, _setting_release, connection);
		g_signal_emit (connection, signals[CHANGED], 0);
	}
}

/**
 * nm_connection_compare:
 * @a: a #NMConnection
 * @b: a second #NMConnection to compare with the first
 * @flags: compare flags, e.g. %NM_SETTING_COMPARE_FLAG_EXACT
 *
 * Compares two #NMConnection objects for similarity, with comparison behavior
 * modified by a set of flags.  See nm_setting_compare() for a description of
 * each flag's behavior.
 *
 * Returns: %TRUE if the comparison succeeds, %FALSE if it does not
 **/
gboolean
nm_connection_compare (NMConnection *a,
                       NMConnection *b,
                       NMSettingCompareFlags flags)
{
	GHashTableIter iter;
	NMSetting *src;

	if (a == b)
		return TRUE;
	if (!a || !b)
		return FALSE;

	/* B / A: ensure settings in B that are not in A make the comparison fail */
	if (g_hash_table_size (NM_CONNECTION_GET_PRIVATE (a)->settings) !=
	    g_hash_table_size (NM_CONNECTION_GET_PRIVATE (b)->settings))
		return FALSE;

	/* A / B: ensure all settings in A match corresponding ones in B */
	g_hash_table_iter_init (&iter, NM_CONNECTION_GET_PRIVATE (a)->settings);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &src)) {
		NMSetting *cmp = nm_connection_get_setting (b, G_OBJECT_TYPE (src));

		if (!cmp || !nm_setting_compare (src, cmp, flags))
			return FALSE;
	}

	return TRUE;
}


static void
diff_one_connection (NMConnection *a,
                     NMConnection *b,
                     NMSettingCompareFlags flags,
                     gboolean invert_results,
                     GHashTable *diffs)
{
	NMConnectionPrivate *priv = NM_CONNECTION_GET_PRIVATE (a);
	GHashTableIter iter;
	NMSetting *a_setting = NULL;

	g_hash_table_iter_init (&iter, priv->settings);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &a_setting)) {
		NMSetting *b_setting = NULL;
		const char *setting_name = nm_setting_get_name (a_setting);
		GHashTable *results;
		gboolean new_results = TRUE;

		if (b)
			b_setting = nm_connection_get_setting (b, G_OBJECT_TYPE (a_setting));

		results = g_hash_table_lookup (diffs, setting_name);
		if (results)
			new_results = FALSE;

		if (!nm_setting_diff (a_setting, b_setting, flags, invert_results, &results)) {
			if (new_results)
				g_hash_table_insert (diffs, g_strdup (setting_name), results);
		}
	}
}

/**
 * nm_connection_diff:
 * @a: a #NMConnection
 * @b: a second #NMConnection to compare with the first
 * @flags: compare flags, e.g. %NM_SETTING_COMPARE_FLAG_EXACT
 * @out_settings: (element-type utf8 GLib.HashTable): if the
 * connections differ, on return a hash table mapping setting names to
 * second-level GHashTable (utf8 to guint32), which contains the key names that
 * differ mapped to one or more of %NMSettingDiffResult as a bitfield
 *
 * Compares two #NMConnection objects for similarity, with comparison behavior
 * modified by a set of flags.  See nm_setting_compare() for a description of
 * each flag's behavior.  If the connections differ, settings and keys within
 * each setting that differ are added to the returned @out_settings hash table.
 * No values are returned, only key names.
 *
 * Returns: %TRUE if the connections contain the same values, %FALSE if they do
 * not
 **/
gboolean
nm_connection_diff (NMConnection *a,
                    NMConnection *b,
                    NMSettingCompareFlags flags,
                    GHashTable **out_settings)
{
	GHashTable *diffs;

	g_return_val_if_fail (NM_IS_CONNECTION (a), FALSE);
	g_return_val_if_fail (out_settings != NULL, FALSE);
	g_return_val_if_fail (*out_settings == NULL, FALSE);
	if (b)
		g_return_val_if_fail (NM_IS_CONNECTION (b), FALSE);

	if (a == b)
		return TRUE;

	diffs = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) g_hash_table_destroy);

	/* Diff A to B, then B to A to capture keys in B that aren't in A */
	diff_one_connection (a, b, flags, FALSE, diffs);
	if (b)
		diff_one_connection (b, a, flags, TRUE, diffs);

	if (g_hash_table_size (diffs) == 0)
		g_hash_table_destroy (diffs);
	else
		*out_settings = diffs;

	return *out_settings ? FALSE : TRUE;
}

NMSetting *
_nm_connection_find_base_type_setting (NMConnection *connection)
{
	NMConnectionPrivate *priv = NM_CONNECTION_GET_PRIVATE (connection);
	GHashTableIter iter;
	NMSetting *setting = NULL, *s_iter;

	g_hash_table_iter_init (&iter, priv->settings);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &s_iter)) {
		if (!_nm_setting_is_base_type (s_iter))
			continue;

		if (setting) {
			/* FIXME: currently, if there is more than one matching base type,
			 * we cannot detect the base setting.
			 * See: https://bugzilla.gnome.org/show_bug.cgi?id=696936#c8 */
			return NULL;
		}
		setting = s_iter;
	}
	return setting;
}

static gboolean
_normalize_connection_uuid (NMConnection *self)
{
	NMSettingConnection *s_con = nm_connection_get_setting_connection (self);
	char *uuid;

	g_assert (s_con);

	if (nm_setting_connection_get_uuid (s_con))
		return FALSE;

	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con, NM_SETTING_CONNECTION_UUID, uuid, NULL);
	g_free (uuid);

	return TRUE;
}

static gboolean
_normalize_connection_type (NMConnection *self)
{
	NMSettingConnection *s_con = nm_connection_get_setting_connection (self);
	NMSetting *s_base = NULL;
	const char *type;

	type = nm_setting_connection_get_connection_type (s_con);

	if (type) {
		s_base = nm_connection_get_setting_by_name (self, type);

		if (!s_base) {
			GType base_type = nm_setting_lookup_type (type);

			g_return_val_if_fail (base_type, FALSE);
			nm_connection_add_setting (self, g_object_new (base_type, NULL));
			return TRUE;
		}
	} else {
		s_base =  _nm_connection_find_base_type_setting (self);
		g_return_val_if_fail (s_base, FALSE);

		type = nm_setting_get_name (s_base);
		g_object_set (s_con, NM_SETTING_CONNECTION_TYPE, type, NULL);
		return TRUE;
	}

	return FALSE;
}

const char *
_nm_connection_detect_slave_type (NMConnection *connection, NMSetting **out_s_port)
{
	NMConnectionPrivate *priv = NM_CONNECTION_GET_PRIVATE (connection);
	GHashTableIter iter;
	const char *slave_type = NULL;
	NMSetting *s_port = NULL, *s_iter;

	g_hash_table_iter_init (&iter, priv->settings);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &s_iter)) {
		const char *name = nm_setting_get_name (s_iter);
		const char *i_slave_type = NULL;

		if (!strcmp (name, NM_SETTING_BRIDGE_PORT_SETTING_NAME))
			i_slave_type = NM_SETTING_BRIDGE_SETTING_NAME;
		else if (!strcmp (name, NM_SETTING_TEAM_PORT_SETTING_NAME))
			i_slave_type = NM_SETTING_TEAM_SETTING_NAME;
		else
			continue;

		if (slave_type) {
			/* there are more then one matching port types, cannot detect the slave type. */
			slave_type = NULL;
			s_port = NULL;
			break;
		}
		slave_type = i_slave_type;
		s_port = s_iter;
	}

	if (out_s_port)
		*out_s_port = s_port;
	return slave_type;
}

static gboolean
_normalize_connection_slave_type (NMConnection *self)
{
	NMSettingConnection *s_con = nm_connection_get_setting_connection (self);
	const char *slave_type, *port_type;

	if (!s_con)
		return FALSE;
	if (!nm_setting_connection_get_master (s_con))
		return FALSE;

	slave_type = nm_setting_connection_get_slave_type (s_con);
	if (slave_type) {
		if (   _nm_setting_slave_type_is_valid (slave_type, &port_type)
		    && port_type) {
			NMSetting *s_port;

			s_port = nm_connection_get_setting_by_name (self, port_type);
			if (!s_port) {
				GType p_type = nm_setting_lookup_type (port_type);

				g_return_val_if_fail (p_type, FALSE);
				nm_connection_add_setting (self, g_object_new (p_type, NULL));
				return TRUE;
			}
		}
	} else {
		if ((slave_type = _nm_connection_detect_slave_type (self, NULL))) {
			g_object_set (s_con, NM_SETTING_CONNECTION_SLAVE_TYPE, slave_type, NULL);
			return TRUE;
		}
	}
	return FALSE;
}

static gboolean
_normalize_ip_config (NMConnection *self, GHashTable *parameters)
{
	NMSettingConnection *s_con = nm_connection_get_setting_connection (self);
	const char *default_ip4_method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;
	const char *default_ip6_method = NULL;
	NMSettingIPConfig *s_ip4, *s_ip6;
	NMSetting *setting;

	if (parameters)
		default_ip6_method = g_hash_table_lookup (parameters, NM_CONNECTION_NORMALIZE_PARAM_IP6_CONFIG_METHOD);
	if (!default_ip6_method)
		default_ip6_method = NM_SETTING_IP6_CONFIG_METHOD_AUTO;

	s_ip4 = nm_connection_get_setting_ip4_config (self);
	s_ip6 = nm_connection_get_setting_ip6_config (self);

	if (nm_setting_connection_get_master (s_con)) {
		/* Slave connections don't have IP configuration. */

		if (s_ip4)
			nm_connection_remove_setting (self, NM_TYPE_SETTING_IP4_CONFIG);

		if (s_ip6)
			nm_connection_remove_setting (self, NM_TYPE_SETTING_IP6_CONFIG);

		return s_ip4 || s_ip6;
	} else {
		/* Ensure all non-slave connections have IP4 and IP6 settings objects. If no
		 * IP6 setting was specified, then assume that means IP6 config is allowed
		 * to fail. But if no IP4 setting was specified, assume the caller was just
		 * being lazy.
		 */
		if (!s_ip4) {
			setting = nm_setting_ip4_config_new ();

			g_object_set (setting,
			              NM_SETTING_IP_CONFIG_METHOD, default_ip4_method,
			              NULL);
			nm_connection_add_setting (self, setting);
		}
		if (!s_ip6) {
			setting = nm_setting_ip6_config_new ();

			g_object_set (setting,
			              NM_SETTING_IP_CONFIG_METHOD, default_ip6_method,
			              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
			              NULL);
			nm_connection_add_setting (self, setting);
		}
		return !s_ip4 || !s_ip6;
	}
}

static gboolean
_normalize_infiniband_mtu (NMConnection *self, GHashTable *parameters)
{
	NMSettingInfiniband *s_infini = nm_connection_get_setting_infiniband (self);

	if (s_infini) {
		const char *transport_mode = nm_setting_infiniband_get_transport_mode (s_infini);
		guint32 max_mtu = 0;

		if (transport_mode) {
			if (!strcmp (transport_mode, "datagram"))
				max_mtu = 2044;
			else if (!strcmp (transport_mode, "connected"))
				max_mtu = 65520;

			if (max_mtu && nm_setting_infiniband_get_mtu (s_infini) > max_mtu) {
				g_object_set (s_infini, NM_SETTING_INFINIBAND_MTU, max_mtu, NULL);
				return TRUE;
			}
		}
	}
	return FALSE;
}

static gboolean
_normalize_bond_mode (NMConnection *self, GHashTable *parameters)
{
	NMSettingBond *s_bond = nm_connection_get_setting_bond (self);

	/* Convert mode from numeric to string notation */
	if (s_bond) {
		const char *mode = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_MODE);
		int mode_int = nm_utils_bond_mode_string_to_int (mode);

		if (mode_int != -1) {
			const char *mode_new = nm_utils_bond_mode_int_to_string (mode_int);
			if (g_strcmp0 (mode_new, mode) != 0) {
				nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MODE, mode_new);
				return TRUE;
			}
		}
	}
	return FALSE;
}

/**
 * nm_connection_verify:
 * @connection: the #NMConnection to verify
 * @error: location to store error, or %NULL
 *
 * Validates the connection and all its settings.  Each setting's properties
 * have allowed values, and some values are dependent on other values.  For
 * example, if a Wi-Fi connection is security enabled, the #NMSettingWireless
 * setting object's 'security' property must contain the setting name of the
 * #NMSettingWirelessSecurity object, which must also be present in the
 * connection for the connection to be valid.  As another example, the
 * #NMSettingWired object's 'mac-address' property must be a validly formatted
 * MAC address.  The returned #GError contains information about which
 * setting and which property failed validation, and how it failed validation.
 *
 * Returns: %TRUE if the connection is valid, %FALSE if it is not
 **/
gboolean
nm_connection_verify (NMConnection *connection, GError **error)
{
	NMSettingVerifyResult result;

	result = _nm_connection_verify (connection, error);

	/* we treat normalizable connections as valid. */
	if (result == NM_SETTING_VERIFY_NORMALIZABLE)
		g_clear_error (error);

	return result == NM_SETTING_VERIFY_SUCCESS || result == NM_SETTING_VERIFY_NORMALIZABLE;
}

static NMSettingVerifyResult
_nm_connection_verify (NMConnection *connection, GError **error)
{
	NMConnectionPrivate *priv;
	NMSettingConnection *s_con;
	NMSettingIPConfig *s_ip4, *s_ip6;
	GHashTableIter iter;
	gpointer value;
	GSList *all_settings = NULL, *setting_i;
	NMSettingVerifyResult success = NM_SETTING_VERIFY_ERROR;
	GError *normalizable_error = NULL;
	NMSettingVerifyResult normalizable_error_type = NM_SETTING_VERIFY_SUCCESS;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NM_SETTING_VERIFY_ERROR);
	g_return_val_if_fail (!error || !*error, NM_SETTING_VERIFY_ERROR);

	priv = NM_CONNECTION_GET_PRIVATE (connection);

	/* First, make sure there's at least 'connection' setting */
	s_con = nm_connection_get_setting_connection (connection);
	if (!s_con) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_MISSING_SETTING,
		                     _("setting not found"));
		g_prefix_error (error, "%s: ", NM_SETTING_CONNECTION_SETTING_NAME);
		goto EXIT;
	}

	/* Build up the list of settings */
	g_hash_table_iter_init (&iter, priv->settings);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		/* Order NMSettingConnection so that it will be verified first.
		 * The reason is, that errors in this setting might be more fundamental
		 * and should be checked and reported with higher priority.
		 */
		if (value == s_con)
			all_settings = g_slist_append (all_settings, value);
		else
			all_settings = g_slist_prepend (all_settings, value);
	}
	all_settings = g_slist_reverse (all_settings);

	/* Now, run the verify function of each setting */
	for (setting_i = all_settings; setting_i; setting_i = setting_i->next) {
		GError *verify_error = NULL;
		NMSettingVerifyResult verify_result;

		/* verify all settings. We stop if we find the first non-normalizable
		 * @NM_SETTING_VERIFY_ERROR. If we find normalizable errors we continue
		 * but remember the error to return it to the user.
		 * @NM_SETTING_VERIFY_NORMALIZABLE_ERROR has a higher priority then
		 * @NM_SETTING_VERIFY_NORMALIZABLE, so, if we encounter such an error type,
		 * we remember it instead (to return it as output).
		 **/
		verify_result = _nm_setting_verify (NM_SETTING (setting_i->data), connection, &verify_error);
		if (verify_result == NM_SETTING_VERIFY_NORMALIZABLE ||
		    verify_result == NM_SETTING_VERIFY_NORMALIZABLE_ERROR) {
			if (   verify_result == NM_SETTING_VERIFY_NORMALIZABLE_ERROR
			    && normalizable_error_type == NM_SETTING_VERIFY_NORMALIZABLE) {
				/* NORMALIZABLE_ERROR has higher priority. */
				g_clear_error (&normalizable_error);
			}
			if (!normalizable_error) {
				g_propagate_error (&normalizable_error, verify_error);
				verify_error = NULL;
				normalizable_error_type = verify_result;
			}
		} else if (verify_result != NM_SETTING_VERIFY_SUCCESS) {
			g_propagate_error (error, verify_error);
			g_slist_free (all_settings);
			g_return_val_if_fail (verify_result == NM_SETTING_VERIFY_ERROR, success);
			goto EXIT;
		}
		g_clear_error (&verify_error);
	}
	g_slist_free (all_settings);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	s_ip6 = nm_connection_get_setting_ip6_config (connection);

	if (nm_setting_connection_get_master (s_con)) {
		if ((normalizable_error_type == NM_SETTING_VERIFY_SUCCESS ||
		    (normalizable_error_type == NM_SETTING_VERIFY_NORMALIZABLE))  && (s_ip4 || s_ip6)) {
			g_clear_error (&normalizable_error);
			g_set_error_literal (&normalizable_error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_SETTING,
			                     _("setting not allowed in slave connection"));
			g_prefix_error (&normalizable_error, "%s: ",
			                s_ip4 ? NM_SETTING_IP4_CONFIG_SETTING_NAME : NM_SETTING_IP6_CONFIG_SETTING_NAME);
			/* having a slave with IP config *was* and is a verify() error. */
			normalizable_error_type = NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
		}
	} else {
		if (normalizable_error_type == NM_SETTING_VERIFY_SUCCESS && (!s_ip4 || !s_ip6)) {
			g_set_error_literal (&normalizable_error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_MISSING_SETTING,
			                     _("setting is required for non-slave connections"));
			g_prefix_error (&normalizable_error, "%s: ",
			                !s_ip4 ? NM_SETTING_IP4_CONFIG_SETTING_NAME : NM_SETTING_IP6_CONFIG_SETTING_NAME);
			/* having a master without IP config was not a verify() error, accept
			 * it for backward compatibility. */
			normalizable_error_type = NM_SETTING_VERIFY_NORMALIZABLE;
		}
	}

	if (normalizable_error_type != NM_SETTING_VERIFY_SUCCESS) {
		g_propagate_error (error, normalizable_error);
		normalizable_error = NULL;
		success = normalizable_error_type;
	} else
		success = NM_SETTING_VERIFY_SUCCESS;

EXIT:
	g_clear_error (&normalizable_error);
	return success;
}

/**
 * nm_connection_normalize:
 * @connection: the #NMConnection to normalize
 * @parameters: (allow-none) (element-type utf8 gpointer): a #GHashTable with
 * normalization parameters to allow customization of the normalization by providing
 * specific arguments. Unknown arguments will be ignored and the default will be
 * used. The keys must be strings, hashed by g_str_hash() and g_str_equal() functions.
 * The values are opaque and depend on the parameter name.
 * @modified: (out) (allow-none): outputs whether any settings were modified.
 * @error: location to store error, or %NULL. Contains the reason,
 * why the connection is invalid, if the function returns an error.
 *
 * Does some basic normalization and fixup of well known inconsistencies
 * and deprecated fields. If the connection was modified in any way,
 * the output parameter @modified is set %TRUE.
 *
 * Finally the connection will be verified and %TRUE returns if the connection
 * is valid. As this function only performs some specific normalization steps
 * it cannot repair all connections. If the connection has errors that
 * cannot be normalized, the connection will not be modified.
 *
 * Returns: %TRUE if the connection is valid, %FALSE if it is not
 **/
gboolean
nm_connection_normalize (NMConnection *connection,
                         GHashTable *parameters,
                         gboolean *modified,
                         GError **error)
{
	NMSettingVerifyResult success;
	gboolean was_modified = FALSE;
	GError *normalizable_error = NULL;

	success = _nm_connection_verify (connection, &normalizable_error);

	if (success == NM_SETTING_VERIFY_ERROR ||
	    success == NM_SETTING_VERIFY_SUCCESS) {
		if (normalizable_error)
			g_propagate_error (error, normalizable_error);
		if (modified)
			*modified = FALSE;
		if (success == NM_SETTING_VERIFY_ERROR && error && !*error) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_FAILED,
			                     _("Unexpected failure to verify the connection"));
			g_return_val_if_reached (FALSE);
		}
		return success == NM_SETTING_VERIFY_SUCCESS;
	}
	g_assert (success == NM_SETTING_VERIFY_NORMALIZABLE || success == NM_SETTING_VERIFY_NORMALIZABLE_ERROR);
	g_clear_error (&normalizable_error);

	/* Try to perform all kind of normalizations on the settings to fix it.
	 * We only do this, after verifying that the connection contains no un-normalizable
	 * errors, because in that case we rather fail without touching the settings. */

	was_modified |= _normalize_connection_uuid (connection);
	was_modified |= _normalize_connection_type (connection);
	was_modified |= _normalize_connection_slave_type (connection);
	was_modified |= _normalize_ip_config (connection, parameters);
	was_modified |= _normalize_infiniband_mtu (connection, parameters);
	was_modified |= _normalize_bond_mode (connection, parameters);

	/* Verify anew. */
	success = _nm_connection_verify (connection, error);

	if (modified)
		*modified = was_modified;

	if (success != NM_SETTING_VERIFY_SUCCESS) {
		/* we would expect, that after normalization, the connection can be verified.
		 * Also treat NM_SETTING_VERIFY_NORMALIZABLE as failure, because there is something
		 * odd going on. */
		if (error && !*error) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_FAILED,
			                     _("Unexpected failure to normalize the connection"));
		}
		g_return_val_if_reached (FALSE);
	}

	/* we would expect, that the connection was modified during normalization. */
	g_return_val_if_fail (was_modified, TRUE);

	return TRUE;
}

/**
 * nm_connection_update_secrets:
 * @connection: the #NMConnection
 * @setting_name: the setting object name to which the secrets apply
 * @secrets: a #GVariant of secrets, of type %NM_VARIANT_TYPE_CONNECTION
 *   or %NM_VARIANT_TYPE_SETTING
 * @error: location to store error, or %NULL
 *
 * Update the specified setting's secrets, given a dictionary of secrets
 * intended for that setting (deserialized from D-Bus for example).  Will also
 * extract the given setting's secrets hash if given a connection dictionary.
 * If @setting_name is %NULL, expects a fully serialized #NMConnection as
 * returned by nm_connection_to_dbus() and will update all secrets from all
 * settings contained in @secrets.
 *
 * Returns: %TRUE if the secrets were successfully updated, %FALSE if the update
 * failed (tried to update secrets for a setting that doesn't exist, etc)
 **/
gboolean
nm_connection_update_secrets (NMConnection *connection,
                              const char *setting_name,
                              GVariant *secrets,
                              GError **error)
{
	NMSetting *setting;
	gboolean success = TRUE, updated = FALSE;
	GVariant *setting_dict = NULL;
	GVariantIter iter;
	const char *key;
	gboolean full_connection;
	int success_detail;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (   g_variant_is_of_type (secrets, NM_VARIANT_TYPE_SETTING)
	                      || g_variant_is_of_type (secrets, NM_VARIANT_TYPE_CONNECTION), FALSE);
	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	full_connection = g_variant_is_of_type (secrets, NM_VARIANT_TYPE_CONNECTION);
	g_return_val_if_fail (setting_name != NULL || full_connection, FALSE);

	/* Empty @secrets means success */
	if (g_variant_n_children (secrets) == 0)
		return TRUE;

	if (setting_name) {
		/* Update just one setting's secrets */
		setting = nm_connection_get_setting_by_name (connection, setting_name);
		if (!setting) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_SETTING_NOT_FOUND,
			                     setting_name);
			return FALSE;
		}

		if (full_connection) {
			setting_dict = g_variant_lookup_value (secrets, setting_name, NM_VARIANT_TYPE_SETTING);
			if (!setting_dict) {
				/* The connection dictionary didn't contain any secrets for
				 * @setting_name; just return success.
				 */
				return TRUE;
			}
		}

		g_signal_handlers_block_by_func (setting, (GCallback) setting_changed_cb, connection);
		success_detail = _nm_setting_update_secrets (setting,
		                                             setting_dict ? setting_dict : secrets,
		                                             error);
		g_signal_handlers_unblock_by_func (setting, (GCallback) setting_changed_cb, connection);

		g_clear_pointer (&setting_dict, g_variant_unref);

		if (success_detail == NM_SETTING_UPDATE_SECRET_ERROR)
			return FALSE;
		if (success_detail == NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED)
			updated = TRUE;
	} else {
		/* check first, whether all the settings exist... */
		g_variant_iter_init (&iter, secrets);
		while (g_variant_iter_next (&iter, "{&s@a{sv}}", &key, NULL)) {
			setting = nm_connection_get_setting_by_name (connection, key);
			if (!setting) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_SETTING_NOT_FOUND,
				                     key);
				return FALSE;
			}
		}

		/* Update each setting with any secrets from the connection dictionary */
		g_variant_iter_init (&iter, secrets);
		while (g_variant_iter_next (&iter, "{&s@a{sv}}", &key, &setting_dict)) {
			/* Update the secrets for this setting */
			setting = nm_connection_get_setting_by_name (connection, key);

			g_signal_handlers_block_by_func (setting, (GCallback) setting_changed_cb, connection);
			success_detail = _nm_setting_update_secrets (setting, setting_dict, error);
			g_signal_handlers_unblock_by_func (setting, (GCallback) setting_changed_cb, connection);

			g_variant_unref (setting_dict);

			if (success_detail == NM_SETTING_UPDATE_SECRET_ERROR) {
				success = FALSE;
				break;
			}
			if (success_detail == NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED)
				updated = TRUE;
		}
	}

	if (updated) {
		g_signal_emit (connection, signals[SECRETS_UPDATED], 0, setting_name);
		g_signal_emit (connection, signals[CHANGED], 0);
	}

	return success;
}

/**
 * nm_connection_need_secrets:
 * @connection: the #NMConnection
 * @hints: (out) (element-type utf8) (allow-none) (transfer container):
 *   the address of a pointer to a #GPtrArray, initialized to %NULL, which on
 *   return points to an allocated #GPtrArray containing the property names of
 *   secrets of the #NMSetting which may be required; the caller owns the array
 *   and must free the array itself with g_ptr_array_free(), but not free its
 *   elements
 *
 * Returns the name of the first setting object in the connection which would
 * need secrets to make a successful connection.  The returned hints are only
 * intended as a guide to what secrets may be required, because in some
 * circumstances, there is no way to conclusively determine exactly which
 * secrets are needed.
 *
 * Returns: the setting name of the #NMSetting object which has invalid or
 *   missing secrets
 **/
const char *
nm_connection_need_secrets (NMConnection *connection,
                            GPtrArray **hints)
{
	NMConnectionPrivate *priv;
	GHashTableIter hiter;
	GSList *settings = NULL;
	GSList *iter;
	const char *name = NULL;
	NMSetting *setting;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	if (hints)
		g_return_val_if_fail (*hints == NULL, NULL);

	priv = NM_CONNECTION_GET_PRIVATE (connection);

	/* Get list of settings in priority order */
	g_hash_table_iter_init (&hiter, priv->settings);
	while (g_hash_table_iter_next (&hiter, NULL, (gpointer) &setting))
		settings = g_slist_insert_sorted (settings, setting, _nm_setting_compare_priority);

	for (iter = settings; iter; iter = g_slist_next (iter)) {
		GPtrArray *secrets;

		setting = NM_SETTING (iter->data);
		secrets = _nm_setting_need_secrets (setting);
		if (secrets) {
			if (hints)
				*hints = secrets;
			else
				g_ptr_array_free (secrets, TRUE);

			name = nm_setting_get_name (setting);
			break;
		}
	}

	g_slist_free (settings);
	return name;
}

/**
 * nm_connection_clear_secrets:
 * @connection: the #NMConnection
 *
 * Clears and frees any secrets that may be stored in the connection, to avoid
 * keeping secret data in memory when not needed.
 **/
void
nm_connection_clear_secrets (NMConnection *connection)
{
	GHashTableIter iter;
	NMSetting *setting;
	gboolean changed = FALSE;

	g_return_if_fail (NM_IS_CONNECTION (connection));

	g_hash_table_iter_init (&iter, NM_CONNECTION_GET_PRIVATE (connection)->settings);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &setting)) {
		g_signal_handlers_block_by_func (setting, (GCallback) setting_changed_cb, connection);
		changed |= _nm_setting_clear_secrets (setting);
		g_signal_handlers_unblock_by_func (setting, (GCallback) setting_changed_cb, connection);
	}

	g_signal_emit (connection, signals[SECRETS_CLEARED], 0);
	if (changed)
		g_signal_emit (connection, signals[CHANGED], 0);
}

/**
 * nm_connection_clear_secrets_with_flags:
 * @connection: the #NMConnection
 * @func: (scope call): function to be called to determine whether a
 *     specific secret should be cleared or not
 * @user_data: caller-supplied data passed to @func
 *
 * Clears and frees secrets determined by @func.
 **/
void
nm_connection_clear_secrets_with_flags (NMConnection *connection,
                                        NMSettingClearSecretsWithFlagsFn func,
                                        gpointer user_data)
{
	GHashTableIter iter;
	NMSetting *setting;
	gboolean changed = FALSE;

	g_return_if_fail (NM_IS_CONNECTION (connection));

	g_hash_table_iter_init (&iter, NM_CONNECTION_GET_PRIVATE (connection)->settings);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &setting)) {
		g_signal_handlers_block_by_func (setting, (GCallback) setting_changed_cb, connection);
		changed |= _nm_setting_clear_secrets_with_flags (setting, func, user_data);
		g_signal_handlers_unblock_by_func (setting, (GCallback) setting_changed_cb, connection);
	}

	g_signal_emit (connection, signals[SECRETS_CLEARED], 0);
	if (changed)
		g_signal_emit (connection, signals[CHANGED], 0);
}

/**
 * nm_connection_to_dbus:
 * @connection: the #NMConnection
 * @flags: serialization flags, e.g. %NM_CONNECTION_SERIALIZE_ALL
 *
 * Converts the #NMConnection into a #GVariant of type
 * %NM_VARIANT_TYPE_CONNECTION describing the connection, suitable for
 * marshalling over D-Bus or otherwise serializing.
 *
 * Returns: (transfer none): a new floating #GVariant describing the connection,
 * its settings, and each setting's properties.
 **/
GVariant *
nm_connection_to_dbus (NMConnection *connection,
                       NMConnectionSerializationFlags flags)
{
	NMConnectionPrivate *priv;
	GVariantBuilder builder;
	GHashTableIter iter;
	gpointer key, data;
	GVariant *setting_dict, *ret;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	priv = NM_CONNECTION_GET_PRIVATE (connection);

	g_variant_builder_init (&builder, NM_VARIANT_TYPE_CONNECTION);

	/* Add each setting's hash to the main hash */
	g_hash_table_iter_init (&iter, priv->settings);
	while (g_hash_table_iter_next (&iter, &key, &data)) {
		NMSetting *setting = NM_SETTING (data);

		setting_dict = _nm_setting_to_dbus (setting, connection, flags);
		if (setting_dict)
			g_variant_builder_add (&builder, "{s@a{sv}}", nm_setting_get_name (setting), setting_dict);
	}

	ret = g_variant_builder_end (&builder);

	/* Don't send empty hashes */
	if (g_variant_n_children (ret) == 0) {
		g_variant_unref (ret);
		ret = NULL;
	}

	return ret;
}

/**
 * nm_connection_is_type:
 * @connection: the #NMConnection
 * @type: a setting name to check the connection's type against (like
 * %NM_SETTING_WIRELESS_SETTING_NAME or %NM_SETTING_WIRED_SETTING_NAME)
 *
 * A convenience function to check if the given @connection is a particular
 * type (ie wired, Wi-Fi, ppp, etc). Checks the #NMSettingConnection:type
 * property of the connection and matches that against @type.
 *
 * Returns: %TRUE if the connection is of the given @type, %FALSE if not
 **/
gboolean
nm_connection_is_type (NMConnection *connection, const char *type)
{
	NMSettingConnection *s_con;
	const char *type2;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (type != NULL, FALSE);

	s_con = nm_connection_get_setting_connection (connection);
	if (!s_con)
		return FALSE;

	type2 = nm_setting_connection_get_connection_type (s_con);

	return (g_strcmp0 (type2, type) == 0);
}

static int
_for_each_sort (NMSetting **p_a, NMSetting **p_b, void *unused)
{
	NMSetting *a = *p_a;
	NMSetting *b = *p_b;
	int c;

	c = _nm_setting_compare_priority (a, b);
	if (c != 0)
		return c;
	return strcmp (nm_setting_get_name (a), nm_setting_get_name (b));
}

/**
 * nm_connection_for_each_setting_value:
 * @connection: the #NMConnection
 * @func: (scope call): user-supplied function called for each setting's property
 * @user_data: user data passed to @func at each invocation
 *
 * Iterates over the properties of each #NMSetting object in the #NMConnection,
 * calling the supplied user function for each property.
 **/
void
nm_connection_for_each_setting_value (NMConnection *connection,
                                      NMSettingValueIterFn func,
                                      gpointer user_data)
{
	NMConnectionPrivate *priv;
	gs_free NMSetting **arr_free = NULL;
	NMSetting *arr_temp[20], **arr;
	GHashTableIter iter;
	gpointer value;
	guint i, size;

	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (func != NULL);

	priv = NM_CONNECTION_GET_PRIVATE (connection);

	size = g_hash_table_size (priv->settings);
	if (!size)
		return;

	if (size > G_N_ELEMENTS (arr_temp))
		arr = arr_free = g_new (NMSetting *, size);
	else
		arr = arr_temp;

	g_hash_table_iter_init (&iter, priv->settings);
	for (i = 0; g_hash_table_iter_next (&iter, NULL, &value); i++)
		arr[i] = NM_SETTING (value);
	g_assert (i == size);

	/* sort the settings. This has an effect on the order in which keyfile
	 * prints them. */
	if (size > 1)
		g_qsort_with_data (arr, size, sizeof (NMSetting *), (GCompareDataFunc) _for_each_sort, NULL);

	for (i = 0; i < size; i++)
		nm_setting_enumerate_values (arr[i], func, user_data);
}

/**
 * nm_connection_dump:
 * @connection: the #NMConnection
 *
 * Print the connection to stdout.  For debugging purposes ONLY, should NOT
 * be used for serialization of the connection or machine-parsed in any way. The
 * output format is not guaranteed to be stable and may change at any time.
 **/
void
nm_connection_dump (NMConnection *connection)
{
	GHashTableIter iter;
	NMSetting *setting;
	const char *setting_name;
	char *str;

	if (!connection)
		return;

	g_hash_table_iter_init (&iter, NM_CONNECTION_GET_PRIVATE (connection)->settings);
	while (g_hash_table_iter_next (&iter, (gpointer) &setting_name, (gpointer) &setting)) {
		str = nm_setting_to_string (setting);
		g_print ("%s\n", str);
		g_free (str);
	}
}

/**
 * nm_connection_set_path:
 * @connection: the #NMConnection
 * @path: the D-Bus path of the connection as given by the settings service
 * which provides the connection
 *
 * Sets the D-Bus path of the connection.  This property is not serialized, and
 * is only for the reference of the caller.  Sets the #NMConnection:path
 * property.
 **/
void
nm_connection_set_path (NMConnection *connection, const char *path)
{
	NMConnectionPrivate *priv;

	g_return_if_fail (NM_IS_CONNECTION (connection));

	priv = NM_CONNECTION_GET_PRIVATE (connection);

	g_free (priv->path);
	priv->path = NULL;

	if (path)
		priv->path = g_strdup (path);
}

/**
 * nm_connection_get_path:
 * @connection: the #NMConnection
 *
 * Returns the connection's D-Bus path.
 *
 * Returns: the D-Bus path of the connection, previously set by a call to
 * nm_connection_set_path().
 **/
const char *
nm_connection_get_path (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return NM_CONNECTION_GET_PRIVATE (connection)->path;
}

/**
 * nm_connection_get_interface_name:
 * @connection: The #NMConnection
 *
 * Returns the interface name as stored in NMSettingConnection:interface_name.
 * If the connection contains no NMSettingConnection, it will return %NULL.
 *
 * For hardware devices and software devices created outside of NetworkManager,
 * this name is used to match the device. for software devices created by
 * NetworkManager, this is the name of the created interface.
 *
 * Returns: Name of the kernel interface or %NULL
 */
const char *
nm_connection_get_interface_name (NMConnection *connection)
{
	NMSettingConnection *s_con;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	s_con = nm_connection_get_setting_connection (connection);

	return s_con ? nm_setting_connection_get_interface_name (s_con) : NULL;
}

gboolean
_nm_connection_verify_required_interface_name (NMConnection *connection,
                                               GError **error)
{
	const char *interface_name;

	interface_name = nm_connection_get_interface_name (connection);
	if (interface_name)
		return TRUE;

	g_set_error_literal (error,
	                     NM_CONNECTION_ERROR,
	                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
	                     _("property is missing"));
	g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_INTERFACE_NAME);
	return FALSE;
}

/**
 * nm_connection_get_uuid:
 * @connection: the #NMConnection
 *
 * A shortcut to return the UUID from the connection's #NMSettingConnection.
 *
 * Returns: the UUID from the connection's 'connection' setting
 **/
const char *
nm_connection_get_uuid (NMConnection *connection)
{
	NMSettingConnection *s_con;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	s_con = nm_connection_get_setting_connection (connection);
	if (!s_con)
		return NULL;

	return nm_setting_connection_get_uuid (s_con);
}

/**
 * nm_connection_get_id:
 * @connection: the #NMConnection
 *
 * A shortcut to return the ID from the connection's #NMSettingConnection.
 *
 * Returns: the ID from the connection's 'connection' setting
 **/
const char *
nm_connection_get_id (NMConnection *connection)
{
	NMSettingConnection *s_con;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	s_con = nm_connection_get_setting_connection (connection);
	g_return_val_if_fail (s_con != NULL, NULL);

	return nm_setting_connection_get_id (s_con);
}

/**
 * nm_connection_get_connection_type:
 * @connection: the #NMConnection
 *
 * A shortcut to return the type from the connection's #NMSettingConnection.
 *
 * Returns: the type from the connection's 'connection' setting
 **/
const char *
nm_connection_get_connection_type (NMConnection *connection)
{
	NMSettingConnection *s_con;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	s_con = nm_connection_get_setting_connection (connection);
	g_return_val_if_fail (s_con != NULL, NULL);

	return nm_setting_connection_get_connection_type (s_con);
}

/**
 * nm_connection_is_virtual:
 * @connection: an #NMConnection
 *
 * Checks if @connection refers to a virtual device (and thus can potentially be
 * activated even if the device it refers to doesn't exist).
 *
 * Returns: whether @connection refers to a virtual device
 */
gboolean
nm_connection_is_virtual (NMConnection *connection)
{
	const char *type;

	type = nm_connection_get_connection_type (connection);
	g_return_val_if_fail (type != NULL, FALSE);

	if (   !strcmp (type, NM_SETTING_BOND_SETTING_NAME)
	    || !strcmp (type, NM_SETTING_TEAM_SETTING_NAME)
	    || !strcmp (type, NM_SETTING_BRIDGE_SETTING_NAME)
	    || !strcmp (type, NM_SETTING_VLAN_SETTING_NAME))
		return TRUE;

	if (!strcmp (type, NM_SETTING_INFINIBAND_SETTING_NAME)) {
		NMSettingInfiniband *s_ib;

		s_ib = nm_connection_get_setting_infiniband (connection);
		g_return_val_if_fail (s_ib != NULL, FALSE);
		return nm_setting_infiniband_get_virtual_interface_name (s_ib) != NULL;
	}

	return FALSE;
}

/**
 * nm_connection_get_virtual_device_description:
 * @connection: an #NMConnection for a virtual device type
 *
 * Returns the name that nm_device_disambiguate_names() would
 * return for the virtual device that would be created for @connection.
 * Eg, "VLAN (eth1.1)".
 *
 * Returns: (transfer full): the name of @connection's device,
 *   or %NULL if @connection is not a virtual connection type
 */
char *
nm_connection_get_virtual_device_description (NMConnection *connection)
{
	const char *type;
	const char *iface = NULL, *display_type = NULL;

	iface = nm_connection_get_interface_name (connection);

	type = nm_connection_get_connection_type (connection);
	g_return_val_if_fail (type != NULL, FALSE);

	if (!strcmp (type, NM_SETTING_BOND_SETTING_NAME))
		display_type = _("Bond");
	else if (!strcmp (type, NM_SETTING_TEAM_SETTING_NAME))
		display_type = _("Team");
	else if (!strcmp (type, NM_SETTING_BRIDGE_SETTING_NAME))
		display_type = _("Bridge");
	else if (!strcmp (type, NM_SETTING_VLAN_SETTING_NAME))
		display_type = _("VLAN");
	else if (!strcmp (type, NM_SETTING_INFINIBAND_SETTING_NAME)) {
		display_type = _("InfiniBand");
		iface = nm_setting_infiniband_get_virtual_interface_name (nm_connection_get_setting_infiniband (connection));
	}

	if (!iface || !display_type)
		return NULL;

	return g_strdup_printf ("%s (%s)", display_type, iface);
}

/*************************************************************/

/**
 * nm_connection_get_setting_802_1x:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSetting8021x the connection might contain.
 *
 * Returns: (transfer none): an #NMSetting8021x if the connection contains one, otherwise %NULL
 **/
NMSetting8021x *
nm_connection_get_setting_802_1x (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSetting8021x *) nm_connection_get_setting (connection, NM_TYPE_SETTING_802_1X);
}

/**
 * nm_connection_get_setting_bluetooth:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingBluetooth the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingBluetooth if the connection contains one, otherwise %NULL
 **/
NMSettingBluetooth *
nm_connection_get_setting_bluetooth (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingBluetooth *) nm_connection_get_setting (connection, NM_TYPE_SETTING_BLUETOOTH);
}

/**
 * nm_connection_get_setting_bond:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingBond the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingBond if the connection contains one, otherwise %NULL
 **/
NMSettingBond *
nm_connection_get_setting_bond (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingBond *) nm_connection_get_setting (connection, NM_TYPE_SETTING_BOND);
}

/**
 * nm_connection_get_setting_team:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingTeam the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingTeam if the connection contains one, otherwise %NULL
 **/
NMSettingTeam *
nm_connection_get_setting_team (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingTeam *) nm_connection_get_setting (connection, NM_TYPE_SETTING_TEAM);
}

/**
 * nm_connection_get_setting_team_port:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingTeamPort the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingTeamPort if the connection contains one, otherwise %NULL
 **/
NMSettingTeamPort *
nm_connection_get_setting_team_port (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingTeamPort *) nm_connection_get_setting (connection, NM_TYPE_SETTING_TEAM_PORT);
}

/**
 * nm_connection_get_setting_bridge:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingBridge the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingBridge if the connection contains one, otherwise %NULL
 **/
NMSettingBridge *
nm_connection_get_setting_bridge (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingBridge *) nm_connection_get_setting (connection, NM_TYPE_SETTING_BRIDGE);
}

/**
 * nm_connection_get_setting_cdma:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingCdma the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingCdma if the connection contains one, otherwise %NULL
 **/
NMSettingCdma *
nm_connection_get_setting_cdma (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingCdma *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CDMA);
}

/**
 * nm_connection_get_setting_connection:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingConnection the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingConnection if the connection contains one, otherwise %NULL
 **/
NMSettingConnection *
nm_connection_get_setting_connection (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
}

/**
 * nm_connection_get_setting_dcb:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingDcb the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingDcb if the connection contains one, otherwise NULL
 **/
NMSettingDcb *
nm_connection_get_setting_dcb (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingDcb *) nm_connection_get_setting (connection, NM_TYPE_SETTING_DCB);
}

/**
 * nm_connection_get_setting_generic:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingGeneric the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingGeneric if the connection contains one, otherwise NULL
 **/
NMSettingGeneric *
nm_connection_get_setting_generic (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingGeneric *) nm_connection_get_setting (connection, NM_TYPE_SETTING_GENERIC);
}

/**
 * nm_connection_get_setting_gsm:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingGsm the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingGsm if the connection contains one, otherwise %NULL
 **/
NMSettingGsm *
nm_connection_get_setting_gsm (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingGsm *) nm_connection_get_setting (connection, NM_TYPE_SETTING_GSM);
}

/**
 * nm_connection_get_setting_infiniband:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingInfiniband the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingInfiniband if the connection contains one, otherwise %NULL
 **/
NMSettingInfiniband *
nm_connection_get_setting_infiniband (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingInfiniband *) nm_connection_get_setting (connection, NM_TYPE_SETTING_INFINIBAND);
}

/**
 * nm_connection_get_setting_ip4_config:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingIP4Config the connection might contain.
 *
 * Note that it returns the value as type #NMSettingIPConfig, since the vast
 * majority of IPv4-setting-related methods are on that type, not
 * #NMSettingIP4Config.
 *
 * Returns: (type NMSettingIP4Config) (transfer none): an #NMSettingIP4Config if the
 * connection contains one, otherwise %NULL
 **/
NMSettingIPConfig *
nm_connection_get_setting_ip4_config (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingIPConfig *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
}

/**
 * nm_connection_get_setting_ip6_config:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingIP6Config the connection might contain.
 *
 * Note that it returns the value as type #NMSettingIPConfig, since the vast
 * majority of IPv6-setting-related methods are on that type, not
 * #NMSettingIP6Config.
 *
 * Returns: (type NMSettingIP6Config) (transfer none): an #NMSettingIP6Config if the
 * connection contains one, otherwise %NULL
 **/
NMSettingIPConfig *
nm_connection_get_setting_ip6_config (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingIPConfig *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP6_CONFIG);
}

/**
 * nm_connection_get_setting_olpc_mesh:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingOlpcMesh the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingOlpcMesh if the connection contains one, otherwise %NULL
 **/
NMSettingOlpcMesh *
nm_connection_get_setting_olpc_mesh (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingOlpcMesh *) nm_connection_get_setting (connection, NM_TYPE_SETTING_OLPC_MESH);
}

/**
 * nm_connection_get_setting_ppp:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingPpp the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingPpp if the connection contains one, otherwise %NULL
 **/
NMSettingPpp *
nm_connection_get_setting_ppp (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingPpp *) nm_connection_get_setting (connection, NM_TYPE_SETTING_PPP);
}

/**
 * nm_connection_get_setting_pppoe:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingPppoe the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingPppoe if the connection contains one, otherwise %NULL
 **/
NMSettingPppoe *
nm_connection_get_setting_pppoe (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingPppoe *) nm_connection_get_setting (connection, NM_TYPE_SETTING_PPPOE);
}

/**
 * nm_connection_get_setting_serial:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingSerial the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingSerial if the connection contains one, otherwise %NULL
 **/
NMSettingSerial *
nm_connection_get_setting_serial (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingSerial *) nm_connection_get_setting (connection, NM_TYPE_SETTING_SERIAL);
}

/**
 * nm_connection_get_setting_vpn:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingVpn the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingVpn if the connection contains one, otherwise %NULL
 **/
NMSettingVpn *
nm_connection_get_setting_vpn (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingVpn *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
}

/**
 * nm_connection_get_setting_wimax:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingWimax the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingWimax if the connection contains one, otherwise %NULL
 **/
NMSettingWimax *
nm_connection_get_setting_wimax (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingWimax *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIMAX);
}

/**
 * nm_connection_get_setting_wired:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingWired the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingWired if the connection contains one, otherwise %NULL
 **/
NMSettingWired *
nm_connection_get_setting_wired (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingWired *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED);
}

/**
 * nm_connection_get_setting_adsl:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingAdsl the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingAdsl if the connection contains one, otherwise %NULL
 **/
NMSettingAdsl *
nm_connection_get_setting_adsl (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingAdsl *) nm_connection_get_setting (connection, NM_TYPE_SETTING_ADSL);
}

/**
 * nm_connection_get_setting_wireless:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingWireless the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingWireless if the connection contains one, otherwise %NULL
 **/
NMSettingWireless *
nm_connection_get_setting_wireless (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingWireless *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS);
}

/**
 * nm_connection_get_setting_wireless_security:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingWirelessSecurity the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingWirelessSecurity if the connection contains one, otherwise %NULL
 **/
NMSettingWirelessSecurity *
nm_connection_get_setting_wireless_security (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingWirelessSecurity *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY);
}

/**
 * nm_connection_get_setting_bridge_port:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingBridgePort the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingBridgePort if the connection contains one, otherwise %NULL
 **/
NMSettingBridgePort *
nm_connection_get_setting_bridge_port (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingBridgePort *) nm_connection_get_setting (connection, NM_TYPE_SETTING_BRIDGE_PORT);
}

/**
 * nm_connection_get_setting_vlan:
 * @connection: the #NMConnection
 *
 * A shortcut to return any #NMSettingVlan the connection might contain.
 *
 * Returns: (transfer none): an #NMSettingVlan if the connection contains one, otherwise %NULL
 **/
NMSettingVlan *
nm_connection_get_setting_vlan (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	return (NMSettingVlan *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VLAN);
}

/*************************************************************/

static void
nm_connection_private_free (NMConnectionPrivate *priv)
{
	NMConnection *self = priv->self;

	g_hash_table_foreach_remove (priv->settings, _setting_release, self);
	g_hash_table_destroy (priv->settings);
	g_free (priv->path);

	g_slice_free (NMConnectionPrivate, priv);
}

static NMConnectionPrivate *
nm_connection_get_private (NMConnection *connection)
{
	NMConnectionPrivate *priv;

	priv = g_object_get_data (G_OBJECT (connection), "NMConnectionPrivate");
	if (!priv) {
		priv = g_slice_new0 (NMConnectionPrivate);
		g_object_set_data_full (G_OBJECT (connection), "NMConnectionPrivate",
		                        priv, (GDestroyNotify) nm_connection_private_free);

		priv->self = connection;
		priv->settings = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);
	}

	return priv;
}

static void
nm_connection_default_init (NMConnectionInterface *iface)
{
	/* Signals */

	/**
	 * NMConnection::secrets-updated:
	 * @connection: the object on which the signal is emitted
	 * @setting_name: the setting name of the #NMSetting for which secrets were
	 * updated
	 *
	 * The ::secrets-updated signal is emitted when the secrets of a setting
	 * have been changed.
	 */
	signals[SECRETS_UPDATED] =
		g_signal_new (NM_CONNECTION_SECRETS_UPDATED,
		              NM_TYPE_CONNECTION,
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMConnectionInterface, secrets_updated),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__STRING,
		              G_TYPE_NONE, 1,
		              G_TYPE_STRING);

	/**
	 * NMConnection::secrets-cleared:
	 * @connection: the object on which the signal is emitted
	 *
	 * The ::secrets-cleared signal is emitted when the secrets of a connection
	 * are cleared.
	 */
	signals[SECRETS_CLEARED] =
		g_signal_new (NM_CONNECTION_SECRETS_CLEARED,
		              NM_TYPE_CONNECTION,
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMConnectionInterface, secrets_cleared),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	/**
	 * NMConnection::changed:
	 * @connection: the object on which the signal is emitted
	 *
	 * The ::changed signal is emitted when any property of any property
	 * (including secrets) of any setting of the connection is modified,
	 * or when settings are added or removed.
	 */
	signals[CHANGED] =
		g_signal_new (NM_CONNECTION_CHANGED,
		              NM_TYPE_CONNECTION,
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMConnectionInterface, changed),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);
}
