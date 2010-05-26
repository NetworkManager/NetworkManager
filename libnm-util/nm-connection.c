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
 * (C) Copyright 2007 - 2009 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include <string.h>
#include "nm-connection.h"
#include "nm-utils.h"
#include "nm-utils-private.h"

#include "nm-setting-8021x.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-connection.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-ppp.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-vpn.h"
#include "nm-setting-olpc-mesh.h"

#include "nm-setting-serial.h"
#include "nm-setting-gsm.h"
#include "nm-setting-cdma.h"

/**
 * SECTION:nm-connection
 * @short_description: Describes a connection to specific network or provider
 * @include: nm-connection.h
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
 * Most connections also have a %NMConnectionScope; a connection will be
 * provided over D-Bus either by the user settings service
 * (org.freedesktop.NetworkManagerUserSettings) running in an active user
 * session, or by the system-wide system settings service
 * (org.freedesktop.NetworkManagerSystemSettings) which provides  connections
 * for all users.
 */

/**
 * nm_connection_error_quark:
 *
 * Registers an error quark for #NMConnection if necessary.
 *
 * Returns: the error quark used for #NMConnection errors.
 **/
GQuark
nm_connection_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-connection-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_connection_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			ENUM_ENTRY (NM_CONNECTION_ERROR_UNKNOWN, "UnknownError"),
			ENUM_ENTRY (NM_CONNECTION_ERROR_CONNECTION_SETTING_NOT_FOUND, "ConnectionSettingNotFound"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMConnectionError", values);
	}
	return etype;
}

typedef struct {
	GHashTable *settings;

	/* Type of the connection (system or user) */
	NMConnectionScope scope;

	/* D-Bus path of the connection, if any */
	char *path;
} NMConnectionPrivate;

#define NM_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CONNECTION, NMConnectionPrivate))

G_DEFINE_TYPE (NMConnection, nm_connection, G_TYPE_OBJECT)

enum {
	PROP_0,
	PROP_SCOPE,
	PROP_PATH,

	LAST_PROP
};

enum {
	SECRETS_UPDATED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static GHashTable *registered_settings = NULL;

#define DEFAULT_MAP_SIZE 15

static struct SettingInfo {
	const char *name;
	GType type;
	guint32 priority;
	GQuark error_quark;
} default_map[DEFAULT_MAP_SIZE] = { { NULL } };

static void
setting_register (const char *name, GType type)
{
	g_return_if_fail (name != NULL);
	g_return_if_fail (G_TYPE_IS_INSTANTIATABLE (type));

	if (G_UNLIKELY (!registered_settings)) {
		registered_settings = g_hash_table_new_full (g_str_hash, g_str_equal, 
		                                             (GDestroyNotify) g_free,
		                                             (GDestroyNotify) g_free);
	}

	if (g_hash_table_lookup (registered_settings, name))
		g_warning ("Already have a creator function for '%s', overriding", name);

	g_hash_table_insert (registered_settings, g_strdup (name), g_strdup (g_type_name (type)));
}

#if UNUSED
static void
setting_unregister (const char *name)
{
	if (registered_settings)
		g_hash_table_remove (registered_settings, name);
}
#endif

static void
register_one_setting (const char *name, GType type, GQuark error_quark, guint32 priority)
{
	static guint32 i = 0;

	g_return_if_fail (i < DEFAULT_MAP_SIZE);
	g_return_if_fail (default_map[i].name == NULL);

	default_map[i].name = name;
	default_map[i].type = type;
	default_map[i].error_quark = error_quark;
	default_map[i].priority = priority;
	i++;

	setting_register (name, type);
}

static void
register_default_settings (void)
{
	_nm_utils_register_value_transformations ();

	if (G_LIKELY (default_map[0].name))
		return;

	register_one_setting (NM_SETTING_CONNECTION_SETTING_NAME,
	                      NM_TYPE_SETTING_CONNECTION,
	                      NM_SETTING_CONNECTION_ERROR,
	                      0);

	register_one_setting (NM_SETTING_WIRED_SETTING_NAME,
	                      NM_TYPE_SETTING_WIRED,
	                      NM_SETTING_WIRED_ERROR,
	                      1);

	register_one_setting (NM_SETTING_WIRELESS_SETTING_NAME,
	                      NM_TYPE_SETTING_WIRELESS,
	                      NM_SETTING_WIRELESS_ERROR,
	                      1);

	register_one_setting (NM_SETTING_OLPC_MESH_SETTING_NAME,
	                      NM_TYPE_SETTING_OLPC_MESH,
	                      NM_SETTING_OLPC_MESH_ERROR,
	                      1);

	register_one_setting (NM_SETTING_GSM_SETTING_NAME,
	                      NM_TYPE_SETTING_GSM,
	                      NM_SETTING_GSM_ERROR,
	                      1);

	register_one_setting (NM_SETTING_CDMA_SETTING_NAME,
	                      NM_TYPE_SETTING_CDMA,
	                      NM_SETTING_CDMA_ERROR,
	                      1);

	register_one_setting (NM_SETTING_BLUETOOTH_SETTING_NAME,
			      NM_TYPE_SETTING_BLUETOOTH,
			      NM_SETTING_BLUETOOTH_ERROR,
			      1);

	register_one_setting (NM_SETTING_WIRELESS_SECURITY_SETTING_NAME,
	                      NM_TYPE_SETTING_WIRELESS_SECURITY,
	                      NM_SETTING_WIRELESS_SECURITY_ERROR,
	                      2);

	register_one_setting (NM_SETTING_SERIAL_SETTING_NAME,
	                      NM_TYPE_SETTING_SERIAL,
	                      NM_SETTING_SERIAL_ERROR,
	                      2);

	register_one_setting (NM_SETTING_PPP_SETTING_NAME,
	                      NM_TYPE_SETTING_PPP,
	                      NM_SETTING_PPP_ERROR,
	                      3);

	register_one_setting (NM_SETTING_PPPOE_SETTING_NAME,
	                      NM_TYPE_SETTING_PPPOE,
	                      NM_SETTING_PPPOE_ERROR,
	                      3);

	register_one_setting (NM_SETTING_802_1X_SETTING_NAME,
	                      NM_TYPE_SETTING_802_1X,
	                      NM_SETTING_802_1X_ERROR,
	                      3);

	register_one_setting (NM_SETTING_VPN_SETTING_NAME,
	                      NM_TYPE_SETTING_VPN,
	                      NM_SETTING_VPN_ERROR,
	                      4);

	register_one_setting (NM_SETTING_IP4_CONFIG_SETTING_NAME,
	                      NM_TYPE_SETTING_IP4_CONFIG,
	                      NM_SETTING_IP4_CONFIG_ERROR,
	                      6);

	register_one_setting (NM_SETTING_IP6_CONFIG_SETTING_NAME,
	                      NM_TYPE_SETTING_IP6_CONFIG,
	                      NM_SETTING_IP6_CONFIG_ERROR,
	                      6);

	/* Be sure to update DEFAULT_MAP_SIZE if you add another setting!! */
}

static guint32
get_priority_for_setting_type (GType type)
{
	int i;

	for (i = 0; default_map[i].name; i++) {
		if (default_map[i].type == type)
			return default_map[i].priority;
	}

	return G_MAXUINT32;
}

/**
 * nm_connection_lookup_setting_type:
 * @name: a setting name
 *
 * Returns the #GType of the setting's class for a given setting name.
 *
 * Returns: the #GType of the setting's class
 **/
GType
nm_connection_lookup_setting_type (const char *name)
{
	char *type_name;
	GType type;

	g_return_val_if_fail (name != NULL, G_TYPE_NONE);

	if (!registered_settings)
		register_default_settings ();

	type_name = (char *) g_hash_table_lookup (registered_settings, name);
	if (type_name) {
		type = g_type_from_name (type_name);
		if (!type)
			g_warning ("Can not get type for '%s'.", type_name);
	} else {
		type = 0;
		g_warning ("Unknown setting '%s'", name);
	}

	return type;
}

/**
 * nm_connection_lookup_setting_type_by_quark:
 * @error_quark: a setting error quark
 *
 * Returns the #GType of the setting's class for a given setting error quark.
 * Useful for figuring out which setting a returned error is for.
 *
 * Returns: the #GType of the setting's class
 **/
GType
nm_connection_lookup_setting_type_by_quark (GQuark error_quark)
{
	int i;

	for (i = 0; default_map[i].name; i++) {
		if (default_map[i].error_quark == error_quark)
			return default_map[i].type;
	}

	return G_TYPE_INVALID;
}

/**
 * nm_connection_create_setting:
 * @name: a setting name
 *
 * Create a new #NMSetting object of the desired type, given a setting name.
 *
 * Returns: the new setting object, or NULL if the setting name was unknown
 **/
NMSetting *
nm_connection_create_setting (const char *name)
{
	GType type;
	NMSetting *setting = NULL;

	g_return_val_if_fail (name != NULL, NULL);

	type = nm_connection_lookup_setting_type (name);
	if (type)
		setting = (NMSetting *) g_object_new (type, NULL);

	return setting;
}

static void
parse_one_setting (gpointer key, gpointer value, gpointer user_data)
{
	NMConnection *connection = (NMConnection *) user_data;
	GType type;
	NMSetting *setting = NULL;

	type = nm_connection_lookup_setting_type ((char *) key);
	if (type)
		setting = nm_setting_new_from_hash (type, (GHashTable *) value);
	if (setting)
		nm_connection_add_setting (connection, setting);
}

/**
 * nm_connection_add_setting:
 * @connection: a #NMConnection
 * @setting: the #NMSetting to add to the connection object
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

	g_hash_table_insert (NM_CONNECTION_GET_PRIVATE (connection)->settings,
					 g_strdup (G_OBJECT_TYPE_NAME (setting)), setting);
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
	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (g_type_is_a (setting_type, NM_TYPE_SETTING));

	g_hash_table_remove (NM_CONNECTION_GET_PRIVATE (connection)->settings, g_type_name (setting_type));
}

/**
 * nm_connection_get_setting:
 * @connection: a #NMConnection
 * @setting_type: the #GType of the setting object to return
 *
 * Gets the #NMSetting with the given #GType, if one has been previously added
 * to the #NMConnection.
 *
 * Returns: the #NMSetting, or NULL if no setting of that type was previously
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
 * the the #NMConnection.
 *
 * Returns: the #NMSetting, or NULL if no setting with that name was previously
 * added to the #NMConnection
 **/
NMSetting *
nm_connection_get_setting_by_name (NMConnection *connection, const char *name)
{
	GType type;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (name != NULL, NULL);

	type = nm_connection_lookup_setting_type (name);

	return type ? nm_connection_get_setting (connection, type) : NULL;
}

/**
 * nm_connection_replace_settings:
 * @connection: a #NMConnection
 * @new_settings: a #GHashTable of settings
 * @error: location to store error, or %NULL
 *
 * Returns: %TRUE if the settings were valid and added to the connection, %FALSE
 * if they were not
 **/
gboolean
nm_connection_replace_settings (NMConnection *connection,
                                GHashTable *new_settings,
                                GError **error)
{
	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (new_settings != NULL, FALSE);
	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	g_hash_table_remove_all (NM_CONNECTION_GET_PRIVATE (connection)->settings);
	g_hash_table_foreach (new_settings, parse_one_setting, connection);

	return nm_connection_verify (connection, error);
}

typedef struct {
	NMConnection *other;
	gboolean failed;
	NMSettingCompareFlags flags;
} CompareConnectionInfo;

static void
compare_one_setting (gpointer key, gpointer value, gpointer user_data)
{
	NMSetting *setting = (NMSetting *) value;
	CompareConnectionInfo *info = (CompareConnectionInfo *) user_data;
	NMSetting *other_setting;

	if (info->failed)
		return;

	other_setting = nm_connection_get_setting (info->other, G_OBJECT_TYPE (setting));
	if (other_setting)
		info->failed = nm_setting_compare (setting, other_setting, info->flags) ? FALSE : TRUE;
	else
		info->failed = TRUE;
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
	NMConnectionPrivate *priv;
	CompareConnectionInfo info = { b, FALSE, flags };

	if (!a && !b)
		return TRUE;

	if (!a || !b)
		return FALSE;

	priv = NM_CONNECTION_GET_PRIVATE (a);
	g_hash_table_foreach (priv->settings, compare_one_setting, &info);
	if (info.failed == FALSE) {
		/* compare A to B, then if that is the same compare B to A to ensure
		 * that keys that are in B but not A will make the comparison fail.
		 */
		info.failed = FALSE;
		info.other = a;
		priv = NM_CONNECTION_GET_PRIVATE (b);
		g_hash_table_foreach (priv->settings, compare_one_setting, &info);
	}

	return info.failed ? FALSE : TRUE;
}

/**
 * nm_connection_verify:
 * @connection: the #NMConnection to verify
 * @error: location to store error, or %NULL
 *
 * Validates the connection and all its settings.  Each setting's properties
 * have allowed values, and some values are dependent on other values.  For
 * example, if a WiFi connection is security enabled, the #NMSettingWireless
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
	NMConnectionPrivate *priv;
	NMSetting *s_con;
	GHashTableIter iter;
	gpointer value;
	GSList *all_settings = NULL;
	gboolean success = TRUE;

	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	if (!NM_IS_CONNECTION (connection)) {
		g_set_error (error,
				NM_SETTING_CONNECTION_ERROR,
				NM_SETTING_CONNECTION_ERROR_UNKNOWN,
				"invalid connection; failed verification");
		g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	}

	priv = NM_CONNECTION_GET_PRIVATE (connection);

	/* First, make sure there's at least 'connection' setting */
	s_con = nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	if (!s_con) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_CONNECTION_SETTING_NOT_FOUND,
		             "connection setting not found");
		return FALSE;
	}

	/* Build up the list of settings */
	g_hash_table_iter_init (&iter, priv->settings);
	while (g_hash_table_iter_next (&iter, NULL, &value))
		all_settings = g_slist_append (all_settings, value);

	/* Now, run the verify function of each setting */
	g_hash_table_iter_init (&iter, priv->settings);
	while (g_hash_table_iter_next (&iter, NULL, &value) && success)
		success = nm_setting_verify (NM_SETTING (value), all_settings, error);

	g_slist_free (all_settings);
	return success;
}

/**
 * nm_connection_update_secrets:
 * @connection: the #NMConnection
 * @setting_name: the setting object name to which the secrets apply
 * @secrets: a #GHashTable mapping string:#GValue of setting property names and
 * secrets
 * @error: location to store error, or %NULL
 *
 * Update the specified setting's secrets, given a hash table of secrets
 * intended for that setting (deserialized from D-Bus for example).
 * 
 * Returns: %TRUE if the secrets were successfully updated and the connection
 * is valid, %FALSE on failure or if the setting was never added to the connection
 **/
gboolean
nm_connection_update_secrets (NMConnection *connection,
                              const char *setting_name,
                              GHashTable *secrets,
                              GError **error)
{
	NMSetting *setting;
	gboolean success;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (setting_name != NULL, FALSE);
	g_return_val_if_fail (secrets != NULL, FALSE);
	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	setting = nm_connection_get_setting (connection, nm_connection_lookup_setting_type (setting_name));
	if (!setting) {
		g_set_error (error, NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_CONNECTION_SETTING_NOT_FOUND,
		             "%s", setting_name);
		return FALSE;
	}

	success = nm_setting_update_secrets (setting, secrets, error);
	if (success)
		g_signal_emit (connection, signals[SECRETS_UPDATED], 0, setting_name);
	return success;
}

static gint
setting_priority_compare (gconstpointer a, gconstpointer b)
{
	guint32 prio_a, prio_b;

	prio_a = get_priority_for_setting_type (G_OBJECT_TYPE (NM_SETTING (a)));
	prio_b = get_priority_for_setting_type (G_OBJECT_TYPE (NM_SETTING (b)));

	if (prio_a < prio_b)
		return -1;
	else if (prio_a == prio_b)
		return 0;
	return 1;
}

static void
add_setting_to_list (gpointer key, gpointer data, gpointer user_data)
{
	GSList **list = (GSList **) user_data;

	*list = g_slist_insert_sorted (*list, NM_SETTING (data), setting_priority_compare);
}

/**
 * nm_connection_need_secrets:
 * @connection: the #NMConnection
 * @hints: the address of a pointer to a #GPtrArray, initialized to NULL, which
 * on return points to an allocated #GPtrArray containing the property names of
 * secrets of the #NMSetting which may be required; the caller owns the array
 * and must free the each array element with g_free(), as well as the array
 * itself with g_ptr_array_free()
 *
 * Returns the name of the first setting object in the connection which would
 * need secrets to make a successful connection.  The returned hints are only
 * intended as a guide to what secrets may be required, because in some
 * circumstances, there is no way to conclusively determine exactly which
 * secrets are needed.
 *
 * Returns: the setting name of the #NMSetting object which has invalid or
 * missing secrets
 **/
const char *
nm_connection_need_secrets (NMConnection *connection,
                            GPtrArray **hints)
{
	NMConnectionPrivate *priv;
	GSList *settings = NULL;
	GSList *iter;
	char *name = NULL;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	if (hints)
		g_return_val_if_fail (*hints == NULL, NULL);

	priv = NM_CONNECTION_GET_PRIVATE (connection);

	/* Get list of settings in priority order */
	g_hash_table_foreach (priv->settings, add_setting_to_list, &settings);

	for (iter = settings; iter; iter = g_slist_next (iter)) {
		NMSetting *setting = NM_SETTING (iter->data);
		GPtrArray *secrets;

		// FIXME: do something with requested secrets rather than asking for
		// all of them.  Maybe make secrets a hash table mapping
		// settings name :: [list of secrets key names].
		secrets = nm_setting_need_secrets (setting);
		if (secrets) {
			if (hints)
				*hints = secrets;
			else
				g_ptr_array_free (secrets, TRUE);

			name = (char *) nm_setting_get_name (setting);
			break;
		}
	}

	g_slist_free (settings);
	return name;
}

static void
clear_setting_secrets (gpointer key, gpointer data, gpointer user_data)
{
	nm_setting_clear_secrets (NM_SETTING (data));
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
	NMConnectionPrivate *priv;

	g_return_if_fail (NM_IS_CONNECTION (connection));

	priv = NM_CONNECTION_GET_PRIVATE (connection);
	g_hash_table_foreach (priv->settings, clear_setting_secrets, NULL);
}

static void
add_one_setting_to_hash (gpointer key, gpointer data, gpointer user_data)
{
	NMSetting *setting = (NMSetting *) data;
	GHashTable *connection_hash = (GHashTable *) user_data;
	GHashTable *setting_hash;

	g_return_if_fail (setting != NULL);
	g_return_if_fail (connection_hash != NULL);

	setting_hash = nm_setting_to_hash (setting);
	if (setting_hash)
		g_hash_table_insert (connection_hash,
							 g_strdup (nm_setting_get_name (setting)),
							 setting_hash);
}

/**
 * nm_connection_to_hash:
 * @connection: the #NMConnection
 *
 * Converts the #NMConnection into a #GHashTable describing the connection,
 * suitable for marshalling over D-Bus or serializing.  The hash table mapping
 * is string:#GHashTable with each element in the returned hash representing
 * a #NMSetting object.  The keys are setting object names, and the values
 * are #GHashTables mapping string:GValue, each of which represents the
 * properties of the #NMSetting object.
 *
 * Returns: a new #GHashTable describing the connection, its settings, and
 * each setting's properties.  The caller owns the hash table and must unref
 * the hash table with g_hash_table_unref() when it is no longer needed.
 **/
GHashTable *
nm_connection_to_hash (NMConnection *connection)
{
	NMConnectionPrivate *priv;
	GHashTable *connection_hash;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	connection_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
									 g_free, (GDestroyNotify) g_hash_table_destroy);

	priv = NM_CONNECTION_GET_PRIVATE (connection);
	g_hash_table_foreach (priv->settings, add_one_setting_to_hash, connection_hash);

	/* Don't send empty hashes */
	if (g_hash_table_size (connection_hash) < 1) {
		g_hash_table_destroy (connection_hash);
		connection_hash = NULL;
	}

	return connection_hash;
}

typedef struct ForEachValueInfo {
	NMSettingValueIterFn func;
	gpointer user_data;
} ForEachValueInfo;

static void
for_each_setting (gpointer key, gpointer value, gpointer user_data)
{
	ForEachValueInfo *info = (ForEachValueInfo *) user_data;

	nm_setting_enumerate_values (NM_SETTING (value), info->func, info->user_data);
}

/**
 * nm_connection_for_each_setting_value:
 * @connection: the #NMConnection
 * @func: user-supplied function called for each setting's property
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
	ForEachValueInfo *info;

	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (func != NULL);

	priv = NM_CONNECTION_GET_PRIVATE (connection);

	info = g_slice_new0 (ForEachValueInfo);
	if (!info) {
		g_warning ("Not enough memory to enumerate values.");
		return;
	}
	info->func = func;
	info->user_data = user_data;

	g_hash_table_foreach (priv->settings, for_each_setting, info);

	g_slice_free (ForEachValueInfo, info);
}

static void
dump_setting (gpointer key, gpointer value, gpointer user_data)
{
	char *str;

	str = nm_setting_to_string (NM_SETTING (value));
	g_print ("%s\n", str);
	g_free (str);
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
	g_return_if_fail (NM_IS_CONNECTION (connection));

	g_hash_table_foreach (NM_CONNECTION_GET_PRIVATE (connection)->settings, dump_setting, NULL);
}

/**
 * nm_connection_set_scope:
 * @connection: the #NMConnection
 * @scope: the scope of the connection
 *
 * Sets the scope of the connection.  This property is not serialized, and is
 * only for the reference of the caller.  A connection may have no scope
 * (internal, temporary connections), "system" scope (provided by the system
 * settings service), or "user" scope, provided by a user settings service.  The
 * creator of the #NMConnection object is responsible for setting the
 * connection's scope if needed.  Sets the #NMConnection:scope property.
 **/
void
nm_connection_set_scope (NMConnection *connection, NMConnectionScope scope)
{
	g_return_if_fail (NM_IS_CONNECTION (connection));

	NM_CONNECTION_GET_PRIVATE (connection)->scope = scope;
}

/**
 * nm_connection_get_scope:
 * @connection: the #NMConnection
 *
 * Returns the connection scope.
 *
 * Returns: the scope of the connection, previously set by a call to
 * nm_connection_set_scope().
 **/
NMConnectionScope
nm_connection_get_scope (NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NM_CONNECTION_SCOPE_UNKNOWN);

	return NM_CONNECTION_GET_PRIVATE (connection)->scope;
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

	if (priv->path) {
		g_free (priv->path);
		priv->path = NULL;
	}

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
 * nm_connection_new:
 *
 * Creates a new #NMConnection object with no #NMSetting objects.
 *
 * Returns: the new empty #NMConnection object
 **/
NMConnection *
nm_connection_new (void)
{
	GObject *object;

	if (!registered_settings)
		register_default_settings ();

	object = g_object_new (NM_TYPE_CONNECTION, NULL);

	return NM_CONNECTION (object);
}

/**
 * nm_connection_new_from_hash:
 * @hash: the #GHashTable describing the connection
 * @error: on unsuccessful return, an error
 *
 * Creates a new #NMConnection from a hash table describing the connection.  See
 * nm_connection_to_hash() for a description of the expected hash table.
 *
 * Returns: the new #NMConnection object, populated with settings created
 * from the values in the hash table, or NULL if the connection failed to
 * validate
 **/
NMConnection *
nm_connection_new_from_hash (GHashTable *hash, GError **error)
{
	NMConnection *connection;

	g_return_val_if_fail (hash != NULL, NULL);

	connection = nm_connection_new ();
	g_hash_table_foreach (hash, parse_one_setting, connection);

	if (!nm_connection_verify (connection, error)) {
		g_object_unref (connection);
		return NULL;
	}

	return connection;
}

static void
duplicate_cb (gpointer key, gpointer value, gpointer user_data)
{
	nm_connection_add_setting (NM_CONNECTION (user_data), nm_setting_duplicate (NM_SETTING (value)));
}

/**
 * nm_connection_duplicate:
 * @connection: the #NMConnection to duplicate
 *
 * Duplicates a #NMConnection.
 *
 * Returns: a new #NMConnection containing the same settings and properties
 * as the source #NMConnection
 **/
NMConnection *
nm_connection_duplicate (NMConnection *connection)
{
	NMConnection *dup;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	dup = nm_connection_new ();
	nm_connection_set_scope (dup, nm_connection_get_scope (connection));
	nm_connection_set_path (dup, nm_connection_get_path (connection));
	g_hash_table_foreach (NM_CONNECTION_GET_PRIVATE (connection)->settings, duplicate_cb, dup);

	return dup;
}

static void
nm_connection_init (NMConnection *connection)
{
	NMConnectionPrivate *priv = NM_CONNECTION_GET_PRIVATE (connection);

	priv->settings = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
}

static void
finalize (GObject *object)
{
	NMConnection *connection = NM_CONNECTION (object);
	NMConnectionPrivate *priv = NM_CONNECTION_GET_PRIVATE (connection);

	g_hash_table_destroy (priv->settings);
	priv->settings = NULL;

	g_free (priv->path);
	priv->path = NULL;

	G_OBJECT_CLASS (nm_connection_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMConnection *connection = NM_CONNECTION (object);

	switch (prop_id) {
	case PROP_SCOPE:
		nm_connection_set_scope (connection, g_value_get_uint (value));
		break;
	case PROP_PATH:
		nm_connection_set_path (connection, g_value_get_string (value));
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
	NMConnection *connection = NM_CONNECTION (object);

	switch (prop_id) {
	case PROP_SCOPE:
		g_value_set_uint (value, nm_connection_get_scope (connection));
		break;
	case PROP_PATH:
		g_value_set_string (value, nm_connection_get_path (connection));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_connection_class_init (NMConnectionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMConnectionPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* Properties */

	/**
	 * NMConnection:scope:
	 *
	 * The connection's scope, used only by the calling process as a record
	 * of which settings service the connection is provided by.  One of the
	 * NM_CONNECTION_SCOPE_* defines.
	 **/
	g_object_class_install_property
		(object_class, PROP_SCOPE,
		 g_param_spec_uint (NM_CONNECTION_SCOPE,
						    "Scope",
						    "Scope",
						    NM_CONNECTION_SCOPE_UNKNOWN,
						    NM_CONNECTION_SCOPE_USER,
						    NM_CONNECTION_SCOPE_UNKNOWN,
						    G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

	/**
	 * NMConnection:path:
	 *
	 * The connection's D-Bus path, used only by the calling process as a record
	 * of the D-Bus path of the connection as provided by a settings service.
	 **/
	g_object_class_install_property
		(object_class, PROP_PATH,
		 g_param_spec_string (NM_CONNECTION_PATH,
						  "Path",
						  "Path",
						  NULL,
						  G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

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
		g_signal_new ("secrets-updated",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMConnectionClass, secrets_updated),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__STRING,
					  G_TYPE_NONE, 1,
					  G_TYPE_STRING);
}

