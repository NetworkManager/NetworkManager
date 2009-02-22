/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#include <NetworkManager.h>
#include <nm-utils.h>
#include <nm-setting-connection.h>
#include "nm-settings.h"
#include "nm-dbus-glib-types.h"


#define NM_TYPE_SETTINGS_ERROR (nm_settings_error_get_type ()) 

/**
 * nm_settings_error_quark:
 *
 * Setting error quark.
 *
 * Returns: the setting error quark
 **/
GQuark
nm_settings_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-settings-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GType
nm_settings_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* The connection was invalid. */
			ENUM_ENTRY (NM_SETTINGS_ERROR_INVALID_CONNECTION, "InvalidConnection"),
			/* The connection is read-only; modifications are not allowed. */
			ENUM_ENTRY (NM_SETTINGS_ERROR_READ_ONLY_CONNECTION, "ReadOnlyConnection"),
			/* A bug in the settings service caused the error. */
			ENUM_ENTRY (NM_SETTINGS_ERROR_INTERNAL_ERROR, "InternalError"),
			/* Retrieval or request of secrets failed. */
			ENUM_ENTRY (NM_SETTINGS_ERROR_SECRETS_UNAVAILABLE, "SecretsUnavailable"),
			/* The request for secrets was canceled. */
			ENUM_ENTRY (NM_SETTINGS_ERROR_SECRETS_REQUEST_CANCELED, "SecretsRequestCanceled"),
			{ 0, 0, 0 },
		};
		etype = g_enum_register_static ("NMSettingsError", values);
	}
	return etype;
}


/*
 * NMSettings implementation
 */

static gboolean impl_settings_list_connections (NMSettings *settings, GPtrArray **connections, GError **error);

#include "nm-settings-glue.h"

#define SETTINGS_CLASS(o) (NM_SETTINGS_CLASS (G_OBJECT_GET_CLASS (o)))

G_DEFINE_TYPE (NMSettings, nm_settings, G_TYPE_OBJECT)

enum {
	S_NEW_CONNECTION,

	S_LAST_SIGNAL
};

static guint settings_signals[S_LAST_SIGNAL] = { 0 };

static gboolean
impl_settings_list_connections (NMSettings *settings, GPtrArray **connections, GError **error)
{
	GSList *list, *iter;

	g_return_val_if_fail (NM_IS_SETTINGS (settings), FALSE);

	list = nm_settings_list_connections (settings);

	*connections = g_ptr_array_new ();
	for (iter = list; iter; iter = iter->next) {
		NMConnection *connection = nm_exported_connection_get_connection (NM_EXPORTED_CONNECTION (iter->data));

		g_ptr_array_add (*connections, g_strdup (nm_connection_get_path (connection)));
	}

	g_slist_free (list);

	return TRUE;
}

static void
nm_settings_init (NMSettings *settings)
{
}

static void
nm_settings_finalize (GObject *object)
{
	G_OBJECT_CLASS (nm_settings_parent_class)->finalize (object);
}

static void
nm_settings_class_init (NMSettingsClass *settings_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (settings_class);

	/* virtual methods */
	object_class->finalize = nm_settings_finalize;

	settings_class->list_connections = NULL;

	/* signals */

	/**
	 * NMSettings::new-connection:
	 * @setting: the setting that received the signal
	 * @connection: the new #NMExportedConnection
	 *
	 * Notifies that a new exported connection is added.
	 **/
	settings_signals[S_NEW_CONNECTION] =
		g_signal_new ("new-connection",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (NMSettingsClass, new_connection),
			      NULL, NULL,
			      g_cclosure_marshal_VOID__OBJECT,
			      G_TYPE_NONE, 1,
			      G_TYPE_OBJECT);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (settings_class),
					 &dbus_glib_nm_settings_object_info);

	dbus_g_error_domain_register (NM_SETTINGS_ERROR, NULL, NM_TYPE_SETTINGS_ERROR);
}

/**
 * nm_settings_list_connections:
 * @settings: 
 *
 * Lists all the available connections.
 *
 * Returns: the #GSList containing #NMExportedConnection<!-- -->s
 **/
GSList *
nm_settings_list_connections (NMSettings *settings)
{
	GSList *list = NULL;

	g_return_val_if_fail (NM_IS_SETTINGS (settings), NULL);

	if (SETTINGS_CLASS (settings)->list_connections)
		list = SETTINGS_CLASS (settings)->list_connections (settings);
	else
		g_warning ("Missing implementation for Settings::list_connections.");

	return list;
}

void
nm_settings_signal_new_connection (NMSettings *settings, NMExportedConnection *connection)
{
	g_return_if_fail (NM_IS_SETTINGS (settings));
	g_return_if_fail (NM_IS_EXPORTED_CONNECTION (connection));

	g_signal_emit (settings, settings_signals[S_NEW_CONNECTION], 0, connection);
}

/*
 * NMExportedConnection implementation
 */

static gboolean impl_exported_connection_get_settings (NMExportedConnection *connection,
						       GHashTable **settings,
						       GError **error);

static gboolean impl_exported_connection_update (NMExportedConnection *connection,
									    GHashTable *new_settings,
									    DBusGMethodInvocation *context);

static gboolean impl_exported_connection_delete (NMExportedConnection *connection,
									    DBusGMethodInvocation *context);

static void impl_exported_connection_get_secrets (NMExportedConnection *connection,
                                                  const gchar *setting_name,
                                                  const gchar **hints,
                                                  gboolean request_new,
                                                  DBusGMethodInvocation *context);

#include "nm-exported-connection-glue.h"

#define EXPORTED_CONNECTION_CLASS(o) (NM_EXPORTED_CONNECTION_CLASS (G_OBJECT_GET_CLASS (o)))

G_DEFINE_TYPE (NMExportedConnection, nm_exported_connection, G_TYPE_OBJECT)

enum {
	EC_UPDATED,
	EC_REMOVED,

	EC_LAST_SIGNAL
};

static guint connection_signals[EC_LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_CONNECTION,

	LAST_PROP
};

typedef struct {
	NMConnection *wrapped;
} NMExportedConnectionPrivate;

#define NM_EXPORTED_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                               NM_TYPE_EXPORTED_CONNECTION, \
                                               NMExportedConnectionPrivate))

NMExportedConnection *
nm_exported_connection_new (NMConnection *wrapped)
{
	g_return_val_if_fail (NM_IS_CONNECTION (wrapped), NULL);

	return (NMExportedConnection *) g_object_new (NM_TYPE_EXPORTED_CONNECTION,
						      NM_EXPORTED_CONNECTION_CONNECTION, wrapped,
						      NULL);
}

static GHashTable *
real_get_settings (NMExportedConnection *exported)
{
	NMExportedConnectionPrivate *priv;
	NMConnection *no_secrets;
	GHashTable *hash;

	g_return_val_if_fail (NM_IS_EXPORTED_CONNECTION (exported), NULL);

	priv = NM_EXPORTED_CONNECTION_GET_PRIVATE (exported);

	/* Secrets should *never* be returned by the GetSettings method, they
	 * get returned by the GetSecrets method which can be better
	 * protected against leakage of secrets to unprivileged callers.
	 */
	no_secrets = nm_connection_duplicate (priv->wrapped);
	nm_connection_clear_secrets (no_secrets);
	hash = nm_connection_to_hash (no_secrets);
	g_object_unref (G_OBJECT (no_secrets));
	return hash;
}

static gboolean
impl_exported_connection_get_settings (NMExportedConnection *connection,
                                       GHashTable **settings,
                                       GError **error)
{
	NMExportedConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_EXPORTED_CONNECTION (connection), FALSE);

	priv = NM_EXPORTED_CONNECTION_GET_PRIVATE (connection);

	if (!EXPORTED_CONNECTION_CLASS (connection)->get_settings)
		*settings = real_get_settings (connection);
	else
		*settings = EXPORTED_CONNECTION_CLASS (connection)->get_settings (connection);

	return TRUE;
}

static gboolean
impl_exported_connection_update (NMExportedConnection *connection,
						   GHashTable *new_settings,
						   DBusGMethodInvocation *context)
{
	GError *err = NULL;
	NMConnection *wrapped;
	gboolean success = FALSE;

	/* Read-only connections obviously cannot be changed */
	wrapped = nm_exported_connection_get_connection (connection);
	if (wrapped) {
		NMSettingConnection *s_con;

		s_con = (NMSettingConnection *) nm_connection_get_setting (wrapped, NM_TYPE_SETTING_CONNECTION);
		if (s_con && nm_setting_connection_get_read_only (s_con)) {
			g_set_error (&err, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_READ_ONLY_CONNECTION,
			             "%s.%d - Read-only connections may not be modified.",
			             __FILE__, __LINE__);
		}
	}

	if (!err) {
		/* A hack to share the DBusGMethodInvocation with the possible overriders of connection::update */
		g_object_set_data (G_OBJECT (connection), NM_EXPORTED_CONNECTION_DBUS_METHOD_INVOCATION, context);
		success = nm_exported_connection_update (connection, new_settings, &err);
		g_object_set_data (G_OBJECT (connection), NM_EXPORTED_CONNECTION_DBUS_METHOD_INVOCATION, NULL);
	}

	if (success) {
		dbus_g_method_return (context);
	} else {
		dbus_g_method_return_error (context, err);
		g_error_free (err);
	}

	return success;
}

static gboolean
impl_exported_connection_delete (NMExportedConnection *connection,
						   DBusGMethodInvocation *context)
{
	GError *err = NULL;
	NMConnection *wrapped;
	gboolean success = FALSE;

	/* Read-only connections obviously cannot be changed */
	wrapped = nm_exported_connection_get_connection (connection);
	if (wrapped) {
		NMSettingConnection *s_con;

		s_con = (NMSettingConnection *) nm_connection_get_setting (wrapped, NM_TYPE_SETTING_CONNECTION);
		if (s_con && nm_setting_connection_get_read_only (s_con)) {
			g_set_error (&err, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_READ_ONLY_CONNECTION,
			             "%s.%d - Read-only connections may not be deleted.",
			             __FILE__, __LINE__);
		}
	}

	if (!err) {
		/* A hack to share the DBusGMethodInvocation with the possible overriders of connection::delete */
		g_object_set_data (G_OBJECT (connection), NM_EXPORTED_CONNECTION_DBUS_METHOD_INVOCATION, context);
		success = nm_exported_connection_delete (connection, &err);
		g_object_set_data (G_OBJECT (connection), NM_EXPORTED_CONNECTION_DBUS_METHOD_INVOCATION, NULL);
	}

	if (success) {
		dbus_g_method_return (context);
	} else {
		dbus_g_method_return_error (context, err);
		g_error_free (err);
	}

	return success;
}

static GValue *
string_to_gvalue (const char *str)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, str);

	return val;
}

static void
copy_one_secret (gpointer key, gpointer value, gpointer user_data)
{
	const char *value_str = (const char *) value;

	if (value_str) {
		g_hash_table_insert ((GHashTable *) user_data,
		                     g_strdup ((char *) key),
		                     string_to_gvalue (value_str));
	}
}

static void
add_secrets (NMSetting *setting,
             const char *key,
             const GValue *value,
             GParamFlags flags,
             gpointer user_data)
{
	GHashTable *secrets = user_data;

	if (!(flags & NM_SETTING_PARAM_SECRET))
		return;

	if (G_VALUE_HOLDS_STRING (value)) {
		const char *tmp;

		tmp = g_value_get_string (value);
		if (tmp)
			g_hash_table_insert (secrets, g_strdup (key), string_to_gvalue (tmp));
	} else if (G_VALUE_HOLDS (value, DBUS_TYPE_G_MAP_OF_STRING)) {
		/* Flatten the string hash by pulling its keys/values out */
		g_hash_table_foreach (g_value_get_boxed (value), copy_one_secret, secrets);
	}
}

static void
destroy_gvalue (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static void
real_get_secrets (NMExportedConnection *exported,
                  const gchar *setting_name,
                  const gchar **hints,
                  gboolean request_new,
                  DBusGMethodInvocation *context)
{
	NMConnection *connection;
	GError *error = NULL;
	GHashTable *settings = NULL;
	GHashTable *secrets = NULL;
	NMSetting *setting;

	connection = nm_exported_connection_get_connection (exported);
	setting = nm_connection_get_setting_by_name (connection, setting_name);
	if (!setting) {
		g_set_error (&error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "%s.%d - Connection didn't have requested setting '%s'.",
		             __FILE__, __LINE__, setting_name);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	/* Returned secrets are a{sa{sv}}; this is the outer a{s...} hash that
	 * will contain all the individual settings hashes.
	 */
	settings = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                  g_free, (GDestroyNotify) g_hash_table_destroy);

	/* Add the secrets from this setting to the inner secrets hash for this setting */
	secrets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, destroy_gvalue);
	nm_setting_enumerate_values (setting, add_secrets, secrets);

	g_hash_table_insert (settings, g_strdup (setting_name), secrets);

	dbus_g_method_return (context, settings);
	g_hash_table_destroy (settings);
}

static void
impl_exported_connection_get_secrets (NMExportedConnection *connection,
                                      const gchar *setting_name,
                                      const gchar **hints,
                                      gboolean request_new,
                                      DBusGMethodInvocation *context)
{
	GError *error = NULL;

	if (!NM_IS_EXPORTED_CONNECTION (connection)) {
		g_set_error (&error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "%s.%d - Invalid connection in ConnectionSettings::GetSecrets.",
		             __FILE__, __LINE__);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	if (!EXPORTED_CONNECTION_CLASS (connection)->service_get_secrets)
		real_get_secrets (connection, setting_name, hints, request_new, context);
	else
		EXPORTED_CONNECTION_CLASS (connection)->service_get_secrets (connection, setting_name, hints, request_new, context);
}

static void
nm_exported_connection_init (NMExportedConnection *connection)
{
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	GObject *connection;
	NMExportedConnectionPrivate *priv = NM_EXPORTED_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		if (priv->wrapped) {
			g_object_unref (priv->wrapped);
			priv->wrapped = NULL;
		}

		connection = g_value_dup_object (value);
		if (connection)
			priv->wrapped = NM_CONNECTION (connection);
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
	NMExportedConnection *exported = NM_EXPORTED_CONNECTION (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_object (value, nm_exported_connection_get_connection (exported));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_exported_connection_dispose (GObject *object)
{
	NMExportedConnectionPrivate *priv = NM_EXPORTED_CONNECTION_GET_PRIVATE (object);

	if (priv->wrapped) {
		g_object_unref (priv->wrapped);
		priv->wrapped = NULL;
	}

	G_OBJECT_CLASS (nm_exported_connection_parent_class)->dispose (object);
}

static void
nm_exported_connection_class_init (NMExportedConnectionClass *exported_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (exported_connection_class);

	g_type_class_add_private (object_class, sizeof (NMExportedConnectionPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = nm_exported_connection_dispose;

	exported_connection_class->get_settings = real_get_settings;
	exported_connection_class->service_get_secrets = real_get_secrets;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_CONNECTION,
		 g_param_spec_object (NM_EXPORTED_CONNECTION_CONNECTION,
						      "Connection",
						      "Wrapped connection",
						      NM_TYPE_CONNECTION,
						      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* signals */
	connection_signals[EC_UPDATED] =
		g_signal_new ("updated",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (NMExportedConnectionClass, updated),
			      NULL, NULL,
			      g_cclosure_marshal_VOID__BOXED,
			      G_TYPE_NONE, 1,
			      DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT);

	connection_signals[EC_REMOVED] =
		g_signal_new ("removed",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (NMExportedConnectionClass, removed),
			      NULL, NULL,
			      g_cclosure_marshal_VOID__VOID,
			      G_TYPE_NONE, 0);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (exported_connection_class),
	                                 &dbus_glib_nm_exported_connection_object_info);
}

NMConnection *
nm_exported_connection_get_connection (NMExportedConnection *connection)
{
	g_return_val_if_fail (NM_IS_EXPORTED_CONNECTION (connection), NULL);

	return NM_EXPORTED_CONNECTION_GET_PRIVATE (connection)->wrapped;
}

void
nm_exported_connection_register_object (NMExportedConnection *connection,
                                        NMConnectionScope scope,
                                        DBusGConnection *dbus_connection)
{
	NMExportedConnectionPrivate *priv;
	static guint32 ec_counter = 0;
	char *path;

	g_return_if_fail (NM_IS_EXPORTED_CONNECTION (connection));
	g_return_if_fail (dbus_connection != NULL);

	priv = NM_EXPORTED_CONNECTION_GET_PRIVATE (connection);
	/* Don't allow the connection to be exported twice */
	g_return_if_fail (nm_connection_get_path (priv->wrapped) == NULL);

	path = g_strdup_printf ("%s/%u", NM_DBUS_PATH_SETTINGS, ec_counter++);
	nm_connection_set_path (priv->wrapped, path);
	nm_connection_set_scope (priv->wrapped, scope);

	dbus_g_connection_register_g_object (dbus_connection,
	                                     path,
	                                     G_OBJECT (connection));
	g_free (path);
}

gboolean
nm_exported_connection_update (NMExportedConnection *connection,
						 GHashTable *new_settings,
						 GError **err)
{
	gboolean success = TRUE;
	GError *error = NULL;

	g_return_val_if_fail (NM_IS_EXPORTED_CONNECTION (connection), FALSE);
	g_return_val_if_fail (new_settings != NULL, FALSE);

	if (EXPORTED_CONNECTION_CLASS (connection)->update)
		success = EXPORTED_CONNECTION_CLASS (connection)->update (connection, new_settings, err);

	if (success) {
		if (!nm_connection_replace_settings (NM_EXPORTED_CONNECTION_GET_PRIVATE (connection)->wrapped, new_settings, &error)) {
			g_warning ("%s: '%s' / '%s' invalid: %d",
			           __func__,
			           error ? g_type_name (nm_connection_lookup_setting_type_by_quark (error->domain)) : "(none)",
			           (error && error->message) ? error->message : "(none)",
			           error ? error->code : -1);
			g_clear_error (&error);
			success = FALSE;
		} else
			nm_exported_connection_signal_updated (connection, new_settings);
	}

	return success;
}

gboolean
nm_exported_connection_delete (NMExportedConnection *connection, GError **err)
{
	gboolean success = TRUE;

	g_return_val_if_fail (NM_IS_EXPORTED_CONNECTION (connection), FALSE);

	if (EXPORTED_CONNECTION_CLASS (connection)->do_delete)
		success = EXPORTED_CONNECTION_CLASS (connection)->do_delete (connection, err);

	if (success)
		nm_exported_connection_signal_removed (connection);

	return success;
}

void
nm_exported_connection_signal_updated (NMExportedConnection *connection, GHashTable *settings)
{
	g_return_if_fail (NM_IS_EXPORTED_CONNECTION (connection));

	g_signal_emit (connection, connection_signals[EC_UPDATED], 0, settings);
}

void
nm_exported_connection_signal_removed (NMExportedConnection *connection)
{
	g_return_if_fail (NM_IS_EXPORTED_CONNECTION (connection));

	g_signal_emit (connection, connection_signals[EC_REMOVED], 0);
}
