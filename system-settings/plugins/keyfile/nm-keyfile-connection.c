/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include <string.h>
#include <glib/gstdio.h>
#include <NetworkManager.h>
#include <nm-setting-connection.h>
#include <nm-utils.h>

#include "nm-dbus-glib-types.h"
#include "nm-keyfile-connection.h"
#include "reader.h"
#include "writer.h"

G_DEFINE_TYPE (NMKeyfileConnection, nm_keyfile_connection, NM_TYPE_SYSCONFIG_CONNECTION)

#define NM_KEYFILE_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_KEYFILE_CONNECTION, NMKeyfileConnectionPrivate))

typedef struct {
	char *filename;
} NMKeyfileConnectionPrivate;

enum {
	PROP_0,
	PROP_FILENAME,

	LAST_PROP
};

NMKeyfileConnection *
nm_keyfile_connection_new (const char *filename)
{
	g_return_val_if_fail (filename != NULL, NULL);

	return (NMKeyfileConnection *) g_object_new (NM_TYPE_KEYFILE_CONNECTION,
	                                             NM_KEYFILE_CONNECTION_FILENAME, filename,
	                                             NULL);
}

const char *
nm_keyfile_connection_get_filename (NMKeyfileConnection *self)
{
	g_return_val_if_fail (NM_IS_KEYFILE_CONNECTION (self), NULL);

	return NM_KEYFILE_CONNECTION_GET_PRIVATE (self)->filename;
}

static GHashTable *
get_settings (NMExportedConnection *exported)
{
	return nm_connection_to_hash (nm_exported_connection_get_connection (exported));
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
	g_hash_table_insert ((GHashTable *) user_data,
	                     g_strdup ((char *) key),
	                     string_to_gvalue (value));
}

static void
add_secrets (NMSetting *setting,
             const char *key,
             const GValue *value,
             gboolean secret,
             gpointer user_data)
{
	GHashTable *secrets = user_data;

	if (!secret)
		return;

	if (G_VALUE_HOLDS_STRING (value)) {
		g_hash_table_insert (secrets, g_strdup (key), string_to_gvalue (g_value_get_string (value)));
	} else if (G_VALUE_HOLDS (value, DBUS_TYPE_G_MAP_OF_STRING)) {
		/* Flatten the string hash by pulling its keys/values out */
		g_hash_table_foreach (g_value_get_boxed (value), copy_one_secret, secrets);
	} else
		g_message ("%s: unhandled secret %s type %s", __func__, key, G_VALUE_TYPE_NAME (value));
}

static void
destroy_gvalue (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static GHashTable *
extract_secrets (NMKeyfileConnection *exported,
                 const char *setting_name,
                 GError **error)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (exported);
	NMConnection *tmp;
	GHashTable *secrets;
	NMSetting *setting;

	tmp = connection_from_file (priv->filename, TRUE);
	if (!tmp) {
		g_set_error (error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Could not read secrets from file %s.",
		             __FILE__, __LINE__, priv->filename);
		return NULL;
	}

	setting = nm_connection_get_setting_by_name (tmp, setting_name);
	if (!setting) {
		g_object_unref (tmp);
		g_set_error (error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Could not read secrets from file %s.",
		             __FILE__, __LINE__, priv->filename);
		return NULL;
	}

	/* Add the secrets from this setting to the secrets hash */
	secrets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, destroy_gvalue);
	nm_setting_enumerate_values (setting, add_secrets, secrets);

	g_object_unref (tmp);

	return secrets;
}

static void
get_secrets (NMExportedConnection *exported,
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
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Connection didn't have requested setting '%s'.",
		             __FILE__, __LINE__, setting_name);
		goto error;
	}

	/* Returned secrets are a{sa{sv}}; this is the outer a{s...} hash that
	 * will contain all the individual settings hashes.
	 */
	settings = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                  g_free, (GDestroyNotify) g_hash_table_destroy);

	/* Read in a temporary connection and just extract the secrets */
	secrets = extract_secrets (NM_KEYFILE_CONNECTION (exported), setting_name, &error);
	if (!secrets)
		goto error;

	g_hash_table_insert (settings, g_strdup (setting_name), secrets);

	dbus_g_method_return (context, settings);
	g_hash_table_destroy (settings);
	return;

error:
	nm_warning ("%s", error->message);
	dbus_g_method_return_error (context, error);
	g_error_free (error);
}

static gboolean
update (NMExportedConnection *exported,
        GHashTable *new_settings,
        GError **error)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (exported);
	gboolean success;

	success = NM_EXPORTED_CONNECTION_CLASS (nm_keyfile_connection_parent_class)->update (exported, new_settings, error);
	if (success) {
		NMConnection *connection;
		char *filename = NULL;

		connection = nm_exported_connection_get_connection (exported);
		nm_connection_replace_settings (connection, new_settings);
		success = write_connection (connection, &filename, error);
		if (success && filename && strcmp (priv->filename, filename)) {
			/* Update the filename if it changed */
			g_free (priv->filename);
			priv->filename = filename;
		} else
			g_free (filename);
	}

	return success;
}

static gboolean
delete (NMExportedConnection *exported, GError **err)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (exported);
	gboolean success;

	success = NM_EXPORTED_CONNECTION_CLASS (nm_keyfile_connection_parent_class)->delete (exported, err);

	if (success)
		g_unlink (priv->filename);

	return success;
}

/* GObject */

static void
nm_keyfile_connection_init (NMKeyfileConnection *connection)
{
}

static GObject *
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	GObject *object;
	NMKeyfileConnectionPrivate *priv;
	NMConnection *wrapped;
	NMSettingConnection *s_con;

	object = G_OBJECT_CLASS (nm_keyfile_connection_parent_class)->constructor (type, n_construct_params, construct_params);

	if (!object)
		return NULL;

	priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (object);

	if (!priv->filename) {
		g_warning ("Keyfile file name not provided.");
		goto err;
	}

	wrapped = connection_from_file (priv->filename, FALSE);
	if (!wrapped)
		goto err;

	/* if for some reason the connection didn't have a UUID, add one */
	s_con = (NMSettingConnection *) nm_connection_get_setting (wrapped, NM_TYPE_SETTING_CONNECTION);
	if (s_con && !s_con->uuid) {
		GError *error = NULL;

		s_con->uuid = nm_utils_uuid_generate ();
		if (!write_connection (wrapped, NULL, &error)) {
			g_warning ("Couldn't update connection %s with a UUID: (%d) %s",
			           s_con->id, error ? error->code : 0,
			           error ? error->message : "unknown");
			g_error_free (error);
		}
	}

	g_object_set (object, NM_EXPORTED_CONNECTION_CONNECTION, wrapped, NULL);
	g_object_unref (wrapped);

	return object;

 err:
	g_object_unref (object);

	return NULL;
}

static void
finalize (GObject *object)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (object);

	g_free (priv->filename);

	G_OBJECT_CLASS (nm_keyfile_connection_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_FILENAME:
		/* Construct only */
		priv->filename = g_value_dup_string (value);
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
	NMKeyfileConnectionPrivate *priv = NM_KEYFILE_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_FILENAME:
		g_value_set_string (value, priv->filename);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_keyfile_connection_class_init (NMKeyfileConnectionClass *keyfile_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (keyfile_connection_class);
	NMExportedConnectionClass *connection_class = NM_EXPORTED_CONNECTION_CLASS (keyfile_connection_class);

	g_type_class_add_private (keyfile_connection_class, sizeof (NMKeyfileConnectionPrivate));

	/* Virtual methods */
	object_class->constructor  = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	connection_class->get_settings = get_settings;
	connection_class->get_secrets  = get_secrets;
	connection_class->update       = update;
	connection_class->delete       = delete;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_FILENAME,
		 g_param_spec_string (NM_KEYFILE_CONNECTION_FILENAME,
						  "FileName",
						  "File name",
						  NULL,
						  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}
