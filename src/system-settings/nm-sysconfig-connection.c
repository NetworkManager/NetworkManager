/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2008 Novell, Inc.
 */

#include <NetworkManager.h>
#include "nm-sysconfig-connection.h"
#include "nm-system-config-error.h"
#include "nm-polkit-helpers.h"
#include "nm-dbus-glib-types.h"

G_DEFINE_ABSTRACT_TYPE (NMSysconfigConnection, nm_sysconfig_connection, NM_TYPE_EXPORTED_CONNECTION)

#define NM_SYSCONFIG_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                                NM_TYPE_SYSCONFIG_CONNECTION, \
                                                NMSysconfigConnectionPrivate))

typedef struct {
	DBusGConnection *dbus_connection;
	PolKitContext *pol_ctx;

	DBusGProxy *proxy;
} NMSysconfigConnectionPrivate;

static gboolean
update (NMExportedConnection *exported,
	   GHashTable *new_settings,
	   GError **err)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (exported);
	DBusGMethodInvocation *context;

	context = g_object_get_data (G_OBJECT (exported), NM_EXPORTED_CONNECTION_DBUS_METHOD_INVOCATION);
	g_return_val_if_fail (context != NULL, FALSE);

	return check_polkit_privileges (priv->dbus_connection, priv->pol_ctx, context, err);
}

static gboolean
do_delete (NMExportedConnection *exported, GError **err)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (exported);
	DBusGMethodInvocation *context;

	context = g_object_get_data (G_OBJECT (exported), NM_EXPORTED_CONNECTION_DBUS_METHOD_INVOCATION);
	g_return_val_if_fail (context != NULL, FALSE);

	return check_polkit_privileges (priv->dbus_connection, priv->pol_ctx, context, err);
}

static GValue *
string_to_gvalue (const char *str)
{
	GValue *val = g_slice_new0 (GValue);

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

GHashTable *
nm_sysconfig_connection_get_secrets (NMSysconfigConnection *self,
                                     const gchar *setting_name,
                                     const gchar **hints,
                                     gboolean request_new,
                                     GError **error)
{
	NMConnection *connection;
	GHashTable *settings = NULL;
	GHashTable *secrets = NULL;
	NMSetting *setting;

	connection = nm_exported_connection_get_connection (NM_EXPORTED_CONNECTION (self));
	setting = nm_connection_get_setting_by_name (connection, setting_name);
	if (!setting) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "%s.%d - Connection didn't have requested setting '%s'.",
		             __FILE__, __LINE__, setting_name);
		return NULL;
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
	return settings;
}

typedef struct {
	NMSysconfigConnection *self;
	char *setting_name;
	DBusGMethodInvocation *context;
} GetUnixUserInfo;

static GetUnixUserInfo *
get_unix_user_info_new (NMSysconfigConnection *self,
                        const char *setting_name,
                        DBusGMethodInvocation *context)
{
	GetUnixUserInfo *info;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (setting_name != NULL, NULL);
	g_return_val_if_fail (context != NULL, NULL);

	info = g_malloc0 (sizeof (GetUnixUserInfo));
	info->self = self;
	info->setting_name = g_strdup (setting_name);
	info->context = context;
	return info;
}

static void
get_unix_user_info_free (gpointer user_data)
{
	GetUnixUserInfo *info = user_data;

	g_free (info->setting_name);
	g_free (info);
}

static void
get_unix_user_cb (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	GetUnixUserInfo *info = user_data;
	NMSysconfigConnection *self;
	NMSysconfigConnectionPrivate *priv;
	GError *error = NULL;
	guint32 requestor_uid = G_MAXUINT32;
	GHashTable *secrets;

	g_return_if_fail (info != NULL);

	self = info->self;
	priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);

	if (!dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_UINT, &requestor_uid, G_TYPE_INVALID))
		goto error;

	/* Non-root users need PolicyKit authorization */
	if (requestor_uid != 0) {
		if (!check_polkit_privileges (priv->dbus_connection, priv->pol_ctx, info->context, &error))
			goto error;
	}

	secrets = nm_sysconfig_connection_get_secrets (self, info->setting_name, NULL, FALSE, &error);
	if (secrets) {
		/* success; return secrets to caller */
		dbus_g_method_return (info->context, secrets);
		g_hash_table_destroy (secrets);
		return;
	}

	if (!error) {
		/* Shouldn't happen, but... */
		g_set_error (&error, NM_SYSCONFIG_SETTINGS_ERROR,
		             NM_SYSCONFIG_SETTINGS_ERROR_GENERAL,
		             "%s", "Could not get secrets from connection (unknown error ocurred)");
	}

error:
	dbus_g_method_return_error (info->context, error);
	g_clear_error (&error);
}

static void
service_get_secrets (NMExportedConnection *exported,
                     const gchar *setting_name,
                     const gchar **hints,
                     gboolean request_new,
                     DBusGMethodInvocation *context)
{
	NMSysconfigConnection *self = NM_SYSCONFIG_CONNECTION (exported);
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);
	GetUnixUserInfo *info;
	GError *error = NULL;
	char *sender = NULL;

	sender = dbus_g_method_get_sender (context);
	if (!sender) {
		g_set_error (&error, NM_SYSCONFIG_SETTINGS_ERROR,
		             NM_SYSCONFIG_SETTINGS_ERROR_GENERAL,
		             "%s", "Could not determine D-Bus requestor to authorize GetSecrets request");
		goto out;
	}

	if (priv->proxy)
		g_object_unref (priv->proxy);

	priv->proxy = dbus_g_proxy_new_for_name (priv->dbus_connection,
	                                         DBUS_SERVICE_DBUS,
	                                         DBUS_PATH_DBUS,
	                                         DBUS_INTERFACE_DBUS);
	if (!priv->proxy) {
		g_set_error (&error, NM_SYSCONFIG_SETTINGS_ERROR,
		             NM_SYSCONFIG_SETTINGS_ERROR_GENERAL,
		             "%s", "Could not connect to D-Bus to authorize GetSecrets request");
		goto out;
	}

	info = get_unix_user_info_new (self, setting_name, context);
	if (!info) {
		g_set_error (&error, NM_SYSCONFIG_SETTINGS_ERROR,
		             NM_SYSCONFIG_SETTINGS_ERROR_GENERAL,
		             "%s", "Not enough memory to authorize GetSecrets request");
		goto out;
	}

	dbus_g_proxy_begin_call_with_timeout (priv->proxy, "GetConnectionUnixUser",
	                                      get_unix_user_cb,
	                                      info,
	                                      get_unix_user_info_free,
	                                      5000,
	                                      G_TYPE_STRING, sender,
	                                      G_TYPE_INVALID);

out:
	if (error) {
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
}

/* GObject */

static void
nm_sysconfig_connection_init (NMSysconfigConnection *self)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);
	GError *err = NULL;

	priv->dbus_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (err) {
		g_warning ("%s: error getting D-Bus connection: %s",
		           __func__,
		           (err && err->message) ? err->message : "(unknown)");
		g_error_free (err);
	}

	priv->pol_ctx = create_polkit_context (&err);
	if (!priv->pol_ctx) {
		g_warning ("%s: error creating PolicyKit context: %s",
		           __func__,
		           (err && err->message) ? err->message : "(unknown)");
	}
}

static void
dispose (GObject *object)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (object);

	if (priv->proxy)
		g_object_unref (priv->proxy);

	if (priv->pol_ctx)
		polkit_context_unref (priv->pol_ctx);

	if (priv->dbus_connection)
		dbus_g_connection_unref (priv->dbus_connection);

	G_OBJECT_CLASS (nm_sysconfig_connection_parent_class)->dispose (object);
}

static void
nm_sysconfig_connection_class_init (NMSysconfigConnectionClass *sysconfig_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (sysconfig_connection_class);
	NMExportedConnectionClass *connection_class = NM_EXPORTED_CONNECTION_CLASS (sysconfig_connection_class);

	g_type_class_add_private (sysconfig_connection_class, sizeof (NMSysconfigConnectionPrivate));

	/* Virtual methods */
	object_class->dispose = dispose;

	connection_class->update = update;
	connection_class->do_delete = do_delete;
	connection_class->service_get_secrets = service_get_secrets;
}
