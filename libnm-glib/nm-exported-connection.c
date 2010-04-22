/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * (C) Copyright 2008 Novell, Inc.
 * (C) Copyright 2008 - 2009 Red Hat, Inc.
 */

#include <NetworkManager.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <nm-setting-connection.h>

#include "nm-exported-connection.h"
#include "nm-settings-interface.h"
#include "nm-settings-connection-interface.h"

static gboolean impl_exported_connection_get_settings (NMExportedConnection *connection,
                                                       GHashTable **settings,
                                                       GError **error);

static void impl_exported_connection_update (NMExportedConnection *connection,
                                             GHashTable *new_settings,
                                             DBusGMethodInvocation *context);

static void impl_exported_connection_delete (NMExportedConnection *connection,
                                             DBusGMethodInvocation *context);

static void impl_exported_connection_get_secrets (NMExportedConnection *connection,
                                                  const gchar *setting_name,
                                                  const gchar **hints,
                                                  gboolean request_new,
                                                  DBusGMethodInvocation *context);

#include "nm-exported-connection-glue.h"

static void settings_connection_interface_init (NMSettingsConnectionInterface *class);

G_DEFINE_TYPE_EXTENDED (NMExportedConnection, nm_exported_connection, NM_TYPE_CONNECTION, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_SETTINGS_CONNECTION_INTERFACE,
                                               settings_connection_interface_init))

#define NM_EXPORTED_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                               NM_TYPE_EXPORTED_CONNECTION, \
                                               NMExportedConnectionPrivate))

typedef struct {
	gboolean foo;
} NMExportedConnectionPrivate;


/**************************************************************/

static GHashTable *
real_get_settings (NMExportedConnection *self, GError **error)
{
	NMConnection *no_secrets;
	GHashTable *settings;

	/* Secrets should *never* be returned by the GetSettings method, they
	 * get returned by the GetSecrets method which can be better
	 * protected against leakage of secrets to unprivileged callers.
	 */
	no_secrets = nm_connection_duplicate (NM_CONNECTION (self));
	g_assert (no_secrets);
	nm_connection_clear_secrets (no_secrets);
	settings = nm_connection_to_hash (no_secrets);
	g_assert (settings);
	g_object_unref (no_secrets);

	return settings;
}

/**************************************************************/

static gboolean
check_writable (NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection,
	                                                           NM_TYPE_SETTING_CONNECTION);
	if (!s_con) {
		g_set_error_literal (error,
		                     NM_SETTINGS_INTERFACE_ERROR,
		                     NM_SETTINGS_INTERFACE_ERROR_INVALID_CONNECTION,
		                     "Connection did not have required 'connection' setting");
		return FALSE;
	}

	/* If the connection is read-only, that has to be changed at the source of
	 * the problem (ex a system settings plugin that can't write connections out)
	 * instead of over D-Bus.
	 */
	if (nm_setting_connection_get_read_only (s_con)) {
		g_set_error_literal (error,
		                     NM_SETTINGS_INTERFACE_ERROR,
		                     NM_SETTINGS_INTERFACE_ERROR_READ_ONLY_CONNECTION,
		                     "Connection is read-only");
		return FALSE;
	}

	return TRUE;
}

static gboolean
impl_exported_connection_get_settings (NMExportedConnection *self,
                                       GHashTable **settings,
                                       GError **error)
{
	/* Must always be implemented */
	g_assert (NM_EXPORTED_CONNECTION_GET_CLASS (self)->get_settings);
	*settings = NM_EXPORTED_CONNECTION_GET_CLASS (self)->get_settings (self, error);
	return *settings ? TRUE : FALSE;
}

static gboolean
update (NMSettingsConnectionInterface *connection,
	    NMSettingsConnectionInterfaceUpdateFunc callback,
	    gpointer user_data)
{
	g_object_ref (connection);
	nm_settings_connection_interface_emit_updated (connection);
	callback (connection, NULL, user_data);
	g_object_unref (connection);
	return TRUE;
}

static void
impl_exported_connection_update (NMExportedConnection *self,
                                 GHashTable *new_settings,
                                 DBusGMethodInvocation *context)
{
	NMConnection *tmp;
	GError *error = NULL;

	/* If the connection is read-only, that has to be changed at the source of
	 * the problem (ex a system settings plugin that can't write connections out)
	 * instead of over D-Bus.
	 */
	if (!check_writable (NM_CONNECTION (self), &error)) {
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	/* Check if the settings are valid first */
	tmp = nm_connection_new_from_hash (new_settings, &error);
	if (!tmp) {
		g_assert (error);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}
	g_object_unref (tmp);

	if (NM_EXPORTED_CONNECTION_GET_CLASS (self)->update)
		NM_EXPORTED_CONNECTION_GET_CLASS (self)->update (self, new_settings, context);
	else {
		error = g_error_new (NM_SETTINGS_INTERFACE_ERROR,
		                     NM_SETTINGS_INTERFACE_ERROR_INTERNAL_ERROR,
		                     "%s: %s:%d update() unimplemented", __func__, __FILE__, __LINE__);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
}

static gboolean
do_delete (NMSettingsConnectionInterface *connection,
	       NMSettingsConnectionInterfaceDeleteFunc callback,
	       gpointer user_data)
{
	g_object_ref (connection);
	g_signal_emit_by_name (connection, "removed");
	callback (connection, NULL, user_data);
	g_object_unref (connection);
	return TRUE;
}

static void
impl_exported_connection_delete (NMExportedConnection *self,
                                 DBusGMethodInvocation *context)
{
	GError *error = NULL;

	if (!check_writable (NM_CONNECTION (self), &error)) {
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	if (NM_EXPORTED_CONNECTION_GET_CLASS (self)->delete)
		NM_EXPORTED_CONNECTION_GET_CLASS (self)->delete (self, context);
	else {
		error = g_error_new (NM_SETTINGS_INTERFACE_ERROR,
		                     NM_SETTINGS_INTERFACE_ERROR_INTERNAL_ERROR,
		                     "%s: %s:%d delete() unimplemented", __func__, __FILE__, __LINE__);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
}

static void
impl_exported_connection_get_secrets (NMExportedConnection *self,
                                      const gchar *setting_name,
                                      const gchar **hints,
                                      gboolean request_new,
                                      DBusGMethodInvocation *context)
{
	GError *error = NULL;

	if (NM_EXPORTED_CONNECTION_GET_CLASS (self)->get_secrets)
		NM_EXPORTED_CONNECTION_GET_CLASS (self)->get_secrets (self, setting_name, hints, request_new, context);
	else {
		error = g_error_new (NM_SETTINGS_INTERFACE_ERROR,
		                     NM_SETTINGS_INTERFACE_ERROR_INTERNAL_ERROR,
		                     "%s: %s:%d get_secrets() unimplemented", __func__, __FILE__, __LINE__);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
}

/**************************************************************/

static void
settings_connection_interface_init (NMSettingsConnectionInterface *iface)
{
	iface->update = update;
	iface->delete = do_delete;
}

/**
 * nm_exported_connection_new:
 * @scope: the Connection scope (either user or system)
 *
 * Creates a new object representing the remote connection.
 *
 * Returns: the new exported connection object on success, or %NULL on failure
 **/
NMExportedConnection *
nm_exported_connection_new (NMConnectionScope scope)
{
	g_return_val_if_fail (scope != NM_CONNECTION_SCOPE_UNKNOWN, NULL);

	return (NMExportedConnection *) g_object_new (NM_TYPE_EXPORTED_CONNECTION,
	                                              NM_CONNECTION_SCOPE, scope,
	                                              NULL);
}

static void
nm_exported_connection_init (NMExportedConnection *self)
{
}

static void
nm_exported_connection_class_init (NMExportedConnectionClass *class)
{
	g_type_class_add_private (class, sizeof (NMExportedConnectionPrivate));

	/* Virtual methods */
	class->get_settings = real_get_settings;

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (class),
	                                 &dbus_glib_nm_exported_connection_object_info);
}
