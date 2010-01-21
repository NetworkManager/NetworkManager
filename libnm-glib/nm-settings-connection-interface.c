/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2007 - 2009 Red Hat, Inc.
 */

#include "nm-settings-connection-interface.h"
#include "nm-dbus-glib-types.h"

/**
 * nm_settings_connection_interface_update:
 * @connection: an object implementing #NMSettingsConnectionInterface
 * @callback: a function to be called when the update completes
 * @user_data: caller-specific data to be passed to @callback
 *
 * Update the connection with current settings and properties.
 *
 * Returns: TRUE on success, FALSE on failure
 **/
gboolean
nm_settings_connection_interface_update (NMSettingsConnectionInterface *connection,
                                         NMSettingsConnectionInterfaceUpdateFunc callback,
                                         gpointer user_data)
{
	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION_INTERFACE (connection), FALSE);
	g_return_val_if_fail (callback != NULL, FALSE);

	if (NM_SETTINGS_CONNECTION_INTERFACE_GET_INTERFACE (connection)->update) {
		return NM_SETTINGS_CONNECTION_INTERFACE_GET_INTERFACE (connection)->update (connection,
		                                                                            callback,
		                                                                            user_data);
	}
	return FALSE;
}

/**
 * nm_settings_connection_interface_delete:
 * @connection: a objecting implementing #NMSettingsConnectionInterface
 * @callback: a function to be called when the delete completes
 * @user_data: caller-specific data to be passed to @callback
 *
 * Delete the connection.
 *
 * Returns: TRUE on success, FALSE on failure
 **/
gboolean
nm_settings_connection_interface_delete (NMSettingsConnectionInterface *connection,
                                         NMSettingsConnectionInterfaceDeleteFunc callback,
                                         gpointer user_data)
{
	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION_INTERFACE (connection), FALSE);
	g_return_val_if_fail (callback != NULL, FALSE);

	if (NM_SETTINGS_CONNECTION_INTERFACE_GET_INTERFACE (connection)->delete) {
		return NM_SETTINGS_CONNECTION_INTERFACE_GET_INTERFACE (connection)->delete (connection,
		                                                                            callback,
		                                                                            user_data);
	}
	return FALSE;
}

/**
 * nm_settings_connection_interface_get_secrets:
 * @connection: a object implementing #NMSettingsConnectionInterface
 * @setting_name: the #NMSetting object name to get secrets for
 * @hints: #NMSetting key names to get secrets for (optional)
 * @request_new: hint that new secrets (instead of cached or stored secrets) 
 *  should be returned
 * @callback: a function to be called when the update completes
 * @user_data: caller-specific data to be passed to @callback
 *
 * Request the connection's secrets.
 *
 * Returns: TRUE on success, FALSE on failure
 **/
gboolean
nm_settings_connection_interface_get_secrets (NMSettingsConnectionInterface *connection,
                                              const char *setting_name,
                                              const char **hints,
                                              gboolean request_new,
                                              NMSettingsConnectionInterfaceGetSecretsFunc callback,
                                              gpointer user_data)
{
	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION_INTERFACE (connection), FALSE);
	g_return_val_if_fail (callback != NULL, FALSE);

	if (NM_SETTINGS_CONNECTION_INTERFACE_GET_INTERFACE (connection)->get_secrets) {
		return NM_SETTINGS_CONNECTION_INTERFACE_GET_INTERFACE (connection)->get_secrets (connection,
		                                                                                 setting_name,
		                                                                                 hints,
		                                                                                 request_new,
		                                                                                 callback,
		                                                                                 user_data);
	}
	return FALSE;
}

void
nm_settings_connection_interface_emit_updated (NMSettingsConnectionInterface *connection)
{
	if (NM_SETTINGS_CONNECTION_INTERFACE_GET_INTERFACE (connection)->emit_updated)
		NM_SETTINGS_CONNECTION_INTERFACE_GET_INTERFACE (connection)->emit_updated (connection);
	else {
		NMConnection *tmp;
		GHashTable *settings;

		tmp = nm_connection_duplicate (NM_CONNECTION (connection));
		nm_connection_clear_secrets (tmp);
		settings = nm_connection_to_hash (tmp);
		g_object_unref (tmp);

		g_signal_emit_by_name (connection, NM_SETTINGS_CONNECTION_INTERFACE_UPDATED, settings);
		g_hash_table_destroy (settings);
	}
}

static void
nm_settings_connection_interface_init (gpointer g_iface)
{
	GType iface_type = G_TYPE_FROM_INTERFACE (g_iface);
	static gboolean initialized = FALSE;

	if (initialized)
		return;

	/* Signals */
	g_signal_new (NM_SETTINGS_CONNECTION_INTERFACE_UPDATED,
				  iface_type,
				  G_SIGNAL_RUN_FIRST,
				  G_STRUCT_OFFSET (NMSettingsConnectionInterface, updated),
				  NULL, NULL,
				  g_cclosure_marshal_VOID__BOXED,
				  G_TYPE_NONE, 1, DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT);

	g_signal_new (NM_SETTINGS_CONNECTION_INTERFACE_REMOVED,
				  iface_type,
				  G_SIGNAL_RUN_FIRST,
				  G_STRUCT_OFFSET (NMSettingsConnectionInterface, removed),
				  NULL, NULL,
				  g_cclosure_marshal_VOID__VOID,
				  G_TYPE_NONE, 0);

	initialized = TRUE;
}

GType
nm_settings_connection_interface_get_type (void)
{
	static GType itype = 0;

	if (!itype) {
		const GTypeInfo iinfo = {
			sizeof (NMSettingsConnectionInterface), /* class_size */
			nm_settings_connection_interface_init,   /* base_init */
			NULL,		/* base_finalize */
			NULL,
			NULL,		/* class_finalize */
			NULL,		/* class_data */
			0,
			0,              /* n_preallocs */
			NULL
		};

		itype = g_type_register_static (G_TYPE_INTERFACE,
		                                "NMSettingsConnectionInterface",
		                                &iinfo, 0);

		g_type_interface_add_prerequisite (itype, NM_TYPE_CONNECTION);
	}

	return itype;
}

