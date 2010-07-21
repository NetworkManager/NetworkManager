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
 * Copyright (C) 2007 - 2010 Red Hat, Inc.
 */

#include "nm-settings-interface.h"


/**
 * nm_settings_interface_error_quark:
 *
 * Setting error quark.
 *
 * Returns: the setting error quark
 **/
GQuark
nm_settings_interface_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-settings-interface-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_settings_interface_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* The connection was invalid. */
			ENUM_ENTRY (NM_SETTINGS_INTERFACE_ERROR_INVALID_CONNECTION, "InvalidConnection"),
			/* The connection is read-only; modifications are not allowed. */
			ENUM_ENTRY (NM_SETTINGS_INTERFACE_ERROR_READ_ONLY_CONNECTION, "ReadOnlyConnection"),
			/* A bug in the settings service caused the error. */
			ENUM_ENTRY (NM_SETTINGS_INTERFACE_ERROR_INTERNAL_ERROR, "InternalError"),
			/* Retrieval or request of secrets failed. */
			ENUM_ENTRY (NM_SETTINGS_INTERFACE_ERROR_SECRETS_UNAVAILABLE, "SecretsUnavailable"),
			/* The request for secrets was canceled. */
			ENUM_ENTRY (NM_SETTINGS_INTERFACE_ERROR_SECRETS_REQUEST_CANCELED, "SecretsRequestCanceled"),
			/* The request could not be completed because permission was denied. */
			ENUM_ENTRY (NM_SETTINGS_INTERFACE_ERROR_PERMISSION_DENIED, "PermissionDenied"),
			/* The requested setting does not existing in this connection. */
			ENUM_ENTRY (NM_SETTINGS_INTERFACE_ERROR_INVALID_SETTING, "InvalidSetting"),
			{ 0, 0, 0 },
		};
		etype = g_enum_register_static ("NMSettingsInterfaceError", values);
	}
	return etype;
}


/**
 * nm_settings_list_connections:
 * @settings: a object implementing %NMSettingsInterface
 *
 * Returns: all connections known to the object.
 **/
GSList *
nm_settings_interface_list_connections (NMSettingsInterface *settings)
{
	g_return_val_if_fail (settings != NULL, NULL);
	g_return_val_if_fail (NM_IS_SETTINGS_INTERFACE (settings), NULL);

	if (NM_SETTINGS_INTERFACE_GET_INTERFACE (settings)->list_connections)
		return NM_SETTINGS_INTERFACE_GET_INTERFACE (settings)->list_connections (settings);
	return NULL;
}

/**
 * nm_settings_get_connection_by_path:
 * @settings: a object implementing %NMSettingsInterface
 * @path: the D-Bus object path of the remote connection
 *
 * Returns the object implementing %NMSettingsConnectionInterface at @path.
 *
 * Returns: the remote connection object on success, or NULL if the object was
 *  not known
 **/
NMSettingsConnectionInterface *
nm_settings_interface_get_connection_by_path (NMSettingsInterface *settings,
                                              const char *path)
{
	g_return_val_if_fail (settings != NULL, NULL);
	g_return_val_if_fail (NM_IS_SETTINGS_INTERFACE (settings), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	if (NM_SETTINGS_INTERFACE_GET_INTERFACE (settings)->get_connection_by_path)
		return NM_SETTINGS_INTERFACE_GET_INTERFACE (settings)->get_connection_by_path (settings, path);
	return NULL;
}

/**
 * nm_settings_interface_add_connection:
 * @settings: a object implementing %NMSettingsInterface
 * @connection: the settings to add; note that this object's settings will be
 *  added, not the object itself
 * @callback: callback to be called when the add operation completes
 * @user_data: caller-specific data passed to @callback
 *
 * Requests that the settings service add the given settings to a new connection.
 *
 * Returns: TRUE if the request was successful, FALSE if it failed
 **/
gboolean
nm_settings_interface_add_connection (NMSettingsInterface *settings,
                                      NMConnection *connection,
                                      NMSettingsAddConnectionFunc callback,
                                      gpointer user_data)
{
	g_return_val_if_fail (settings != NULL, FALSE);
	g_return_val_if_fail (NM_IS_SETTINGS_INTERFACE (settings), FALSE);
	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (callback != NULL, FALSE);

	if (NM_SETTINGS_INTERFACE_GET_INTERFACE (settings)->add_connection) {
		return NM_SETTINGS_INTERFACE_GET_INTERFACE (settings)->add_connection (settings,
		                                                                       connection,
		                                                                       callback,
		                                                                       user_data);
	}
	return FALSE;
}

/*****************************************************************/

static void
nm_settings_interface_init (gpointer g_iface)
{
	GType iface_type = G_TYPE_FROM_INTERFACE (g_iface);
	static gboolean initialized = FALSE;

	if (initialized)
		return;

	/* Signals */
	g_signal_new (NM_SETTINGS_INTERFACE_NEW_CONNECTION,
				  iface_type,
				  G_SIGNAL_RUN_FIRST,
				  G_STRUCT_OFFSET (NMSettingsInterface, new_connection),
				  NULL, NULL,
				  g_cclosure_marshal_VOID__OBJECT,
				  G_TYPE_NONE, 1, G_TYPE_OBJECT);

	g_signal_new (NM_SETTINGS_INTERFACE_CONNECTIONS_READ,
				  iface_type,
				  G_SIGNAL_RUN_FIRST,
				  G_STRUCT_OFFSET (NMSettingsInterface, connections_read),
				  NULL, NULL,
				  g_cclosure_marshal_VOID__VOID,
				  G_TYPE_NONE, 0);

	initialized = TRUE;
}

GType
nm_settings_interface_get_type (void)
{
	static GType settings_interface_type = 0;

	if (!settings_interface_type) {
		const GTypeInfo settings_interface_info = {
			sizeof (NMSettingsInterface), /* class_size */
			nm_settings_interface_init,   /* base_init */
			NULL,		/* base_finalize */
			NULL,
			NULL,		/* class_finalize */
			NULL,		/* class_data */
			0,
			0,              /* n_preallocs */
			NULL
		};

		settings_interface_type = g_type_register_static (G_TYPE_INTERFACE,
		                                                  "NMSettingsInterface",
		                                                  &settings_interface_info, 0);

		g_type_interface_add_prerequisite (settings_interface_type, G_TYPE_OBJECT);
	}

	return settings_interface_type;
}

