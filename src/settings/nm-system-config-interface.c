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
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#include "config.h"

#include "nm-system-config-interface.h"
#include "nm-settings-connection.h"

static void
interface_init (gpointer g_iface)
{
	GType iface_type = G_TYPE_FROM_INTERFACE (g_iface);
	static gboolean initialized = FALSE;

	if (initialized)
		return;

	/* Properties */
	g_object_interface_install_property
		(g_iface,
		 g_param_spec_string (NM_SYSTEM_CONFIG_INTERFACE_NAME, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_string (NM_SYSTEM_CONFIG_INTERFACE_INFO, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_uint (NM_SYSTEM_CONFIG_INTERFACE_CAPABILITIES, "", "",
		                    NM_SYSTEM_CONFIG_INTERFACE_CAP_NONE,
		                    NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_CONNECTIONS,
		                    NM_SYSTEM_CONFIG_INTERFACE_CAP_NONE,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/* Signals */
	g_signal_new (NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED,
				  iface_type,
				  G_SIGNAL_RUN_FIRST,
				  G_STRUCT_OFFSET (NMSystemConfigInterface, connection_added),
				  NULL, NULL,
				  g_cclosure_marshal_VOID__OBJECT,
				  G_TYPE_NONE, 1,
				  NM_TYPE_SETTINGS_CONNECTION);

	g_signal_new (NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED,
				  iface_type,
				  G_SIGNAL_RUN_FIRST,
				  G_STRUCT_OFFSET (NMSystemConfigInterface, unmanaged_specs_changed),
				  NULL, NULL,
				  g_cclosure_marshal_VOID__VOID,
				  G_TYPE_NONE, 0);

	g_signal_new (NM_SYSTEM_CONFIG_INTERFACE_UNRECOGNIZED_SPECS_CHANGED,
	              iface_type,
	              G_SIGNAL_RUN_FIRST,
	              G_STRUCT_OFFSET (NMSystemConfigInterface, unrecognized_specs_changed),
	              NULL, NULL,
	              g_cclosure_marshal_VOID__VOID,
	              G_TYPE_NONE, 0);

	initialized = TRUE;
}


GType
nm_system_config_interface_get_type (void)
{
	static GType system_config_interface_type = 0;

	if (!system_config_interface_type) {
		const GTypeInfo system_config_interface_info = {
			sizeof (NMSystemConfigInterface), /* class_size */
			interface_init,   /* base_init */
			NULL,		/* base_finalize */
			NULL,
			NULL,		/* class_finalize */
			NULL,		/* class_data */
			0,
			0,              /* n_preallocs */
			NULL
		};

		system_config_interface_type = g_type_register_static (G_TYPE_INTERFACE,
														       "NMSystemConfigInterface",
														       &system_config_interface_info,
														       0);

		g_type_interface_add_prerequisite (system_config_interface_type, G_TYPE_OBJECT);
	}

	return system_config_interface_type;
}

void
nm_system_config_interface_init (NMSystemConfigInterface *config,
                                 gpointer unused)
{
	g_return_if_fail (config != NULL);

	if (NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE (config)->init)
		NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE (config)->init (config);
}

GSList *
nm_system_config_interface_get_connections (NMSystemConfigInterface *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	if (NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE (config)->get_connections)
		return NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE (config)->get_connections (config);
	return NULL;
}

gboolean
nm_system_config_interface_load_connection (NMSystemConfigInterface *config,
                                            const char *filename)
{
	g_return_val_if_fail (config != NULL, FALSE);

	if (NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE (config)->load_connection)
		return NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE (config)->load_connection (config, filename);
	return FALSE;
}

void
nm_system_config_interface_reload_connections (NMSystemConfigInterface *config)
{
	g_return_if_fail (config != NULL);

	if (NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE (config)->reload_connections)
		NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE (config)->reload_connections (config);
}

GSList *
nm_system_config_interface_get_unmanaged_specs (NMSystemConfigInterface *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	if (NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE (config)->get_unmanaged_specs)
		return NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE (config)->get_unmanaged_specs (config);
	return NULL;
}

GSList *
nm_system_config_interface_get_unrecognized_specs (NMSystemConfigInterface *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	if (NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE (config)->get_unrecognized_specs)
		return NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE (config)->get_unrecognized_specs (config);
	return NULL;
}

/**
 * nm_system_config_interface_add_connection:
 * @config: the #NMSystemConfigInterface
 * @connection: the source connection to create a plugin-specific
 * #NMSettingsConnection from
 * @save_to_disk: %TRUE to save the connection to disk immediately, %FALSE to
 * not save to disk
 * @error: on return, a location to store any errors that may occur
 *
 * Creates a new #NMSettingsConnection for the given source @connection.  If the
 * plugin cannot handle the given connection type, it should return %NULL and
 * set @error.  The plugin owns the returned object and the caller must reference
 * the object if it wishes to continue using it.
 *
 * Returns: the new #NMSettingsConnection or %NULL
 */
NMSettingsConnection *
nm_system_config_interface_add_connection (NMSystemConfigInterface *config,
                                           NMConnection *connection,
                                           gboolean save_to_disk,
                                           GError **error)
{
	g_return_val_if_fail (config != NULL, NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	if (NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE (config)->add_connection)
		return NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE (config)->add_connection (config, connection, save_to_disk, error);

	return NULL;
}
