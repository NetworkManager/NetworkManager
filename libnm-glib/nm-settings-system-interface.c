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
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#include "nm-settings-interface.h"
#include "nm-settings-system-interface.h"


/**
 * nm_settings_system_interface_save_hostname:
 * @settings: a object implementing %NMSettingsSystemInterface
 * @hostname: the new persistent hostname to set, or NULL to clear any existing
 *  persistent hostname
 * @callback: callback to be called when the hostname operation completes
 * @user_data: caller-specific data passed to @callback
 *
 * Requests that the machine's persistent hostname be set to the specified value
 * or cleared.
 *
 * Returns: TRUE if the request was successful, FALSE if it failed
 **/
gboolean
nm_settings_system_interface_save_hostname (NMSettingsSystemInterface *settings,
                                            const char *hostname,
                                            NMSettingsSystemSaveHostnameFunc callback,
                                            gpointer user_data)
{
	g_return_val_if_fail (settings != NULL, FALSE);
	g_return_val_if_fail (NM_IS_SETTINGS_SYSTEM_INTERFACE (settings), FALSE);
	g_return_val_if_fail (hostname != NULL, FALSE);
	g_return_val_if_fail (callback != NULL, FALSE);

	if (NM_SETTINGS_SYSTEM_INTERFACE_GET_INTERFACE (settings)->save_hostname) {
		return NM_SETTINGS_SYSTEM_INTERFACE_GET_INTERFACE (settings)->save_hostname (settings,
		                                                                             hostname,
		                                                                             callback,
		                                                                             user_data);
	}
	return FALSE;
}

/**
 * nm_settings_system_interface_get_permissions:
 * @settings: a object implementing %NMSettingsSystemInterface
 * @callback: callback to be called when the permissions operation completes
 * @user_data: caller-specific data passed to @callback
 *
 * Requests an indication of the operations the caller is permitted to perform
 * including those that may require authorization.
 *
 * Returns: TRUE if the request was successful, FALSE if it failed
 **/
gboolean
nm_settings_system_interface_get_permissions (NMSettingsSystemInterface *settings,
                                              NMSettingsSystemGetPermissionsFunc callback,
                                              gpointer user_data)
{
	g_return_val_if_fail (settings != NULL, FALSE);
	g_return_val_if_fail (NM_IS_SETTINGS_SYSTEM_INTERFACE (settings), FALSE);
	g_return_val_if_fail (callback != NULL, FALSE);

	if (NM_SETTINGS_SYSTEM_INTERFACE_GET_INTERFACE (settings)->get_permissions)
		return NM_SETTINGS_SYSTEM_INTERFACE_GET_INTERFACE (settings)->get_permissions (settings, callback, user_data);
	return FALSE;
}

static void
nm_settings_system_interface_init (gpointer g_iface)
{
	GType iface_type = G_TYPE_FROM_INTERFACE (g_iface);
	static gboolean initialized = FALSE;

	if (initialized)
		return;

	/* Properties */
	g_object_interface_install_property
		(g_iface,
		 g_param_spec_string (NM_SETTINGS_SYSTEM_INTERFACE_HOSTNAME,
							  "Hostname",
							  "Persistent hostname",
							  NULL,
							  G_PARAM_READABLE));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_boolean (NM_SETTINGS_SYSTEM_INTERFACE_CAN_MODIFY,
		                       "CanModify",
		                       "Can modify anything (hostname, connections, etc)",
		                       FALSE,
		                       G_PARAM_READABLE));

	/* Signals */
	g_signal_new (NM_SETTINGS_SYSTEM_INTERFACE_CHECK_PERMISSIONS,
				  iface_type,
				  G_SIGNAL_RUN_FIRST,
				  G_STRUCT_OFFSET (NMSettingsSystemInterface, check_permissions),
				  NULL, NULL,
				  g_cclosure_marshal_VOID__VOID,
				  G_TYPE_NONE, 0);

	initialized = TRUE;
}

GType
nm_settings_system_interface_get_type (void)
{
	static GType itype = 0;

	if (!itype) {
		const GTypeInfo iinfo = {
			sizeof (NMSettingsSystemInterface), /* class_size */
			nm_settings_system_interface_init,   /* base_init */
			NULL,		/* base_finalize */
			NULL,
			NULL,		/* class_finalize */
			NULL,		/* class_data */
			0,
			0,              /* n_preallocs */
			NULL
		};

		itype = g_type_register_static (G_TYPE_INTERFACE,
		                                "NMSettingsSystemInterface",
		                                &iinfo, 0);

		g_type_interface_add_prerequisite (itype, NM_TYPE_SETTINGS_INTERFACE);
	}

	return itype;
}

