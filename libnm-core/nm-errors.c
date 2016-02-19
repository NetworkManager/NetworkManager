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
 * Copyright 2004 - 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>

#include "nm-errors.h"
#include "nm-vpn-dbus-interface.h"
#include "nm-core-internal.h"

G_DEFINE_QUARK (nm-agent-manager-error-quark, nm_agent_manager_error)
G_DEFINE_QUARK (nm-connection-error-quark, nm_connection_error)
G_DEFINE_QUARK (nm-crypto-error-quark, nm_crypto_error)
G_DEFINE_QUARK (nm-device-error-quark, nm_device_error)
G_DEFINE_QUARK (nm-manager-error-quark, nm_manager_error)
G_DEFINE_QUARK (nm-secret-agent-error-quark, nm_secret_agent_error)
G_DEFINE_QUARK (nm-settings-error-quark, nm_settings_error)
G_DEFINE_QUARK (nm-vpn-plugin-error-quark, nm_vpn_plugin_error)

static void
register_error_domain (GQuark domain,
                       const char *interface,
                       GType enum_type)
{
	GEnumClass *enum_class;
	GEnumValue *e;
	char *error_name;
	int i;

	enum_class = g_type_class_ref (enum_type);
	for (i = 0; i < enum_class->n_values; i++) {
		e = &enum_class->values[i];
		g_assert (strchr (e->value_nick, '-') == NULL);
		error_name = g_strdup_printf ("%s.%s", interface, e->value_nick);
		g_dbus_error_register_error (domain, e->value, error_name);
		g_free (error_name);
	}

	g_type_class_unref (enum_class);
}

void
_nm_dbus_errors_init (void)
{
	register_error_domain (NM_AGENT_MANAGER_ERROR,
	                       NM_DBUS_INTERFACE_AGENT_MANAGER,
	                       NM_TYPE_AGENT_MANAGER_ERROR);
	register_error_domain (NM_CONNECTION_ERROR,
	                       NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                       NM_TYPE_CONNECTION_ERROR);
	register_error_domain (NM_DEVICE_ERROR,
	                       NM_DBUS_INTERFACE_DEVICE,
	                       NM_TYPE_DEVICE_ERROR);
	register_error_domain (NM_MANAGER_ERROR,
	                       NM_DBUS_INTERFACE,
	                       NM_TYPE_MANAGER_ERROR);
	register_error_domain (NM_SECRET_AGENT_ERROR,
	                       NM_DBUS_INTERFACE_SECRET_AGENT,
	                       NM_TYPE_SECRET_AGENT_ERROR);
	register_error_domain (NM_SETTINGS_ERROR,
	                       NM_DBUS_INTERFACE_SETTINGS,
	                       NM_TYPE_SETTINGS_ERROR);
	register_error_domain (NM_SETTINGS_ERROR,
	                       NM_DBUS_INTERFACE_SETTINGS,
	                       NM_TYPE_SETTINGS_ERROR);
	register_error_domain (NM_VPN_PLUGIN_ERROR,
	                       NM_DBUS_VPN_ERROR_PREFIX,
	                       NM_TYPE_VPN_PLUGIN_ERROR);
}
