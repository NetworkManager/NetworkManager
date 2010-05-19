/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2008 - 2010 Red Hat, Inc.
 */

#include <glib.h>
#include "nm-active-connection.h"
#include "NetworkManager.h"
#include "nm-active-connection-glue.h"
#include "nm-logging.h"

char *
nm_active_connection_get_next_object_path (void)
{
	static guint32 counter = 0;

	return g_strdup_printf (NM_DBUS_PATH "/ActiveConnection/%d", counter++);
}

void
nm_active_connection_install_type_info (GObjectClass *klass)
{
	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_active_connection_object_info);
}

void
nm_active_connection_scope_to_value (NMConnection *connection, GValue *value)
{
	if (!connection) {
		g_value_set_string (value, "");
		return;
	}

	switch (nm_connection_get_scope (connection)) {
	case NM_CONNECTION_SCOPE_SYSTEM:
		g_value_set_string (value, NM_DBUS_SERVICE_SYSTEM_SETTINGS);
		break;
	case NM_CONNECTION_SCOPE_USER:
		g_value_set_string (value, NM_DBUS_SERVICE_USER_SETTINGS);
		break;
	default:
		nm_log_err (LOGD_CORE, "unknown connection scope!");
		break;
	}
}


