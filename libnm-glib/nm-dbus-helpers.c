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
 * Copyright 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "nm-dbus-helpers-private.h"
#include "NetworkManager.h"

DBusGConnection *
_nm_dbus_new_connection (GError **error)
{
	DBusGConnection *connection = NULL;

	if (connection == NULL)
		connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, error);

	return connection;
}

DBusGProxy *
_nm_dbus_new_proxy_for_connection (DBusGConnection *connection,
                                   const char *path,
                                   const char *interface)
{
	return dbus_g_proxy_new_for_name (connection, NM_DBUS_SERVICE, path, interface);
}
