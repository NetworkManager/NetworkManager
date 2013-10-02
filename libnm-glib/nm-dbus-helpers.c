/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
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
 * Copyright (C) 2013 Red Hat, Inc.
 */

#include <string.h>
#include <config.h>
#include <gio/gio.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include "nm-dbus-helpers-private.h"
#include "NetworkManager.h"

static dbus_int32_t priv_slot = -1;

static gboolean
_ensure_dbus_data_slot (void)
{
	static gsize init_value = 0;
	gboolean success = TRUE;

	if (g_once_init_enter (&init_value)) {
		success = dbus_connection_allocate_data_slot (&priv_slot);
		g_once_init_leave (&init_value, 1);
	}
	return success;
}

DBusGConnection *
_nm_dbus_new_connection (GError **error)
{
	DBusGConnection *connection = NULL;

	if (!_ensure_dbus_data_slot ()) {
		g_set_error (error, DBUS_GERROR, DBUS_GERROR_FAILED, "failed to allocated data slot");
		return NULL;
	}

#if HAVE_DBUS_GLIB_100
	/* If running as root try the private bus first */
	if (0 == geteuid ()) {
		connection = dbus_g_connection_open ("unix:path=" NMRUNDIR "/private", error);
		if (connection) {
			DBusConnection *dbus_connection = dbus_g_connection_get_connection (connection);

			/* Mark this connection as private */
			dbus_connection_set_data (dbus_connection, priv_slot, GUINT_TO_POINTER (TRUE), NULL);
			dbus_connection_set_exit_on_disconnect (dbus_connection, FALSE);
			return connection;
		}
		/* Fall back to a bus if for some reason private socket isn't available */
		g_clear_error (error);
	}
#endif

	if (connection == NULL) {
#ifdef LIBNM_GLIB_TEST
		connection = dbus_g_bus_get (DBUS_BUS_SESSION, error);
#else
		connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, error);
#endif
	}

	return connection;
}

gboolean
_nm_dbus_is_connection_private (DBusGConnection *connection)
{
	if (!_ensure_dbus_data_slot ())
		return FALSE;
	return !!dbus_connection_get_data (dbus_g_connection_get_connection (connection), priv_slot);
}

DBusGProxy *
_nm_dbus_new_proxy_for_connection (DBusGConnection *connection,
                                   const char *path,
                                   const char *interface)
{
	/* Private connections can't use dbus_g_proxy_new_for_name() or
	 * dbus_g_proxy_new_for_name_owner() because peer-to-peer connections don't
	 * have either a bus daemon or name owners, both of which those functions
	 * require.
	 */
	if (_nm_dbus_is_connection_private (connection))
		return dbus_g_proxy_new_for_peer (connection, path, interface);

	return dbus_g_proxy_new_for_name (connection, NM_DBUS_SERVICE, path, interface);
}

