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
 * Copyright (C) 2008 Red Hat, Inc.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>

#define NM_AVAHI_AUTOIPD_DBUS_SERVICE "org.freedesktop.nm_avahi_autoipd"
#define NM_AVAHI_AUTOIPD_DBUS_IFACE   "org.freedesktop.nm_avahi_autoipd"

static DBusConnection *
dbus_init (void)
{
	DBusConnection * connection;
	DBusError error;
	int ret;

	dbus_connection_set_change_sigpipe (TRUE);

	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (dbus_error_is_set (&error)) {
		fprintf (stderr, "Error: could not get the system bus.  Make sure "
		            "the message bus daemon is running!  Message: (%s) %s\n",
		            error.name,
		            error.message);
		goto error;
	}

	dbus_connection_set_exit_on_disconnect (connection, FALSE);

	dbus_error_init (&error);
	ret = dbus_bus_request_name (connection,
	                             NM_AVAHI_AUTOIPD_DBUS_SERVICE,
	                             DBUS_NAME_FLAG_DO_NOT_QUEUE,
	                             &error);
	if (dbus_error_is_set (&error)) {
		fprintf (stderr, "Error: Could not acquire the NM DHCP client service. "
		            "Message: (%s) %s\n",
		            error.name,
		            error.message);
		goto error;
	}

	if (ret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		fprintf (stderr, "Error: Could not acquire the NM DHCP client service "
		         "as it is already taken.  Return: %d\n",
		         ret);
		goto error;
	}

	return connection;

error:
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	if (connection)
		dbus_connection_unref (connection);
	return NULL;
}

int
main (int argc, char *argv[])
{
	DBusConnection *connection;
	DBusMessage *message;
	dbus_bool_t result;
	char *event, *iface, *address;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	if (argc != 4) {
		fprintf (stderr, "Error: expected 3 arguments (event, interface, address).\n");
		exit (1);
	}

	event = argv[1];
	iface = argv[2];
	address = argv[3] ? argv[3] : "";

	if (!event || !iface || !strlen (event) || !strlen (iface)) {
		fprintf (stderr, "Error: unexpected arguments received from avahi-autoipd.\n");
		exit (1);
	}

	/* Get a connection to the system bus */
	connection = dbus_init ();
	if (connection == NULL)
		exit (1);

	message = dbus_message_new_signal ("/", NM_AVAHI_AUTOIPD_DBUS_IFACE, "Event");
	if (message == NULL) {
		fprintf (stderr, "Error: not enough memory to send autoip Event signal.\n");
		exit (1);
	}

	if (!dbus_message_append_args (message,
	                               DBUS_TYPE_STRING, &event,
	                               DBUS_TYPE_STRING, &iface,
	                               DBUS_TYPE_STRING, &address,
	                               DBUS_TYPE_INVALID)) {
		fprintf (stderr, "Error: failed to construct autoip Event signal.\n");
		exit (1);
	}

	/* queue the message */
	result = dbus_connection_send (connection, message, NULL);
	if (!result) {
		fprintf (stderr, "Error: could not send send autoip Event signal.\n");
		exit (1);
	}
	dbus_message_unref (message);

	/* Send out the message */
	dbus_connection_flush (connection);

	return 0;
}

