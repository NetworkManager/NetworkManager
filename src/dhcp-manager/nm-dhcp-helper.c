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
 * Copyright (C) 2007 - 2013 Red Hat, Inc.
 */

/* for environ */
#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <config.h>

#include <dbus/dbus.h>

#define NM_DHCP_CLIENT_DBUS_IFACE   "org.freedesktop.nm_dhcp_client"

/**
 * _dbus_dict_open_write:
 * @iter: A valid dbus message iterator
 * @iter_dict: on return, a dict iterator to pass to further dict functions
 *
 * Start a dict in a dbus message.  Should be paired with a call to
 * _dbus_dict_close_write().
 *
 * Returns: %TRUE on success, %FALSE on failure
 */
static dbus_bool_t
_dbus_dict_open_write (DBusMessageIter *iter, DBusMessageIter *iter_dict)
{
	if (!iter || !iter_dict)
		return FALSE;

	return dbus_message_iter_open_container (iter,
	                                         DBUS_TYPE_ARRAY,
	                                         DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
	                                         DBUS_TYPE_STRING_AS_STRING
	                                         DBUS_TYPE_VARIANT_AS_STRING
	                                         DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
	                                         iter_dict);
}

/**
 * _dbus_dict_close_write:
 * @iter: valid dbus message iterator, same as passed to _dbus_dict_open_write()
 * @iter_dict: a dbus dict iterator returned from _dbus_dict_open_write()
 *
 * End a dict element in a dbus message.  Should be paired with a call to
 * _dbus_dict_open_write().
 *
 * Returns: %TRUE on success, %FALSE on failure
 */
static dbus_bool_t
_dbus_dict_close_write (DBusMessageIter *iter, DBusMessageIter *iter_dict)
{
	if (!iter || !iter_dict)
		return FALSE;

	return dbus_message_iter_close_container (iter, iter_dict);
}

static dbus_bool_t
_dbus_add_dict_entry_start (DBusMessageIter *iter_dict,
                            DBusMessageIter *iter_dict_entry,
                            const char *key,
                            const int value_type)
{
	if (!dbus_message_iter_open_container (iter_dict, DBUS_TYPE_DICT_ENTRY, NULL, iter_dict_entry))
		return FALSE;

	if (!dbus_message_iter_append_basic (iter_dict_entry, DBUS_TYPE_STRING, &key))
		return FALSE;

	return TRUE;
}


static dbus_bool_t
_dbus_add_dict_entry_end (DBusMessageIter *iter_dict,
                          DBusMessageIter *iter_dict_entry,
                          DBusMessageIter *iter_dict_val)
{
	if (!dbus_message_iter_close_container (iter_dict_entry, iter_dict_val))
		return FALSE;
	if (!dbus_message_iter_close_container (iter_dict, iter_dict_entry))
		return FALSE;

	return TRUE;
}

static dbus_bool_t
_dbus_add_dict_entry_byte_array (DBusMessageIter *iter_dict,
                                 const char *key,
                                 const char *value,
                                 const dbus_uint32_t value_len)
{
	DBusMessageIter iter_dict_entry, iter_dict_val, iter_array;
	dbus_uint32_t i;

	if (!_dbus_add_dict_entry_start (iter_dict, &iter_dict_entry, key, DBUS_TYPE_ARRAY))
		return FALSE;

	if (!dbus_message_iter_open_container (&iter_dict_entry,
	                                       DBUS_TYPE_VARIANT,
	                                       DBUS_TYPE_ARRAY_AS_STRING
	                                       DBUS_TYPE_BYTE_AS_STRING,
	                                       &iter_dict_val))
		return FALSE;

	if (!dbus_message_iter_open_container (&iter_dict_val,
	                                       DBUS_TYPE_ARRAY,
	                                       DBUS_TYPE_BYTE_AS_STRING,
	                                       &iter_array))
		return FALSE;

	for (i = 0; i < value_len; i++) {
		if (!dbus_message_iter_append_basic (&iter_array, DBUS_TYPE_BYTE, &(value[i])))
			return FALSE;
	}

	if (!dbus_message_iter_close_container (&iter_dict_val, &iter_array))
		return FALSE;

	if (!_dbus_add_dict_entry_end (iter_dict, &iter_dict_entry, &iter_dict_val))
		return FALSE;

	return TRUE;
}

/**
 * _dbus_dict_append_byte_array:
 * @iter_dict: A valid %DBusMessageIter returned from _dbus_dict_open_write()
 * @key: The key of the dict item
 * @value: The byte array
 * @value_len: The length of the byte array, in bytes
 *
 * Add a byte array entry to the dict.
 *
 * Returns: %TRUE on success, %FALSE on failure
 *
 */
static dbus_bool_t
_dbus_dict_append_byte_array (DBusMessageIter *iter_dict,
                              const char *key,
                              const char *value,
                              const dbus_uint32_t value_len)
{
	if (!key)
		return FALSE;
	if (!value && (value_len != 0))
		return FALSE;
	return _dbus_add_dict_entry_byte_array (iter_dict, key, value, value_len);
}


static const char * ignore[] = {"PATH", "SHLVL", "_", "PWD", "dhc_dbus", NULL};

static dbus_bool_t
build_message (DBusMessage * message)
{
	char **item;
	dbus_bool_t success = FALSE;
	DBusMessageIter iter, iter_dict;

	dbus_message_iter_init_append (message, &iter);
	if (!_dbus_dict_open_write (&iter, &iter_dict))
		goto out;

	/* List environment and format for dbus dict */
	for (item = environ; *item; item++) {
		char *name, *val, **p;

		/* Split on the = */
		name = strdup (*item);
		val = strchr (name, '=');
		if (!val)
			goto next;
		*val++ = '\0';
		if (!strlen (val))
			val = NULL;

		/* Ignore non-DCHP-related environment variables */
		for (p = (char **) ignore; *p; p++) {
			if (strncmp (name, *p, strlen (*p)) == 0)
				goto next;
		}

		/* Value passed as a byte array rather than a string, because there are
		 * no character encoding guarantees with DHCP, and D-Bus requires
		 * strings to be UTF-8.
		 */
		if (!_dbus_dict_append_byte_array (&iter_dict,
		                                      name,
		                                      val ? val : "\0",
		                                      val ? strlen (val) : 1)) {
			fprintf (stderr, "Error: failed to add item '%s' to signal\n", name);
		}

	next:
		free (name);
	}

	if (!_dbus_dict_close_write (&iter, &iter_dict))
		goto out;

	success = TRUE;

out:
	return success;
}

#if !HAVE_DBUS_GLIB_100
static DBusConnection *
shared_connection_init (void)
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

	dbus_error_init (&error);
	ret = dbus_bus_request_name (connection, "org.freedesktop.nm_dhcp_client", 0, &error);
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
#endif

static void
fatal_error (void)
{
	const char *pid_str = getenv ("pid");
	int pid = 0;

	if (pid_str)
		pid = strtol (pid_str, NULL, 10);
	if (pid) {
		fprintf (stderr, "Fatal error occured, killing dhclient instance with pid %d.\n", pid);
		kill (pid, SIGTERM);
	}

	exit (1);
}

int
main (int argc, char *argv[])
{
	DBusConnection *connection;
	DBusMessage *message;
	dbus_bool_t result;
	DBusError error;

	dbus_connection_set_change_sigpipe (TRUE);

	dbus_error_init (&error);
	connection = dbus_connection_open_private ("unix:path=" NMRUNDIR "/private-dhcp", &error);
	if (!connection) {
#if !HAVE_DBUS_GLIB_100
		connection = shared_connection_init ();
#endif
		if (!connection) {
			fprintf (stderr, "Error: could not connect to NetworkManager DBus socket: (%s) %s\n",
				     error.name, error.message);
			dbus_error_free (&error);
			fatal_error ();
		}
	}
	dbus_connection_set_exit_on_disconnect (connection, FALSE);

	message = dbus_message_new_signal ("/", NM_DHCP_CLIENT_DBUS_IFACE, "Event");
	if (message == NULL) {
		fprintf (stderr, "Error: Not enough memory to send DHCP Event signal.\n");
		fatal_error ();
	}

	/* Dump environment variables into the message */
	result = build_message (message);
	if (result == FALSE) {
		fprintf (stderr, "Error: Not enough memory to send DHCP Event signal.\n");
		fatal_error ();
	}

	/* queue the message */
	result = dbus_connection_send (connection, message, NULL);
	if (!result) {
		fprintf (stderr, "Error: Could not send send DHCP Event signal.\n");
		fatal_error ();
	}
	dbus_message_unref (message);

	/* Send out the message */
	dbus_connection_flush (connection);

	return 0;
}

