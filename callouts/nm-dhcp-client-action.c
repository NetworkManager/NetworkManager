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
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>

#define NM_DHCP_CLIENT_DBUS_SERVICE "org.freedesktop.nm_dhcp_client"
#define NM_DHCP_CLIENT_DBUS_IFACE   "org.freedesktop.nm_dhcp_client"

/**
 * Start a dict in a dbus message.  Should be paired with a call to
 * {@link wpa_dbus_dict_close_write}.
 *
 * @param iter A valid dbus message iterator
 * @param iter_dict (out) A dict iterator to pass to further dict functions
 * @return TRUE on success, FALSE on failure
 *
 */
static dbus_bool_t wpa_dbus_dict_open_write(DBusMessageIter *iter,
				     DBusMessageIter *iter_dict)
{
	dbus_bool_t result;

	if (!iter || !iter_dict)
		return FALSE;

	result = dbus_message_iter_open_container(
		iter,
		DBUS_TYPE_ARRAY,
		DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		DBUS_TYPE_STRING_AS_STRING
		DBUS_TYPE_VARIANT_AS_STRING
		DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
		iter_dict);
	return result;
}

/**
 * End a dict element in a dbus message.  Should be paired with
 * a call to {@link wpa_dbus_dict_open_write}.
 *
 * @param iter valid dbus message iterator, same as passed to
 *    wpa_dbus_dict_open_write()
 * @param iter_dict a dbus dict iterator returned from
 *    {@link wpa_dbus_dict_open_write}
 * @return TRUE on success, FALSE on failure
 *
 */
static dbus_bool_t wpa_dbus_dict_close_write(DBusMessageIter *iter,
				      DBusMessageIter *iter_dict)
{
	if (!iter || !iter_dict)
		return FALSE;

	return dbus_message_iter_close_container(iter, iter_dict);
}

static dbus_bool_t _wpa_dbus_add_dict_entry_start(
	DBusMessageIter *iter_dict, DBusMessageIter *iter_dict_entry,
	const char *key, const int value_type)
{
	if (!dbus_message_iter_open_container(iter_dict,
					      DBUS_TYPE_DICT_ENTRY, NULL,
					      iter_dict_entry))
		return FALSE;

	if (!dbus_message_iter_append_basic(iter_dict_entry, DBUS_TYPE_STRING,
					    &key))
		return FALSE;

	return TRUE;
}


static dbus_bool_t _wpa_dbus_add_dict_entry_end(
	DBusMessageIter *iter_dict, DBusMessageIter *iter_dict_entry,
	DBusMessageIter *iter_dict_val)
{
	if (!dbus_message_iter_close_container(iter_dict_entry, iter_dict_val))
		return FALSE;
	if (!dbus_message_iter_close_container(iter_dict, iter_dict_entry))
		return FALSE;

	return TRUE;
}

static dbus_bool_t _wpa_dbus_add_dict_entry_byte_array(
	DBusMessageIter *iter_dict, const char *key,
	const char *value, const dbus_uint32_t value_len)
{
	DBusMessageIter iter_dict_entry, iter_dict_val, iter_array;
	dbus_uint32_t i;

	if (!_wpa_dbus_add_dict_entry_start(iter_dict, &iter_dict_entry,
					    key, DBUS_TYPE_ARRAY))
		return FALSE;

	if (!dbus_message_iter_open_container(&iter_dict_entry,
					      DBUS_TYPE_VARIANT,
					      DBUS_TYPE_ARRAY_AS_STRING
					      DBUS_TYPE_BYTE_AS_STRING,
					      &iter_dict_val))
		return FALSE;

	if (!dbus_message_iter_open_container(&iter_dict_val, DBUS_TYPE_ARRAY,
					      DBUS_TYPE_BYTE_AS_STRING,
					      &iter_array))
		return FALSE;

	for (i = 0; i < value_len; i++) {
		if (!dbus_message_iter_append_basic(&iter_array,
						    DBUS_TYPE_BYTE,
						    &(value[i])))
			return FALSE;
	}

	if (!dbus_message_iter_close_container(&iter_dict_val, &iter_array))
		return FALSE;

	if (!_wpa_dbus_add_dict_entry_end(iter_dict, &iter_dict_entry,
					  &iter_dict_val))
		return FALSE;

	return TRUE;
}

/**
 * Add a byte array entry to the dict.
 *
 * @param iter_dict A valid DBusMessageIter returned from
 *    {@link wpa_dbus_dict_open_write}
 * @param key The key of the dict item
 * @param value The byte array
 * @param value_len The length of the byte array, in bytes
 * @return TRUE on success, FALSE on failure
 *
 */
static dbus_bool_t wpa_dbus_dict_append_byte_array(DBusMessageIter *iter_dict,
					    const char *key,
					    const char *value,
					    const dbus_uint32_t value_len)
{
	if (!key)
		return FALSE;
	if (!value && (value_len != 0))
		return FALSE;
	return _wpa_dbus_add_dict_entry_byte_array(iter_dict, key, value,
						   value_len);
}


static const char * ignore[] = {"PATH", "SHLVL", "_", "PWD", "dhc_dbus", NULL};

static dbus_bool_t
build_message (DBusMessage * message)
{
	char ** env = NULL;
	char ** item;
	char ** p;
	dbus_bool_t success = FALSE;
	DBusMessageIter iter, iter_dict;

	dbus_message_iter_init_append (message, &iter);
	if (!wpa_dbus_dict_open_write (&iter, &iter_dict))
		goto out;

	/* List environment and format for dbus dict */
	env = g_listenv ();
	for (item = env; *item; item++) {
		gboolean ignore_item = FALSE;
		const char * val = g_getenv (*item);

		/* Ignore non-DCHP-related environment variables */
		for (p = (char **) ignore; *p && !ignore_item; p++) {
			if (strncmp (*item, *p, strlen (*p)) == 0)
				ignore_item = TRUE;
		}
		if (ignore_item)
			continue;

		/* Value passed as a byte array rather than a string, because there are
		 * no character encoding guarantees with DHCP, and D-Bus requires
		 * strings to be UTF-8.
		 */
		if (!wpa_dbus_dict_append_byte_array (&iter_dict,
		                                      *item,
		                                      val ? val : "\0",
		                                      val ? strlen (val) : 1)) {
			fprintf (stderr, "Error: failed to add item '%s' to signal\n",
			         *item);
			goto out;
		}
	}

	if (!wpa_dbus_dict_close_write (&iter, &iter_dict))
		goto out;

	success = TRUE;

out:
	g_strfreev (env);
	return success;
}

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
	                             NM_DHCP_CLIENT_DBUS_SERVICE,
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
	DBusConnection * connection;
	DBusMessage * message;
	dbus_bool_t result;

	g_type_init ();

	/* Get a connection to the system bus */
	connection = dbus_init ();
	if (connection == NULL)
		exit (1);

	message = dbus_message_new_signal ("/", NM_DHCP_CLIENT_DBUS_IFACE, "Event");
	if (message == NULL) {
		fprintf (stderr, "Error: Not enough memory to send DHCP Event signal.\n");
		exit (1);
	}

	/* Dump environment variables into the message */
	result = build_message (message);
	if (result == FALSE) {
		fprintf (stderr, "Error: Not enough memory to send DHCP Event signal.\n");
		exit (1);
	}

	/* queue the message */
	result = dbus_connection_send (connection, message, NULL);
	if (!result) {
		fprintf (stderr, "Error: Could not send send DHCP Event signal.\n");
		exit (1);
	}
	dbus_message_unref (message);

	/* Send out the message */
	dbus_connection_flush (connection);

	return 0;
}

