/*
 * nm-online.c - Are we online?
 *
 * Return values:
 *
 * 	0	: already online or connection established within given timeout
 *	1	: offline or not online within given timeout
 *	2	: unspecified error
 *
 * Robert Love <rml@novell.com>
 */

#define DBUS_API_SUBJECT_TO_CHANGE 1
#define PROGRESS_STEPS 15

#include <stdio.h>
#include <stdlib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>

#include "NetworkManager.h"

typedef struct 
{
	int value;
	double norm;
} Timeout;

static DBusHandlerResult dbus_filter (DBusConnection *connection G_GNUC_UNUSED,
				      DBusMessage *message,
				      void *user_data G_GNUC_UNUSED)
{
	if (!dbus_message_is_signal (message, NM_DBUS_INTERFACE,
				     "DeviceNowActive"))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	exit (0);
}

static gboolean check_online (DBusConnection *connection)
{
	DBusMessage *message, *reply;
	DBusError error;
	dbus_uint32_t state;
	
	message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH,
						NM_DBUS_INTERFACE, "state");
	if (!message)
		exit (2);

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message,
							   -1, &error);
	dbus_message_unref (message);
	if (!reply) 
		return FALSE;

	if (!dbus_message_get_args (reply, NULL, DBUS_TYPE_UINT32, &state,
				    DBUS_TYPE_INVALID))
		exit (2);

	if (state != NM_STATE_CONNECTED)
		return FALSE;

	return TRUE;
}

static gboolean handle_timeout (gpointer data)
{
	int i = PROGRESS_STEPS;
	Timeout *timeout = (Timeout *) data;

	g_print ("\rConnecting");
	for (; i > 0; i--)
		putchar ((timeout->value >= (i * timeout->norm)) ? ' ' : '.');
	if (timeout->value)
		g_print (" %4is", timeout->value);
	fflush (stdout);

	timeout->value--;
	if (timeout->value < 0)
		exit (1);

	return TRUE;
}

int main (int argc, char *argv[])
{
	DBusConnection *connection;
	DBusError error;
	GMainLoop *loop;
	Timeout timeout;
	
	timeout.value = 30;

	if (argc == 2) {
		timeout.value = (int) strtol (argv[1], NULL, 10);
		if (timeout.value <= 0 || timeout.value > 3600) 
			return 2;
	}

	g_type_init ();

	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (connection == NULL) {
		dbus_error_free (&error);
		return 2;
	}

	dbus_connection_setup_with_g_main (connection, NULL);

	if (!dbus_connection_add_filter (connection, dbus_filter, NULL, NULL))
		return 2;

	dbus_bus_add_match (connection,
			    "type='signal',"
			    "interface='" NM_DBUS_INTERFACE "',"
			    "sender='" NM_DBUS_SERVICE "',"
			    "path='" NM_DBUS_PATH "'", &error);
	if (dbus_error_is_set (&error)) {
		dbus_error_free (&error);
		return 2;
	}

	/* Check after we setup the filter to ensure that we cannot race. */
	if (check_online (connection))
		return 0;

	if (timeout.value) {
		timeout.norm = (double) timeout.value / (double) PROGRESS_STEPS;
		g_timeout_add (1000, handle_timeout, &timeout);
	}

	loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (loop);

	return 2;
}
