// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2012 Red Hat, Inc.
 */

/*
 * This example monitors NM state via D-Bus "StateChanged" signal on
 * "org.freedesktop.NetworkManager" object.
 * It uses GDBus and the libnm headers.

 * You don't need to have the NetworkManager devel packages installed. You can just
 * grab nm-dbus-interface.h and put it in the path.
 *
 * Standalone compilation:
 *   gcc -Wall monitor-nm-state-gdbus.c -o monitor-nm-state-gdbus `pkg-config --cflags --libs libnm`
 */

#include <gio/gio.h>
#include <string.h>
#include <nm-dbus-interface.h>

static const char *
nm_state_to_string (NMState state)
{
	switch (state) {
	case NM_STATE_ASLEEP:
		return "asleep";
	case NM_STATE_CONNECTING:
		return "connecting";
	case NM_STATE_CONNECTED_LOCAL:
		return "connected (local only)";
	case NM_STATE_CONNECTED_SITE:
		return "connected (site only)";
	case NM_STATE_CONNECTED_GLOBAL:
		return "connected";
	case NM_STATE_DISCONNECTING:
		return "disconnecting";
	case NM_STATE_DISCONNECTED:
		return "disconnected";
	case NM_STATE_UNKNOWN:
	default:
		return "unknown";
	}
}

static void
on_signal (GDBusProxy *proxy,
           char       *sender_name,
           char       *signal_name,
           GVariant   *parameters,
           gpointer    user_data)
{
	guint32 new_state;

	/* Print all signals */
	//char *parameters_str;
	//parameters_str = g_variant_print (parameters, TRUE);
	//g_print (" *** Received Signal: %s: %s\n", signal_name, parameters_str);
	//g_free (parameters_str);

	/* We are only interested in "StateChanged" signal */
	if (strcmp (signal_name, "StateChanged") == 0) {
		GVariant *tmp = g_variant_get_child_value (parameters, 0);
		new_state = g_variant_get_uint32 (tmp);
		g_variant_unref (tmp);
		g_print ("NetworkManager state is: (%d) %s\n", new_state, nm_state_to_string ((NMState) new_state));
	}
}

int
main (int argc, char *argv[])
{
	GMainLoop *loop;
	GError *error = NULL;
	GDBusProxyFlags flags;
	GDBusProxy *proxy;

	/* Monitor 'StateChanged' signal on 'org.freedesktop.NetworkManager' interface */
	g_print ("Monitor NetworkManager's state\n");
	g_print ("==============================\n");

	flags = G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES | G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START;
	proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
                                           flags,
                                           NULL, /* GDBusInterfaceInfo */
                                           "org.freedesktop.NetworkManager",
                                           "/org/freedesktop/NetworkManager",
                                           "org.freedesktop.NetworkManager",
                                           NULL, /* GCancellable */
                                           &error);

	if (proxy == NULL)
	{
		g_dbus_error_strip_remote_error (error);
		g_printerr ("Error creating D-Bus proxy: %s\n", error->message);
		g_error_free (error);
		return -1;
	}

	/* Connect to g-signal to receive signals from proxy (remote object) */
	g_signal_connect (proxy,
	                  "g-signal",
	                  G_CALLBACK (on_signal),
	                  NULL);

	/* Run main loop */
	loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (loop);

	g_object_unref (proxy);

	return 0;
}

