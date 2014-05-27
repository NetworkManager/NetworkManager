/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* vim: set ft=c ts=4 sts=4 sw=4 noexpandtab smartindent: */
/*
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
 * (C) Copyright 2012 Red Hat, Inc.
 */

/*
 * This example monitors NM state via D-Bus "StateChanged" signal on
 * "org.freedesktop.NetworkManager" object.
 * It uses GDBus.

 * You don't need to have NetworkManager devel package installed. You can just
 * grab NetworkManager.h and put it in the path.
 *
 * Standalone compilation:
 *   gcc -Wall `pkg-config --libs --cflags glib-2.0 gio-2.0 NetworkManager` monitor-nm-state-GDBus.c -o monitor-nm-state-GDBus
 */

#include <gio/gio.h>
#include <string.h>
#include <NetworkManager.h>

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
           gchar      *sender_name,
           gchar      *signal_name,
           GVariant   *parameters,
           gpointer    user_data)
{
	guint32 new_state;

	/* Print all signals */
	//gchar *parameters_str;
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

#if !GLIB_CHECK_VERSION (2, 35, 0)
	/* Initialize GType system */
	g_type_init ();
#endif

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

