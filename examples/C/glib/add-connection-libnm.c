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
 * Copyright 2011 Red Hat, Inc.
 */

/*
 * The example shows how to add a new connection using libnm.  Contrast this
 * example with add-connection-gdbus.c, which is a bit lower level and talks
 * directly to NM using GDBus.  This example is simpler because libnm handles
 * much of the low-level stuff for you.
 *
 * Compile with:
 *   gcc -Wall add-connection-libnm.c -o add-connection-libnm `pkg-config --libs --cflags libnm`
 */

#include <glib.h>
#include <NetworkManager.h>

static void
added_cb (GObject *client,
          GAsyncResult *result,
          gpointer user_data)
{
	GMainLoop *loop = user_data;
	NMRemoteConnection *remote;
	GError *error = NULL;

	/* NM responded to our request; either handle the resulting error or
	 * print out the object path of the connection we just added.
	 */
	remote = nm_client_add_connection_finish (NM_CLIENT (client), result, &error);

	if (error) {
		g_print ("Error adding connection: %s", error->message);
		g_error_free (error);
	} else {
		g_print ("Added: %s\n", nm_connection_get_path (NM_CONNECTION (remote)));
		g_object_unref (remote);
	}

	/* Tell the mainloop we're done and we can quit now */
	g_main_loop_quit (loop);
}

static void
add_connection (NMClient *client, GMainLoop *loop, const char *con_name)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIP4Config *s_ip4;
	char *uuid;

	/* Create a new connection object */
	connection = nm_simple_connection_new ();

	/* Build up the 'connection' Setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	uuid = nm_utils_uuid_generate ();
	g_object_set (G_OBJECT (s_con),
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_ID, con_name,
	              NM_SETTING_CONNECTION_TYPE, "802-3-ethernet",
	              NULL);
	g_free (uuid);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	/* Build up the 'wired' Setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* Build up the 'ipv4' Setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	g_object_set (G_OBJECT (s_ip4),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	/* Ask the settings service to add the new connection; we'll quit the
	 * mainloop and exit when the callback is called.
	 */
	nm_client_add_connection_async (client, connection, TRUE, NULL, added_cb, loop);
	g_object_unref (connection);
}

int
main (int argc, char *argv[])
{
	NMClient *client;
	GMainLoop *loop;
	GError *error = NULL;

	loop = g_main_loop_new (NULL, FALSE);

	/* Connect to NetworkManager */
	client = nm_client_new (NULL, &error);
	if (!client) {
		g_message ("Error: Could not connect to NetworkManager: %s.", error->message);
		g_error_free (error);
		return 1;
	}

	/* Ask NM to add the new connection */
	add_connection (client, loop, "__Test connection__");
	/* Wait for the connection to be added */
	g_main_loop_run (loop);

	/* Clean up */
	g_object_unref (client);

	return 0;
}
