/* NetworkManagerInfo -- Manage allowed access points and provide a UI
 *                         for WEP key entry
 *
 * Dan Williams <dcbw@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2004 Red Hat, Inc.
 */

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <getopt.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <gconf/gconf-client.h>
#include <libgnome/gnome-init.h>
#include <libgnomeui/gnome-ui-init.h>
#include <sys/types.h>
#include <signal.h>
#include <libgnomevfs/gnome-vfs-utils.h>
#include "config.h"
#include "NetworkManagerInfoDbus.h"
#include "NetworkManagerInfo.h"
#include "NetworkManagerInfoPassphraseDialog.h"


/*
 * nmi_gconf_notify_callback
 *
 * Callback from gconf when wireless networking key/values have changed.
 *
 */
void nmi_gconf_notify_callback (GConfClient *client, guint connection_id, GConfEntry *entry, gpointer user_data)
{
	NMIAppInfo	*info = (NMIAppInfo *)user_data;
	const char	*key = NULL;

	g_return_if_fail (client != NULL);
	g_return_if_fail (entry != NULL);
	g_return_if_fail (info != NULL);

	if ((key = gconf_entry_get_key (entry)))
	{
		int	path_len = strlen (NMI_GCONF_WIRELESS_NETWORKS_PATH) + 1;

		if (strncmp (NMI_GCONF_WIRELESS_NETWORKS_PATH"/", key, path_len) == 0)
		{
			char 	*network = g_strdup ((key + path_len));
			char		*slash_pos;
			char		*escaped_network;

			/* If its a key under the network name, zero out the slash so we
			 * are left with only the network name.
			 */
			if ((slash_pos = strchr (network, '/')))
				*slash_pos = '\0';

			escaped_network = gnome_vfs_escape_string (network);
			nmi_dbus_signal_update_network (info->connection, network, NETWORK_TYPE_ALLOWED);
			g_free (escaped_network);
			g_free (network);
		}
	}
}


/*
 * main
 *
 */
int main( int argc, char *argv[] )
{
 	GnomeProgram 	*program;
	gboolean		 no_daemon;
	DBusError		 dbus_error;
	DBusConnection	*dbus_connection;
	int			 err;
	NMIAppInfo	*app_info = NULL;
	GMainLoop		*loop;
	guint		 notify_id;
	GError		*error;

	struct poptOption options[] =
	{
		{ "no-daemon", 'n', POPT_ARG_NONE, NULL, 0,
		  "Don't detatch from the console and run in the background.", NULL },
		{ NULL, '\0', 0, NULL, 0, NULL, NULL }
	};

	gchar *notification_icon_cmd[] = {LIBEXECDIR"/NetworkManagerNotification"};

	options[0].arg = &no_daemon;

	program = gnome_program_init ("NetworkManagerInfo", VERSION,
							LIBGNOMEUI_MODULE, argc, argv,
							GNOME_PROGRAM_STANDARD_PROPERTIES,
							GNOME_PARAM_POPT_TABLE, options,
							GNOME_PARAM_HUMAN_READABLE_NAME, "Network Manager User Info Service",
							NULL);

	openlog("NetworkManagerInfo", (no_daemon) ? LOG_CONS | LOG_PERROR : LOG_CONS, (no_daemon) ? LOG_USER : LOG_DAEMON);

	if (!no_daemon)
	{
		int child_pid;

		if (chdir ("/") < 0)
		{
			syslog( LOG_CRIT, "NetworkManagerInfo could not chdir to /.  errno=%d", errno);
			return 1;
		}

		child_pid = fork ();
		switch (child_pid)
		{
			case -1:
				syslog( LOG_ERR, "NetworkManagerInfo could not daemonize.  errno = %d", errno );
				break;

			case 0:
				/* Child */
				break;

			default:
				exit (0);
				break;
		}
	}

	app_info = g_new0 (NMIAppInfo, 1);
	if (!app_info)
	{
		syslog (LOG_CRIT, "Not enough memory for application data.");
		exit (1);
	}

	g_type_init ();
	if (!g_thread_supported ())
		g_thread_init (NULL);

	/* Set up our connection to the message bus */
	dbus_error_init (&dbus_error);
	dbus_connection = dbus_bus_get (DBUS_BUS_SYSTEM, &dbus_error);
	if (dbus_connection == NULL)
	{
		syslog (LOG_CRIT, "NetworkManagerInfo could not get the system bus.  Make sure the message bus daemon is running?");
		exit (1);
	}
	dbus_connection_set_change_sigpipe (TRUE);
	dbus_connection_set_exit_on_disconnect (dbus_connection, FALSE);
	dbus_connection_setup_with_g_main (dbus_connection, NULL);
	app_info->connection = dbus_connection;

	/* Grab a connection to the GConf daemon.  We also want to
	 * get change notifications for our wireless networking data.
	 */
	app_info->gconf_client = gconf_client_get_default ();
	gconf_client_add_dir (app_info->gconf_client, NMI_GCONF_WIRELESS_NETWORKING_PATH,
						GCONF_CLIENT_PRELOAD_NONE, NULL);
	notify_id = gconf_client_notify_add (app_info->gconf_client, NMI_GCONF_WIRELESS_NETWORKING_PATH,
						nmi_gconf_notify_callback, app_info, NULL, NULL);

	/* Create our own dbus service */
	err = nmi_dbus_service_init (dbus_connection, app_info);
	if (err == -1)
		exit (1);

	gnome_program_init ("NetworkManagerInfo", VERSION, LIBGNOMEUI_MODULE,
			   argc, argv,
			   GNOME_PARAM_NONE);


	app_info->notification_icon_pid = 0;

#ifdef BUILD_NOTIFICATION_ICON
	/*spawn the panel notification icon*/
	if (!g_spawn_async (NULL,
			    notification_icon_cmd,
			    NULL, 0, NULL, NULL,
			    &(app_info->notification_icon_pid),
			    &error))
	{
		g_warning ("Could not spawn NetworkManager's notification icon (%s)", error->message);
		g_error_free (error);
	}

#endif

	if (nmi_passphrase_dialog_init (app_info) != 0)
		exit (1);

	gtk_main ();

	if (app_info->notification_icon_pid > 0)
		kill (app_info->notification_icon_pid, SIGTERM);

	gconf_client_notify_remove (app_info->gconf_client, notify_id);
	g_object_unref (G_OBJECT (app_info->gconf_client));
	/*g_object_unref (app_info->notification_icon);*/
	g_free (app_info);

	return 0;
}
