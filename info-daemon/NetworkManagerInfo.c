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

#include "NetworkManagerInfoDbus.h"
#include "NetworkManagerInfo.h"
#include "NetworkManagerInfoPassphraseDialog.h"


/*
 * nmi_get_next_priority
 *
 * Gets the next available worse priority
 *
 */
int nmi_get_next_priority (NMIAppInfo *info)
{
	GSList	*dir_list = NULL;
	GSList	*element = NULL;
	int		 worst_prio = 0;

	g_return_val_if_fail (info != NULL, 999);

	/* List all allowed access points that gconf knows about */
	element = dir_list = gconf_client_all_dirs (info->gconf_client, NMI_GCONF_TRUSTED_NETWORKS_PATH, NULL);
	if (!dir_list)
		return (10);

	while (element)
	{
		gchar		 key[100];
		GConfValue	*value;

		g_snprintf (&key[0], 99, "%s/priority", (char *)(element->data));
		if ((value = gconf_client_get (info->gconf_client, key, NULL)))
		{
			if (worst_prio < gconf_value_get_int (value))
				worst_prio = gconf_value_get_int (value);
			gconf_value_free (value);
		}

		g_free (element->data);
		element = g_slist_next (element);
	}
	g_slist_free (dir_list);

	return (worst_prio + 10);
}


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
		NMINetworkType	type = NETWORK_TYPE_UNKNOWN;
		int			trusted_path_len = strlen (NMI_GCONF_TRUSTED_NETWORKS_PATH) + 1;
		int			preferred_path_len = strlen (NMI_GCONF_PREFERRED_NETWORKS_PATH) + 1;
		int			len;

		/* Extract the network name from the key */
		if (strncmp (NMI_GCONF_TRUSTED_NETWORKS_PATH"/", key, trusted_path_len) == 0)
		{
			type = NETWORK_TYPE_TRUSTED;
			len = trusted_path_len;
		}
		else if (strncmp (NMI_GCONF_PREFERRED_NETWORKS_PATH"/", key, preferred_path_len) == 0)
		{
			type = NETWORK_TYPE_PREFERRED;
			len = preferred_path_len;
		}

		if (type != NETWORK_TYPE_UNKNOWN)
		{
			char 	*network = g_strdup ((key + len));
			char		*slash_pos;

			/* If its a key under the network name, zero out the slash so we
			 * are left with only the network name.
			 */
			if ((slash_pos = strchr (network, '/')))
				*slash_pos = '\0';

			nmi_dbus_signal_update_network (info->connection, network, type);
			g_free (network);
		}
	}
}


/*
 * nmi_print_usage
 *
 * Prints program usage.
 *
 */
static void nmi_print_usage (void)
{
	fprintf (stderr, "\n" "usage : NetworkManagerInfo [--daemon=yes|no] [--help]\n");
	fprintf (stderr,
		"\n"
		"        --daemon=yes|no    Become a daemon\n"
		"        --help             Show this information and exit\n"
		"\n"
		"NetworkManagerInfo responds to NetworkManager requests for allowed access points\n"
		"and WEP keys.\n"
		"\n");
}


/*
 * main
 *
 */
int main( int argc, char *argv[] )
{
	gboolean		 become_daemon = TRUE;
	DBusError		 dbus_error;
	DBusConnection	*dbus_connection;
	int			 err;
	NMIAppInfo	*app_info = NULL;
	GMainLoop		*loop;
	guint		 notify_id;

	/* Parse options */
	while (1)
	{
		int c;
		int option_index = 0;
		const char *opt;

		static struct option options[] = {
			{"daemon",	1, NULL, 0},
			{"help",		0, NULL, 0},
			{NULL,		0, NULL, 0}
		};

		c = getopt_long (argc, argv, "", options, &option_index);
		if (c == -1)
			break;

		switch (c)
		{
			case 0:
				opt = options[option_index].name;
				if (strcmp (opt, "help") == 0)
				{
					nmi_print_usage ();
					return 0;
				}
				else if (strcmp (opt, "daemon") == 0)
				{
					if (strcmp ("yes", optarg) == 0)
						become_daemon = TRUE;
					else if (strcmp ("no", optarg) == 0)
						become_daemon = FALSE;
					else
					{
						nmi_print_usage ();
						return 1;
					}
				}
				break;

			default:
				nmi_print_usage ();
				return 1;
				break;
		}
	}

	if (become_daemon)
	{
		int child_pid;

		if (chdir ("/") < 0)
		{
			fprintf( stderr, "NetworkManagerInfo could not chdir to /.  errno=%d", errno);
			return 1;
		}

		child_pid = fork ();
		switch (child_pid)
		{
			case -1:
				fprintf( stderr, "NetworkManagerInfo could not daemonize.  errno = %d\n", errno );
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
		fprintf (stderr, "Not enough memory for application data.\n");
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
		fprintf (stderr, "NetworkManagerInfo could not get the system bus.  Make sure the message bus daemon is running?\n");
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

	gtk_init (&argc, &argv);

	if (nmi_passphrase_dialog_init (app_info) != 0)
		exit (1);

	loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (loop);

	gconf_client_notify_remove (app_info->gconf_client, notify_id);
	g_object_unref (G_OBJECT (app_info->gconf_client));
	g_free (app_info);

	return 0;
}
