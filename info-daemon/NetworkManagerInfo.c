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

#include <libgnomeui/gnome-client.h>
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

static void nmi_spawn_notification_icon (NMIAppInfo *info);



/*
 * nmi_gconf_get_wireless_scan_method
 *
 * Grab the wireless scan method from GConf
 *
 */
NMWirelessScanMethod nmi_gconf_get_wireless_scan_method (NMIAppInfo *info)
{
	NMWirelessScanMethod	method = NM_SCAN_METHOD_ALWAYS;
	GConfEntry *			entry;

	g_return_val_if_fail (info, NM_SCAN_METHOD_ALWAYS);
	g_return_val_if_fail (info->gconf_client, NM_SCAN_METHOD_ALWAYS);

	if ((entry = gconf_client_get_entry (info->gconf_client, NMI_GCONF_WIRELESS_PATH "/scan_method", NULL, TRUE, NULL)))
	{
		GConfValue *	value = gconf_entry_get_value (entry);

		if (value && (value->type == GCONF_VALUE_INT))
		{
			NMWirelessScanMethod	temp_method = gconf_value_get_int (value);

			if ((method == NM_SCAN_METHOD_ALWAYS) || (method == NM_SCAN_METHOD_NEVER) || (method == NM_SCAN_METHOD_WHEN_UNASSOCIATED))
				method = temp_method;
		}
	}

	return method;
}


/*
 * nmi_gconf_prefs_notify_callback
 *
 * Callback from gconf when wireless key/values have changed.
 *
 */
void nmi_gconf_prefs_notify_callback (GConfClient *client, guint connection_id, GConfEntry *entry, gpointer user_data)
{
	NMIAppInfo	*info = (NMIAppInfo *)user_data;
	const char	*key = NULL;

	g_return_if_fail (client != NULL);
	g_return_if_fail (entry != NULL);
	g_return_if_fail (info != NULL);

	if ((key = gconf_entry_get_key (entry)))
	{
		int	net_path_len = strlen (NMI_GCONF_WIRELESS_PATH) + 1;

		if (strcmp (NMI_GCONF_WIRELESS_PATH "/scan_method", key) == 0)
		{
			GConfValue *	value = gconf_entry_get_value (entry);

			if (value && (value->type == GCONF_VALUE_INT))
			{
				NMWirelessScanMethod	method = gconf_value_get_int (value);

				if ((method == NM_SCAN_METHOD_ALWAYS) || (method == NM_SCAN_METHOD_NEVER) || (method == NM_SCAN_METHOD_WHEN_UNASSOCIATED))
					nmi_dbus_signal_update_scan_method (info->connection);
			}
		}
		if (strncmp (NMI_GCONF_WIRELESS_NETWORKS_PATH"/", key, net_path_len) == 0)
		{
			char 	*network = g_strdup ((key + net_path_len));
			char		*slash_pos;
			char		*unescaped_network;

			/* If its a key under the network name, zero out the slash so we
			 * are left with only the network name.
			 */
			unescaped_network = gconf_unescape_key (network, strlen (network));
			if ((slash_pos = strchr (unescaped_network, '/')))
				*slash_pos = '\0';

			nmi_dbus_signal_update_network (info->connection, unescaped_network, NETWORK_TYPE_ALLOWED);
			g_free (unescaped_network);
			g_free (network);
		}
	}
}


#ifdef BUILD_NOTIFICATION_ICON
static void 
on_icon_exit_callback (GPid pid, int status, gpointer data)
{
	NMIAppInfo *info;
	info = (NMIAppInfo *) data;

	nmi_spawn_notification_icon (info);
}

static void 
nmi_spawn_notification_icon (NMIAppInfo *info)
{
	GError *error;

	gchar *notification_icon_cmd[] = {LIBEXECDIR"/NetworkManagerNotification", NULL};

	if (info->notification_icon_pid > 0)
		g_spawn_close_pid (info->notification_icon_pid);

	if (info->notification_icon_watch != 0)
		g_source_remove (info->notification_icon_watch);

	if (info->notification_icon_respawn_timer == NULL)
		info->notification_icon_respawn_timer = g_timer_new();
	else
	{
		gdouble elapsed_time;
		gulong dummy;

		elapsed_time = g_timer_elapsed (info->notification_icon_respawn_timer, &dummy);
		
		/*5 seconds between respawns*/
		if (elapsed_time > 5)
			info->notification_icon_respawn_counter = 0;
		else
			info->notification_icon_respawn_counter++;
			
	}

	g_timer_start (info->notification_icon_respawn_timer);

	/*spawn the panel notification icon unless it has crashed numerous times within a time frame*/
	if (info->notification_icon_respawn_counter < 5) 
	{
		if (!g_spawn_async (NULL,
				    notification_icon_cmd,
				    NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
				    &(info->notification_icon_pid),
				    &error))
		{
			g_warning ("Could not spawn NetworkManager's notification icon (%s)", error->message);
			g_error_free (error);
		}
		else
		{
			info->notification_icon_watch = g_child_watch_add (info->notification_icon_pid, on_icon_exit_callback, info);
		}
	} else {
		g_timer_destroy (info->notification_icon_respawn_timer);
		info->notification_icon_respawn_timer = NULL;
	}
}

#endif

static void session_die (GnomeClient *client, gpointer client_data)
{
        gtk_main_quit ();
}

static gboolean session_save (GnomeClient *client, gpointer client_data)
{
        return TRUE;
}


/*
 * main
 *
 */
int main( int argc, char *argv[] )
{
 	GnomeProgram 	*program;
	GnomeClient *client;
	GPtrArray *restart_argv;
	gboolean		 no_daemon;
	DBusError		 dbus_error;
	DBusConnection	*dbus_connection;
	int			 err;
	NMIAppInfo	*app_info = NULL;
	guint		 notify_id;

	struct poptOption options[] =
	{
		{ "no-daemon", 'n', POPT_ARG_NONE, NULL, 0,
		  "Don't detatch from the console and run in the background.", NULL },
		{ NULL, '\0', 0, NULL, 0, NULL, NULL }
	};

	options[0].arg = &no_daemon;

	program = gnome_program_init ("NetworkManagerInfo", VERSION,
							LIBGNOMEUI_MODULE, argc, argv,
							GNOME_PROGRAM_STANDARD_PROPERTIES,
							GNOME_PARAM_POPT_TABLE, options,
							GNOME_PARAM_HUMAN_READABLE_NAME, "Network Manager User Info Service",
							NULL);

	client = gnome_master_client ();

	openlog("NetworkManagerInfo", (no_daemon) ? LOG_CONS | LOG_PERROR : LOG_CONS, (no_daemon) ? LOG_USER : LOG_DAEMON);

	if (!no_daemon && daemon (FALSE, FALSE) < 0)
	{
		syslog( LOG_ERR, "NetworkManagerInfo could not daemonize.  errno = %d", errno );
		exit (1);
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
	gconf_client_add_dir (app_info->gconf_client, NMI_GCONF_WIRELESS_PATH, GCONF_CLIENT_PRELOAD_NONE, NULL);
	notify_id = gconf_client_notify_add (app_info->gconf_client, NMI_GCONF_WIRELESS_PATH,
						nmi_gconf_prefs_notify_callback, app_info, NULL, NULL);

	/* Create our own dbus service */
	err = nmi_dbus_service_init (dbus_connection, app_info);
	if (err == -1)
		exit (1);

	gnome_program_init ("NetworkManagerInfo", VERSION, LIBGNOMEUI_MODULE,
			   argc, argv,
			   GNOME_PARAM_NONE);


	app_info->notification_icon_pid = 0;

#ifdef BUILD_NOTIFICATION_ICON
	nmi_spawn_notification_icon (app_info);
#endif

	restart_argv = g_ptr_array_new ();
        g_ptr_array_add (restart_argv, g_get_prgname ());
        gnome_client_set_restart_command (client, restart_argv->len, (char**) restart_argv->pdata);
        g_ptr_array_free (restart_argv, TRUE);
        gnome_client_set_restart_style (client, GNOME_RESTART_IMMEDIATELY);

	if (nmi_passphrase_dialog_init (app_info) != 0)
	{
		gnome_client_set_restart_style (client, GNOME_RESTART_ANYWAY);
		exit (1);
	}

	g_signal_connect (client,
                          "save_yourself",
                          G_CALLBACK (session_save),
                          NULL);

        g_signal_connect (client,
                          "die",
                          G_CALLBACK (session_die),
                          NULL);

	gtk_main ();

	if (app_info->notification_icon_pid > 0)
		kill (app_info->notification_icon_pid, SIGTERM);

	gnome_client_set_restart_style (client, GNOME_RESTART_ANYWAY);

	gconf_client_notify_remove (app_info->gconf_client, notify_id);
	g_object_unref (G_OBJECT (app_info->gconf_client));
	/*g_object_unref (app_info->notification_icon);*/
	g_free (app_info);

	return 0;
}
