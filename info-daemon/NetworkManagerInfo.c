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


/*
 * nmi_clear_dialog
 *
 * Return dialog to its original state; clear out any network or device qdatas,
 * clear the passphrase entry, and hide the dialog.
 *
 */
static void nmi_clear_dialog (GtkWidget *dialog, GtkWidget *entry)
{
	char 	*data;

	g_return_if_fail (dialog != NULL);
	g_return_if_fail (entry  != NULL);

	data = g_object_get_data (G_OBJECT (dialog), "device");
	if (data)
	{
		g_free (data);
		g_object_set_data (G_OBJECT (dialog), "device", NULL);
	}

	data = g_object_get_data (G_OBJECT (dialog), "network");
	if (data)
	{
		g_free (data);
		g_object_set_data (G_OBJECT (dialog), "network", NULL);
	}

	gtk_entry_set_text (GTK_ENTRY (entry), "");
	gtk_widget_hide (dialog);
}


/*
 * ok_button_clicked
 *
 * OK button handler; grab the passphrase and send it back
 * to NetworkManager.  Get rid of the dialog.
 *
 */
static void ok_button_clicked (GtkWidget *ok_button, gpointer user_data)
{
	GtkWidget		*dialog = gtk_widget_get_toplevel (ok_button);
	NMIAppInfo	*info = (NMIAppInfo *)user_data;

	g_return_if_fail (info != NULL);

	if (GTK_WIDGET_TOPLEVEL (dialog))
	{
		GtkWidget		*entry = glade_xml_get_widget (info->xml, "passphrase_entry");
		const char	*passphrase = gtk_entry_get_text (GTK_ENTRY (entry));
		const char	*device = g_object_get_data (G_OBJECT (dialog), "device");
		const char	*network = g_object_get_data (G_OBJECT (dialog), "network");

		nmi_dbus_return_user_key (info->connection, device, network, passphrase);
		nmi_clear_dialog (dialog, entry);
	}
}


/*
 * cancel_button_clicked
 *
 * Cancel button handler; return a cancellation message to NetworkManager
 * and get rid of the dialog.
 *
 */
static void cancel_button_clicked (GtkWidget *cancel_button, gpointer user_data)
{
	GtkWidget 	*dialog = gtk_widget_get_toplevel (cancel_button);
	NMIAppInfo	*info = (NMIAppInfo *)user_data;

	g_return_if_fail (info != NULL);

	if (GTK_WIDGET_TOPLEVEL (dialog))
	{
		const char	*device = g_object_get_data (G_OBJECT (dialog), "device");
		const char	*network = g_object_get_data (G_OBJECT (dialog), "network");

		nmi_dbus_return_user_key (info->connection, device, network, "***cancelled***");
		nmi_clear_dialog (dialog, glade_xml_get_widget (info->xml, "passphrase_entry"));
	}
}


/*
 * nmi_show_user_key_dialog
 *
 * Pop up the user key dialog in response to a dbus message
 *
 */
void nmi_show_user_key_dialog (const char *device, const char *network, NMIAppInfo *info)
{
	GtkWidget			*dialog;
	GtkWidget			*label;
	const gchar		*label_text;

	g_return_if_fail (info != NULL);
	g_return_if_fail (device != NULL);
	g_return_if_fail (network != NULL);

	dialog = glade_xml_get_widget (info->xml, "passphrase_dialog");
	nmi_clear_dialog (dialog, glade_xml_get_widget (info->xml, "passphrase_entry"));

	/* Insert the Network name into the dialog text */
	label  = glade_xml_get_widget (info->xml, "label1");
	label_text = gtk_label_get_label (GTK_LABEL (label));
	if (label_text)
	{
		gchar *new_label_text = g_strdup_printf (label_text, network);
		gtk_label_set_label (GTK_LABEL (label), new_label_text);
	}

	g_object_set_data (G_OBJECT (dialog), "device", g_strdup (device));
	g_object_set_data (G_OBJECT (dialog), "network", g_strdup (network));

	gtk_widget_show (dialog);
}


/*
 * nmi_cancel_user_key_dialog
 *
 * Cancel and hide any user key dialog that might be up
 *
 */
void nmi_cancel_user_key_dialog (NMIAppInfo *info)
{
	GtkWidget		*dialog;
	GtkWidget		*entry;

	g_return_if_fail (info != NULL);

	dialog = glade_xml_get_widget (info->xml, "passphrase_dialog");
	entry  = glade_xml_get_widget (info->xml, "passphrase_entry");
	nmi_clear_dialog (dialog, entry);
}


/*
 * nmi_interface_init
 *
 * Initialize the UI pieces of NMI.
 *
 */
static void nmi_interface_init (NMIAppInfo *info)
{
	GtkWidget		*dialog;
	GtkButton		*ok_button;
	GtkButton		*cancel_button;
	GtkEntry		*entry;

	info->xml = glade_xml_new(GLADEDIR"/passphrase.glade", NULL, NULL);
	if (!info->xml)
	{
		fprintf (stderr, "Could not open glade file!\n");
		exit (1);
	}
	
	dialog = glade_xml_get_widget (info->xml, "passphrase_dialog");
	gtk_widget_hide (dialog);

	ok_button = GTK_BUTTON (glade_xml_get_widget (info->xml, "login_button"));
	g_signal_connect (GTK_OBJECT (ok_button), "clicked", GTK_SIGNAL_FUNC (ok_button_clicked), info);
	gtk_widget_grab_default (GTK_WIDGET (ok_button));
	cancel_button = GTK_BUTTON (glade_xml_get_widget (info->xml, "cancel_button"));
	g_signal_connect (GTK_OBJECT (cancel_button), "clicked", GTK_SIGNAL_FUNC (cancel_button_clicked), info);

	entry = GTK_ENTRY (glade_xml_get_widget (info->xml, "passphrase_entry"));
	gtk_entry_set_visibility (entry, FALSE);
	gtk_entry_set_invisible_char (entry, '*');

	nmi_clear_dialog (dialog, GTK_WIDGET (entry));
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

	key = gconf_entry_get_key (entry);
	if (key)
	{
		static int	gconf_path_len = 0;

		if (!gconf_path_len)
			gconf_path_len = strlen (NMI_GCONF_ALLOWED_NETWORKS_PATH) + 1;

		/* Extract the network name from the key */
		if (strncmp (NMI_GCONF_ALLOWED_NETWORKS_PATH"/", key, gconf_path_len) == 0)
		{
			char 	*network = g_strdup ((key + gconf_path_len));
			char		*slash_pos;

			/* If its a key under the network name, zero out the slash so we
			 * are left with only the network name.
			 */
			if ((slash_pos = strchr (network, '/')))
				*slash_pos = '\0';

			nmi_dbus_signal_update_allowed_network (info->connection, network);
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

	nmi_interface_init (app_info);

	loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (loop);

	gconf_client_notify_remove (app_info->gconf_client, notify_id);
	g_object_unref (G_OBJECT (app_info->gconf_client));
	g_free (app_info);

	return 0;
}
