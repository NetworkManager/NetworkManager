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

#include <stdio.h>
#include <stdlib.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

#include "NetworkManagerInfoDbus.h"
#include "NetworkManagerInfoPassphraseDialog.h"


/*
 * nmi_passphrase_dialog_clear
 *
 * Return dialog to its original state; clear out any network or device qdatas,
 * clear the passphrase entry, and hide the dialog.
 *
 */
void nmi_passphrase_dialog_clear (GtkWidget *dialog, GtkWidget *entry)
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
 * nmi_passphrase_dialog_ok_clicked
 *
 * OK button handler; grab the passphrase and send it back
 * to NetworkManager.  Get rid of the dialog.
 *
 */
void nmi_passphrase_dialog_ok_clicked (GtkWidget *ok_button, gpointer user_data)
{
	GtkWidget		*dialog = gtk_widget_get_toplevel (ok_button);
	NMIAppInfo	*info = (NMIAppInfo *)user_data;

	g_return_if_fail (info != NULL);

	if (GTK_WIDGET_TOPLEVEL (dialog))
	{
		GtkWidget		*entry = glade_xml_get_widget (info->passphrase_dialog, "passphrase_entry");
		const char	*passphrase = gtk_entry_get_text (GTK_ENTRY (entry));
		const char	*device = g_object_get_data (G_OBJECT (dialog), "device");
		const char	*network = g_object_get_data (G_OBJECT (dialog), "network");
		gchar		*key = NULL;
		GConfEntry	*gconf_entry;

		/* Tell NetworkManager about the key the user typed in */
		nmi_dbus_return_user_key (info->connection, device, network, passphrase);

		/* Update GConf with the new user key */
		key = g_strdup_printf ("%s/%s", NMI_GCONF_TRUSTED_NETWORKS_PATH, network);
		gconf_entry = gconf_client_get_entry (info->gconf_client, key, NULL, TRUE, NULL);
		g_free (key);
		if (gconf_entry)
		{
			gconf_entry_unref (gconf_entry);
			key = g_strdup_printf ("%s/%s/key", NMI_GCONF_TRUSTED_NETWORKS_PATH, network);
			gconf_client_set_string (info->gconf_client, key, passphrase, NULL);
			g_free (key);
			key = g_strdup_printf ("%s/%s/essid", NMI_GCONF_TRUSTED_NETWORKS_PATH, network);
			gconf_client_set_string (info->gconf_client, key, network, NULL);
			g_free (key);
		}

		nmi_passphrase_dialog_clear (dialog, entry);
	}
}


/*
 * nmi_passphrase_dialog_cancel_clicked
 *
 * Cancel button handler; return a cancellation message to NetworkManager
 * and get rid of the dialog.
 *
 */
void nmi_passphrase_dialog_cancel_clicked (GtkWidget *cancel_button, gpointer user_data)
{
	GtkWidget 	*dialog = gtk_widget_get_toplevel (cancel_button);
	NMIAppInfo	*info = (NMIAppInfo *)user_data;

	g_return_if_fail (info != NULL);

	if (GTK_WIDGET_TOPLEVEL (dialog))
	{
		const char	*device = g_object_get_data (G_OBJECT (dialog), "device");
		const char	*network = g_object_get_data (G_OBJECT (dialog), "network");

		nmi_dbus_return_user_key (info->connection, device, network, "***canceled***");
		nmi_passphrase_dialog_clear (dialog, glade_xml_get_widget (info->passphrase_dialog, "passphrase_entry"));
	}
}


/*
 * nmi_passphrase_dialog_show
 *
 * Pop up the user key dialog in response to a dbus message
 *
 */
void nmi_passphrase_dialog_show (const char *device, const char *network, NMIAppInfo *info)
{
	GtkWidget			*dialog;
	GtkWidget			*label;
	const gchar		*label_text;

	g_return_if_fail (info != NULL);
	g_return_if_fail (device != NULL);
	g_return_if_fail (network != NULL);

	dialog = glade_xml_get_widget (info->passphrase_dialog, "passphrase_dialog");
	nmi_passphrase_dialog_clear (dialog, glade_xml_get_widget (info->passphrase_dialog, "passphrase_entry"));

	/* Insert the Network name into the dialog text */
	label  = glade_xml_get_widget (info->passphrase_dialog, "label1");
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
 * nmi_passphrase_dialog_cancel
 *
 * Cancel and hide any user key dialog that might be up
 *
 */
void nmi_passphrase_dialog_cancel (NMIAppInfo *info)
{
	GtkWidget		*dialog;
	GtkWidget		*entry;

	g_return_if_fail (info != NULL);

	dialog = glade_xml_get_widget (info->passphrase_dialog, "passphrase_dialog");
	entry  = glade_xml_get_widget (info->passphrase_dialog, "passphrase_entry");
	nmi_passphrase_dialog_clear (dialog, entry);
}


/*
 * nmi_passphrase_dialog_init
 *
 * Initialize the passphrase dialog
 *
 * Returns:	 0 on success
 *			-1 on failure
 */
int nmi_passphrase_dialog_init (NMIAppInfo *info)
{
	GtkWidget		*dialog;
	GtkButton		*ok_button;
	GtkButton		*cancel_button;
	GtkEntry		*entry;

	info->passphrase_dialog = glade_xml_new(GLADEDIR"/passphrase.glade", NULL, NULL);
	if (!info->passphrase_dialog)
	{
		fprintf (stderr, "Could not open the passphrase dialog glade file!\n");
		return (-1);
	}
	
	dialog = glade_xml_get_widget (info->passphrase_dialog, "passphrase_dialog");
	gtk_widget_hide (dialog);

	ok_button = GTK_BUTTON (glade_xml_get_widget (info->passphrase_dialog, "login_button"));
	g_signal_connect (G_OBJECT (ok_button), "clicked", GTK_SIGNAL_FUNC (nmi_passphrase_dialog_ok_clicked), info);
	gtk_widget_grab_default (GTK_WIDGET (ok_button));
	cancel_button = GTK_BUTTON (glade_xml_get_widget (info->passphrase_dialog, "cancel_button"));
	g_signal_connect (G_OBJECT (cancel_button), "clicked", GTK_SIGNAL_FUNC (nmi_passphrase_dialog_cancel_clicked), info);

	entry = GTK_ENTRY (glade_xml_get_widget (info->passphrase_dialog, "passphrase_entry"));
	nmi_passphrase_dialog_clear (dialog, GTK_WIDGET (entry));

	return (0);
}
