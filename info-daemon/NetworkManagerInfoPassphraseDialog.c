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

#include <config.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

#ifndef _
#define _(x) dgettext (GETTEXT_PACKAGE, x)
#define N_(x) x
#endif

#include "NetworkManagerInfoDbus.h"
#include "NetworkManagerInfoPassphraseDialog.h"

enum NMIPassphraseDialogKeyTypes
{
	KEY_TYPE_128_BIT_PASSPHRASE = 0,
	KEY_TYPE_ASCII_KEY = 1,
	KEY_TYPE_HEX_KEY = 2
};

static void update_button_cb (GtkWidget *widget, GladeXML *xml)
{
	GtkButton	*button;
	GtkComboBox	*combo;
	GtkEntry	*passphrase_entry;
	const char	*passphrase_text;
	gboolean		 enable = TRUE;

	g_return_if_fail (xml != NULL);

	button = GTK_BUTTON (glade_xml_get_widget (xml, "login_button"));
	combo = GTK_COMBO_BOX (glade_xml_get_widget (xml, "key_type_combo"));
	passphrase_entry = GTK_ENTRY (glade_xml_get_widget (xml, "passphrase_entry"));
	passphrase_text = gtk_entry_get_text (passphrase_entry);

	if (passphrase_text[0] == '\000')
		enable = FALSE;
	else
	{
		int combo_choice = gtk_combo_box_get_active (combo);
		switch (combo_choice)
		{
			case KEY_TYPE_ASCII_KEY:
				if ((strlen (passphrase_text) != 5) && (strlen (passphrase_text) != 13))
					enable = FALSE;
				break;
			case KEY_TYPE_HEX_KEY:
				if ((strlen (passphrase_text) != 10) && (strlen (passphrase_text) != 26))
					enable = FALSE;
				break;
			default:
				break;
		}
	}		

	gtk_widget_set_sensitive (GTK_WIDGET (button), enable);
}

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
 * nmi_passphrase_dialog_key_type_combo_changed
 *
 * Change the text of the passphrase entry label to match the selected
 * key type.
 *
 */
void nmi_passphrase_dialog_key_type_combo_changed (GtkWidget *key_type_combo, gpointer user_data)
{
	GtkLabel		*entry_label;
	int			 combo_choice;
	NMIAppInfo	*info = (NMIAppInfo *)user_data;

	g_return_if_fail (info != NULL);

	entry_label = GTK_LABEL (glade_xml_get_widget (info->passphrase_dialog, "passphrase_entry_label"));
	switch ((combo_choice = gtk_combo_box_get_active (GTK_COMBO_BOX (key_type_combo))))
	{
		case KEY_TYPE_128_BIT_PASSPHRASE:
			gtk_label_set_label (entry_label, _("Passphrase:"));
			break;
		case KEY_TYPE_ASCII_KEY:
			gtk_label_set_label (entry_label, _("Ascii Key:"));
			break;
		case KEY_TYPE_HEX_KEY:
			gtk_label_set_label (entry_label, _("Hex Key:"));
			break;
		default:
			break;
	}
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
		GtkEntry		*entry = GTK_ENTRY (glade_xml_get_widget (info->passphrase_dialog, "passphrase_entry"));
		GtkComboBox	*key_type_combo = GTK_COMBO_BOX (glade_xml_get_widget (info->passphrase_dialog, "key_type_combo"));
		int			 key_type = gtk_combo_box_get_active (key_type_combo);
		const char	*passphrase = gtk_entry_get_text (entry);
		const char	*device = g_object_get_data (G_OBJECT (dialog), "device");
		const char	*network = g_object_get_data (G_OBJECT (dialog), "network");
		char			*key = NULL;
		int			 key_type_return = NM_ENC_TYPE_UNKNOWN;
		GConfEntry	*gconf_entry;
		char			*escaped_network;

		switch (key_type)
		{
			case KEY_TYPE_128_BIT_PASSPHRASE:
				key_type_return = NM_ENC_TYPE_128_BIT_PASSPHRASE;
				break;
			case KEY_TYPE_ASCII_KEY:
				key_type_return = NM_ENC_TYPE_ASCII_KEY;
				break;
			case KEY_TYPE_HEX_KEY:
				key_type_return = NM_ENC_TYPE_HEX_KEY;
				break;
			default:
				key_type_return = NM_ENC_TYPE_UNKNOWN;
				break;
		}

		/* Tell NetworkManager about the key the user typed in */
		nmi_dbus_return_user_key (info->connection, device, network, passphrase, key_type_return);

		/* Update GConf with the new user key */
		escaped_network = gconf_escape_key (network, strlen (network));
		key = g_strdup_printf ("%s/%s", NMI_GCONF_WIRELESS_NETWORKS_PATH, escaped_network);
		gconf_entry = gconf_client_get_entry (info->gconf_client, key, NULL, TRUE, NULL);
		g_free (key);
		if (gconf_entry)
		{
			gconf_entry_unref (gconf_entry);
			key = g_strdup_printf ("%s/%s/key", NMI_GCONF_WIRELESS_NETWORKS_PATH, escaped_network);
			gconf_client_set_string (info->gconf_client, key, passphrase, NULL);
			g_free (key);
			key = g_strdup_printf ("%s/%s/essid", NMI_GCONF_WIRELESS_NETWORKS_PATH, escaped_network);
			gconf_client_set_string (info->gconf_client, key, network, NULL);
			g_free (key);
			key = g_strdup_printf ("%s/%s/key_type", NMI_GCONF_WIRELESS_NETWORKS_PATH, escaped_network);
			gconf_client_set_int (info->gconf_client, key, key_type_return, NULL);
			g_free (key);
		}
		g_free (escaped_network);

		nmi_passphrase_dialog_clear (dialog, GTK_WIDGET (entry));
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

		nmi_dbus_return_user_key (info->connection, device, network, "***canceled***", NM_ENC_TYPE_UNKNOWN);
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

	g_return_if_fail (info != NULL);
	g_return_if_fail (device != NULL);
	g_return_if_fail (network != NULL);

	dialog = glade_xml_get_widget (info->passphrase_dialog, "passphrase_dialog");
	nmi_passphrase_dialog_clear (dialog, glade_xml_get_widget (info->passphrase_dialog, "passphrase_entry"));

	/* Insert the Network name into the dialog text */
	if (info->orig_label_text)
	{
		GtkWidget	*label = glade_xml_get_widget (info->passphrase_dialog, "label1");
		char		*new_label_text = g_strdup_printf (info->orig_label_text, network);

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
	GtkComboBox	*key_type_combo;
	GtkLabel		*label;

	info->passphrase_dialog = glade_xml_new(GLADEDIR"/passphrase.glade", NULL, NULL);
	if (!info->passphrase_dialog)
	{
		syslog (LOG_ERR, "Could not open the passphrase dialog glade file!");
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
	gtk_widget_set_sensitive (GTK_WIDGET (ok_button), FALSE);
	g_signal_connect (entry, "changed", G_CALLBACK (update_button_cb), info->passphrase_dialog);

	key_type_combo = GTK_COMBO_BOX (glade_xml_get_widget (info->passphrase_dialog, "key_type_combo"));
	gtk_combo_box_set_active (key_type_combo, 0);
	g_signal_connect (G_OBJECT (key_type_combo), "changed", GTK_SIGNAL_FUNC (nmi_passphrase_dialog_key_type_combo_changed), info);
	nmi_passphrase_dialog_key_type_combo_changed (GTK_WIDGET (key_type_combo), info);

	/* Save original label text to preserve the '%s' and other formatting that gets overwritten
	 * when the dialog is first shown.
	 */
	label = GTK_LABEL (glade_xml_get_widget (info->passphrase_dialog, "label1"));
	info->orig_label_text = g_strdup (gtk_label_get_label (label));

	return (0);
}
