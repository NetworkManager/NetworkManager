/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
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
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <config.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

#include "applet.h"
#include "applet-dbus-info.h"
#include "passphrase-dialog.h"
#include "nm-utils.h"
#include "NetworkManager.h"

static GladeXML *get_dialog_xml (GtkWidget *dialog)
{
	char *data;

	g_return_val_if_fail (dialog != NULL, NULL);

	if ((data = g_object_get_data (G_OBJECT (dialog), "glade-xml")))
		return (GladeXML *)data;

	return NULL;
}


static void update_button_cb (GtkWidget *widget, GladeXML *xml)
{
	GtkButton	*	button;
	GtkComboBox *	combo;
	GtkEntry	*	passphrase_entry;
	const char *	passphrase_text;
	gboolean		enable = FALSE;

	g_return_if_fail (xml != NULL);

	button = GTK_BUTTON (glade_xml_get_widget (xml, "login_button"));
	combo = GTK_COMBO_BOX (glade_xml_get_widget (xml, "key_type_combo"));
	passphrase_entry = GTK_ENTRY (glade_xml_get_widget (xml, "passphrase_entry"));
	passphrase_text = gtk_entry_get_text (passphrase_entry);

	switch (gtk_combo_box_get_active (combo))
	{
		case KEY_TYPE_128_BIT_PASSPHRASE:
			if (strlen (passphrase_text) > 0)
				enable = TRUE;
			break;
		case KEY_TYPE_ASCII_KEY:
			if ((strlen (passphrase_text) == 5) || (strlen (passphrase_text) == 13))
				enable = TRUE;
			break;
		case KEY_TYPE_HEX_KEY:
			if ((strlen (passphrase_text) == 10) || (strlen (passphrase_text) == 26))
				enable = TRUE;
			break;
		default:
			break;
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
static void nmi_passphrase_dialog_clear (GtkWidget *dialog)
{
	char *		data;
	GtkWidget *	entry = NULL;
	GladeXML *	xml = NULL;

	g_return_if_fail (dialog != NULL);

	if ((data = g_object_get_data (G_OBJECT (dialog), "device")))
	{
		network_device_unref ((NetworkDevice *)data);
		g_object_set_data (G_OBJECT (dialog), "device", NULL);
	}

	if ((data = g_object_get_data (G_OBJECT (dialog), "network")))
	{
		wireless_network_unref ((WirelessNetwork *)data);
		g_object_set_data (G_OBJECT (dialog), "network", NULL);
	}

	if ((data = g_object_get_data (G_OBJECT (dialog), "dbus-message")))
	{
		dbus_message_unref ((DBusMessage *) data);
		g_object_set_data (G_OBJECT (dialog), "dbus-message", NULL);
	}

	if ((xml = (GladeXML *)g_object_get_data (G_OBJECT (dialog), "glade-xml")))
	{
		entry  = glade_xml_get_widget (xml, "passphrase_entry");
		gtk_entry_set_text (GTK_ENTRY (entry), "");
	}

	gtk_widget_hide (dialog);
}


/*
 * nmi_passphrase_dialog_key_type_combo_changed
 *
 * Change the text of the passphrase entry label to match the selected
 * key type.
 *
 */
static void nmi_passphrase_dialog_key_type_combo_changed (GtkWidget *key_type_combo, gpointer user_data)
{
	GtkWidget *	dialog = gtk_widget_get_toplevel (key_type_combo);

	if (GTK_WIDGET_TOPLEVEL (dialog))
	{
		GtkLabel *		entry_label;
		int				combo_choice;
		GladeXML *		dialog_xml;

		g_return_if_fail ((dialog_xml = get_dialog_xml (dialog)) != NULL);

		entry_label = GTK_LABEL (glade_xml_get_widget (dialog_xml, "passphrase_entry_label"));
		switch ((combo_choice = gtk_combo_box_get_active (GTK_COMBO_BOX (key_type_combo))))
		{
			case KEY_TYPE_128_BIT_PASSPHRASE:
				gtk_label_set_label (entry_label, _("Passphrase:"));
				break;
			case KEY_TYPE_ASCII_KEY:
				gtk_label_set_label (entry_label, _("ASCII Key:"));
				break;
			case KEY_TYPE_HEX_KEY:
				gtk_label_set_label (entry_label, _("Hex Key:"));
				break;
			default:
				break;
		}
	}
}


/*
 * nmi_passphrase_dialog_response_received
 *
 * response handler; grab the passphrase and return it
 * to NetworkManager if it was given to us, else return
 * a cancellation message to NetworkManager.
 * Either way, get rid of the dialog.
 */
static void nmi_passphrase_dialog_response_received (GtkWidget *cancel_button, gint response, gpointer user_data)
{
	GtkWidget *		dialog = gtk_widget_get_toplevel (cancel_button);
	NMWirelessApplet *	applet = (NMWirelessApplet *)user_data;

	GladeXML *		dialog_xml;
	GtkEntry *		entry;
	GtkComboBox *		key_type_combo;
	const char *		passphrase;
	NetworkDevice *		dev;
	WirelessNetwork *	net;
	DBusMessage *		message;
	NMEncKeyType		key_type_return;

	g_return_if_fail (applet != NULL);

	if (! GTK_WIDGET_TOPLEVEL (dialog))
		return;

	if (response != GTK_RESPONSE_OK)
	{
		DBusMessage *		message = g_object_get_data (G_OBJECT (dialog), "dbus-message");

		nmi_dbus_return_user_key (applet->connection, message, "***canceled***", NM_ENC_TYPE_UNKNOWN);
		nmi_passphrase_dialog_clear (dialog);

		return;
	}

	dev = g_object_get_data (G_OBJECT (dialog), "device");
	net = g_object_get_data (G_OBJECT (dialog), "network");
	message = g_object_get_data (G_OBJECT (dialog), "dbus-message");
	key_type_return = NM_ENC_TYPE_UNKNOWN;

	g_return_if_fail ((dialog_xml = get_dialog_xml (dialog)) != NULL);

	entry = GTK_ENTRY (glade_xml_get_widget (dialog_xml, "passphrase_entry"));
	key_type_combo = GTK_COMBO_BOX (glade_xml_get_widget (dialog_xml, "key_type_combo"));
	passphrase = gtk_entry_get_text (entry);

	switch (gtk_combo_box_get_active (key_type_combo))
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
	nmi_dbus_return_user_key (applet->connection, message, passphrase, key_type_return);
	nmi_passphrase_dialog_clear (dialog);
}


typedef struct PPDialogCBData
{
	NMWirelessApplet *	applet;
	NetworkDevice *	dev;
	WirelessNetwork *	net;
	DBusMessage *		message;
} PPDialogCBData;

/*
 * nmi_passphrase_dialog_show
 *
 * Pop up the user key dialog in response to a dbus message
 *
 */
static gboolean nmi_passphrase_dialog_show (PPDialogCBData *cb_data)
{
	GtkWidget *		dialog;
	GladeXML *		dialog_xml;
	const char *		orig_label_text;
	guint32			timestamp;

	g_return_val_if_fail (cb_data != NULL, FALSE);
	g_return_val_if_fail (cb_data->applet != NULL, FALSE);
	g_return_val_if_fail (cb_data->dev != NULL, FALSE);
	g_return_val_if_fail (cb_data->net != NULL, FALSE);

	dialog = cb_data->applet->passphrase_dialog;
	g_return_val_if_fail ((dialog_xml = get_dialog_xml (dialog)) != NULL, FALSE);

	if (GTK_WIDGET_VISIBLE (dialog))
		return FALSE;

	if (!(orig_label_text = g_object_get_data (G_OBJECT (dialog), "orig-label-text")))
		return FALSE;

	nmi_passphrase_dialog_clear (dialog);

	/* Insert the Network name into the dialog text */
	if (orig_label_text)
	{
		GtkWidget *	label = glade_xml_get_widget (dialog_xml, "label1");
		char *		new_label_text = g_strdup_printf (orig_label_text, wireless_network_get_essid (cb_data->net));

		gtk_label_set_label (GTK_LABEL (label), new_label_text);
	}

	g_object_set_data (G_OBJECT (dialog), "device", cb_data->dev);
	g_object_set_data (G_OBJECT (dialog), "network", cb_data->net);
	g_object_set_data (G_OBJECT (dialog), "dbus-message", cb_data->message);

	gtk_widget_show (dialog);

	/* Bash focus-stealing prevention in the face */
	timestamp = gdk_x11_get_server_time (dialog->window);
	gdk_x11_window_set_user_time (dialog->window, timestamp);

	return FALSE;
}


/*
 * nmi_passphrase_dialog_schedule_show
 *
 * Schedule the passphrase dialog to show
 *
 */
gboolean nmi_passphrase_dialog_schedule_show (NetworkDevice *dev, WirelessNetwork *net, DBusMessage *message, NMWirelessApplet *applet)
{
	PPDialogCBData *	cb_data;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (net != NULL, FALSE);
	g_return_val_if_fail (message != NULL, FALSE);
	g_return_val_if_fail (applet != NULL, FALSE);

	cb_data = g_malloc0 (sizeof (PPDialogCBData));
	network_device_ref (dev);
	cb_data->dev = dev;
	wireless_network_ref (net);
	cb_data->net = net;
	cb_data->applet = applet;
	dbus_message_ref (message);
	cb_data->message = message;

	g_idle_add ((GSourceFunc) nmi_passphrase_dialog_show, cb_data);

	return TRUE;
}


/*
 * nmi_passphrase_dialog_cancel
 *
 * Cancel and hide any user key dialog that might be up
 *
 */
static gboolean nmi_passphrase_dialog_cancel (NMWirelessApplet *applet)
{
	GtkWidget *dialog;

	g_return_val_if_fail (applet != NULL, FALSE);
	dialog = applet->passphrase_dialog;

	if (GTK_WIDGET_VISIBLE (dialog))
		nmi_passphrase_dialog_clear (dialog);

	return FALSE;
}


/*
 * nmi_passphrase_dialog_schedule_cancel
 *
 * Schedule the passphrase dialog cancellation
 *
 */
void nmi_passphrase_dialog_schedule_cancel (NMWirelessApplet *applet)
{
	g_return_if_fail (applet != NULL);

	g_idle_add ((GSourceFunc) nmi_passphrase_dialog_cancel, applet);
}


/*
 * nmi_passphrase_dialog_init
 *
 * Initialize the passphrase dialog
 *
 * Returns:	TRUE on success
 *			FALSE on failure
 */
GtkWidget *nmi_passphrase_dialog_init (NMWirelessApplet *applet)
{
	GtkWidget *	dialog;
	GtkButton *	ok_button;
	GtkButton *	cancel_button;
	GtkEntry *	entry;
	GtkComboBox *	key_type_combo;
	GtkLabel *	label;
	GladeXML *	dialog_xml;
	char *		orig_label_text;

	if (!(dialog_xml = glade_xml_new (applet->glade_file, "passphrase_dialog", NULL)))
	{
		nmwa_schedule_warning_dialog (applet, _("The NetworkManager Applet could not find some required resources (the glade file was not found)."));
		return NULL;
	}

	dialog = glade_xml_get_widget (dialog_xml, "passphrase_dialog");
	gtk_widget_hide (dialog);

	g_object_set_data (G_OBJECT (dialog), "glade-xml", dialog_xml);

	/* Save original label text to preserve the '%s' and other formatting that gets overwritten
	 * when the dialog is first shown.
	 */
	label = GTK_LABEL (glade_xml_get_widget (dialog_xml, "label1"));
	orig_label_text = g_strdup (gtk_label_get_label (label));

	g_object_set_data (G_OBJECT (dialog), "orig-label-text", orig_label_text);

	g_signal_connect (G_OBJECT (dialog), "response", GTK_SIGNAL_FUNC (nmi_passphrase_dialog_response_received), applet);

	ok_button = GTK_BUTTON (glade_xml_get_widget (dialog_xml, "login_button"));
	gtk_widget_grab_default (GTK_WIDGET (ok_button));

	entry = GTK_ENTRY (glade_xml_get_widget (dialog_xml, "passphrase_entry"));
	nmi_passphrase_dialog_clear (dialog);
	gtk_widget_set_sensitive (GTK_WIDGET (ok_button), FALSE);
	g_signal_connect (entry, "changed", G_CALLBACK (update_button_cb), dialog_xml);

	key_type_combo = GTK_COMBO_BOX (glade_xml_get_widget (dialog_xml, "key_type_combo"));
	gtk_combo_box_set_active (key_type_combo, 0);
	g_signal_connect (G_OBJECT (key_type_combo), "changed", GTK_SIGNAL_FUNC (nmi_passphrase_dialog_key_type_combo_changed), applet);
	nmi_passphrase_dialog_key_type_combo_changed (GTK_WIDGET (key_type_combo), applet);

	return dialog;
}


/*
 * nmi_passphrase_dialog_destroy
 *
 * Dispose of the passphrase dialog and its data
 *
 */
void nmi_passphrase_dialog_destroy (GtkWidget *dialog)
{
	char 	*data;

	g_return_if_fail (dialog != NULL);

	nmi_passphrase_dialog_clear (dialog);

	if ((data = g_object_get_data (G_OBJECT (dialog), "glade-xml")))
	{
		g_object_unref (G_OBJECT (data));
		g_object_set_data (G_OBJECT (dialog), "glade-xml", NULL);
	}

	if ((data = g_object_get_data (G_OBJECT (dialog), "orig-label-text")))
	{
		g_free (data);
		g_object_set_data (G_OBJECT (dialog), "orig-label-text", NULL);
	}

	gtk_widget_destroy (dialog);
}
