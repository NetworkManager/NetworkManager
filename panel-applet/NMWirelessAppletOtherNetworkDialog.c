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
 * This applet used the GNOME Wireless Applet as a skeleton to build from.
 *
 * GNOME Wireless Applet Authors:
 *		Eskil Heyn Olsen <eskil@eskil.dk>
 *		Bastien Nocera <hadess@hadess.net> (Gnome2 port)
 *
 * (C) Copyright 2004 Red Hat, Inc.
 * (C) Copyright 2001, 2002 Free Software Foundation
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>

#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

#include "NetworkManager.h"
#include "NMWirelessApplet.h"
#include "NMWirelessAppletDbus.h"
#include "NMWirelessAppletOtherNetworkDialog.h"

enum NMWAEncryptionKeyTypes
{
	KEY_TYPE_128_BIT_PASSPHRASE = 0,
	KEY_TYPE_ASCII_KEY = 1,
	KEY_TYPE_HEX_KEY = 2
};

static void update_button_cb (GtkWidget *widget, GladeXML *xml)
{
	gboolean		 enable = TRUE;
	const char	*text;
	GtkButton		*button;
	GtkEntry		*essid_entry;
	GtkCheckButton	*enc_check_button;

	g_return_if_fail (xml != NULL);

	essid_entry = GTK_ENTRY (glade_xml_get_widget (xml, "essid_entry"));
	button = GTK_BUTTON (glade_xml_get_widget (xml, "ok_button"));
	enc_check_button = GTK_CHECK_BUTTON (glade_xml_get_widget (xml, "use_encryption_checkbox"));
	
	text = gtk_entry_get_text (essid_entry);
	if (text[0] == '\000')
		enable = FALSE;

	/* If we're using encryptin, validate the settings */
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (enc_check_button)))
	{
		GtkComboBox	*combo = GTK_COMBO_BOX (glade_xml_get_widget (xml, "key_type_combo"));
		GtkEntry		*passphrase_entry = GTK_ENTRY (glade_xml_get_widget (xml, "passphrase_entry"));
		const char	*passphrase_text = gtk_entry_get_text (passphrase_entry);

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
	}

	gtk_widget_set_sensitive (GTK_WIDGET (button), enable);
}

static GtkTreeModel *create_wireless_adapter_model (NMWirelessApplet *applet)
{
	GtkListStore	*retval;
	GSList		*element;

	retval = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_POINTER);
	/* We should have already locked applet->data_mutex */
	for (element = applet->gui_device_list; element; element = element->next)
	{
		NetworkDevice *network = (NetworkDevice *)(element->data);

		g_assert (network);
		if (network->type == DEVICE_TYPE_WIRELESS_ETHERNET)
		{
			GtkTreeIter iter;
			const char *network_name;

			network_name = network->hal_name ? network->hal_name : network->nm_name;

			gtk_list_store_append (retval, &iter);
			gtk_list_store_set (retval, &iter,
							0, network_name,
							1, network,
							-1);
		}
	}
	return GTK_TREE_MODEL (retval);
}


/*
 * nmwa_other_network_dialog_key_type_combo_changed
 *
 * Change the text of the passphrase entry label to match the selected
 * key type.
 *
 */
void nmwa_other_network_dialog_key_type_combo_changed (GtkWidget *key_type_combo, gpointer user_data)
{
	GtkLabel		*entry_label;
	int			 combo_choice;
	GladeXML		*xml = (GladeXML *)user_data;

	g_return_if_fail (xml != NULL);

	entry_label = GTK_LABEL (glade_xml_get_widget (xml, "passphrase_entry_label"));
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

	update_button_cb (key_type_combo, xml);
}


/*
 * nmwa_other_network_dialog_enc_check_toggled
 *
 * Enable/disable the encryption-related dialog items based on the
 * widget's status.
 *
 */
void nmwa_other_network_dialog_enc_check_toggled (GtkWidget *enc_check_button, gpointer user_data)
{
	GladeXML		*xml = (GladeXML *)user_data;
	GtkComboBox	*combo;
	GtkEntry		*entry;
	GtkLabel		*combo_label;
	GtkLabel		*entry_label;
	gboolean		 active;

	g_return_if_fail (xml != NULL);

	combo = GTK_COMBO_BOX (glade_xml_get_widget (xml, "key_type_combo"));
	combo_label = GTK_LABEL (glade_xml_get_widget (xml, "key_type_combo_label"));
	entry = GTK_ENTRY (glade_xml_get_widget (xml, "passphrase_entry"));
	entry_label = GTK_LABEL (glade_xml_get_widget (xml, "passphrase_entry_label"));

	active = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (enc_check_button));
	gtk_widget_set_sensitive (GTK_WIDGET (combo), active);
	gtk_widget_set_sensitive (GTK_WIDGET (combo_label), active);
	gtk_widget_set_sensitive (GTK_WIDGET (entry), active);
	gtk_widget_set_sensitive (GTK_WIDGET (entry_label), active);

	update_button_cb (enc_check_button, xml);
}


static GtkDialog *nmwa_other_network_dialog_init (GladeXML *xml, NMWirelessApplet *applet, NetworkDevice **def_dev, gboolean create_network)
{
	GtkDialog		*dialog = NULL;
	GtkWidget		*essid_entry;
	GtkWidget		*button;
	GtkComboBox	*key_type_combo;
	GtkEntry		*passphrase_entry;
	gint			 n_wireless_interfaces = 0;
	GSList		*element;
	char			*label;
	GtkCheckButton	*enc_check_button;

	g_return_val_if_fail (xml != NULL, NULL);
	g_return_val_if_fail (applet != NULL, NULL);
	g_return_val_if_fail (def_dev != NULL, NULL);
	g_return_val_if_fail (*def_dev == NULL, NULL);

	/* Set up the dialog */
	dialog = GTK_DIALOG (glade_xml_get_widget (xml, "custom_essid_dialog"));
	if (!dialog)
		return NULL;

	essid_entry = glade_xml_get_widget (xml, "essid_entry");
	button = glade_xml_get_widget (xml, "ok_button");

	gtk_widget_grab_focus (essid_entry);
	gtk_entry_set_text (GTK_ENTRY (essid_entry), "");
	gtk_widget_set_sensitive (button, FALSE);
	g_signal_connect (essid_entry, "changed", G_CALLBACK (update_button_cb), xml);

	if (create_network)
	{
		label = g_strdup_printf ("<span size=\"larger\" weight=\"bold\">%s</span>\n\n%s",
			_("Create new wireless network"),
			_("Enter the ESSID and security settings of the wireless network you wish to create."));
	}
	else
	{
		label = g_strdup_printf ("<span size=\"larger\" weight=\"bold\">%s</span>\n\n%s",
			_("Custom wireless network"),
			_("Enter the ESSID of the wireless network to which you wish to connect."));
	}
	gtk_label_set_markup (GTK_LABEL (glade_xml_get_widget (xml, "essid_label")), label);

	/* Do we have multiple Network cards? */
	g_mutex_lock (applet->data_mutex);
	for (element = applet->gui_device_list; element; element = element->next)
	{
		NetworkDevice *dev = (NetworkDevice *)(element->data);

		g_assert (dev);
		if (dev->type == DEVICE_TYPE_WIRELESS_ETHERNET)
		{
			if (!*def_dev)
			{
				*def_dev = dev;
				network_device_ref (*def_dev);
			}
			n_wireless_interfaces++;
		}
	}

	if (n_wireless_interfaces < 1)
 	{
		g_mutex_unlock (applet->data_mutex);
		/* Run away!!! */
		return (NULL);
	}
	else if (n_wireless_interfaces == 1)
	{
		gtk_widget_hide (glade_xml_get_widget (xml, "wireless_adapter_label"));
		gtk_widget_hide (glade_xml_get_widget (xml, "wireless_adapter_combo"));
	}
	else
	{
		GtkWidget *combo;
		GtkTreeModel *model;

		combo = glade_xml_get_widget (xml, "wireless_adapter_combo");
		model = create_wireless_adapter_model (applet);
		gtk_combo_box_set_model (GTK_COMBO_BOX (combo), model);

		/* Select the first one randomly */
		gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 0);
	}
	g_mutex_unlock (applet->data_mutex);

	/* Uncheck the "use encryption" checkbox and disable relevant encryption widgets */
	enc_check_button = GTK_CHECK_BUTTON (glade_xml_get_widget (xml, "use_encryption_checkbox"));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (enc_check_button), 0);
	g_signal_connect (G_OBJECT (enc_check_button), "toggled", GTK_SIGNAL_FUNC (nmwa_other_network_dialog_enc_check_toggled), xml);
	nmwa_other_network_dialog_enc_check_toggled (GTK_WIDGET (enc_check_button), xml);

	/* Set initial passphrase entry label and key type combo box item */
	key_type_combo = GTK_COMBO_BOX (glade_xml_get_widget (xml, "key_type_combo"));
	gtk_combo_box_set_active (key_type_combo, 0);
	g_signal_connect (G_OBJECT (key_type_combo), "changed", GTK_SIGNAL_FUNC (nmwa_other_network_dialog_key_type_combo_changed), xml);
	nmwa_other_network_dialog_key_type_combo_changed (GTK_WIDGET (key_type_combo), xml);

	passphrase_entry = GTK_ENTRY (glade_xml_get_widget (xml, "passphrase_entry"));
	g_signal_connect (passphrase_entry, "changed", G_CALLBACK (update_button_cb), xml);

	return (dialog);
}


void nmwa_other_network_dialog_run (NMWirelessApplet *applet, gboolean create_network)
{
	gchar		*glade_file;
	GtkDialog		*dialog;
	gint			 response;
	NetworkDevice	*def_dev = NULL;
	GladeXML		*xml;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (applet->glade_file != NULL);

	xml = glade_xml_new (applet->glade_file, NULL, NULL);
	if (xml == NULL)
	{
		show_warning_dialog (TRUE, _("The NetworkManager Applet could not find some required resources (the glade file was not found)."));
		return;
	}

	if (!(dialog = nmwa_other_network_dialog_init (xml, applet, &def_dev, create_network)))
		return;

	/* Run the dialog */
	response = gtk_dialog_run (dialog);

	if (response == GTK_RESPONSE_OK)
	{
		GtkEntry		*essid_entry;
		GtkCheckButton	*enc_check_button;
		GtkEntry		*passphrase_entry;
		GtkComboBox	*key_type_combo;
		const char	*essid = NULL;
		const char	*passphrase = NULL;
		int			 key_type = -1;

		essid_entry = GTK_ENTRY (glade_xml_get_widget (xml, "essid_entry"));
		essid = gtk_entry_get_text (essid_entry);

		enc_check_button = GTK_CHECK_BUTTON (glade_xml_get_widget (xml, "use_encryption_checkbox"));
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (enc_check_button)))
		{
			passphrase_entry = GTK_ENTRY (glade_xml_get_widget (xml, "passphrase_entry"));
			passphrase = gtk_entry_get_text (passphrase_entry);

			key_type_combo = GTK_COMBO_BOX (glade_xml_get_widget (xml, "key_type_combo"));
			key_type = gtk_combo_box_get_active (GTK_COMBO_BOX (key_type_combo));
		}

		if (essid[0] != '\000')
		{
			WirelessNetwork *net = wireless_network_new_with_essid (essid);

			/* FIXME: allow picking of the wireless device, we currently just
			 * use the first one found in our device list.
			 *
			 * FIXME: default_dev might have gone away by the time the dialog
			 * gets dismissed and we get here...
			 */
			if (net)
			{
				NMEncKeyType	nm_key_type;

				switch (key_type)
				{
					case KEY_TYPE_128_BIT_PASSPHRASE:
						nm_key_type = NM_ENC_TYPE_128_BIT_PASSPHRASE;
						break;
					case KEY_TYPE_ASCII_KEY:
						nm_key_type = NM_ENC_TYPE_ASCII_KEY;
						break;
					case KEY_TYPE_HEX_KEY:
						nm_key_type = NM_ENC_TYPE_HEX_KEY;
						break;
					default:
						nm_key_type = NM_ENC_TYPE_UNKNOWN;
						break;
				}
				if (create_network)
					nmwa_dbus_create_network (applet->connection, def_dev, net, nm_key_type, passphrase);
				else
					nmwa_dbus_set_device (applet->connection, def_dev, net, nm_key_type, passphrase);
				network_device_unref (def_dev);
				wireless_network_unref (net);
			}
		}
	}

	gtk_widget_destroy (GTK_WIDGET (dialog));
	g_object_unref (xml);
}
