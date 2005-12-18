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
#include "wireless-security-manager.h"

static GladeXML *get_dialog_xml (GtkWidget *dialog)
{
	g_return_val_if_fail (dialog != NULL, NULL);

	return (GladeXML *) g_object_get_data (G_OBJECT (dialog), "glade-xml");
}

static void update_button_cb (GtkWidget *unused, GtkDialog *dialog)
{
	gboolean		enable = FALSE;
	const char *	ssid = NULL;
	GtkWidget *	button;
	GladeXML *	xml;
	WirelessSecurityManager * wsm;
	GtkComboBox *	security_combo;

	g_return_if_fail (dialog != NULL);
	xml = get_dialog_xml (GTK_WIDGET (dialog));
	g_return_if_fail (xml != NULL);
	wsm = (WirelessSecurityManager *) g_object_get_data (G_OBJECT (dialog), "wireless-security-manager");
	g_return_if_fail (wsm != NULL);

	if ((ssid = (const char *) g_object_get_data (G_OBJECT (dialog), "network")))
	{
		/* Validate the wireless security choices */
		security_combo = GTK_COMBO_BOX (glade_xml_get_widget (xml, "security_combo"));
		enable = wsm_validate_active (wsm, security_combo, ssid);
	}

	button = glade_xml_get_widget (xml, "login_button");
	gtk_widget_set_sensitive (button, enable);
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
		/* FIXME: clear WSO widgets here */
	}

	gtk_widget_hide (dialog);
}


/*
 * nmi_passphrase_dialog_security_combo_changed
 *
 * Replace the current wireless security widgets with new ones
 * according to what the user chose.
 *
 */
static void nmi_passphrase_dialog_security_combo_changed (GtkWidget *security_combo, gpointer user_data)
{
	int			choice;
	GtkDialog *	dialog = (GtkDialog *) user_data;
	WirelessSecurityManager * wsm;
	GtkWidget *	wso_widget;
	GladeXML *	xml;
	GtkWidget *	vbox;
	GList *		elt;

	g_return_if_fail (dialog != NULL);
	xml = get_dialog_xml (GTK_WIDGET (dialog));
	g_return_if_fail (xml != NULL);

	wsm = g_object_get_data (G_OBJECT (dialog), "wireless-security-manager");
	g_return_if_fail (wsm != NULL);

	vbox = GTK_WIDGET (glade_xml_get_widget (xml, "wireless_security_vbox"));

	/* Remove any previous wireless security widgets */
	for (elt = gtk_container_get_children (GTK_CONTAINER (vbox)); elt; elt = g_list_next (elt))
	{
		GtkWidget * child = GTK_WIDGET (elt->data);

		if (wso_is_wso_widget (child))
			gtk_container_remove (GTK_CONTAINER (vbox), child);
	}

	/* Determine and add the correct wireless security widget to the dialog */
	wso_widget = wsm_get_widget_for_active (wsm, GTK_COMBO_BOX (security_combo), GTK_SIGNAL_FUNC (update_button_cb), dialog);
	if (wso_widget)
		gtk_container_add (GTK_CONTAINER (vbox), wso_widget);

	update_button_cb (NULL, dialog);
}


/*
 * nmi_passphrase_dialog_response_received
 *
 * response handler; grab the passphrase and return it
 * to NetworkManager if it was given to us, else return
 * a cancellation message to NetworkManager.
 * Either way, get rid of the dialog.
 */
static void nmi_passphrase_dialog_response_received (GtkWidget *dialog, gint response, gpointer user_data)
{
	NMWirelessApplet *	applet = (NMWirelessApplet *) user_data;

	GladeXML *		xml;
	GtkEntry *		entry;
	GtkComboBox *		security_combo;
	DBusMessage *		message;
	WirelessSecurityManager *wsm;
	WirelessSecurityOption *	opt;
	WirelessNetwork *	net;
	NMGConfWSO *		gconf_wso;

	g_return_if_fail (applet != NULL);

	message = g_object_get_data (G_OBJECT (dialog), "dbus-message");
	g_assert (message);

	if (response != GTK_RESPONSE_OK)
	{
		DBusMessage *	reply;

		reply = dbus_message_new_error (message, "CanceledError", "Request was cancelled.");
		dbus_connection_send (applet->connection, reply, NULL);
		goto out;
	}

	xml = get_dialog_xml (dialog);
	g_assert (xml);

	wsm = g_object_get_data (G_OBJECT (dialog), "wireless-security-manager");
	g_assert (wsm);

	security_combo = GTK_COMBO_BOX (glade_xml_get_widget (xml, "security_combo"));
	opt = wsm_get_option_for_active (wsm, security_combo);

	net = (WirelessNetwork *) g_object_get_data (G_OBJECT (dialog), "network");
	g_assert (net);
	gconf_wso = nm_gconf_wso_new_from_wso (opt, wireless_network_get_essid (net));

	/* Return new security information to NM */
	nmi_dbus_return_user_key (applet->connection, message, gconf_wso);
	g_object_unref (G_OBJECT (gconf_wso));

out:
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
DBusMessage *
nmi_passphrase_dialog_cancel (DBusConnection *connection,
                              DBusMessage *message,
                              void *user_data)
{
	NMWirelessApplet *applet = (NMWirelessApplet *) user_data;
	GtkWidget *dialog;

	g_return_val_if_fail (applet != NULL, NULL);
	dialog = applet->passphrase_dialog;

	if (GTK_WIDGET_VISIBLE (dialog))
		nmi_passphrase_dialog_clear (dialog);
	return NULL;
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
	GtkWidget *				dialog;
	GtkButton *				ok_button;
	GtkEntry *				entry;
	GtkLabel *				label;
	GladeXML *				xml;
	char *					orig_label_text;
	WirelessSecurityManager *	wsm;
	GtkComboBox *				security_combo;

	if (!(xml = glade_xml_new (applet->glade_file, "passphrase_dialog", NULL)))
	{
		nmwa_schedule_warning_dialog (applet, _("The NetworkManager Applet could not find some required resources (the glade file was not found)."));
		return NULL;
	}

	dialog = glade_xml_get_widget (xml, "passphrase_dialog");
	gtk_widget_hide (dialog);

	g_object_set_data (G_OBJECT (dialog), "glade-xml", xml);

	/* Save original label text to preserve the '%s' and other formatting that gets overwritten
	 * when the dialog is first shown.
	 */
	label = GTK_LABEL (glade_xml_get_widget (xml, "label1"));
	orig_label_text = g_strdup (gtk_label_get_label (label));

	g_object_set_data (G_OBJECT (dialog), "orig-label-text", orig_label_text);

	g_signal_connect (G_OBJECT (dialog), "response", GTK_SIGNAL_FUNC (nmi_passphrase_dialog_response_received), applet);

	ok_button = GTK_BUTTON (glade_xml_get_widget (xml, "login_button"));
	gtk_widget_grab_default (GTK_WIDGET (ok_button));

	nmi_passphrase_dialog_clear (dialog);
	gtk_widget_set_sensitive (GTK_WIDGET (ok_button), FALSE);

	wsm = wsm_new (applet->glade_file);
	g_object_set_data (G_OBJECT (dialog), "wireless-security-manager", (gpointer) wsm);

	security_combo = GTK_COMBO_BOX (glade_xml_get_widget (xml, "security_combo"));
	wsm_populate_combo (wsm, security_combo);
	g_signal_connect (G_OBJECT (security_combo), "changed", GTK_SIGNAL_FUNC (nmi_passphrase_dialog_security_combo_changed), dialog);
	nmi_passphrase_dialog_security_combo_changed (GTK_WIDGET (security_combo), dialog);

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
	char *	data;

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
