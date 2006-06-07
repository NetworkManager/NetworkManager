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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>

#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

#if !GLIB_CHECK_VERSION(2,8,0)
#include <unistd.h>
#endif

#include "NetworkManager.h"
#include "applet.h"
#include "applet-dbus.h"
#include "applet-dbus-devices.h"
#include "other-network-dialog.h"
#include "wireless-security-manager.h"
#include "wireless-security-option.h"

#define NAME_COLUMN		0
#define DEV_COLUMN		1


static void update_button_cb (GtkWidget *unused, GtkDialog *dialog)
{
	gboolean		enable = FALSE;
	const char *	ssid;
	GtkButton *	ok_button;
	GtkEntry *	network_name_entry;
	GladeXML *	xml;
	WirelessSecurityManager * wsm;

	g_return_if_fail (dialog != NULL);

	xml = (GladeXML *) g_object_get_data (G_OBJECT (dialog), "glade-xml");
	g_return_if_fail (xml != NULL);
	wsm = (WirelessSecurityManager *) g_object_get_data (G_OBJECT (dialog), "wireless-security-manager");
	g_assert (wsm);
	g_return_if_fail (wsm != NULL);

	/* An SSID is required */
	network_name_entry = GTK_ENTRY (glade_xml_get_widget (xml, "network_name_entry"));	
	ssid = gtk_entry_get_text (network_name_entry);
	if (ssid && strlen (ssid) > 0)
		enable = TRUE;

	/* Validate the wireless security choices */
	if (enable)
	{
		GtkComboBox * security_combo;

		security_combo = GTK_COMBO_BOX (glade_xml_get_widget (xml, "security_combo"));
		enable = wsm_validate_active (wsm, security_combo, ssid);
	}

	ok_button = GTK_BUTTON (glade_xml_get_widget (xml, "ok_button"));
	gtk_widget_set_sensitive (GTK_WIDGET (ok_button), enable);
}

/*
 * nma_ond_device_combo_changed
 *
 * Replace current wireless security information with options
 * suitable for the current network device.
 *
 */
static void nma_ond_device_combo_changed (GtkWidget *dev_combo, gpointer user_data)
{
	GtkDialog *	dialog = (GtkDialog *) user_data;
	WirelessSecurityManager * wsm;
	GtkWidget *	wso_widget;
	GladeXML *	xml;
	GtkWidget *	vbox;
	GtkWidget *	security_combo;
	GList *		elt;
	NetworkDevice *dev;
	char *		str;
	GtkTreeModel *	model;
	GtkTreeIter	iter;

	g_return_if_fail (dialog != NULL);
	xml = (GladeXML *) g_object_get_data (G_OBJECT (dialog), "glade-xml");
	g_return_if_fail (xml != NULL);

	wsm = g_object_get_data (G_OBJECT (dialog), "wireless-security-manager");
	g_return_if_fail (wsm != NULL);

	vbox = glade_xml_get_widget (xml, "wireless_security_vbox");

	/* Remove any previous wireless security widgets */
	for (elt = gtk_container_get_children (GTK_CONTAINER (vbox)); elt; elt = g_list_next (elt))
	{
		GtkWidget * child = GTK_WIDGET (elt->data);

		if (wso_is_wso_widget (child))
			gtk_container_remove (GTK_CONTAINER (vbox), child);
	}

	/* Update WirelessSecurityManager with the new device's capabilities */
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (dev_combo), &iter);
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (dev_combo));
	gtk_tree_model_get (model, &iter, NAME_COLUMN, &str, DEV_COLUMN, &dev, -1);
	g_assert (dev);

	wsm_set_capabilities (wsm, network_device_get_type_capabilities (dev));
	security_combo = glade_xml_get_widget (xml, "security_combo");
	wsm_update_combo (wsm, GTK_COMBO_BOX (security_combo));

	/* Determine and add the correct wireless security widget to the dialog */
	wso_widget = wsm_get_widget_for_active (wsm, GTK_COMBO_BOX (security_combo), GTK_SIGNAL_FUNC (update_button_cb), dialog);
	if (wso_widget)
		gtk_container_add (GTK_CONTAINER (vbox), wso_widget);

	update_button_cb (NULL, dialog);
}


/*
 * nma_ond_security_combo_changed
 *
 * Replace the current wireless security widgets with new ones
 * according to what the user chose.
 *
 */
static void nma_ond_security_combo_changed (GtkWidget *combo, gpointer user_data)
{
	GtkDialog *	dialog = (GtkDialog *) user_data;
	WirelessSecurityManager * wsm;
	GtkWidget *	wso_widget;
	GladeXML *	xml;
	GtkWidget *	vbox;
	GList *		elt;

	g_return_if_fail (dialog != NULL);
	xml = (GladeXML *) g_object_get_data (G_OBJECT (dialog), "glade-xml");
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
	wso_widget = wsm_get_widget_for_active (wsm, GTK_COMBO_BOX (combo), GTK_SIGNAL_FUNC (update_button_cb), dialog);
	if (wso_widget)
		gtk_container_add (GTK_CONTAINER (vbox), wso_widget);

	update_button_cb (NULL, dialog);
}

static GtkTreeModel * create_wireless_adapter_model (NMApplet *applet)
{
	GtkListStore *	model;
	GSList *		elt;

	model = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_POINTER);

	for (elt = applet->device_list; elt; elt = g_slist_next (elt))
	{
		NetworkDevice *dev = (NetworkDevice *)(elt->data);

		g_assert (dev);

		/* Ignore unsupported devices */
		if (!(network_device_get_capabilities (dev) & NM_DEVICE_CAP_NM_SUPPORTED))
			continue;

		if (network_device_is_wireless (dev))
		{
			GtkTreeIter iter;
			const char *name;

			network_device_ref (dev);
			if (!(name = network_device_get_desc (dev)))
				name = network_device_get_iface (dev);

			gtk_list_store_append (model, &iter);
			gtk_list_store_set (model, &iter, NAME_COLUMN, name, DEV_COLUMN, dev, -1);
		}
	}

	g_object_ref (G_OBJECT (model));
	return GTK_TREE_MODEL (model);
}

static void destroy_wireless_adapter_model (GtkTreeModel *model)
{
	GtkTreeIter	iter;
	gboolean		valid;

	g_return_if_fail (model != NULL);

	valid = gtk_tree_model_get_iter_first (model, &iter);
	while (valid)
	{
		char *str;
		NetworkDevice *dev;

		gtk_tree_model_get (model, &iter, NAME_COLUMN, &str, DEV_COLUMN, &dev, -1);
		if (dev)
			network_device_unref (dev);
		valid = gtk_tree_model_iter_next (model, &iter);
	}

	g_object_unref (G_OBJECT (model));
}


static const char * get_host_name (void)
{
#if GLIB_CHECK_VERSION(2,8,0)
	const char *hostname = g_get_host_name ();
#else
	char hostname[HOST_NAME_MAX] = "hostname";

	gethostname (hostname, HOST_NAME_MAX);
	hostname[HOST_NAME_MAX-1] = '\0';	/* unspecified whether a truncated hostname is terminated */
#endif

	return hostname;
}



static GtkDialog *nma_ond_init (GladeXML *xml, NMApplet *applet, gboolean create_network)
{
	GtkDialog *				dialog = NULL;
	GtkWidget *				network_name_entry;
	GtkWidget *				button;
	WirelessSecurityManager *	wsm;
	GtkComboBox *				security_combo;
	gint						n_wireless_interfaces = 0;
	char *					label;
	GtkTreeModel *				model;
	gboolean					valid;
	GtkWidget *				combo;
	GtkTreeIter				iter;
	NetworkDevice *			dev;
	char *					str;
	int						dev_caps;

	g_return_val_if_fail (xml != NULL, NULL);
	g_return_val_if_fail (applet != NULL, NULL);

	/* Set up the dialog */
	if (!(dialog = GTK_DIALOG (glade_xml_get_widget (xml, "other_network_dialog"))))
		return NULL;

	g_object_set_data (G_OBJECT (dialog), "glade-xml", xml);
	g_object_set_data (G_OBJECT (dialog), "applet", applet);
	g_object_set_data (G_OBJECT (dialog), "create-network", GINT_TO_POINTER (create_network));

	network_name_entry = glade_xml_get_widget (xml, "network_name_entry");
	button = glade_xml_get_widget (xml, "ok_button");
	gtk_widget_grab_default (GTK_WIDGET (button));
#if GTK_CHECK_VERSION(2,6,0)
	{
		GtkWidget *connect_image = gtk_image_new_from_stock (GTK_STOCK_CONNECT, GTK_ICON_SIZE_BUTTON);
		gtk_button_set_image (GTK_BUTTON (button), connect_image);
	}
#endif

	gtk_widget_grab_focus (network_name_entry);
	gtk_widget_set_sensitive (button, FALSE);
	g_signal_connect (network_name_entry, "changed", G_CALLBACK (update_button_cb), dialog);

	model = create_wireless_adapter_model (applet);

	valid = gtk_tree_model_get_iter_first (model, &iter);
	while (valid)
	{
		n_wireless_interfaces++;
		valid = gtk_tree_model_iter_next (model, &iter);
	}

	/* Can connect to a wireless network if there aren't any wireless devices */
	if (n_wireless_interfaces < 1)
		return NULL;

	combo = glade_xml_get_widget (xml, "wireless_adapter_combo");
	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), model);
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 0);
	g_signal_connect (G_OBJECT (combo), "changed", GTK_SIGNAL_FUNC (nma_ond_device_combo_changed), dialog);

	if (n_wireless_interfaces == 1)
	{
		gtk_widget_hide (glade_xml_get_widget (xml, "wireless_adapter_label"));
		gtk_widget_hide (combo);
	}

	wsm = wsm_new (applet->glade_file);
	g_object_set_data (G_OBJECT (dialog), "wireless-security-manager", (gpointer) wsm);

	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter);
	gtk_tree_model_get (model, &iter, NAME_COLUMN, &str, DEV_COLUMN, &dev, -1);
	g_assert (dev);
	dev_caps = network_device_get_type_capabilities (dev);
	/* Can't do WPA2/CCMP or WPA-EAP Ad-Hoc networks because wpa_supplicant
	 * doesn't support the former and the latter does not make sense.
	 */
	if (create_network)
		dev_caps &= ~(NM_802_11_CAP_PROTO_WPA2 | NM_802_11_CAP_KEY_MGMT_802_1X);
	wsm_set_capabilities (wsm, dev_caps);

	security_combo = GTK_COMBO_BOX (glade_xml_get_widget (xml, "security_combo"));
	wsm_update_combo (wsm, security_combo);
	g_signal_connect (G_OBJECT (security_combo), "changed", GTK_SIGNAL_FUNC (nma_ond_security_combo_changed), dialog);
	nma_ond_security_combo_changed (GTK_WIDGET (security_combo), dialog);

	if (create_network)
	{
		gchar * default_essid_text;
		const char * hostname = get_host_name ();

		gtk_entry_set_text (GTK_ENTRY (network_name_entry), hostname);
		gtk_editable_set_position (GTK_EDITABLE (network_name_entry), -1);

		default_essid_text = g_strdup_printf (_("By default, the wireless"
				" network's name is set to your computer's name, %s, with"
				" no encryption enabled"),
		                                      hostname);

		label = g_strdup_printf ("<span size=\"larger\" weight=\"bold\">%s</span>\n\n%s\n\n%s",
		                         _("Create new wireless network"),
		                         _("Enter the name and security settings of the wireless network you wish to create."),
		                         default_essid_text);
		g_free (default_essid_text);

		gtk_window_set_title (GTK_WINDOW(dialog), _("Create New Wireless Network"));
	}
	else
	{
		label = g_strdup_printf ("<span size=\"larger\" weight=\"bold\">%s</span>\n\n%s",
		                         _("Existing wireless network"),
		                         _("Enter the name of the wireless network to which you wish to connect."));

		gtk_window_set_title (GTK_WINDOW (dialog), _("Connect to Other Wireless Network"));
	}

	gtk_label_set_markup (GTK_LABEL (glade_xml_get_widget (xml, "caption_label")), label);
	g_free (label);

	return dialog;
}


static void nma_ond_response_cb (GtkDialog *dialog, gint response, gpointer data)
{
	GladeXML *		xml;
	NMApplet *		applet;
	gboolean			create_network;
	GtkTreeModel *		model;
	GtkComboBox *		combo;
	WirelessSecurityManager *wsm;

	xml = (GladeXML *) g_object_get_data (G_OBJECT (dialog), "glade-xml");
	applet = (NMApplet *) g_object_get_data (G_OBJECT (dialog), "applet");
	create_network = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (dialog), "create-network"));

	combo = GTK_COMBO_BOX (glade_xml_get_widget (xml, "wireless_adapter_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));

	wsm = g_object_get_data (G_OBJECT (dialog), "wireless-security-manager");
	g_assert (wsm);

	if (response == GTK_RESPONSE_OK)
	{
		GtkEntry *	network_name_entry;
		const char *	essid = NULL;

		network_name_entry = GTK_ENTRY (glade_xml_get_widget (xml, "network_name_entry"));
		essid = gtk_entry_get_text (network_name_entry);

		if (essid[0] != '\000')
		{
			WirelessSecurityOption *	opt;
			GtkComboBox *			security_combo;
			GtkTreeIter			iter;
			char *				str;
			NetworkDevice *		dev;

			gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter);
			gtk_tree_model_get (model, &iter, NAME_COLUMN, &str, DEV_COLUMN, &dev, -1);

			security_combo = GTK_COMBO_BOX (glade_xml_get_widget (xml, "security_combo"));
			opt = wsm_get_option_for_active (wsm, security_combo);

			if (create_network)
				nma_dbus_create_network (applet->connection, dev, essid, opt);
			else
				nma_dbus_set_device (applet->connection, dev, essid, opt);
		}
	}

	g_object_set_data (G_OBJECT (dialog), "glade-xml", NULL);
	g_object_unref (xml);

	g_object_set_data (G_OBJECT (dialog), "applet", NULL);
	g_object_set_data (G_OBJECT (dialog), "create-network", NULL);

	g_object_set_data (G_OBJECT (dialog), "wireless-security-manager", NULL);
	wsm_free (wsm);

	gtk_widget_destroy (GTK_WIDGET (dialog));
	destroy_wireless_adapter_model (model);
}


void nma_other_network_dialog_run (NMApplet *applet, gboolean create_network)
{
	GtkWidget *	dialog;
	GladeXML *	xml;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (applet->glade_file != NULL);

	if (!(xml = glade_xml_new (applet->glade_file, "other_network_dialog", NULL)))
	{
		nma_schedule_warning_dialog (applet, _("The NetworkManager Applet could not find some required resources (the glade file was not found)."));
		return;
	}

	if (!(dialog = GTK_WIDGET (nma_ond_init (xml, applet, create_network))))
		return;
	g_signal_connect (dialog, "response", G_CALLBACK (nma_ond_response_cb), NULL);

	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER_ALWAYS);
	gtk_widget_realize (dialog);
	gdk_x11_window_set_user_time (dialog->window, gtk_get_current_event_time ());
	gtk_window_present (GTK_WINDOW (dialog));
}
