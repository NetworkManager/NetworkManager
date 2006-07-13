/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
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
 * (C) Copyright 2006 Thiago Jung Bauermann <thiago.bauermann@gmail.com>
 */

/* This file is heavily based on wso-wpa-eap.c */

#include <glib.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <dbus/dbus.h>
#include <iwlib.h>

#include "wireless-security-option.h"
#include "wso-leap.h"
#include "wso-private.h"
#include "dbus-helpers.h"
#include "NetworkManager.h"


struct OptData
{
	const char *	username;
	const char *	passwd;
	const char *	key_mgmt;
};


static void
data_free_func (WirelessSecurityOption *opt)
{
	g_return_if_fail (opt != NULL);
	g_return_if_fail (opt->data != NULL);

	if (opt->data->key_mgmt) {
		   g_free((char *) opt->data->key_mgmt);
	}

	memset (opt->data, 0, sizeof (opt->data));
	g_free (opt->data);
}


static gboolean
append_dbus_params_func (WirelessSecurityOption *opt,
                         const char *ssid,
                         DBusMessage *message)
{
	GtkWidget *		entry;
	GtkTreeModel *		combo_model;
	GtkTreeIter		iter;
	DBusMessageIter	dbus_iter;

	g_return_val_if_fail (opt != NULL, FALSE);
	g_return_val_if_fail (opt->data != NULL, FALSE);

	entry = glade_xml_get_widget (opt->uixml, "leap_username_entry");
	opt->data->username = gtk_entry_get_text (GTK_ENTRY (entry));

	entry = glade_xml_get_widget (opt->uixml, "leap_password_entry");
	opt->data->passwd = gtk_entry_get_text (GTK_ENTRY (entry));

	entry = glade_xml_get_widget (opt->uixml, "leap_key_mgmt_combobox");
	combo_model = gtk_combo_box_get_model(GTK_COMBO_BOX(entry));
	gtk_combo_box_get_active_iter(GTK_COMBO_BOX(entry), &iter);
	gtk_tree_model_get(combo_model, &iter, 1, &opt->data->key_mgmt, -1);

	dbus_message_iter_init_append (message, &dbus_iter);

	nmu_security_serialize_leap_with_cipher (&dbus_iter,
								      opt->data->username,
								      opt->data->passwd,
									 opt->data->key_mgmt);

	return TRUE;
}

static GtkWidget *
widget_create_func (WirelessSecurityOption *opt,
                    GtkSignalFunc validate_cb,
                    gpointer user_data)
{
	GtkWidget *	entry;
	GtkWidget *	widget;
	GtkWidget *	key_mgmt;
	GtkListStore *	list_store;
	GtkTreeIter 	iter;

	g_return_val_if_fail (opt != NULL, NULL);
	g_return_val_if_fail (opt->data != NULL, NULL);
	g_return_val_if_fail (validate_cb != NULL, NULL);

	widget = wso_widget_helper (opt);

	entry = glade_xml_get_widget (opt->uixml, "leap_username_entry");
	g_signal_connect (G_OBJECT (entry), "changed", validate_cb, user_data);

	entry = glade_xml_get_widget (opt->uixml, "leap_password_entry");
	g_signal_connect (G_OBJECT (entry), "changed", validate_cb, user_data);

	/* set-up key_mgmt combo box */

	key_mgmt = glade_xml_get_widget (opt->uixml, "leap_key_mgmt_combobox");

	/* create tree model containing combo box items */
	list_store = gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_STRING);
	gtk_list_store_append(list_store, &iter);
	gtk_list_store_set(list_store, &iter, 0, "IEEE 802.1X", 1, "IEEE8021X", -1);
	gtk_list_store_append(list_store, &iter);
	gtk_list_store_set(list_store, &iter, 0, "WPA-EAP", 1, "WPA-EAP", -1);

	gtk_combo_box_set_model(GTK_COMBO_BOX(key_mgmt), GTK_TREE_MODEL(list_store));

	/* set default choice to be IEEE 802.1X */
	gtk_combo_box_set_active(GTK_COMBO_BOX(key_mgmt), 0);

	return widget;
}

static gboolean
validate_input_func (WirelessSecurityOption *opt,
                     const char *ssid,
                     IEEE_802_11_Cipher **out_cipher)
{
	return TRUE;
}


WirelessSecurityOption *
wso_leap_new (const char *glade_file,
              int capabilities)
{
	WirelessSecurityOption * opt = NULL;

	g_return_val_if_fail (glade_file != NULL, NULL);

	opt = g_malloc0 (sizeof (WirelessSecurityOption));
	opt->name = g_strdup("LEAP");
	opt->widget_name = "leap_notebook";
	opt->data_free_func = data_free_func;
	opt->validate_input_func = validate_input_func;
	opt->widget_create_func = widget_create_func;
	opt->append_dbus_params_func = append_dbus_params_func;

	if (!(opt->uixml = glade_xml_new (glade_file, opt->widget_name, NULL)))
	{
		wso_free (opt);
		return NULL;
	}

	/* Option-specific data */
	opt->data = g_malloc0 (sizeof (OptData));

	return opt;
}
