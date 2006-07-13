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

#include <glib.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <dbus/dbus.h>
#include <iwlib.h>

#include "wireless-security-option.h"
#include "wso-wpa-psk.h"
#include "wso-private.h"
#include "cipher.h"
#include "cipher-wpa-psk-hex.h"
#include "cipher-wpa-psk-passphrase.h"
#include "dbus-helpers.h"
#include "NetworkManager.h"


struct OptData
{
	gboolean				wpa2;
	const char *			entry_name;
	const char *			key_type_combo_name;
	const char *			show_checkbutton_name;
	IEEE_802_11_Cipher *	hex_cipher;
	IEEE_802_11_Cipher *	passphrase_cipher;
};

static void
data_free_func (WirelessSecurityOption *opt)
{
	g_return_if_fail (opt != NULL);
	g_return_if_fail (opt->data != NULL);

	ieee_802_11_cipher_ref (opt->data->passphrase_cipher);
	ieee_802_11_cipher_ref (opt->data->hex_cipher);
	memset (opt->data, 0, sizeof (opt->data));
	g_free (opt->data);
}


static void show_passphrase_cb (GtkToggleButton *button, GtkEntry *entry)
{
	gtk_entry_set_visibility (entry, gtk_toggle_button_get_active (button));
}


static GtkWidget *
widget_create_func (WirelessSecurityOption *opt,
                    GtkSignalFunc validate_cb,
                    gpointer user_data)
{
	GtkWidget *	entry;
	GtkWidget *	checkbutton;
	GtkWidget *	widget;

	g_return_val_if_fail (opt != NULL, NULL);
	g_return_val_if_fail (opt->data != NULL, NULL);
	g_return_val_if_fail (validate_cb != NULL, NULL);

	widget = wso_widget_helper (opt);
	entry = glade_xml_get_widget (opt->uixml, opt->data->entry_name);
	g_signal_connect (G_OBJECT (entry), "changed", validate_cb, user_data);

	checkbutton = glade_xml_get_widget (opt->uixml, opt->data->show_checkbutton_name);
	g_signal_connect (G_OBJECT (checkbutton), "toggled", GTK_SIGNAL_FUNC (show_passphrase_cb), GTK_ENTRY (entry));

	return widget;
}


static gboolean
validate_input_func (WirelessSecurityOption *opt,
                     const char *ssid,
                     IEEE_802_11_Cipher **out_cipher)
{
	GtkWidget *	entry;
	const char *	input;

	g_return_val_if_fail (opt != NULL, FALSE);

	entry = glade_xml_get_widget (opt->uixml, opt->data->entry_name);
	input = gtk_entry_get_text (GTK_ENTRY (entry));
	return wso_validate_helper (opt, ssid, input, out_cipher);
}


static gboolean
append_dbus_params_func (WirelessSecurityOption *opt,
                         const char *ssid,
                         DBusMessage *message)
{
	IEEE_802_11_Cipher *	cipher = NULL;
	GtkWidget *			entry;
	const char *			input;

	g_return_val_if_fail (opt != NULL, FALSE);
	g_return_val_if_fail (opt->data != NULL, FALSE);
	g_return_val_if_fail (opt->data->entry_name != NULL, FALSE);

	entry = glade_xml_get_widget (opt->uixml, opt->data->entry_name);
	input = gtk_entry_get_text (GTK_ENTRY (entry));
	if (!wso_validate_helper (opt, ssid, input, &cipher) || !cipher)
		return FALSE;

	nmu_security_serialize_wpa_psk_with_cipher (message, cipher, ssid, input,
	     opt->data->wpa2 ? IW_AUTH_WPA_VERSION_WPA2 : IW_AUTH_WPA_VERSION_WPA,
	     IW_AUTH_KEY_MGMT_PSK);

	return TRUE;
}


static void
key_type_combo_changed_cb (GtkComboBox *combo,
                           gpointer user_data)
{
	WirelessSecurityOption * opt = (WirelessSecurityOption *) user_data;
	int					we_cipher;
	GtkTreeModel *			model;
	GtkTreeIter			iter;
	GSList *				elt;

	g_return_if_fail (opt != NULL);

	model = gtk_combo_box_get_model (combo);
	gtk_combo_box_get_active_iter (combo, &iter);
	gtk_tree_model_get (model, &iter, WPA_KEY_TYPE_CIPHER_COL, &we_cipher, -1);

	for (elt = opt->ciphers; elt; elt = g_slist_next (elt))
	{
		IEEE_802_11_Cipher * cipher = (IEEE_802_11_Cipher *)(elt->data);

		if (cipher == opt->data->passphrase_cipher)
			cipher_wpa_psk_passphrase_set_we_cipher (cipher, we_cipher);
		else if (cipher == opt->data->hex_cipher)
			cipher_wpa_psk_hex_set_we_cipher (cipher, we_cipher);
	}
}


WirelessSecurityOption *
wso_wpa_psk_new (const char *glade_file,
                 int capabilities,
                 gboolean wpa2)
{
	WirelessSecurityOption * opt = NULL;
	OptData *				data = NULL;
	GtkWidget *			key_type_combo;
	int					num_added;
	GtkTreeModel *			model;
	GtkTreeIter			iter;

	g_return_val_if_fail (glade_file != NULL, NULL);

	opt = g_malloc0 (sizeof (WirelessSecurityOption));
	if (wpa2)
		opt->name = g_strdup (_("WPA2 Personal"));
	else
		opt->name = g_strdup (_("WPA Personal"));
	opt->widget_name = "wpa_psk_notebook";
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
	opt->data = data = g_malloc0 (sizeof (OptData));
	data->wpa2 = wpa2;
	data->entry_name = "wpa_psk_entry";
	data->key_type_combo_name = "wpa_psk_type_combo";
	data->show_checkbutton_name = "show_checkbutton";

	/* Set up our ciphers */
	data->passphrase_cipher = cipher_wpa_psk_passphrase_new ();
	ieee_802_11_cipher_ref (data->passphrase_cipher);
	opt->ciphers = g_slist_append (opt->ciphers, data->passphrase_cipher);
	data->hex_cipher = cipher_wpa_psk_hex_new ();
	ieee_802_11_cipher_ref (data->hex_cipher);
	opt->ciphers = g_slist_append (opt->ciphers, data->hex_cipher);

	key_type_combo = glade_xml_get_widget (opt->uixml, data->key_type_combo_name);
	g_signal_connect (G_OBJECT (key_type_combo), "changed", (GCallback) key_type_combo_changed_cb, opt);
	model = wso_wpa_create_key_type_model (capabilities, FALSE, &num_added);
	gtk_combo_box_set_model (GTK_COMBO_BOX (key_type_combo), model);
	gtk_tree_model_get_iter_first (model, &iter);
	gtk_combo_box_set_active_iter (GTK_COMBO_BOX (key_type_combo), &iter);
	if (num_added == 1)
		gtk_widget_set_sensitive (key_type_combo, FALSE);

	return opt;
}

