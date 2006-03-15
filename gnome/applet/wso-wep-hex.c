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

#include "wireless-security-option.h"
#include "wso-wep-hex.h"
#include "wso-private.h"
#include "cipher.h"
#include "cipher-wep-hex.h"
#include "dbus-helpers.h"


struct OptData
{
	const char *	entry_name;
	const char *	auth_combo_name;
	const char *	show_checkbutton_name;
};

static void data_free_func (WirelessSecurityOption *opt)
{
	GtkWidget * combo;

	g_return_if_fail (opt != NULL);
	g_return_if_fail (opt->data != NULL);

	combo = glade_xml_get_widget (opt->uixml, opt->data->auth_combo_name);
	wso_wep_auth_combo_cleanup (opt, GTK_COMBO_BOX (combo));

	g_free (opt->data);
}


static void show_key_cb (GtkToggleButton *button, GtkEntry *entry)
{
	gtk_entry_set_visibility (entry, gtk_toggle_button_get_active (button));
}


static GtkWidget * widget_create_func (WirelessSecurityOption *opt, GtkSignalFunc validate_cb, gpointer user_data)
{
	GtkWidget *	entry;
	GtkWidget *	checkbutton;
	GtkWidget *	combo;
	GtkWidget *	widget;

	g_return_val_if_fail (opt != NULL, NULL);
	g_return_val_if_fail (opt->data != NULL, NULL);
	g_return_val_if_fail (validate_cb != NULL, NULL);

	widget = wso_widget_helper (opt);
	entry = glade_xml_get_widget (opt->uixml, opt->data->entry_name);
	g_signal_connect (G_OBJECT (entry), "changed", validate_cb, user_data);

	checkbutton = glade_xml_get_widget (opt->uixml, opt->data->show_checkbutton_name);
	g_signal_connect (G_OBJECT (checkbutton), "toggled", GTK_SIGNAL_FUNC (show_key_cb), GTK_ENTRY (entry));

	combo = glade_xml_get_widget (opt->uixml, opt->data->auth_combo_name);
	wso_wep_auth_combo_setup (opt, GTK_COMBO_BOX (combo));

	return widget;
}


static gboolean validate_input_func (WirelessSecurityOption *opt, const char *ssid, IEEE_802_11_Cipher ** out_cipher)
{
	GtkWidget *	entry;
	const char *	input;

	g_return_val_if_fail (opt != NULL, FALSE);

	entry = glade_xml_get_widget (opt->uixml, opt->data->entry_name);
	input = gtk_entry_get_text (GTK_ENTRY (entry));
	return wso_validate_helper (opt, ssid, input, out_cipher);
}


static gboolean append_dbus_params_func (WirelessSecurityOption *opt, const char *ssid, DBusMessage *message)
{
	IEEE_802_11_Cipher *	cipher = NULL;
	GtkWidget *			auth_combo;
	int					auth_alg = -1;
	GtkWidget *			entry;
	const char *			input;

	g_return_val_if_fail (opt != NULL, FALSE);
	g_return_val_if_fail (opt->data != NULL, FALSE);
	g_return_val_if_fail (opt->data->auth_combo_name != NULL, FALSE);
	g_return_val_if_fail (opt->data->entry_name != NULL, FALSE);

	entry = glade_xml_get_widget (opt->uixml, opt->data->entry_name);
	input = gtk_entry_get_text (GTK_ENTRY (entry));
	if (!wso_validate_helper (opt, ssid, input, &cipher) || !cipher)
		return FALSE;

	auth_combo = glade_xml_get_widget (opt->uixml, opt->data->auth_combo_name);
	auth_alg = wso_wep_auth_combo_get_auth_alg (opt, GTK_COMBO_BOX (auth_combo));

	nmu_security_serialize_wep_with_cipher (message, cipher, ssid, input, auth_alg);
	return TRUE;
}


WirelessSecurityOption * wso_wep_hex_new (const char *glade_file)
{
	WirelessSecurityOption * opt = NULL;
	OptData *				data = NULL;

	g_return_val_if_fail (glade_file != NULL, NULL);

	opt = g_malloc0 (sizeof (WirelessSecurityOption));
	opt->name = g_strdup (_("WEP 64/128-bit Hex"));
	opt->widget_name = "wep_key_notebook";
	opt->data_free_func = data_free_func;
	opt->validate_input_func = validate_input_func;
	opt->widget_create_func = widget_create_func;
	opt->append_dbus_params_func = append_dbus_params_func;

	if (!(opt->uixml = glade_xml_new (glade_file, opt->widget_name, NULL)))
	{
		wso_free (opt);
		return NULL;
	}
	opt->ciphers = g_slist_append (opt->ciphers, cipher_wep128_hex_new ());
	opt->ciphers = g_slist_append (opt->ciphers, cipher_wep64_hex_new ());

	/* Option-specific data */
	opt->data = data = g_malloc0 (sizeof (OptData));
	data->entry_name = "wep_key_entry";
	data->auth_combo_name = "auth_method_combo";
	data->show_checkbutton_name = "show_checkbutton";

	return opt;
}

