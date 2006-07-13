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
 * (C) Copyright 2006 Novell, Inc.
 */

#include <glib.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <dbus/dbus.h>
#include <iwlib.h>

#include "wireless-security-option.h"
#include "wso-wpa-eap.h"
#include "wso-private.h"
#include "cipher.h"
#include "dbus-helpers.h"
#include "NetworkManager.h"

#define WPA_EAP_NAME_COL		0
#define WPA_EAP_VALUE_COL	1

struct OptData
{
	int			eap_method;
	int			key_type;
	const char *	identity;
	const char *	passwd;
	const char *	anon_identity;
	const char *	private_key_passwd;
	const char *	private_key_file;
	const char *	client_cert_file;
	const char *	ca_cert_file;
	gboolean		wpa2;
};


static void
data_free_func (WirelessSecurityOption *opt)
{
	g_return_if_fail (opt != NULL);
	g_return_if_fail (opt->data != NULL);

	memset (opt->data, 0, sizeof (opt->data));
	g_free (opt->data);
}


static void show_passwords_cb (GtkToggleButton *button, WirelessSecurityOption *opt)
{
	GtkWidget *	entry;
	gboolean		visible;

	visible = gtk_toggle_button_get_active (button);

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_passwd_entry");
	gtk_entry_set_visibility (GTK_ENTRY (entry), visible);

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_private_key_passwd_entry");
	gtk_entry_set_visibility (GTK_ENTRY (entry), visible);
}


static GtkWidget *
widget_create_func (WirelessSecurityOption *opt,
                    GtkSignalFunc validate_cb,
                    gpointer user_data)
{
	GtkWidget *	entry;
	GtkWidget *	widget;
	GtkWidget *	checkbutton;

	g_return_val_if_fail (opt != NULL, NULL);
	g_return_val_if_fail (opt->data != NULL, NULL);
	g_return_val_if_fail (validate_cb != NULL, NULL);

	widget = wso_widget_helper (opt);

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_identity_entry");
	g_signal_connect (G_OBJECT (entry), "changed", validate_cb, user_data);

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_passwd_entry");
	g_signal_connect (G_OBJECT (entry), "changed", validate_cb, user_data);

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_anon_identity_entry");
	g_signal_connect (G_OBJECT (entry), "changed", validate_cb, user_data);

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_client_cert_file_chooser_button");
	g_signal_connect (G_OBJECT (entry), "selection-changed", validate_cb, user_data);

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_private_key_file_chooser_button");
	g_signal_connect (G_OBJECT (entry), "selection-changed", validate_cb, user_data);

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_ca_cert_file_chooser_button");
	g_signal_connect (G_OBJECT (entry), "selection-changed", validate_cb, user_data);

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_private_key_passwd_entry");
	g_signal_connect (G_OBJECT (entry), "changed", validate_cb, user_data);

	checkbutton = glade_xml_get_widget (opt->uixml, "show_checkbutton");
	g_signal_connect (G_OBJECT (checkbutton), "toggled", GTK_SIGNAL_FUNC (show_passwords_cb), opt);

	return widget;
}


static gboolean
validate_input_func (WirelessSecurityOption *opt,
                     const char *ssid,
                     IEEE_802_11_Cipher **out_cipher)
{
#if 0	/* FIXME: Figure out valid combinations of options and enforce */
	GtkWidget *	entry;
	GtkWidget *	filechooser;
	const char *	input;

	g_return_val_if_fail (opt != NULL, FALSE);

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_private_key_passwd_entry");
	input = gtk_entry_get_text (GTK_ENTRY (entry));
	if (!input || strlen (input) < 1)
		return FALSE;

	filechooser = glade_xml_get_widget (opt->uixml, "wpa_eap_private_key_file_chooser_button");
	input = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (filechooser));
	if (!input)
		return FALSE;

	filechooser = glade_xml_get_widget (opt->uixml, "wpa_eap_ca_cert_file_chooser_button");
	input = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (filechooser));
	if (!input)
		return FALSE;
#endif

	return TRUE;
}


static gboolean
append_dbus_params_func (WirelessSecurityOption *opt,
                         const char *ssid,
                         DBusMessage *message)
{
	GtkWidget *		entry;
	GtkTreeModel *		model;
	GtkTreeIter		tree_iter;
	DBusMessageIter	dbus_iter;

	g_return_val_if_fail (opt != NULL, FALSE);
	g_return_val_if_fail (opt->data != NULL, FALSE);

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_eap_method_combo");
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (entry));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (entry), &tree_iter);
	gtk_tree_model_get (model, &tree_iter, WPA_EAP_VALUE_COL, &opt->data->eap_method, -1);

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_key_type_combo");
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (entry));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (entry), &tree_iter);
	gtk_tree_model_get (model, &tree_iter, WPA_KEY_TYPE_CIPHER_COL, &opt->data->key_type, -1);

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_identity_entry");
	opt->data->identity = gtk_entry_get_text (GTK_ENTRY (entry)) ? : "";

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_passwd_entry");
	opt->data->passwd = gtk_entry_get_text (GTK_ENTRY (entry)) ? : "";

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_anon_identity_entry");
	opt->data->anon_identity = gtk_entry_get_text (GTK_ENTRY (entry)) ? : "";

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_client_cert_file_chooser_button");
	opt->data->client_cert_file = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (entry)) ? : "";

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_ca_cert_file_chooser_button");
	opt->data->ca_cert_file = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (entry)) ? : "";

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_private_key_file_chooser_button");
	opt->data->private_key_file = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (entry)) ? : "";

	entry = glade_xml_get_widget (opt->uixml, "wpa_eap_private_key_passwd_entry");
	opt->data->private_key_passwd = gtk_entry_get_text (GTK_ENTRY (entry)) ? : "";

	dbus_message_iter_init_append (message, &dbus_iter);

	nmu_security_serialize_wpa_eap_with_cipher (&dbus_iter,
									    opt->data->eap_method,
									    opt->data->key_type,
									    opt->data->identity,
									    opt->data->passwd,
									    opt->data->anon_identity,
									    opt->data->private_key_passwd,
									    opt->data->private_key_file,
									    opt->data->client_cert_file,
									    opt->data->ca_cert_file,
							  		    opt->data->wpa2 ? IW_AUTH_WPA_VERSION_WPA2 : IW_AUTH_WPA_VERSION_WPA);

	return TRUE;
}


WirelessSecurityOption *
wso_wpa_eap_new (const char *glade_file,
                 int capabilities,
                 gboolean wpa2)
{
	WirelessSecurityOption * opt = NULL;
	OptData *				data = NULL;
	GtkWidget *			eap_method_combo;
	GtkWidget *			key_type_combo;
	GtkListStore *			model;
	GtkTreeModel *			tree_model;
	GtkTreeIter			iter;
	GtkCellRenderer *		renderer;
	int					num_added;

	struct {
		const char *		name;
		int				value;
	} *list, eap_method_list[] = {
		{ _("PEAP"),		NM_EAP_METHOD_PEAP },
		{ _("TLS"),		NM_EAP_METHOD_TLS },
		{ _("TTLS"),		NM_EAP_METHOD_TTLS },
		{ NULL,			0 }
	};

	g_return_val_if_fail (glade_file != NULL, NULL);

	opt = g_malloc0 (sizeof (WirelessSecurityOption));
	if (wpa2)
		opt->name = g_strdup (_("WPA2 Enterprise"));
	else
		opt->name = g_strdup (_("WPA Enterprise"));
	opt->widget_name = "wpa_eap_notebook";
	opt->data_free_func = data_free_func;
	opt->validate_input_func = validate_input_func;
	opt->widget_create_func = widget_create_func;
	opt->append_dbus_params_func = append_dbus_params_func;

	if (!(opt->uixml = glade_xml_new (glade_file, opt->widget_name, NULL)))
	{
		wso_free (opt);
		return NULL;
	}

	eap_method_combo = glade_xml_get_widget (opt->uixml, "wpa_eap_eap_method_combo");
	model = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);
	list = eap_method_list;
	while (list->name)
	{
		gtk_list_store_append (model, &iter);
		gtk_list_store_set (model, &iter, WPA_EAP_NAME_COL, list->name, WPA_EAP_VALUE_COL, list->value, -1);
		list++;
	}
	gtk_combo_box_set_model (GTK_COMBO_BOX (eap_method_combo), GTK_TREE_MODEL (model));
	gtk_tree_model_get_iter_first (GTK_TREE_MODEL (model), &iter);
	gtk_combo_box_set_active_iter (GTK_COMBO_BOX (eap_method_combo), &iter);

	/* FIXME: Why do we need this here but not in the same place in wso-wpa-psk.c ? */
	renderer = gtk_cell_renderer_text_new ();
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (eap_method_combo), renderer, TRUE);
	gtk_cell_layout_set_attributes (GTK_CELL_LAYOUT (eap_method_combo), renderer, "text", 0, NULL);

	key_type_combo = glade_xml_get_widget (opt->uixml, "wpa_eap_key_type_combo");
	tree_model = wso_wpa_create_key_type_model (capabilities, TRUE, &num_added);
	gtk_combo_box_set_model (GTK_COMBO_BOX (key_type_combo), tree_model);
	gtk_tree_model_get_iter_first (tree_model, &iter);
	gtk_combo_box_set_active_iter (GTK_COMBO_BOX (key_type_combo), &iter);
	if (num_added == 1)
		gtk_widget_set_sensitive (key_type_combo, FALSE);

	/* FIXME: Why do we need this here but not in the same place in wso-wpa-psk.c ? */
	renderer = gtk_cell_renderer_text_new ();
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (key_type_combo), renderer, TRUE);
	gtk_cell_layout_set_attributes (GTK_CELL_LAYOUT (key_type_combo), renderer, "text", 0, NULL);

	/* Option-specific data */
	opt->data = data = g_malloc0 (sizeof (OptData));
	data->wpa2 = wpa2;
	data->eap_method = NM_EAP_METHOD_TLS;

	return opt;
}

