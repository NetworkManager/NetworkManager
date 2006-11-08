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
#include <string.h>
#include <glade/glade.h>
#include <iwlib.h>
#include <dbus/dbus.h>

#include "wireless-security-option.h"
#include "cipher.h"
#include "wso-private.h"
#include "NetworkManager.h"

gboolean wso_is_wso_widget (GtkWidget * widget)
{
	gpointer	tag;

	g_return_val_if_fail (widget != NULL, FALSE);

	tag = g_object_get_data (G_OBJECT (widget), WS_TAG_NAME);
	if (tag && (GPOINTER_TO_INT (tag) == WS_TAG_MAGIC))
		return TRUE;
	return FALSE;
}

const char * wso_get_name (WirelessSecurityOption * opt)
{
	g_return_val_if_fail (opt != NULL, NULL);

	return opt->name;
}

GtkWidget * wso_get_widget (WirelessSecurityOption * opt, GtkSignalFunc validate_cb, gpointer user_data)
{
	g_return_val_if_fail (opt != NULL, NULL);
	g_return_val_if_fail (validate_cb != NULL, NULL);

	if (!opt->widget && opt->widget_create_func)
		opt->widget = (*(opt->widget_create_func))(opt, validate_cb, user_data);
	return opt->widget;
}

gboolean wso_validate_input (WirelessSecurityOption * opt, const char * ssid, IEEE_802_11_Cipher ** out_cipher)
{
	g_return_val_if_fail (opt != NULL, FALSE);
	g_return_val_if_fail (ssid != NULL, FALSE);

	if (opt->validate_input_func)
		return (*(opt->validate_input_func))(opt, ssid, out_cipher);
	return FALSE;
}

gboolean wso_append_dbus_params (WirelessSecurityOption *opt, const char *ssid, DBusMessage *message)
{
	g_return_val_if_fail (opt != NULL, FALSE);
	g_return_val_if_fail (ssid != NULL, FALSE);
	g_return_val_if_fail (message != NULL, FALSE);

	g_assert (opt->append_dbus_params_func);
	return (*(opt->append_dbus_params_func))(opt, ssid, message);
}

void wso_free (WirelessSecurityOption * opt)
{
	/* Free the option-specific data first */
	if (opt->data_free_func)
		(*(opt->data_free_func))(opt);

	g_free (opt->name);
	if (opt->uixml)
		g_object_unref (opt->uixml);
	if (opt->widget)
		g_object_unref (opt->widget);
	g_slist_foreach (opt->ciphers, (GFunc) ieee_802_11_cipher_unref, NULL);
	g_slist_free (opt->ciphers);

	memset (opt, 0, sizeof (WirelessSecurityOption));
	g_free (opt);
}


/**********************************************/

gboolean wso_validate_helper (WirelessSecurityOption *opt, const char *ssid, const char *input, IEEE_802_11_Cipher ** out_cipher)
{
	GSList * elt;

	g_return_val_if_fail (opt != NULL, FALSE);
	g_return_val_if_fail (input != NULL, FALSE);
	g_return_val_if_fail (ssid != NULL, FALSE);

	if (out_cipher)
		g_return_val_if_fail (*out_cipher == NULL, FALSE);

	/* Try each of our ciphers in turn, if one validates that's enough */
	for (elt = opt->ciphers; elt; elt = g_slist_next (elt))
	{
		IEEE_802_11_Cipher * cipher = (IEEE_802_11_Cipher *) (elt->data);
		if (ieee_802_11_cipher_validate (cipher, ssid, input) == 0)
		{
			if (out_cipher)
				*out_cipher = cipher;
			return TRUE;
		}
	}
	return FALSE;
}


GtkWidget * wso_widget_helper (WirelessSecurityOption *opt)
{
	GtkWidget * widget;

	g_return_val_if_fail (opt != NULL, NULL);

	widget = glade_xml_get_widget (opt->uixml, opt->widget_name);
	g_object_ref (G_OBJECT (widget));
	g_object_set_data (G_OBJECT (widget), WS_TAG_NAME, GINT_TO_POINTER (WS_TAG_MAGIC));
	return widget;
}


#define NAME_COLUMN			0
#define AUTH_ALG_COLUMN		1
void wso_wep_auth_combo_setup (WirelessSecurityOption *opt, GtkComboBox * combo)
{
	GtkListStore *	model;
	GtkTreeIter	iter;

	g_return_if_fail (opt != NULL);
	g_return_if_fail (combo != NULL);

	model = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);

	gtk_list_store_append (model, &iter);
	gtk_list_store_set (model, &iter, NAME_COLUMN, _("Open System"), AUTH_ALG_COLUMN, IW_AUTH_ALG_OPEN_SYSTEM, -1);

	gtk_list_store_append (model, &iter);
	gtk_list_store_set (model, &iter, NAME_COLUMN, _("Shared Key"), AUTH_ALG_COLUMN, IW_AUTH_ALG_SHARED_KEY, -1);

	g_object_ref (G_OBJECT (model));

	gtk_combo_box_set_model (combo, GTK_TREE_MODEL (model));
	gtk_combo_box_set_active (combo, 0);
}

int wso_wep_auth_combo_get_auth_alg (WirelessSecurityOption *opt, GtkComboBox * combo)
{
	GtkTreeIter	iter;
	GtkTreeModel *	model;
	int			auth_alg;

	g_return_val_if_fail (opt != NULL, -1);
	g_return_val_if_fail (combo != NULL, -1);

	model = gtk_combo_box_get_model (combo);
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter);
	gtk_tree_model_get (model, &iter, AUTH_ALG_COLUMN, &auth_alg, -1);
	return auth_alg;
}

void wso_wep_auth_combo_cleanup (WirelessSecurityOption *opt, GtkComboBox * combo)
{
	GtkListStore * model;

	g_return_if_fail (opt != NULL);
	g_return_if_fail (combo != NULL);

	model = GTK_LIST_STORE (gtk_combo_box_get_model (combo));
	g_object_unref (G_OBJECT (model));
}


GtkTreeModel *
wso_wpa_create_key_type_model (int capabilities, gboolean wpa_eap, int *num_added)
{
	GtkListStore *	model;
	GtkTreeIter	iter;
	int			num = 1;
	const char *	name;

	g_return_val_if_fail (num_added != NULL, NULL);

	model = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);

	name = _("Automatic (Default)");
	gtk_list_store_append (model, &iter);
	gtk_list_store_set (model, &iter, WPA_KEY_TYPE_NAME_COL, name,
					WPA_KEY_TYPE_CIPHER_COL, NM_AUTH_TYPE_WPA_PSK_AUTO, -1);

	if (capabilities & NM_802_11_CAP_CIPHER_CCMP)
	{
		name = _("AES-CCMP");
		gtk_list_store_append (model, &iter);
		gtk_list_store_set (model, &iter, WPA_KEY_TYPE_NAME_COL, name,
			WPA_KEY_TYPE_CIPHER_COL, IW_AUTH_CIPHER_CCMP, -1);
		num++;
	}
	if (capabilities & NM_802_11_CAP_CIPHER_TKIP)
	{
		name = _("TKIP");
		gtk_list_store_append (model, &iter);
		gtk_list_store_set (model, &iter, WPA_KEY_TYPE_NAME_COL, name,
			WPA_KEY_TYPE_CIPHER_COL, IW_AUTH_CIPHER_TKIP, -1);
		num++;
	}
	if (wpa_eap && capabilities & NM_802_11_CAP_KEY_MGMT_802_1X)
	{
		name = _("Dynamic WEP");
		gtk_list_store_append (model, &iter);
		gtk_list_store_set (model, &iter, WPA_KEY_TYPE_NAME_COL, name,
			WPA_KEY_TYPE_CIPHER_COL, IW_AUTH_CIPHER_WEP104, -1);
		num++;
	}

	*num_added = num;
	return GTK_TREE_MODEL (model);
}
