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
#include <string.h>
#include <glade/glade.h>

#include "wireless-security-manager.h"
#include "wireless-security-option.h"


struct WirelessSecurityManager
{
	char *	glade_file;
	GSList *	options;
};

WirelessSecurityManager * wsm_new (const char * glade_file)
{
	WirelessSecurityManager *	wsm = NULL;
	WirelessSecurityOption *		opt;

	g_return_val_if_fail (glade_file, NULL);

	wsm = g_malloc0 (sizeof (WirelessSecurityManager));
	wsm->glade_file = g_strdup (glade_file);

	/* Add the items */
	if ((opt = wso_none_new (glade_file)))
		wsm->options = g_slist_append (wsm->options, opt);

	if ((opt = wso_wep_passphrase_new (glade_file)))
		wsm->options = g_slist_append (wsm->options, opt);

	if ((opt = wso_wep_hex_new (glade_file)))
		wsm->options = g_slist_append (wsm->options, opt);

	if ((opt = wso_wep_ascii_new (glade_file)))
		wsm->options = g_slist_append (wsm->options, opt);

/*
	if ((opt = wso_wpa_psk_passphrase_new (glade_file)))
		wsm->options = g_slist_append (wsm->options, opt);
*/

	return wsm;
}

#define NAME_COLUMN	0
#define OPT_COLUMN		1
void wsm_populate_combo (WirelessSecurityManager *wsm, GtkComboBox *combo)
{
	GtkListStore *	model;
	GSList *		elt;

	g_return_if_fail (wsm != NULL);
	g_return_if_fail (combo != NULL);

	model = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_POINTER);

	for (elt = wsm->options; elt; elt = elt->next)
	{
		WirelessSecurityOption * opt = (WirelessSecurityOption *) (elt->data);
		GtkTreeIter			iter;

		g_assert (opt);

		gtk_list_store_append (model, &iter);
		gtk_list_store_set (model, &iter, NAME_COLUMN, wso_get_name (opt), OPT_COLUMN, opt, -1);
	}

	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (model));
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 0);
}


GtkWidget * wsm_get_widget_for_active (WirelessSecurityManager *wsm, GtkComboBox *combo,
				GtkSignalFunc validate_cb, gpointer user_data)
{
	WirelessSecurityOption * opt = NULL;
	GtkTreeIter			iter;
	GtkTreeModel *			model;
	char *				str;

	g_return_val_if_fail (wsm != NULL, NULL);
	g_return_val_if_fail (combo != NULL, NULL);

	model = gtk_combo_box_get_model (combo);
	g_assert (model);
	gtk_combo_box_get_active_iter (combo, &iter);
	gtk_tree_model_get (model, &iter, NAME_COLUMN, &str, OPT_COLUMN, &opt, -1);
	g_return_val_if_fail (opt != NULL, NULL);

	return wso_get_widget (opt, validate_cb, user_data);
}

gboolean wsm_validate_active (WirelessSecurityManager *wsm, GtkComboBox *combo, const char *ssid)
{
	WirelessSecurityOption * opt = NULL;
	GtkTreeIter			iter;
	GtkTreeModel *			model;
	char *				str;

	g_return_val_if_fail (wsm != NULL, FALSE);
	g_return_val_if_fail (combo != NULL, FALSE);

	model = gtk_combo_box_get_model (combo);
	g_assert (model);
	gtk_combo_box_get_active_iter (combo, &iter);
	gtk_tree_model_get (model, &iter, NAME_COLUMN, &str, OPT_COLUMN, &opt, -1);
	g_return_val_if_fail (opt != NULL, FALSE);

	return wso_validate_input (opt, ssid);
}


void wsm_free (WirelessSecurityManager *wsm)
{
	g_return_if_fail (wsm != NULL);

	g_slist_foreach (wsm->options, (GFunc) wso_free, NULL);
	g_slist_free (wsm->options);
	memset (wsm, 0, sizeof (WirelessSecurityManager));
	g_free (wsm);
}
