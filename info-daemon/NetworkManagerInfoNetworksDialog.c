/* NetworkManagerInfo -- Manage allowed access points and provide a UI
 *                         for WEP key entry
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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

#include "NetworkManagerInfo.h"
#include "NetworkManagerInfoNetworksDialog.h"


/*
 * nmi_networks_dialog_init
 *
 * Initialize the networks modification dialog
 *
 * Returns:	 0 on success
 *			-1 on failure
 */
int nmi_networks_dialog_init (NMIAppInfo *info)
{
	GtkWidget			*dialog;
	GtkWidget			*list_view;
	GtkButton			*save_button;
	GtkButton			*cancel_button;
	GtkCellRenderer	*renderer;
	GtkTreeViewColumn 	*column;
	GError			*error = NULL;

	info->networks_dialog = glade_xml_new(GLADEDIR"/networks.glade", NULL, NULL);
	if (!info->networks_dialog)
	{
		fprintf (stderr, "Could not open the networks dialog glade file!\n");
		return (-1);
	}
	
	dialog = glade_xml_get_widget (info->networks_dialog, "networks_dialog");
	gtk_widget_hide (dialog);

#if 0
	save_button = GTK_BUTTON (glade_xml_get_widget (info->networks_dialog, "save_button"));
	g_signal_connect (G_OBJECT (save_button), "clicked", GTK_SIGNAL_FUNC (nmi_networks_dialog_save_clicked), info);
	cancel_button = GTK_BUTTON (glade_xml_get_widget (info->networks_dialog, "cancel_button"));
	g_signal_connect (G_OBJECT (cancel_button), "clicked", GTK_SIGNAL_FUNC (nmi_networks_dialog_cancel_clicked), info);

	/* Create data store for our networks list */
	info->networks_list_store = gtk_list_store_new (N_COLUMNS, G_TYPE_INT, G_TYPE_STRING, G_TYPE_BOOLEAN);
	if (!info->networks_list_store)
		return (-1);

	/* Tell the list to use our data store */
	list_view = glade_xml_get_widget (info->networks_dialog, "networks_list");
	gtk_tree_view_set_model (GTK_TREE_VIEW (list_view), GTK_TREE_MODEL (info->networks_list_store));

	/* Set up the columns and renderers for our list */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_expand (column, TRUE);
	gtk_tree_view_column_pack_start (column, renderer, TRUE);
	gtk_tree_view_column_set_attributes (column, renderer, "markup", TEXT_COLUMN, NULL);
	gtk_tree_view_append_column (GTK_TREE_VIEW (list_view), column);

	info->padlock_pixbuf = gdk_pixbuf_new_from_file_at_size (GLADEDIR"/keyring.png", 16, 16, &error);
	if (!info->padlock_pixbuf)
		fprintf (stderr, "nmi_new_networks_dialog_init(): could not load padlock image\n");
#endif
	
	return (0);
}
