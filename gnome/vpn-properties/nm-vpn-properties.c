/***************************************************************************
 * CVSID: $Id$
 *
 * nm-vpn-properties.c : GNOME UI dialogs for manipulating VPN connections
 *
 * Copyright (C) 2005 David Zeuthen, <davidz@redhat.com>
 *
 * === 
 * NOTE NOTE NOTE: All source for nm-vpn-properties is licensed to you
 * under your choice of the Academic Free License version 2.0, or the
 * GNU General Public License version 2.
 * ===
 *
 * Licensed under the Academic Free License version 2.0
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <gnome.h>
#include <gdk/gdkx.h>
#include <gtk/gtkwindow.h>
#include <glade/glade.h>
#include <gconf/gconf-client.h>
#include <glib/gi18n-lib.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE
#include "nm-vpn-ui-interface.h"

#define NM_GCONF_VPN_CONNECTIONS_PATH "/system/networking/vpn_connections"

static GladeXML *xml;
static GConfClient *gconf_client;
static GtkWidget *dialog;
static GtkWindow *druid_window;
static GtkTreeView *vpn_conn_view;
static GtkListStore *vpn_conn_list;
static GtkWidget *vpn_edit;
static GtkWidget *vpn_export;
static GtkWidget *vpn_delete;
static GnomeDruid *druid;
static GnomeDruidPageEdge *druid_confirm_page;
static GtkComboBox *vpn_type_combo_box;
static GtkVBox *vpn_type_details;
static GtkDialog *edit_dialog;
static GSList *vpn_types;

static NetworkManagerVpnUI *
find_vpn_ui_by_service_name (const char *service_name)
{
	GSList *i;

	for (i = vpn_types; i != NULL; i = g_slist_next (i)) {
		NetworkManagerVpnUI *vpn_ui;

		vpn_ui = i->data;
		if (strcmp (vpn_ui->get_service_name (vpn_ui), service_name) == 0)
			return vpn_ui;
	}

	return NULL;
}

enum {
	VPNCONN_NAME_COLUMN,
	VPNCONN_SVC_NAME_COLUMN,
	VPNCONN_GCONF_COLUMN,
	VPNCONN_USER_CAN_EDIT_COLUMN,
	VPNCONN_N_COLUMNS
};

static void
update_edit_del_sensitivity (void)
{
	GtkTreeSelection *selection;
	gboolean is_editable, is_exportable;
	GtkTreeIter iter;

	selection = gtk_tree_view_get_selection (vpn_conn_view);
	if (!selection || !gtk_tree_selection_get_selected (selection, NULL, &iter))
		is_editable = is_exportable = FALSE;
	else {
		NetworkManagerVpnUI *vpn_ui;
		const char *service_name;

		gtk_tree_model_get (GTK_TREE_MODEL (vpn_conn_list), &iter, VPNCONN_USER_CAN_EDIT_COLUMN, &is_editable, -1);
		gtk_tree_model_get (GTK_TREE_MODEL (vpn_conn_list), &iter, VPNCONN_SVC_NAME_COLUMN, &service_name, -1);

		vpn_ui = find_vpn_ui_by_service_name (service_name);
		is_exportable = vpn_ui->can_export (vpn_ui);
	}

	gtk_widget_set_sensitive (vpn_edit, is_editable);
	gtk_widget_set_sensitive (vpn_delete, is_editable);
	gtk_widget_set_sensitive (vpn_export, is_editable && is_exportable);
}

static gboolean
add_vpn_connection (const char *conn_name, const char *service_name, GSList *conn_data, GSList *routes)
{
	char *gconf_key;
	GtkTreeIter iter;
	char conn_gconf_path[PATH_MAX];
	char *escaped_conn_name;
	gboolean ret;
	gboolean conn_user_can_edit = TRUE;

	ret = FALSE;

	escaped_conn_name = gconf_escape_key (conn_name, strlen (conn_name));

	g_snprintf (conn_gconf_path, 
		    sizeof (conn_gconf_path), 
		    NM_GCONF_VPN_CONNECTIONS_PATH "/%s",
		    escaped_conn_name);

	if (gconf_client_dir_exists (gconf_client, conn_gconf_path, NULL))
		goto out;
	       
	/* User-visible name of connection */
	gconf_key = g_strdup_printf ("%s/name", conn_gconf_path);
	gconf_client_set_string (gconf_client, gconf_key, conn_name, NULL);

	/* Service name of connection */
	gconf_key = g_strdup_printf ("%s/service_name", conn_gconf_path);
	gconf_client_set_string (gconf_client, gconf_key, service_name, NULL);

	/* vpn-daemon specific data */
	gconf_key = g_strdup_printf ("%s/vpn_data", conn_gconf_path);
	{
		gconf_client_set_list (gconf_client, gconf_key, GCONF_VALUE_STRING, conn_data, NULL);
	}

	/* routes */
	gconf_key = g_strdup_printf ("%s/routes", conn_gconf_path);

#if 0
	{
		GSList *i;

		i = NULL;
		i = g_slist_append (i, "172.16.0.0/16");
		gconf_client_set_list (gconf_client, gconf_key, GCONF_VALUE_STRING, routes, NULL);
		g_slist_free (i);
	}
#else
		gconf_client_set_list (gconf_client, gconf_key, GCONF_VALUE_STRING, routes, NULL);
#endif

	gconf_client_suggest_sync (gconf_client, NULL);

	conn_user_can_edit = TRUE;

	gtk_list_store_append (vpn_conn_list, &iter);
	gtk_list_store_set (vpn_conn_list, &iter,
			    VPNCONN_NAME_COLUMN, conn_name,
			    VPNCONN_SVC_NAME_COLUMN, service_name,
			    VPNCONN_GCONF_COLUMN, conn_gconf_path,
			    VPNCONN_USER_CAN_EDIT_COLUMN, &conn_user_can_edit,
			    -1);

	ret = TRUE;

out:
	g_free (escaped_conn_name);
	return ret;
}

static void 
vpn_druid_vpn_validity_changed (NetworkManagerVpnUI *vpn_ui,
				gboolean is_valid, 
				gpointer user_data)
{
	char *conn_name;
	GtkTreeIter iter;

	/*printf ("vpn_druid_vpn_validity_changed %d!\n", is_valid);*/

	conn_name = vpn_ui->get_connection_name (vpn_ui);

	/* get list of existing connection names */
	if (gtk_tree_model_get_iter_first (GTK_TREE_MODEL (vpn_conn_list), &iter)) {
		do {
			char *name;

			gtk_tree_model_get (GTK_TREE_MODEL (vpn_conn_list),
					    &iter,
					    VPNCONN_NAME_COLUMN,
					    &name,
					    -1);
			
			if (strcmp (name, conn_name) == 0) {
				/*printf ("name '%s' is already in use\n", conn_name);*/
				is_valid = FALSE;
				break;
			}

		} while (gtk_tree_model_iter_next (GTK_TREE_MODEL (vpn_conn_list), &iter));
	}

	g_free (conn_name);

	gnome_druid_set_buttons_sensitive (druid, 
					   TRUE,
					   is_valid,
					   TRUE,
					   FALSE);
}


static gboolean vpn_druid_vpn_type_page_next (GnomeDruidPage *druidpage,
					      GtkWidget *widget,
					      gpointer user_data)
{
	GtkWidget *w;
	NetworkManagerVpnUI *vpn_ui;

	/*printf ("vpn_type_next!\n");*/

	/* first hide existing child */
	w = g_list_nth_data (gtk_container_children (GTK_CONTAINER (vpn_type_details)), 0);
	if (w != NULL) {
		gtk_widget_hide (w);
	}

	/* show appropriate child */
	vpn_ui = (NetworkManagerVpnUI *) g_slist_nth_data (vpn_types, gtk_combo_box_get_active (vpn_type_combo_box));
	if (vpn_ui != NULL) {
		w = vpn_ui->get_widget (vpn_ui, NULL, NULL, NULL);
		if (w != NULL) {	
			GtkWidget *old_parent;
			gtk_widget_ref (w);
			old_parent = gtk_widget_get_parent (w);
			if (old_parent != NULL)
				gtk_container_remove (GTK_CONTAINER (old_parent), w);
			gtk_container_add (GTK_CONTAINER (vpn_type_details), w);
			gtk_widget_unref (w);

			gtk_widget_show_all (w);
		}

		vpn_ui->set_validity_changed_callback (vpn_ui, vpn_druid_vpn_validity_changed, NULL);
	}

	return FALSE;
}

static void vpn_druid_vpn_details_page_prepare (GnomeDruidPage *druidpage,
						GtkWidget *widget,
						gpointer user_data)
{
	gnome_druid_set_buttons_sensitive (druid, TRUE, FALSE, TRUE, FALSE);	
}

static gboolean vpn_druid_vpn_details_page_next (GnomeDruidPage *druidpage,
						 GtkWidget *widget,
						 gpointer user_data)
{
	gboolean is_valid;
	NetworkManagerVpnUI *vpn_ui;

	is_valid = FALSE;

	/*printf ("vpn_details_next!\n");*/

	/* validate input */
	vpn_ui = (NetworkManagerVpnUI *) g_slist_nth_data (vpn_types, gtk_combo_box_get_active (vpn_type_combo_box));
	if (vpn_ui != NULL)
		is_valid = vpn_ui->is_valid (vpn_ui);

	return !is_valid;
}

static void vpn_druid_vpn_confirm_page_prepare (GnomeDruidPage *druidpage,
						GtkWidget *widget,
						gpointer user_data)
{
	NetworkManagerVpnUI *vpn_ui;

	/*printf ("vpn_confirm_prepare!\n");*/

	vpn_ui = (NetworkManagerVpnUI *) g_slist_nth_data (vpn_types, gtk_combo_box_get_active (vpn_type_combo_box));
	if (vpn_ui != NULL) {
		gchar *confirm_text;

		vpn_ui->get_confirmation_details (vpn_ui, &confirm_text);
		
		gnome_druid_page_edge_set_text (druid_confirm_page,
						confirm_text);

		g_free (confirm_text);
	}
}

static gboolean vpn_druid_vpn_confirm_page_finish (GnomeDruidPage *druidpage,
						   GtkWidget *widget,
						   gpointer user_data)
{
	GSList *conn_data;
	GSList *conn_routes;
	char *conn_name;
	NetworkManagerVpnUI *vpn_ui;

	/*printf ("vpn_confirm_finish!\n");*/

	vpn_ui = (NetworkManagerVpnUI *) g_slist_nth_data (vpn_types, gtk_combo_box_get_active (vpn_type_combo_box));
	conn_name   = vpn_ui->get_connection_name (vpn_ui);
	conn_data   = vpn_ui->get_properties (vpn_ui);
	conn_routes = vpn_ui->get_routes (vpn_ui);

	add_vpn_connection (conn_name, vpn_ui->get_service_name (vpn_ui), conn_data, conn_routes);

	gtk_widget_hide_all (GTK_WIDGET (druid_window));

	return FALSE;
}

static gboolean vpn_druid_cancel (GnomeDruid *ignored_druid, gpointer user_data)
{
	gtk_widget_hide_all (GTK_WIDGET (druid_window));
	return FALSE;
}



static void
add_cb (GtkButton *button, gpointer user_data)
{
	GtkWidget *w;
	GList *i;
	GList *children;

	/* Bail out if we don't have any VPN implementations on our system */
	if (vpn_types == NULL || g_slist_length (vpn_types) == 0) {
		GtkWidget *err_dialog;

		err_dialog = gtk_message_dialog_new (NULL,
						 GTK_DIALOG_DESTROY_WITH_PARENT,
						 GTK_MESSAGE_ERROR,
						 GTK_BUTTONS_CLOSE,
						 _("Cannot add VPN connection"));
		gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (err_dialog),
		   _("No suitable VPN software was found on your system. Contact your system administrator."));
		gtk_dialog_run (GTK_DIALOG (err_dialog));
		gtk_widget_destroy (err_dialog);
		goto out;
	}

	/* remove existing VPN widget */
	children = gtk_container_get_children (GTK_CONTAINER (vpn_type_details));
	for (i = children; i != NULL; i = g_list_next (i)) {
		w = GTK_WIDGET (i->data);
		g_object_ref (G_OBJECT (w));
		gtk_container_remove (GTK_CONTAINER (vpn_type_details), w);
	}
	g_list_free (children);

	w = glade_xml_get_widget (xml, "vpn-druid-vpn-start");
	gnome_druid_set_page (druid, GNOME_DRUID_PAGE (w));

	gtk_widget_set_sensitive (w, TRUE);

	gtk_window_set_policy (druid_window, FALSE, FALSE, TRUE);

	gtk_widget_show_all (GTK_WIDGET (druid_window));
out:
	;
}


static void
import_settings (const char *svc_name, const char *name)
{
	GtkWidget *w;
	GList *i;
	GList *children;
	NetworkManagerVpnUI *vpn_ui;

	/*printf ("import_settings svc_name='%s', name='%s' vpn-ui-=\n", svc_name, name);*/

	vpn_ui = find_vpn_ui_by_service_name (svc_name);

	/* Bail out if we don't have the requested VPN implementation on our system */
	if (vpn_ui == NULL) {
		char *basename;
		GtkWidget *err_dialog;

		basename = g_path_get_basename (name);

		err_dialog = gtk_message_dialog_new (NULL,
						 GTK_DIALOG_DESTROY_WITH_PARENT,
						 GTK_MESSAGE_ERROR,
						 GTK_BUTTONS_CLOSE,
						 _("Cannot import VPN connection"));
		gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (err_dialog),
							  _("Cannot find suitable software for VPN connection type '%s' to import the file '%s'. Contact your system administrator."),
							  svc_name, basename);
		gtk_dialog_run (GTK_DIALOG (err_dialog));
		gtk_widget_destroy (err_dialog);
		g_free (basename);
		goto out;
	}

	/* remove existing VPN widget */
	children = gtk_container_get_children (GTK_CONTAINER (vpn_type_details));
	for (i = children; i != NULL; i = g_list_next (i)) {
		w = GTK_WIDGET (i->data);
		g_object_ref (G_OBJECT (w));
		gtk_container_remove (GTK_CONTAINER (vpn_type_details), w);
	}
	g_list_free (children);

	w = glade_xml_get_widget (xml, "vpn-druid-vpn-details-page");
	gnome_druid_set_page (druid, GNOME_DRUID_PAGE (w));

	/* show appropriate child */
	w = vpn_ui->get_widget (vpn_ui, NULL, NULL, NULL);
	if (w != NULL) {	
		GtkWidget *old_parent;
		gtk_widget_ref (w);
		old_parent = gtk_widget_get_parent (w);
		if (old_parent != NULL)
			gtk_container_remove (GTK_CONTAINER (old_parent), w);
		gtk_container_add (GTK_CONTAINER (vpn_type_details), w);
		gtk_widget_unref (w);
		gtk_widget_show_all (w);
	}

	vpn_ui->set_validity_changed_callback (vpn_ui, vpn_druid_vpn_validity_changed, NULL);

	vpn_ui->import_file (vpn_ui, name);

	gtk_widget_set_sensitive (w, TRUE);

	gtk_window_set_policy (druid_window, FALSE, FALSE, TRUE);
	gtk_widget_show_all (GTK_WIDGET (druid_window));

out:
	;
}


static void 
vpn_edit_vpn_validity_changed (NetworkManagerVpnUI *vpn_ui,
				gboolean is_valid, 
				gpointer user_data)
{
	const char *orig_conn_name;
	char *conn_name;
	GtkTreeIter iter;

	orig_conn_name = (const char *) user_data;

	/*printf ("vpn_edit_vpn_validity_changed %d!\n", is_valid);*/

	conn_name = vpn_ui->get_connection_name (vpn_ui);

	/* get list of existing connection names */
	if (gtk_tree_model_get_iter_first (GTK_TREE_MODEL (vpn_conn_list), &iter)) {
		do {
			char *name;

			gtk_tree_model_get (GTK_TREE_MODEL (vpn_conn_list),
					    &iter,
					    VPNCONN_NAME_COLUMN,
					    &name,
					    -1);

			/* Can override the original name (stored in user_data, see edit_cb()) */
			if (strcmp (name, orig_conn_name) != 0) {			
				if (strcmp (name, conn_name) == 0) {
					/*printf ("name '%s' is already in use\n", conn_name);*/
					is_valid = FALSE;
					break;
				}
			}

		} while (gtk_tree_model_iter_next (GTK_TREE_MODEL (vpn_conn_list), &iter));
	}

	g_free (conn_name);

	gtk_dialog_set_response_sensitive (edit_dialog, GTK_RESPONSE_ACCEPT, is_valid);

}

static gboolean
retrieve_data_from_selected_connection (NetworkManagerVpnUI **vpn_ui,
					GSList **conn_vpn_data,
					GSList **conn_routes,
					const char **conn_name,
					char **conn_gconf_path)
{
	gboolean result;
	const char *conn_service_name;
	GSList *conn_vpn_data_gconfvalue;
	GSList *conn_routes_gconfvalue;
	GSList *i;
	char key[PATH_MAX];
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	GConfValue *value;

	result = FALSE;

	if ((selection = gtk_tree_view_get_selection (vpn_conn_view)) == NULL)
		goto out;

	if (!gtk_tree_selection_get_selected (selection, NULL, &iter))
		goto out;

	gtk_tree_model_get (GTK_TREE_MODEL (vpn_conn_list), 
			    &iter, 
			    VPNCONN_GCONF_COLUMN, 
			    conn_gconf_path, 
			    -1);

	g_snprintf (key, sizeof (key), "%s/name", *conn_gconf_path);
	if ((value = gconf_client_get (gconf_client, key, NULL)) == NULL ||
	    (*conn_name = gconf_value_get_string (value)) == NULL)
		goto out;

	g_snprintf (key, sizeof (key), "%s/service_name", *conn_gconf_path);
	if ((value = gconf_client_get (gconf_client, key, NULL)) == NULL ||
	    (conn_service_name = gconf_value_get_string (value)) == NULL)
		goto out;

	*vpn_ui = find_vpn_ui_by_service_name (conn_service_name);
	if (*vpn_ui == NULL) {
		GtkWidget *err_dialog;

		err_dialog = gtk_message_dialog_new (NULL,
						 GTK_DIALOG_DESTROY_WITH_PARENT,
						 GTK_MESSAGE_ERROR,
						 GTK_BUTTONS_CLOSE,
						 _("Error retrieving VPN connection '%s'"),
						 *conn_name);
		gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (err_dialog),
		    _("Could not find the UI files for VPN connection type '%s'. Contact your system administrator."),
		    conn_service_name);
		gtk_dialog_run (GTK_DIALOG (err_dialog));
		gtk_widget_destroy (err_dialog);
		goto out;
	}

	g_snprintf (key, sizeof (key), "%s/vpn_data", *conn_gconf_path);
	if ((value = gconf_client_get (gconf_client, key, NULL)) == NULL ||
	    gconf_value_get_list_type (value) != GCONF_VALUE_STRING ||
	    (conn_vpn_data_gconfvalue = gconf_value_get_list (value)) == NULL)
		goto out;

	*conn_vpn_data = NULL;
	for (i = conn_vpn_data_gconfvalue; i != NULL; i = g_slist_next (i)) {
		const char *val;
		val = gconf_value_get_string ((GConfValue *) i->data);
		*conn_vpn_data = g_slist_append (*conn_vpn_data, (gpointer) val);
	}


	/* routes may be an empty list */
	g_snprintf (key, sizeof (key), "%s/routes", *conn_gconf_path);
	if ((value = gconf_client_get (gconf_client, key, NULL)) == NULL ||
	    gconf_value_get_list_type (value) != GCONF_VALUE_STRING)
		goto out;

	conn_routes_gconfvalue = gconf_value_get_list (value);
	*conn_routes = NULL;
	for (i = conn_routes_gconfvalue; i != NULL; i = g_slist_next (i)) {
		const char *val;
		val = gconf_value_get_string ((GConfValue *) i->data);
		*conn_routes = g_slist_append (*conn_routes, (gpointer) val);
	}

	result = TRUE;

out:
	return result;
}

static void
edit_cb (GtkButton *button, gpointer user_data)
{
	gint result;
	GtkWidget *vpn_edit_widget;
	NetworkManagerVpnUI *vpn_ui;
	GSList *conn_vpn_data;
	GSList *conn_routes;
	const char *conn_name;
	char key[PATH_MAX];
	char *conn_gconf_path;
	GtkTreeIter iter;

	/*printf ("edit\n");*/

	if (!retrieve_data_from_selected_connection (&vpn_ui, &conn_vpn_data, &conn_routes, &conn_name, &conn_gconf_path))
		goto out;

	vpn_edit_widget = vpn_ui->get_widget (vpn_ui, conn_vpn_data, conn_routes, conn_name);

	g_slist_free (conn_vpn_data);
	g_slist_free (conn_routes);

	vpn_ui->set_validity_changed_callback (vpn_ui, vpn_edit_vpn_validity_changed, (gpointer) conn_name);

	gtk_widget_reparent (vpn_edit_widget, GTK_WIDGET (edit_dialog->vbox));

	gtk_widget_show_all (vpn_edit_widget);
	/*gtk_widget_set_sensitive (vpn_edit_widget, TRUE);*/

	/* auto-shrink our window */
	gtk_window_set_policy (GTK_WINDOW (edit_dialog), FALSE, FALSE, TRUE);

	gtk_widget_show (GTK_WIDGET (edit_dialog));

	result = gtk_dialog_run (GTK_DIALOG (edit_dialog));

	if (result == GTK_RESPONSE_ACCEPT) {
		char *new_conn_name;
		GSList *new_conn_data;
		GSList *new_conn_routes;

		new_conn_name   = vpn_ui->get_connection_name (vpn_ui);
		new_conn_data   = vpn_ui->get_properties (vpn_ui);
		new_conn_routes = vpn_ui->get_routes (vpn_ui);

		if (strcmp (new_conn_name, conn_name) == 0) {
			/* same name, just update properties and routes */
			g_snprintf (key, sizeof (key), "%s/vpn_data", conn_gconf_path);
			gconf_client_set_list (gconf_client, key, GCONF_VALUE_STRING, new_conn_data, NULL);
			g_snprintf (key, sizeof (key), "%s/routes", conn_gconf_path);
			gconf_client_set_list (gconf_client, key, GCONF_VALUE_STRING, new_conn_routes, NULL);

			gconf_client_suggest_sync (gconf_client, NULL);
		} else {
			/* remove old entry */
			g_snprintf (key, sizeof (key), "%s/name", conn_gconf_path);
			gconf_client_unset (gconf_client, key, NULL);
			g_snprintf (key, sizeof (key), "%s/service_name", conn_gconf_path);
			gconf_client_unset (gconf_client, key, NULL);
			g_snprintf (key, sizeof (key), "%s/vpn_data", conn_gconf_path);
			gconf_client_unset (gconf_client, key, NULL);
			/* TODO: at some point remove routes and user_name */
			g_snprintf (key, sizeof (key), "%s/routes", conn_gconf_path);
			gconf_client_unset (gconf_client, key, NULL);
			g_snprintf (key, sizeof (key), "%s/user_name", conn_gconf_path);
			gconf_client_unset (gconf_client, key, NULL);
			gconf_client_unset (gconf_client, conn_gconf_path, NULL);
			gconf_client_suggest_sync (gconf_client, NULL);
			gtk_list_store_remove (vpn_conn_list, &iter);

			/* add new entry */
			add_vpn_connection (new_conn_name, vpn_ui->get_service_name (vpn_ui), 
					    new_conn_data, new_conn_routes);
		}

		if (new_conn_data != NULL) {
			g_slist_foreach (new_conn_data, (GFunc)g_free, NULL);
			g_slist_free (new_conn_data);
		}
		if (new_conn_routes != NULL) {
			g_slist_foreach (new_conn_routes, (GFunc)g_free, NULL);
			g_slist_free (new_conn_routes);
		}
	}

	gtk_widget_hide (GTK_WIDGET (vpn_edit_widget));
	gtk_widget_hide (GTK_WIDGET (edit_dialog));

out:
	;
}

static void
delete_cb (GtkButton *button, gpointer user_data)
{
	GtkTreeIter iter;
	GtkTreeSelection *selection;
	gchar *conn_gconf_path;
	gchar *conn_name;
	GtkWidget *confirm_dialog;
	int response;

	/*printf ("delete\n");*/

	if ((selection = gtk_tree_view_get_selection (vpn_conn_view)) == NULL)
		goto out;

	if (!gtk_tree_selection_get_selected (selection, NULL, &iter))
		goto out;

	gtk_tree_model_get (GTK_TREE_MODEL (vpn_conn_list), &iter, VPNCONN_NAME_COLUMN, &conn_name, -1);
	confirm_dialog = gtk_message_dialog_new (NULL,
					 GTK_DIALOG_DESTROY_WITH_PARENT,
					 GTK_MESSAGE_WARNING,
					 GTK_BUTTONS_CANCEL,
					 _("Delete VPN connection \"%s\"?"), conn_name);
	gtk_dialog_add_buttons (GTK_DIALOG (confirm_dialog), GTK_STOCK_DELETE, GTK_RESPONSE_OK, NULL);
	gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (confirm_dialog),
						  _("All information about the VPN connection \"%s\" will be lost and you may need your system administrator to provide information to create a new connection."), conn_name);
	response = gtk_dialog_run (GTK_DIALOG (confirm_dialog));
	gtk_widget_destroy (confirm_dialog);

	if (response != GTK_RESPONSE_OK)
		goto out;

	gtk_tree_model_get (GTK_TREE_MODEL (vpn_conn_list), &iter, VPNCONN_GCONF_COLUMN, &conn_gconf_path, -1);

	if (conn_gconf_path != NULL) {
		char key[PATH_MAX];
		
		g_snprintf (key, sizeof (key), "%s/name", conn_gconf_path);
		gconf_client_unset (gconf_client, key, NULL);
		g_snprintf (key, sizeof (key), "%s/service_name", conn_gconf_path);
		gconf_client_unset (gconf_client, key, NULL);
		g_snprintf (key, sizeof (key), "%s/vpn_data", conn_gconf_path);
		gconf_client_unset (gconf_client, key, NULL);
		g_snprintf (key, sizeof (key), "%s/routes", conn_gconf_path);
		gconf_client_unset (gconf_client, key, NULL);
		/* TODO: remove user_name */
		g_snprintf (key, sizeof (key), "%s/user_name", conn_gconf_path);
		gconf_client_unset (gconf_client, key, NULL);
		g_snprintf (key, sizeof (key), "%s/last_attempt_success", conn_gconf_path);
		gconf_client_unset (gconf_client, key, NULL);

		gconf_client_unset (gconf_client, conn_gconf_path, NULL);

		gconf_client_suggest_sync (gconf_client, NULL);

		if (gtk_list_store_remove (vpn_conn_list, &iter))
			gtk_tree_selection_select_iter (selection, &iter);
	}

	update_edit_del_sensitivity ();

out:
	;
}

static void
close_cb (void)
{
	gtk_widget_destroy (dialog);
	gtk_main_quit ();
}

static void
export_cb (GtkButton *button, gpointer user_data)
{
	NetworkManagerVpnUI *vpn_ui;
	GSList *conn_vpn_data;
	GSList *conn_routes;
	const char *conn_name;
	char *conn_gconf_path;

	/*printf ("edit\n");*/

	if (!retrieve_data_from_selected_connection (&vpn_ui, &conn_vpn_data, &conn_routes, &conn_name, &conn_gconf_path))
		goto out;

	vpn_ui->export (vpn_ui, conn_vpn_data, conn_routes, conn_name);

out:
	;
}

static void get_all_vpn_connections (void)
{
	GtkTreeIter iter;
	GSList *vpn_conn = NULL;

	for (vpn_conn = gconf_client_all_dirs (gconf_client, NM_GCONF_VPN_CONNECTIONS_PATH, NULL);
	     vpn_conn != NULL;
	     vpn_conn = g_slist_next (vpn_conn)) {
		char key[PATH_MAX];
		GConfValue *value;
		const char *conn_gconf_path;
		const char *conn_name;
		const char *conn_service_name;
		GSList *conn_vpn_data;
		gboolean conn_user_can_edit = TRUE;

		conn_gconf_path = (const char *) (vpn_conn->data);

		g_snprintf (key, sizeof (key), "%s/name", conn_gconf_path);
		conn_user_can_edit = gconf_client_key_is_writable (gconf_client, key, NULL);
		if ((value = gconf_client_get (gconf_client, key, NULL)) == NULL ||
		    (conn_name = gconf_value_get_string (value)) == NULL)
			goto error;

		g_snprintf (key, sizeof (key), "%s/service_name", conn_gconf_path);
		if ((value = gconf_client_get (gconf_client, key, NULL)) == NULL ||
		    (conn_service_name = gconf_value_get_string (value)) == NULL)
			goto error;

		g_snprintf (key, sizeof (key), "%s/vpn_data", conn_gconf_path);
		if ((value = gconf_client_get (gconf_client, key, NULL)) == NULL ||
		    gconf_value_get_list_type (value) != GCONF_VALUE_STRING ||
		    (conn_vpn_data = gconf_value_get_list (value)) == NULL)
			goto error;
		
		//conn_user_can_edit = (strcmp (conn_name, "RH VPN Boston") != 0);

		gtk_list_store_append (vpn_conn_list, &iter);
		gtk_list_store_set (vpn_conn_list, &iter,
				    VPNCONN_NAME_COLUMN, conn_name,
				    VPNCONN_SVC_NAME_COLUMN, conn_service_name,
				    VPNCONN_GCONF_COLUMN, conn_gconf_path,
				    VPNCONN_USER_CAN_EDIT_COLUMN, conn_user_can_edit,
				    -1);

#if 0
		printf ("conn_name = '%s'\n", conn_name);
		printf ("conn_service_name = '%s'\n", conn_service_name);
		printf ("conn_vpn_data = {");
		{
			GSList *i;
			for (i = conn_vpn_data; i != NULL; i = g_slist_next (i)) {
				printf ("'%s'", gconf_value_get_string ((GConfValue *) i->data));
				if (g_slist_next (i) != NULL)
					printf (", ");
			}
			printf ("}\n");
		}
#endif

error:
		g_free (vpn_conn->data);
	}
}

static void 
vpn_list_cursor_changed_cb (GtkTreeView *treeview,
			    gpointer user_data)
{
	/*printf ("*** vpn_list_cursor_changed_cb\n");*/

	update_edit_del_sensitivity ();
}

/* TODO: remove these once we get the GModule thing going */
//extern NetworkManagerVpnUI* vpn_ui_factory_vpnc (void);
extern NetworkManagerVpnUI* vpn_ui_factory_dummy (void);

static void
load_properties_module (GSList **vpn_types_list, const char *path)
{
	GModule *module;
	NetworkManagerVpnUI* (*nm_vpn_properties_factory) (void) = NULL;
	NetworkManagerVpnUI* impl;

	module = g_module_open (path, G_MODULE_BIND_LAZY);
	if (module == NULL) {
		g_warning ("Cannot open module '%s'", path);
		goto out;
	}

	if (!g_module_symbol (module, "nm_vpn_properties_factory", 
			      (gpointer) &nm_vpn_properties_factory)) {
		g_warning ("Cannot locate function 'nm_vpn_properties_factory' in '%s': %s", 
			   path, g_module_error ());
		g_module_close (module);
		goto out;		
	}

	impl = nm_vpn_properties_factory ();
	if (impl == NULL) {
		g_warning ("Function 'nm_vpn_properties_factory' in '%s' returned NULL", path);
		g_module_close (module);
		goto out;
	}

	*vpn_types_list = g_slist_append (*vpn_types_list, impl);

out:
	;
}

#define VPN_NAME_FILES_DIR SYSCONFDIR"/NetworkManager/VPN"

static gboolean
init_app (void)
{
	GtkWidget *w;
	gchar *glade_file;
	GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;
	GSList *i;
	GtkHBox *vpn_type_hbox1;
	GDir *dir;

	/* TODO: ensure only one copy of this program is running at any time */

	gconf_client = gconf_client_get_default ();
	gconf_client_add_dir (gconf_client, NM_GCONF_VPN_CONNECTIONS_PATH,
			      GCONF_CLIENT_PRELOAD_ONELEVEL, NULL);

	glade_file = g_strdup_printf ("%s/%s", GLADEDIR, "nm-vpn-properties.glade");
	xml = glade_xml_new (glade_file, NULL, NULL);
	g_free (glade_file);
	if (!xml) {
		GtkWidget *err_dialog;

		err_dialog = gtk_message_dialog_new (NULL,
						 GTK_DIALOG_DESTROY_WITH_PARENT,
						 GTK_MESSAGE_ERROR,
						 GTK_BUTTONS_CLOSE,
						 _("Unable to load"));
		gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (err_dialog),
		   _("Cannot find some needed resources (the glade file)!"));
		gtk_dialog_run (GTK_DIALOG (err_dialog));
		gtk_widget_destroy (err_dialog);

		return FALSE;
	}

	/* Load all VPN UI modules by inspecting .name files */
	vpn_types = NULL;
	if ((dir = g_dir_open (VPN_NAME_FILES_DIR, 0, NULL)) != NULL) {
		const char *f;

		while ((f = g_dir_read_name (dir)) != NULL) {
			char *path;
			GKeyFile *keyfile;

			if (!g_str_has_suffix (f, ".name"))
				continue;

			path = g_strdup_printf ("%s/%s", VPN_NAME_FILES_DIR, f);

			keyfile = g_key_file_new ();
			if (g_key_file_load_from_file (keyfile, path, 0, NULL)) {
				char *so_path;

				if ((so_path = g_key_file_get_string (keyfile, 
								      "GNOME", 
								      "properties", NULL)) != NULL) {
					load_properties_module (&vpn_types, so_path);
					g_free (so_path);
				}
			}
			g_key_file_free (keyfile);
			g_free (path);
		}
		g_dir_close (dir);
	}

	dialog = glade_xml_get_widget (xml, "vpn-ui-properties");

	vpn_type_details = GTK_VBOX (glade_xml_get_widget (xml, "vpn-connection-druid-details-box"));

	w = glade_xml_get_widget (xml, "add");
	gtk_signal_connect (GTK_OBJECT (w), "clicked", GTK_SIGNAL_FUNC (add_cb), NULL);
	vpn_edit = glade_xml_get_widget (xml, "edit");
	gtk_signal_connect (GTK_OBJECT (vpn_edit), "clicked", GTK_SIGNAL_FUNC (edit_cb), NULL);
	vpn_export = glade_xml_get_widget (xml, "export");
	gtk_signal_connect (GTK_OBJECT (vpn_export), "clicked", GTK_SIGNAL_FUNC (export_cb), NULL);
	vpn_delete = glade_xml_get_widget (xml, "delete");
	gtk_signal_connect (GTK_OBJECT (vpn_delete), "clicked", GTK_SIGNAL_FUNC (delete_cb), NULL);
	w = glade_xml_get_widget (xml, "close");
	gtk_signal_connect (GTK_OBJECT (w), "clicked",
			    GTK_SIGNAL_FUNC (close_cb), NULL);
	gtk_signal_connect (GTK_OBJECT (dialog), "delete_event",
			    GTK_SIGNAL_FUNC (close_cb), NULL);

	vpn_conn_view = GTK_TREE_VIEW (glade_xml_get_widget (xml, "vpnlist"));
	vpn_conn_list = gtk_list_store_new (VPNCONN_N_COLUMNS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_BOOLEAN);

	gtk_signal_connect_after (GTK_OBJECT (vpn_conn_view), "cursor-changed",
				  GTK_SIGNAL_FUNC (vpn_list_cursor_changed_cb), NULL);

	get_all_vpn_connections ();

	column = gtk_tree_view_column_new ();
	renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_column_pack_start (column, renderer, TRUE);
	gtk_tree_view_column_set_attributes (column, renderer,
					     "text", VPNCONN_NAME_COLUMN,
					     NULL);
	gtk_tree_view_append_column (vpn_conn_view, column);

	gtk_tree_view_set_model (vpn_conn_view, GTK_TREE_MODEL (vpn_conn_list));
	gtk_tree_view_expand_all (vpn_conn_view);

	gtk_widget_show_all (dialog);

	/* fill in possibly choices in the druid when adding a connection */
	vpn_type_hbox1 = GTK_HBOX (glade_xml_get_widget (xml, "vpn-create-connection-druid-hbox1"));
	vpn_type_combo_box = GTK_COMBO_BOX (gtk_combo_box_new_text ());
	for (i = vpn_types; i != NULL; i = g_slist_next (i)) {
		NetworkManagerVpnUI *vpn_ui = i->data;
		gtk_combo_box_append_text (vpn_type_combo_box, vpn_ui->get_display_name (vpn_ui));
	}
	gtk_combo_box_set_active (vpn_type_combo_box, 0);
	gtk_box_pack_end (GTK_BOX (vpn_type_hbox1), GTK_WIDGET (vpn_type_combo_box), TRUE, TRUE, 0);

	/* Druid */
	druid = GNOME_DRUID (glade_xml_get_widget (xml, "vpn-create-connection-druid"));
	gtk_signal_connect (GTK_OBJECT (druid), "cancel", GTK_SIGNAL_FUNC (vpn_druid_cancel), NULL);
	druid_confirm_page = GNOME_DRUID_PAGE_EDGE (glade_xml_get_widget (xml, "vpn-druid-vpn-confirm-page"));
	/* use connect_after, otherwise gnome_druid_set_buttons_sensitive() won't work in prepare handlers */
	w = glade_xml_get_widget (xml, "vpn-druid-vpn-type-page");
	gtk_signal_connect_after (GTK_OBJECT (w), "next", GTK_SIGNAL_FUNC (vpn_druid_vpn_type_page_next), NULL);
	w = glade_xml_get_widget (xml, "vpn-druid-vpn-details-page");
	gtk_signal_connect_after (GTK_OBJECT (w), "prepare", GTK_SIGNAL_FUNC (vpn_druid_vpn_details_page_prepare), NULL);
	gtk_signal_connect_after (GTK_OBJECT (w), "next", GTK_SIGNAL_FUNC (vpn_druid_vpn_details_page_next), NULL);
	w = glade_xml_get_widget (xml, "vpn-druid-vpn-confirm-page");
	gtk_signal_connect_after (GTK_OBJECT (w), "prepare", GTK_SIGNAL_FUNC (vpn_druid_vpn_confirm_page_prepare), NULL);
	gtk_signal_connect_after (GTK_OBJECT (w), "finish", GTK_SIGNAL_FUNC (vpn_druid_vpn_confirm_page_finish), NULL);

	druid_window = GTK_WINDOW (glade_xml_get_widget (xml, "vpn-create-connection"));

	/* make the druid window modal wrt. our main window */
	gtk_window_set_modal (druid_window, TRUE);
	gtk_window_set_transient_for (druid_window, GTK_WINDOW (dialog));

	/* Edit dialog */
	edit_dialog = GTK_DIALOG (gtk_dialog_new_with_buttons (_("Edit VPN Connection"),
							       NULL,
							       GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
							       GTK_STOCK_CANCEL,
							       GTK_RESPONSE_REJECT,
							       GTK_STOCK_APPLY,
							       GTK_RESPONSE_ACCEPT,
							       NULL));

	/* update "Edit" and "Delete" for current selection */
	update_edit_del_sensitivity ();

	return TRUE;
}

int
main (int argc, char *argv[])
{
	GOptionContext *context;
	int ret;
	gboolean bad_opts;
	gboolean do_import;
	GError *error = NULL;
	gchar *import_svc = NULL;
	gchar *import_file = NULL;
	GOptionEntry entries[] =  {
			{ "import-service", 's', 0, G_OPTION_ARG_STRING, &import_svc, "VPN Service for importing", NULL},
			{ "import-file", 'f', 0, G_OPTION_ARG_STRING, &import_file, "File to import", NULL},
			{ NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
	};

	bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	context = g_option_context_new ("- NetworkManager VPN properties");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);
	g_option_context_add_group (context, gtk_get_option_group (TRUE));
	g_option_context_parse (context, &argc, &argv, &error);

	bad_opts = FALSE;
	do_import = FALSE;
	if (import_svc != NULL) {
		if (import_file != NULL)
			do_import = TRUE;
		else
			bad_opts = TRUE;
	} else if (import_file != NULL)
			bad_opts = TRUE;

	if (bad_opts) {
		fprintf (stderr, "Have to supply both service and file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	gnome_program_init (GETTEXT_PACKAGE, VERSION, LIBGNOMEUI_MODULE, argc, argv,
			    GNOME_PARAM_NONE, GNOME_PARAM_NONE);

	glade_gnome_init ();

	if (init_app () == FALSE) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (do_import)
		import_settings (import_svc, import_file);

	gtk_main ();

	ret = EXIT_SUCCESS;

out:
	return ret;
}
