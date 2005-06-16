/***************************************************************************
 * CVSID: $Id$
 *
 * nm-vpnc.c : GNOME UI dialogs for configuring vpnc VPN connections
 *
 * Copyright (C) 2005 David Zeuthen, <davidz@redhat.com>
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

#include <glib/gi18n-lib.h>
#include <string.h>
#include <glade/glade.h>

#include <NetworkManager/nm-vpn-ui-interface.h>

typedef struct _NetworkManagerVpnUIImpl NetworkManagerVpnUIImpl;


struct _NetworkManagerVpnUIImpl {
	NetworkManagerVpnUI parent;

	NetworkManagerVpnUIDialogValidityCallback callback;
	gpointer callback_user_data;

	GladeXML *xml;

	GtkWidget *widget;

	GtkEntry *w_connection_name;
	GtkEntry *w_gateway;
	GtkEntry *w_group_name;
	GtkCheckButton *w_use_alternate_username;
	GtkEntry *w_username;
	GtkCheckButton *w_use_domain;
	GtkEntry *w_domain;
	GtkCheckButton *w_use_routes;
	GtkEntry *w_routes;
	GtkExpander *w_opt_info_expander;
	GtkButton *w_import_button;
};

static void 
vpnc_clear_widget (NetworkManagerVpnUIImpl *impl)
{
	gtk_entry_set_text (impl->w_connection_name, "");
	gtk_entry_set_text (impl->w_gateway, "");
	gtk_entry_set_text (impl->w_group_name, "");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_alternate_username), FALSE);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_routes), FALSE);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_domain), FALSE);
	gtk_entry_set_text (impl->w_username, "");
	gtk_entry_set_text (impl->w_routes, "");
	gtk_entry_set_text (impl->w_domain, "");
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_username), FALSE);
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_routes), FALSE);
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_domain), FALSE);
	gtk_expander_set_expanded (impl->w_opt_info_expander, FALSE);
}

static const char *
impl_get_display_name (NetworkManagerVpnUI *self)
{
	return _("Compatible Cisco VPN client (vpnc)");
}

static const char *
impl_get_service_name (NetworkManagerVpnUI *self)
{
	return "org.freedesktop.NetworkManager.vpnc";
}

static GtkWidget *
impl_get_widget (NetworkManagerVpnUI *self, GSList *properties, GSList *routes, const char *connection_name)
{
	GSList *i;
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
	gboolean should_expand;

	vpnc_clear_widget (impl);

	should_expand = FALSE;

	if (connection_name != NULL)
		gtk_entry_set_text (impl->w_connection_name, connection_name);

	for (i = properties; i != NULL && g_slist_next (i) != NULL; i = g_slist_next (g_slist_next (i))) {
		const char *key;
		const char *value;

		key = i->data;
		value = (g_slist_next (i))->data;

		if (strcmp (key, "IPSec gateway") == 0) {
			gtk_entry_set_text (impl->w_gateway, value);		
		} else if (strcmp (key, "IPSec ID") == 0) {
			gtk_entry_set_text (impl->w_group_name, value);
		} else if (strcmp (key, "Xauth username") == 0) {
			gtk_entry_set_text (impl->w_username, value);
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_alternate_username), TRUE);
			gtk_widget_set_sensitive (GTK_WIDGET (impl->w_username), TRUE);
			should_expand = TRUE;
		} else if (strcmp (key, "Domain") == 0) {
			gtk_entry_set_text (impl->w_domain, value);
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_domain), TRUE);
			gtk_widget_set_sensitive (GTK_WIDGET (impl->w_domain), TRUE);
			should_expand = TRUE;
		}
	}


	if (routes != NULL) {
		GString *route_str;
		char *str;

		route_str = g_string_new ("");
		for (i = routes; i != NULL; i = g_slist_next (i)) {
			const char *route;
			
			if (i != routes)
				g_string_append_c (route_str, ' ');
			
			route = (const char *) i->data;
			g_string_append (route_str, route);
		}

		str = g_string_free (route_str, FALSE);
		gtk_entry_set_text (impl->w_routes, str);
		g_free (str);
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_routes), TRUE);
		gtk_widget_set_sensitive (GTK_WIDGET (impl->w_routes), TRUE);

		should_expand = TRUE;
	}

	gtk_expander_set_expanded (impl->w_opt_info_expander, should_expand);

	gtk_container_resize_children (GTK_CONTAINER (impl->widget));

	return impl->widget;
}

static GSList *
impl_get_properties (NetworkManagerVpnUI *self)
{
	GSList *data;
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
	const char *connectionname;
	const char *gateway;
	const char *groupname;
	const char *secret;
	gboolean use_alternate_username;
	const char *username;
	gboolean use_domain;
	const char *domain;

	connectionname         = gtk_entry_get_text (impl->w_connection_name);
	gateway                = gtk_entry_get_text (impl->w_gateway);
	groupname              = gtk_entry_get_text (impl->w_group_name);
	use_alternate_username = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_alternate_username));
	username               = gtk_entry_get_text (impl->w_username);
	use_domain             = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_domain));
	domain                 = gtk_entry_get_text (impl->w_domain);

	data = NULL;
	data = g_slist_append (data, g_strdup ("IPSec gateway"));
	data = g_slist_append (data, g_strdup (gateway));
	data = g_slist_append (data, g_strdup ("IPSec ID"));
	data = g_slist_append (data, g_strdup (groupname));
	if (use_alternate_username) {
		data = g_slist_append (data, g_strdup ("Xauth username"));
		data = g_slist_append (data, g_strdup (username));
	}
	if (use_domain) {
		data = g_slist_append (data, g_strdup ("Domain"));
		data = g_slist_append (data, g_strdup (domain));
	}

	return data;
}

static GSList *
get_routes (NetworkManagerVpnUIImpl *impl)
{
	GSList *routes;
	const char *routes_entry;
	gboolean use_routes;
	char **substrs;
	unsigned int i;

	routes = NULL;

	routes_entry = gtk_entry_get_text (impl->w_routes);
	use_routes = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_routes));

	if (!use_routes)
		goto out;

	substrs = g_strsplit (routes_entry, " ", 0);
	for (i = 0; substrs[i] != NULL; i++) {
		char *route;

		route = substrs[i];
		if (strlen (route) > 0)
			routes = g_slist_append (routes, g_strdup (route));
	}

	g_strfreev (substrs);

out:
	return routes;
}

static GSList *
impl_get_routes (NetworkManagerVpnUI *self)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;

	return get_routes (impl);
}


static char *
impl_get_connection_name (NetworkManagerVpnUI *self)
{
	const char *name;
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;

	name = gtk_entry_get_text (impl->w_connection_name);
	if (name != NULL)
		return g_strdup (name);
	else
		return NULL;
}

static gboolean
impl_is_valid (NetworkManagerVpnUI *self)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
	gboolean is_valid;
	const char *connectionname;
	const char *gateway;
	const char *groupname;
	gboolean use_alternate_username;
	const char *username;
	gboolean use_routes;
	const char *routes_entry;
	gboolean use_domain;
	const char *domain_entry;

	is_valid = FALSE;

	connectionname         = gtk_entry_get_text (impl->w_connection_name);
	gateway                = gtk_entry_get_text (impl->w_gateway);
	groupname              = gtk_entry_get_text (impl->w_group_name);
	use_alternate_username = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_alternate_username));
	username               = gtk_entry_get_text (impl->w_username);
	use_routes             = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_routes));
	routes_entry           = gtk_entry_get_text (impl->w_routes);
	use_domain             = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_domain));
	domain_entry           = gtk_entry_get_text (impl->w_domain);

	/* initial sanity checking */
	if (strlen (connectionname) > 0 &&
	    strlen (gateway) > 0 &&
	    strlen (groupname) > 0 &&
	    ((!use_alternate_username) || (use_alternate_username && strlen (username) > 0)) &&
	    ((!use_routes) || (use_routes && strlen (routes_entry) > 0)) &&
	    ((!use_domain) || (use_domain && strlen (domain_entry) > 0)))
		is_valid = TRUE;

	/* validate gateway: can be a hostname or an IP; do not allow spaces or tabs */
	if (is_valid &&
	    (strstr (gateway, " ") != NULL ||
	     strstr (gateway, "\t") != NULL)) {
		is_valid = FALSE;
	}

	/* validate groupname; can be anything */

	/* validate user; can be anything */

	/* validate routes: each entry must be of the form 'a.b.c.d/mask' */
	if (is_valid) {
		GSList *i;
		GSList *routes;

		routes = get_routes (impl);

		//if (routes != NULL)
		//	printf ("routes:\n");

		for (i = routes; i != NULL; i = g_slist_next (i)) {
			int d1, d2, d3, d4, mask;

			const char *route = (const char *) i->data;
			//printf ("route = '%s'\n", route);

			if (sscanf (route, "%d.%d.%d.%d/%d", &d1, &d2, &d3, &d4, &mask) != 5) {
				is_valid = FALSE;
				break;
			}

			/* TODO: this can be improved a bit */
			if (d1 < 0 || d1 > 255 ||
			    d2 < 0 || d2 > 255 ||
			    d3 < 0 || d3 > 255 ||
			    d4 < 0 || d4 > 255 ||
			    mask < 0 || mask > 32) {
				is_valid = FALSE;
				break;
			}

		}
		//if (routes != NULL)
		//	printf ("\n");

		if (routes != NULL) {
			g_slist_foreach (routes, (GFunc)g_free, NULL);
			g_slist_free (routes);
		}
	}

	return is_valid;
}


static void 
use_alternate_username_toggled (GtkToggleButton *togglebutton, gpointer user_data)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;

	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_username), 
				  gtk_toggle_button_get_active (togglebutton));

	if (impl->callback != NULL) {
		gboolean is_valid;

		is_valid = impl_is_valid (&(impl->parent));
		impl->callback (&(impl->parent), is_valid, impl->callback_user_data);
	}
}

static void 
use_routes_toggled (GtkToggleButton *togglebutton, gpointer user_data)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;

	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_routes), 
				  gtk_toggle_button_get_active (togglebutton));

	if (impl->callback != NULL) {
		gboolean is_valid;

		is_valid = impl_is_valid (&(impl->parent));
		impl->callback (&(impl->parent), is_valid, impl->callback_user_data);
	}
}

static void 
use_domain_toggled (GtkToggleButton *togglebutton, gpointer user_data)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;

	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_domain), 
				  gtk_toggle_button_get_active (togglebutton));

	if (impl->callback != NULL) {
		gboolean is_valid;

		is_valid = impl_is_valid (&(impl->parent));
		impl->callback (&(impl->parent), is_valid, impl->callback_user_data);
	}
}

static void 
editable_changed (GtkEditable *editable, gpointer user_data)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;

	if (impl->callback != NULL) {
		gboolean is_valid;

		is_valid = impl_is_valid (&(impl->parent));
		impl->callback (&(impl->parent), is_valid, impl->callback_user_data);
	}
}


static void 
impl_set_validity_changed_callback (NetworkManagerVpnUI *self, 
				    NetworkManagerVpnUIDialogValidityCallback callback,
				    gpointer user_data)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;

	impl->callback = callback;
	impl->callback_user_data = user_data;
}

static const char *
impl_get_confirmation_details (NetworkManagerVpnUI *self)
{
	static char buf[512];
	static char buf2[128];
	static char buf3[128];
	static char buf4[128];
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
	const char *connectionname;
	const char *gateway;
	const char *groupname;
	gboolean use_alternate_username;
	const char *username;
	gboolean use_routes;
	const char *routes;
	gboolean use_domain;
	const char *domain;

	connectionname         = gtk_entry_get_text (impl->w_connection_name);
	gateway                = gtk_entry_get_text (impl->w_gateway);
	groupname              = gtk_entry_get_text (impl->w_group_name);
	use_alternate_username = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_alternate_username));
	username               = gtk_entry_get_text (impl->w_username);
	use_routes             = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_routes));
	routes                 = gtk_entry_get_text (impl->w_routes);
	use_domain             = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_domain));
	domain                 = gtk_entry_get_text (impl->w_domain);

	g_snprintf (buf2, sizeof (buf2), _("\tUsername:  %s\n"), username);
	g_snprintf (buf3, sizeof (buf2), _("\tRoutes:  %s\n"), routes);
	g_snprintf (buf4, sizeof (buf4), _("\tDomain:  %s\n"), domain);

	g_snprintf (buf, sizeof (buf), 
		    _("The following vpnc VPN connection will be created:\n"
		      "\n"
		      "\tName:  %s\n"
		      "\n"
		      "\tGateway:  %s\n"
		      "\tGroup Name:  %s\n"
		      "%s"
		      "%s"
		      "%s"
		      "\n"
		      "The connection details can be changed using the \"Edit\" button.\n"),
		    connectionname,
		    gateway,
		    groupname,
		    use_alternate_username ? buf2 : "",
		    use_domain ? buf4 : "",
		    use_routes ? buf3 : "");

	return buf;
}

static void
import_button_clicked (GtkButton *button, gpointer user_data)
{
	GtkWidget *dialog;
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;

	dialog = gtk_file_chooser_dialog_new (_("Select file to import"),
					      NULL,
					      GTK_FILE_CHOOSER_ACTION_OPEN,
					      GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					      GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
					      NULL);

	if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT)
	{
		char *filename;
		
		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
		//printf ("User selected '%s'\n", filename);
		g_free (filename);
	}
	
	gtk_widget_destroy (dialog);
      
}

static NetworkManagerVpnUI* 
impl_get_object (void)
{
	char *glade_file;
	NetworkManagerVpnUIImpl *impl;

	impl = g_new0 (NetworkManagerVpnUIImpl, 1);

	glade_file = g_strdup_printf ("%s/%s", GLADEDIR, "nm-vpnc-dialog.glade");
	//glade_file = g_strdup ("nm-vpnc-dialog.glade");
	impl->xml = glade_xml_new (glade_file, NULL, GETTEXT_PACKAGE);
	g_free (glade_file);
	if (impl->xml == NULL)
		goto error;

	impl->widget = glade_xml_get_widget (impl->xml, "nm-vpnc-widget");

	impl->w_connection_name        = GTK_ENTRY (glade_xml_get_widget (impl->xml, "vpnc-connection-name"));
	impl->w_gateway                = GTK_ENTRY (glade_xml_get_widget (impl->xml, "vpnc-gateway"));
	impl->w_group_name             = GTK_ENTRY (glade_xml_get_widget (impl->xml, "vpnc-group-name"));
	impl->w_use_alternate_username = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "vpnc-use-alternate-username"));
	impl->w_username               = GTK_ENTRY (glade_xml_get_widget (impl->xml, "vpnc-username"));
	impl->w_use_routes             = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "vpnc-use-routes"));
	impl->w_routes                 = GTK_ENTRY (glade_xml_get_widget (impl->xml, "vpnc-routes"));
	impl->w_use_domain             = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "vpnc-use-domain"));
	impl->w_domain                 = GTK_ENTRY (glade_xml_get_widget (impl->xml, "vpnc-domain"));
	impl->w_opt_info_expander      = GTK_EXPANDER (glade_xml_get_widget (impl->xml, 
									     "vpnc-optional-information-expander"));
	impl->w_import_button          = GTK_BUTTON (glade_xml_get_widget (impl->xml, 
									   "vpnc-import-button"));
	impl->callback                 = NULL;

	gtk_signal_connect (GTK_OBJECT (impl->w_use_alternate_username), 
			    "toggled", GTK_SIGNAL_FUNC (use_alternate_username_toggled), impl);

	gtk_signal_connect (GTK_OBJECT (impl->w_use_routes), 
			    "toggled", GTK_SIGNAL_FUNC (use_routes_toggled), impl);

	gtk_signal_connect (GTK_OBJECT (impl->w_use_domain), 
			    "toggled", GTK_SIGNAL_FUNC (use_domain_toggled), impl);

	gtk_signal_connect (GTK_OBJECT (impl->w_connection_name), 
			    "changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_gateway), 
			    "changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_group_name), 
			    "changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_username), 
			    "changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_routes), 
			    "changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_domain), 
			    "changed", GTK_SIGNAL_FUNC (editable_changed), impl);

	gtk_signal_connect (GTK_OBJECT (impl->w_import_button), 
			    "clicked", GTK_SIGNAL_FUNC (import_button_clicked), impl);

	/* make the widget reusable */
	gtk_signal_connect (GTK_OBJECT (impl->widget), "delete-event", 
			    GTK_SIGNAL_FUNC (gtk_widget_hide_on_delete), NULL);

	vpnc_clear_widget (impl);

	impl->parent.get_display_name              = impl_get_display_name;
	impl->parent.get_service_name              = impl_get_service_name;
	impl->parent.get_widget                    = impl_get_widget;
	impl->parent.get_connection_name           = impl_get_connection_name;
	impl->parent.get_properties                = impl_get_properties;
	impl->parent.get_routes                    = impl_get_routes;
	impl->parent.set_validity_changed_callback = impl_set_validity_changed_callback;
	impl->parent.is_valid                      = impl_is_valid;
	impl->parent.get_confirmation_details      = impl_get_confirmation_details;
	impl->parent.data = impl;
	
	return &(impl->parent);

error:
	g_free (impl);

	return NULL;
}

NetworkManagerVpnUI* 
nm_vpn_properties_factory (void)
{
	return impl_get_object ();
}
