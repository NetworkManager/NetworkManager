/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
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

#include <stdlib.h>
#include <glib/gi18n-lib.h>
#include <string.h>
#include <glade/glade.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-vpn-properties.h>
#include <nm-setting-connection.h>

#include "../src/nm-vpnc-service.h"
#include "pcf-file.h"

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
	GtkCheckButton *w_use_keepalive;
	GtkEntry *w_keepalive;
	GtkCheckButton *w_disable_natt;
	GtkCheckButton *w_enable_singledes;
	GtkEntry *w_routes;
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
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_disable_natt), FALSE);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_enable_singledes), FALSE);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_domain), FALSE);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_keepalive), FALSE);
	gtk_entry_set_text (impl->w_username, "");
	gtk_entry_set_text (impl->w_routes, "");
	gtk_entry_set_text (impl->w_domain, "");
	gtk_entry_set_text (impl->w_keepalive, "");
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_username), FALSE);
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_routes), FALSE);
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_domain), FALSE);
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_keepalive), FALSE);
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

static GValue *
str_to_gvalue (const char *str)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_STRING);
	g_value_set_string (value, str);

	return value;
}

static GValue *
bool_to_gvalue (gboolean b)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_BOOLEAN);
	g_value_set_boolean (value, b);

	return value;
}

static void
impl_fill_connection (NetworkManagerVpnUI *self, NMConnection *connection)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	NMSettingVPNProperties *s_vpn_props;
	const char *id;
	const char *gateway;
	const char *groupname;
	gboolean use_alternate_username;
	const char *username;
	gboolean use_keepalive;
	const char *keepalive;
	gboolean use_domain;
	gboolean disable_natt;
	gboolean enable_singledes;
	const char *domain;

	g_return_if_fail (NM_IS_CONNECTION (connection));

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_return_if_fail (s_con != NULL);

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	g_return_if_fail (s_vpn != NULL);

	s_vpn_props = NM_SETTING_VPN_PROPERTIES (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN_PROPERTIES));
	g_return_if_fail (s_vpn_props != NULL);

	/* Connection name */
	id = gtk_entry_get_text (impl->w_connection_name);
	g_assert (id);
	s_con->id = g_strdup (id);

	/* Populate routes */
	if (s_vpn->routes) {
		g_slist_foreach (s_vpn->routes, (GFunc) g_free, NULL);
		g_slist_free (s_vpn->routes);
	}
	s_vpn->routes = get_routes (impl);

	/* vpnc specific properties */
	gateway                = gtk_entry_get_text (impl->w_gateway);
	groupname              = gtk_entry_get_text (impl->w_group_name);
	use_alternate_username = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_alternate_username));
	username               = gtk_entry_get_text (impl->w_username);
	use_domain             = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_domain));
	keepalive              = gtk_entry_get_text (impl->w_keepalive);
	use_keepalive          = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_keepalive));
	disable_natt           = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_disable_natt));
	enable_singledes       = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_enable_singledes));
	domain                 = gtk_entry_get_text (impl->w_domain);

	if (s_vpn_props->data)
		g_hash_table_remove_all (s_vpn_props->data);

	g_hash_table_insert (s_vpn_props->data, NM_VPNC_KEY_GATEWAY, str_to_gvalue (gateway));
	g_hash_table_insert (s_vpn_props->data, NM_VPNC_KEY_ID, str_to_gvalue (groupname));

	if (use_alternate_username)
		g_hash_table_insert (s_vpn_props->data, NM_VPNC_KEY_XAUTH_USER, str_to_gvalue (username));
	if (use_domain)
		g_hash_table_insert (s_vpn_props->data, NM_VPNC_KEY_DOMAIN, str_to_gvalue (domain));
	if (use_keepalive)
		g_hash_table_insert (s_vpn_props->data, NM_VPNC_KEY_NAT_KEEPALIVE, str_to_gvalue (keepalive));
	if (enable_singledes)
		g_hash_table_insert (s_vpn_props->data, NM_VPNC_KEY_SINGLE_DES, bool_to_gvalue (TRUE));
	if (disable_natt)
		g_hash_table_insert (s_vpn_props->data, NM_VPNC_KEY_DISABLE_NAT, bool_to_gvalue (TRUE));
}

static void
set_property (gpointer key, gpointer val, gpointer user_data)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;
	const char *name = (const char *) key;
	GValue *value = (GValue *) val;

	if (!strcmp (name, NM_VPNC_KEY_GATEWAY)) {
		gtk_entry_set_text (impl->w_gateway, g_value_get_string (value));		
	} else if (!strcmp (name, NM_VPNC_KEY_ID)) {
		gtk_entry_set_text (impl->w_group_name, g_value_get_string (value));
	} else if (!strcmp (name, NM_VPNC_KEY_XAUTH_USER)) {
		gtk_entry_set_text (impl->w_username, g_value_get_string (value));
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_alternate_username), TRUE);
		gtk_widget_set_sensitive (GTK_WIDGET (impl->w_username), TRUE);
	} else if (!strcmp (name, NM_VPNC_KEY_DOMAIN)) {
		gtk_entry_set_text (impl->w_domain, g_value_get_string (value));
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_domain), TRUE);
		gtk_widget_set_sensitive (GTK_WIDGET (impl->w_domain), TRUE);
	} else if (!strcmp (name, NM_VPNC_KEY_NAT_KEEPALIVE)) {
		gtk_entry_set_text (impl->w_keepalive, g_value_get_string (value));
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_keepalive), TRUE);
		gtk_widget_set_sensitive (GTK_WIDGET (impl->w_keepalive), TRUE);
	} else if (!strcmp (name, NM_VPNC_KEY_DISABLE_NAT)) {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_disable_natt), g_value_get_boolean (value));
	} else if (!strcmp (name, NM_VPNC_KEY_SINGLE_DES)) {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_enable_singledes), g_value_get_boolean (value));
	}
}

static GtkWidget *
impl_get_widget (NetworkManagerVpnUI *self, NMConnection *connection)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	NMSettingVPNProperties *s_vpn_props;

	vpnc_clear_widget (impl);

	if (!connection)
		goto out;

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	g_return_val_if_fail (s_vpn != NULL, NULL);

	s_vpn_props = NM_SETTING_VPN_PROPERTIES (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN_PROPERTIES));
	g_return_val_if_fail (s_vpn_props != NULL, NULL);

	/* Populate UI bits from the NMConnection */
	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_return_val_if_fail (s_con != NULL, NULL);
	g_assert (s_con->id);
	gtk_entry_set_text (impl->w_connection_name, s_con->id);

	if (s_vpn_props->data)
		g_hash_table_foreach (s_vpn_props->data, set_property, self);

	if (s_vpn->routes != NULL) {
		GSList *i;
		GString *route_str;
		char *str;

		route_str = g_string_new ("");
		for (i = s_vpn->routes; i != NULL; i = g_slist_next (i)) {
			const char *route;
			
			if (i != s_vpn->routes)
				g_string_append_c (route_str, ' ');
			
			route = (const char *) i->data;
			g_string_append (route_str, route);
		}

		str = g_string_free (route_str, FALSE);
		gtk_entry_set_text (impl->w_routes, str);
		g_free (str);
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_routes), TRUE);
		gtk_widget_set_sensitive (GTK_WIDGET (impl->w_routes), TRUE);
	}

out:
	return impl->widget;
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
	gboolean use_keepalive;
	const char* keepalive;
	gboolean disable_natt;
	gboolean enable_singledes;
	const char *domain_entry;

	is_valid = FALSE;

	connectionname         = gtk_entry_get_text (impl->w_connection_name);
	gateway                = gtk_entry_get_text (impl->w_gateway);
	groupname              = gtk_entry_get_text (impl->w_group_name);
	use_alternate_username = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_alternate_username));
	username               = gtk_entry_get_text (impl->w_username);
	use_routes             = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_routes));
	disable_natt           = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_disable_natt));
	enable_singledes       = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_enable_singledes));
	routes_entry           = gtk_entry_get_text (impl->w_routes);
	use_domain             = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_domain));
	domain_entry           = gtk_entry_get_text (impl->w_domain);
	use_keepalive          = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_keepalive));
	keepalive              = gtk_entry_get_text (impl->w_keepalive);

	/* initial sanity checking */
	if (strlen (connectionname) > 0 &&
	    strlen (gateway) > 0 &&
	    strlen (groupname) > 0 &&
	    ((!use_alternate_username) || (use_alternate_username && strlen (username) > 0)) &&
	    ((!use_routes) || (use_routes && strlen (routes_entry) > 0)) &&
	    ((!use_keepalive) || (use_keepalive && strlen (keepalive) > 0)) &&
	    ((!use_domain) || (use_domain && strlen (domain_entry) > 0)))
		is_valid = TRUE;

	/* validate gateway: can be a hostname or an IP; do not allow spaces or tabs */
	if (is_valid &&
	    (strstr (gateway, " ") != NULL ||
	     strstr (gateway, "\t") != NULL)) {
		is_valid = FALSE;
	}

	/* validate keepalive: must be non-zero */
	if (use_keepalive && atoi(keepalive) == 0) {
		is_valid = FALSE;
	}

	/* validate groupname; can be anything */

	/* validate user; can be anything */

	/* validate routes: each entry must be of the form 'a.b.c.d/mask' */
	if (is_valid) {
		GSList *i;
		GSList *routes;

		routes = get_routes (impl);

		for (i = routes; i != NULL; i = g_slist_next (i)) {
			int d1, d2, d3, d4, mask;
			const char *route = (const char *) i->data;

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
use_keepalive_toggled (GtkToggleButton *togglebutton, gpointer user_data)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;

	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_keepalive), 
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

static void
impl_get_confirmation_details (NetworkManagerVpnUI *self, gchar **retval)
{
	GString *buf;
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
	const char *connectionname;
	const char *gateway;
	const char *groupname;
	gboolean use_alternate_username;
	const char *username;
	gboolean use_routes;
	gboolean disable_natt;
	gboolean enable_singledes;
	const char *routes;
	gboolean use_domain;
	const char *domain;
	gboolean use_keepalive;
	const char *keepalive;

	connectionname         = gtk_entry_get_text (impl->w_connection_name);
	gateway                = gtk_entry_get_text (impl->w_gateway);
	groupname              = gtk_entry_get_text (impl->w_group_name);
	use_alternate_username = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_alternate_username));
	username               = gtk_entry_get_text (impl->w_username);
	use_routes             = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_routes));
	disable_natt           = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_disable_natt));
	enable_singledes       = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_enable_singledes));
	routes                 = gtk_entry_get_text (impl->w_routes);
	use_domain             = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_domain));
	domain                 = gtk_entry_get_text (impl->w_domain);
	use_keepalive          = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_keepalive));
	keepalive              = gtk_entry_get_text (impl->w_keepalive);

	buf = g_string_sized_new (1024);

	g_string_append (buf, _("The following vpnc VPN connection will be created:"));
	g_string_append (buf, "\n\n\t");
	g_string_append_printf (buf, _("Name:  %s"), connectionname);
	g_string_append (buf, "\n\n\t");

	g_string_append_printf (buf, _("Gateway:  %s"), gateway);
	g_string_append (buf, "\n\t");
	g_string_append_printf (buf, _("Group Name:  %s"), groupname);

	if (use_alternate_username) {
		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("Username:  %s"), username);
	}

	if (use_domain) {
		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("Domain:  %s"), domain);
	}

	if (use_routes) {
		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("Routes:  %s"), routes);
	}
	if (use_keepalive) {
		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("NAT-Keepalive packet interval:  %s"), keepalive);
	}
	if (enable_singledes) {
		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("Enable Single DES"));
	}
	if (disable_natt) {
		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("Disable NAT Traversal"));
	}

	g_string_append (buf, "\n\n");
	g_string_append (buf, _("The connection details can be changed using the \"Edit\" button."));
	g_string_append (buf, "\n");

	*retval = g_string_free (buf, FALSE);
}

static gboolean
import_from_file (NetworkManagerVpnUI *self,
                  const char *path,
                  NMConnection *connection)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
	GHashTable *pcf;
	const char *buf;
	gboolean have_value;
	char *basename = NULL;
	gboolean success = FALSE;

	pcf = pcf_file_load (path);
	if (pcf == NULL)
		return FALSE;

	/* Connection name */
	if ((buf = pcf_file_lookup_value (pcf, "main", "Description")) == NULL || strlen (buf) < 1)
		goto error;
	gtk_entry_set_text (impl->w_connection_name, buf);

	/* Gateway */
	if ((buf = pcf_file_lookup_value (pcf, "main", "Host")) == NULL || strlen (buf) < 1)
		goto error;
	gtk_entry_set_text (impl->w_gateway, buf);

	/* Group name */
	if ((buf = pcf_file_lookup_value (pcf, "main", "GroupName")) == NULL || strlen (buf) < 1)
		goto error;
	gtk_entry_set_text (impl->w_group_name, buf);

	/* Optional settings */

	if ((buf = pcf_file_lookup_value (pcf, "main", "UserName")))
		gtk_entry_set_text (impl->w_username, buf);
	have_value = buf == NULL ? FALSE : strlen (buf) > 0;
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_alternate_username), have_value);
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_username), have_value);

	if ((buf = pcf_file_lookup_value (pcf, "main", "NTDomain")))
		gtk_entry_set_text (impl->w_domain, buf);
	have_value = buf == NULL ? FALSE : strlen (buf) > 0;
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_domain), have_value);
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_domain), have_value);

	buf = pcf_file_lookup_value (pcf, "main", "ForceKeepAlives");
	have_value = (buf == NULL ? FALSE : strcmp (buf, "0") != 0);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_keepalive), have_value);
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_keepalive), have_value);
	gtk_entry_set_text (impl->w_keepalive, have_value ? buf : "");

	buf = pcf_file_lookup_value (pcf, "main", "SingleDES");
	have_value = (buf ? strncmp (buf, "1", 1) == 0 : FALSE);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_enable_singledes), have_value);

	/* Default is enabled, only disabled if explicit EnableNat=0 exists */
	buf = pcf_file_lookup_value (pcf, "main", "EnableNat");
	have_value = (buf ? strncmp (buf, "0", 1) == 0 : FALSE);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_disable_natt), have_value);

	if ((buf = pcf_file_lookup_value (pcf, "main", "X-NM-Routes")))
		gtk_entry_set_text (impl->w_routes, buf);
	have_value = buf == NULL ? FALSE : strlen (buf) > 0;
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_routes), have_value);
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_routes), have_value);

	if ((buf = pcf_file_lookup_value (pcf, "main", "TunnelingMode"))) {
		/* If applicable, put up warning that TCP tunneling will be disabled */

		if (strncmp (buf, "1", 1) == 0) {
			GtkWidget *dialog;

			basename = g_path_get_basename (path);
			dialog = gtk_message_dialog_new (NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
											 GTK_MESSAGE_WARNING, GTK_BUTTONS_CLOSE,
											 _("TCP tunneling not supported"));
			gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog),
													  _("The VPN settings file '%s' specifies that VPN traffic should be tunneled through TCP which is currently not supported in the vpnc software.\n\nThe connection can still be created, with TCP tunneling disabled, however it may not work as expected."), basename);
			gtk_dialog_run (GTK_DIALOG (dialog));
			gtk_widget_destroy (dialog);
		}
	}

	if (connection)
		impl_fill_connection (self, connection);

	success = TRUE;

 error:	
	g_hash_table_destroy (pcf);

	if (!success) {
		GtkWidget *dialog;

		if (!basename)
			basename = g_path_get_basename (path);

		dialog = gtk_message_dialog_new (NULL,
						 GTK_DIALOG_DESTROY_WITH_PARENT,
						 GTK_MESSAGE_WARNING,
						 GTK_BUTTONS_CLOSE,
						 _("Cannot import settings"));
		gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog),
							  _("The VPN settings file '%s' does not contain valid data."), basename);
		gtk_dialog_run (GTK_DIALOG (dialog));
		gtk_widget_destroy (dialog);
	}

	g_free (basename);

	return success;
}

static void
import_button_clicked (GtkButton *button, gpointer user_data)
{
	char *filename = NULL;
	GtkWidget *dialog;
	NetworkManagerVpnUI *self = (NetworkManagerVpnUI *) user_data;

	dialog = gtk_file_chooser_dialog_new (_("Select file to import"),
					      NULL,
					      GTK_FILE_CHOOSER_ACTION_OPEN,
					      GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					      GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
					      NULL);

	if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT)
		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
	
	gtk_widget_destroy (dialog);

	if (filename != NULL) {
		import_from_file (self, filename, NULL);
		g_free (filename);
	}      
}

static gboolean 
impl_can_export (NetworkManagerVpnUI *self)
{
	return TRUE;
}

static gboolean 
impl_import_file (NetworkManagerVpnUI *self,
                  const char *path,
                  NMConnection *connection)
{
	return import_from_file (self, path, connection);
}

static gboolean
export_to_file (NetworkManagerVpnUIImpl *impl,
                const char *path,
                NMConnection *connection)
{
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	NMSettingVPNProperties *s_vpn_props;
	FILE *f;
	GValue *val;
	const char *gateway = NULL;
	const char *keepalive = "0";
	const char *enablenat = "1";
	const char *singledes = "0";
	const char *groupname = NULL;
	const char *username = NULL;
	const char *domain = NULL;
	char *routes_str = NULL;
	gboolean ret = TRUE;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	g_assert (s_vpn);

	s_vpn_props = NM_SETTING_VPN_PROPERTIES (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN_PROPERTIES));
	g_assert (s_vpn_props);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_GATEWAY);
	if (val)
		gateway = g_value_get_string (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_ID);
	if (val)
		groupname = g_value_get_string (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_XAUTH_USER);
	if (val)
		username = g_value_get_string (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_DOMAIN);
	if (val)
		domain = g_value_get_string (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_DISABLE_NAT);
	if (val)
		enablenat = g_value_get_boolean (val) ? "0" : "1";

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_SINGLE_DES);
	if (val)
		singledes = g_value_get_boolean (val) ? "1" : "0";

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_NAT_KEEPALIVE);
	if (val)
		keepalive = g_value_get_string (val);

	if (s_vpn->routes != NULL) {
		GSList *i;
		GString *str;

		str = g_string_new ("X-NM-Routes=");
		for (i = s_vpn->routes; i != NULL; i = g_slist_next (i)) {
			const char *route;
			
			if (i != s_vpn->routes)
				g_string_append_c (str, ' ');
			
			route = (const char *) i->data;
			g_string_append (str, route);
		}

		g_string_append_c (str, '\n');

		routes_str = g_string_free (str, FALSE);
	}

	f = fopen (path, "w");
	if (f == NULL)
	{
		ret = FALSE;
		goto out;
	}

	fprintf (f, 
		 "[main]\n"
		 "Description=%s\n"
		 "Host=%s\n"
		 "AuthType=1\n"
		 "GroupName=%s\n"
		 "GroupPwd=\n"
		 "EnableISPConnect=0\n"
		 "ISPConnectType=0\n"
		 "ISPConnect=\n"
		 "ISPCommand=\n"
		 "Username=%s\n"
		 "SaveUserPassword=0\n"
		 "EnableBackup=0\n"
		 "BackupServer=\n"
		 "EnableNat=%s\n"
		 "CertStore=0\n"
		 "CertName=\n"
		 "CertPath=\n"
		 "CertSubjectName=\n"
		 "CertSerialHash=\n"
		 "DHGroup=2\n"
		 "ForceKeepAlives=%s\n"
		 "enc_GroupPwd=\n"
		 "UserPassword=\n"
		 "enc_UserPassword=\n"
		 "NTDomain=%s\n"
		 "EnableMSLogon=0\n"
		 "MSLogonType=0\n"
		 "TunnelingMode=0\n"
		 "TcpTunnelingPort=10000\n"
		 "PeerTimeout=90\n"
		 "EnableLocalLAN=1\n"
		 "SendCertChain=0\n"
		 "VerifyCertDN=\n"
		 "EnableSplitDNS=1\n"
		 "SingleDES=%s\n"
		 "SPPhonebook=\n"
		 "%s",
		 /* Description */ s_con->id,
		 /* Host */        gateway,
		 /* GroupName */   groupname,
		 /* Username */    username != NULL ? username : "",
		 /* EnableNat */   enablenat,
		 /* KeepAlive */   keepalive != NULL ? keepalive : "",
		 /* NTDomain */    domain != NULL ? domain : "",
		 /* SingleDES */   singledes,
		 /* X-NM-Routes */ routes_str != NULL ? routes_str : "");

	fclose (f);
out:
	g_free (routes_str);

	return ret;
}


static gboolean 
impl_export (NetworkManagerVpnUI *self, NMConnection *connection)
{
	NMSettingConnection *s_con;
	char *suggested_name;
	char *path = NULL;
	GtkWidget *dialog;
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;

	dialog = gtk_file_chooser_dialog_new (_("Save as..."),
					      NULL,
					      GTK_FILE_CHOOSER_ACTION_SAVE,
					      GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					      GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT,
					      NULL);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);
	g_assert (s_con->id);

	suggested_name = g_strdup_printf ("%s.pcf", s_con->id);
	gtk_file_chooser_set_current_name (GTK_FILE_CHOOSER (dialog), suggested_name);
	g_free (suggested_name);

	if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT)
		path = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));

	gtk_widget_destroy (dialog);

	if (path != NULL) {
		if (g_file_test (path, G_FILE_TEST_EXISTS)) {
			int response;
			GtkWidget *dialog;

			dialog = gtk_message_dialog_new (NULL,
							 GTK_DIALOG_DESTROY_WITH_PARENT,
							 GTK_MESSAGE_QUESTION,
							 GTK_BUTTONS_CANCEL,
							 _("A file named \"%s\" already exists."), path);
			gtk_dialog_add_buttons (GTK_DIALOG (dialog), "_Replace", GTK_RESPONSE_OK, NULL);
			gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog),
								  _("Do you want to replace it with the one you are saving?"));
			response = gtk_dialog_run (GTK_DIALOG (dialog));
			gtk_widget_destroy (dialog);
			if (response != GTK_RESPONSE_OK)
				goto out;
		}

		if (!export_to_file (impl, path, connection)) {
			GtkWidget *dialog;

			dialog = gtk_message_dialog_new (NULL,
									   GTK_DIALOG_DESTROY_WITH_PARENT,
									   GTK_MESSAGE_WARNING,
									   GTK_BUTTONS_CLOSE,
									   _("Failed to export configuration"));
			gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog),
											  _("Failed to save file %s"), path);
			gtk_dialog_run (GTK_DIALOG (dialog));
			gtk_widget_destroy (dialog);
		}
	}

out:
	g_free (path);

	return TRUE;
}

static NetworkManagerVpnUI* 
impl_get_object (void)
{
	char *glade_file;
	NetworkManagerVpnUIImpl *impl;

	impl = g_new0 (NetworkManagerVpnUIImpl, 1);

	glade_file = g_strdup_printf ("%s/%s", GLADEDIR, "nm-vpnc-dialog.glade");
	impl->xml = glade_xml_new (glade_file, "nm-vpnc-widget", GETTEXT_PACKAGE);
	g_free (glade_file);
	if (impl->xml == NULL)
		goto error;

	impl->widget = glade_xml_get_widget (impl->xml, "nm-vpnc-widget");
	g_object_ref_sink (impl->widget);

	impl->w_connection_name        = GTK_ENTRY (glade_xml_get_widget (impl->xml, "vpnc-connection-name"));
	impl->w_gateway                = GTK_ENTRY (glade_xml_get_widget (impl->xml, "vpnc-gateway"));
	impl->w_group_name             = GTK_ENTRY (glade_xml_get_widget (impl->xml, "vpnc-group-name"));
	impl->w_use_alternate_username = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "vpnc-use-alternate-username"));
	impl->w_username               = GTK_ENTRY (glade_xml_get_widget (impl->xml, "vpnc-username"));
	impl->w_use_routes             = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "vpnc-use-routes"));
	impl->w_use_keepalive          = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "vpnc-use-keepalive"));
	impl->w_keepalive              = GTK_ENTRY (glade_xml_get_widget (impl->xml, "vpnc-keepalive"));
	impl->w_disable_natt           = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "vpnc-disable-natt"));
	impl->w_enable_singledes       = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "vpnc-enable-singledes"));
	impl->w_routes                 = GTK_ENTRY (glade_xml_get_widget (impl->xml, "vpnc-routes"));
	impl->w_use_domain             = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "vpnc-use-domain"));
	impl->w_domain                 = GTK_ENTRY (glade_xml_get_widget (impl->xml, "vpnc-domain"));
	impl->w_import_button          = GTK_BUTTON (glade_xml_get_widget (impl->xml,
									   "vpnc-import-button"));
	impl->callback                 = NULL;

	gtk_signal_connect (GTK_OBJECT (impl->w_use_alternate_username), 
			    "toggled", GTK_SIGNAL_FUNC (use_alternate_username_toggled), impl);

	gtk_signal_connect (GTK_OBJECT (impl->w_use_routes), 
			    "toggled", GTK_SIGNAL_FUNC (use_routes_toggled), impl);

	gtk_signal_connect (GTK_OBJECT (impl->w_use_domain), 
			    "toggled", GTK_SIGNAL_FUNC (use_domain_toggled), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_use_keepalive), 
			    "toggled", GTK_SIGNAL_FUNC (use_keepalive_toggled), impl);

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
	gtk_signal_connect (GTK_OBJECT (impl->w_keepalive), 
			    "changed", GTK_SIGNAL_FUNC (editable_changed), impl);

	gtk_signal_connect (GTK_OBJECT (impl->w_import_button), 
			    "clicked", GTK_SIGNAL_FUNC (import_button_clicked),
			    &(impl->parent));

	/* make the widget reusable */
	gtk_signal_connect (GTK_OBJECT (impl->widget), "delete-event", 
			    GTK_SIGNAL_FUNC (gtk_widget_hide_on_delete), NULL);

	vpnc_clear_widget (impl);

	impl->parent.get_display_name              = impl_get_display_name;
	impl->parent.get_service_name              = impl_get_service_name;
	impl->parent.fill_connection               = impl_fill_connection;
	impl->parent.get_widget                    = impl_get_widget;
	impl->parent.set_validity_changed_callback = impl_set_validity_changed_callback;
	impl->parent.is_valid                      = impl_is_valid;
	impl->parent.get_confirmation_details      = impl_get_confirmation_details;
	impl->parent.can_export                    = impl_can_export;
	impl->parent.import_file                   = impl_import_file;
	impl->parent.export                        = impl_export;
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
