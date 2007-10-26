/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
/* nm-openvpn.c : GNOME UI dialogs for configuring OpenVPN connections
 *
 * Copyright (C) 2005 Tim Niemueller <tim@niemueller.de>
 * Based on work by David Zeuthen, <davidz@redhat.com>
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
 * $Id$
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n-lib.h>
#include <string.h>
#include <stdlib.h>
#include <glade/glade.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-ui-interface.h>

#include "../src/nm-openvpn-service.h"

typedef struct _NetworkManagerVpnUIImpl NetworkManagerVpnUIImpl;

struct _NetworkManagerVpnUIImpl {
	NetworkManagerVpnUI parent;

	NetworkManagerVpnUIDialogValidityCallback callback;
	gpointer callback_user_data;

	gchar    *last_fc_dir;

	GladeXML *xml;

	GtkWidget *widget;
	GtkDialog *advanced;

	GtkEntry       *w_connection_name;
	GtkEntry       *w_remote;
	GtkEntry       *w_port;
	GtkEntry       *w_ca;
	GtkEntry       *w_cert;
	GtkEntry       *w_key;
	GtkCheckButton *w_use_routes;
	GtkEntry       *w_routes;
	GtkCheckButton *w_use_lzo;
	GtkCheckButton *w_use_tap;
	GtkCheckButton *w_use_tcp;
	GtkExpander    *w_opt_info_expander;
	GtkButton      *w_advanced_button;
	GtkButton      *w_import_button;
	GtkButton      *w_button_ca;
	GtkButton      *w_button_cert;
	GtkButton      *w_button_key;
	GtkComboBox    *w_connection_type;
	GtkNotebook    *w_settings_notebook;
	GtkButton      *w_button_shared_key;
	GtkEntry       *w_shared_key;
	GtkEntry       *w_local_ip;
	GtkEntry       *w_remote_ip;
	GtkEntry       *w_username;
	GtkEntry       *w_password_ca;
	GtkButton      *w_button_password_ca;
	GtkEntry       *w_x509userpass_ca;
	GtkEntry       *w_x509userpass_cert;
	GtkEntry       *w_x509userpass_key;
	GtkEntry       *w_x509userpass_username;
	GtkButton      *w_button_x509userpass_ca;
	GtkButton      *w_button_x509userpass_cert;
	GtkButton      *w_button_x509userpass_key;
	GtkCheckButton *w_use_cipher;
	GtkComboBox    *w_cipher;
	GtkCheckButton *w_use_ta;
	GtkEntry       *w_ta;
	GtkButton      *w_button_ta;
	GtkLabel       *w_ta_dir_label;
	GtkRadioButton *w_ta_dir_none;
	GtkRadioButton *w_ta_dir_zero;
	GtkRadioButton *w_ta_dir_one;
};

static void connection_type_changed(GtkComboBox *box, gpointer user_data);


static void
openvpn_clear_widget (NetworkManagerVpnUIImpl *impl)
{
	gtk_entry_set_text (impl->w_connection_name, "");
	gtk_entry_set_text (impl->w_remote,   "");
	gtk_entry_set_text (impl->w_port,   "1194");
	gtk_entry_set_text (impl->w_ca,   "");
	gtk_entry_set_text (impl->w_cert, "");
	gtk_entry_set_text (impl->w_key,  "");
	gtk_entry_set_text (impl->w_shared_key,  "");
	gtk_entry_set_text (impl->w_local_ip,  "");
	gtk_entry_set_text (impl->w_remote_ip,  "");
	gtk_entry_set_text (impl->w_username,  "");
	gtk_entry_set_text (impl->w_password_ca,  "");
	gtk_entry_set_text (impl->w_x509userpass_ca,  "");
	gtk_entry_set_text (impl->w_x509userpass_cert,  "");
	gtk_entry_set_text (impl->w_x509userpass_key,  "");
	gtk_entry_set_text (impl->w_x509userpass_username,  "");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_routes), FALSE);
	gtk_entry_set_text (impl->w_routes, "");
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_routes), FALSE);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_lzo), FALSE);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_tap), FALSE);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_tcp), FALSE);
	gtk_combo_box_set_active (GTK_COMBO_BOX (impl->w_connection_type), 0);
	connection_type_changed (GTK_COMBO_BOX (impl->w_connection_type), impl);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_cipher), FALSE);
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_cipher), FALSE);
	gtk_combo_box_set_active (GTK_COMBO_BOX (impl->w_cipher), 0);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_ta), FALSE);
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_ta), FALSE);
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_button_ta), FALSE);
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_ta_dir_label), FALSE);
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_ta_dir_none), FALSE);
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_ta_dir_zero), FALSE);
	gtk_widget_set_sensitive (GTK_WIDGET (impl->w_ta_dir_one), FALSE);
	gtk_entry_set_text (impl->w_ta, "");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_ta_dir_none), TRUE);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_ta_dir_zero), FALSE);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_ta_dir_one), FALSE);
}

static const char *
impl_get_display_name (NetworkManagerVpnUI *self)
{
	return _("OpenVPN Client");
}

static const char *
impl_get_service_name (NetworkManagerVpnUI *self)
{
	return "org.freedesktop.NetworkManager.openvpn";
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

static GValue *
int_to_gvalue (int i)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_INT);
	g_value_set_int (value, i);

	return value;
}

static GValue *
uint_to_gvalue (guint u)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_UINT);
	g_value_set_uint (value, u);

	return value;
}

static void
impl_fill_connection (NetworkManagerVpnUI *self, NMConnection *connection)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	NMSettingVPNProperties *s_vpn_props;
	GHashTable *properties;
	const char *connectionname;
	const char *remote;
	const char *port;
	const char *ca;
	const char *cert;
	const char *key;
	const char *shared_key;
	const char *local_ip;
	const char *remote_ip;
	const char *username;
	gboolean    use_lzo;
	gboolean    use_tap;
	gboolean    use_tcp;
	gboolean    use_cipher;
	gboolean    use_ta;

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_SETTING_CONNECTION);
	g_assert (s_con);

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_SETTING_VPN);
	g_assert (s_vpn);

	s_vpn_props = (NMSettingVPNProperties *) nm_connection_get_setting (connection, NM_SETTING_VPN_PROPERTIES);
	g_assert (s_vpn_props);
	properties = s_vpn_props->data;

	/* Connection name */
	connectionname = gtk_entry_get_text (impl->w_connection_name);
	g_assert (connectionname);
	s_con->name = g_strdup (connectionname);

	/* Populate routes */
	if (s_vpn->routes) {
		g_slist_foreach (s_vpn->routes, (GFunc) g_free, NULL);
		g_slist_free (s_vpn->routes);
	}
	s_vpn->routes = get_routes (impl);

	remote                 = gtk_entry_get_text (impl->w_remote);
	port                   = gtk_entry_get_text (impl->w_port);
	ca                     = gtk_entry_get_text (impl->w_ca);
	cert                   = gtk_entry_get_text (impl->w_cert);
	key                    = gtk_entry_get_text (impl->w_key);
	use_lzo                = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_lzo));
	use_tap                = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_tap));
	use_tcp                = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_tcp));
	shared_key             = gtk_entry_get_text (impl->w_shared_key);
	local_ip               = gtk_entry_get_text (impl->w_local_ip);
	remote_ip              = gtk_entry_get_text (impl->w_remote_ip);
	username               = gtk_entry_get_text (impl->w_username);
	use_cipher             = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_cipher));
	use_ta                 = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_ta));

	g_hash_table_insert (properties, NM_OPENVPN_KEY_CONNECTION_TYPE,
					 int_to_gvalue (gtk_combo_box_get_active (GTK_COMBO_BOX (impl->w_connection_type))));

	g_hash_table_insert (properties, NM_OPENVPN_KEY_TAP_DEV, bool_to_gvalue (use_tap));
	g_hash_table_insert (properties, NM_OPENVPN_KEY_REMOTE, str_to_gvalue (remote));
	g_hash_table_insert (properties, NM_OPENVPN_KEY_PORT, uint_to_gvalue ((guint) atoi (port)));
	g_hash_table_insert (properties, NM_OPENVPN_KEY_PROTO_TCP, bool_to_gvalue (use_tcp));
	g_hash_table_insert (properties, NM_OPENVPN_KEY_CA, str_to_gvalue (ca));
	g_hash_table_insert (properties, NM_OPENVPN_KEY_CERT, str_to_gvalue (cert));
	g_hash_table_insert (properties, NM_OPENVPN_KEY_KEY, str_to_gvalue (key));
	g_hash_table_insert (properties, NM_OPENVPN_KEY_COMP_LZO, bool_to_gvalue (use_lzo));
	g_hash_table_insert (properties, NM_OPENVPN_KEY_SHARED_KEY, str_to_gvalue (shared_key));
	g_hash_table_insert (properties, NM_OPENVPN_KEY_LOCAL_IP, str_to_gvalue (local_ip));
	g_hash_table_insert (properties, NM_OPENVPN_KEY_REMOTE_IP, str_to_gvalue (remote_ip));
	g_hash_table_insert (properties, NM_OPENVPN_KEY_USERNAME, str_to_gvalue (username));

	if (use_cipher) {
		const gchar *cipher = gtk_combo_box_get_active_text (impl->w_cipher);
		if (cipher != NULL)
			g_hash_table_insert (properties, NM_OPENVPN_KEY_CIPHER, str_to_gvalue (cipher));
	}
	if (use_ta) {
		const gchar* dir;

		g_hash_table_insert (properties, NM_OPENVPN_KEY_TA,
						 str_to_gvalue (gtk_entry_get_text (impl->w_ta)));

		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_ta_dir_zero)))
			dir = "0";
		else if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_ta_dir_one)))
			dir = "1";
		else
			dir = "";

		g_hash_table_insert (properties, NM_OPENVPN_KEY_TA, str_to_gvalue (dir));
	}
}

static void
set_cipher (GtkComboBox *box, GtkCheckButton *button, const char *value)
{
	GtkTreeModel *tree = gtk_combo_box_get_model(box);
	GtkTreeIter   iter;
	gboolean      valid;

	valid = gtk_tree_model_get_iter_first(tree, &iter);

	while (valid) {
		gchar *alg;

		gtk_tree_model_get (tree, &iter, 0, &alg, -1);

		/*     printf("set_cipher: %s %s\n", alg, value); */

		if (strcmp(value, alg) == 0) {
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(button), TRUE);
			gtk_widget_set_sensitive (GTK_WIDGET (box), TRUE);
			gtk_combo_box_set_active_iter (box, &iter);
			valid = FALSE;
		} else
			valid = gtk_tree_model_iter_next (tree, &iter);

		g_free (alg);
	}
}

static void
set_property (gpointer key, gpointer val, gpointer user_data)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;
	const char *name = (const char *) key;
	GValue *value = (GValue *) val;

	if (!strcmp (name, NM_OPENVPN_KEY_REMOTE))
		gtk_entry_set_text (impl->w_remote, g_value_get_string (value));
	else if (!strcmp (name, NM_OPENVPN_KEY_PORT)) {
		char *port = g_strdup_printf ("%u", g_value_get_uint (value));
		gtk_entry_set_text (impl->w_port, port);
		g_free (port);
	} else if (!strcmp (name, NM_OPENVPN_KEY_CA))
		gtk_entry_set_text (impl->w_ca, g_value_get_string (value));
	else if (!strcmp (name, NM_OPENVPN_KEY_CERT))
		gtk_entry_set_text (impl->w_cert, g_value_get_string (value));
	else if (!strcmp (name, NM_OPENVPN_KEY_KEY))
		gtk_entry_set_text (impl->w_key, g_value_get_string (value));
	else if (!strcmp (name, NM_OPENVPN_KEY_COMP_LZO))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_lzo), g_value_get_boolean (value));
	else if (!strcmp (name, NM_OPENVPN_KEY_CONNECTION_TYPE)) {
		gtk_combo_box_set_active (GTK_COMBO_BOX (impl->w_connection_type), g_value_get_int (value));
		connection_type_changed (GTK_COMBO_BOX (impl->w_connection_type), impl);
	} else if (!strcmp (name, NM_OPENVPN_KEY_LOCAL_IP))
		gtk_entry_set_text (impl->w_local_ip, g_value_get_string (value));
	else if (!strcmp (name, NM_OPENVPN_KEY_REMOTE_IP))
		gtk_entry_set_text (impl->w_remote_ip, g_value_get_string (value));
	else if (!strcmp (name, NM_OPENVPN_KEY_SHARED_KEY))
		gtk_entry_set_text (impl->w_shared_key, g_value_get_string (value));
	else if (!strcmp (name, NM_OPENVPN_KEY_USERNAME))
		gtk_entry_set_text (impl->w_username, g_value_get_string (value));
	else if (!strcmp (name, NM_OPENVPN_KEY_TAP_DEV))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_tap), g_value_get_boolean (value));
	else if (!strcmp (name, NM_OPENVPN_KEY_PROTO_TCP))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_tcp), g_value_get_boolean (value));
	else if (!strcmp (name, NM_OPENVPN_KEY_CIPHER))
		set_cipher(impl->w_cipher, impl->w_use_cipher, g_value_get_string (value));
	else if (!strcmp (name, NM_OPENVPN_KEY_TA)) {
		gtk_entry_set_text (impl->w_ta, g_value_get_string (value));
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_ta), TRUE);
	} else if (!strcmp (name, NM_OPENVPN_KEY_TA_DIR)) {
		const char *dir = g_value_get_string (value);

		if (!strcmp (dir, "0"))
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_ta_dir_zero), TRUE);
		else if (!strcmp (dir, "1"))
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_ta_dir_one), TRUE);
	}
}

static GtkWidget *
impl_get_widget (NetworkManagerVpnUI *self, NMConnection *connection)
{
	GSList *i;
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	NMSettingVPNProperties *s_vpn_props;

	openvpn_clear_widget (impl);
	if (!connection)
		goto out;

	/* Populate UI bits from the NMConnection */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_SETTING_CONNECTION);
	g_assert (s_con);
	g_assert (s_con->name);
	gtk_entry_set_text (impl->w_connection_name, s_con->name);

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_SETTING_VPN);
	g_assert (s_vpn);

	s_vpn_props = (NMSettingVPNProperties *) nm_connection_get_setting (connection, NM_SETTING_VPN_PROPERTIES);
	g_assert (s_vpn_props);

	if (s_vpn_props->data)
		g_hash_table_foreach (s_vpn_props->data, set_property, self);

	if (s_vpn->routes != NULL) {
		GString *route_str;
		char *str;

		route_str = g_string_new ("");
		for (i = s_vpn->routes; i; i = i->next) {
			if (i != s_vpn->routes)
				g_string_append_c (route_str, ' ');
			g_string_append (route_str, (char *) i->data);
		}

		str = g_string_free (route_str, FALSE);
		gtk_entry_set_text (impl->w_routes, str);
		g_free (str);
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_routes), TRUE);
		gtk_widget_set_sensitive (GTK_WIDGET (impl->w_routes), TRUE);
	}

	gtk_container_resize_children (GTK_CONTAINER (impl->widget));

 out:
	return impl->widget;
}


/** Checks if port is an integer and
 *  less than 65 
 */
static gboolean
check_port (const char *port)
{
	int d;

	if (sscanf (port, "%d", &d) != 1) {
		return FALSE;
	}

	if (d < 1 || d > 65536 ) {
		return FALSE;
	}

	return TRUE;
}


/** Checks if ip is in notation
 * a.b.c.d where a,b,c,d in {0..255}
 */
static gboolean
check_ip (const char *ip)
{
	int d1, d2, d3, d4;

	if (sscanf (ip, "%d.%d.%d.%d", &d1, &d2, &d3, &d4) != 4) {
		return FALSE;
	}

	/* TODO: this can be improved a bit */
	if (d1 < 0 || d1 > 255 ||
	    d2 < 0 || d2 > 255 ||
	    d3 < 0 || d3 > 255 ||
	    d4 < 0 || d4 > 255 ) {

		return FALSE;
	}

	return TRUE;
}

/** Checks if net cidr is in notation
 * a.b.c.d/n where a,b,c,d in {0..255} and
 * n in {0..32}
 */
static gboolean
check_net_cidr (const char *net)
{
	int d1, d2, d3, d4, mask;

	if (sscanf (net, "%d.%d.%d.%d/%d", &d1, &d2, &d3, &d4, &mask) != 5) {
		return FALSE;
	}

	/* TODO: this can be improved a bit */
	if (d1 < 0 || d1 > 255 ||
	    d2 < 0 || d2 > 255 ||
	    d3 < 0 || d3 > 255 ||
	    d4 < 0 || d4 > 255 ||
	    mask < 0 || mask > 32) {
		return FALSE;
	}

	return TRUE;
}


static gboolean
impl_is_valid (NetworkManagerVpnUI *self)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
	gboolean is_valid;
	gboolean use_routes;
	const char *routes_entry;
	const char *connectionname;
	const char *remote;
	const char *port;
	gint connection_type =   gtk_combo_box_get_active (GTK_COMBO_BOX (impl->w_connection_type));

	connectionname         = gtk_entry_get_text (impl->w_connection_name);
	remote                 = gtk_entry_get_text (impl->w_remote);
	port	                 = gtk_entry_get_text (impl->w_port);
	use_routes             = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_routes));
	routes_entry           = gtk_entry_get_text (impl->w_routes);

	is_valid = FALSE;

	if ( (strlen (connectionname) == 0) ||
		(strlen (remote) == 0) ||
		(strstr (remote, " ") != NULL)  ||
		(strstr (remote, "\t") != NULL) || 
		(strlen (port) == 0) ||
		(strstr (port, " ") != NULL)  ||
		(strstr (port, "\t") != NULL)  ||
		(!check_port (port)) ) {

		is_valid = FALSE;

	} else if ( connection_type == NM_OPENVPN_CONTYPE_SHAREDKEY ) {
		const char *shared_key;
		const char *local_ip;
		const char *remote_ip;

		shared_key             = gtk_entry_get_text (impl->w_shared_key);
		local_ip               = gtk_entry_get_text (impl->w_local_ip);
		remote_ip              = gtk_entry_get_text (impl->w_remote_ip);

		if ( (strlen (shared_key) > 0) &&
			(strlen (local_ip) > 0) &&
			(strlen (remote_ip) > 0) &&
			check_ip (local_ip) &&
			check_ip (remote_ip) &&
			g_file_test( shared_key, G_FILE_TEST_IS_REGULAR) ) {

			is_valid = TRUE;
		}

	} else if ( connection_type == NM_OPENVPN_CONTYPE_PASSWORD ) {

		const char *username;
		const char *ca;

		username    = gtk_entry_get_text (impl->w_username);
		ca          = gtk_entry_get_text (impl->w_password_ca);


		if (strlen (username) > 0 &&
		    strlen (ca) > 0 &&
		    g_file_test( ca, G_FILE_TEST_IS_REGULAR) ) {

			is_valid = TRUE;
		}

	} else if ( connection_type == NM_OPENVPN_CONTYPE_X509USERPASS ) {

		const char *ca;
		const char *cert;
		const char *key;
		const char *username;

		ca          = gtk_entry_get_text (impl->w_x509userpass_ca);
		cert        = gtk_entry_get_text (impl->w_x509userpass_cert);
		key         = gtk_entry_get_text (impl->w_x509userpass_key);
		username    = gtk_entry_get_text (impl->w_x509userpass_username);

		if (strlen (username) > 0 &&
		    strlen (ca) > 0 &&
		    strlen (cert) > 0 &&
		    strlen (key) > 0 &&
		    ((!use_routes) || (use_routes && strlen (routes_entry) > 0)) &&
		    /* validate ca/cert/key files */
		    g_file_test( ca, G_FILE_TEST_IS_REGULAR) &&
		    g_file_test( cert, G_FILE_TEST_IS_REGULAR) &&
		    g_file_test( key, G_FILE_TEST_IS_REGULAR) ) {

			is_valid = TRUE;
		}

	} else {
		// default to NM_OPENVPN_CONTYPE_X509
		const char *ca;
		const char *cert;
		const char *key;

		ca          = gtk_entry_get_text (impl->w_ca);
		cert        = gtk_entry_get_text (impl->w_cert);
		key         = gtk_entry_get_text (impl->w_key);

		/* initial sanity checking */
		if (strlen (ca) > 0 &&
		    strlen (cert) > 0 &&
		    strlen (key) > 0 &&
		    ((!use_routes) || (use_routes && strlen (routes_entry) > 0)) &&
		    /* validate ca/cert/key files */
		    g_file_test( ca, G_FILE_TEST_IS_REGULAR) &&
		    g_file_test( cert, G_FILE_TEST_IS_REGULAR) &&
		    g_file_test( key, G_FILE_TEST_IS_REGULAR) ) {

			is_valid = TRUE;
		}

	}

	/* validate routes: each entry must be of the form 'a.b.c.d/mask' */
	if (is_valid) {
		GSList *i;
		GSList *routes;

		routes = get_routes (impl);

		for (i = routes; is_valid && (i != NULL); i = g_slist_next (i)) {
			is_valid = (is_valid && check_net_cidr ( i->data ));
		}

		if (routes != NULL) {
			g_slist_foreach (routes, (GFunc)g_free, NULL);
			g_slist_free (routes);
		}
	}

	return is_valid;
}


static void
use_editable_toggled (GtkToggleButton *togglebutton, gpointer user_data)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;

	if (GTK_CHECK_BUTTON(togglebutton) == impl->w_use_routes)
		gtk_widget_set_sensitive (GTK_WIDGET (impl->w_routes),
							 gtk_toggle_button_get_active (togglebutton));
	else if (GTK_CHECK_BUTTON(togglebutton) == impl->w_use_cipher)
		gtk_widget_set_sensitive (GTK_WIDGET (impl->w_cipher),
							 gtk_toggle_button_get_active (togglebutton));
	else if (GTK_CHECK_BUTTON(togglebutton) == impl->w_use_ta) {
		gtk_widget_set_sensitive (GTK_WIDGET (impl->w_ta),
							 gtk_toggle_button_get_active (togglebutton));
		gtk_widget_set_sensitive (GTK_WIDGET (impl->w_button_ta),
							 gtk_toggle_button_get_active (togglebutton));
		gtk_widget_set_sensitive (GTK_WIDGET (impl->w_ta_dir_label),
							 gtk_toggle_button_get_active (togglebutton));
		gtk_widget_set_sensitive (GTK_WIDGET (impl->w_ta_dir_none),
							 gtk_toggle_button_get_active (togglebutton));
		gtk_widget_set_sensitive (GTK_WIDGET (impl->w_ta_dir_zero),
							 gtk_toggle_button_get_active (togglebutton));
		gtk_widget_set_sensitive (GTK_WIDGET (impl->w_ta_dir_one),
							 gtk_toggle_button_get_active (togglebutton));
	}

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

	// Sync X.509 and password CA, we save the same for both. Since this is ONE
	// connection we do not expect the value to change
	if ( GTK_ENTRY (editable) == impl->w_ca ) {
		gtk_entry_set_text ( impl->w_password_ca, gtk_entry_get_text (GTK_ENTRY (impl->w_ca)));
		gtk_entry_set_text ( impl->w_x509userpass_ca, gtk_entry_get_text (GTK_ENTRY (impl->w_ca)));
	} else if ( GTK_ENTRY (editable) == impl->w_password_ca ) {
		gtk_entry_set_text ( impl->w_ca, gtk_entry_get_text (GTK_ENTRY (impl->w_password_ca)));
		gtk_entry_set_text ( impl->w_x509userpass_ca, gtk_entry_get_text (GTK_ENTRY (impl->w_password_ca)));
	} else if ( GTK_ENTRY (editable) == impl->w_x509userpass_ca ) {
		gtk_entry_set_text ( impl->w_ca, gtk_entry_get_text (GTK_ENTRY (impl->w_x509userpass_ca)));
		gtk_entry_set_text ( impl->w_password_ca, gtk_entry_get_text (GTK_ENTRY (impl->w_x509userpass_ca)));
	}

	if ( GTK_ENTRY (editable) == impl->w_cert ) {
		gtk_entry_set_text ( impl->w_x509userpass_cert, gtk_entry_get_text (GTK_ENTRY (impl->w_cert)));
	} else if ( GTK_ENTRY (editable) == impl->w_x509userpass_cert ) {
		gtk_entry_set_text ( impl->w_cert, gtk_entry_get_text (GTK_ENTRY (impl->w_x509userpass_cert)));
	}

	if ( GTK_ENTRY (editable) == impl->w_key ) {
		gtk_entry_set_text ( impl->w_x509userpass_key, gtk_entry_get_text (GTK_ENTRY (impl->w_key)));
	} else if ( GTK_ENTRY (editable) == impl->w_x509userpass_key ) {
		gtk_entry_set_text ( impl->w_key, gtk_entry_get_text (GTK_ENTRY (impl->w_x509userpass_key)));
	}

	if ( GTK_ENTRY (editable) == impl->w_username ) {
		gtk_entry_set_text ( impl->w_x509userpass_username, gtk_entry_get_text (GTK_ENTRY (impl->w_username)));
	} else if ( GTK_ENTRY (editable) == impl->w_x509userpass_username ) {
		gtk_entry_set_text ( impl->w_username, gtk_entry_get_text (GTK_ENTRY (impl->w_x509userpass_username)));
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
	const char *remote;
	const char *port;
	const char *ca;
	const char *cert;
	const char *key;
	const char *shared_key;
	const char *local_ip;
	const char *remote_ip;
	const char *username;
	gboolean use_routes;
	const char *routes;
	gboolean use_lzo;
	gboolean use_tap;
	gboolean use_tcp;
	gint connection_type;
	gboolean use_cipher;
	const gchar *cipher;
	gboolean use_ta;
	const char *ta;
	const char *ta_dir;

	connectionname         = gtk_entry_get_text (impl->w_connection_name);
	connection_type        = gtk_combo_box_get_active (impl->w_connection_type);
	remote                 = gtk_entry_get_text (impl->w_remote);
	port                   = gtk_entry_get_text (impl->w_port);
	cert                   = gtk_entry_get_text (impl->w_cert);
	key                    = gtk_entry_get_text (impl->w_key);
	shared_key             = gtk_entry_get_text (impl->w_shared_key);
	local_ip               = gtk_entry_get_text (impl->w_local_ip);
	remote_ip              = gtk_entry_get_text (impl->w_remote_ip);
	username               = gtk_entry_get_text (impl->w_username);
	use_routes             = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_routes));
	routes                 = gtk_entry_get_text (impl->w_routes);
	use_lzo                = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_lzo));
	use_tap                = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_tap));
	use_tcp                = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_tcp));
	use_cipher             = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_cipher));
	cipher                 = gtk_combo_box_get_active_text(impl->w_cipher);
	use_ta                 = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_ta));
	ta                     = gtk_entry_get_text (impl->w_ta);
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(impl->w_ta_dir_zero)))
		ta_dir               = "0";
	else if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(impl->w_ta_dir_one)))
		ta_dir               = "1";
	else
		ta_dir               = "";

	// This is risky, should be variable length depending on actual data!
	buf = g_string_sized_new (512);

	g_string_append (buf, _("The following OpenVPN connection will be created:"));
	g_string_append (buf, "\n\n\t");
	g_string_append_printf (buf, _("Name:  %s"), connectionname);
	g_string_append (buf, "\n\n\t");

	switch ( connection_type ) {

	case NM_OPENVPN_CONTYPE_X509:
		ca = gtk_entry_get_text (impl->w_ca);

		g_string_append (buf, _("Connection Type: X.509 Certificates"));

		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("CA:  %s"), ca);

		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("Cert:  %s"), cert);

		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("Key:  %s"), key);
		break;

	case NM_OPENVPN_CONTYPE_SHAREDKEY:
		g_string_append (buf, _("Connection Type: Shared Key"));

		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("Shared Key:  %s"), shared_key);

		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("Local IP:  %s"), local_ip);

		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("Remote IP:  %s"), remote_ip);
		break;

	case NM_OPENVPN_CONTYPE_PASSWORD:
		ca = gtk_entry_get_text (impl->w_password_ca);
		g_string_append (buf, _("Connection Type: Password"));

		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("CA:  %s"), ca);

		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("Username:  %s"), username);
		break;

	case NM_OPENVPN_CONTYPE_X509USERPASS:
		ca = gtk_entry_get_text (impl->w_x509userpass_ca);

		g_string_append (buf, _("Connection Type: X.509 with Password Authentication"));

		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("CA:  %s"), ca);

		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("Cert:  %s"), cert);

		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("Key:  %s"), key);

		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("Username:  %s"), username);
		break;

	}

	g_string_append (buf, "\n\t");
	g_string_append_printf (buf, _("Remote:  %s"), remote);

	g_string_append (buf, "\n\t");
	g_string_append_printf (buf, _("Port:  %s"), port);

	g_string_append (buf, "\n\t");
	g_string_append_printf( buf, _("Device: %s"), ((use_tap) ? _("TAP") : _("TUN")));

	g_string_append (buf, "\n\t");
	g_string_append_printf( buf, _("Protocol: %s"), ((use_tcp) ? _("TCP") : _("UDP")));

	if (use_routes) {
		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("Routes:  %s"), routes);
	}

	g_string_append (buf, "\n\t");
	g_string_append_printf( buf, _("Use LZO Compression: %s"), ((use_lzo) ? _("Yes") : _("No")));

	if (use_cipher && (cipher != NULL)) {
		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("Cipher:  %s"), cipher);
	}

	if (use_ta) {
		g_string_append (buf, "\n\t");
		g_string_append_printf (buf, _("TLS auth:  %s %s"), ta, ta_dir);
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
	char *basename;
	GKeyFile *keyfile;
	gboolean file_is_good;

	file_is_good = TRUE;
	basename = g_path_get_basename (path);

	keyfile = g_key_file_new ();
	if (g_key_file_load_from_file (keyfile, path, 0, NULL)) {
		char *connectionname = NULL;
		char *remote = NULL;
		char *port = NULL;
		char *ca = NULL;
		char *cert = NULL;
		char *key = NULL;
		char *routes = NULL;
		char *lzo = NULL;
		char *dev = NULL;
		char *proto = NULL;
		char *connection_type = NULL;
		char *shared_key = NULL;
		char *local_ip = NULL;
		char *remote_ip = NULL;
		char *username = NULL;
		char *cipher = NULL;
		char *ta = NULL;
		char *ta_dir = NULL;
		gint connection_type_sel = 0;
		gboolean should_expand;

		connectionname  = g_key_file_get_string (keyfile, "openvpn", "description", NULL);
		connection_type = g_key_file_get_string (keyfile, "openvpn", "connection-type", NULL);
		remote          = g_key_file_get_string (keyfile, "openvpn", "remote", NULL);
		port            = g_key_file_get_string (keyfile, "openvpn", "port", NULL);
		dev             = g_key_file_get_string (keyfile, "openvpn", "dev", NULL);
		proto           = g_key_file_get_string (keyfile, "openvpn", "proto", NULL);
		ca              = g_key_file_get_string (keyfile, "openvpn", "ca", NULL);
		cert            = g_key_file_get_string (keyfile, "openvpn", "cert", NULL);
		key             = g_key_file_get_string (keyfile, "openvpn", "key", NULL);
		lzo             = g_key_file_get_string (keyfile, "openvpn", "comp-lzo", NULL);
		shared_key      = g_key_file_get_string (keyfile, "openvpn", "shared-key", NULL);
		local_ip        = g_key_file_get_string (keyfile, "openvpn", "local-ip", NULL);
		remote_ip       = g_key_file_get_string (keyfile, "openvpn", "remote-ip", NULL);
		username        = g_key_file_get_string (keyfile, "openvpn", "username", NULL);
		cipher          = g_key_file_get_string (keyfile, "openvpn", "cipher", NULL);
		ta              = g_key_file_get_string (keyfile, "openvpn", "ta", NULL);
		ta_dir          = g_key_file_get_string (keyfile, "openvpn", "ta_dir", NULL);

		/* may not exist */
		if ((routes = g_key_file_get_string (keyfile, "openvpn", "routes", NULL)) == NULL)
			routes = g_strdup ("");

		/* sanity check data */
		if ( (connectionname != NULL) &&
			(remote != NULL ) &&
			(port != NULL ) &&
			(dev != NULL) &&
			(proto != NULL) &&
			(connection_type != NULL) &&
			(strlen (remote) > 0) &&
			(strlen (port) > 0) &&
			(strlen (dev) > 0) &&
			(strlen (proto) > 0) &&
			(strlen (connectionname) > 0) ) {

			// Basics ok, now check per poosible mode

			if (strcmp (connection_type, "x509") == 0) {
				if ( (ca != NULL ) &&
					(cert != NULL ) &&
					(key != NULL ) &&
					(strlen(ca) > 0) &&
					(strlen(cert) > 0) &&
					(strlen(key) > 0) ) {

					gtk_entry_set_text (impl->w_ca, ca);
					gtk_entry_set_text (impl->w_password_ca, ca);
					gtk_entry_set_text (impl->w_x509userpass_ca, ca);
					gtk_entry_set_text (impl->w_cert, cert);
					gtk_entry_set_text (impl->w_x509userpass_cert, cert);
					gtk_entry_set_text (impl->w_key, key);
					gtk_entry_set_text (impl->w_x509userpass_key, key);
					connection_type_sel = NM_OPENVPN_CONTYPE_X509;
				} else {
					file_is_good = FALSE;
				}
			} else if (strcmp (connection_type, "shared-key") == 0) {
				if ( (shared_key != NULL ) &&
					(local_ip != NULL ) &&
					(remote_ip != NULL ) &&
					(strlen(shared_key) > 0) &&
					(strlen(local_ip) > 0) &&
					(strlen(remote_ip) > 0) &&
					check_ip (local_ip) &&
					check_ip (remote_ip) ) {

					gtk_entry_set_text (impl->w_shared_key, shared_key);
					gtk_entry_set_text (impl->w_local_ip, local_ip);
					gtk_entry_set_text (impl->w_remote_ip, remote_ip);
					connection_type_sel = NM_OPENVPN_CONTYPE_SHAREDKEY;
				} else {
					file_is_good = FALSE;
				}
			} else if (strcmp (connection_type, "password") == 0) {
				if ( (username != NULL ) &&
					(strlen(username) > 0) ) {

					gtk_entry_set_text (impl->w_username, username);
					gtk_entry_set_text (impl->w_x509userpass_username, username);
					gtk_entry_set_text (impl->w_ca, ca);
					gtk_entry_set_text (impl->w_password_ca, ca);
					gtk_entry_set_text (impl->w_x509userpass_ca, ca);
					connection_type_sel = NM_OPENVPN_CONTYPE_PASSWORD;
				} else {
					file_is_good = FALSE;
				}
			} else if (strcmp (connection_type, "x509userpass") == 0) {
				if ( (ca != NULL ) &&
					(cert != NULL ) &&
					(key != NULL ) &&
					(username != NULL ) &&
					(strlen(ca) > 0) &&
					(strlen(cert) > 0) &&
					(strlen(key) > 0) &&
					(strlen(username) > 0) ) {

					gtk_entry_set_text (impl->w_ca, ca);
					gtk_entry_set_text (impl->w_password_ca, ca);
					gtk_entry_set_text (impl->w_x509userpass_ca, ca);
					gtk_entry_set_text (impl->w_cert, cert);
					gtk_entry_set_text (impl->w_x509userpass_cert, cert);
					gtk_entry_set_text (impl->w_key, key);
					gtk_entry_set_text (impl->w_x509userpass_key, key);
					gtk_entry_set_text (impl->w_username, username);
					gtk_entry_set_text (impl->w_x509userpass_username, username);
					connection_type_sel = NM_OPENVPN_CONTYPE_X509USERPASS;
				} else {
					file_is_good = FALSE;
				}
			} else {
				// no connection type given in config
				file_is_good = FALSE;
			}
		} else {
			// invlid basic data
			file_is_good = FALSE;
		}

		if ((cipher != NULL) && (strlen (cipher) > 0)) {
			set_cipher(impl->w_cipher, impl->w_use_cipher, cipher);
		}

		if ((ta != NULL) && (strlen (ta) > 0)) {
			gtk_entry_set_text (impl->w_ta, ta);
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_ta), TRUE);
			gtk_widget_set_sensitive (GTK_WIDGET (impl->w_ta), TRUE);
			gtk_widget_set_sensitive (GTK_WIDGET (impl->w_button_ta), TRUE);
			gtk_widget_set_sensitive (GTK_WIDGET (impl->w_ta_dir_label), TRUE);
			gtk_widget_set_sensitive (GTK_WIDGET (impl->w_ta_dir_none), TRUE);
			gtk_widget_set_sensitive (GTK_WIDGET (impl->w_ta_dir_zero), TRUE);
			gtk_widget_set_sensitive (GTK_WIDGET (impl->w_ta_dir_one), TRUE);
		}

		if ((ta_dir != NULL) && (strlen (ta_dir) > 0)) {
			if (strcmp(ta_dir, "0") == 0)
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(impl->w_ta_dir_zero), TRUE);
			else if (strcmp(ta_dir, "1") == 0)
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(impl->w_ta_dir_one), TRUE);
			else
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(impl->w_ta_dir_none), TRUE);
		}

		if (file_is_good) {
			should_expand = FALSE;

			gtk_entry_set_text (impl->w_connection_name, connectionname);
			gtk_entry_set_text (impl->w_remote, remote);

			if ( check_port (port) ) {
				gtk_entry_set_text (impl->w_port, port);
			} else {
				gtk_entry_set_text (impl->w_port, "1194");
			} 

			gtk_combo_box_set_active (GTK_COMBO_BOX (impl->w_connection_type), connection_type_sel);
			connection_type_changed (GTK_COMBO_BOX (impl->w_connection_type), impl);

			if ( (lzo != NULL) && (strcmp(lzo, "yes") == 0) ) {
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_lzo), TRUE);
				should_expand = TRUE;
			}

			if ( strcmp (dev, "tap") == 0 ) {
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_tap), TRUE);
				should_expand = TRUE;
			}

			if ( strcmp (proto, "tcp-client") == 0 ) {
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_tcp), TRUE);
				should_expand = TRUE;
			}

			if ( strlen (routes) > 0 ) {
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_routes), TRUE);
				should_expand = TRUE;
				gtk_entry_set_text (impl->w_routes, routes);
				gtk_widget_set_sensitive (GTK_WIDGET (impl->w_routes), TRUE);
			}

			if (connection)
				impl_fill_connection (self, connection);
		} else {
			GtkWidget *dialog;

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

		g_key_file_free (keyfile);

		g_free (connectionname);
		g_free (connection_type);
		g_free (remote);
		g_free (port);
		g_free (dev);
		g_free (proto);
		g_free (ca);
		g_free (cert);
		g_free (key);
		g_free (lzo);
		g_free (shared_key);
		g_free (local_ip);
		g_free (remote_ip);
		g_free (username);
		g_free (cipher);
		g_free (ta);
		g_free (ta_dir);
	}

	g_free (basename);

	return file_is_good;
}

static void
advanced_button_clicked (GtkButton *button, gpointer user_data)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;
  
	gtk_dialog_run (impl->advanced);
	gtk_widget_hide (GTK_WIDGET(impl->advanced));
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

	if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT) {

		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
		/*printf ("User selected '%s'\n", filename);*/

	}

	gtk_widget_destroy (dialog);

	if (filename != NULL) {
		import_from_file (self, filename, NULL);
		g_free (filename);
	}
}

static void
connection_type_changed (GtkComboBox *box, gpointer user_data)
{
	int i;
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;
	gint sel = gtk_combo_box_get_active( box );

	switch ( sel ) {
	case NM_OPENVPN_CONTYPE_X509:
	case NM_OPENVPN_CONTYPE_SHAREDKEY:
	case NM_OPENVPN_CONTYPE_PASSWORD:
	case NM_OPENVPN_CONTYPE_X509USERPASS:
		{
			gtk_notebook_set_current_page( impl->w_settings_notebook, sel );
			for (i = NM_OPENVPN_CONTYPE_X509; i <= NM_OPENVPN_CONTYPE_X509USERPASS; ++i) {
				GtkWidget *tab = GTK_WIDGET ( gtk_notebook_get_nth_page( GTK_NOTEBOOK (impl->w_settings_notebook), i));
				gtk_widget_set_sensitive( tab, (i == sel));
				gtk_widget_set_sensitive( GTK_WIDGET ( gtk_notebook_get_tab_label( GTK_NOTEBOOK (impl->w_settings_notebook), tab) ), (i == sel));
			}
		}
		break;
	}
}

static void
open_button_clicked (GtkButton *button, gpointer user_data)
{

	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *)user_data;
	GtkWidget *dialog;

	const char *msg;
	GtkEntry *entry;

	gchar *dir;

	if ( button == impl->w_button_ca ) {
		msg = _("Select CA to use");
		entry = impl->w_ca;
	} else if ( button == impl->w_button_cert ) {
		msg = _("Select certificate to use");
		entry = impl->w_cert;
	} else if ( button == impl->w_button_key ) {
		msg = _("Select key to use");
		entry = impl->w_key;
	} else if ( button == impl->w_button_shared_key ) {
		msg = _("Select shared key to use");
		entry = impl->w_shared_key;
	} else if ( button == impl->w_button_password_ca ) {
		msg = _("Select CA to use");
		entry = impl->w_password_ca;
	} else if ( button == impl->w_button_x509userpass_ca ) {
		msg = _("Select CA to use");
		entry = impl->w_x509userpass_ca;
	} else if ( button == impl->w_button_x509userpass_cert ) {
		msg = _("Select certificate to use");
		entry = impl->w_x509userpass_cert;
	} else if ( button == impl->w_button_x509userpass_key ) {
		msg = _("Select key to use");
		entry = impl->w_x509userpass_key;
	} else if ( button == impl->w_button_ta ) {
		msg = _("Select TA to use");
		entry = impl->w_ta;
	} else {
		return;
	}

	dialog = gtk_file_chooser_dialog_new (msg,
								   NULL,
								   GTK_FILE_CHOOSER_ACTION_OPEN,
								   GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
								   GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
								   NULL);

	if ( impl->last_fc_dir != NULL ) {
		gtk_file_chooser_set_current_folder (GTK_FILE_CHOOSER (dialog), impl->last_fc_dir);
	}

	if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT) {
		gtk_entry_set_text (entry, gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog)));
		dir = gtk_file_chooser_get_current_folder (GTK_FILE_CHOOSER (dialog));
		g_free( impl->last_fc_dir );
		impl->last_fc_dir = dir;
	}

	gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
	gtk_widget_destroy (dialog);

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
	GValue *val;
	FILE *f;
	const char *connection_type = "";
	const char *remote = "";
	guint port;
	gboolean tap_dev;
	gboolean proto_tcp;
	const char *ca = "";
	const char *cert = "";
	const char *key = "";
	gboolean lzo;
	const char *shared_key = "";
	const char *local_ip = "";
	const char *remote_ip = "";
	const char *username = "";
	const char *cipher = "";
	const char *ta = "";
	const char *ta_dir = "";
	char *routes_str = NULL;
	gboolean ret;

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_SETTING_CONNECTION);
	g_assert (s_con);

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_SETTING_VPN);
	g_assert (s_vpn);

	s_vpn_props = (NMSettingVPNProperties *) nm_connection_get_setting (connection, NM_SETTING_VPN_PROPERTIES);
	g_assert (s_vpn_props);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_REMOTE);
	if (val)
		remote = g_value_get_string (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_PORT);
	if (val)
		port = g_value_get_uint (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_TAP_DEV);
	if (val)
		tap_dev = g_value_get_boolean (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_PROTO_TCP);
	if (val)
		proto_tcp = g_value_get_boolean (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_CA);
	if (val)
		ca = g_value_get_string (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_CERT);
	if (val)
		cert = g_value_get_string (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_KEY);
	if (val)
		key = g_value_get_string (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_COMP_LZO);
	if (val)
		lzo = g_value_get_boolean (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_SHARED_KEY);
	if (val)
		shared_key = g_value_get_string (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_LOCAL_IP);
	if (val)
		local_ip = g_value_get_string (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_REMOTE_IP);
	if (val)
		remote_ip = g_value_get_string (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_USERNAME);
	if (val)
		username = g_value_get_string (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_CONNECTION_TYPE);
	if (val) {
		switch (g_value_get_int (val)) {
		case NM_OPENVPN_CONTYPE_X509:
			connection_type = "x509";
			break;
		case NM_OPENVPN_CONTYPE_SHAREDKEY:
			connection_type = "shared-key";
			break;
		case NM_OPENVPN_CONTYPE_PASSWORD:
			connection_type = "password";
			break;
		case NM_OPENVPN_CONTYPE_X509USERPASS:
			connection_type = "x509userpass";
			break;
		default:
			break;
		}
	}

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_CIPHER);
	if (val)
		cipher = g_value_get_string (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_TA);
	if (val)
		ta = g_value_get_string (val);

	val = (GValue *) g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_TA_DIR);
	if (val)
		ta_dir = g_value_get_string (val);


	if (s_vpn->routes != NULL) {
		GSList *i;
		GString *str;

		str = g_string_new ("");
		for (i = s_vpn->routes; i != NULL; i = g_slist_next (i)) {
			if (i != s_vpn->routes)
				g_string_append_c (str, ' ');
			g_string_append (str, (const char *) i->data);
		}

		g_string_append_c (str, '\n');

		routes_str = g_string_free (str, FALSE);
	}

	f = fopen (path, "w");
	if (f != NULL) {

		fprintf (f,
			    "[openvpn]\n"
			    "description=%s\n"
			    "connection-type=%s\n"
			    "remote=%s\n"
			    "port=%u\n"
			    "dev=%s\n"
			    "proto=%s\n"
			    "ca=%s\n"
			    "cert=%s\n"
			    "key=%s\n"
			    "comp-lzo=%s\n"
			    "shared-key=%s\n"
			    "local-ip=%s\n"
			    "remote-ip=%s\n"
			    "username=%s\n"
			    "cipher=%s\n"
			    "ta=%s\n"
			    "ta_dir=%s\n"
			    "routes=%s\n",
			    /* Description */ s_con->name,
			    /* conn type */   connection_type,
			    /* Host */        remote,
			    /* Port */        port,
			    /* TUN or TAP */  tap_dev ? "tap" : "tun",
			    /* TCP or UDP */  proto_tcp ? "tcp-client" : "udp",
			    /* CA */          ca,
			    /* Cert */        cert,
			    /* Key */         key,
			    /* Comp-LZO */    lzo ? "yes" : "",
			    /* Shared key */  shared_key,
			    /* local ip */    local_ip,
			    /* remote ip */   remote_ip,
			    /* username */    username,
			    /* cipher */      cipher,
			    /* TA */          ta,
			    /* TA direction*/ ta_dir,
			    /* X-NM-Routes */ routes_str != NULL ? routes_str : "");

		fclose (f);
		ret = TRUE;
	}
	else
		ret = FALSE;

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

	/*printf ("in impl_export\n");*/

	dialog = gtk_file_chooser_dialog_new (_("Save as..."),
								   NULL,
								   GTK_FILE_CHOOSER_ACTION_SAVE,
								   GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
								   GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT,
								   NULL);

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_SETTING_CONNECTION);
	g_assert (s_con);
	g_assert (s_con->name);

	suggested_name = g_strdup_printf ("%s.pcf", s_con->name);
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

static const char *
nm_find_openvpn (void)
{
	static const char *openvpn_binary_paths[] = {
		"/usr/sbin/openvpn",
		"/sbin/openvpn",
		NULL
	};
	const char  **openvpn_binary = openvpn_binary_paths;

	while (*openvpn_binary != NULL) {
		if (g_file_test (*openvpn_binary, G_FILE_TEST_EXISTS))
			break;
		openvpn_binary++;
	}

	return *openvpn_binary;
}

static void
populate_cipher (GtkComboBox *box)
{
	const char *openvpn_binary = NULL;
	gchar      *cmdline, *tmp, *token;

	openvpn_binary = nm_find_openvpn ();
	if (!openvpn_binary)
		return;

	cmdline = g_strdup_printf("/bin/sh -c \"%s --show-ciphers | /bin/awk '/^[A-Z][A-Z0-9]+-/ { print $1 }'\"", openvpn_binary);
	if (!g_spawn_command_line_sync(cmdline, &tmp, NULL, NULL, NULL))
		goto end;

	token = strtok(tmp, "\n");

	while (token) {
		if (strlen(token))
			gtk_combo_box_append_text(box, token);
		token = strtok(NULL, "\n");
	}

 end:
	g_free(tmp);
}

static NetworkManagerVpnUI*
impl_get_object (void)
{
	char *glade_file;
	NetworkManagerVpnUIImpl *impl;

	impl = g_new0 (NetworkManagerVpnUIImpl, 1);

	impl->last_fc_dir = NULL;

	glade_file = g_strdup_printf ("%s/%s", GLADEDIR, "nm-openvpn-dialog.glade");
	impl->xml = glade_xml_new (glade_file, "nm-openvpn-widget", GETTEXT_PACKAGE);
	g_free( glade_file );
	if (impl->xml == NULL)
		goto error;

	impl->widget = glade_xml_get_widget(impl->xml, "nm-openvpn-widget");
	g_object_ref_sink (impl->widget);

	impl->advanced = GTK_DIALOG (glade_xml_get_widget(impl->xml, "nm-openvpn-advanced-dialog"));

	impl->w_connection_name        = GTK_ENTRY (glade_xml_get_widget (impl->xml, "openvpn-connection-name"));
	impl->w_remote                = GTK_ENTRY (glade_xml_get_widget (impl->xml, "openvpn-remote"));
	impl->w_port                  = GTK_ENTRY (glade_xml_get_widget (impl->xml, "openvpn-port"));
	impl->w_use_routes             = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "openvpn-use-routes"));
	impl->w_routes                 = GTK_ENTRY (glade_xml_get_widget (impl->xml, "openvpn-routes"));
	impl->w_opt_info_expander      = GTK_EXPANDER (glade_xml_get_widget (impl->xml,
														    "openvpn-optional-information-expander"));
	impl->w_advanced_button          = GTK_BUTTON (glade_xml_get_widget (impl->xml,
														    "openvpn-advanced-button"));

	impl->w_import_button          = GTK_BUTTON (glade_xml_get_widget (impl->xml,
														  "openvpn-import-button"));

	impl->w_ca                     = GTK_ENTRY( glade_xml_get_widget( impl->xml, "openvpn-ca" ) );
	impl->w_cert                   = GTK_ENTRY( glade_xml_get_widget( impl->xml, "openvpn-cert" ) );
	impl->w_key                    = GTK_ENTRY( glade_xml_get_widget( impl->xml, "openvpn-key" ) );

	impl->w_button_ca              = GTK_BUTTON( glade_xml_get_widget( impl->xml, "openvpn-but-ca" ) );
	impl->w_button_cert            = GTK_BUTTON( glade_xml_get_widget( impl->xml, "openvpn-but-cert" ) );
	impl->w_button_key             = GTK_BUTTON( glade_xml_get_widget( impl->xml, "openvpn-but-key" ) );

	impl->w_use_lzo                = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "openvpn-use-lzo"));
	impl->w_use_tap                = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "openvpn-use-tap"));
	impl->w_use_tcp                = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "openvpn-use-tcp"));

	impl->w_connection_type        = GTK_COMBO_BOX (glade_xml_get_widget (impl->xml, "openvpn-connection-type"));
	impl->w_settings_notebook      = GTK_NOTEBOOK (glade_xml_get_widget (impl->xml, "openvpn-settings"));

	impl->w_button_shared_key      = GTK_BUTTON( glade_xml_get_widget( impl->xml, "openvpn-but-shared-key" ) );
	impl->w_shared_key             = GTK_ENTRY( glade_xml_get_widget( impl->xml, "openvpn-shared-key" ) );
	impl->w_local_ip               = GTK_ENTRY( glade_xml_get_widget( impl->xml, "openvpn-local-ip" ) );
	impl->w_remote_ip              = GTK_ENTRY( glade_xml_get_widget( impl->xml, "openvpn-remote-ip" ) );

	impl->w_username               = GTK_ENTRY( glade_xml_get_widget( impl->xml, "openvpn-username" ) );
	impl->w_password_ca            = GTK_ENTRY( glade_xml_get_widget( impl->xml, "openvpn-password-ca" ) );
	impl->w_button_password_ca     = GTK_BUTTON( glade_xml_get_widget( impl->xml, "openvpn-password-but-ca" ) );

	impl->w_x509userpass_ca                     = GTK_ENTRY( glade_xml_get_widget( impl->xml, "openvpn-x509userpass-ca" ) );
	impl->w_x509userpass_cert                   = GTK_ENTRY( glade_xml_get_widget( impl->xml, "openvpn-x509userpass-cert" ) );
	impl->w_x509userpass_key                    = GTK_ENTRY( glade_xml_get_widget( impl->xml, "openvpn-x509userpass-key" ) );
	impl->w_x509userpass_username               = GTK_ENTRY( glade_xml_get_widget( impl->xml, "openvpn-x509userpass-username" ) );

	impl->w_button_x509userpass_ca              = GTK_BUTTON( glade_xml_get_widget( impl->xml, "openvpn-x509userpass-but-ca" ) );
	impl->w_button_x509userpass_cert            = GTK_BUTTON( glade_xml_get_widget( impl->xml, "openvpn-x509userpass-but-cert" ) );
	impl->w_button_x509userpass_key             = GTK_BUTTON( glade_xml_get_widget( impl->xml, "openvpn-x509userpass-but-key" ) );

	impl->w_use_cipher             = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "openvpn-use-cipher"));
	impl->w_cipher                 = GTK_COMBO_BOX( glade_xml_get_widget( impl->xml, "openvpn-cipher" ) );
	populate_cipher(impl->w_cipher);

	impl->w_use_ta                 = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "openvpn-use-ta"));
	impl->w_ta                     = GTK_ENTRY( glade_xml_get_widget( impl->xml, "openvpn-ta" ) );
	impl->w_button_ta              = GTK_BUTTON( glade_xml_get_widget( impl->xml, "openvpn-but-ta" ) );
	impl->w_ta_dir_label           = GTK_LABEL( glade_xml_get_widget( impl->xml, "openvpn-ta-dir-label" ) );
	impl->w_ta_dir_none            = GTK_RADIO_BUTTON( glade_xml_get_widget( impl->xml, "openvpn-ta-dir-none" ) );
	impl->w_ta_dir_zero            = GTK_RADIO_BUTTON( glade_xml_get_widget( impl->xml, "openvpn-ta-dir-zero" ) );
	impl->w_ta_dir_one             = GTK_RADIO_BUTTON( glade_xml_get_widget( impl->xml, "openvpn-ta-dir-one" ) );

	impl->callback                 = NULL;


	gtk_signal_connect (GTK_OBJECT (impl->w_use_routes),
					"toggled", GTK_SIGNAL_FUNC (use_editable_toggled), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_use_cipher),
					"toggled", GTK_SIGNAL_FUNC (use_editable_toggled), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_use_ta),
					"toggled", GTK_SIGNAL_FUNC (use_editable_toggled), impl);

	gtk_signal_connect (GTK_OBJECT (impl->w_connection_name),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_remote),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_port),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_routes),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_ca),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_cert),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_key),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_shared_key),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_local_ip),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_remote_ip),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_username),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_password_ca),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_x509userpass_ca),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_x509userpass_cert),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_x509userpass_key),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_x509userpass_username),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_ta),
					"changed", GTK_SIGNAL_FUNC (editable_changed), impl);

	gtk_signal_connect (GTK_OBJECT (impl->w_button_ca),
					"clicked", GTK_SIGNAL_FUNC (open_button_clicked), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_button_cert),
					"clicked", GTK_SIGNAL_FUNC (open_button_clicked), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_button_key),
					"clicked", GTK_SIGNAL_FUNC (open_button_clicked), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_button_shared_key),
					"clicked", GTK_SIGNAL_FUNC (open_button_clicked), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_button_password_ca),
					"clicked", GTK_SIGNAL_FUNC (open_button_clicked), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_button_x509userpass_ca),
					"clicked", GTK_SIGNAL_FUNC (open_button_clicked), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_button_x509userpass_cert),
					"clicked", GTK_SIGNAL_FUNC (open_button_clicked), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_button_x509userpass_key),
					"clicked", GTK_SIGNAL_FUNC (open_button_clicked), impl);
	gtk_signal_connect (GTK_OBJECT (impl->w_button_ta),
					"clicked", GTK_SIGNAL_FUNC (open_button_clicked), impl);

	gtk_signal_connect (GTK_OBJECT (impl->w_advanced_button),
					"clicked", GTK_SIGNAL_FUNC (advanced_button_clicked), impl);

	gtk_signal_connect (GTK_OBJECT (impl->w_import_button),
					"clicked", GTK_SIGNAL_FUNC (import_button_clicked), &(impl->parent));

	gtk_signal_connect (GTK_OBJECT (impl->w_connection_type),
					"changed", GTK_SIGNAL_FUNC (connection_type_changed), impl);

	/* make the widget reusable */
	gtk_signal_connect (GTK_OBJECT (impl->widget), "delete-event",
					GTK_SIGNAL_FUNC (gtk_widget_hide_on_delete), NULL);
	gtk_signal_connect (GTK_OBJECT (impl->advanced), "delete-event",
					GTK_SIGNAL_FUNC (gtk_widget_hide_on_delete), NULL);

	openvpn_clear_widget (impl);

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
	impl->parent.data                          = impl;

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
