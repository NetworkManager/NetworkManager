/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * CVSID: $Id$
 *
 * nm-vpnc.c : GNOME UI dialogs for configuring vpnc VPN connections
 *
 * Copyright (C) 2005 David Zeuthen, <davidz@redhat.com>
 * Copyright (C) 2005 - 2008 Dan Williams, <dcbw@redhat.com>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <glib/gi18n-lib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-vpn-properties.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "../src/nm-vpnc-service.h"
#include "pcf-file.h"
#include "nm-vpnc.h"

#define VPNC_PLUGIN_NAME    _("Cisco Compatible VPN (vpnc)")
#define VPNC_PLUGIN_DESC    _("Compatible with various Cisco, Juniper, Netscreen, and Sonicwall IPSec-based VPN gateways.")
#define VPNC_PLUGIN_SERVICE NM_DBUS_SERVICE_VPNC 

#define ENC_TYPE_SECURE 0
#define ENC_TYPE_WEAK   1
#define ENC_TYPE_NONE   2

/************** plugin class **************/

static void vpnc_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (VpncPluginUi, vpnc_plugin_ui, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_INTERFACE,
											   vpnc_plugin_ui_interface_init))

/************** UI widget class **************/

static void vpnc_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (VpncPluginUiWidget, vpnc_plugin_ui_widget, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_WIDGET_INTERFACE,
											   vpnc_plugin_ui_widget_interface_init))

#define VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), VPNC_TYPE_PLUGIN_UI_WIDGET, VpncPluginUiWidgetPrivate))

typedef struct {
	GladeXML *xml;
	GtkWidget *widget;
	GtkSizeGroup *group;
	gint orig_dpd_timeout;
} VpncPluginUiWidgetPrivate;


#define VPNC_PLUGIN_UI_ERROR vpnc_plugin_ui_error_quark ()

static GQuark
vpnc_plugin_ui_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("vpnc-plugin-ui-error-quark");

	return error_quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
vpnc_plugin_ui_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (VPNC_PLUGIN_UI_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (VPNC_PLUGIN_UI_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (VPNC_PLUGIN_UI_ERROR_MISSING_PROPERTY, "MissingProperty"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("VpncPluginUiError", values);
	}
	return etype;
}


static gboolean
check_validity (VpncPluginUiWidget *self, GError **error)
{
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	char *str;

	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str) || strstr (str, " ") || strstr (str, "\t")) {
		g_set_error (error,
		             VPNC_PLUGIN_UI_ERROR,
		             VPNC_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_VPNC_KEY_GATEWAY);
		return FALSE;
	}

	widget = glade_xml_get_widget (priv->xml, "group_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             VPNC_PLUGIN_UI_ERROR,
		             VPNC_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_VPNC_KEY_ID);
		return FALSE;
	}

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (VPNC_PLUGIN_UI_WIDGET (user_data), "changed");
}

static gboolean
init_plugin_ui (VpncPluginUiWidget *self, NMConnection *connection, GError **error)
{
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPNProperties *s_vpn_props;
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	int active = -1;
	GValue *value;
	const char *natt_mode = NULL;

	s_vpn_props = (NMSettingVPNProperties *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN_PROPERTIES);

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn_props) {
		value = g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_GATEWAY);
		if (value && G_VALUE_HOLDS_STRING (value))
			gtk_entry_set_text (GTK_ENTRY (widget), g_value_get_string (value));
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "group_entry");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn_props) {
		value = g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_ID);
		if (value && G_VALUE_HOLDS_STRING (value))
			gtk_entry_set_text (GTK_ENTRY (widget), g_value_get_string (value));
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "encryption_combo");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));

	store = gtk_list_store_new (1, G_TYPE_STRING);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Secure (default)"), -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Weak (use with caution)"), -1);
	if ((active < 0) && s_vpn_props) {
		value = g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_SINGLE_DES);
		if (value && G_VALUE_HOLDS_BOOLEAN (value) && g_value_get_boolean (value))
			active = 1;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("None (completely insecure)"), -1);
	if ((active < 0) && s_vpn_props) {
		value = g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_NO_ENCRYPTION);
		if (value && G_VALUE_HOLDS_BOOLEAN (value) && g_value_get_boolean (value))
			active = 2;
	}

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "user_entry");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn_props) {
		value = g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_XAUTH_USER);
		if (value && G_VALUE_HOLDS_STRING (value))
			gtk_entry_set_text (GTK_ENTRY (widget), g_value_get_string (value));
		else {
		}
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "domain_entry");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn_props) {
		value = g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_DOMAIN);
		if (value && G_VALUE_HOLDS_STRING (value))
			gtk_entry_set_text (GTK_ENTRY (widget), g_value_get_string (value));
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	active = -1;
	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
	if (s_vpn_props) {
		value = g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
		if (value && G_VALUE_HOLDS_STRING (value))
			natt_mode = g_value_get_string (value);
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("NAT-T (default)"), 1, NM_VPNC_NATT_MODE_NATT, -1);
	if ((active < 0) && natt_mode) {
		if (!strcmp (natt_mode, NM_VPNC_NATT_MODE_NATT))
			active = 0;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Cisco UDP"), 1, NM_VPNC_NATT_MODE_CISCO, -1);
	if ((active < 0) && natt_mode) {
		if (!strcmp (natt_mode, NM_VPNC_NATT_MODE_CISCO))
			active = 1;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Disabled"), 1, NM_VPNC_NATT_MODE_NONE, -1);
	if ((active < 0) && natt_mode) {
		if (!strcmp (natt_mode, NM_VPNC_NATT_MODE_NONE))
			active = 2;
	}

	widget = glade_xml_get_widget (priv->xml, "natt_combo");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "disable_dpd_checkbutton");
	if (!widget)
		return FALSE;
	if (s_vpn_props) {
		value = g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_DPD_IDLE_TIMEOUT);
		if (value && G_VALUE_HOLDS_INT (value)) {
			priv->orig_dpd_timeout = g_value_get_int (value);
			if (priv->orig_dpd_timeout == 0)
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
		}
	}
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (stuff_changed_cb), self);

	return TRUE;
}

static GObject *
get_widget (NMVpnPluginUiWidgetInterface *iface)
{
	VpncPluginUiWidget *self = VPNC_PLUGIN_UI_WIDGET (iface);
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
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
int_to_gvalue (gint i)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_INT);
	g_value_set_int (value, i);

	return value;
}

static gboolean
update_connection (NMVpnPluginUiWidgetInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	VpncPluginUiWidget *self = VPNC_PLUGIN_UI_WIDGET (iface);
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	NMSettingVPNProperties *s_vpn_props;
	GtkWidget *widget;
	char *str;
	GtkTreeModel *model;
	GtkTreeIter iter;

	if (!check_validity (self, error))
		return FALSE;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	s_vpn->service_type = g_strdup (NM_DBUS_SERVICE_VPNC);
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	s_vpn_props = NM_SETTING_VPN_PROPERTIES (nm_setting_vpn_properties_new ());

	/* Gateway */
	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str)) {
		g_hash_table_insert (s_vpn_props->data,
		                     g_strdup (NM_VPNC_KEY_GATEWAY),
		                     str_to_gvalue (str));
	}

	/* Group name */
	widget = glade_xml_get_widget (priv->xml, "group_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str)) {
		g_hash_table_insert (s_vpn_props->data,
		                     g_strdup (NM_VPNC_KEY_ID),
		                     str_to_gvalue (str));
	}

	widget = glade_xml_get_widget (priv->xml, "user_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str)) {
		g_hash_table_insert (s_vpn_props->data,
		                     g_strdup (NM_VPNC_KEY_XAUTH_USER),
		                     str_to_gvalue (str));
	}

	widget = glade_xml_get_widget (priv->xml, "domain_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str)) {
		g_hash_table_insert (s_vpn_props->data,
		                     g_strdup (NM_VPNC_KEY_DOMAIN),
		                     str_to_gvalue (str));
	}

	widget = glade_xml_get_widget (priv->xml, "encryption_combo");
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget))) {
	case ENC_TYPE_WEAK:
		g_hash_table_insert (s_vpn_props->data,
		                     g_strdup (NM_VPNC_KEY_SINGLE_DES),
		                     bool_to_gvalue (TRUE));
		break;
	case ENC_TYPE_NONE:
		g_hash_table_insert (s_vpn_props->data,
		                     g_strdup (NM_VPNC_KEY_NO_ENCRYPTION),
		                     bool_to_gvalue (TRUE));
		break;
	case ENC_TYPE_SECURE:
	default:
		break;
	}

	widget = glade_xml_get_widget (priv->xml, "natt_combo");
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		const char *mode;

		gtk_tree_model_get (model, &iter, 1, &mode, -1);
		g_hash_table_insert (s_vpn_props->data,
		                     g_strdup (NM_VPNC_KEY_NAT_TRAVERSAL_MODE),
		                     str_to_gvalue (mode));
	} else {
		g_hash_table_insert (s_vpn_props->data,
		                     g_strdup (NM_VPNC_KEY_NAT_TRAVERSAL_MODE),
		                     str_to_gvalue (NM_VPNC_NATT_MODE_NATT));
	}
	
	widget = glade_xml_get_widget (priv->xml, "disable_dpd_checkbutton");
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		g_hash_table_insert (s_vpn_props->data,
		                     g_strdup (NM_VPNC_KEY_DPD_IDLE_TIMEOUT),
		                     int_to_gvalue (0));
	} else {
		g_hash_table_insert (s_vpn_props->data,
		                     g_strdup (NM_VPNC_KEY_DPD_IDLE_TIMEOUT),
		                     int_to_gvalue (priv->orig_dpd_timeout));
	}

	nm_connection_add_setting (connection, NM_SETTING (s_vpn_props));
	return TRUE;
}

static NMVpnPluginUiWidgetInterface *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
	NMVpnPluginUiWidgetInterface *object;
	VpncPluginUiWidgetPrivate *priv;
	char *glade_file;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = NM_VPN_PLUGIN_UI_WIDGET_INTERFACE (g_object_new (VPNC_TYPE_PLUGIN_UI_WIDGET, NULL));
	if (!object) {
		g_set_error (error, VPNC_PLUGIN_UI_ERROR, 0, "could not create vpnc object");
		return NULL;
	}

	priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (object);

	glade_file = g_strdup_printf ("%s/%s", GLADEDIR, "nm-vpnc-dialog.glade");
	priv->xml = glade_xml_new (glade_file, "vpnc-vbox", GETTEXT_PACKAGE);
	if (priv->xml == NULL) {
		g_set_error (error, VPNC_PLUGIN_UI_ERROR, 0,
		             "could not load required resources at %s", glade_file);
		g_free (glade_file);
		g_object_unref (object);
		return NULL;
	}
	g_free (glade_file);

	priv->widget = glade_xml_get_widget (priv->xml, "vpnc-vbox");
	if (!priv->widget) {
		g_set_error (error, VPNC_PLUGIN_UI_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	if (!init_plugin_ui (VPNC_PLUGIN_UI_WIDGET (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	VpncPluginUiWidget *plugin = VPNC_PLUGIN_UI_WIDGET (object);
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (plugin);

	if (priv->group)
		g_object_unref (priv->group);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->xml)
		g_object_unref (priv->xml);

	G_OBJECT_CLASS (vpnc_plugin_ui_widget_parent_class)->dispose (object);
}

static void
vpnc_plugin_ui_widget_class_init (VpncPluginUiWidgetClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (VpncPluginUiWidgetPrivate));

	object_class->dispose = dispose;
}

static void
vpnc_plugin_ui_widget_init (VpncPluginUiWidget *plugin)
{
}

static void
vpnc_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

static GSList *
get_routes (const char *routelist)
{
	GSList *routes = NULL;
	char **substrs;
	unsigned int i;

	substrs = g_strsplit (routelist, " ", 0);
	for (i = 0; substrs[i] != NULL; i++) {
		struct in_addr tmp;
		char *p, *str_route;
		long int prefix = 32;

		str_route = g_strdup (substrs[i]);
		p = strchr (str_route, '/');
		if (!p || !(*(p + 1))) {
			g_warning ("Ignoring invalid route '%s'", str_route);
			goto next;
		}

		errno = 0;
		prefix = strtol (p + 1, NULL, 10);
		if (errno || prefix <= 0 || prefix > 32) {
			g_warning ("Ignoring invalid route '%s'", str_route);
			goto next;
		}

		/* don't pass the prefix to inet_pton() */
		*p = '\0';
		if (inet_pton (AF_INET, str_route, &tmp) > 0) {
			NMSettingIP4Route *route;

			route = g_new0 (NMSettingIP4Route, 1);
			route->address = tmp.s_addr;
			route->prefix = (guint32) prefix;

			routes = g_slist_append (routes, route);
		} else
			g_warning ("Ignoring invalid route '%s'", str_route);

next:
		g_free (str_route);
	}

	g_strfreev (substrs);
	return routes;
}

static NMConnection *
import (NMVpnPluginUiInterface *iface, const char *path, GError **error)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	NMSettingVPNProperties *s_vpn_props;
	GHashTable *pcf;
	const char *buf;
	gboolean have_value;

	pcf = pcf_file_load (path);
	if (!pcf) {
		g_set_error (error, 0, 0, "does not look like a %s VPN connection",
		             VPNC_PLUGIN_NAME);
		return NULL;
	}

	connection = nm_connection_new ();
	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	s_vpn->service_type = g_strdup (VPNC_PLUGIN_SERVICE);
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	s_vpn_props = NM_SETTING_VPN_PROPERTIES (nm_setting_vpn_properties_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_vpn_props));

	/* Connection name */
	if ((buf = pcf_file_lookup_value (pcf, "main", "Description")))
		s_con->id = g_strdup (buf);
	else {
		g_set_error (error, 0, 0, "does not look like a %s VPN connection (parse failed)",
		             VPNC_PLUGIN_NAME);
		g_object_unref (connection);
		return NULL;
	}

	/* Gateway */
	if ((buf = pcf_file_lookup_value (pcf, "main", "Host")))
		g_hash_table_insert (s_vpn_props->data, g_strdup (NM_VPNC_KEY_GATEWAY), str_to_gvalue (buf));
	else {
		g_set_error (error, 0, 0, "does not look like a %s VPN connection (no Host)",
		             VPNC_PLUGIN_NAME);
		g_object_unref (connection);
		return NULL;
	}

	/* Group name */
	if ((buf = pcf_file_lookup_value (pcf, "main", "GroupName")))
		g_hash_table_insert (s_vpn_props->data, g_strdup (NM_VPNC_KEY_ID), str_to_gvalue (buf));
	else {
		g_set_error (error, 0, 0, "does not look like a %s VPN connection (no GroupName)",
		             VPNC_PLUGIN_NAME);
		g_object_unref (connection);
		return NULL;
	}

	/* Optional settings */

	buf = pcf_file_lookup_value (pcf, "main", "UserName");
	have_value = buf == NULL ? FALSE : strlen (buf) > 0;
	if (have_value)
		g_hash_table_insert (s_vpn_props->data, g_strdup (NM_VPNC_KEY_XAUTH_USER), str_to_gvalue (buf));

	buf = pcf_file_lookup_value (pcf, "main", "NTDomain");
	have_value = buf == NULL ? FALSE : strlen (buf) > 0;
	if (have_value)
		g_hash_table_insert (s_vpn_props->data, g_strdup (NM_VPNC_KEY_DOMAIN), str_to_gvalue (buf));

	buf = pcf_file_lookup_value (pcf, "main", "SingleDES");
	have_value = (buf == NULL ? FALSE : strcmp (buf, "0") != 0);
	if (have_value)
		g_hash_table_insert (s_vpn_props->data, g_strdup (NM_VPNC_KEY_SINGLE_DES), bool_to_gvalue (TRUE));

	/* Default is enabled, only disabled if explicit EnableNat=0 exists */
	buf = pcf_file_lookup_value (pcf, "main", "EnableNat");
	have_value = (buf ? strncmp (buf, "0", 1) == 0 : FALSE);
	if (have_value)
		g_hash_table_insert (s_vpn_props->data, g_strdup (NM_VPNC_KEY_NAT_TRAVERSAL_MODE), str_to_gvalue (NM_VPNC_NATT_MODE_NATT));

	if ((buf = pcf_file_lookup_value (pcf, "main", "PeerTimeout"))) {
		gulong val = strtol (buf, NULL, 10);

		if ((val == 0) || ((val > 10) && (val < 86400)))
			g_hash_table_insert (s_vpn_props->data, g_strdup (NM_VPNC_KEY_DPD_IDLE_TIMEOUT), int_to_gvalue ((gint) val));
	}

	buf = pcf_file_lookup_value (pcf, "main", "X-NM-Routes");
	have_value = buf == NULL ? FALSE : strlen (buf) > 0;
	if (have_value) {
		NMSettingIP4Config *s_ip4;

		s_ip4 = NM_SETTING_IP4_CONFIG (nm_setting_ip4_config_new ());
		nm_connection_add_setting (connection, NM_SETTING (s_ip4));
		s_ip4->routes = get_routes (buf);
	}

	if ((buf = pcf_file_lookup_value (pcf, "main", "TunnelingMode"))) {
		/* If applicable, put up warning that TCP tunneling will be disabled */

		if (strncmp (buf, "1", 1) == 0) {
			GtkWidget *dialog;
			char *basename;

			basename = g_path_get_basename (path);
			dialog = gtk_message_dialog_new (NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
											 GTK_MESSAGE_WARNING, GTK_BUTTONS_CLOSE,
											 _("TCP tunneling not supported"));
			gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog),
													  _("The VPN settings file '%s' specifies that VPN traffic should be tunneled through TCP which is currently not supported in the vpnc software.\n\nThe connection can still be created, with TCP tunneling disabled, however it may not work as expected."), basename);
			g_free (basename);
			gtk_dialog_run (GTK_DIALOG (dialog));
			gtk_widget_destroy (dialog);
		}
	}

	g_hash_table_destroy (pcf);

	return connection;
}

static gboolean
export (NMVpnPluginUiInterface *iface,
        const char *path,
        NMConnection *connection,
        GError **error)
{
	NMSettingConnection *s_con;
	NMSettingVPNProperties *s_vpn_props;
	NMSettingIP4Config *s_ip4;
	FILE *f;
	GValue *value;
	const char *gateway = NULL;
	gboolean enablenat = TRUE;
	gboolean singledes = FALSE;
	const char *groupname = NULL;
	const char *username = NULL;
	const char *domain = NULL;
	int peertimeout = 0;
	GString *routes = NULL;
	gboolean success = FALSE;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);

	s_vpn_props = (NMSettingVPNProperties *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN_PROPERTIES);
	if (!s_vpn_props || !s_vpn_props->data) {
		g_set_error (error, 0, 0, "connection was incomplete");
		return FALSE;
	}

	f = fopen (path, "w");
	if (!f) {
		g_set_error (error, 0, 0, "could not open file for writing");
		return FALSE;
	}

	value = g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_GATEWAY);
	if (value && G_VALUE_HOLDS_STRING (value))
		gateway = g_value_get_string (value);
	else {
		g_set_error (error, 0, 0, "connection was incomplete (missing gateway)");
		goto done;
	}

	value = g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_ID);
	if (value && G_VALUE_HOLDS_STRING (value))
		groupname = g_value_get_string (value);
	else {
		g_set_error (error, 0, 0, "connection was incomplete (missing group)");
		goto done;
	}

	value = g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_XAUTH_USER);
	if (value && G_VALUE_HOLDS_STRING (value))
		username = g_value_get_string (value);

	value = g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_DOMAIN);
	if (value && G_VALUE_HOLDS_STRING (value))
		domain = g_value_get_string (value);

	value = g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_SINGLE_DES);
	if (value && G_VALUE_HOLDS_BOOLEAN (value) && g_value_get_boolean (value))
		singledes = TRUE;

	value = g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	if (value && G_VALUE_HOLDS_STRING (value)) {
		if (strlen (g_value_get_string (value)))
			enablenat = TRUE;
	}

	value = g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_DPD_IDLE_TIMEOUT);
	if (value && G_VALUE_HOLDS_INT (value))
		peertimeout = g_value_get_int (value);

	routes = g_string_new ("");
	if (s_ip4 && s_ip4->routes) {
		GSList *iter;

		for (iter = s_ip4->routes; iter; iter = g_slist_next (iter)) {
			NMSettingIP4Route *route = (NMSettingIP4Route *) iter->data;
			char str_addr[INET_ADDRSTRLEN + 1];
			struct in_addr num_addr;

			if (routes->len)
				g_string_append_c (routes, ' ');

			num_addr.s_addr = route->address;
			if (inet_ntop (AF_INET, &num_addr, &str_addr[0], INET_ADDRSTRLEN + 1))
				g_string_append_printf (routes, "%s/%d", str_addr, route->prefix);
		}
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
		 "ForceKeepAlives=0\n"
		 "enc_GroupPwd=\n"
		 "UserPassword=\n"
		 "enc_UserPassword=\n"
		 "NTDomain=%s\n"
		 "EnableMSLogon=0\n"
		 "MSLogonType=0\n"
		 "TunnelingMode=0\n"
		 "TcpTunnelingPort=10000\n"
		 "PeerTimeout=%d\n"
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
		 /* EnableNat */   enablenat ? "1" : "0",
		 /* NTDomain */    domain != NULL ? domain : "",
		 /* PeerTimeout */ peertimeout,
		 /* SingleDES */   singledes ? "1" : "0",
		 /* X-NM-Routes */ routes->str ? routes->str : "");

	success = TRUE;

done:
	if (routes)
		g_string_free (routes, TRUE);
	fclose (f);
	return success;
}

static char *
get_suggested_name (NMVpnPluginUiInterface *iface, NMConnection *connection)
{
	NMSettingConnection *s_con;

	g_return_val_if_fail (connection != NULL, NULL);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_return_val_if_fail (s_con != NULL, NULL);
	g_return_val_if_fail (s_con->id != NULL, NULL);

	return g_strdup_printf ("%s.pcf", s_con->id);
}

static guint32
get_capabilities (NMVpnPluginUiInterface *iface)
{
	return (NM_VPN_PLUGIN_UI_CAPABILITY_IMPORT | NM_VPN_PLUGIN_UI_CAPABILITY_EXPORT);
}

static NMVpnPluginUiWidgetInterface *
ui_factory (NMVpnPluginUiInterface *iface, NMConnection *connection, GError **error)
{
	return nm_vpn_plugin_ui_widget_interface_new (connection, error);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME:
		g_value_set_string (value, VPNC_PLUGIN_NAME);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC:
		g_value_set_string (value, VPNC_PLUGIN_DESC);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE:
		g_value_set_string (value, VPNC_PLUGIN_SERVICE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
vpnc_plugin_ui_class_init (VpncPluginUiClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	object_class->get_property = get_property;

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME,
									  NM_VPN_PLUGIN_UI_INTERFACE_NAME);

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC,
									  NM_VPN_PLUGIN_UI_INTERFACE_DESC);

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE,
									  NM_VPN_PLUGIN_UI_INTERFACE_SERVICE);
}

static void
vpnc_plugin_ui_init (VpncPluginUi *plugin)
{
}

static void
vpnc_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class)
{
	/* interface implementation */
	iface_class->ui_factory = ui_factory;
	iface_class->get_capabilities = get_capabilities;
	iface_class->import = import;
	iface_class->export = export;
	iface_class->get_suggested_name = get_suggested_name;
}


G_MODULE_EXPORT NMVpnPluginUiInterface *
nm_vpn_plugin_ui_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	return NM_VPN_PLUGIN_UI_INTERFACE (g_object_new (VPNC_TYPE_PLUGIN_UI, NULL));
}

