/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * CVSID: $Id$
 *
 * nm-openvpn.c : GNOME UI dialogs for configuring openvpn VPN connections
 *
 * Copyright (C) 2005 Tim Niemueller <tim@niemueller.de>
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
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
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "../src/nm-openvpn-service.h"
#include "nm-openvpn.h"
#include "auth-helpers.h"
#include "import-export.h"

#define OPENVPN_PLUGIN_NAME    _("OpenVPN")
#define OPENVPN_PLUGIN_DESC    _("Compatible with the OpenVPN server.")
#define OPENVPN_PLUGIN_SERVICE NM_DBUS_SERVICE_OPENVPN 


/************** plugin class **************/

static void openvpn_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (OpenvpnPluginUi, openvpn_plugin_ui, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_INTERFACE,
											   openvpn_plugin_ui_interface_init))

/************** UI widget class **************/

static void openvpn_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (OpenvpnPluginUiWidget, openvpn_plugin_ui_widget, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_WIDGET_INTERFACE,
											   openvpn_plugin_ui_widget_interface_init))

#define OPENVPN_PLUGIN_UI_WIDGET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), OPENVPN_TYPE_PLUGIN_UI_WIDGET, OpenvpnPluginUiWidgetPrivate))

typedef struct {
	GladeXML *xml;
	GtkWidget *widget;
	GtkSizeGroup *group;
	GtkWindowGroup *window_group;
	gboolean window_added;
	GHashTable *advanced;
} OpenvpnPluginUiWidgetPrivate;


#define COL_AUTH_NAME 0
#define COL_AUTH_PAGE 1
#define COL_AUTH_TYPE 2

GQuark
openvpn_plugin_ui_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("openvpn-plugin-ui-error-quark");

	return error_quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
openvpn_plugin_ui_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (OPENVPN_PLUGIN_UI_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (OPENVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (OPENVPN_PLUGIN_UI_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The file to import could not be read. */
			ENUM_ENTRY (OPENVPN_PLUGIN_UI_ERROR_FILE_NOT_READABLE, "FileNotReadable"),
			/* The file to import could was not an OpenVPN client file. */
			ENUM_ENTRY (OPENVPN_PLUGIN_UI_ERROR_FILE_NOT_OPENVPN, "FileNotOpenVPN"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("OpenvpnPluginUiError", values);
	}
	return etype;
}

static gboolean
check_validity (OpenvpnPluginUiWidget *self, GError **error)
{
	OpenvpnPluginUiWidgetPrivate *priv = OPENVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *str;
	GtkTreeModel *model;
	GtkTreeIter iter;
	const char *contype = NULL;

	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             OPENVPN_PLUGIN_UI_ERROR,
		             OPENVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_OPENVPN_KEY_REMOTE);
		return FALSE;
	}

	widget = glade_xml_get_widget (priv->xml, "auth_combo");
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	g_assert (model);
	g_assert (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter));

	gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &contype, -1);
	if (!auth_widget_check_validity (priv->xml, contype, error))
		return FALSE;

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (OPENVPN_PLUGIN_UI_WIDGET (user_data), "changed");
}

static void
auth_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	OpenvpnPluginUiWidget *self = OPENVPN_PLUGIN_UI_WIDGET (user_data);
	OpenvpnPluginUiWidgetPrivate *priv = OPENVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *auth_notebook;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gint new_page = 0;

	auth_notebook = glade_xml_get_widget (priv->xml, "auth_notebook");
	g_assert (auth_notebook);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));
	g_assert (model);
	g_assert (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter));

	gtk_tree_model_get (model, &iter, COL_AUTH_PAGE, &new_page, -1);
	gtk_notebook_set_current_page (GTK_NOTEBOOK (auth_notebook), new_page);

	stuff_changed_cb (combo, self);
}

static void
advanced_dialog_close_cb (GtkWidget *dialog, gpointer user_data)
{
	gtk_widget_hide (dialog);
	/* gtk_widget_destroy() will remove the window from the window group */
	gtk_widget_destroy (dialog);
}

static void
advanced_dialog_response_cb (GtkWidget *dialog, gint response, gpointer user_data)
{
	OpenvpnPluginUiWidget *self = OPENVPN_PLUGIN_UI_WIDGET (user_data);
	OpenvpnPluginUiWidgetPrivate *priv = OPENVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GError *error = NULL;

	if (response != GTK_RESPONSE_OK) {
		advanced_dialog_close_cb (dialog, self);
		return;
	}

	if (priv->advanced)
		g_hash_table_destroy (priv->advanced);
	priv->advanced = advanced_dialog_new_hash_from_dialog (dialog, &error);
	if (!priv->advanced) {
		g_message ("%s: error reading advanced settings: %s", __func__, error->message);
		g_error_free (error);
	}
	advanced_dialog_close_cb (dialog, self);

	stuff_changed_cb (NULL, self);
}

static void
advanced_button_clicked_cb (GtkWidget *button, gpointer user_data)
{
	OpenvpnPluginUiWidget *self = OPENVPN_PLUGIN_UI_WIDGET (user_data);
	OpenvpnPluginUiWidgetPrivate *priv = OPENVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *dialog, *toplevel, *widget;
	GtkTreeModel *model;
	GtkTreeIter iter;
	const char *contype = NULL;

	toplevel = gtk_widget_get_toplevel (priv->widget);
	g_return_if_fail (GTK_WIDGET_TOPLEVEL (toplevel));

	widget = glade_xml_get_widget (priv->xml, "auth_combo");
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter))
		gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &contype, -1);

	dialog = advanced_dialog_new (priv->advanced, contype);
	if (!dialog) {
		g_warning ("%s: failed to create the Advanced dialog!", __func__);
		return;
	}

	gtk_window_group_add_window (priv->window_group, GTK_WINDOW (dialog));
	if (!priv->window_added) {
		gtk_window_group_add_window (priv->window_group, GTK_WINDOW (toplevel));
		priv->window_added = TRUE;
	}

	gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (toplevel));
	g_signal_connect (G_OBJECT (dialog), "response", G_CALLBACK (advanced_dialog_response_cb), self);
	g_signal_connect (G_OBJECT (dialog), "close", G_CALLBACK (advanced_dialog_close_cb), self);

	gtk_widget_show_all (dialog);
}

static gboolean
init_plugin_ui (OpenvpnPluginUiWidget *self, NMConnection *connection, GError **error)
{
	OpenvpnPluginUiWidgetPrivate *priv = OPENVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	int active = -1;
	const char *value;
	const char *contype = NM_OPENVPN_CONTYPE_TLS;

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = g_hash_table_lookup (s_vpn->data, NM_OPENVPN_KEY_REMOTE);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "auth_combo");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);

	store = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);

	if (s_vpn && s_vpn->data) {
		contype = g_hash_table_lookup (s_vpn->data, NM_OPENVPN_KEY_CONNECTION_TYPE);
		if (contype) {
			if (   strcmp (contype, NM_OPENVPN_CONTYPE_TLS)
			    && strcmp (contype, NM_OPENVPN_CONTYPE_STATIC_KEY)
			    && strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD)
			    && strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS))
				contype = NM_OPENVPN_CONTYPE_TLS;
		} else
			contype = NM_OPENVPN_CONTYPE_TLS;
	}

	/* TLS auth widget */
	tls_pw_init_auth_widget (priv->xml, priv->group, s_vpn,
	                         NM_OPENVPN_CONTYPE_TLS, "tls",
	                         stuff_changed_cb, self);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Certificates (TLS)"),
	                    COL_AUTH_PAGE, 0,
	                    COL_AUTH_TYPE, NM_OPENVPN_CONTYPE_TLS,
	                    -1);

	/* Password auth widget */
	tls_pw_init_auth_widget (priv->xml, priv->group, s_vpn,
	                         NM_OPENVPN_CONTYPE_PASSWORD, "pw",
	                         stuff_changed_cb, self);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Password"),
	                    COL_AUTH_PAGE, 1,
	                    COL_AUTH_TYPE, NM_OPENVPN_CONTYPE_PASSWORD,
	                    -1);
	if ((active < 0) && !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD))
		active = 1;

	/* Password+TLS auth widget */
	tls_pw_init_auth_widget (priv->xml, priv->group, s_vpn,
	                         NM_OPENVPN_CONTYPE_PASSWORD_TLS, "pw_tls",
	                         stuff_changed_cb, self);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Password with Certificates (TLS)"),
	                    COL_AUTH_PAGE, 2,
	                    COL_AUTH_TYPE, NM_OPENVPN_CONTYPE_PASSWORD_TLS,
	                    -1);
	if ((active < 0) && !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS))
		active = 2;

	/* Static key auth widget */
	sk_init_auth_widget (priv->xml, priv->group, s_vpn, stuff_changed_cb, self);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Static Key"),
	                    COL_AUTH_PAGE, 3,
	                    COL_AUTH_TYPE, NM_OPENVPN_CONTYPE_STATIC_KEY,
	                    -1);
	if ((active < 0) && !strcmp (contype, NM_OPENVPN_CONTYPE_STATIC_KEY))
		active = 3;

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	g_signal_connect (widget, "changed", G_CALLBACK (auth_combo_changed_cb), self);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);

	widget = glade_xml_get_widget (priv->xml, "advanced_button");
	g_signal_connect (G_OBJECT (widget), "clicked", G_CALLBACK (advanced_button_clicked_cb), self);

	return TRUE;
}

static GObject *
get_widget (NMVpnPluginUiWidgetInterface *iface)
{
	OpenvpnPluginUiWidget *self = OPENVPN_PLUGIN_UI_WIDGET (iface);
	OpenvpnPluginUiWidgetPrivate *priv = OPENVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static void
hash_copy_advanced (gpointer key, gpointer data, gpointer user_data)
{
	GHashTable *hash = (GHashTable *) user_data;
	const char *value = (const char *) data;

	g_hash_table_insert (hash, g_strdup ((const char *) key), g_strdup (value));
}

static gboolean
update_connection (NMVpnPluginUiWidgetInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	OpenvpnPluginUiWidget *self = OPENVPN_PLUGIN_UI_WIDGET (iface);
	OpenvpnPluginUiWidgetPrivate *priv = OPENVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	char *str;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gboolean valid = FALSE;
	const char *auth_type = NULL;

	if (!check_validity (self, error))
		return FALSE;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	s_vpn->service_type = g_strdup (NM_DBUS_SERVICE_OPENVPN);

	/* Gateway */
	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str)) {
		g_hash_table_insert (s_vpn->data,
		                     g_strdup (NM_OPENVPN_KEY_REMOTE),
		                     g_strdup (str));
	}

	widget = glade_xml_get_widget (priv->xml, "auth_combo");
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &auth_type, -1);
		g_hash_table_insert (s_vpn->data,
		                     g_strdup (NM_OPENVPN_KEY_CONNECTION_TYPE),
		                     g_strdup (auth_type));
		auth_widget_update_connection (priv->xml, auth_type, s_vpn);
	}

	if (priv->advanced)
		g_hash_table_foreach (priv->advanced, hash_copy_advanced, s_vpn->data);

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	valid = TRUE;

done:
	return valid;
}

static NMVpnPluginUiWidgetInterface *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
	NMVpnPluginUiWidgetInterface *object;
	OpenvpnPluginUiWidgetPrivate *priv;
	char *glade_file;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = NM_VPN_PLUGIN_UI_WIDGET_INTERFACE (g_object_new (OPENVPN_TYPE_PLUGIN_UI_WIDGET, NULL));
	if (!object) {
		g_set_error (error, OPENVPN_PLUGIN_UI_ERROR, 0, "could not create openvpn object");
		return NULL;
	}

	priv = OPENVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (object);

	glade_file = g_strdup_printf ("%s/%s", GLADEDIR, "nm-openvpn-dialog.glade");
	priv->xml = glade_xml_new (glade_file, "openvpn-vbox", GETTEXT_PACKAGE);
	if (priv->xml == NULL) {
		g_set_error (error, OPENVPN_PLUGIN_UI_ERROR, 0,
		             "could not load required resources at %s", glade_file);
		g_free (glade_file);
		g_object_unref (object);
		return NULL;
	}
	g_free (glade_file);

	priv->widget = glade_xml_get_widget (priv->xml, "openvpn-vbox");
	if (!priv->widget) {
		g_set_error (error, OPENVPN_PLUGIN_UI_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	priv->window_group = gtk_window_group_new ();

	if (!init_plugin_ui (OPENVPN_PLUGIN_UI_WIDGET (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	priv->advanced = advanced_dialog_new_hash_from_connection (connection, error);
	if (!priv->advanced) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	OpenvpnPluginUiWidget *plugin = OPENVPN_PLUGIN_UI_WIDGET (object);
	OpenvpnPluginUiWidgetPrivate *priv = OPENVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (plugin);

	if (priv->group)
		g_object_unref (priv->group);

	if (priv->window_group)
		g_object_unref (priv->window_group);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->xml)
		g_object_unref (priv->xml);

	if (priv->advanced)
		g_hash_table_destroy (priv->advanced);

	G_OBJECT_CLASS (openvpn_plugin_ui_widget_parent_class)->dispose (object);
}

static void
openvpn_plugin_ui_widget_class_init (OpenvpnPluginUiWidgetClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (OpenvpnPluginUiWidgetPrivate));

	object_class->dispose = dispose;
}

static void
openvpn_plugin_ui_widget_init (OpenvpnPluginUiWidget *plugin)
{
}

static void
openvpn_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

static NMConnection *
import (NMVpnPluginUiInterface *iface, const char *path, GError **error)
{
	NMConnection *connection = NULL;
	char *contents = NULL;
	char **lines = NULL;
	char *ext;

	ext = strrchr (path, '.');
	if (!ext) {
		g_set_error (error,
		             OPENVPN_PLUGIN_UI_ERROR,
		             OPENVPN_PLUGIN_UI_ERROR_FILE_NOT_OPENVPN,
		             "unknown OpenVPN file extension");
		goto out;
	}

	if (strcmp (ext, ".ovpn") && strcmp (ext, ".conf") && strcmp (ext, ".cnf")) {
		g_set_error (error,
		             OPENVPN_PLUGIN_UI_ERROR,
		             OPENVPN_PLUGIN_UI_ERROR_FILE_NOT_OPENVPN,
		             "unknown OpenVPN file extension");
		goto out;
	}

	if (!g_file_get_contents (path, &contents, NULL, error))
		return NULL;

	lines = g_strsplit_set (contents, "\r\n", 0);
	if (g_strv_length (lines) <= 1) {
		g_set_error (error,
		             OPENVPN_PLUGIN_UI_ERROR,
		             OPENVPN_PLUGIN_UI_ERROR_FILE_NOT_READABLE,
		             "not a valid OpenVPN configuration file");
		goto out;
	}

	connection = do_import (path, lines, error);

out:
	if (lines)
		g_strfreev (lines);
	g_free (contents);
	return connection;
}

static gboolean
export (NMVpnPluginUiInterface *iface,
        const char *path,
        NMConnection *connection,
        GError **error)
{
	return do_export (path, connection, error);
}

static char *
get_suggested_name (NMVpnPluginUiInterface *iface, NMConnection *connection)
{
	NMSettingConnection *s_con;

	g_return_val_if_fail (connection != NULL, NULL);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_return_val_if_fail (s_con != NULL, NULL);
	g_return_val_if_fail (s_con->id != NULL, NULL);

	return g_strdup_printf ("%s (openvpn).conf", s_con->id);
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
		g_value_set_string (value, OPENVPN_PLUGIN_NAME);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC:
		g_value_set_string (value, OPENVPN_PLUGIN_DESC);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE:
		g_value_set_string (value, OPENVPN_PLUGIN_SERVICE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
openvpn_plugin_ui_class_init (OpenvpnPluginUiClass *req_class)
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
openvpn_plugin_ui_init (OpenvpnPluginUi *plugin)
{
}

static void
openvpn_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class)
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

	return NM_VPN_PLUGIN_UI_INTERFACE (g_object_new (OPENVPN_TYPE_PLUGIN_UI, NULL));
}

