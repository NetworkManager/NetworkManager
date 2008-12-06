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
#include <gnome-keyring.h>
#include <gnome-keyring-memory.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "src/nm-vpnc-service.h"
#include "common-gnome/keyring-helpers.h"
#include "pcf-file.h"
#include "nm-vpnc.h"

#define VPNC_PLUGIN_NAME    _("Cisco Compatible VPN (vpnc)")
#define VPNC_PLUGIN_DESC    _("Compatible with various Cisco, Juniper, Netscreen, and Sonicwall IPSec-based VPN gateways.")
#define VPNC_PLUGIN_SERVICE NM_DBUS_SERVICE_VPNC 

#define ENC_TYPE_SECURE 0
#define ENC_TYPE_WEAK   1
#define ENC_TYPE_NONE   2

#define PW_TYPE_SAVE   0
#define PW_TYPE_ASK	   1
#define PW_TYPE_UNUSED 2

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
			/* The connection was missing invalid. */
			ENUM_ENTRY (VPNC_PLUGIN_UI_ERROR_INVALID_CONNECTION, "InvalidConnection"),
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
fill_vpn_passwords (VpncPluginUiWidget *self, NMConnection *connection)
{
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	gboolean success = FALSE;
	char *password = NULL;
	char *group_password = NULL;

	/* Grab secrets from the keyring */
	if (connection) {
		NMSettingConnection *s_con;
		NMSettingVPN *s_vpn;
		const char *tmp;

		s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

		if (nm_connection_get_scope (connection) == NM_CONNECTION_SCOPE_SYSTEM) {
			if (s_vpn) {
				tmp = nm_setting_vpn_get_secret (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD);
				if (tmp)
					password = gnome_keyring_memory_strdup (tmp);

				tmp = nm_setting_vpn_get_secret (s_vpn, NM_VPNC_KEY_SECRET);
				if (tmp)
					group_password = gnome_keyring_memory_strdup (tmp);
			}
		} else {
			s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));

			/* Lookup passwords in the keyring, and if they weren't there, try
			 * the connection itself, which is where they'd be right after import.
			 */
			keyring_helpers_get_one_secret (nm_setting_connection_get_uuid (s_con),
			                                VPNC_USER_PASSWORD,
			                                &password,
			                                NULL);
			if (!password)
				password = gnome_keyring_memory_strdup (nm_setting_vpn_get_secret (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD));

			keyring_helpers_get_one_secret (nm_setting_connection_get_uuid (s_con),
			                                VPNC_GROUP_PASSWORD,
			                                &group_password,
			                                NULL);
			if (!group_password)
				group_password = gnome_keyring_memory_strdup (nm_setting_vpn_get_secret (s_vpn, NM_VPNC_KEY_SECRET));
		}
	}

	/* User password */
	widget = glade_xml_get_widget (priv->xml, "user_password_entry");
	if (!widget)
		goto out;
	if (password)
		gtk_entry_set_text (GTK_ENTRY (widget), password);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Group password */
	widget = glade_xml_get_widget (priv->xml, "group_password_entry");
	if (!widget)
		goto out;
	if (group_password)
		gtk_entry_set_text (GTK_ENTRY (widget), group_password);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	success = TRUE;

out:
	gnome_keyring_memory_free (password);
	gnome_keyring_memory_free (group_password);

	return success;
}

static void
show_toggled_cb (GtkCheckButton *button, VpncPluginUiWidget *self)
{
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	gboolean visible;

	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button));

	widget = glade_xml_get_widget (priv->xml, "user_password_entry");
	g_assert (widget);
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);

	widget = glade_xml_get_widget (priv->xml, "group_password_entry");
	g_assert (widget);
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);
}

static void
pw_type_changed_helper (VpncPluginUiWidget *self, GtkWidget *combo)
{
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	const char *entry = NULL;
	GtkWidget *widget;
	GtkTreeModel *model;

	/* If the user chose "Not required", desensitize and clear the correct
	 * password entry.
	 */
	widget = glade_xml_get_widget (priv->xml, "user_pass_type_combo");
	if (combo == widget)
		entry = "user_password_entry";
	else {
		widget = glade_xml_get_widget (priv->xml, "group_pass_type_combo");
		if (combo == widget)
			entry = "group_password_entry";
	}
	if (!entry)
		return;

	widget = glade_xml_get_widget (priv->xml, entry);
	g_assert (widget);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (combo))) {
	case PW_TYPE_ASK:
	case PW_TYPE_UNUSED:
		gtk_entry_set_text (GTK_ENTRY (widget), "");
		gtk_widget_set_sensitive (widget, FALSE);
		break;
	default:
		gtk_widget_set_sensitive (widget, TRUE);
		break;
	}
}

static void
pw_type_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	VpncPluginUiWidget *self = VPNC_PLUGIN_UI_WIDGET (user_data);

	pw_type_changed_helper (self, combo);
	stuff_changed_cb (combo, self);
}

static void
init_one_pw_combo (VpncPluginUiWidget *self,
                   NMSettingVPN *s_vpn,
                   const char *combo_name,
                   const char *key,
                   const char *entry_name)
{
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	int active = -1;
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	const char *value = NULL;
	guint32 default_idx = 1;

	/* If there's already a password and the password type can't be found in
	 * the VPN settings, default to saving it.  Otherwise, always ask for it.
	 */
	widget = glade_xml_get_widget (priv->xml, entry_name);
	if (widget) {
		const char *tmp;

		tmp = gtk_entry_get_text (GTK_ENTRY (widget));
		if (tmp && strlen (tmp))
			default_idx = 0;
	}

	store = gtk_list_store_new (1, G_TYPE_STRING);
	if (s_vpn)
		value = nm_setting_vpn_get_data_item (s_vpn, key);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Saved"), -1);
	if ((active < 0) && value) {
		if (!strcmp (value, NM_VPNC_PW_TYPE_SAVE))
			active = 0;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Always Ask"), -1);
	if ((active < 0) && value) {
		if (!strcmp (value, NM_VPNC_PW_TYPE_ASK))
			active = 1;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Not Required"), -1);
	if ((active < 0) && value) {
		if (!strcmp (value, NM_VPNC_PW_TYPE_UNUSED))
			active = 2;
	}

	widget = glade_xml_get_widget (priv->xml, combo_name);
	g_assert (widget);
	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? default_idx : active);
	pw_type_changed_helper (self, widget);

	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (pw_type_combo_changed_cb), self);
}

static gboolean
init_plugin_ui (VpncPluginUiWidget *self, NMConnection *connection, GError **error)
{
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	const char *value = NULL;
	int active = -1;
	const char *natt_mode = NULL;

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_GATEWAY);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "group_entry");
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_ID);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "encryption_combo");
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));

	store = gtk_list_store_new (1, G_TYPE_STRING);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Secure (default)"), -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Weak (use with caution)"), -1);
	if (s_vpn && (active < 0)) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_SINGLE_DES);
		if (value && !strcmp (value, "yes"))
			active = 1;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("None (completely insecure)"), -1);
	if (s_vpn && (active < 0)) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_NO_ENCRYPTION);
		if (value && !strcmp (value, "yes"))
			active = 2;
	}

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Fill the VPN passwords *before* initializing the PW type combos, since
	 * knowing if there are passwords when initializing the combos is helpful.
	 */
	fill_vpn_passwords (self, connection);

	init_one_pw_combo (self, s_vpn, "user_pass_type_combo",
	                   NM_VPNC_KEY_XAUTH_PASSWORD_TYPE, "user_password_entry");
	init_one_pw_combo (self, s_vpn, "group_pass_type_combo",
	                   NM_VPNC_KEY_SECRET_TYPE, "group_password_entry");

	widget = glade_xml_get_widget (priv->xml, "user_entry");
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_XAUTH_USER);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "domain_entry");
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_DOMAIN);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	active = -1;
	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
	if (s_vpn)
		natt_mode = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Cisco UDP (default)"), 1, NM_VPNC_NATT_MODE_CISCO, -1);
	if ((active < 0) && natt_mode) {
		if (!strcmp (natt_mode, NM_VPNC_NATT_MODE_CISCO))
			active = 0;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("NAT-T"), 1, NM_VPNC_NATT_MODE_NATT, -1);
	if ((active < 0) && natt_mode) {
		if (!strcmp (natt_mode, NM_VPNC_NATT_MODE_NATT))
			active = 1;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Disabled"), 1, NM_VPNC_NATT_MODE_NONE, -1);
	if ((active < 0) && natt_mode) {
		if (!strcmp (natt_mode, NM_VPNC_NATT_MODE_NONE))
			active = 2;
	}

	widget = glade_xml_get_widget (priv->xml, "natt_combo");
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "disable_dpd_checkbutton");
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_DPD_IDLE_TIMEOUT);
		if (value) {
			long int tmp;

			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (tmp >= 0 && tmp <= G_MAXUINT32 && errno == 0)
				priv->orig_dpd_timeout = (guint32) tmp;

			if (priv->orig_dpd_timeout == 0)
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
		}
	}
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "show_passwords_checkbutton");
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "toggled",
	                  (GCallback) show_toggled_cb,
	                  self);

	return TRUE;
}

static GObject *
get_widget (NMVpnPluginUiWidgetInterface *iface)
{
	VpncPluginUiWidget *self = VPNC_PLUGIN_UI_WIDGET (iface);
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static guint32
handle_one_pw_type (NMSettingVPN *s_vpn, GladeXML *xml, const char *name, const char *key)
{
	GtkWidget *widget;
	GtkTreeModel *model;
	guint32 pw_type;

	widget = glade_xml_get_widget (xml, name);
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));

	pw_type = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));
	switch (pw_type) {
	case PW_TYPE_SAVE:
		nm_setting_vpn_add_data_item (s_vpn, key, NM_VPNC_PW_TYPE_SAVE);
		break;
	case PW_TYPE_UNUSED:
		nm_setting_vpn_add_data_item (s_vpn, key, NM_VPNC_PW_TYPE_UNUSED);
		break;
	case PW_TYPE_ASK:
	default:
		pw_type = PW_TYPE_ASK;
		nm_setting_vpn_add_data_item (s_vpn, key, NM_VPNC_PW_TYPE_ASK);
		break;
	}

	return pw_type;
}

static gboolean
update_connection (NMVpnPluginUiWidgetInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	VpncPluginUiWidget *self = VPNC_PLUGIN_UI_WIDGET (iface);
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	char *str;
	GtkTreeModel *model;
	GtkTreeIter iter;
	guint32 upw_type, gpw_type;

	if (!check_validity (self, error))
		return FALSE;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_VPNC, NULL);

	/* Gateway */
	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_GATEWAY, str);

	/* Group name */
	widget = glade_xml_get_widget (priv->xml, "group_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_ID, str);

	widget = glade_xml_get_widget (priv->xml, "user_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_XAUTH_USER, str);

	widget = glade_xml_get_widget (priv->xml, "domain_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DOMAIN, str);

	widget = glade_xml_get_widget (priv->xml, "encryption_combo");
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget))) {
	case ENC_TYPE_WEAK:
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_SINGLE_DES, "yes");
		break;
	case ENC_TYPE_NONE:
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_NO_ENCRYPTION, "yes");
		break;
	case ENC_TYPE_SECURE:
	default:
		break;
	}

	widget = glade_xml_get_widget (priv->xml, "natt_combo");
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		const char *mode = NULL;

		gtk_tree_model_get (model, &iter, 1, &mode, -1);
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE, mode);
	} else
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE, NM_VPNC_NATT_MODE_NATT);

	widget = glade_xml_get_widget (priv->xml, "disable_dpd_checkbutton");
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DPD_IDLE_TIMEOUT, "0");
	} else {
		/* If DPD was disabled and now the user wishes to enable it, just
		 * don't pass the DPD_IDLE_TIMEOUT option to vpnc and thus use the
		 * default DPD idle time.  Otherwise keep the original DPD idle timeout.
		 */
		if (priv->orig_dpd_timeout >= 10) {
			char *tmp = g_strdup_printf ("%d", priv->orig_dpd_timeout);
			nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DPD_IDLE_TIMEOUT, tmp);
			g_free (tmp);
		}
	}

	upw_type = handle_one_pw_type (s_vpn, priv->xml, "user_pass_type_combo", NM_VPNC_KEY_XAUTH_PASSWORD_TYPE);
	gpw_type = handle_one_pw_type (s_vpn, priv->xml, "group_pass_type_combo", NM_VPNC_KEY_SECRET_TYPE);

	/* System secrets get stored in the connection, user secrets are saved
	 * via the save_secrets() hook.
	 */
	if (nm_connection_get_scope (connection) == NM_CONNECTION_SCOPE_SYSTEM) {
		/* User password */
		widget = glade_xml_get_widget (priv->xml, "user_password_entry");
		str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
		if (str && strlen (str) && (upw_type != PW_TYPE_UNUSED))
			nm_setting_vpn_add_secret (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD, str);

		/* Group password */
		widget = glade_xml_get_widget (priv->xml, "group_password_entry");
		str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
		if (str && strlen (str) && (gpw_type != PW_TYPE_UNUSED))
			nm_setting_vpn_add_secret (s_vpn, NM_VPNC_KEY_SECRET, str);
	}

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	return TRUE;
}

static void
save_one_password (GladeXML *xml,
                   const char *keyring_tag,
                   const char *uuid,
                   const char *id,
                   const char *entry,
                   const char *combo,
                   const char *desc)
{
	GnomeKeyringResult ret;
	GtkWidget *widget;
	const char *password;
	GtkTreeModel *model;
	gboolean saved = FALSE;

	widget = glade_xml_get_widget (xml, combo);
	g_assert (widget);
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active (GTK_COMBO_BOX (widget)) == PW_TYPE_SAVE) {
		widget = glade_xml_get_widget (xml, entry);
		g_assert (widget);
		password = gtk_entry_get_text (GTK_ENTRY (widget));
		if (password && strlen (password)) {
			ret = keyring_helpers_save_secret (uuid, id, NULL, keyring_tag, password);
			if (ret == GNOME_KEYRING_RESULT_OK)
				saved = TRUE;
			else
				g_warning ("%s: failed to save %s to keyring.", __func__, desc);
		}
	}

	if (!saved)
		keyring_helpers_delete_secret (uuid, keyring_tag);
}

static gboolean
save_secrets (NMVpnPluginUiWidgetInterface *iface,
              NMConnection *connection,
              GError **error)
{
	VpncPluginUiWidget *self = VPNC_PLUGIN_UI_WIDGET (iface);
	VpncPluginUiWidgetPrivate *priv = VPNC_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	const char *str, *id, *uuid;

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	if (!s_con) {
		g_set_error (error,
		             VPNC_PLUGIN_UI_ERROR,
		             VPNC_PLUGIN_UI_ERROR_INVALID_CONNECTION,
		             "missing 'connection' setting");
		return FALSE;
	}

	id = nm_setting_connection_get_id (s_con);
	uuid = nm_setting_connection_get_uuid (s_con);

	save_one_password (priv->xml, VPNC_USER_PASSWORD, uuid, id,
	                   "user_password_entry", "user_pass_type_combo", "user password");
	save_one_password (priv->xml, VPNC_GROUP_PASSWORD, uuid, id,
	                   "group_password_entry", "group_pass_type_combo", "group password");

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
	iface_class->save_secrets = save_secrets;
}

static void
add_routes (NMSettingIP4Config *s_ip4, const char *routelist)
{
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
			NMIP4Route *route = nm_ip4_route_new ();

			nm_ip4_route_set_dest (route, tmp.s_addr);
			nm_ip4_route_set_prefix (route, (guint32) prefix);

			nm_setting_ip4_config_add_route (s_ip4, route);
		} else
			g_warning ("Ignoring invalid route '%s'", str_route);

next:
		g_free (str_route);
	}

	g_strfreev (substrs);
}

static void
decrypt_child_finished_cb (GPid pid, gint status, gpointer userdata)
{
	int *child_status = (gint *) userdata;

	*child_status = status;
}

static gboolean
child_stdout_data_cb (GIOChannel *source, GIOCondition condition, gpointer userdata)
{
	char *str;
	char **output = (char **) userdata;

	if (*output || !(condition & (G_IO_IN | G_IO_ERR)))
		return TRUE;

	if (g_io_channel_read_line (source, &str, NULL, NULL, NULL) == G_IO_STATUS_NORMAL) {
		int len;

		len = strlen (str);
		if (len > 0) {
			/* remove terminating newline */
			*output = g_strchomp (str);
		} else
			g_free (str);
	}
	return TRUE;
}

static char *
decrypt_cisco_key (const char* enc_key)
{
	int child_stdout, child_status;
	GPid child_pid;
	guint32 ioid;
	char *key = NULL;
	GIOChannel *channel;
	const char **decrypt_path;
	GError *error = NULL;

	const char *decrypt_possible_paths[] = {
		"/usr/lib/vpnc/cisco-decrypt",
		"/usr/bin/cisco-decrypt",
		NULL
	};

	const char *argv[] = {
		NULL, /* The path we figure out later. */
		enc_key, /* The key in encrypted form */
		NULL
	};

	/* Find the binary. */
	decrypt_path = decrypt_possible_paths;
	while (*decrypt_path != NULL){
		if (g_file_test (*decrypt_path, G_FILE_TEST_EXISTS))
			break;
		++decrypt_path;
	}

	if (*decrypt_path == NULL){
		g_warning ("Couldn't find cisco-decrypt.\n");
		return NULL;
	}

	/* Now that we know where it is, we call the decrypter. */
	argv[0] = *decrypt_path;
	child_status = -1;

	if (!g_spawn_async_with_pipes ("/", /* working directory */
	                               (gchar **) argv, /* argv */
	                               NULL , /* envp */
	                               G_SPAWN_DO_NOT_REAP_CHILD, /* flags */
	                               NULL, /* child setup */
	                               NULL, /* user data */
	                               &child_pid, /* child pid */
	                               NULL, /* child stdin */
	                               &child_stdout, /* child stdout */
	                               NULL, /* child stderr */
	                               &error)) { /* error */
		/* The child did not spawn */
		g_warning ("Error processing password: %s", error ? error->message : "(none)");
		if (error)
			g_error_free (error);
		return NULL;
	}

	g_child_watch_add (child_pid, decrypt_child_finished_cb, (gpointer) &child_status);

	/* Grab child output and wait for it to exit */
	channel = g_io_channel_unix_new (child_stdout);
	g_io_channel_set_encoding (channel, NULL, NULL);
	ioid = g_io_add_watch (channel, G_IO_IN | G_IO_ERR, child_stdout_data_cb, &key);

	while (child_status == -1) /* Wait until the child has finished. */
		g_main_context_iteration (NULL, TRUE);

	g_source_remove (ioid);
	g_io_channel_shutdown (channel, TRUE, NULL);
	g_io_channel_unref (channel);

	return key;
}

static NMConnection *
import (NMVpnPluginUiInterface *iface, const char *path, GError **error)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
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
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_VPNC, NULL);
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	/* Connection name */
	if ((buf = pcf_file_lookup_value (pcf, "main", "Description")))
		g_object_set (s_con, NM_SETTING_CONNECTION_ID, buf, NULL);
	else {
		g_set_error (error, 0, 0, "does not look like a %s VPN connection (parse failed)",
		             VPNC_PLUGIN_NAME);
		g_object_unref (connection);
		return NULL;
	}

	/* Gateway */
	if ((buf = pcf_file_lookup_value (pcf, "main", "Host")))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_GATEWAY, buf);
	else {
		g_set_error (error, 0, 0, "does not look like a %s VPN connection (no Host)",
		             VPNC_PLUGIN_NAME);
		g_object_unref (connection);
		return NULL;
	}

	/* Group name */
	if ((buf = pcf_file_lookup_value (pcf, "main", "GroupName")))
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_ID, buf);
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
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_XAUTH_USER, buf);

	buf = pcf_file_lookup_value (pcf, "main", "UserPassword");
	have_value = buf == NULL ? FALSE : strlen (buf) > 0;
	if (have_value)
		nm_setting_vpn_add_secret (s_vpn, NM_VPNC_KEY_XAUTH_PASSWORD, buf);

	buf = pcf_file_lookup_value (pcf, "main", "GroupPwd");
	have_value = buf == NULL ? FALSE : strlen (buf) > 0;
	if (have_value)
		nm_setting_vpn_add_secret (s_vpn, NM_VPNC_KEY_SECRET, buf);
	else {
		/* Handle encrypted passwords */
		buf = pcf_file_lookup_value (pcf, "main", "enc_GroupPwd");
		have_value = buf == NULL ? FALSE : strlen (buf) > 0;
		if (have_value) {
			char *decrypted;

			decrypted = decrypt_cisco_key (buf);
			if (decrypted) {
				nm_setting_vpn_add_secret (s_vpn, NM_VPNC_KEY_SECRET, decrypted);
				memset (decrypted, 0, strlen (decrypted));
				g_free (decrypted);
			}
		}
	}

	buf = pcf_file_lookup_value (pcf, "main", "NTDomain");
	have_value = buf == NULL ? FALSE : strlen (buf) > 0;
	if (have_value)
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DOMAIN, buf);

	buf = pcf_file_lookup_value (pcf, "main", "SingleDES");
	have_value = (buf == NULL ? FALSE : strcmp (buf, "0") != 0);
	if (have_value)
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_SINGLE_DES, "yes");

	/* Default is enabled, only disabled if explicit EnableNat=0 exists */
	buf = pcf_file_lookup_value (pcf, "main", "EnableNat");
	have_value = (buf ? strncmp (buf, "0", 1) == 0 : FALSE);
	if (have_value)
		nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE, NM_VPNC_NATT_MODE_NATT);

	if ((buf = pcf_file_lookup_value (pcf, "main", "PeerTimeout"))) {
		long int val;

		errno = 0;
		val = strtol (buf, NULL, 10);
		if ((errno == 0) && ((val == 0) || ((val >= 10) && (val <= 86400)))) {
			char *tmp = g_strdup_printf ("%d", (gint) val);
			nm_setting_vpn_add_data_item (s_vpn, NM_VPNC_KEY_DPD_IDLE_TIMEOUT, tmp);
			g_free (tmp);
		}
	}

	buf = pcf_file_lookup_value (pcf, "main", "X-NM-Routes");
	have_value = buf == NULL ? FALSE : strlen (buf) > 0;
	if (have_value) {
		NMSettingIP4Config *s_ip4;

		s_ip4 = NM_SETTING_IP4_CONFIG (nm_setting_ip4_config_new ());
		nm_connection_add_setting (connection, NM_SETTING (s_ip4));
		add_routes (s_ip4, buf);
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
	NMSettingIP4Config *s_ip4;
	NMSettingVPN *s_vpn;
	FILE *f;
	const char *value;
	const char *gateway = NULL;
	gboolean enablenat = TRUE;
	gboolean singledes = FALSE;
	const char *groupname = NULL;
	const char *username = NULL;
	const char *domain = NULL;
	const char *peertimeout = NULL;
	GString *routes = NULL;
	gboolean success = FALSE;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	f = fopen (path, "w");
	if (!f) {
		g_set_error (error, 0, 0, "could not open file for writing");
		return FALSE;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_GATEWAY);
	if (value && strlen (value))
		gateway = value;
	else {
		g_set_error (error, 0, 0, "connection was incomplete (missing gateway)");
		goto done;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_ID);
	if (value && strlen (value))
		groupname = value;
	else {
		g_set_error (error, 0, 0, "connection was incomplete (missing group)");
		goto done;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_XAUTH_USER);
	if (value && strlen (value))
		username = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_DOMAIN);
	if (value && strlen (value))
		domain =  value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_SINGLE_DES);
	if (value && !strcmp (value, "yes"))
		singledes = TRUE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	if (value && strlen (value) && strcmp (value, NM_VPNC_NATT_MODE_NONE))
		enablenat = TRUE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_VPNC_KEY_DPD_IDLE_TIMEOUT);
	if (value && strlen (value))
		peertimeout = value;

	routes = g_string_new ("");
	if (s_ip4 && nm_setting_ip4_config_get_num_routes (s_ip4)) {
		int i;

		for (i = 0; i < nm_setting_ip4_config_get_num_routes (s_ip4); i++) {
			NMIP4Route *route = nm_setting_ip4_config_get_route (s_ip4, i);
			char str_addr[INET_ADDRSTRLEN + 1];
			struct in_addr num_addr;

			if (routes->len)
				g_string_append_c (routes, ' ');

			num_addr.s_addr = nm_ip4_route_get_dest (route);
			if (inet_ntop (AF_INET, &num_addr, &str_addr[0], INET_ADDRSTRLEN + 1))
				g_string_append_printf (routes, "%s/%d", str_addr, nm_ip4_route_get_prefix (route));
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
		 "PeerTimeout=%s\n"
		 "EnableLocalLAN=1\n"
		 "SendCertChain=0\n"
		 "VerifyCertDN=\n"
		 "EnableSplitDNS=1\n"
		 "SingleDES=%s\n"
		 "SPPhonebook=\n"
		 "%s",
		 /* Description */ nm_setting_connection_get_id (s_con),
		 /* Host */        gateway,
		 /* GroupName */   groupname,
		 /* Username */    username != NULL ? username : "",
		 /* EnableNat */   enablenat ? "1" : "0",
		 /* NTDomain */    domain != NULL ? domain : "",
		 /* PeerTimeout */ peertimeout != NULL ? peertimeout : "0",
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
	const char *id;

	g_return_val_if_fail (connection != NULL, NULL);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_return_val_if_fail (s_con != NULL, NULL);

	id = nm_setting_connection_get_id (s_con);
	g_return_val_if_fail (id != NULL, NULL);

	return g_strdup_printf ("%s.pcf", id);
}

static guint32
get_capabilities (NMVpnPluginUiInterface *iface)
{
	return (NM_VPN_PLUGIN_UI_CAPABILITY_IMPORT | NM_VPN_PLUGIN_UI_CAPABILITY_EXPORT);
}

static gboolean
delete_connection (NMVpnPluginUiInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	NMSettingConnection *s_con;
	const char *id, *uuid;

	/* Remove any secrets in the keyring associated with this connection's UUID */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	if (!s_con) {
		g_set_error (error,
		             VPNC_PLUGIN_UI_ERROR,
		             VPNC_PLUGIN_UI_ERROR_INVALID_CONNECTION,
		             "missing 'connection' setting");
		return FALSE;
	}

	id = nm_setting_connection_get_id (s_con);
	uuid = nm_setting_connection_get_uuid (s_con);

	if (!keyring_helpers_delete_secret (uuid, VPNC_USER_PASSWORD))
		g_message ("%s: couldn't delete user password for '%s'", __func__, id);

	if (!keyring_helpers_delete_secret (uuid, VPNC_GROUP_PASSWORD))
		g_message ("%s: couldn't delete group password for '%s'", __func__, id);

	return TRUE;
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
	iface_class->delete_connection = delete_connection;
}


G_MODULE_EXPORT NMVpnPluginUiInterface *
nm_vpn_plugin_ui_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	return NM_VPN_PLUGIN_UI_INTERFACE (g_object_new (VPNC_TYPE_PLUGIN_UI, NULL));
}

