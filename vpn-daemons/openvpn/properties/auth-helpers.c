/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * nm-openvpn.c : GNOME UI dialogs for configuring openvpn VPN connections
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
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
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <glib/gi18n-lib.h>

#include "auth-helpers.h"
#include "nm-openvpn.h"
#include "../src/nm-openvpn-service.h"

void
tls_pw_init_auth_widget (GladeXML *xml,
                         GtkSizeGroup *group,
                         NMSettingVPNProperties *s_vpn_props,
                         gint contype,
                         const char *prefix,
                         ChangedCallback changed_cb,
                         gpointer user_data)
{
	GtkWidget *widget;
	GValue *value;
	char *tmp;
	GtkFileFilter *filter;

	g_return_if_fail (xml != NULL);
	g_return_if_fail (group != NULL);
	g_return_if_fail (changed_cb != NULL);
	g_return_if_fail (prefix != NULL);

	tmp = g_strdup_printf ("%s_ca_cert_chooser", prefix);
	widget = glade_xml_get_widget (xml, tmp);
	g_free (tmp);

	gtk_size_group_add_widget (group, widget);
	filter = tls_file_chooser_filter_new ();
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);
	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (widget),
	                                   _("Choose a Certificate Authority certificate..."));
	g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (changed_cb), user_data);

	if (s_vpn_props && s_vpn_props->data) {
		value = g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_CA);
		if (value && G_VALUE_HOLDS_STRING (value))
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), g_value_get_string (value));
	}

	if (contype == NM_OPENVPN_CONTYPE_TLS || contype == NM_OPENVPN_CONTYPE_PASSWORD_TLS) {
		tmp = g_strdup_printf ("%s_user_cert_chooser", prefix);
		widget = glade_xml_get_widget (xml, tmp);
		g_free (tmp);

		gtk_size_group_add_widget (group, widget);
		filter = tls_file_chooser_filter_new ();
		gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);
		gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
		gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (widget),
		                                   _("Choose your personal certificate..."));
		g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (changed_cb), user_data);

		if (s_vpn_props && s_vpn_props->data) {
			value = g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_CERT);
			if (value && G_VALUE_HOLDS_STRING (value))
				gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), g_value_get_string (value));
		}

		tmp = g_strdup_printf ("%s_private_key_chooser", prefix);
		widget = glade_xml_get_widget (xml, tmp);
		g_free (tmp);

		gtk_size_group_add_widget (group, widget);
		filter = tls_file_chooser_filter_new ();
		gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);
		gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
		gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (widget),
		                                   _("Choose your private key..."));
		g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (changed_cb), user_data);

		if (s_vpn_props && s_vpn_props->data) {
			value = g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_KEY);
			if (value && G_VALUE_HOLDS_STRING (value))
				gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), g_value_get_string (value));
		}
	}

	if (contype == NM_OPENVPN_CONTYPE_PASSWORD || contype == NM_OPENVPN_CONTYPE_PASSWORD_TLS) {
		tmp = g_strdup_printf ("%s_username_entry", prefix);
		widget = glade_xml_get_widget (xml, tmp);
		g_free (tmp);

		gtk_size_group_add_widget (group, widget);
		if (s_vpn_props && s_vpn_props->data) {
			value = g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_USERNAME);
			if (value && G_VALUE_HOLDS_STRING (value))
				gtk_entry_set_text (GTK_ENTRY (widget), g_value_get_string (value));
		}
		g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);
	}
}

#define SK_DIR_COL_NAME 0
#define SK_DIR_COL_NUM  1

void
sk_init_auth_widget (GladeXML *xml,
                     GtkSizeGroup *group,
                     NMSettingVPNProperties *s_vpn_props,
                     ChangedCallback changed_cb,
                     gpointer user_data)
{
	GtkWidget *widget;
	GValue *value = NULL;
	gint sk_direction = -1;
	GtkListStore *store;
	GtkTreeIter iter;
	gint active = -1;
	gint direction = -1;
	GtkFileFilter *filter;

	g_return_if_fail (xml != NULL);
	g_return_if_fail (group != NULL);
	g_return_if_fail (changed_cb != NULL);

	widget = glade_xml_get_widget (xml, "sk_key_chooser");
	gtk_size_group_add_widget (group, widget);
	filter = sk_file_chooser_filter_new ();
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);
	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (widget),
	                                   _("Choose an OpenVPN static key..."));
	g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (changed_cb), user_data);

	if (s_vpn_props && s_vpn_props->data) {
		value = g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_SHARED_KEY);
		if (value && G_VALUE_HOLDS_STRING (value))
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), g_value_get_string (value));
	}

	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);

	if (s_vpn_props && s_vpn_props->data) {
		value = g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_SHARED_KEY_DIRECTION);
		if (value && G_VALUE_HOLDS_INT (value))
			direction = g_value_get_int (value);
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, SK_DIR_COL_NAME, _("None"), SK_DIR_COL_NUM, -1, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, SK_DIR_COL_NAME, "0", SK_DIR_COL_NUM, 0, -1);
	if (value && G_VALUE_HOLDS_INT (value)) {
		if (g_value_get_int (value) == 0)
			active = 1;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, SK_DIR_COL_NAME, "1", SK_DIR_COL_NUM, 1, -1);
	if (value && G_VALUE_HOLDS_INT (value)) {
		if (g_value_get_int (value) == 1)
			active = 2;
	}

	widget = glade_xml_get_widget (xml, "sk_direction_combo");
	gtk_size_group_add_widget (group, widget);

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);

	widget = glade_xml_get_widget (xml, "sk_dir_help_label");
	gtk_size_group_add_widget (group, widget);
}

static gboolean
validate_file_chooser (GladeXML *xml, const char *name)
{
	GtkWidget *widget;
	char *str;

	widget = glade_xml_get_widget (xml, name);
	str = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (!str || !strlen (str))
		return FALSE;
	return TRUE;
}

static gboolean
validate_tls (GladeXML *xml, const char *prefix, GError **error)
{
	char *tmp;
	gboolean valid;

	tmp = g_strdup_printf ("%s_ca_cert_chooser", prefix);
	valid = validate_file_chooser (xml, tmp);
	g_free (tmp);
	if (!valid) {
		g_set_error (error,
		             OPENVPN_PLUGIN_UI_ERROR,
		             OPENVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_OPENVPN_KEY_CA);
		return FALSE;
	}

	tmp = g_strdup_printf ("%s_user_cert_chooser", prefix);
	valid = validate_file_chooser (xml, tmp);
	g_free (tmp);
	if (!valid) {
		g_set_error (error,
		             OPENVPN_PLUGIN_UI_ERROR,
		             OPENVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_OPENVPN_KEY_CERT);
		return FALSE;
	}

	tmp = g_strdup_printf ("%s_private_key_chooser", prefix);
	valid = validate_file_chooser (xml, tmp);
	g_free (tmp);
	if (!valid) {
		g_set_error (error,
		             OPENVPN_PLUGIN_UI_ERROR,
		             OPENVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_OPENVPN_KEY_KEY);
		return FALSE;
	}

	return FALSE;
}

gboolean
auth_widget_check_validity (GladeXML *xml, gint contype, GError **error)
{
	GtkWidget *widget;
	gboolean is_valid = TRUE;
	const char *str;

	switch (contype) {
	case NM_OPENVPN_CONTYPE_TLS:
		if (!validate_tls (xml, "tls", error))
			is_valid = FALSE;
		break;

	case NM_OPENVPN_CONTYPE_PASSWORD_TLS:
		if (!validate_tls (xml, "pw_tls", error)) {
			is_valid = FALSE;
			break;
		}
		widget = glade_xml_get_widget (xml, "pw_tls_username_entry");
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (!str || !strlen (str)) {
			g_set_error (error,
			             OPENVPN_PLUGIN_UI_ERROR,
			             OPENVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_USERNAME);
			is_valid = FALSE;
		}
		break;

	case NM_OPENVPN_CONTYPE_PASSWORD:
		if (!validate_file_chooser (xml, "pw_ca_cert_chooser")) {
			g_set_error (error,
			             OPENVPN_PLUGIN_UI_ERROR,
			             OPENVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_CA);
			is_valid = FALSE;
			break;
		}
		widget = glade_xml_get_widget (xml, "pw_username_entry");
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (!str || !strlen (str)) {
			g_set_error (error,
			             OPENVPN_PLUGIN_UI_ERROR,
			             OPENVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_USERNAME);
			is_valid = FALSE;
		}
		break;

	case NM_OPENVPN_CONTYPE_STATIC_KEY:
		if (!validate_file_chooser (xml, "sk_key_chooser")) {
			g_set_error (error,
			             OPENVPN_PLUGIN_UI_ERROR,
			             OPENVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_SHARED_KEY);
			is_valid = FALSE;
			break;
		}
		break;

	default:
		g_assert_not_reached ();
	}

	return is_valid;
}

static void
update_from_filechooser (GladeXML *xml,
                         const char *key,
                         const char *prefix,
                         const char *widget_name,
                         NMSettingVPNProperties *s_vpn_props)
{
	GtkWidget *widget;
	char *tmp, *filename;

	g_return_if_fail (xml != NULL);
	g_return_if_fail (key != NULL);
	g_return_if_fail (prefix != NULL);
	g_return_if_fail (widget_name != NULL);
	g_return_if_fail (s_vpn_props != NULL);
	g_return_if_fail (s_vpn_props->data != NULL);

	tmp = g_strdup_printf ("%s_%s", prefix, widget_name);
	widget = glade_xml_get_widget (xml, tmp);
	g_free (tmp);

	filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (!filename)
		return;

	if (strlen (filename))
		g_hash_table_insert (s_vpn_props->data, g_strdup (key), str_to_gvalue (filename));
	
done:
	g_free (filename);
}

static void
update_tls (GladeXML *xml, const char *prefix, NMSettingVPNProperties *s_vpn_props)
{
	update_from_filechooser (xml, NM_OPENVPN_KEY_CA, prefix, "ca_cert_chooser", s_vpn_props);
	update_from_filechooser (xml, NM_OPENVPN_KEY_CERT, prefix, "user_cert_chooser", s_vpn_props);
	update_from_filechooser (xml, NM_OPENVPN_KEY_KEY, prefix, "private_key_chooser", s_vpn_props);
}

static void
update_username (GladeXML *xml, const char *prefix, NMSettingVPNProperties *s_vpn_props)
{
	GtkWidget *widget;
	char *tmp;
	const char *str;

	g_return_if_fail (xml != NULL);
	g_return_if_fail (prefix != NULL);
	g_return_if_fail (s_vpn_props != NULL);
	g_return_if_fail (s_vpn_props->data != NULL);

	tmp = g_strdup_printf ("%s_username_entry", prefix);
	widget = glade_xml_get_widget (xml, tmp);
	g_free (tmp);

	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str)) {
		g_hash_table_insert (s_vpn_props->data,
		                     g_strdup (NM_OPENVPN_KEY_USERNAME),
		                     str_to_gvalue (str));
	}
}

gboolean
auth_widget_update_connection (GladeXML *xml,
                               gint contype,
                               NMSettingVPNProperties *s_vpn_props)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkWidget *widget;

	switch (contype) {
	case NM_OPENVPN_CONTYPE_TLS:
		update_tls (xml, "tls", s_vpn_props);
		break;

	case NM_OPENVPN_CONTYPE_PASSWORD:
		update_from_filechooser (xml, NM_OPENVPN_KEY_CA, "pw", "ca_cert_chooser", s_vpn_props);
		update_username (xml, "pw", s_vpn_props);
		break;

	case NM_OPENVPN_CONTYPE_PASSWORD_TLS:
		update_tls (xml, "pw_tls", s_vpn_props);
		update_username (xml, "pw_tls", s_vpn_props);
		break;

	case NM_OPENVPN_CONTYPE_STATIC_KEY:
		update_from_filechooser (xml, NM_OPENVPN_KEY_SHARED_KEY, "sk", "key_chooser", s_vpn_props);
		widget = glade_xml_get_widget (xml, "sk_direction_combo");
		g_assert (widget);
		model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
		if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
			int direction = -1;

			gtk_tree_model_get (model, &iter, SK_DIR_COL_NUM, &direction, -1);
			if (direction > -1) {
				g_hash_table_insert (s_vpn_props->data,
				                     g_strdup (NM_OPENVPN_KEY_SHARED_KEY_DIRECTION),
				                     int_to_gvalue (direction));
			}
		}
		break;

	default:
		g_assert_not_reached ();
	}

	return TRUE;
}

static const char *
find_tag (const char *tag, const char *buf, gsize len)
{
	gsize i, taglen;

	taglen = strlen (tag);
	if (len < taglen)
		return NULL;

	for (i = 0; i < len - taglen; i++) {
		if (memcmp (buf + i, tag, taglen) == 0)
			return buf + i;
	}
	return NULL;
}

static const char *pem_rsa_key_begin = "-----BEGIN RSA PRIVATE KEY-----";
static const char *pem_dsa_key_begin = "-----BEGIN DSA PRIVATE KEY-----";
static const char *pem_cert_begin = "-----BEGIN CERTIFICATE-----";

static gboolean
tls_default_filter (const GtkFileFilterInfo *filter_info, gpointer data)
{
	int fd;
	unsigned char buffer[1024];
	ssize_t bytes_read;
	gboolean show = FALSE;
	char *p;
	char *ext;

	if (!filter_info->filename)
		return FALSE;

	p = strrchr (filter_info->filename, '.');
	if (!p)
		return FALSE;

	ext = g_ascii_strdown (p, -1);
	if (!ext)
		return FALSE;
	if (strcmp (ext, ".pem")) {
		g_free (ext);
		return FALSE;
	}
	g_free (ext);

	fd = open (filter_info->filename, O_RDONLY);
	if (fd < 0)
		return FALSE;

	bytes_read = read (fd, buffer, sizeof (buffer) - 1);
	if (bytes_read < 400)  /* needs to be lower? */
		goto out;
	buffer[bytes_read] = '\0';

	/* Check for PEM signatures */
	if (find_tag (pem_rsa_key_begin, (const char *) buffer, bytes_read)) {
		show = TRUE;
		goto out;
	}

	if (find_tag (pem_dsa_key_begin, (const char *) buffer, bytes_read)) {
		show = TRUE;
		goto out;
	}

	if (find_tag (pem_cert_begin, (const char *) buffer, bytes_read)) {
		show = TRUE;
		goto out;
	}

out:
	close (fd);
	return show;
}

GtkFileFilter *
tls_file_chooser_filter_new (void)
{
	GtkFileFilter *filter;

	filter = gtk_file_filter_new ();
	gtk_file_filter_add_custom (filter, GTK_FILE_FILTER_FILENAME, tls_default_filter, NULL, NULL);
	gtk_file_filter_set_name (filter, _("PEM certificates (*.pem)"));
	return filter;
}


static const char *sk_key_begin = "-----BEGIN OpenVPN Static key V1-----";

static gboolean
sk_default_filter (const GtkFileFilterInfo *filter_info, gpointer data)
{
	int fd;
	unsigned char buffer[1024];
	ssize_t bytes_read;
	gboolean show = FALSE;
	char *p;
	char *ext;

	if (!filter_info->filename)
		return FALSE;

	p = strrchr (filter_info->filename, '.');
	if (!p)
		return FALSE;

	ext = g_ascii_strdown (p, -1);
	if (!ext)
		return FALSE;
	if (strcmp (ext, ".key")) {
		g_free (ext);
		return FALSE;
	}
	g_free (ext);

	fd = open (filter_info->filename, O_RDONLY);
	if (fd < 0)
		return FALSE;

	bytes_read = read (fd, buffer, sizeof (buffer) - 1);
	if (bytes_read < 400)  /* needs to be lower? */
		goto out;
	buffer[bytes_read] = '\0';

	/* Check for PEM signatures */
	if (find_tag (sk_key_begin, (const char *) buffer, bytes_read)) {
		show = TRUE;
		goto out;
	}

out:
	close (fd);
	return show;
}

GtkFileFilter *
sk_file_chooser_filter_new (void)
{
	GtkFileFilter *filter;

	filter = gtk_file_filter_new ();
	gtk_file_filter_add_custom (filter, GTK_FILE_FILTER_FILENAME, sk_default_filter, NULL, NULL);
	gtk_file_filter_set_name (filter, _("OpenVPN Static Keys (*.key)"));
	return filter;
}

