/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Red Hat, Inc.
 */

/**
 * SECTION:vpn-helpers
 * @short_description: VPN-related utilities
 *
 * This is copied directly from libnm-gtk and should probably
 * eventually move into libnm.
 *
 * It is also currently unused in nmtui.
 *
 * FIXME.
 */

#include "config.h"

#include <string.h>
#include <gmodule.h>

#include "nm-default.h"
#include "vpn-helpers.h"

#include "nm-macros-internal.h"

static gboolean plugins_loaded;
static GSList *plugins = NULL;

NMVpnEditorPlugin *
vpn_get_plugin_by_service (const char *service)
{
	NMVpnEditorPlugin *plugin = NULL;
	NMVpnPluginInfo *plugin_info;

	g_return_val_if_fail (service != NULL, NULL);

	if (G_UNLIKELY (!plugins_loaded))
		vpn_get_plugins ();

	plugin_info = nm_vpn_plugin_info_list_find_by_service (plugins, service);
	if (plugin_info) {
		plugin = nm_vpn_plugin_info_get_editor_plugin (plugin_info);
		if (!plugin)
			plugin = nm_vpn_plugin_info_load_editor_plugin (plugin_info, NULL);
	}
	return plugin;
}

GSList *
vpn_get_plugins ()
{
	if (G_LIKELY (plugins_loaded))
		return plugins;
	plugins_loaded = TRUE;
	plugins = nm_vpn_plugin_info_list_load ();
	return plugins;
}

#if 0
typedef struct {
	VpnImportSuccessCallback callback;
	gpointer user_data;
} ActionInfo;

static void
import_vpn_from_file_cb (GtkWidget *dialog, gint response, gpointer user_data)
{
	char *filename = NULL;
	ActionInfo *info = (ActionInfo *) user_data;
	GHashTableIter iter;
	gpointer key;
	NMVpnPluginUiInterface *plugin;
	NMConnection *connection = NULL;
	GError *error = NULL;

	if (response != GTK_RESPONSE_ACCEPT)
		goto out;

	filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
	if (!filename) {
		g_warning ("%s: didn't get a filename back from the chooser!", __func__);
		goto out;
	}

	g_hash_table_iter_init (&iter, plugins);
	while (!connection && g_hash_table_iter_next (&iter, &key, (gpointer *)&plugin)) {
		g_clear_error (&error);
		connection = nm_vpn_plugin_ui_interface_import (plugin, filename, &error);
	}

	if (connection)
		info->callback (connection, info->user_data);
	else {
		GtkWidget *err_dialog;
		char *bname = g_path_get_basename (filename);

		err_dialog = gtk_message_dialog_new (NULL,
		                                     GTK_DIALOG_DESTROY_WITH_PARENT,
		                                     GTK_MESSAGE_ERROR,
		                                     GTK_BUTTONS_OK,
		                                     _("Cannot import VPN connection"));
		gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (err_dialog),
		                                 _("The file '%s' could not be read or does not contain recognized VPN connection information\n\nError: %s."),
		                                 bname, error ? error->message : "unknown error");
		g_free (bname);
		g_signal_connect (err_dialog, "delete-event", G_CALLBACK (gtk_widget_destroy), NULL);
		g_signal_connect (err_dialog, "response", G_CALLBACK (gtk_widget_destroy), NULL);
		gtk_widget_show_all (err_dialog);
		gtk_window_present (GTK_WINDOW (err_dialog));
	}

	g_clear_error (&error);
	g_free (filename);

out:
	gtk_widget_hide (dialog);
	gtk_widget_destroy (dialog);
	g_free (info);
}

static void
destroy_import_chooser (GtkWidget *dialog, gpointer user_data)
{
	g_free (user_data);
	gtk_widget_destroy (dialog);
}

void
vpn_import (VpnImportSuccessCallback callback, gpointer user_data)
{
	GtkWidget *dialog;
	ActionInfo *info;
	const char *home_folder;

	dialog = gtk_file_chooser_dialog_new (_("Select file to import"),
	                                      NULL,
	                                      GTK_FILE_CHOOSER_ACTION_OPEN,
	                                      GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
	                                      GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
	                                      NULL);
	home_folder = g_get_home_dir ();
	gtk_file_chooser_set_current_folder (GTK_FILE_CHOOSER (dialog), home_folder);

	info = g_malloc0 (sizeof (ActionInfo));
	info->callback = callback;
	info->user_data = user_data;

	g_signal_connect (G_OBJECT (dialog), "close", G_CALLBACK (destroy_import_chooser), info);
	g_signal_connect (G_OBJECT (dialog), "response", G_CALLBACK (import_vpn_from_file_cb), info);
	gtk_widget_show_all (dialog);
	gtk_window_present (GTK_WINDOW (dialog));
}

static void
export_vpn_to_file_cb (GtkWidget *dialog, gint response, gpointer user_data)
{
	NMConnection *connection = NM_CONNECTION (user_data);
	char *filename = NULL;
	GError *error = NULL;
	NMVpnPluginUiInterface *plugin;
	NMSettingConnection *s_con = NULL;
	NMSettingVpn *s_vpn = NULL;
	const char *service_type;
	const char *id = NULL;
	gboolean success = FALSE;

	if (response != GTK_RESPONSE_ACCEPT)
		goto out;

	filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
	if (!filename) {
		g_set_error (&error, NMA_ERROR, NMA_ERROR_GENERIC, "no filename");
		goto done;
	}

	if (g_file_test (filename, G_FILE_TEST_EXISTS)) {
		int replace_response;
		GtkWidget *replace_dialog;
		char *bname;

		bname = g_path_get_basename (filename);
		replace_dialog = gtk_message_dialog_new (NULL,
		                                         GTK_DIALOG_DESTROY_WITH_PARENT,
		                                         GTK_MESSAGE_QUESTION,
		                                         GTK_BUTTONS_CANCEL,
		                                         _("A file named \"%s\" already exists."),
		                                         bname);
		gtk_dialog_add_buttons (GTK_DIALOG (replace_dialog), _("_Replace"), GTK_RESPONSE_OK, NULL);
		gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (replace_dialog),
							  _("Do you want to replace %s with the VPN connection you are saving?"), bname);
		g_free (bname);
		replace_response = gtk_dialog_run (GTK_DIALOG (replace_dialog));
		gtk_widget_destroy (replace_dialog);
		if (replace_response != GTK_RESPONSE_OK)
			goto out;
	}

	s_con = nm_connection_get_setting_connection (connection);
	id = s_con ? nm_setting_connection_get_id (s_con) : NULL;
	if (!id) {
		g_set_error (&error, NMA_ERROR, NMA_ERROR_GENERIC, "connection setting invalid");
		goto done;
	}

	s_vpn = nm_connection_get_setting_vpn (connection);
	service_type = s_vpn ? nm_setting_vpn_get_service_type (s_vpn) : NULL;

	if (!service_type) {
		g_set_error (&error, NMA_ERROR, NMA_ERROR_GENERIC, "VPN setting invalid");
		goto done;
	}

	plugin = vpn_get_plugin_by_service (service_type);
	if (plugin)
		success = nm_vpn_plugin_ui_interface_export (plugin, filename, connection, &error);

done:
	if (!success) {
		GtkWidget *err_dialog;
		char *bname = filename ? g_path_get_basename (filename) : g_strdup ("(none)");

		err_dialog = gtk_message_dialog_new (NULL,
		                                     GTK_DIALOG_DESTROY_WITH_PARENT,
		                                     GTK_MESSAGE_ERROR,
		                                     GTK_BUTTONS_OK,
		                                     _("Cannot export VPN connection"));
		gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (err_dialog),
		                                 _("The VPN connection '%s' could not be exported to %s.\n\nError: %s."),
		                                 id ? id : "(unknown)", bname, error ? error->message : "unknown error");
		g_free (bname);
		g_signal_connect (err_dialog, "delete-event", G_CALLBACK (gtk_widget_destroy), NULL);
		g_signal_connect (err_dialog, "response", G_CALLBACK (gtk_widget_destroy), NULL);
		gtk_widget_show_all (err_dialog);
		gtk_window_present (GTK_WINDOW (err_dialog));
	}

out:
	if (error)
		g_error_free (error);
	g_object_unref (connection);

	gtk_widget_hide (dialog);
	gtk_widget_destroy (dialog);
}

void
vpn_export (NMConnection *connection)
{
	GtkWidget *dialog;
	NMVpnPluginUiInterface *plugin;
	NMSettingVpn *s_vpn = NULL;
	const char *service_type;
	const char *home_folder;

	s_vpn = nm_connection_get_setting_vpn (connection);
	service_type = s_vpn ? nm_setting_vpn_get_service_type (s_vpn) : NULL;

	if (!service_type) {
		g_warning ("%s: invalid VPN connection!", __func__);
		return;
	}

	dialog = gtk_file_chooser_dialog_new (_("Export VPN connection..."),
	                                      NULL,
	                                      GTK_FILE_CHOOSER_ACTION_SAVE,
	                                      GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
	                                      GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT,
	                                      NULL);
	home_folder = g_get_home_dir ();
	gtk_file_chooser_set_current_folder (GTK_FILE_CHOOSER (dialog), home_folder);

	plugin = vpn_get_plugin_by_service (service_type);
	if (plugin) {
		char *suggested = NULL;

		suggested = nm_vpn_plugin_ui_interface_get_suggested_name (plugin, connection);
		if (suggested) {
			gtk_file_chooser_set_current_name (GTK_FILE_CHOOSER (dialog), suggested);
			g_free (suggested);
		}
	}

	g_signal_connect (G_OBJECT (dialog), "close", G_CALLBACK (gtk_widget_destroy), NULL);
	g_signal_connect (G_OBJECT (dialog), "response", G_CALLBACK (export_vpn_to_file_cb), g_object_ref (connection));
	gtk_widget_show_all (dialog);
	gtk_window_present (GTK_WINDOW (dialog));
}
#endif

gboolean
vpn_supports_ipv6 (NMConnection *connection)
{
	NMSettingVpn *s_vpn;
	const char *service_type;
	NMVpnEditorPlugin *plugin;
	guint32 capabilities;

	s_vpn = nm_connection_get_setting_vpn (connection);
	g_return_val_if_fail (s_vpn != NULL, FALSE);

	service_type = nm_setting_vpn_get_service_type (s_vpn);
	g_return_val_if_fail (service_type != NULL, FALSE);

	plugin = vpn_get_plugin_by_service (service_type);
	g_return_val_if_fail (plugin != NULL, FALSE);

	capabilities = nm_vpn_editor_plugin_get_capabilities (plugin);
	return NM_FLAGS_HAS (capabilities, NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6);
}
