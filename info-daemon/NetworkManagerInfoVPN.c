/* NetworkManagerInfo -- Manage allowed access points and provide a UI
 *                         for WEP key entry
 *
 * Colin Walters <walters@redhat.com>
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

#include <config.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <gnome-keyring.h>
#include <libgnomeui/gnome-password-dialog.h>

#ifndef _
#define _(x) dgettext (GETTEXT_PACKAGE, x)
#define N_(x) x
#endif

#include "NetworkManagerInfoDbus.h"
#include "NetworkManagerInfoVPN.h"
#include "nm-utils.h"

int nmi_vpn_init (NMIAppInfo *info)
{
	info->vpn_password_dialog = NULL;
	info->vpn_password_message = NULL;
	return 0;
}

static gboolean lookup_pass (const char *vpn, const char *username, char **password)
{
	GList *result;

	if (gnome_keyring_find_network_password_sync (username,
						      NULL,
						      vpn,
						      NULL,
						      "vpn",
						      NULL,
						      0,
						      &result) != GNOME_KEYRING_RESULT_OK)
		return FALSE;

	if (result)
	{
		GnomeKeyringNetworkPasswordData *data = result->data;
		*password = g_strdup (data->password);
		gnome_keyring_network_password_list_free (result);
		return TRUE;
	}
	return FALSE;
}

static void save_vpn_password (const char *vpn, const char *keyring, const char *username, const char *password)
{
	guint32 item_id;
	GnomeKeyringResult keyring_result;

	keyring_result = gnome_keyring_set_network_password_sync (NULL,
								  username,
								  NULL,
								  vpn,
								  NULL,
								  "vpn",
								  NULL,
								  0,
								  password,
								  &item_id);

	if (keyring_result != GNOME_KEYRING_RESULT_OK)
	{
		nm_warning ("Couldn't store password in keyring, code %d",
			(int) keyring_result);
	}
}

static void close_cb (GtkWidget *dialog, gpointer user_data)
{
	NMIAppInfo *info = user_data;
	nmi_dbus_return_vpn_password (info->connection, info->vpn_password_message, NULL);
	gtk_widget_destroy (dialog);
	info->vpn_password_dialog = NULL;
}

static void response_cb (GtkWidget *dialog, int response, gpointer user_data)
{
	NMIAppInfo *info = user_data;
	GnomePasswordDialog *passwd_dialog;
	char *password;
	const char *vpn, *username;

	if (response != GTK_RESPONSE_OK)
	{
		close_cb (dialog, user_data);
		return;
	}

	passwd_dialog = GNOME_PASSWORD_DIALOG (dialog);
	username = g_object_get_data (G_OBJECT (passwd_dialog), "NetworkManagerInfoVPN-username");
	vpn = g_object_get_data (G_OBJECT (passwd_dialog), "NetworkManagerInfoVPN-vpn");
	password = gnome_password_dialog_get_password (passwd_dialog);
	nm_warning ("returning VPN vpn_password for %s@%s: %s", username, vpn, password);
	nmi_dbus_return_vpn_password (info->connection, info->vpn_password_message, password);
	switch (gnome_password_dialog_get_remember (passwd_dialog))
	{
	case GNOME_PASSWORD_DIALOG_REMEMBER_SESSION:
		save_vpn_password (vpn, "session", username, password);
		break;
	case GNOME_PASSWORD_DIALOG_REMEMBER_FOREVER:
		save_vpn_password (vpn, NULL, username, password);
		break;
	default:
		break;
	}
  
	g_free (password);
	gtk_widget_destroy (dialog);
	info->vpn_password_dialog = NULL;
}

void nmi_vpn_request_password (NMIAppInfo *info, DBusMessage *message, const char *vpn, const char *username, gboolean retry)
{
	char *prompt;
	char *password;

	if (!username)
		username = g_get_user_name ();

	if (!retry && lookup_pass (vpn, username, &password))
	{
		nmi_dbus_return_vpn_password (info->connection, message, password);
		g_free (password);
		return;
	}
	
	prompt = g_strdup_printf (_("You must log in to access the private network %s"), vpn);

	info->vpn_password_dialog = gnome_password_dialog_new ("",
							       prompt,
							       username,
							       NULL,
							       FALSE);
	g_free (prompt);
	info->vpn_password_message = message;
	dbus_message_ref (info->vpn_password_message);
	gnome_password_dialog_set_show_username (GNOME_PASSWORD_DIALOG (info->vpn_password_dialog), TRUE);
	gnome_password_dialog_set_readonly_username (GNOME_PASSWORD_DIALOG (info->vpn_password_dialog), TRUE);
	gnome_password_dialog_set_show_userpass_buttons (GNOME_PASSWORD_DIALOG (info->vpn_password_dialog), FALSE);
	gnome_password_dialog_set_show_domain (GNOME_PASSWORD_DIALOG (info->vpn_password_dialog), FALSE);
	gnome_password_dialog_set_show_remember (GNOME_PASSWORD_DIALOG (info->vpn_password_dialog), TRUE);
	g_object_set_data_full (G_OBJECT (info->vpn_password_dialog), "NetworkManagerInfoVPN-username", g_strdup (username), (GDestroyNotify) g_free);
	g_object_set_data_full (G_OBJECT (info->vpn_password_dialog), "NetworkManagerInfoVPN-vpn", g_strdup (vpn), (GDestroyNotify) g_free);
	g_signal_connect (info->vpn_password_dialog, "response", G_CALLBACK (response_cb), info);
	g_signal_connect (info->vpn_password_dialog, "close", G_CALLBACK (close_cb), info);
	gtk_widget_show (info->vpn_password_dialog);
}

void nmi_vpn_cancel_request_password (NMIAppInfo *info)
{
	if (info->vpn_password_dialog)
	{
		gtk_widget_destroy (info->vpn_password_dialog);
		dbus_message_unref (info->vpn_password_message);
		info->vpn_password_message = NULL;
	}
}
