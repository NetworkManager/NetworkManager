/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
 *
 * Dan Williams <dcbw@redhat.com>
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

#include "applet.h"
#include "vpn-password-dialog.h"
#include "nm-utils.h"

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

char *nmwa_vpn_request_password (NMWirelessApplet *applet, const char *vpn, const char *username, gboolean retry)
{
	GtkWidget	*dialog;
	char		*prompt;
	char		*password = NULL;

	g_return_val_if_fail (applet != NULL, NULL);
	g_return_val_if_fail (vpn != NULL, NULL);
	g_return_val_if_fail (username != NULL, NULL);

	/* Use the system user name, since the VPN might have a different user name */
	if (!retry && lookup_pass (vpn, g_get_user_name (), &password))
		return password;
	
	prompt = g_strdup_printf (_("You must log in to access the Virtual Private Network '%s'."), vpn);
	dialog = gnome_password_dialog_new ("", prompt, username, NULL, FALSE);
	g_free (prompt);

	gnome_password_dialog_set_show_username (GNOME_PASSWORD_DIALOG (dialog), TRUE);
	gnome_password_dialog_set_readonly_username (GNOME_PASSWORD_DIALOG (dialog), TRUE);
	gnome_password_dialog_set_show_userpass_buttons (GNOME_PASSWORD_DIALOG (dialog), FALSE);
	gnome_password_dialog_set_show_domain (GNOME_PASSWORD_DIALOG (dialog), FALSE);
	gnome_password_dialog_set_show_remember (GNOME_PASSWORD_DIALOG (dialog), TRUE);
	gtk_widget_show (dialog);

	if (gnome_password_dialog_run_and_block (GNOME_PASSWORD_DIALOG (dialog)))
	{
		password = gnome_password_dialog_get_password (GNOME_PASSWORD_DIALOG (dialog));
		switch (gnome_password_dialog_get_remember (GNOME_PASSWORD_DIALOG (dialog)))
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
	}

	gtk_widget_destroy (dialog);
	return password;
}
