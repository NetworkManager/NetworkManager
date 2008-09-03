/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2004 - 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <gnome-keyring.h>
#include <gnome-keyring-memory.h>

#include <nm-setting-vpn.h>

#include "common-gnome/keyring-helpers.h"
#include "src/nm-vpnc-service.h"
#include "gnome-two-password-dialog.h"

#define KEYRING_UUID_TAG "connection-uuid"
#define KEYRING_SN_TAG "setting-name"
#define KEYRING_SK_TAG "setting-key"

static gboolean
get_secrets (const char *vpn_uuid,
             const char *vpn_name,
             const char *vpn_service,
             gboolean retry,
             char **password,
             char **group_password)
{
	GnomeTwoPasswordDialog *dialog;
	gboolean is_session = TRUE;
	gboolean found;
	char *prompt;

	g_return_val_if_fail (vpn_uuid != NULL, FALSE);
	g_return_val_if_fail (vpn_name != NULL, FALSE);
	g_return_val_if_fail (password != NULL, FALSE);
	g_return_val_if_fail (*password == NULL, FALSE);
	g_return_val_if_fail (group_password != NULL, FALSE);
	g_return_val_if_fail (*group_password == NULL, FALSE);

	found = keyring_helpers_lookup_secrets (vpn_uuid, password, group_password, &is_session);
	if (!retry && found && *password && *group_password)
		return TRUE;

	prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network '%s'."), vpn_name);
	dialog = GNOME_TWO_PASSWORD_DIALOG (gnome_two_password_dialog_new (_("Authenticate VPN"), prompt, NULL, NULL, FALSE));
	g_free (prompt);

	gnome_two_password_dialog_set_show_username (dialog, FALSE);
	gnome_two_password_dialog_set_show_userpass_buttons (dialog, FALSE);
	gnome_two_password_dialog_set_show_domain (dialog, FALSE);
	gnome_two_password_dialog_set_show_remember (dialog, TRUE);
	gnome_two_password_dialog_set_password_secondary_label (dialog, _("_Group Password:"));

	/* If nothing was found in the keyring, default to not remembering any secrets */
	if (found) {
		/* Otherwise set default remember based on which keyring the secrets were found in */
		if (is_session)
			gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION);
		else
			gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER);
	} else
		gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_NOTHING);

	/* if retrying, pre-fill dialog with the password */
	if (*password) {
		gnome_two_password_dialog_set_password (dialog, *password);
		gnome_keyring_memory_free (*password);
		*password = NULL;
	}
	if (*group_password) {
		gnome_two_password_dialog_set_password_secondary (dialog, *group_password);
		gnome_keyring_memory_free (*group_password);
		*group_password = NULL;
	}

	gtk_widget_show (GTK_WIDGET (dialog));

	if (gnome_two_password_dialog_run_and_block (dialog)) {
		*password = gnome_two_password_dialog_get_password (dialog);
		*group_password = gnome_two_password_dialog_get_password_secondary (dialog);

		switch (gnome_two_password_dialog_get_remember (dialog)) {
		case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION:
			keyring_helpers_save_secret (vpn_uuid, vpn_name, vpn_service, "session", "password", *password);
			keyring_helpers_save_secret (vpn_uuid, vpn_name, vpn_service, "session", "group-password", *group_password);
			break;
		case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER:
			keyring_helpers_save_secret (vpn_uuid, vpn_name, vpn_service, NULL, "password", *password);
			keyring_helpers_save_secret (vpn_uuid, vpn_name, vpn_service, NULL, "group-password", *group_password);
			break;
		default:
			break;
		}

	}

	gtk_widget_hide (GTK_WIDGET (dialog));
	gtk_widget_destroy (GTK_WIDGET (dialog));

	return TRUE;
}

int 
main (int argc, char *argv[])
{
	gboolean retry = FALSE;
	gchar *vpn_name = NULL;
	gchar *vpn_uuid = NULL;
	gchar *vpn_service = NULL;
	char *password = NULL, *group_password = NULL;
	char buf[1];
	int ret;
	GError *error = NULL;
	GOptionContext *context;
	GOptionEntry entries[] = {
			{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
			{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL},
			{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
			{ "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
			{ NULL }
		};

	bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	gtk_init (&argc, &argv);
	textdomain (GETTEXT_PACKAGE);

	context = g_option_context_new ("- vpnc auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		g_warning ("Error parsing options: %s\n", error->message);
		g_error_free (error);
		return 1;
	}

	g_option_context_free (context);

	if (vpn_uuid == NULL || vpn_name == NULL || vpn_service == NULL) {
		fprintf (stderr, "Have to supply UUID, name, and service\n");
		return 1;
	}

	if (strcmp (vpn_service, NM_DBUS_SERVICE_VPNC) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", NM_DBUS_SERVICE_VPNC);
		return 1;
	}

	if (!get_secrets (vpn_uuid, vpn_name, vpn_service, retry, &password, &group_password))
		return 1;

	/* dump the passwords to stdout */
	printf ("%s\n%s\n", NM_VPNC_KEY_XAUTH_PASSWORD, password);
	printf ("%s\n%s\n", NM_VPNC_KEY_SECRET, group_password);
	printf ("\n\n");

	if (password) {
		memset (password, 0, strlen (password));
		gnome_keyring_memory_free (password);
	}
	if (group_password) {
		memset (group_password, 0, strlen (group_password));
		gnome_keyring_memory_free (group_password);
	}

	/* for good measure, flush stdout since Kansas is going Bye-Bye */
	fflush (stdout);

	/* wait for data on stdin  */
	ret = fread (buf, sizeof (char), sizeof (buf), stdin);
	return 0;
}
