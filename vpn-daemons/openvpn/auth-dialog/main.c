/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
 *
 * Dan Williams <dcbw@redhat.com>
 * Tim Niemueller <tim@niemueller.de>
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
 *               2005 Tim Niemueller [www.niemueller.de]
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <libgnomeui/libgnomeui.h>
#include <gconf/gconf-client.h>
#include <gnome-keyring.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>

#include "common-gnome/keyring-helpers.h"
#include "src/nm-openvpn-service.h"
#include "gnome-two-password-dialog.h"

typedef struct {
	char *vpn_uuid;
	char *vpn_name;

	gboolean need_password;
	char *password;

	gboolean need_certpass;
	char *certpass;
} PasswordsInfo;

#define PROC_TYPE_TAG "Proc-Type: 4,ENCRYPTED"

/** Checks if a key is encrypted
 * The key file is read and it is checked if it contains a line reading
 * Proc-Type: 4,ENCRYPTED
 * This is defined in RFC 1421 (PEM)
 * @param filename the path to the file
 * @return returns true if the key is encrypted, false otherwise
 */
static gboolean
pem_is_encrypted (const char *filename)
{
	GIOChannel *pem_chan;
	char       *str = NULL;
	gboolean encrypted = FALSE;

	pem_chan = g_io_channel_new_file (filename, "r", NULL);
	if (!pem_chan)
		return FALSE;

	while (g_io_channel_read_line (pem_chan, &str, NULL, NULL, NULL) != G_IO_STATUS_EOF) {
		if (strncmp (str, PROC_TYPE_TAG, strlen (PROC_TYPE_TAG)) == 0) {
			encrypted = TRUE;
			break;
		}
		g_free (str);
	}

	g_io_channel_shutdown (pem_chan, FALSE, NULL);
	g_io_channel_unref (pem_chan);
	return encrypted;
}


static void
clear_secrets (PasswordsInfo *info)
{
	if (info->password) {
		memset (info->password, 0, strlen (info->password));
		g_free (info->password);
	}
	if (info->certpass) {
		memset (info->certpass, 0, strlen (info->certpass));
		g_free (info->certpass);
	}
}

static gboolean
get_secrets (PasswordsInfo *info, gboolean retry)
{
	GnomeTwoPasswordDialog *dialog;
	gboolean is_session = TRUE;
	char *prompt;
	gboolean success = FALSE, need_secret = FALSE;

	g_return_val_if_fail (info->vpn_uuid != NULL, FALSE);
	g_return_val_if_fail (info->vpn_name != NULL, FALSE);

	if (info->need_password) {
		info->password = keyring_helpers_lookup_secret (info->vpn_uuid, NM_OPENVPN_KEY_PASSWORD, &is_session);
		if (!info->password)
			need_secret = TRUE;
	}

	if (info->need_certpass) {
		info->certpass = keyring_helpers_lookup_secret (info->vpn_uuid, NM_OPENVPN_KEY_CERTPASS, &is_session);
		if (!info->certpass)
			need_secret = TRUE;
	}

	/* Have all passwords and we're not supposed to ask the user again */
	if (!need_secret && !retry)
		return TRUE;

	prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network '%s'."), info->vpn_name);
	dialog = GNOME_TWO_PASSWORD_DIALOG (gnome_two_password_dialog_new (_("Authenticate VPN"), prompt, NULL, NULL, FALSE));
	g_free (prompt);

	gnome_two_password_dialog_set_show_username (dialog, FALSE);
	gnome_two_password_dialog_set_show_userpass_buttons (dialog, FALSE);
	gnome_two_password_dialog_set_show_domain (dialog, FALSE);
	gnome_two_password_dialog_set_show_remember (dialog, TRUE);

	/* If nothing was found in the keyring, default to not remembering any secrets */
	if (info->password || info->certpass) {
		/* Otherwise set default remember based on which keyring the secrets were found in */
		if (is_session)
			gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION);
		else
			gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER);
	} else
		gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_NOTHING);

	/* pre-fill dialog with the password */
	if (info->need_password && info->need_certpass) {
		gnome_two_password_dialog_set_show_password_secondary (dialog, TRUE);
		gnome_two_password_dialog_set_password_secondary_label (dialog, _("Certificate pass_word:") );

		/* if retrying, put in the passwords from the keyring */
		if (info->password)
			gnome_two_password_dialog_set_password (dialog, info->password);
		if (info->certpass)
			gnome_two_password_dialog_set_password_secondary (dialog, info->certpass);
	} else {
		gnome_two_password_dialog_set_show_password_secondary (dialog, FALSE);
		if (info->need_password) {
			/* if retrying, put in the passwords from the keyring */
			if (info->password)
				gnome_two_password_dialog_set_password (dialog, info->password);
		} else if (info->need_certpass) {
			gnome_two_password_dialog_set_password_primary_label (dialog, _("Certificate password:"));
			/* if retrying, put in the passwords from the keyring */
			if (info->certpass)
				gnome_two_password_dialog_set_password (dialog, info->certpass);
		}
	}
	clear_secrets (info);

	gtk_widget_show (GTK_WIDGET (dialog));

	if (gnome_two_password_dialog_run_and_block (dialog)) {
		gboolean save = FALSE;
		char *keyring = NULL;

		if (info->need_password)
			info->password = g_strdup (gnome_two_password_dialog_get_password (dialog));
		if (info->need_certpass) {
			info->certpass = g_strdup (info->need_password ? 
								  gnome_two_password_dialog_get_password_secondary (dialog) :
								  gnome_two_password_dialog_get_password (dialog));
		}

		switch (gnome_two_password_dialog_get_remember (dialog)) {
		case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION:
			keyring = "session";
			/* Fall through */
		case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER:
			save = TRUE;
			break;
		default:
			break;
		}

		if (save) {
			if (info->password) {
				keyring_helpers_save_secret (info->vpn_uuid, info->vpn_name,
											 keyring, NM_OPENVPN_KEY_PASSWORD, info->password);
			}
			if (info->certpass) {
				keyring_helpers_save_secret (info->vpn_uuid, info->vpn_name,
											 keyring, NM_OPENVPN_KEY_CERTPASS, info->certpass);
			}
		}

		success = TRUE;
	}

	gtk_widget_destroy (GTK_WIDGET (dialog));

	return success;
}

static gboolean
get_password_types (PasswordsInfo *info)
{
	GConfClient *gconf_client = NULL;
	GSList *conf_list;
	GSList *iter;
	char *key;
	char *str;
	char *connection_path = NULL;
	gboolean success = FALSE;
	char *connection_type;

	/* FIXME: This whole thing sucks: we should not go around poking gconf
	   directly, but there's nothing that does it for us right now */

	gconf_client = gconf_client_get_default ();

	conf_list = gconf_client_all_dirs (gconf_client, "/system/networking/connections", NULL);
	if (!conf_list)
		return FALSE;

	for (iter = conf_list; iter; iter = iter->next) {
		const char *path = (const char *) iter->data;

		key = g_strdup_printf ("%s/%s/%s", 
		                       path,
		                       NM_SETTING_CONNECTION_SETTING_NAME,
		                       NM_SETTING_CONNECTION_TYPE);
		str = gconf_client_get_string (gconf_client, key, NULL);
		g_free (key);

		if (!str || strcmp (str, "vpn")) {
			g_free (str);
			continue;
		}
		g_free (str);

		key = g_strdup_printf ("%s/%s/%s", 
		                       path,
		                       NM_SETTING_CONNECTION_SETTING_NAME,
		                       NM_SETTING_CONNECTION_UUID);
		str = gconf_client_get_string (gconf_client, key, NULL);
		g_free (key);

		if (!str || strcmp (str, info->vpn_uuid)) {
			g_free (str);
			continue;
		}
		g_free (str);

		/* Woo, found the connection */
		connection_path = g_strdup (path);
		break;
	}

	g_slist_foreach (conf_list, (GFunc) g_free, NULL);
	g_slist_free (conf_list);

	if (!connection_path)
		goto out;

	key = g_strdup_printf ("%s/%s/%s", connection_path,
	                       NM_SETTING_VPN_SETTING_NAME,
	                       NM_OPENVPN_KEY_CONNECTION_TYPE);
	connection_type = gconf_client_get_string (gconf_client, key, NULL);
	g_free (key);
	
	if (   !strcmp (connection_type, NM_OPENVPN_CONTYPE_TLS)
	    || !strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		success = TRUE;

		if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS))
			info->need_password = TRUE;

		key = g_strdup_printf ("%s/%s/%s", connection_path, NM_SETTING_VPN_SETTING_NAME,
		                       NM_OPENVPN_KEY_KEY);
		str = gconf_client_get_string (gconf_client, key, NULL);
		if (str)
			info->need_certpass = pem_is_encrypted (str);
		g_free (str);
		g_free (key);
	} else if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_STATIC_KEY)) {
		success = TRUE;
	} else if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD)) {
		success = TRUE;
		info->need_password = TRUE;
	}

	g_free (connection_type);
	g_free (connection_path);

out:
	g_object_unref (gconf_client);
	return success;
}

int 
main (int argc, char *argv[])
{
	PasswordsInfo info;
	gboolean retry = FALSE;
	gchar *vpn_name = NULL;
	gchar *vpn_uuid = NULL;
	gchar *vpn_service = NULL;
	char buf[1];
	int ret, exit_status = 1;
	GOptionContext *context;
	GnomeProgram *program;
	GOptionEntry entries[] = {
			{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
			{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL},
			{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
			{ "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
			{ NULL }
		};

	bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	context = g_option_context_new ("- openvpn auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);

	program = gnome_program_init ("nm-openvpn-auth-dialog", VERSION,
							LIBGNOMEUI_MODULE,
							argc, argv,
							GNOME_PARAM_GOPTION_CONTEXT, context,
							GNOME_PARAM_NONE);

	if (vpn_uuid == NULL || vpn_name == NULL || vpn_service == NULL) {
		fprintf (stderr, "Have to supply ID, name, and service\n");
		goto out;
	}

	if (strcmp (vpn_service, NM_DBUS_SERVICE_OPENVPN) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", NM_DBUS_SERVICE_OPENVPN);
		goto out;		
	}

	memset (&info, 0, sizeof (PasswordsInfo));
	info.vpn_uuid = vpn_uuid;
	info.vpn_name = vpn_name;

	if (!get_password_types (&info)) {
		fprintf (stderr, "Invalid connection");
		goto out;
	}

	exit_status = 0;

	if (!info.need_password && !info.need_certpass) {
		printf ("%s\n%s\n\n\n", NM_OPENVPN_KEY_NOSECRET, "true");
		goto out;
	}

	if (get_secrets (&info, retry)) {
		if (info.need_password)
			printf ("%s\n%s\n", NM_OPENVPN_KEY_PASSWORD, info.password);
		if (info.need_certpass)
			printf ("%s\n%s\n", NM_OPENVPN_KEY_CERTPASS, info.certpass);
	}
	printf ("\n\n");

	clear_secrets (&info);

	/* for good measure, flush stdout since Kansas is going Bye-Bye */
	fflush (stdout);

	/* wait for data on stdin  */
	ret = fread (buf, sizeof (char), sizeof (buf), stdin);

 out:
	g_object_unref (program);

	return exit_status;
}
