/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
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
 * (C) Copyright 2004 Red Hat, Inc.
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

#include "../src/nm-openvpn-service.h"
#include "gnome-two-password-dialog.h"

typedef struct {
	char *vpn_id;
	char *vpn_name;
	char *vpn_service;

	gboolean need_password;
	char *password;

	gboolean need_certpass;
	char *certpass;
} PasswordsInfo;

#define KEYRING_CID_TAG "connection-id"
#define KEYRING_SN_TAG "setting-name"
#define KEYRING_SK_TAG "setting-key"


static gboolean
lookup_pass (PasswordsInfo *info, gboolean *is_session)
{
	int status;
	GList *list = NULL;
	GList *iter;

	status = gnome_keyring_find_network_password_sync (g_get_user_name (),     /* user */
											 NULL,                   /* domain */
											 info->vpn_name,         /* server */
											 NULL,                   /* object */
											 info->vpn_service,      /* protocol */
											 NULL,                   /* authtype */
											 0,                      /* port */
											 &list);

	if (status != GNOME_KEYRING_RESULT_OK || list == NULL)
		return FALSE;

	*is_session = FALSE;

	/* Go through all passwords and assign to appropriate variable */
	for (iter = list; iter; iter = iter->next) {
		GnomeKeyringNetworkPasswordData *data = iter->data;
      
		if (!strcmp (data->object, "password") && data->password)
			info->password = g_strdup (data->password);
		else if (strcmp (data->object, "certpass") == 0)
			info->certpass = g_strdup (data->password);

		if (strcmp (data->keyring, "session") == 0)
			*is_session = TRUE;
	}

	gnome_keyring_network_password_list_free (list);

	return TRUE;
}

static void
save_vpn_password (PasswordsInfo *info, const char *keyring)
{
	guint32 item_id;
	GnomeKeyringResult keyring_result;

	if (info->password) {
		keyring_result = gnome_keyring_set_network_password_sync (keyring,
													   g_get_user_name (),
													   NULL,
													   info->vpn_name,
													   "password",
													   info->vpn_service,
													   NULL,
													   0,
													   info->password,
													   &item_id);
		if (keyring_result != GNOME_KEYRING_RESULT_OK)
			g_warning ("Couldn't store password in keyring, code %d", (int) keyring_result);
	}

	if (info->certpass) {
		keyring_result = gnome_keyring_set_network_password_sync (keyring,
													   g_get_user_name (),
													   NULL,
													   info->vpn_name,
													   "certpass",
													   info->vpn_service,
													   NULL,
													   0,
													   info->certpass,
													   &item_id);
		if (keyring_result != GNOME_KEYRING_RESULT_OK)
			g_warning ("Couldn't store certpass in keyring, code %d", (int) keyring_result);
	}
}

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


static gboolean
get_passwords (PasswordsInfo *info, gboolean retry)
{
	char *prompt;
	GtkWidget *dialog;
	gboolean keyring_is_session;
	GnomeTwoPasswordDialogRemember remember = GNOME_TWO_PASSWORD_DIALOG_REMEMBER_NOTHING;
	gboolean success = FALSE;

	if (lookup_pass (info, &keyring_is_session)) {
		if (!retry)
			return TRUE;

		if (keyring_is_session)
			remember = GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION;
		else
			remember = GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER;				
	}

	prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network '%s'."), info->vpn_name);
	dialog = gnome_two_password_dialog_new (_("Authenticate VPN"), prompt, NULL, NULL, FALSE);
	g_free (prompt);

	gnome_two_password_dialog_set_remember (GNOME_TWO_PASSWORD_DIALOG (dialog), remember);
	gnome_two_password_dialog_set_show_username (GNOME_TWO_PASSWORD_DIALOG (dialog), FALSE);
	gnome_two_password_dialog_set_show_userpass_buttons (GNOME_TWO_PASSWORD_DIALOG (dialog), FALSE);
	gnome_two_password_dialog_set_show_domain (GNOME_TWO_PASSWORD_DIALOG (dialog), FALSE);
	gnome_two_password_dialog_set_show_remember (GNOME_TWO_PASSWORD_DIALOG (dialog), TRUE);

	if (info->need_password && info->need_certpass) {
		gnome_two_password_dialog_set_show_password_secondary (GNOME_TWO_PASSWORD_DIALOG (dialog),
													TRUE);
		gnome_two_password_dialog_set_password_secondary_label (GNOME_TWO_PASSWORD_DIALOG (dialog),
													 _("Certificate pass_word:") );

		/* if retrying, put in the passwords from the keyring */
		if (info->password)
			gnome_two_password_dialog_set_password (GNOME_TWO_PASSWORD_DIALOG (dialog), info->password);
		if (info->certpass)
			gnome_two_password_dialog_set_password_secondary (GNOME_TWO_PASSWORD_DIALOG (dialog), info->certpass);
	} else {
		gnome_two_password_dialog_set_show_password_secondary (GNOME_TWO_PASSWORD_DIALOG (dialog), FALSE);
		if (info->need_password) {
			/* if retrying, put in the passwords from the keyring */
			if (info->password)
				gnome_two_password_dialog_set_password (GNOME_TWO_PASSWORD_DIALOG (dialog), info->password);
		} else if (info->need_certpass) {
			gnome_two_password_dialog_set_password_primary_label (GNOME_TWO_PASSWORD_DIALOG (dialog),
													    _("Certificate password:"));
			/* if retrying, put in the passwords from the keyring */
			if (info->certpass)
				gnome_two_password_dialog_set_password (GNOME_TWO_PASSWORD_DIALOG (dialog), info->certpass);
		}
	}

	gtk_widget_show (dialog);
	if (gnome_two_password_dialog_run_and_block (GNOME_TWO_PASSWORD_DIALOG (dialog))) {
		success = TRUE;

		if (info->need_password)
			info->password = g_strdup (gnome_two_password_dialog_get_password (GNOME_TWO_PASSWORD_DIALOG (dialog)));
		if (info->need_certpass)
			info->certpass = g_strdup (info->need_password ? 
								  gnome_two_password_dialog_get_password_secondary (GNOME_TWO_PASSWORD_DIALOG (dialog)) :
								  gnome_two_password_dialog_get_password (GNOME_TWO_PASSWORD_DIALOG (dialog)));


		switch (gnome_two_password_dialog_get_remember (GNOME_TWO_PASSWORD_DIALOG (dialog))) {
		case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION:
			save_vpn_password (info, "session");
			break;
		case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER:
			save_vpn_password (info, NULL);
			break;
		default:
			break;
		}
	}

	gtk_widget_destroy (dialog);

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

		key = g_strdup_printf ("%s/%s/%s", 
		                       path,
		                       NM_SETTING_CONNECTION_SETTING_NAME,
		                       NM_SETTING_CONNECTION_ID);
		str = gconf_client_get_string (gconf_client, key, NULL);
		g_free (key);

		if (!str || strcmp (str, info->vpn_name)) {
			g_free (str);
			continue;
		}

		/* Woo, found the connection */
		connection_path = g_strdup (path);
		break;
	}

	g_slist_foreach (conf_list, (GFunc) g_free, NULL);
	g_slist_free (conf_list);

	if (connection_path) {
		const char *connection_type;

		key = g_strdup_printf ("%s/%s/%s", connection_path, NM_SETTING_VPN_SETTING_NAME,
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

		g_free (connection_path);
	}

	g_object_unref (gconf_client);

	return success;
}

int 
main (int argc, char *argv[])
{
	PasswordsInfo info;
	int exit_status = 1;
	static gboolean  retry = FALSE;
	static gchar    *vpn_name = NULL;
	static gchar    *vpn_id = NULL;
	static gchar    *vpn_service = NULL;
	GOptionContext  *context;
	GnomeProgram    *program = NULL;
	int          bytes_read;
	GOptionEntry entries[] =
		{
			{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
			{ "id", 'i', 0, G_OPTION_ARG_STRING, &vpn_id, "ID of VPN connection", NULL},
			{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
			{ "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
			{ NULL }
		};
	char buf[1];

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

	if (vpn_id == NULL || vpn_name == NULL || vpn_service == NULL) {
		fprintf (stderr, "Have to supply ID, name, and service\n");
		goto out;
	}

	if (strcmp (vpn_service, NM_DBUS_SERVICE_OPENVPN) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", NM_DBUS_SERVICE_OPENVPN);
		goto out;		
	}

	memset (&info, 0, sizeof (PasswordsInfo));
	info.vpn_id = vpn_id;
	info.vpn_name = vpn_name;
	info.vpn_service = vpn_service;

	if (!get_password_types (&info)) {
		fprintf (stderr, "Invalid connection");
		goto out;
	}

	exit_status = 0;

	if (!info.need_password && !info.need_certpass) {
		printf ("%s\n%s\n\n\n", NM_OPENVPN_KEY_NOSECRET, "true");
		goto out;
	}

	if (get_passwords (&info, retry)) {
		if (info.need_password)
			printf ("%s\n%s\n", NM_OPENVPN_KEY_PASSWORD, info.password);
		if (info.need_certpass)
			printf ("%s\n%s\n", NM_OPENVPN_KEY_CERTPASS, info.certpass);
	}
	printf ("\n\n");
	/* for good measure, flush stdout since Kansas is going Bye-Bye */
	fflush (stdout);

	/* wait for data on stdin  */
	bytes_read = fread (buf, sizeof (char), sizeof (buf), stdin);

 out:
	g_object_unref (program);

	return exit_status;
}
