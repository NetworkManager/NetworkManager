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
 * (C) Copyright 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <libgnomeui/libgnomeui.h>
#include <gnome-keyring.h>

#include <nm-setting-vpn.h>

#include "../src/nm-pptp-service.h"
#include "gnome-two-password-dialog.h"

#define KEYRING_CID_TAG "connection-id"
#define KEYRING_SN_TAG "setting-name"
#define KEYRING_SK_TAG "setting-key"

static char *
find_one_password (const char *vpn_id,
                   const char *vpn_name,
                   const char *vpn_service,
                   const char *secret_name,
                   gboolean *is_session)
{
	GList *found_list = NULL;
	GnomeKeyringResult ret;
	GnomeKeyringFound *found;
	char *secret;

	ret = gnome_keyring_find_itemsv_sync (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                      &found_list,
	                                      KEYRING_CID_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      vpn_id,
	                                      KEYRING_SN_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      NM_SETTING_VPN_SETTING_NAME,
	                                      KEYRING_SK_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      secret_name,
	                                      NULL);
	if ((ret != GNOME_KEYRING_RESULT_OK) || (g_list_length (found_list) == 0))
		return NULL;

	found = (GnomeKeyringFound *) found_list->data;

	if (strcmp (found->keyring, "session") == 0)
		*is_session = TRUE;
	else
		*is_session = FALSE;

	secret = found->secret ? g_strdup (found->secret) : NULL;
	gnome_keyring_found_list_free (found_list);

	return secret;
}

static GSList *
lookup_pass (const char *vpn_id, const char *vpn_name, const char *vpn_service, gboolean *is_session)
{
	GSList *passwords = NULL;
	char *password;

	password = find_one_password (vpn_id, vpn_name, vpn_service, "password", is_session);
	if (password)
		passwords = g_slist_append (passwords, password);

	return passwords;
}

static void
save_vpn_password (const char *vpn_id,
                   const char *vpn_name,
                   const char *vpn_service,
                   const char *keyring,
                   const char *secret_name,
                   const char *secret)
{
	char *display_name;
	GnomeKeyringResult ret;
	GnomeKeyringAttributeList *attrs = NULL;
	guint32 id = 0;

	display_name = g_strdup_printf ("VPN %s secret for %s/%s/" NM_SETTING_VPN_SETTING_NAME,
	                                secret_name,
	                                vpn_name,
	                                vpn_service);

	attrs = gnome_keyring_attribute_list_new ();
	gnome_keyring_attribute_list_append_string (attrs,
	                                            KEYRING_CID_TAG,
	                                            vpn_id);
	gnome_keyring_attribute_list_append_string (attrs,
	                                            KEYRING_SN_TAG,
	                                            NM_SETTING_VPN_SETTING_NAME);
	gnome_keyring_attribute_list_append_string (attrs,
	                                            KEYRING_SK_TAG,
	                                            secret_name);

	ret = gnome_keyring_item_create_sync (keyring,
	                                      GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                      display_name,
	                                      attrs,
	                                      secret,
	                                      TRUE,
	                                      &id);
	gnome_keyring_attribute_list_free (attrs);
	g_free (display_name);
}

static GSList *
get_passwords (const char *vpn_id,
               const char *vpn_name,
               const char *vpn_service,
               gboolean retry)
{
	GSList          *result;
	char            *prompt;
	GtkWidget	*dialog;
	char            *keyring_password;
	gboolean         keyring_is_session;
	GSList          *keyring_result;
	GnomeTwoPasswordDialogRemember remember;

	result = NULL;
	keyring_password = NULL;
	keyring_result = NULL;

	g_return_val_if_fail (vpn_id != NULL, NULL);
	g_return_val_if_fail (vpn_name != NULL, NULL);

	/* Use the system user name, since the VPN might have a different user name */
	if (!retry) {
		if ((result = lookup_pass (vpn_id, vpn_name, vpn_service, &keyring_is_session)) != NULL) {
			return result;
		}
	} else {
		if ((keyring_result = lookup_pass (vpn_id, vpn_name, vpn_service, &keyring_is_session)) != NULL)
			keyring_password = g_strdup ((char *) (g_slist_next (keyring_result))->data);

		g_slist_foreach (keyring_result, (GFunc)g_free, NULL);
		g_slist_free (keyring_result);
	}

	prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network '%s'."), vpn_name);
	dialog = gnome_two_password_dialog_new (_("Authenticate VPN"), prompt, NULL, NULL, FALSE);
	g_free (prompt);

	gnome_two_password_dialog_set_show_username (GNOME_TWO_PASSWORD_DIALOG (dialog), FALSE);
	gnome_two_password_dialog_set_show_userpass_buttons (GNOME_TWO_PASSWORD_DIALOG (dialog), FALSE);
	gnome_two_password_dialog_set_show_domain (GNOME_TWO_PASSWORD_DIALOG (dialog), FALSE);
	gnome_two_password_dialog_set_show_remember (GNOME_TWO_PASSWORD_DIALOG (dialog), TRUE);
	gnome_two_password_dialog_set_show_password_secondary (GNOME_TWO_PASSWORD_DIALOG (dialog), FALSE);

	/* use the same keyring storage options as from the items we put in the entry boxes */
	remember = GNOME_TWO_PASSWORD_DIALOG_REMEMBER_NOTHING;
	if (keyring_result != NULL) {
		if (keyring_is_session)
			remember = GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION;
		else
			remember = GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER;				
	}
	gnome_two_password_dialog_set_remember (GNOME_TWO_PASSWORD_DIALOG (dialog), remember);

	/* if retrying, put in the passwords from the keyring */
	if (keyring_password != NULL) {
		gnome_two_password_dialog_set_password (GNOME_TWO_PASSWORD_DIALOG (dialog), keyring_password);
	}

	gtk_widget_show (dialog);

	if (gnome_two_password_dialog_run_and_block (GNOME_TWO_PASSWORD_DIALOG (dialog)))
	{
		char *password;

		password = gnome_two_password_dialog_get_password (GNOME_TWO_PASSWORD_DIALOG (dialog));
		result = g_slist_append (result, password);

		switch (gnome_two_password_dialog_get_remember (GNOME_TWO_PASSWORD_DIALOG (dialog)))
		{
			case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION:
				save_vpn_password (vpn_id, vpn_name, vpn_service, "session", "password", password);
				break;
			case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER:
				save_vpn_password (vpn_id, vpn_name, vpn_service, NULL, "password", password);
				break;
			default:
				break;
		}

	}

	g_free (keyring_password);

	gtk_widget_destroy (dialog);

	return result;
}

int 
main (int argc, char *argv[])
{
	GSList *passwords;
	static gboolean retry = FALSE;
	static gchar *vpn_name = NULL;
	static gchar *vpn_id = NULL;
	static gchar *vpn_service = NULL;
	char buf[1];
	int ret;
	GOptionContext *context;
	GnomeProgram *program;
	GOptionEntry entries[] =
		{
			{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
			{ "id", 'i', 0, G_OPTION_ARG_STRING, &vpn_id, "ID of VPN connection", NULL},
			{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
			{ "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
			{ NULL }
		};

	bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	passwords = NULL;
	
	context = g_option_context_new ("- pptp auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);
	
	program = gnome_program_init ("nm-pptp-auth-dialog", VERSION,
				      LIBGNOMEUI_MODULE,
				      argc, argv,
				      GNOME_PARAM_GOPTION_CONTEXT, context,
				      GNOME_PARAM_NONE);
	  

	if (vpn_id == NULL || vpn_name == NULL || vpn_service == NULL) {
		fprintf (stderr, "Have to supply ID, name, and service\n");
		goto out;
	}

	if (strcmp (vpn_service, NM_DBUS_SERVICE_PPTP) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", NM_DBUS_SERVICE_PPTP);
		goto out;		
	}

	passwords = get_passwords (vpn_id, vpn_name, vpn_service, retry);
	if (passwords == NULL)
		goto out;

	/* dump the passwords to stdout */

	printf ("%s\n%s\n", NM_PPTP_KEY_PASSWORD, (char *) passwords->data);
	printf ("\n\n");

	/* for good measure, flush stdout since Kansas is going Bye-Bye */
	fflush (stdout);

	g_slist_foreach (passwords, (GFunc)g_free, NULL);
	g_slist_free (passwords);

	/* wait for data on stdin  */
	ret = fread (buf, sizeof (char), sizeof (buf), stdin);

out:
	g_object_unref (program);

	return passwords != NULL ? 0 : 1;
}
