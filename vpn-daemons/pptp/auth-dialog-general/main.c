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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <libgnomeui/libgnomeui.h>
#include <gnome-keyring.h>

#include "gnome-generic-auth-dialog.h"

#define SERVICE_NAME "org.freedesktop.NetworkManager.ppp_starter"

static void save_auth_info (const char *connection_name, const char *service_name, const char *keyring, 
			       const char *auth_type, const char *username, const char *password)
{
	guint32 item_id;
	GnomeKeyringResult keyring_result;

	keyring_result = gnome_keyring_set_network_password_sync (keyring,
								  username,
								  NULL,
								  connection_name,
								  "password",
								  service_name,
								  auth_type,
								  0,
								  password,
								  &item_id);
	if (keyring_result != GNOME_KEYRING_RESULT_OK)
	{
		g_warning ("Couldn't store authentication information in keyring, code %d", (int) keyring_result);
	}

}

static GSList *
get_passwords (const char *connection_name, const char *service_name, gboolean retry)
{
	GSList          *result;
	char            *prompt;
	GnomeGenericAuthDialog *dialog;
	GnomeGenericAuthDialogRemember remember;

	result = NULL;

	g_return_val_if_fail (connection_name != NULL, NULL);

	prompt = g_strdup_printf (_("You need to authenticate to access '%s'."), connection_name);
	dialog = GNOME_GENERIC_AUTH_DIALOG( 
                 gnome_generic_auth_dialog_new (
                       _("Authenticate Connection"), 
                      prompt, 
                      NULL,           /* User */ 
                      NULL,           /* Domain */ 
                      connection_name,  /* Server - fixed */
                      service_name,  /* Protocol - Fixed */
                      0,        /* Port - can vary */
                      NULL      /* Allowed auth types */
                      ));
    if (dialog==NULL) {
      return NULL;
    }
	g_free (prompt);

    gnome_generic_auth_dialog_set_show_remember (dialog, TRUE);
	//gnome_generic_auth_dialog_set_remember (dialog, GNOME_GENERIC_AUTH_DIALOG_REMEMBER_NOTHING);

	gtk_widget_show (GTK_WIDGET(dialog));

	if (gnome_generic_auth_dialog_run_and_block (dialog))
	{
        GSList *secrets;
        GSList *item;
		const char *username;
		char *password;
		const char *auth_type;

		username = gnome_generic_auth_dialog_get_user (dialog);
		secrets = gnome_generic_auth_dialog_get_secrets (dialog);
        auth_type = gnome_generic_auth_dialog_get_auth_type (dialog);
// DEBUG: Force auth_type, username, password
//		result = g_slist_append (result, g_strdup("CHAP"));
//		result = g_slist_append (result, g_strdup("username"));
//		result = g_slist_append (result, g_strdup("password"));

		result = g_slist_append (result, g_strdup(auth_type));
g_warning("Secret: %s",auth_type);
		result = g_slist_append (result, g_strdup(username));
g_warning("Secret: %s",username);

        for (item=secrets; item!=NULL; item=g_slist_next(item))
        { 
          g_free(item->data);
          item = g_slist_next(item);
g_warning("Secret: %s",item->data);
		  result = g_slist_append (result, item->data);
        } 
        g_slist_free(secrets);

	}

	gtk_widget_destroy (GTK_WIDGET(dialog));
	return result;
}

int 
main (int argc, char *argv[])
{
	GSList *i;
	GSList *passwords;
	static gboolean retry = FALSE;
	static gchar *connection_name = NULL;
	static gchar *auth_types = NULL;
	static gchar *service_name = NULL;
	GError *error = NULL;
	GOptionContext *context;
	static GOptionEntry entries[] = 
		{
			{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
			{ "name", 'n', 0, G_OPTION_ARG_STRING, &connection_name, "Name of connection", NULL},
			{ "service", 's', 0, G_OPTION_ARG_STRING, &service_name, "Service type", NULL},
			{ "authtype", 'a', 0, G_OPTION_ARG_STRING_ARRAY, &auth_types, "Authentication Types", NULL},
			{ NULL }
		};
	char buf[1];

	bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	passwords = NULL;
	
	context = g_option_context_new ("- ppp auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);
	g_option_context_add_group (context, gtk_get_option_group (TRUE));
	g_option_context_parse (context, &argc, &argv, &error);

	if (connection_name == NULL || service_name == NULL) {
		fprintf (stderr, "Have to supply both name and service\n");
		goto out;
	}

	if (strcmp (service_name, SERVICE_NAME) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", SERVICE_NAME);
		goto out;		
	}

	gnome_program_init ("nm-ppp-auth-dialog", VERSION, LIBGNOMEUI_MODULE,
			    argc, argv, 
			    GNOME_PARAM_NONE);
	  
	passwords = get_passwords (connection_name, service_name, retry);
	if (passwords == NULL)
		goto out;

	/* dump the passwords to stdout */
	for (i = passwords; i != NULL; i = g_slist_next (i)) {
		char *password = (char *) i->data;
		printf ("%s\n", password);
	}
	printf ("\n\n");
	/* for good measure, flush stdout since Kansas is going Bye-Bye */
	fflush (stdout);

	g_slist_foreach (passwords, (GFunc)g_free, NULL);
	g_slist_free (passwords);

	/* wait for data on stdin  */
	fread (buf, sizeof (char), sizeof (buf), stdin);

out:
	g_option_context_free (context);

	return passwords != NULL ? 0 : 1;
}
