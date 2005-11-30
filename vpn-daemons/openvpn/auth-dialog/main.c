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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
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

#include "gnome-two-password-dialog.h"

#define VPN_SERVICE "org.freedesktop.NetworkManager.openvpn"
// MUST be the same as in gnome/applet/applet.h
// A real fix for this is needed by giving more information to auth apps
#define GCONF_PATH_VPN_CONNECTIONS "/system/networking/vpn_connections"

static GSList *
lookup_pass (const char *vpn_name, const char *vpn_service, gboolean *is_session)
{
  GSList *passwords;
  GList *keyring_result;

  passwords = NULL;

  if (gnome_keyring_find_network_password_sync (g_get_user_name (),     /* user */
						NULL,                   /* domain */
						vpn_name,               /* server */
						NULL,                   /* object */
						vpn_service,            /* protocol */
						NULL,                   /* authtype */
						0,                      /* port */
						&keyring_result) != GNOME_KEYRING_RESULT_OK)
    return FALSE;

  if (keyring_result != NULL && g_list_length (keyring_result) == 2) {
    char *password;
    GnomeKeyringNetworkPasswordData *data1 = keyring_result->data;

    password = NULL;

    if (strcmp (data1->object, "password") == 0) {
      password = data1->password;
    }

    if (password != NULL) {
      passwords = g_slist_append (passwords, g_strdup (password));
      if (strcmp (data1->keyring, "session") == 0)
	*is_session = TRUE;
      else
	*is_session = FALSE;
    }

    gnome_keyring_network_password_list_free (keyring_result);
  }

  return passwords;
}

static void save_vpn_password (const char *vpn_name, const char *vpn_service, const char *keyring, 
			       const char *password)
{
  guint32 item_id;
  GnomeKeyringResult keyring_result;

  keyring_result = gnome_keyring_set_network_password_sync (keyring,
							    g_get_user_name (),
							    NULL,
							    vpn_name,
							    "password",
							    vpn_service,
							    NULL,
							    0,
							    password,
							    &item_id);
  if (keyring_result != GNOME_KEYRING_RESULT_OK)
    {
      g_warning ("Couldn't store password in keyring, code %d", (int) keyring_result);
    }

}

static GSList *
get_passwords (const char *vpn_name, const char *vpn_service, gboolean retry)
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

  g_return_val_if_fail (vpn_name != NULL, NULL);

  /* Use the system user name, since the VPN might have a different user name */
  if (!retry) {
    if ((result = lookup_pass (vpn_name, vpn_service, &keyring_is_session)) != NULL) {
      return result;
    }
  } else {
    if ((keyring_result = lookup_pass (vpn_name, vpn_service, &keyring_is_session)) != NULL) {
      keyring_password = g_strdup ((char *) keyring_result->data);
    }
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
	  save_vpn_password (vpn_name, vpn_service, "session", password);
	  break;
	case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER:
	  save_vpn_password (vpn_name, vpn_service, NULL, password);
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
  GConfClient *gconf_client = NULL;
  GConfValue  *gconf_val = NULL;
  gchar       *gconf_key = NULL;
  char        *escaped_name;
  gboolean     needs_password = FALSE;
  gboolean     valid_conn = FALSE;
  GSList *i;
  GSList *passwords;
  static gboolean retry = FALSE;
  static gchar *vpn_name = NULL;
  static gchar *vpn_service = NULL;
  GError *error = NULL;
  GOptionContext *context;
  static GOptionEntry entries[] = 
    {
      { "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
      { "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
      { "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
      { NULL }
    };
  char buf[1];

  bindtextdomain (GETTEXT_PACKAGE, NULL);
  bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
  textdomain (GETTEXT_PACKAGE);

  passwords = NULL;

  context = g_option_context_new ("- openvpn auth dialog");
  g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);
  g_option_context_add_group (context, gtk_get_option_group (TRUE));
  g_option_context_parse (context, &argc, &argv, &error);

  if (vpn_name == NULL || vpn_service == NULL) {
    fprintf (stderr, "Have to supply both name and service\n");
    goto out;
  }

  if (strcmp (vpn_service, VPN_SERVICE) != 0) {
    fprintf (stderr, "This dialog only works with the '%s' service\n", VPN_SERVICE);
    goto out;		
  }

  gnome_program_init ("nm-openvpn-auth-dialog", VERSION, LIBGNOMEUI_MODULE,
		      argc, argv, 
		      GNOME_PARAM_NONE);


  gconf_client = gconf_client_get_default();
  escaped_name = gconf_escape_key (vpn_name, strlen (vpn_name));
  gconf_key    = g_strdup_printf ("%s/%s/vpn_data", GCONF_PATH_VPN_CONNECTIONS, escaped_name);
  if ( !(gconf_val = gconf_client_get (gconf_client, gconf_key, NULL)) ||
       !(gconf_val->type == GCONF_VALUE_LIST) ||
       !(gconf_value_get_list_type (gconf_val) == GCONF_VALUE_STRING)) {

    if (gconf_val)
      gconf_value_free (gconf_val);
    g_free (gconf_key);
    goto out;
  }
  g_free (gconf_key);

  valid_conn = TRUE;
    
  for (i = gconf_value_get_list (gconf_val); i != NULL; i = g_slist_next (i)) {
    const char *string = gconf_value_get_string ((GConfValue *)i->data);
    if (string) {
      if ( strcmp (string, "connection-type") == 0 ) {
	i = g_slist_next (i);
	if (i != NULL) {
	  const char *string2 = gconf_value_get_string ((GConfValue *)i->data);
	  if ( strcmp (string2, "password") == 0 ) {
	    needs_password = TRUE;
	  }
	}
	break;
      }
    }
  }
  gconf_value_free (gconf_val);

  if ( needs_password ) {
    passwords = get_passwords (vpn_name, vpn_service, retry);
    if (passwords == NULL)
      goto out;

    /* dump the passwords to stdout */
    for (i = passwords; i != NULL; i = g_slist_next (i)) {
      char *password = (char *) i->data;
      printf ("%s\n", password);
    }

    g_slist_foreach (passwords, (GFunc)g_free, NULL);
    g_slist_free (passwords);

  } else {
    printf ("No password needed\n");
  }

  printf ("\n\n");
  /* for good measure, flush stdout since Kansas is going Bye-Bye */
  fflush (stdout);

  /* wait for data on stdin  */
  fread (buf, sizeof (char), sizeof (buf), stdin);

 out:
  g_object_unref (gconf_client);
  g_option_context_free (context);

  if ( ! valid_conn ) {
    return 1;
  } else if ( needs_password ) {
    return (passwords != NULL) ? 0 : 1;
  } else {
    return 0;
  }
}
