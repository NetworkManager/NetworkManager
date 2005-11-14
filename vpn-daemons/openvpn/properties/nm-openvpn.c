/***************************************************************************
 * CVSID: $Id$
 *
 * nm-openvpn.c : GNOME UI dialogs for configuring OpenVPN connections
 *
 * Copyright (C) 2005 Tim Niemueller <tim@niemueller.de>
 * Based on work by David Zeuthen, <davidz@redhat.com>
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

#include <glib/gi18n-lib.h>
#include <string.h>
#include <glade/glade.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <NetworkManager/nm-vpn-ui-interface.h>

typedef struct _NetworkManagerVpnUIImpl NetworkManagerVpnUIImpl;


struct _NetworkManagerVpnUIImpl {
  NetworkManagerVpnUI parent;

  NetworkManagerVpnUIDialogValidityCallback callback;
  gpointer callback_user_data;

  GladeXML *xml;

  GtkWidget *widget;

  GtkEntry       *w_connection_name;
  GtkEntry       *w_remote;
  GtkEntry       *w_ca;
  GtkEntry       *w_cert;
  GtkEntry       *w_key;
  GtkCheckButton *w_use_routes;
  GtkEntry       *w_routes;
  GtkCheckButton *w_use_lzo;
  GtkExpander    *w_opt_info_expander;
  GtkButton      *w_import_button;
  GtkButton      *w_button_ca;
  GtkButton      *w_button_cert;
  GtkButton      *w_button_key;
};

static void 
openvpn_clear_widget (NetworkManagerVpnUIImpl *impl)
{
  gtk_entry_set_text (impl->w_connection_name, "");
  gtk_entry_set_text (impl->w_remote,   "");
  gtk_entry_set_text (impl->w_ca,   "");
  gtk_entry_set_text (impl->w_cert, "");
  gtk_entry_set_text (impl->w_key,  "");
  gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_routes), FALSE);
  gtk_entry_set_text (impl->w_routes, "");
  gtk_widget_set_sensitive (GTK_WIDGET (impl->w_routes), FALSE);
  gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_lzo), FALSE);
  gtk_expander_set_expanded (impl->w_opt_info_expander, FALSE);
}

static const char *
impl_get_display_name (NetworkManagerVpnUI *self)
{
  return _("OpenVPN Client");
}

static const char *
impl_get_service_name (NetworkManagerVpnUI *self)
{
  return "org.freedesktop.NetworkManager.openvpn";
}

static GtkWidget *
impl_get_widget (NetworkManagerVpnUI *self, GSList *properties, GSList *routes, const char *connection_name)
{
  GSList *i;
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
  gboolean should_expand;

  openvpn_clear_widget (impl);

  should_expand = FALSE;

  if (connection_name != NULL)
    gtk_entry_set_text (impl->w_connection_name, connection_name);

  for (i = properties; i != NULL && g_slist_next (i) != NULL; i = g_slist_next (g_slist_next (i))) {
    const char *key;
    const char *value;

    key = i->data;
    value = (g_slist_next (i))->data;

    if (strcmp (key, "remote") == 0) {
      gtk_entry_set_text (impl->w_remote, value);		
    } else if (strcmp (key, "ca") == 0) {
      gtk_entry_set_text (impl->w_ca, value);
    } else if (strcmp (key, "cert") == 0) {
      gtk_entry_set_text (impl->w_cert, value);
    } else if (strcmp (key, "key") == 0) {
      gtk_entry_set_text (impl->w_key, value);
    } else if ( (strcmp (key, "comp-lzo") == 0) &&
		(strcmp (value, "yes")) ) {
      gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_routes), TRUE);
      should_expand = TRUE;
    }
  }

  if (routes != NULL) {
    GString *route_str;
    char *str;

    route_str = g_string_new ("");
    for (i = routes; i != NULL; i = g_slist_next (i)) {
      const char *route;
			
      if (i != routes)
	g_string_append_c(route_str, ' ');
			
      route = (const char *) i->data;
      g_string_append(route_str, route);
    }

    str = g_string_free (route_str, FALSE);
    gtk_entry_set_text (impl->w_routes, str);
    g_free (str);
    gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_routes), TRUE);
    gtk_widget_set_sensitive (GTK_WIDGET (impl->w_routes), TRUE);
    
    should_expand = TRUE;
  }

  gtk_expander_set_expanded (impl->w_opt_info_expander, should_expand);
  gtk_container_resize_children (GTK_CONTAINER (impl->widget));

  return impl->widget;
}

static GSList *
impl_get_properties (NetworkManagerVpnUI *self)
{
  GSList *data;
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
  const char *connectionname;
  const char *remote;
  const char *ca;
  const char *cert;
  const char *key;
  gboolean use_lzo;

  connectionname         = gtk_entry_get_text (impl->w_connection_name);
  remote                 = gtk_entry_get_text (impl->w_remote);
  ca                     = gtk_entry_get_text (impl->w_ca);
  cert                   = gtk_entry_get_text (impl->w_cert);
  key                    = gtk_entry_get_text (impl->w_key);
  use_lzo                = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_lzo));
 
  data = NULL;
  data = g_slist_append (data, g_strdup ("remote"));
  data = g_slist_append (data, g_strdup (remote));
  data = g_slist_append (data, g_strdup ("ca"));
  data = g_slist_append (data, g_strdup (ca));
  data = g_slist_append (data, g_strdup ("cert"));
  data = g_slist_append (data, g_strdup (cert));
  data = g_slist_append (data, g_strdup ("key"));
  data = g_slist_append (data, g_strdup (key));
  data = g_slist_append (data, g_strdup ("comp-lzo"));
  data = g_slist_append (data, use_lzo ? g_strdup ("yes") : g_strdup("no"));

  return data;
}

static GSList *
get_routes (NetworkManagerVpnUIImpl *impl)
{
  GSList *routes;
  const char *routes_entry;
  gboolean use_routes;
  char **substrs;
  unsigned int i;

  routes = NULL;

  routes_entry = gtk_entry_get_text (impl->w_routes);
  use_routes = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_routes));

  if (!use_routes)
    goto out;

  substrs = g_strsplit (routes_entry, " ", 0);
  for (i = 0; substrs[i] != NULL; i++) {
    char *route;

    route = substrs[i];
    if (strlen (route) > 0)
      routes = g_slist_append (routes, g_strdup (route));
  }

  g_strfreev (substrs);

 out:
  return routes;
}

static GSList *
impl_get_routes (NetworkManagerVpnUI *self)
{
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;

  return get_routes (impl);
}


static char *
impl_get_connection_name (NetworkManagerVpnUI *self)
{
  const char *name;
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;

  name = gtk_entry_get_text (impl->w_connection_name);
  if (name != NULL)
    return g_strdup (name);
  else
    return NULL;
}

static gboolean
impl_is_valid (NetworkManagerVpnUI *self)
{
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
  gboolean is_valid;
  const char *connectionname;
  const char *remote;
  const char *ca;
  const char *cert;
  const char *key;
  gboolean use_routes;
  const char *routes_entry;


  is_valid = FALSE;

  connectionname         = gtk_entry_get_text (impl->w_connection_name);
  remote                 = gtk_entry_get_text (impl->w_remote);
  ca                     = gtk_entry_get_text (impl->w_ca);
  cert                   = gtk_entry_get_text (impl->w_cert);
  key                    = gtk_entry_get_text (impl->w_key);
  use_routes             = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_routes));
  routes_entry           = gtk_entry_get_text (impl->w_routes);

  /* initial sanity checking */
  if (strlen (connectionname) > 0 &&
      strlen (remote) > 0 &&
      strlen (ca) > 0 &&
      strlen (cert) > 0 &&
      strlen (key) > 0 &&
      ((!use_routes) || (use_routes && strlen (routes_entry) > 0)) ) {
    is_valid = TRUE;
  }

  /* validate gateway: can be a hostname or an IP; do not allow spaces or tabs */
  if (is_valid &&
      ( (strstr (remote, " ") != NULL)  ||
	(strstr (remote, "\t") != NULL) ||
	(strstr (ca, " ") != NULL)  ||
	(strstr (ca, "\t") != NULL) ||
	(strstr (cert, " ") != NULL)  ||
	(strstr (cert, "\t") != NULL) ||
	(strstr (key, " ") != NULL)  ||
	(strstr (key, "\t") != NULL) ) ) {
    is_valid = FALSE;
  }

  /* validate ca/cert/key files */
  if ( ! ( g_file_test( ca, G_FILE_TEST_IS_REGULAR) &&
	   g_file_test( cert, G_FILE_TEST_IS_REGULAR) &&
	   g_file_test( key, G_FILE_TEST_IS_REGULAR) ) ) {
    is_valid = FALSE;
  }

  /* validate routes: each entry must be of the form 'a.b.c.d/mask' */
  if (is_valid) {
    GSList *i;
    GSList *routes;

    routes = get_routes (impl);

    for (i = routes; i != NULL; i = g_slist_next (i)) {
      int d1, d2, d3, d4, mask;

      const char *route = (const char *) i->data;
      //printf ("route = '%s'\n", route);

      if (sscanf (route, "%d.%d.%d.%d/%d", &d1, &d2, &d3, &d4, &mask) != 5) {
	is_valid = FALSE;
	break;
      }

      /* TODO: this can be improved a bit */
      if (d1 < 0 || d1 > 255 ||
	  d2 < 0 || d2 > 255 ||
	  d3 < 0 || d3 > 255 ||
	  d4 < 0 || d4 > 255 ||
	  mask < 0 || mask > 32) {
	is_valid = FALSE;
	break;
      }

    }
    //if (routes != NULL)
    //	printf ("\n");

    if (routes != NULL) {
      g_slist_foreach (routes, (GFunc)g_free, NULL);
      g_slist_free (routes);
    }
  }

  return is_valid;
}


static void 
use_routes_toggled (GtkToggleButton *togglebutton, gpointer user_data)
{
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;

  gtk_widget_set_sensitive (GTK_WIDGET (impl->w_routes), 
			    gtk_toggle_button_get_active (togglebutton));

  if (impl->callback != NULL) {
    gboolean is_valid;

    is_valid = impl_is_valid (&(impl->parent));
    impl->callback (&(impl->parent), is_valid, impl->callback_user_data);
  }
}


static void 
editable_changed (GtkEditable *editable, gpointer user_data)
{
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;

  if (impl->callback != NULL) {
    gboolean is_valid;

    is_valid = impl_is_valid (&(impl->parent));
    impl->callback (&(impl->parent), is_valid, impl->callback_user_data);
  }
}


static void 
impl_set_validity_changed_callback (NetworkManagerVpnUI *self, 
				    NetworkManagerVpnUIDialogValidityCallback callback,
				    gpointer user_data)
{
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;

  impl->callback = callback;
  impl->callback_user_data = user_data;
}

static void
impl_get_confirmation_details (NetworkManagerVpnUI *self, gchar **retval)
{
  GString *buf;
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
  const char *connectionname;
  const char *remote;
  const char *ca;
  const char *cert;
  const char *key;
  gboolean use_routes;
  const char *routes;
  gboolean use_lzo;

  connectionname         = gtk_entry_get_text (impl->w_connection_name);
  remote                 = gtk_entry_get_text (impl->w_remote);
  ca                     = gtk_entry_get_text (impl->w_ca);
  cert                   = gtk_entry_get_text (impl->w_cert);
  key                    = gtk_entry_get_text (impl->w_key);
  use_routes             = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_routes));
  routes                 = gtk_entry_get_text (impl->w_routes);
  use_lzo                = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (impl->w_use_lzo));

  
  // This is risky, should be variable length depending on actual data!
  buf = g_string_sized_new (512);

  g_string_append (buf, _("The following OpenVPN connection will be created:"));
  g_string_append (buf, "\n\n\t");
  g_string_append_printf (buf, _("Name:  %s"), connectionname);
  g_string_append (buf, "\n\n\t");

  g_string_append_printf (buf, _("Remote:  %s"), remote);
  g_string_append (buf, "\n\t");

  g_string_append_printf (buf, _("CA:  %s"), ca);
  g_string_append (buf, "\n\t");

  g_string_append_printf (buf, _("Cert:  %s"), cert);
  g_string_append (buf, "\n\t");

  g_string_append_printf (buf, _("Key:  %s"), key);

  if (use_routes) {
    g_string_append (buf, "\n\t");
    g_string_append_printf (buf, _("Routes:  %s"), routes);
  }

  g_string_append_printf( buf, _("Use LZO Compression: %s"), ((use_lzo) ? _("Yes") : _("No")));

  g_string_append (buf, "\n\n");
  g_string_append (buf, _("The connection details can be changed using the \"Edit\" button."));
  g_string_append (buf, "\n");

  *retval = g_string_free (buf, FALSE);
}

static gboolean
import_from_file (NetworkManagerVpnUIImpl *impl, const char *path)
{
  char *basename;
  GKeyFile *keyfile;
  gboolean file_is_good;

  file_is_good = FALSE;
  basename = g_path_get_basename (path);

  keyfile = g_key_file_new ();
  if (g_key_file_load_from_file (keyfile, path, 0, NULL)) {
    char *connectionname = NULL;
    char *remote = NULL;
    char *ca = NULL;
    char *cert = NULL;
    char *key = NULL;
    char *routes = NULL;
    char *lzo = NULL;
    gboolean should_expand;

    connectionname = g_key_file_get_string (keyfile, "main", "Description", NULL);
    remote = g_key_file_get_string (keyfile, "main", "Remote", NULL);
    ca = g_key_file_get_string (keyfile, "main", "CA", NULL);
    cert = g_key_file_get_string (keyfile, "main", "Cert", NULL);
    key = g_key_file_get_string (keyfile, "main", "Key", NULL);
    lzo = g_key_file_get_string (keyfile, "main", "Comp-LZO", NULL);

    /* may not exist */
    if ((routes = g_key_file_get_string (keyfile, "main", "X-NM-Routes", NULL)) == NULL)
      routes = g_strdup ("");

    /* sanity check data */
    if ( ( connectionname != NULL) &&
	 ( remote != NULL ) &&
	 ( ca != NULL ) &&
	 ( cert != NULL ) &&
	 ( key != NULL ) &&
	 (strlen(connectionname) > 0) &&
	 (strlen(remote) > 0) &&
	 (strlen(ca) > 0) &&
	 (strlen(cert) > 0) &&
	 (strlen(key) > 0) ) {

      gtk_entry_set_text (impl->w_connection_name, connectionname);
      gtk_entry_set_text (impl->w_remote, remote);
      gtk_entry_set_text (impl->w_ca, ca);
      gtk_entry_set_text (impl->w_cert, cert);
      gtk_entry_set_text (impl->w_key, key);

      gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_lzo), ((lzo != NULL) && (strcmp(lzo, "yes") == 0)));

      gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (impl->w_use_routes), strlen (routes) > 0);
      gtk_entry_set_text (impl->w_routes, routes);
      gtk_widget_set_sensitive (GTK_WIDGET (impl->w_routes), strlen (routes) > 0);

      should_expand = (strlen (routes) > 0) ||
	              ((lzo != NULL) && (strcmp(lzo, "yes") == 0));
      gtk_expander_set_expanded (impl->w_opt_info_expander, should_expand);

    } else {
      g_free (connectionname);
      g_free (remote);
      g_free (ca);
      g_free (cert);
      g_free (key);
      g_free (lzo);
    }
    g_key_file_free (keyfile);

    if (!file_is_good) {
      GtkWidget *dialog;
		
      dialog = gtk_message_dialog_new (NULL,
				       GTK_DIALOG_DESTROY_WITH_PARENT,
				       GTK_MESSAGE_WARNING,
				       GTK_BUTTONS_CLOSE,
				       _("Cannot import settings"));
      gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog),
						_("The VPN settings file '%s' does not contain valid data."), basename);
      gtk_dialog_run (GTK_DIALOG (dialog));
      gtk_widget_destroy (dialog);
    }
  }

  g_free (basename);

  return file_is_good;
}

static void
import_button_clicked (GtkButton *button, gpointer user_data)
{
  char *filename = NULL;
  GtkWidget *dialog;
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;

  dialog = gtk_file_chooser_dialog_new (_("Select file to import"),
					NULL,
					GTK_FILE_CHOOSER_ACTION_OPEN,
					GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
					NULL);
  
  if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT) {
		
    filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
    /*printf ("User selected '%s'\n", filename);*/

  }
	
  gtk_widget_destroy (dialog);

  if (filename != NULL) {
    import_from_file (impl, filename);
    g_free (filename);
  }      
}

static void
open_button_clicked (GtkButton *button, gpointer user_data)
{

  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *)user_data;
  GtkWidget *dialog;

  const char *msg;
  GtkEntry *entry;

  if ( button == impl->w_button_ca ) {
    msg = _("Select CA to use");
    entry = impl->w_ca;
  } else if ( button == impl->w_button_cert ) {
    msg = _("Select certificate to use");
    entry = impl->w_cert;
  } else if ( button == impl->w_button_key ) {
    msg = _("Select key to use");
    entry = impl->w_key;
  } else {
    return;
  }

  dialog = gtk_file_chooser_dialog_new (msg,
					NULL,
					GTK_FILE_CHOOSER_ACTION_OPEN,
					GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
					NULL);
  
  if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT) {
    gtk_entry_set_text (entry, gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog)));
  }
	
  gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
  gtk_widget_destroy (dialog);

}

static gboolean 
impl_can_export (NetworkManagerVpnUI *self)
{
  return TRUE;
}

static gboolean 
impl_import_file (NetworkManagerVpnUI *self, const char *path)
{
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;

  return import_from_file (impl, path);
}

static void
export_to_file (NetworkManagerVpnUIImpl *impl, const char *path, 
		GSList *properties, GSList *routes, const char *connection_name)
{
  FILE *f;
  GSList *i;
  const char *remote = NULL;
  const char *ca = NULL;
  const char *cert = NULL;
  const char *key = NULL;
  const char *lzo = NULL;
  char *routes_str = NULL;

  /*printf ("in export_to_file; path='%s'\n", path);*/

  for (i = properties; i != NULL && g_slist_next (i) != NULL; i = g_slist_next (g_slist_next (i))) {
    const char *key;
    const char *value;

    key = i->data;
    value = (g_slist_next (i))->data;

    if (strcmp (key, "remote") == 0) {
      remote = value;
    } else if (strcmp (key, "ca") == 0) {
      ca = value;
    } else if (strcmp (key, "cert") == 0) {
      cert = value;
    } else if (strcmp (key, "key") == 0) {
      key = value;
    } else if (strcmp (key, "comp-lzo") == 0) {
      lzo = value;
    }
  }


  if (routes != NULL) {
    GString *str;

    str = g_string_new ("X-NM-Routes=");
    for (i = routes; i != NULL; i = g_slist_next (i)) {
      const char *route;
      
      if (i != routes)
	g_string_append_c (str, ' ');
			
      route = (const char *) i->data;
      g_string_append (str, route);
    }

    g_string_append_c (str, '\n');

    routes_str = g_string_free (str, FALSE);
  }

  f = fopen (path, "w");
  if (f != NULL) {

    fprintf (f, 
	     "[main]\n"
	     "Description=%s\n"
	     "Remote=%s\n"
	     "CA=%s\n"
	     "Cert=%s\n"
	     "Key=%s\n"
	     "Comp-LZO=%s\n"
	     "%s",
	     /* Description */ connection_name,
	     /* Host */        remote,
	     /* CA */          ca,
	     /* Cert */        cert,
	     /* Key */         key,
	     /* Comp-LZO */    lzo,
	     /* X-NM-Routes */ routes_str != NULL ? routes_str : "");

    fclose (f);
  }
  g_free (routes_str);
}


static gboolean 
impl_export (NetworkManagerVpnUI *self, GSList *properties, GSList *routes, const char *connection_name)
{
  char *suggested_name;
  char *path = NULL;
  GtkWidget *dialog;
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;

  /*printf ("in impl_export\n");*/

  dialog = gtk_file_chooser_dialog_new (_("Save as..."),
					NULL,
					GTK_FILE_CHOOSER_ACTION_SAVE,
					GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT,
					NULL);

  suggested_name = g_strdup_printf ("%s.pcf", connection_name);
  gtk_file_chooser_set_current_name (GTK_FILE_CHOOSER (dialog), suggested_name);
  g_free (suggested_name);

  if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT)
    {
      
      path = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
      /*printf ("User selected '%s'\n", path);*/
      
    }
	
  gtk_widget_destroy (dialog);

  if (path != NULL) {
    if (g_file_test (path, G_FILE_TEST_EXISTS)) {
      int response;
      GtkWidget *dialog;

      dialog = gtk_message_dialog_new (NULL,
				       GTK_DIALOG_DESTROY_WITH_PARENT,
				       GTK_MESSAGE_QUESTION,
				       GTK_BUTTONS_CANCEL,
				       _("A file named \"%s\" already exists."), path);
      gtk_dialog_add_buttons (GTK_DIALOG (dialog), "_Replace", GTK_RESPONSE_OK, NULL);
      gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog),
						_("Do you want to replace it with the one you are saving?"));
      response = gtk_dialog_run (GTK_DIALOG (dialog));
      gtk_widget_destroy (dialog);
      if (response == GTK_RESPONSE_OK)
	export_to_file (impl, path, properties, routes, connection_name);
    }
  }      

  g_free (path);

  return TRUE;
}

static NetworkManagerVpnUI* 
impl_get_object (void)
{
  char *glade_file;
  NetworkManagerVpnUIImpl *impl;

  impl = g_new0 (NetworkManagerVpnUIImpl, 1);

  glade_file = g_strdup_printf ("%s/%s", GLADEDIR, "nm-openvpn-dialog.glade");
  impl->xml = glade_xml_new (glade_file, NULL, GETTEXT_PACKAGE);
  g_free( glade_file );
  if (impl->xml != NULL) {

    impl->widget = glade_xml_get_widget(impl->xml, "nm-openvpn-widget");

    impl->w_connection_name        = GTK_ENTRY (glade_xml_get_widget (impl->xml, "openvpn-connection-name"));
    impl->w_remote                = GTK_ENTRY (glade_xml_get_widget (impl->xml, "openvpn-remote"));
    impl->w_use_routes             = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "openvpn-use-routes"));
    impl->w_routes                 = GTK_ENTRY (glade_xml_get_widget (impl->xml, "openvpn-routes"));
    impl->w_opt_info_expander      = GTK_EXPANDER (glade_xml_get_widget (impl->xml, 
									 "openvpn-optional-information-expander"));
    impl->w_import_button          = GTK_BUTTON (glade_xml_get_widget (impl->xml, 
								       "openvpn-import-button"));

    impl->w_ca                     = GTK_ENTRY( glade_xml_get_widget( impl->xml, "openvpn-ca" ) );
    impl->w_cert                   = GTK_ENTRY( glade_xml_get_widget( impl->xml, "openvpn-cert" ) );
    impl->w_key                    = GTK_ENTRY( glade_xml_get_widget( impl->xml, "openvpn-key" ) );

    impl->w_button_ca              = GTK_BUTTON( glade_xml_get_widget( impl->xml, "openvpn-but-ca" ) );
    impl->w_button_cert            = GTK_BUTTON( glade_xml_get_widget( impl->xml, "openvpn-but-cert" ) );
    impl->w_button_key             = GTK_BUTTON( glade_xml_get_widget( impl->xml, "openvpn-but-key" ) );

    impl->w_use_lzo                = GTK_CHECK_BUTTON (glade_xml_get_widget (impl->xml, "openvpn-use-lzo"));

    impl->callback                 = NULL;

    gtk_signal_connect (GTK_OBJECT (impl->w_use_routes), 
			"toggled", GTK_SIGNAL_FUNC (use_routes_toggled), impl);

    gtk_signal_connect (GTK_OBJECT (impl->w_connection_name), 
			"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
    gtk_signal_connect (GTK_OBJECT (impl->w_remote), 
			"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
    gtk_signal_connect (GTK_OBJECT (impl->w_routes), 
			"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
    gtk_signal_connect (GTK_OBJECT (impl->w_ca), 
			"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
    gtk_signal_connect (GTK_OBJECT (impl->w_cert), 
			"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
    gtk_signal_connect (GTK_OBJECT (impl->w_key), 
			"changed", GTK_SIGNAL_FUNC (editable_changed), impl);
    
    
    gtk_signal_connect (GTK_OBJECT (impl->w_button_ca), 
			"clicked", GTK_SIGNAL_FUNC (open_button_clicked), impl);
    gtk_signal_connect (GTK_OBJECT (impl->w_button_cert), 
			"clicked", GTK_SIGNAL_FUNC (open_button_clicked), impl);
    gtk_signal_connect (GTK_OBJECT (impl->w_button_key), 
			"clicked", GTK_SIGNAL_FUNC (open_button_clicked), impl);

    gtk_signal_connect (GTK_OBJECT (impl->w_import_button), 
			"clicked", GTK_SIGNAL_FUNC (import_button_clicked), impl);

    /* make the widget reusable */
    gtk_signal_connect (GTK_OBJECT (impl->widget), "delete-event", 
			GTK_SIGNAL_FUNC (gtk_widget_hide_on_delete), NULL);
    
    openvpn_clear_widget (impl);

    impl->parent.get_display_name              = impl_get_display_name;
    impl->parent.get_service_name              = impl_get_service_name;
    impl->parent.get_widget                    = impl_get_widget;
    impl->parent.get_connection_name           = impl_get_connection_name;
    impl->parent.get_properties                = impl_get_properties;
    impl->parent.get_routes                    = impl_get_routes;
    impl->parent.set_validity_changed_callback = impl_set_validity_changed_callback;
    impl->parent.is_valid                      = impl_is_valid;
    impl->parent.get_confirmation_details      = impl_get_confirmation_details;
    impl->parent.can_export                    = impl_can_export;
    impl->parent.import_file                   = impl_import_file;
    impl->parent.export                        = impl_export;
    impl->parent.data                          = impl;
    
    return &(impl->parent);
  } else {
    g_free (impl);
    return NULL;
  }
}

NetworkManagerVpnUI* 
nm_vpn_properties_factory (void)
{
	return impl_get_object();
}
