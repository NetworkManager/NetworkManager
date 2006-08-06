#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n-lib.h>
#include <string.h>
#include <glade/glade.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE
#include <NetworkManager/nm-vpn-ui-interface.h>

#define NMVPNUI_IMPL_C
#include "vpnui_impl.h"
#include "vpnui_expand.h"
#include "vpnui_opt.h"

/* Stuff to be provided by the specific instance */
extern const char *GLADE_FILE;
extern const char *GLADE_WIDGET;
extern void impl_setup (NetworkManagerVpnUIImpl *impl);
extern void impl_hide_and_show (NetworkManagerVpnUIImpl *impl);

static void 
impl_set_validity_changed_callback (NetworkManagerVpnUI *self, 
				    NetworkManagerVpnUIDialogValidityCallback callback,
				    gpointer user_data)
{
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;

  impl->callback = callback;
  impl->callback_user_data = user_data;
}


void 
impl_clear_widget (NetworkManagerVpnUIImpl *impl)
{
  GSList *item;

  g_return_if_fail(impl!=NULL);

  if (impl->connection_name_opt!=NULL) vpnui_opt_set(impl->connection_name_opt,"");
  if (impl->variant_combo!=NULL) gtk_combo_box_set_active(impl->variant_combo,-1);
  if (impl->defaults!=NULL)
    for (item=impl->config_options; item != NULL; item = g_slist_next(item))
    {
      vpnui_opt_set_default((VpnUIConfigOption *)item->data, impl->defaults);
    }

//  vpnui_expand_reset_all(impl);
  impl_hide_and_show(impl); 
}

static const char *
impl_get_display_name (NetworkManagerVpnUI *self)
{
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
  return impl->display_name;
}

static const char *
impl_get_service_name (NetworkManagerVpnUI *self)
{
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
  return impl->service_name; 
}

static GtkWidget *
impl_get_widget (NetworkManagerVpnUI *self, GSList *properties, GSList *routes, const char *connection_name)
{
  GSList *item;
  VpnUIConfigOption *opt;
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;

  impl_clear_widget (impl);

  if (connection_name != NULL) {
      if ((opt = impl->connection_name_opt) != NULL) {
        vpnui_opt_set(opt,connection_name);
      }
  }

  for (item=properties; item != NULL; item = g_slist_next(g_slist_next(item)))
  {
    if (item->data==NULL) continue;
    if ((g_slist_next(item))->data==NULL) continue;
    opt = impl_opt_bygconf(impl,(char *)item->data);
    if (opt==NULL) continue;
    vpnui_opt_set(opt, (char *)(g_slist_next(item))->data);
  }

  if (routes != NULL) {
    GString *route_str;
    char *str;

    route_str = g_string_new ("");
    for (item = routes; item != NULL; item = g_slist_next (item)) {
      if (item != routes) g_string_append_c(route_str, ' ');
      g_string_append(route_str, (const char *) item->data);
    }
    str = g_string_free (route_str, FALSE);

    if(impl->routes_opt!=NULL) vpnui_opt_set(impl->routes_opt,str);
    if(impl->routes_toggle_opt!=NULL) vpnui_opt_set(impl->routes_toggle_opt,"yes");
    g_free (str);
  }

//  vpnui_expand_reset_all(impl);
  impl_hide_and_show(impl); 

  return impl->widget;
}

static GSList *
impl_get_properties (NetworkManagerVpnUI *self)
{
  GSList *data;
  GSList *item;
  VpnUIConfigOption *opt;
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;

  data = NULL;
  for (item=impl->config_options; item != NULL; item = g_slist_next(item))
  {
    opt = (VpnUIConfigOption *)item->data;
    if (opt==NULL) continue;
    if (opt->gconf_name==NULL) continue;
    if (!opt->active) continue;

    data = g_slist_append (data, g_strdup(opt->gconf_name));
    data = g_slist_append (data, g_strdup(vpnui_opt_get(opt)));
  }

  return data;
}

static GSList *
get_routes (NetworkManagerVpnUIImpl *impl)
{
  GSList *routes;
  const char *routes_entry;
  const char *use_routes;
  char **substrs;
  unsigned int i;
  VpnUIConfigOption *opt;

  routes = NULL;

  opt = impl_opt_byglade(impl,"routes");
  g_return_val_if_fail(opt!=NULL,NULL);
  if (!opt->active) return NULL;
  routes_entry = vpnui_opt_get(opt);

  opt = impl_opt_byglade(impl,"use-routes");
  g_return_val_if_fail(opt!=NULL,NULL);
  use_routes = vpnui_opt_get(impl_opt_byglade(impl,"use-routes"));

  if (strcmp("no",use_routes)==0) {
    goto out;
  }

  substrs = g_strsplit (routes_entry, " ", 0);
  for (i = 0; substrs[i] != NULL; i++) {
    char *route;

    if (strlen(substrs[i]) > 0)
      routes = g_slist_append (routes, g_strdup (substrs[i]));
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
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;

  return g_strdup( vpnui_opt_get(impl->connection_name_opt) );
}


gboolean
impl_is_valid (NetworkManagerVpnUI *self)
{
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
  GSList *item;
  gboolean is_valid;
  VpnUIConfigOption *opt;

  is_valid = TRUE;
  for (item=impl->config_options; item != NULL; item = g_slist_next(item))
  {
    opt = (VpnUIConfigOption *)item->data;
    if (opt==NULL) continue;
    if (!opt->active) continue;
    is_valid &= vpnui_opt_validate(opt);
    if (!is_valid) return is_valid;
  }

  return is_valid;
}



static void
impl_get_confirmation_details (NetworkManagerVpnUI *self, gchar **retval)
{
  GString *buf;
  GSList *item;
  const char *value;
  VpnUIConfigOption *opt;
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
  
  // This is risky, should be variable length depending on actual data!
  buf = g_string_sized_new (1024);

  g_string_append_printf (buf, _("The following '%s' connection will be created:"), impl->display_name);
  g_string_append (buf, "\n\n");
  for (item=impl->config_options; item != NULL; item = g_slist_next(item))
  {
    opt = (VpnUIConfigOption *)item->data;
    if (opt==NULL) continue;
    if (opt->description==NULL) continue;
    if (!opt->active) continue;

    value = vpnui_opt_get(opt);
    if (value==NULL) continue;
    if (strlen(value)==0) continue;
    
    g_string_append_printf (buf, _("\t%s:  %s\n"), opt->description, value);
  }

  g_string_append (buf, _("The connection details can be changed using the \"Back\" button."));
  g_string_append (buf, "\n");

  *retval = g_string_free (buf, FALSE);
}

static gboolean
import_from_file (NetworkManagerVpnUIImpl *impl, const char *path)
{
  char *basename;
  GKeyFile *keyfile;
  VpnUIConfigOption *opt;
  GSList *item;
  gboolean file_is_good;

  file_is_good = FALSE;
  basename = g_path_get_basename (path);

  keyfile = g_key_file_new ();
  if (g_key_file_load_from_file (keyfile, path, 0, NULL)) {
    char *value = NULL;

    for (item=impl->config_options; item != NULL; item = g_slist_next(item))
    {
      opt = (VpnUIConfigOption *)item->data;
      if (opt==NULL) continue;
      if (opt->export_name==NULL) continue;

      value = g_key_file_get_string (keyfile, "main", opt->export_name, NULL);
      vpnui_opt_set(opt,value);
      g_free (value);
    }
    g_key_file_free (keyfile);
  }

  g_free (basename);

  impl_hide_and_show(impl); 

  return file_is_good;

//    if (!file_is_good) {
//      GtkWidget *dialog;
//		
//      dialog = gtk_message_dialog_new (NULL,
//				       GTK_DIALOG_DESTROY_WITH_PARENT,
//				       GTK_MESSAGE_WARNING,
//				       GTK_BUTTONS_CLOSE,
//				       _("Cannot import settings"));
//      gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog),
//						_("The VPN settings file '%s' does not contain valid data."), basename);
//      gtk_dialog_run (GTK_DIALOG (dialog));
//      gtk_widget_destroy (dialog);
//    }
}

static void
show_widget (GtkWidget *widget, gpointer user_data)
{
  g_warning("Widget show event");

  impl_hide_and_show((NetworkManagerVpnUIImpl *) user_data);
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
  GSList *item;
  VpnUIConfigOption *opt;
//  gboolean use_routes = FALSE;
  const char *export = NULL;
  const char *value = NULL;
  char *routes_str = NULL;

  f = fopen (path, "w");
  if (f == NULL) return;

  /* Print the header */
  fprintf (f, "[main]\n");

  /* Handle the connection-name */
  if (connection_name != NULL) {
    opt = impl_opt_byglade(impl,"connection-name");
    if (opt != NULL ) {
      export = opt->export_name;
      value = connection_name;
      if ((export != NULL ) && (value!=NULL) ) {
        fprintf (f, "%s=%s\n",export,value);
      }
    }
  }

  for (item=properties; item != NULL; item = g_slist_next(g_slist_next(item)))
  {
    if (item->data==NULL) continue;
    if ((g_slist_next(item))->data==NULL) continue;
    opt = impl_opt_bygconf(impl,(char *)item->data);
    if (opt==NULL) continue;
    vpnui_opt_set(opt, (char *)(g_slist_next(item))->data);
  }

  if (routes != NULL) {
    GString *route_str;
    char *str;

    route_str = g_string_new ("");
    for (item = routes; item != NULL; item = g_slist_next (item)) {
      if (item != routes) g_string_append_c(route_str, ' ');
      g_string_append(route_str, (const char *) item->data);
    }
    str = g_string_free (route_str, FALSE);

    if (impl->routes_opt!=NULL) vpnui_opt_set(impl->routes_opt,str);
    if (impl->routes_toggle_opt!=NULL) vpnui_opt_set(impl->routes_toggle_opt,"yes");
    g_free (str);
  }

  /* Loop over properties and print them out */
  for (item=properties; item != NULL; item = g_slist_next(g_slist_next(item)))
  {
    if (item->data==NULL) continue;
    if ((g_slist_next(item))->data==NULL) continue;

//    if (strcmp("use_routes",item->data)==0) {
//      if (strcmp("yes",(g_slist_next(item))->data)==0) use_routes=TRUE;
//    }

    opt = impl_opt_bygconf(impl,(char *)item->data);
    if (opt==NULL) continue;
    if (opt->export_name==NULL) continue;
    if (!opt->active) continue;

    export = opt->export_name;
    value = (const char *)(g_slist_next(item))->data;

    if ((export != NULL ) && (value!=NULL) ) {
      fprintf (f, "%s=%s\n",export,value);
    }
  }

  if (routes != NULL) {
    GString *route_str;
    char *str;

    route_str = g_string_new ("");
    for (item = routes; item != NULL; item = g_slist_next (item)) {
      if (item != routes) g_string_append_c(route_str, ' ');
      g_string_append(route_str, (const char *) item->data);
    }
    value = ( str = g_string_free (route_str, FALSE) );
    value = str;

    opt = impl_opt_byglade(impl,"routes");
    g_free (str);
    g_free (routes_str);
  }
  fclose (f);

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
    } else {
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

  glade_file = g_strdup_printf ("%s/%s", GLADEDIR, GLADE_FILE);
  impl->xml = glade_xml_new (glade_file, NULL, GETTEXT_PACKAGE);
  g_free( glade_file );
  if (impl->xml != NULL) {

    impl->widget = glade_xml_get_widget(impl->xml, GLADE_WIDGET);

    impl_setup(impl);

    impl->callback                 = NULL;

    if (impl->w_import_button!=NULL) {
      gtk_signal_connect (GTK_OBJECT (impl->w_import_button), 
			"clicked", GTK_SIGNAL_FUNC (import_button_clicked), impl);
    }

    gtk_signal_connect (GTK_OBJECT (impl->widget), 
			"show", GTK_SIGNAL_FUNC (show_widget), impl);

    /* make the widget reusable */
    gtk_signal_connect (GTK_OBJECT (impl->widget), "delete-event", 
			GTK_SIGNAL_FUNC (gtk_widget_hide_on_delete), NULL);
    
    impl_clear_widget (impl);

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


