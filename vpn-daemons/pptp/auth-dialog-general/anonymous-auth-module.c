#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n-lib.h>
#include <string.h>
#include <glade/glade.h>

#define GNOME_GENERIC_AUTH_MODULE_SUBJECT_TO_CHANGE
#include "gnome-generic-auth-module.h"

/* Stuff to be provided by the specific instance */
typedef struct _GnomeGenericAuthModuleImpl GnomeGenericAuthModuleImpl;

struct _GnomeGenericAuthModuleImpl {
  GnomeGenericAuthModule parent;

  GladeXML *xml;

  GtkWidget *widget;

//  GtkEntry       *w_connection_name;
//  GtkEntry       *w_remote;
};

#define GLADE_FILE "nm-ppp-auth.glade"
#define GLADE_WIDGET "auth-none-widget"

#define AUTH_TYPE "NONE"
#define AUTH_TYPE_DISPLAY_NAME "None (Anonymous)"


void 
impl_clear_widget (GnomeGenericAuthModuleImpl *impl)
{
//  g_return_if_fail(impl!=NULL);
}

static const char *
impl_get_display_name (GnomeGenericAuthModule *self)
{
  return AUTH_TYPE_DISPLAY_NAME;
}


static const char *
impl_get_auth_type (GnomeGenericAuthModule *self)
{
  return AUTH_TYPE; 
}

static GtkWidget *
impl_get_widget (GnomeGenericAuthModule *self)
{
  GnomeGenericAuthModuleImpl *impl = (GnomeGenericAuthModuleImpl *) self->data;

  impl_clear_widget (impl);
//
//  if (connection_name != NULL) {
//      if ((opt = impl->connection_name_opt) != NULL) {
//        vpnui_opt_set(opt,connection_name);
//      }
//  }
//
//  for (item=properties; item != NULL; item = g_slist_next(g_slist_next(item)))
//  {
//    if (item->data==NULL) continue;
//    if ((g_slist_next(item))->data==NULL) continue;
//    opt = impl_opt_bygconf(impl,(char *)item->data);
//    if (opt==NULL) continue;
//    vpnui_opt_set(opt, (char *)(g_slist_next(item))->data);
//  }
//
//  if (routes != NULL) {
//    GString *route_str;
//    char *str;
//
//    route_str = g_string_new ("");
//    for (item = routes; item != NULL; item = g_slist_next (item)) {
//      if (item != routes) g_string_append_c(route_str, ' ');
//      g_string_append(route_str, (const char *) item->data);
//    }
//    str = g_string_free (route_str, FALSE);
//
//    vpnui_opt_set(impl->routes_opt,str);
//    vpnui_opt_set(impl->routes_toggle_opt,"yes");
//    g_free (str);
//  }
//
//  vpnui_expand_reset_all(impl);
//
  return impl->widget;
}

static GnomeGenericAuthModule* 
impl_get_object (void)
{
  char *glade_file;
  GnomeGenericAuthModuleImpl *impl;

  impl = g_new0 (GnomeGenericAuthModuleImpl, 1);

  glade_file = g_strdup_printf ("%s/%s", GLADEDIR, GLADE_FILE);
  impl->xml = glade_xml_new (glade_file, NULL, GETTEXT_PACKAGE);
  g_free( glade_file );
  if (impl->xml != NULL) {

  impl->widget = glade_xml_get_widget(impl->xml, GLADE_WIDGET);

//  impl_setup(impl);

//  impl->callback                 = NULL;

//    if (impl->w_import_button!=NULL) {
//      g_signal_connect (GTK_OBJECT (impl->w_import_button), 
//			"clicked", G_CALLBACK (import_button_clicked), impl);
//    }
//
//    /* make the widget reusable */
//    g_signal_connect (GTK_OBJECT (impl->widget), "delete-event", 
//			G_CALLBACK (gtk_widget_hide_on_delete), NULL);
//    
    impl_clear_widget (impl);

    impl->parent.get_display_name              = impl_get_display_name;
    impl->parent.get_auth_type                 = impl_get_auth_type;
    impl->parent.get_widget                    = impl_get_widget;
    impl->parent.data                          = impl;
    
    return &(impl->parent);
  } else {
    g_free (impl);
    return NULL;
  }
}

const char *
get_auth_type (void)
{
  return AUTH_TYPE; 
}

GnomeGenericAuthModule* 
gnome_generic_auth_module_factory (void)
{
	return impl_get_object();
}


