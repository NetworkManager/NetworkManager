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

  GtkEntry       *w_remotename;
  GtkEntry       *w_username;
  GtkEntry       *w_password;

};

#define GLADE_FILE "nm-ppp-auth.glade"
#define GLADE_WIDGET "auth-mschapv2-widget"

#define AUTH_TYPE "MSCHAPV2"
#define AUTH_TYPE_DISPLAY_NAME "MS CHAP V2"


static void 
clear_widget (GnomeGenericAuthModuleImpl *impl)
{
   gtk_entry_set_text(impl->w_username,"");
   gtk_entry_set_text(impl->w_password,"");
   gtk_widget_grab_focus (GTK_WIDGET(impl->w_username));
}

static void 
goto_next (GtkWidget *widget,gpointer data)
{
   GnomeGenericAuthModuleImpl *impl = (GnomeGenericAuthModuleImpl *) data;
g_warning("Goto next!");
   if (strcmp(gtk_widget_get_name(widget),"remotename")==0) {
     gtk_widget_grab_focus (GTK_WIDGET(impl->w_username));
   } else if (strcmp(gtk_widget_get_name(widget),"username")==0) {
     gtk_widget_grab_focus (GTK_WIDGET(impl->w_password));
   } else if (strcmp(gtk_widget_get_name(widget),"password")==0) {
   }
}

static gboolean
impl_set_user (GnomeGenericAuthModule *self, const char *user)
{
  GnomeGenericAuthModuleImpl *impl = (GnomeGenericAuthModuleImpl *) self->data;

  gtk_entry_set_text(impl->w_username,user);
  return TRUE;
}

static const char *
impl_get_user (GnomeGenericAuthModule *self)
{
  GnomeGenericAuthModuleImpl *impl = (GnomeGenericAuthModuleImpl *) self->data;

  return gtk_entry_get_text(impl->w_username);
}

static gboolean
impl_set_secret (GnomeGenericAuthModule *self, const char *object, const char *secret)
{
  GnomeGenericAuthModuleImpl *impl = (GnomeGenericAuthModuleImpl *) self->data;

g_warning("Setting secret: %s=%s",object,secret);
  if (strcmp(object,"remotename")==0) {
    gtk_entry_set_text(impl->w_remotename,secret);
  } else if (strcmp(object,"password")==0) {
    gtk_entry_set_text(impl->w_password,secret);
  } else {
    return FALSE;
  }

  return TRUE;
}

static GSList *
impl_get_secrets (GnomeGenericAuthModule *self)
{
  GnomeGenericAuthModuleImpl *impl = (GnomeGenericAuthModuleImpl *) self->data;
  GSList *secrets=NULL;

  secrets = 
    g_slist_append(secrets, g_strdup("password"));
  secrets = 
    g_slist_append(secrets, g_strdup(gtk_entry_get_text(impl->w_password)));
  secrets = 
    g_slist_append(secrets, g_strdup("remotename"));
  secrets = 
    g_slist_append(secrets, g_strdup(gtk_entry_get_text(impl->w_remotename)));

  return secrets;
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

  clear_widget (impl);

  return impl->widget;
}

static GnomeGenericAuthModule* 
impl_get_object (void)
{
  char *glade_file;
  GnomeGenericAuthModuleImpl *impl;
//  GtkWidget *w;

  impl = g_new0 (GnomeGenericAuthModuleImpl, 1);
  glade_file = g_strdup_printf ("%s/%s", GLADEDIR, GLADE_FILE);
  impl->xml = glade_xml_new (glade_file, NULL, GETTEXT_PACKAGE);
  g_free( glade_file );
  if (impl->xml != NULL) {

    impl->widget = glade_xml_get_widget(impl->xml, GLADE_WIDGET);

    /* make the widget reusable */
    gtk_signal_connect (GTK_OBJECT (impl->widget), "delete-event", 
			GTK_SIGNAL_FUNC (gtk_widget_hide_on_delete), NULL);

   	impl->w_remotename = GTK_ENTRY(glade_xml_get_widget(impl->xml,"remotename"));
   	impl->w_username = GTK_ENTRY(glade_xml_get_widget(impl->xml,"username"));
   	impl->w_password = GTK_ENTRY(glade_xml_get_widget(impl->xml,"password"));

   	g_signal_connect (impl->w_remotename, "activate", G_CALLBACK (goto_next), impl);
   	g_signal_connect (impl->w_username, "activate", G_CALLBACK (goto_next), impl);
   	g_signal_connect (impl->w_password, "activate", G_CALLBACK (goto_next), impl);
   
    gtk_widget_show_all(impl->widget); 
    clear_widget (impl);

    impl->parent.get_user          = impl_get_user;
    impl->parent.set_user          = impl_set_user;
    impl->parent.get_secrets       = impl_get_secrets;
    impl->parent.set_secret        = impl_set_secret;
    impl->parent.get_display_name  = impl_get_display_name;
    impl->parent.get_auth_type     = impl_get_auth_type;
    impl->parent.get_widget        = impl_get_widget;
    impl->parent.data              = impl;
    
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


