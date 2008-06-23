/* gnome-password-dialog.c - A use password prompting dialog widget.

   Copyright (C) 2006 

   This is free software; you can redistribute it and/or modify it under 
   the terms of the GNU Library General Public License as published by 
   the Free Software Foundation; either version 2 of the License, or 
   (at your option) any later version.

   This software is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this package; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Authors: Antony J Mee <eemynotna@gmail.com>
   Based loosely on the gnome-two-password-dialog code by:
       Ramiro Estrugo <ramiro@eazel.com>
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
//#include "gnome-i18nP.h"
#define GNOME_GENERIC_AUTH_MODULE_SUBJECT_TO_CHANGE
#include "gnome-generic-auth-module.h"
#include "gnome-generic-auth-dialog.h"
//#include <gtk/gtkbox.h>
//#include <gtk/gtkcheckbutton.h>
//#include <gtk/gtkentry.h>
//#include <gtk/gtkhbox.h>
//#include <gtk/gtkimage.h>
//#include <gtk/gtklabel.h>
//#include <gtk/gtkmain.h>
//#include <gtk/gtksignal.h>
//#include <gtk/gtkstock.h>
//#include <gtk/gtktable.h>
//#include <gtk/gtkvbox.h>
//#include <gtk/gtkradiobutton.h>
//#include <gtk/gtkstock.h>
#include <string.h>
#include <glib.h>

#include <glib/gi18n.h>
#include <gtk/gtk.h>
#define GNOME_GENERIC_AUTH_DIALOG_MODULES_DIR AUTH_MODULES_DIR

/* Layout constants */
static const guint DIALOG_BORDER_WIDTH = 6;
//static const guint CAPTION_TABLE_BORDER_WIDTH = 4;

struct GnomeGenericAuthDialogDetails
{
	/* Attributes */
    GSList *allowed_auth_types;

	/* Attributes */
    GSList *auth_modules;
    GnomeGenericAuthModule *current_module; 
	
	GtkWidget *remember_session_button;
	GtkWidget *remember_forever_button;

	GtkWidget *current_widget;
	GtkWidget *widget_holder;
	GtkWidget *current_widget_old_parent;
	GtkComboBox *auth_type_combo;


    char *user;
    char *domain;
    char *server;
    char *protocol;
    guint32 port;

    gboolean found_multiple_types;

	/* TODO: */
//	gboolean can_remember_1;
//	char *remember_label_text2;
//	gboolean can_remember_2;
//	char *remember_label_text2;

};


/* GnomeGenericAuthDialogClass methods */
static void gnome_generic_auth_dialog_class_init (GnomeGenericAuthDialogClass *dialog);
static void gnome_generic_auth_dialog_init       (GnomeGenericAuthDialog      *dialog);

/* GObjectClass methods */
static void gnome_generic_auth_dialog_finalize         (GObject                *object);


/* GtkDialog callbacks */
//static void dialog_show_callback                 (GtkWidget              *widget,
//						  gpointer                callback_data);
static void dialog_close_callback                (GtkWidget              *widget,
						  gpointer                callback_data);

static gpointer parent_class;

GType
gnome_generic_auth_dialog_get_type (void)
{
	static GType type = 0;

	if (!type) {
		static const GTypeInfo info = {
			sizeof (GnomeGenericAuthDialogClass),
                        NULL, NULL,
			(GClassInitFunc) gnome_generic_auth_dialog_class_init,
                        NULL, NULL,
			sizeof (GnomeGenericAuthDialog), 0,
			(GInstanceInitFunc) gnome_generic_auth_dialog_init,
			NULL
		};

        type = g_type_register_static (gtk_dialog_get_type(), 
					       "GnomeGenericAuthDialog", 
					       &info, 0);

		parent_class = g_type_class_ref (gtk_dialog_get_type());
	}

	return type;
}

static void save_to_keyring_as_needed(GnomeGenericAuthDialog *dialog)
{
	switch (gnome_generic_auth_dialog_get_remember (dialog))
	{
		case GNOME_GENERIC_AUTH_DIALOG_REMEMBER_SESSION:
//			save_auth_info (connection_name, service_name, "session", auth_type, username, password);
			break;
		case GNOME_GENERIC_AUTH_DIALOG_REMEMBER_FOREVER:
//			save_auth_info (connection_name, service_name, NULL, auth_type, username, password);
			break;
		default:
			break;
	}
}

static void load_module (GnomeGenericAuthDialog *dialog, const char *path)
{
	GModule *module;
	GnomeGenericAuthModule* (*module_factory) (void) = NULL;
	const char* (*module_get_auth_type) (void) = NULL;
	GnomeGenericAuthModule* impl;
    gboolean allowed = FALSE;
    const char *provided_auth_type;

	module = g_module_open (path, G_MODULE_BIND_LAZY);
	if (module == NULL) {
		g_warning ("Cannot open module '%s'", path);
		goto out;
	}

	if (!g_module_symbol (module, "get_auth_type", 
			      (gpointer) &module_get_auth_type)) {
		g_warning ("Cannot locate function 'get_auth_type' in '%s': %s", 
			   path, g_module_error ());
		g_module_close (module);
		goto out;		
	}

	provided_auth_type = module_get_auth_type ();
    if (dialog->details->allowed_auth_types==NULL) {
      allowed=TRUE;
    } else {
      GSList *item;
      for (item=dialog->details->allowed_auth_types; item!=NULL; item=g_slist_next(item)) {
        if ((item->data!=NULL) && (strcmp(item->data,provided_auth_type)==0)) {
          allowed=TRUE;
          break;
        }
      }
    }
    if (!allowed) goto out;

	if (!g_module_symbol (module, "gnome_generic_auth_module_factory", 
			      (gpointer) &module_factory)) {
		g_warning ("Cannot locate function 'gnome_generic_auth_module_factory' in '%s': %s", 
			   path, g_module_error ());
		g_module_close (module);
		goto out;		
	}

	impl = module_factory ();
	if (impl == NULL) {
		g_warning ("Function 'gnome_generic_auth_widget_factory' in '%s' returned NULL", path);
		g_module_close (module);
		goto out;
	}

// Inflict some state upon the module!
    impl->override_user=(dialog->details->user!=NULL);
    impl->override_domain=(dialog->details->user!=NULL);
    impl->override_server=(dialog->details->user!=NULL);
    impl->override_protocol=(dialog->details->user!=NULL);
    impl->override_port=(dialog->details->port!=0);

	dialog->details->auth_modules = g_slist_append (dialog->details->auth_modules, impl);

out:
	;
}

static void 
load_all_modules (GnomeGenericAuthDialog *dialog)
{
	GDir *dir;

	/* Load all VPN UI modules by inspecting .name files */
	if ((dir = g_dir_open (GNOME_GENERIC_AUTH_DIALOG_MODULES_DIR, 0, NULL)) != NULL) {
		const char *f;

		while ((f = g_dir_read_name (dir)) != NULL) {
			char *so_path;
//			GKeyFile *keyfile;

			if (!g_str_has_suffix (f, ".so"))
				continue;

			so_path = g_strdup_printf ("%s/%s", GNOME_GENERIC_AUTH_DIALOG_MODULES_DIR, f);

			load_module (dialog, so_path);
			g_free (so_path);
		}
		g_dir_close (dir);
	}
}

static void
gnome_generic_auth_dialog_class_init (GnomeGenericAuthDialogClass * klass)
{
	G_OBJECT_CLASS (klass)->finalize = gnome_generic_auth_dialog_finalize;
}

static void
gnome_generic_auth_dialog_init (GnomeGenericAuthDialog *dialog)
{
	dialog->details = g_new0 (GnomeGenericAuthDialogDetails, 1);
	dialog->details->auth_modules = NULL;
	dialog->details->allowed_auth_types = NULL;

//	dialog->details->secondary_password_label = g_strdup ( _("_Secondary Password:") );
}

/* GObjectClass methods */
static void
gnome_generic_auth_dialog_finalize (GObject *object)
{
	GnomeGenericAuthDialog *dialog;
	
	dialog = GNOME_GENERIC_AUTH_DIALOG (object);

//	g_object_unref (dialog->details->username_entry);
//	g_object_unref (dialog->details->domain_entry);
//	g_object_unref (dialog->details->password_entry);
//	g_object_unref (dialog->details->password_entry_secondary);

    if (dialog->details->allowed_auth_types != NULL) {
      g_slist_foreach(dialog->details->allowed_auth_types,(GFunc)g_free,NULL);
      g_slist_free(dialog->details->allowed_auth_types);
    }
//    g_slist_foreach(dialog->details->auth_modules,(GFunc)destroy_auth_method,NULL)
    if (dialog->details->auth_modules != NULL) {
      g_slist_foreach(dialog->details->auth_modules,(GFunc)g_free,NULL);
      g_slist_free(dialog->details->auth_modules);
    }

	if (G_OBJECT_CLASS (parent_class)->finalize != NULL)
		(* G_OBJECT_CLASS (parent_class)->finalize) (object);
}

static void auth_widget_reparent(GnomeGenericAuthDialog *dialog, GtkWidget *new_parent)
{
  if (dialog->details->current_widget==NULL) {
    if (dialog->details->current_widget_old_parent!=NULL) {
      g_error("parent previously was not restored to widget");
    }
    return;
  }
  if ((new_parent==NULL) && (dialog->details->current_widget_old_parent==NULL)) {
    return;
  } else if (new_parent==NULL) {
    gtk_widget_reparent(dialog->details->current_widget,dialog->details->current_widget_old_parent);
    dialog->details->current_widget_old_parent=NULL;
    return;
  } else if (dialog->details->current_widget_old_parent==NULL) {
    dialog->details->current_widget_old_parent=gtk_widget_get_parent(dialog->details->current_widget);
  }

  gtk_widget_reparent(dialog->details->current_widget,new_parent);
}

static void auth_widget_get_current(GnomeGenericAuthDialog *dialog)
{
    GSList *auth_modules;

    if (dialog->details->current_widget!=NULL) {
        auth_widget_reparent(dialog,NULL);
        dialog->details->current_widget=NULL;
    }

    auth_modules=dialog->details->auth_modules;

    if (dialog->details->current_module != NULL) {
        dialog->details->current_widget = dialog->details->current_module->get_widget (dialog->details->current_module);
    }
}

static void
dialog_close_callback (GtkWidget *widget, gpointer user_data)
{
	GnomeGenericAuthDialog *dialog = (GnomeGenericAuthDialog *) user_data;

    auth_widget_reparent(dialog,NULL); 
	gtk_widget_hide (widget);
}

static void
auth_type_changed_callback (GtkWidget *widget, gpointer user_data) 
{
	GnomeGenericAuthDialog *dialog = (GnomeGenericAuthDialog *) user_data;
    GList *i;
    GList *children;
    GtkWidget *w;
    GSList *auth_modules;
    GtkWidget *widget_holder;
//    GtkWidget *widget_holder_parent;
    GtkComboBox *auth_type_combo;

    auth_modules=dialog->details->auth_modules;
    widget_holder = dialog->details->widget_holder;
    auth_type_combo = dialog->details->auth_type_combo;

    g_return_if_fail(widget_holder!=NULL);
    g_return_if_fail(GTK_IS_CONTAINER(widget_holder));

    auth_widget_reparent(dialog,NULL);

	/* show appropriate child */
	dialog->details->current_module = (GnomeGenericAuthModule *) 
            g_slist_nth_data (auth_modules, 
                 gtk_combo_box_get_active (GTK_COMBO_BOX(auth_type_combo)));
	if (dialog->details->current_module == NULL) return;

    auth_widget_get_current(dialog);
    auth_widget_reparent(dialog,dialog->details->widget_holder);

//    dialog->details->current_module->set_validity_changed_callback (
//          dialog->details->current_module, 
//          auth_widget_validity_changed, NULL);
}

gboolean
gnome_generic_auth_dialog_set_secret (GnomeGenericAuthDialog	*dialog, const char *object, const char *secret)
{
    GnomeGenericAuthModule *module;

    g_return_val_if_fail(dialog!=NULL,FALSE);
    g_return_val_if_fail(dialog->details!=NULL,FALSE);
    module = dialog->details->current_module;
    g_return_val_if_fail(module!=NULL,FALSE);
    g_return_val_if_fail(module->set_secret!=NULL,FALSE);

    return module->set_secret(module,object,secret); 
}

const char *
gnome_generic_auth_dialog_get_secret (GnomeGenericAuthDialog *dialog, const char *object)
{
    GnomeGenericAuthModule *module;
    GSList *item;
    GSList *secrets;
    const char *secret=NULL;

    g_return_val_if_fail(dialog!=NULL,NULL);
    g_return_val_if_fail(dialog->details!=NULL,NULL);
    module = dialog->details->current_module;
    g_return_val_if_fail(module!=NULL,NULL);
    g_return_val_if_fail(module->get_secrets!=NULL,NULL);

    secrets=module->get_secrets(module);

    for(item=secrets; 
        (item!=NULL) && (g_slist_next(item)!=NULL) ;
        item=g_slist_next(g_slist_next(item))) {
      if (strcmp(object,(const char *)item->data)==0) {
        secret=(const char *)(g_slist_next(item)->data);
        break;
      }
    }

    g_slist_free(secrets);
    return secret;
}

gboolean
gnome_generic_auth_dialog_set_secrets (GnomeGenericAuthDialog	*dialog, GSList *secrets)
{
    GnomeGenericAuthModule *module;
    GSList *item;
    gboolean result = TRUE;
    const char *object;
    const char *secret;

    g_return_val_if_fail(dialog!=NULL,FALSE);
    g_return_val_if_fail(dialog->details!=NULL,FALSE);
    module = dialog->details->current_module;
    g_return_val_if_fail(module!=NULL,FALSE);
    g_return_val_if_fail(module->set_secret!=NULL,FALSE);

    for(item=secrets; 
        (item!=NULL) && (g_slist_next(item)!=NULL) ;
        item=g_slist_next(g_slist_next(item))) {
      object=(const char *)(item->data);
      secret=(const char *)(g_slist_next(item)->data);
      result &= module->set_secret(module,object,secret); 
    }
    return result;
}

GSList *
gnome_generic_auth_dialog_get_secrets (GnomeGenericAuthDialog	*dialog)
{
    GnomeGenericAuthModule *module;

    g_return_val_if_fail(dialog!=NULL,NULL);
    g_return_val_if_fail(dialog->details!=NULL,NULL);
    module = dialog->details->current_module;
    g_return_val_if_fail(module!=NULL,NULL);
    g_return_val_if_fail(module->get_secrets!=NULL,NULL);

    return module->get_secrets(module); 
}

gboolean
gnome_generic_auth_dialog_set_user (GnomeGenericAuthDialog	*dialog, const char *user)
{
    GnomeGenericAuthModule *module;

    g_return_val_if_fail(dialog!=NULL,FALSE);
    g_return_val_if_fail(dialog->details!=NULL,FALSE);
    if (dialog->details->user!=NULL) return FALSE;

    module = dialog->details->current_module;
    g_return_val_if_fail(module!=NULL,FALSE);
    g_return_val_if_fail(module->set_user!=NULL,FALSE);

    return module->set_user(module,user); 
}

const char *
gnome_generic_auth_dialog_get_user (GnomeGenericAuthDialog	*dialog)
{
    GnomeGenericAuthModule *module;

    g_return_val_if_fail(dialog!=NULL,NULL);
    g_return_val_if_fail(dialog->details!=NULL,NULL);
    if (dialog->details->user!=NULL) return dialog->details->user;

    module = dialog->details->current_module;
    g_return_val_if_fail(module!=NULL,NULL);
    g_return_val_if_fail(module->get_user!=NULL,NULL);

    return module->get_user(module); 
}

gboolean
gnome_generic_auth_dialog_set_domain (GnomeGenericAuthDialog	*dialog, const char *domain)
{
    GnomeGenericAuthModule *module;

    g_return_val_if_fail(dialog!=NULL,FALSE);
    g_return_val_if_fail(dialog->details!=NULL,FALSE);
    if (dialog->details->domain!=NULL) return FALSE;

    module = dialog->details->current_module;
    g_return_val_if_fail(module!=NULL,FALSE);
    g_return_val_if_fail(module->set_domain!=NULL,FALSE);

    return module->set_domain(module,domain); 
}

const char *
gnome_generic_auth_dialog_get_domain (GnomeGenericAuthDialog	*dialog)
{
    GnomeGenericAuthModule *module;

    g_return_val_if_fail(dialog!=NULL,NULL);
    g_return_val_if_fail(dialog->details!=NULL,NULL);
    if (dialog->details->domain!=NULL) return dialog->details->domain;

    module = dialog->details->current_module;
    g_return_val_if_fail(module!=NULL,NULL);
    g_return_val_if_fail(module->get_domain!=NULL,NULL);
    return module->get_domain(module); 
}

gboolean
gnome_generic_auth_dialog_set_server (GnomeGenericAuthDialog	*dialog, const char *server)
{
    GnomeGenericAuthModule *module;

    g_return_val_if_fail(dialog!=NULL,FALSE);
    g_return_val_if_fail(dialog->details!=NULL,FALSE);
    if (dialog->details->server!=NULL) return FALSE;

    module = dialog->details->current_module;
    g_return_val_if_fail(module!=NULL,FALSE);
    g_return_val_if_fail(module->set_server!=NULL,FALSE);

    return module->set_server(module,server); 
}

const char *
gnome_generic_auth_dialog_get_server (GnomeGenericAuthDialog	*dialog)
{
    GnomeGenericAuthModule *module;

    g_return_val_if_fail(dialog!=NULL,NULL);
    g_return_val_if_fail(dialog->details!=NULL,NULL);
    if (dialog->details->server!=NULL) return dialog->details->server;

    module = dialog->details->current_module;
    g_return_val_if_fail(module!=NULL,NULL);
    g_return_val_if_fail(module->get_server!=NULL,NULL);
    return module->get_server(module);
}

gboolean
gnome_generic_auth_dialog_set_port (GnomeGenericAuthDialog	*dialog, guint32 port)
{
    GnomeGenericAuthModule *module;

    g_return_val_if_fail(dialog!=NULL,FALSE);
    g_return_val_if_fail(dialog->details!=NULL,FALSE);
    if (dialog->details->port!=0) return FALSE;

    module = dialog->details->current_module;
    g_return_val_if_fail(module!=NULL,FALSE);
    g_return_val_if_fail(module->set_port!=NULL,FALSE);

    return module->set_port(module,port); 
}

guint32 
gnome_generic_auth_dialog_get_port (GnomeGenericAuthDialog	*dialog)
{
    GnomeGenericAuthModule *module;

    g_return_val_if_fail(dialog!=NULL,0);
    g_return_val_if_fail(dialog->details!=NULL,0);
    if (dialog->details->port!=0) return dialog->details->port;

    module = dialog->details->current_module;
    g_return_val_if_fail(module!=NULL,0);
    g_return_val_if_fail(module->get_port!=NULL,0);
    return module->get_port(module);
}

gboolean
gnome_generic_auth_dialog_set_protocol (GnomeGenericAuthDialog	*dialog, const char *protocol)
{
    GnomeGenericAuthModule *module;

    g_return_val_if_fail(dialog!=NULL,FALSE);
    g_return_val_if_fail(dialog->details!=NULL,FALSE);
    if (dialog->details->protocol!=NULL) return FALSE;

    module = dialog->details->current_module;
    g_return_val_if_fail(module!=NULL,FALSE);
    g_return_val_if_fail(module->set_protocol!=NULL,FALSE);

    return module->set_protocol(module,protocol); 
}

const char *
gnome_generic_auth_dialog_get_protocol (GnomeGenericAuthDialog	*dialog)
{
    GnomeGenericAuthModule *module;

    g_return_val_if_fail(dialog!=NULL,NULL);
    g_return_val_if_fail(dialog->details!=NULL,NULL);
    if (dialog->details->protocol!=NULL) return dialog->details->protocol;

    module = dialog->details->current_module;
    g_return_val_if_fail(module!=NULL,NULL);
    g_return_val_if_fail(module->get_protocol!=NULL,NULL);
    return module->get_protocol(module);
}

const char *
gnome_generic_auth_dialog_get_auth_type (GnomeGenericAuthDialog	*dialog)
{
    GnomeGenericAuthModule *module;

    g_return_val_if_fail(dialog!=NULL,NULL);
    g_return_val_if_fail(dialog->details!=NULL,NULL);
    module = dialog->details->current_module;
    g_return_val_if_fail(dialog->details->current_module!=NULL,NULL);

    return module->get_auth_type(module); 
}

gboolean
gnome_generic_auth_dialog_set_auth_type (GnomeGenericAuthDialog	*dialog,
                      const char *auth_type)
{
    GSList *item;
    int i=0;

	g_return_val_if_fail (GNOME_IS_GENERIC_AUTH_DIALOG (dialog),FALSE);
	g_return_val_if_fail (dialog->details->auth_type_combo != NULL,FALSE);

	for (item = dialog->details->auth_modules; item != NULL; item = g_slist_next (item)) {
		GnomeGenericAuthModule *auth_module = (GnomeGenericAuthModule *)item->data;
	    if (strcmp(auth_type,auth_module->get_auth_type(auth_module))==0) {
  	        gtk_combo_box_set_active (dialog->details->auth_type_combo, i);
            return TRUE;
        }
        i++;
	}
    return FALSE;
}


gboolean
gnome_generic_auth_dialog_lookup_in_keyring (GnomeGenericAuthDialog	*dialog) {
    GList *keyring_result;
    GList *item;
    const char *auth_type=NULL;
    GnomeKeyringNetworkPasswordData *data;
    const char *previous_auth_type=NULL;
    const char *first_auth_type=NULL;
    GnomeGenericAuthModule *module;


	g_return_val_if_fail (GNOME_IS_GENERIC_AUTH_DIALOG (dialog),FALSE);

    if (dialog->details->current_module!=NULL)
      auth_type = gnome_generic_auth_dialog_get_auth_type(dialog);
    if (auth_type==NULL) dialog->details->found_multiple_types=FALSE;

	if (gnome_keyring_find_network_password_sync (dialog->details->user, 
						      dialog->details->domain, 
                              dialog->details->server, 
						      NULL,                   /* object */
						      dialog->details->protocol, 
                              auth_type, 
                              dialog->details->port,
						      &keyring_result) != GNOME_KEYRING_RESULT_OK)
		return FALSE;
//    if (dialog->details->found_keys != NULL) 
//       gnome_keyring_network_password_list_free (dialog->details->found_keys);
//    found_keys=NULL;

   // Find the first auth_type we are allowed to use
   first_auth_type=NULL;
   for (item = keyring_result; item != NULL; item=g_list_next(item)) {
     data = (GnomeKeyringNetworkPasswordData *)item->data;
     if (gnome_generic_auth_dialog_set_auth_type(dialog,data->authtype)) {
       if (first_auth_type==NULL) first_auth_type=data->authtype;
       if ((previous_auth_type!=NULL) &&
              (strcmp(previous_auth_type,data->authtype)!=0)) {
         dialog->details->found_multiple_types=TRUE;
         break;
       }      
     }
   }

   if (first_auth_type==NULL) {
     gnome_keyring_network_password_list_free (keyring_result);
     return FALSE;
   }

   gnome_generic_auth_dialog_set_auth_type(dialog,first_auth_type);
   module = dialog->details->current_module;

   for (item = keyring_result; item != NULL; item=g_list_next(item)) {
     data = (GnomeKeyringNetworkPasswordData *)item->data;
     if (strcmp(data->authtype,first_auth_type)==0) {
       if (data->user!=NULL) gnome_generic_auth_dialog_set_user(dialog, data->user);
       if (data->server!=NULL) gnome_generic_auth_dialog_set_server(dialog, data->server);
       if (data->domain!=NULL) gnome_generic_auth_dialog_set_domain(dialog, data->domain);
       if (data->protocol!=NULL) gnome_generic_auth_dialog_set_protocol(dialog, data->protocol);
       if (data->port!=0) gnome_generic_auth_dialog_set_port(dialog, data->port);
       if (data->object!=NULL || data->password!=NULL) 
         gnome_generic_auth_dialog_set_secret(dialog, data->object, data->password);
       if (strcmp(data->keyring,"session")==0)
  	     gnome_generic_auth_dialog_set_remember (dialog, GNOME_GENERIC_AUTH_DIALOG_REMEMBER_SESSION);
       else
  	     gnome_generic_auth_dialog_set_remember (dialog, GNOME_GENERIC_AUTH_DIALOG_REMEMBER_FOREVER);
 

     }
   }

   gnome_keyring_network_password_list_free (keyring_result);
   return TRUE;
}

/* Public GnomeGenericAuthDialog methods */
GtkWidget *
gnome_generic_auth_dialog_new (const char	*dialog_title,
                const char	 *message,
                const char   *user,
                const char   *domain,
                const char   *server,
                const char   *protocol,
                guint32       port,
			    const char    **allowed_types)
{
	GnomeGenericAuthDialog *dialog;
	GtkWidget *widget_holder;
	GtkLabel *message_label;
	GtkLabel *auth_type_label;
    GtkWidget *auth_type_hbox;
    GtkComboBox *auth_type_combo_box;
    GtkWidget *hbox;
	GtkWidget *vbox;
	GtkWidget *dialog_icon;
	GSList *allowed_auth_types=NULL;
	GSList *item;
    const char **types;

	dialog = GNOME_GENERIC_AUTH_DIALOG (gtk_widget_new (gnome_generic_auth_dialog_get_type (), NULL));

    dialog->details->user=NULL;
    dialog->details->server=NULL;
    dialog->details->protocol=NULL;
    dialog->details->domain=NULL;
    dialog->details->port=0;
    if (user!=NULL) dialog->details->user=g_strdup(user);
    if (server!=NULL) dialog->details->server=g_strdup(server);
    if (protocol!=NULL) dialog->details->protocol=g_strdup(protocol);
    if (domain!=NULL) dialog->details->domain=g_strdup(domain);
    if (port!=0) dialog->details->port=port;

    if (allowed_types!=NULL) {
      for (types=allowed_types; *types !=NULL; *types++) {
        allowed_auth_types=g_slist_append(allowed_auth_types,g_strdup(*types));
      } 
      dialog->details->allowed_auth_types = allowed_auth_types;
    } 

    load_all_modules(dialog);

    if (dialog->details->auth_modules==NULL) {
      g_warning("gnome-generic-auth-dialog: Cannot find any authentication modules!");
      g_free(dialog);
      return NULL;
    }

	gtk_window_set_title (GTK_WINDOW (dialog), dialog_title);
    gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);
	gtk_dialog_add_buttons (GTK_DIALOG (dialog),
				GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
				GTK_STOCK_OK, GTK_RESPONSE_OK,
				NULL);

	/* Setup the dialog */
	gtk_dialog_set_has_separator (GTK_DIALOG (dialog), FALSE);

 	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER);
	gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);

 	gtk_container_set_border_width (GTK_CONTAINER (dialog), DIALOG_BORDER_WIDTH);

	gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);

//	g_signal_connect (dialog, "show",
//			  G_CALLBACK (dialog_show_callback), dialog);
	g_signal_connect (dialog, "close",
			  G_CALLBACK (dialog_close_callback), dialog);

	/* The table that holds the captions */
// Get the current auth_widget.
    widget_holder = gtk_hbox_new(FALSE,0);
	g_object_ref (widget_holder);
    dialog->details->widget_holder = GTK_WIDGET(widget_holder);

	/* fill in possibly choices in the druid when adding a connection */
	auth_type_hbox = gtk_hbox_new(FALSE,6);
	auth_type_label = GTK_LABEL (gtk_label_new (_("Authentication Type:")));
	gtk_label_set_justify (auth_type_label, GTK_JUSTIFY_LEFT);
	gtk_label_set_line_wrap (auth_type_label, TRUE);

	gtk_box_pack_start (GTK_BOX (auth_type_hbox),
				    GTK_WIDGET (auth_type_label),
				    TRUE,	/* expand */
				    TRUE,	/* fill */
				    5);		/* padding */
    auth_type_combo_box = GTK_COMBO_BOX(gtk_combo_box_new_text ());
	dialog->details->auth_type_combo = auth_type_combo_box;
	for (item = dialog->details->auth_modules; item != NULL; item = g_slist_next (item)) {
		GnomeGenericAuthModule *auth_module = (GnomeGenericAuthModule *)item->data;
		gtk_combo_box_append_text (GTK_COMBO_BOX(auth_type_combo_box), auth_module->get_display_name(auth_module));
	}
	g_signal_connect (auth_type_combo_box, "changed",
			  G_CALLBACK (auth_type_changed_callback), (gpointer) dialog);
	gtk_box_pack_end (GTK_BOX (auth_type_hbox), GTK_WIDGET(auth_type_combo_box), TRUE, TRUE, 0);

	//g_object_unref (widget_holder);


	/* Adds some eye-candy to the dialog */
	hbox = gtk_hbox_new (FALSE, 12);
	dialog_icon = gtk_image_new_from_stock (GTK_STOCK_DIALOG_AUTHENTICATION, GTK_ICON_SIZE_DIALOG);
	gtk_misc_set_alignment (GTK_MISC (dialog_icon), 0.5, 0.0);
	gtk_box_pack_start (GTK_BOX (hbox), dialog_icon, FALSE, FALSE, 0);

	gtk_box_set_spacing (GTK_BOX (GTK_DIALOG(dialog)->vbox), 12);
 	gtk_container_set_border_width (GTK_CONTAINER(hbox), 6);
	gtk_box_set_spacing (GTK_BOX (hbox), 12);

	/* Fills the vbox */
	vbox = gtk_vbox_new (FALSE, 0);

	if (message) {
		message_label = GTK_LABEL (gtk_label_new (message));
		gtk_label_set_justify (message_label, GTK_JUSTIFY_LEFT);
		gtk_label_set_line_wrap (message_label, TRUE);

		gtk_box_pack_start (GTK_BOX (vbox),
				    GTK_WIDGET (message_label),
				    TRUE,	/* expand */
				    TRUE,	/* fill */
				    5);		/* padding */
	}

//	THe following will be the widget from the plugin!
	gtk_box_pack_start (GTK_BOX (vbox), auth_type_hbox, 
			    TRUE, TRUE, 5);
	gtk_box_pack_start (GTK_BOX (vbox), widget_holder, 
			    TRUE, TRUE, 5);


	gtk_box_pack_start (GTK_BOX (hbox), vbox, TRUE, TRUE, 5);

	gtk_box_pack_start (GTK_BOX (GTK_DIALOG(dialog)->vbox),
			    hbox,
			    TRUE,	/* expand */
			    TRUE,	/* fill */
			    0);       	/* padding */
	
	gtk_widget_show (GTK_DIALOG (dialog)->vbox);

	dialog->details->remember_session_button =
		gtk_check_button_new_with_mnemonic (_("_Remember for this session"));
	dialog->details->remember_forever_button =
		gtk_check_button_new_with_mnemonic (_("_Save in keyring"));

	gtk_box_pack_start (GTK_BOX (vbox), dialog->details->remember_session_button, 
			    TRUE, TRUE, 6);
	gtk_box_pack_start (GTK_BOX (vbox), dialog->details->remember_forever_button, 
			    TRUE, TRUE, 0);
	
    if (!gnome_generic_auth_dialog_lookup_in_keyring(dialog)) {
          g_warning("Lookup failed");
  	      gtk_combo_box_set_active (auth_type_combo_box, 0);
    }
    
	return GTK_WIDGET (dialog);
}

gboolean
gnome_generic_auth_dialog_run_and_block (GnomeGenericAuthDialog *dialog)
{
	gint button_clicked;

	g_return_val_if_fail (dialog != NULL, FALSE);
	g_return_val_if_fail (GNOME_IS_GENERIC_AUTH_DIALOG (dialog), FALSE);

	button_clicked = gtk_dialog_run (GTK_DIALOG (dialog));

    save_to_keyring_as_needed(dialog);

    auth_widget_reparent(dialog,NULL);
	gtk_widget_hide (GTK_WIDGET (dialog));

	return button_clicked == GTK_RESPONSE_OK;
}

GnomeKeyringNetworkPasswordData *
gnome_generic_auth_dialog_get_password_data (GnomeGenericAuthDialog *dialog)
{
	g_return_val_if_fail (GNOME_IS_GENERIC_AUTH_DIALOG (dialog), NULL);

//	return g_strdup (gtk_entry_get_text (GTK_ENTRY (dialog->details->username_entry)));
   return NULL;
}

void
gnome_generic_auth_dialog_set_show_remember (GnomeGenericAuthDialog         *dialog,
					 gboolean                     show_remember)
{
	if (show_remember) {
		gtk_widget_show (dialog->details->remember_session_button);
		gtk_widget_show (dialog->details->remember_forever_button);
	} else {
		gtk_widget_hide (dialog->details->remember_session_button);
		gtk_widget_hide (dialog->details->remember_forever_button);
	}
}

void
gnome_generic_auth_dialog_set_remember (GnomeGenericAuthDialog         *dialog,
					 GnomeGenericAuthDialogRemember  remember)
{
	gboolean session, forever;

	session = FALSE;
	forever = FALSE;
	if (remember == GNOME_GENERIC_AUTH_DIALOG_REMEMBER_SESSION) {
		session = TRUE;
	} else if (remember == GNOME_GENERIC_AUTH_DIALOG_REMEMBER_FOREVER){
		forever = TRUE;
	}
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (dialog->details->remember_session_button),
				      session);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (dialog->details->remember_forever_button),
				      forever);
}

GnomeGenericAuthDialogRemember
gnome_generic_auth_dialog_get_remember (GnomeGenericAuthDialog         *dialog)
{
	gboolean session, forever;

	session = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (dialog->details->remember_session_button));
	forever = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (dialog->details->remember_forever_button));
	if (forever) {
		return GNOME_GENERIC_AUTH_DIALOG_REMEMBER_FOREVER;
	} else if (session) {
		return GNOME_GENERIC_AUTH_DIALOG_REMEMBER_SESSION;
	}
	return GNOME_GENERIC_AUTH_DIALOG_REMEMBER_NOTHING;
}

