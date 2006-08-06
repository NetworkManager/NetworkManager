#include <gtk/gtk.h>
#include <string.h>
#include <glade/glade.h>

#define NMVPNUI_OPT_C
#include "vpnui_impl.h"
#include "util_lists.h"
#include "vpnui_opt.h"

char get_opt_buffer[64];

extern void use_routes_toggled (GtkToggleButton *togglebutton, gpointer user_data);
extern void editable_changed (GtkEditable *editable, gpointer user_data);
extern void impl_set_validity_changed_callback (NetworkManagerVpnUI *self, 
				    NetworkManagerVpnUIDialogValidityCallback callback,
				    gpointer user_data);


void vpnui_opt_free(VpnUIConfigOption *opt)
{
  g_return_if_fail(opt!=NULL);

  if (opt->glade_name !=NULL) g_free(opt->glade_name);
  if (opt->gconf_name != NULL) g_free(opt->gconf_name);
  if (opt->export_name != NULL) g_free(opt->export_name);
   
  g_free(opt);
}

VpnUIConfigOption *vpnui_opt_new( char *glade_name,  
                           int     option_type, 
                           char   *gconf_name, 
                           char   *export_name, 
                           char   *description, 
                           void (*change_handler)(void),
                           gboolean (*validator)(VpnUIConfigOption *opt),
                           NetworkManagerVpnUIImpl *impl )
{
  VpnUIConfigOption *opt;

  g_return_val_if_fail(impl!=NULL,NULL);

  if (impl->config_options == NULL) impl->config_options = NULL;

  if (!(opt =  (VpnUIConfigOption *) g_new0(VpnUIConfigOption,1)))
        return NULL;

  opt->glade_name=g_strdup(glade_name);
  opt->option_type=option_type;
  if (gconf_name != NULL) opt->gconf_name=g_strdup(gconf_name);
  if (export_name != NULL) opt->export_name=g_strdup(export_name);
  if (description != NULL) opt->description=g_strdup(description);

  opt->change_handler=change_handler;
  opt->validator=validator;

  opt->impl=impl;
  impl->config_options = g_slist_append(impl->config_options, (gpointer) opt);

  vpnui_opt_get_widget(opt);
  vpnui_opt_connect_signals(opt);
 
  return opt;
}

void vpnui_opt_connect_signals(VpnUIConfigOption *opt)
{
  g_return_if_fail(opt!=NULL);
  g_return_if_fail(opt->widget!=NULL);
  g_return_if_fail(opt->impl!=NULL);

  if (opt->change_handler==NULL) return;

  switch (opt->option_type) 
  {
    case VPN_UI_OPTTYPE_YESNO:
      gtk_signal_connect (GTK_OBJECT (opt->widget), 
			"toggled", GTK_SIGNAL_FUNC (opt->change_handler), opt->impl);
      break;
    case VPN_UI_OPTTYPE_STRING:
      gtk_signal_connect (GTK_OBJECT (opt->widget), 
			"changed", GTK_SIGNAL_FUNC (opt->change_handler), opt->impl);
      break;
    case VPN_UI_OPTTYPE_SPINNER:
      gtk_signal_connect (GTK_OBJECT (opt->widget), 
			"changed", GTK_SIGNAL_FUNC (opt->change_handler), opt->impl);
      break;
    case VPN_UI_OPTTYPE_COMBO:
      gtk_signal_connect (GTK_OBJECT (opt->widget), 
			"changed", GTK_SIGNAL_FUNC (opt->change_handler), opt->impl);
      break;
  }
}

void vpnui_opt_get_widget(VpnUIConfigOption *opt)
{
  g_return_if_fail(opt!=NULL);
  g_return_if_fail(opt->impl!=NULL);

  switch (opt->option_type) 
  {
    case VPN_UI_OPTTYPE_YESNO:
    case VPN_UI_OPTTYPE_STRING:
    case VPN_UI_OPTTYPE_SPINNER:
    case VPN_UI_OPTTYPE_COMBO:
      opt->widget = GTK_WIDGET (glade_xml_get_widget(opt->impl->xml, opt->glade_name));
      break;
  }
}

const char * vpnui_opt_get(VpnUIConfigOption *opt)
{
  GtkTreeModel *combo_tree;
  GtkTreeIter iter;
  char *setting;
  gdouble value;
  g_return_val_if_fail(opt!=NULL,NULL);

  switch (opt->option_type) 
  {
    case VPN_UI_OPTTYPE_YESNO:
      if (gtk_toggle_button_get_active ( GTK_TOGGLE_BUTTON (opt->widget) )) {
        return "yes";
      }
      return "no";
    case VPN_UI_OPTTYPE_STRING:
      return gtk_entry_get_text(GTK_ENTRY(opt->widget));
    case VPN_UI_OPTTYPE_SPINNER:
      value = gtk_spin_button_get_value(GTK_SPIN_BUTTON(opt->widget));
      sprintf(get_opt_buffer,"%.0f",value);
      return get_opt_buffer;
    case VPN_UI_OPTTYPE_COMBO:
      combo_tree = gtk_combo_box_get_model(GTK_COMBO_BOX(opt->widget));
      if (combo_tree==NULL) return NULL;
      if (!gtk_combo_box_get_active_iter(GTK_COMBO_BOX(opt->widget), &iter))
           return NULL;

      gtk_tree_model_get (combo_tree, &iter, 0, &setting, -1);
      return setting;
  }

  return NULL;
}

void vpnui_opt_set(VpnUIConfigOption *opt, const char *value)
{
  int num_value;
  GtkTreeModel *combo_tree;
  GtkTreeIter iter;
  gboolean found;

  g_return_if_fail(opt!=NULL);
  g_return_if_fail(value!=NULL);

  switch (opt->option_type) 
  {
    case VPN_UI_OPTTYPE_YESNO:
      if (strcmp("yes",value) == 0) {
        gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (opt->widget), TRUE);
      } else if (strcmp("no",value) == 0) {
        gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (opt->widget), FALSE);
      } else {
        return;      
      }
      break;
    case VPN_UI_OPTTYPE_STRING:
      gtk_entry_set_text ( GTK_ENTRY( opt->widget ), value );
      break;
    case VPN_UI_OPTTYPE_SPINNER:
      sscanf(value,"%d",&num_value);
      gtk_spin_button_set_value(GTK_SPIN_BUTTON(opt->widget),num_value);
      break;
    case VPN_UI_OPTTYPE_COMBO:
      combo_tree = gtk_combo_box_get_model(GTK_COMBO_BOX(opt->widget));
      if (combo_tree==NULL) return;
      for (found = gtk_tree_model_get_iter_first(combo_tree, &iter);  
           found == TRUE;
           found = gtk_tree_model_iter_next(combo_tree, &iter)) {
        char *setting;
        gtk_tree_model_get (combo_tree, &iter, 0, &setting, -1);
        if (strcmp(setting,value)==0) {
          gtk_combo_box_set_active_iter(GTK_COMBO_BOX(opt->widget),&iter);
          return;
        }
      }
      gtk_combo_box_set_active(GTK_COMBO_BOX(opt->widget),-1);

      break;
  }
}

gboolean vpnui_opt_set_default(VpnUIConfigOption *opt, GSList *defaults)
{
  GSList *item;

  g_return_val_if_fail(opt!=NULL,FALSE);
  g_return_val_if_fail(defaults!=NULL,FALSE);

  
//  if (defaults == NULL) {
//    vpnui_opt_set_inactive(opt);
//    return FALSE;
//  }
  if (opt==opt->impl->connection_name_opt) {
     if (strlen(vpnui_opt_get(opt))>0)
       return TRUE;
  }

  for (item=defaults; item != NULL; item = g_slist_next(g_slist_next(item)))
  {
    if (strcmp((char *)item->data,opt->glade_name)!=0) continue;
    if ((g_slist_next(item))->data == NULL) continue;
    vpnui_opt_set(opt,(char *)(g_slist_next(item))->data);
    vpnui_opt_set_active(opt);
    return TRUE;
  }

  vpnui_opt_set_inactive(opt);
  return FALSE;
}

gboolean vpnui_opt_query_default(VpnUIConfigOption *opt, GSList *defaults)
{
  GSList *item;
  const char *value;

  g_return_val_if_fail(opt!=NULL,TRUE);

  if (defaults == NULL) return TRUE;

  for (item=defaults; item != NULL; item = g_slist_next(g_slist_next(item)))
  {
    if (strcmp(item->data,opt->glade_name)!=0) continue;
    value = vpnui_opt_get(opt);
    if (strcmp((g_slist_next(item))->data,value)==0) {
      return TRUE;
    } else {
      return FALSE;
    }
  }

  return TRUE;
}

void vpnui_opt_set_active(VpnUIConfigOption *opt)
{
  g_return_if_fail(opt!=NULL);

  gtk_widget_set_sensitive(GTK_WIDGET(opt->widget),TRUE);
  opt->active = TRUE;
}

void vpnui_opt_set_inactive(VpnUIConfigOption *opt)
{
  g_return_if_fail(opt!=NULL);

  if (GTK_WIDGET(opt->widget)==GTK_WIDGET(opt->impl->variant_combo)) return;
  if (opt==opt->impl->connection_name_opt) return;

  gtk_widget_set_sensitive(GTK_WIDGET(opt->widget),FALSE);
  opt->active = FALSE;
}

gboolean vpnui_opt_validate(VpnUIConfigOption *opt)
{
  g_return_val_if_fail(opt!=NULL,TRUE);

  if (opt->validator==NULL) return TRUE;
  return (opt->validator)(opt);
}

VpnUIConfigOption *
impl_opt_bygconf (NetworkManagerVpnUIImpl *impl, const char *name)
{
  GSList *item;
  VpnUIConfigOption *opt;

  for (item=impl->config_options; item != NULL; item = g_slist_next(item))
  {
    opt = (VpnUIConfigOption *)item->data;
    if (opt == NULL) continue;
    if (opt->gconf_name == NULL) continue;
    if (strcmp(opt->gconf_name,name)==0) return opt;
  }

  return NULL;
}

VpnUIConfigOption *
impl_opt_byglade (NetworkManagerVpnUIImpl *impl, const char *name)
{
  GSList *item;
  VpnUIConfigOption *opt;

  for (item=impl->config_options; item != NULL; item = g_slist_next(item))
  {
    opt = (VpnUIConfigOption *)item->data;
    if (opt == NULL) continue;
    if (opt->glade_name == NULL) continue;
    if (strcmp(opt->glade_name,name)==0) return opt;
  }

  return NULL;
}

gboolean vpnui_opt_has_active_children(GtkContainer *container, NetworkManagerVpnUIImpl *impl)
{
   VpnUIConfigOption *opt;
   GList *item;

   g_return_val_if_fail(GTK_IS_CONTAINER(container) ,FALSE);

   for (item=gtk_container_get_children(container); 
        item != NULL; item=g_list_next(item)) {
     if (item->data==NULL) continue;
//     g_warning("%s has child %s",gtk_widget_get_name(GTK_WIDGET(container)),
//                                gtk_widget_get_name(GTK_WIDGET(item->data)));
     opt = impl_opt_byglade(impl,gtk_widget_get_name(GTK_WIDGET(item->data)));
     if (opt!=NULL && opt->active) return TRUE;

     if (GTK_IS_CONTAINER(item->data) 
         && vpnui_opt_has_active_children(GTK_CONTAINER(item->data),impl)) {
       return TRUE;
     }
   }

  return FALSE;
}


//const char * vpnui_opt_get(VpnUIConfigOption *opt)
//{
//  g_return_if_fail(opt!=NULL);
//
//  switch (opt->option_type) 
//  {
//    case VPN_UI_OPTTYPE_YESNO:
//      if (gtk_toggle_button_get_active ( GTK_CHECK_BUTTON (opt->widget) )) {
//        return "yes";
//      } else {
//        return "no";
//      }
//      break;
//    case VPN_UI_OPTTYPE_STRING:
//      return gtk_entry_get_text(GTK_ENTRY(opt->widget));
//      break;
//  }
//
//  return NULL;
//}
