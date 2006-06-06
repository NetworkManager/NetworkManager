#include <string.h>
#include <glade/glade.h>

#define NMVPNUI_EXPAND_C
#include "vpnui_opt.h"
#include "vpnui_expand.h"

void vpnui_expand_free(VpnUIExpander *expand)
{
  g_return_if_fail(expand!=NULL);

  if (expand->glade_name !=NULL) g_free(expand->glade_name);
   
  g_free(expand);
}

VpnUIExpander *vpnui_expand_new( char *glade_name,  
                           NetworkManagerVpnUIImpl *impl )
{
  VpnUIExpander *expand;

  g_return_val_if_fail(impl!=NULL,NULL);

  if (!(expand =  (VpnUIExpander *) g_new0(VpnUIExpander,1)))
        return NULL;

  expand->glade_name=g_strdup(glade_name);

  expand->impl=impl;

  expand->widget = GTK_WIDGET (glade_xml_get_widget(expand->impl->xml, expand->glade_name));
  impl->expanders = g_slist_append(impl->expanders, (gpointer) expand);
 
  return expand;
}

void 
vpnui_expand_reset_all (NetworkManagerVpnUIImpl *impl)
{
  GSList *item;

  for (item=impl->expanders; item != NULL; item = g_slist_next(item))
  {
    vpnui_expand_reset((VpnUIExpander *)item->data);
  }

  gtk_container_resize_children (GTK_CONTAINER (impl->widget));
}

void vpnui_expand_reset(VpnUIExpander *expand)
{
   GList *item;
   
   g_return_if_fail(expand!=NULL);
   g_return_if_fail(expand->widget!=NULL);

   if (GTK_IS_CONTAINER(expand->widget)) {
     if (vpnui_opt_has_active_children(GTK_CONTAINER(expand->widget),expand->impl)) {
//        gtk_expander_set_expanded(GTK_EXPANDER(expand->widget),TRUE);
        gtk_widget_show(GTK_WIDGET(expand->widget));
     } else {
//        gtk_expander_set_expanded(GTK_EXPANDER(expand->widget),FALSE);
        gtk_widget_hide(GTK_WIDGET(expand->widget));
     }
   }

//   g_return_if_fail(expand!=NULL);
//   gtk_expander_set_expanded (GTK_EXPANDER(expand->widget), TRUE);
}



