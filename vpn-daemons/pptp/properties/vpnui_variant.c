#include <string.h>
#include <glade/glade.h>

#define NMVPNUI_EXPAND_C
#include "util_lists.h"
#include "vpnui_opt.h"
#include "vpnui_variant.h"


void vpnui_variant_free( VpnUIVariant *variant )
{
  g_return_if_fail(variant != NULL);

  g_free(variant->name);
  g_free(variant->defaults);
  g_free(variant);  
}

VpnUIVariant *vpnui_variant_new( const char *name, const char *description,
                        const char *defaults,
                        NetworkManagerVpnUIImpl *impl
                      )
{
  VpnUIVariant *variant;
  GtkListStore *store;
  GtkTreeIter iter;
  GtkCellRenderer *renderer;
  gboolean first_variant=FALSE;

  g_return_val_if_fail(name != NULL,NULL);
  g_return_val_if_fail(defaults != NULL,NULL);
  g_return_val_if_fail(impl != NULL,NULL);
  g_return_val_if_fail(impl->variant_combo != NULL,NULL);

  if (!(variant =  (VpnUIVariant *) g_new0(VpnUIVariant,1)))
        return NULL;

  variant->name = g_strdup(name);  
  variant->description = g_strdup(description);  
  variant->defaults = list_from_string(defaults);  
  variant->impl = impl;

  first_variant=(impl->variants == NULL);
 
  if (first_variant) {
    store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
  } else {
    store = 
     (GtkListStore *)gtk_combo_box_get_model(GTK_COMBO_BOX(impl->variant_combo));
  }

  gtk_list_store_append (store, &iter);
  gtk_list_store_set (store, &iter, 0, variant->name, 1, variant->description, -1);
 
  gtk_combo_box_set_model(impl->variant_combo,GTK_TREE_MODEL(store));
  if (first_variant) {
    gtk_cell_layout_clear (GTK_CELL_LAYOUT (impl->variant_combo));
//    renderer = gtk_cell_renderer_text_new ();
//    gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (impl->variant_combo), renderer, FALSE);
//    gtk_cell_layout_set_attributes (GTK_CELL_LAYOUT (impl->variant_combo), renderer,
//                                "text", 0, "visible", FALSE,
//                                NULL);
    renderer = gtk_cell_renderer_text_new ();
    gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (impl->variant_combo), renderer, TRUE);
    gtk_cell_layout_set_attributes (GTK_CELL_LAYOUT (impl->variant_combo), renderer,
                                "text", 1,
                                NULL);
  }

//  gtk_combo_box_append_text(GTK_COMBO_BOX(impl->variant_combo), variant->name);
  g_object_unref (store);

  impl->variants = g_slist_append(impl->variants, (gpointer) variant);
  return variant;
}

VpnUIVariant *
vpnui_variant_byname (NetworkManagerVpnUIImpl *impl, const char *name)
{
  GSList *item;
  VpnUIVariant *variant;

  for (item=impl->variants; item != NULL; item = g_slist_next(item))
  {
    variant = (VpnUIVariant *)item->data;
    if (variant == NULL) continue;
    if (variant->name == NULL) continue;
    if (strcmp(variant->name,name)==0) return variant;
  }

  return NULL;
}

void
vpnui_variant_select (VpnUIVariant *variant)
{
  NetworkManagerVpnUIImpl *impl;
  GSList *item;

  g_return_if_fail(variant != NULL);
  impl=variant->impl;

  impl->defaults=variant->defaults;
  for (item=impl->config_options; item != NULL; item = g_slist_next(item)) {
    vpnui_opt_set_default((VpnUIConfigOption *)item->data, impl->defaults);
  }
}


void
vpnui_variant_select_byname (NetworkManagerVpnUIImpl *impl, const char *name)
{
  VpnUIVariant *variant;

  g_return_if_fail(impl != NULL);
  g_return_if_fail(name != NULL);

  variant = vpnui_variant_byname(impl,name);
  g_return_if_fail(variant != NULL);
  vpnui_variant_select(variant);
}

