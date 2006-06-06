#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <gtk/gtk.h>

#define NMVPNUI_VALIDATE_C
#include "vpnui_impl.h"
#include "vpnui_opt.h"
#include "vpnui_validate.h"

gboolean vld_non_empty (VpnUIConfigOption *opt)
{
  const char *value = vpnui_opt_get(opt);
  if ((value == NULL) || (strlen (value) == 0))  {
    return FALSE;
  }
  return TRUE;
}

gboolean vld_non_empty_no_ws (VpnUIConfigOption *opt)
{
  const char *value = vpnui_opt_get(opt);
  if ((value == NULL) || 
      (strlen (value) == 0) ||
      (strstr(value, " ") != NULL) ||
      (strstr(value, "\t") != NULL) ) {
    return FALSE;
  }
  return TRUE;
}

gboolean vld_routes_if_sens (VpnUIConfigOption *opt)
{
  GSList *item;
  GSList *routes = NULL;
  VpnUIConfigOption *opt2;
  const char *value;
  const char *use_routes;
  char **substrs;
  int i;
  gboolean sens, is_valid;

  sens =  GTK_WIDGET_IS_SENSITIVE(GTK_WIDGET(opt->widget));
  if (!sens) return TRUE; 

//  routes = get_routes (opt->impl);
  g_return_val_if_fail(opt!=NULL,TRUE);
  value = vpnui_opt_get(opt);

  opt2 = impl_opt_byglade(opt->impl,"use-routes");
  g_return_val_if_fail(opt2!=NULL,TRUE);
  use_routes = vpnui_opt_get(opt2);

  if (strcmp("yes",use_routes)==0) {
    substrs = g_strsplit (value, " ", 0);
    for (i = 0; substrs[i] != NULL; i++) {
      char *route;
  
      if (strlen(substrs[i]) > 0)
        routes = g_slist_append (routes, g_strdup (substrs[i]));
    }
  
    g_strfreev (substrs);
  }

  is_valid=TRUE;
  for (item = routes; item != NULL; item = g_slist_next (item)) {
    int d1, d2, d3, d4, mask;
  
    const char *route = (const char *) item->data;
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
  
  if (routes != NULL) {
    g_slist_foreach (routes, (GFunc)g_free, NULL);
    g_slist_free (routes);
  }

  return is_valid;
}
