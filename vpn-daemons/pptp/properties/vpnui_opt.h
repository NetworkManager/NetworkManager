#ifndef NMVPNUI_OPT_H
#define NMVPNUI_OPT_H


#include <string.h>
#include <glade/glade.h>

//##include <NetworkManager/nm-vpn-ui-interface.h>
#include "vpnui_impl.h"

#define VPN_UI_OPTTYPE_YESNO   1
#define VPN_UI_OPTTYPE_STRING  2
#define VPN_UI_OPTTYPE_SPINNER 3
#define VPN_UI_OPTTYPE_COMBO   4

#ifndef HAVE_VpnUIConfigOption
 typedef struct _VpnUIConfigOption VpnUIConfigOption;
#endif

struct _VpnUIConfigOption
{
  char   *glade_name;
  int     option_type; 
  char   *gconf_name;
  char   *export_name;
  char   *description;
  gboolean   active;
  GCallback change_handler;
  gboolean (*validator)(VpnUIConfigOption *opt);
  GtkWidget  *widget;
  NetworkManagerVpnUIImpl *impl;
};

#define STORAGE_CLASS extern
#ifdef NMVPNUI_OPT_C
#undef STORAGE_CLASS 
#define STORAGE_CLASS 
#endif

STORAGE_CLASS void vpnui_opt_free(VpnUIConfigOption *opt);
STORAGE_CLASS VpnUIConfigOption *vpnui_opt_new( char *glade_name,  
                           int     option_type, 
                           char   *gconf_name, 
                           char   *export_name, 
                           char   *description, 
                           void  (*change_handler)(void),
                           gboolean (*validator)(VpnUIConfigOption *opt),
                           NetworkManagerVpnUIImpl *impl );
STORAGE_CLASS void vpnui_opt_set_active(VpnUIConfigOption *opt);
STORAGE_CLASS void vpnui_opt_set_inactive(VpnUIConfigOption *opt);
STORAGE_CLASS void vpnui_opt_get_widget(VpnUIConfigOption *opt);
//static char * vpnui_opt_get(VpnUIConfigOption *opt);
STORAGE_CLASS void vpnui_opt_set(VpnUIConfigOption *opt, const char *value);
STORAGE_CLASS gboolean vpnui_opt_query_default(VpnUIConfigOption *opt, GSList *defaults);
STORAGE_CLASS gboolean vpnui_opt_set_default(VpnUIConfigOption *opt, GSList *defaults);
STORAGE_CLASS gboolean vpnui_opt_validate(VpnUIConfigOption *opt);
STORAGE_CLASS const char * vpnui_opt_get(VpnUIConfigOption *opt);
STORAGE_CLASS void vpnui_opt_connect_signals(VpnUIConfigOption *opt);
STORAGE_CLASS VpnUIConfigOption *impl_opt_bygconf (NetworkManagerVpnUIImpl *impl, const char *name);
STORAGE_CLASS VpnUIConfigOption *impl_opt_byglade (NetworkManagerVpnUIImpl *impl, const char *name);
STORAGE_CLASS gboolean vpnui_opt_has_active_children(GtkContainer *container, NetworkManagerVpnUIImpl *impl);
#undef STORAGE_CLASS
#endif
