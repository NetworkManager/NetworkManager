#ifndef NMVPNUI_IMPL_H
#define NMVPNUI_IMPL_H

#include <glade/glade.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE
#include <NetworkManager/nm-vpn-ui-interface.h>

struct impl_config
{
 const char *display_name;
 const char *glade_widget;
 const char *glade_file; 
 const char *glade_connection_name; 
 const char *glade_routes;
 const char *glade_routes_toggle;
 const char *glade_import_button;
};

#define HAVE_VpnUIConfigOption
typedef struct _VpnUIConfigOption VpnUIConfigOption;
typedef struct _NetworkManagerVpnUIImpl NetworkManagerVpnUIImpl;

struct _NetworkManagerVpnUIImpl {
  NetworkManagerVpnUI parent;

  NetworkManagerVpnUIDialogValidityCallback callback;
  gpointer callback_user_data;

  GladeXML *xml;

  GtkWidget *widget;

  GSList         *config_options;
  GSList         *variants;

//  GtkEntry       *w_connection_name;
//  GtkEntry       *w_remote;
//  GtkCheckButton *w_use_routes;
//  GtkEntry       *w_routes;
//  GtkCheckButton *w_use_mppe;
//  GtkCheckButton *w_use_mppc;
//  GtkExpander    *w_pppd_opt_info_expander;
//  GtkExpander    *w_routing_opt_info_expander;
//  GtkExpander    *w_pptp_opt_info_expander;
  VpnUIConfigOption *connection_name_opt;
  VpnUIConfigOption *routes_opt;
  VpnUIConfigOption *routes_toggle_opt;
  GtkComboBox    *variant_combo;
  GtkButton      *w_import_button;
  GSList         *defaults;
  GSList         *expanders;

  const char     *display_name;
  const char     *service_name;
};

#ifdef NMVPNUI_IMPL_C
#define STORAGE_CLASS static
#define STORAGE_CLASS2
#else
#define STORAGE_CLASS extern
#define STORAGE_CLASS2 extern
#endif

STORAGE_CLASS GSList *get_routes (NetworkManagerVpnUIImpl *impl);
STORAGE_CLASS2 gboolean impl_is_valid (NetworkManagerVpnUI *self);
STORAGE_CLASS void impl_set_validity_changed_callback (NetworkManagerVpnUI *self, 
				    NetworkManagerVpnUIDialogValidityCallback callback,
				    gpointer user_data);

#undef STORAGE_CLASS
#endif
