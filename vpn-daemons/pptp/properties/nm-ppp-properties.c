/***************************************************************************
 * CVSID: $Id$
 *
 * nm-pptp.c : GNOME UI dialogs for configuring PPTP connections
 *
 * Copyright (C) 2005 Antony Mee <eemynotna@gmail.com>
 * Based on work by Tim Niemueller <tim@niemueller.de> 
 *              and David Zeuthen, <davidz@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n-lib.h>
#include <string.h>
#include <glade/glade.h>

#define NMVPNUI_PPTP_PROPERTIES_C

#include "vpnui_impl.h"
#include "vpnui_opt.h"
#include "vpnui_expand.h"
#include "vpnui_validate.h"
#include "vpnui_variant.h"
#include "util_lists.h"

#include "nm-ppp-properties.h"

const char *GLADE_FILE="nm-ppp-dialog.glade";
const char *GLADE_WIDGET="nm-ppp-widget";

void 
impl_setup (NetworkManagerVpnUIImpl *impl)
{
  GSList *item;
  VpnUIConfigOption *opt;
  VpnUIVariant *variant;
  VpnUIExpander *expand;
  g_return_if_fail(impl!=NULL);

  impl->display_name = VPNUI_DISPLAY_NAME;
  impl->service_name = VPNUI_SERVICE_NAME;
//    GLADE NAME   TYPE  
//    GCONF_NAME     EXPORT_NAME   DESCRIPTION(for summary)
//    VALIDATOR_Fn
  opt = vpnui_opt_new(
 "connection-name", VPN_UI_OPTTYPE_STRING, 
  NULL, "Description", _("Name"),
  GTK_SIGNAL_FUNC(&editable_changed), &vld_non_empty, impl );
  impl->connection_name_opt = opt;

  opt = vpnui_opt_new(
 "ppp-connection-type", VPN_UI_OPTTYPE_COMBO, 
 "ppp-connection-type", "Connection-Type", NULL,
  GTK_SIGNAL_FUNC(&variant_changed), NULL, impl );
  impl->variant_combo = GTK_COMBO_BOX(opt->widget);

  opt = vpnui_opt_new(
 "pptp-remote", VPN_UI_OPTTYPE_STRING, 
 "pptp-remote", "PPTP-Server", _("PPTP Server"),
  GTK_SIGNAL_FUNC(&editable_changed), &vld_non_empty, impl );

  opt = vpnui_opt_new(
 "phone-number", VPN_UI_OPTTYPE_STRING, 
 "phone-number", "Telephone-Number", _("Telephone Number"),
  GTK_SIGNAL_FUNC(&editable_changed), &vld_non_empty, impl );

  opt = vpnui_opt_new(
 "usepeerdns"  , VPN_UI_OPTTYPE_YESNO , 
 "usepeerdns", "Use-Peer-DNS", _("Use Peer DNS"),
  NULL, NULL, impl );

  opt = vpnui_opt_new(
 "encrypt-mppe"  , VPN_UI_OPTTYPE_YESNO , 
 "encrypt-mppe", "Encrypt-MPPE", _("Use MPPE encryption"),
  NULL, NULL, impl );

  opt = vpnui_opt_new(
 "compress-mppc"  , VPN_UI_OPTTYPE_YESNO , 
 "compress-mppc", "Compress-MPPC", _("Use MPPC compression"),
  NULL, NULL, impl );

  opt = vpnui_opt_new(
 "compress-deflate"  , VPN_UI_OPTTYPE_YESNO , 
 "compress-deflate", "Compress-Deflate", _("Do not use deflate compression"),
  NULL, NULL, impl );
 
  opt = vpnui_opt_new(
 "compress-bsd"  , VPN_UI_OPTTYPE_YESNO ,
 "compress-bsd", "Compress-BSD", _("Do not use BSD compression"),
  NULL, NULL, impl );

  opt = vpnui_opt_new(
 "ppp-lock"  , VPN_UI_OPTTYPE_YESNO ,
 "ppp-lock", "PPP-Lock", _("Exclusive device access by pppd"),
  NULL, NULL, impl );

  opt = vpnui_opt_new(
 "ppp-auth-peer"  , VPN_UI_OPTTYPE_YESNO ,
 "ppp-auth-peer", "Auth-Peer", _("Authenticate remote peer"),
  NULL, NULL, impl );

  opt = vpnui_opt_new(
 "mtu"  , VPN_UI_OPTTYPE_SPINNER ,
 "mtu", "MTU", _("Maximum transmit unit (in bytes)"),
  NULL, NULL, impl );

  opt = vpnui_opt_new(
 "mru"  , VPN_UI_OPTTYPE_SPINNER ,
 "mru", "MRU", _("Maximum receive unit (in bytes)"),
  NULL, NULL, impl );

  opt = vpnui_opt_new(
 "lcp-echo-failure"  , VPN_UI_OPTTYPE_SPINNER ,
 "lcp-echo-failure", "LCP-Echo-Failure", _("Number of failed LCP echos to cause disconnect"),
  NULL, NULL, impl );

  opt = vpnui_opt_new(
 "lcp-echo-interval"  , VPN_UI_OPTTYPE_SPINNER ,
 "lcp-echo-interval", "LCP-Echo-Interval", _("Interval (in seconds) at which to issue LCP echos"),
  NULL, NULL, impl );

  opt = vpnui_opt_new(
 "ppp-debug"  , VPN_UI_OPTTYPE_YESNO ,
 "ppp-debug", NULL, NULL,
  NULL, NULL, impl );

  opt = vpnui_opt_new(
 "usepeerdns-overtunnel"  , VPN_UI_OPTTYPE_YESNO , 
 "usepeerdns-overtunnel", "Peer-DNS-Over-Tunnel", _("Use Peer DNS over the Tunnel"),
  NULL, NULL, impl );


  opt = vpnui_opt_new(
 "routes"  , VPN_UI_OPTTYPE_STRING , 
 "routes", "X-NM-Routes", _("Specific networks available"),
  GTK_SIGNAL_FUNC(&editable_changed), &vld_routes_if_sens, impl );

  opt = vpnui_opt_new(
 "use-routes"  , VPN_UI_OPTTYPE_YESNO , 
 "use-routes", "Use-Routes", _("Limit to specific networks"),
  GTK_SIGNAL_FUNC(&use_routes_toggled), NULL, impl );

  variant = vpnui_variant_new( "pptp","Windows VPN (PPTP)",
                        VPNUI_BASIC_DEFAULTS VPNUI_PPTP_DEFAULTS,
                        impl);
  variant = vpnui_variant_new( "dialup", "Dialup",
                        VPNUI_BASIC_DEFAULTS VPNUI_DIALUP_DEFAULTS,
                        impl);
//
//                     GLADE NAME   IMPLEMENTATION_OBJ
  expand= vpnui_expand_new ("routing-expander",impl);
  expand= vpnui_expand_new ("dialup-expander",impl);
  expand= vpnui_expand_new ("pppd-expander",impl);
  expand= vpnui_expand_new ("pptp-expander",impl);

// Attach an import_button
  impl->w_import_button = GTK_BUTTON (glade_xml_get_widget (impl->xml, 
								       "import-button"));
}

void 
use_routes_toggled (GtkToggleButton *togglebutton, gpointer user_data)
{
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;
  VpnUIConfigOption *opt = impl_opt_byglade(impl,"routes");

  if (opt!=NULL) gtk_widget_set_sensitive (GTK_WIDGET (opt->widget),  
                           gtk_toggle_button_get_active (togglebutton));

  if (impl->callback != NULL) {
    gboolean is_valid;

    is_valid = impl_is_valid (&(impl->parent));
    impl->callback (&(impl->parent), is_valid, impl->callback_user_data);
  }
}

void 
editable_changed (GtkEditable *editable, gpointer user_data)
{
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;

  if (impl->callback != NULL) {
    gboolean is_valid;

    is_valid = impl_is_valid (&(impl->parent));
    impl->callback (&(impl->parent), is_valid, impl->callback_user_data);
  }
}

void 
variant_changed (GtkComboBox *combo, gpointer user_data)
{
  NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;
  char *variant_name;


  variant_name=gtk_combo_box_get_active_text(combo);

  vpnui_variant_select_byname(impl,variant_name);

  vpnui_expand_reset_all(impl);

  if (impl->callback != NULL) {
    gboolean is_valid;

    is_valid = impl_is_valid (&(impl->parent));
    impl->callback (&(impl->parent), is_valid, impl->callback_user_data);
  }
}


