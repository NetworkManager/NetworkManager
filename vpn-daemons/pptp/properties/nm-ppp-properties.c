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

#define BUILD_BLUETOOTH

#define VPNUI_DISPLAY_NAME _("Tunnel via pppd")
#define VPNUI_SERVICE_NAME "org.freedesktop.NetworkManager.ppp_starter"
#define VPNUI_BASIC_DEFAULTS "connection-name='';" \
                             "ppp-debug=no;" \
                             "usepeerdns=yes;" \
                             "usepeerdns-overtunnel=yes;" \
                             "encrypt-mppe=yes;" \
                             "compress-mppc=no;" \
                             "ppp-lock=yes;" \
                             "ppp-auth-peer=no;" \
                             "compress-bsd=no;" \
                             "compress-deflate=no;" \
                             "mru=1000;" \
                             "mtu=1000;" \
                             "lcp-echo-failure=10;" \
                             "lcp-echo-interval=10;" \
                             "use-routes=no;" \
                             "routes=;" \
                             "ppp-debug=no;" \
                             "ppp-extra='';"
#define VPNUI_BTOOTH_DEFAULTS "bt-bdaddr=00:00:00:00:00:00;" \
                              "bt-channel=1;" 
#define VPNUI_GPRS_DEFAULTS "gprs-packet-type=IP;" \
                             "gprs-context-num=1;" \
                             "gprs-ip-address=0.0.0.0;" \
                             "gprs-apn=internet;" \
                             "ppp-crtscts=yes;" \
                             "ppp-noipdefault=yes;" \
                             "ppp-modem=yes;" \
                             "usepeerdns=yes;" \
                             "ppp-connect-delay=5000;" 
#define VPNUI_BTGPRS_DEFAULTS "ppp-connection-type=btgprs;" 
#define VPNUI_PPTP_DEFAULTS "pptp-remote='';" \
                             "ppp-connection-type=pptp;" 
#define VPNUI_DIALUP_DEFAULTS "phone-number=THIS DOESN'T DO ANYTHING;" \
                              "ppp-crtscts=yes;" \
                              "ppp-modem=yes;" \
                              "ppp-connection-type=dialup;" 

#ifdef NMVPNUI_PPTP_PROPERTIES_C
#endif

void impl_setup (NetworkManagerVpnUIImpl *impl);
void use_routes_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void editable_changed (GtkEditable *editable, gpointer user_data);
void variant_changed (GtkComboBox *combo, gpointer user_data);


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
  "bt-bdaddr", VPN_UI_OPTTYPE_STRING, 
  "bt-bdaddr", "Bluetooth-Address", _("Bluetooth Address"),
  GTK_SIGNAL_FUNC(&editable_changed), &vld_non_empty, impl );

  opt = vpnui_opt_new(
  "bt-channel", VPN_UI_OPTTYPE_STRING, 
  "bt-channel", "Bluetooth-Channel", _("Bluetooth Channel"),
  GTK_SIGNAL_FUNC(&editable_changed), &vld_non_empty, impl );

  opt = vpnui_opt_new(
  "gprs-apn", VPN_UI_OPTTYPE_STRING, 
  "gprs-apn", "GPRS-Access-Point-Name", _("GPRS APN"),
  GTK_SIGNAL_FUNC(&editable_changed), &vld_non_empty, impl );

  opt = vpnui_opt_new(
  "gprs-ip-address", VPN_UI_OPTTYPE_STRING, 
  "gprs-ip-address", "GPRS-IP-Address", _("GPRS IP"),
  GTK_SIGNAL_FUNC(&editable_changed), &vld_non_empty, impl );

  opt = vpnui_opt_new(
  "gprs-context-num", VPN_UI_OPTTYPE_STRING, 
  "gprs-context-num", "GPRS-Context-Number", _("GPRS Context No."),
  GTK_SIGNAL_FUNC(&editable_changed), &vld_non_empty, impl );

  opt = vpnui_opt_new(
  "gprs-packet-type", VPN_UI_OPTTYPE_STRING, 
  "gprs-packet-type", "GPRS-Packet-Type", _("GPRS Packet Type"),
  GTK_SIGNAL_FUNC(&editable_changed), &vld_non_empty, impl );

  opt = vpnui_opt_new(
  "ppp-crtscts", VPN_UI_OPTTYPE_YESNO, 
  "ppp-crtscts", "PPP-Hardware-CTSRTS", _("Use CTS/RTS flow control"),
  GTK_SIGNAL_FUNC(&editable_changed), NULL, impl );

  opt = vpnui_opt_new(
  "ppp-modem", VPN_UI_OPTTYPE_YESNO, 
  "ppp-modem", "PPP-Modem", _("Connect via a modem"),
  GTK_SIGNAL_FUNC(&editable_changed), NULL, impl );

  opt = vpnui_opt_new(
  "ppp-noipdefault", VPN_UI_OPTTYPE_YESNO, 
  "ppp-noipdefault", "PPP-No-IP-Default", _("Require IP to be provided"),
  GTK_SIGNAL_FUNC(&editable_changed), NULL, impl );

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
  "ppp-connect-delay"  , VPN_UI_OPTTYPE_SPINNER ,
  "ppp-connect-delay", "PPP-Connect-Delay", _("Interval (in milliseconds) to wait before connecting."),
  NULL, NULL, impl );

  opt = vpnui_opt_new(
  "ppp-extra", VPN_UI_OPTTYPE_STRING, 
  "ppp-extra", "PPP-Custom-Options", _("Custom PPP options"),
  GTK_SIGNAL_FUNC(&editable_changed), NULL, impl );

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

#ifdef BUILD_BLUETOOTH
  variant = vpnui_variant_new( "btgprs", "GPRS over Bluetooth (via mobile phone)",
                        VPNUI_BASIC_DEFAULTS VPNUI_GPRS_DEFAULTS VPNUI_BTOOTH_DEFAULTS VPNUI_BTGPRS_DEFAULTS,
                        impl);
#endif

  variant = vpnui_variant_new( "dialup", "Dialup",
                        VPNUI_BASIC_DEFAULTS VPNUI_DIALUP_DEFAULTS,
                        impl);
//
//                     GLADE NAME   IMPLEMENTATION_OBJ
  expand= vpnui_expand_new ("routing-expander",impl);
  expand= vpnui_expand_new ("dialup-expander",impl);
  expand= vpnui_expand_new ("pppd-expander",impl);
  expand= vpnui_expand_new ("pptp-expander",impl);
  expand= vpnui_expand_new ("bluetooth-expander",impl);
  expand= vpnui_expand_new ("serial-expander",impl);
  expand= vpnui_expand_new ("gprs-expander",impl);

// Attach to press event of the Bluetooth "Find Device" button.
//    will need libbtcl
//  impl->w_import_button = GTK_BUTTON (glade_xml_get_widget (impl->xml, 
//								       "import-button"));

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


