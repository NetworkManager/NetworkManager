#define VPNUI_ROUTES_WIDGET "routes"
#define VPNUI_ROUTES_TOGGLE_WIDGET "use-routes"
#define VPNUI_DISPLAY_NAME _("PPPD Tunnel Client")
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
                             "ppp-debug=no;"
#define VPNUI_PPTP_DEFAULTS "pptp-remote='';" \
                             "ppp-connection-type=pptp;" 
#define VPNUI_DIALUP_DEFAULTS "phone-number=THIS DOESN'T DO ANYTHING;" \
                             "ppp-connection-type=dialup;" 

#ifdef NMVPNUI_PPTP_PROPERTIES_C
#endif

void impl_setup (NetworkManagerVpnUIImpl *impl);
void use_routes_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void editable_changed (GtkEditable *editable, gpointer user_data);
void variant_changed (GtkComboBox *combo, gpointer user_data);

