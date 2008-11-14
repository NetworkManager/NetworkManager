/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_VPNC_PLUGIN_H
#define NM_VPNC_PLUGIN_H

#include <glib/gtypes.h>
#include <glib-object.h>
#include <nm-vpn-plugin.h>

#define NM_TYPE_VPNC_PLUGIN            (nm_vpnc_plugin_get_type ())
#define NM_VPNC_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPNC_PLUGIN, NMVPNCPlugin))
#define NM_VPNC_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_VPNC_PLUGIN, NMVPNCPluginClass))
#define NM_IS_VPNC_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPNC_PLUGIN))
#define NM_IS_VPNC_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_VPNC_PLUGIN))
#define NM_VPNC_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPNC_PLUGIN, NMVPNCPluginClass))

#define NM_DBUS_SERVICE_VPNC    "org.freedesktop.NetworkManager.vpnc"
#define NM_DBUS_INTERFACE_VPNC  "org.freedesktop.NetworkManager.vpnc"
#define NM_DBUS_PATH_VPNC       "/org/freedesktop/NetworkManager/vpnc"

#define NM_VPNC_KEY_GATEWAY "IPSec gateway"
#define NM_VPNC_KEY_ID "IPSec ID"
#define NM_VPNC_KEY_SECRET "IPSec secret"
#define NM_VPNC_KEY_SECRET_TYPE "ipsec-secret-type"
#define NM_VPNC_KEY_XAUTH_USER "Xauth username"
#define NM_VPNC_KEY_XAUTH_PASSWORD "Xauth password"
#define NM_VPNC_KEY_XAUTH_PASSWORD_TYPE "xauth-password-type"
#define NM_VPNC_KEY_DOMAIN "Domain"
#define NM_VPNC_KEY_DHGROUP "IKE DH Group"
#define NM_VPNC_KEY_PERFECT_FORWARD "Perfect Forward Secrecy"
#define NM_VPNC_KEY_APP_VERSION "Application Version"
#define NM_VPNC_KEY_SINGLE_DES "Enable Single DES"
#define NM_VPNC_KEY_NO_ENCRYPTION "Enable no encryption"
#define NM_VPNC_KEY_NAT_TRAVERSAL_MODE "NAT Traversal Mode"
#define NM_VPNC_KEY_DPD_IDLE_TIMEOUT "DPD idle timeout (our side)"
#define NM_VPNC_KEY_CISCO_UDP_ENCAPS_PORT "Cisco UDP Encapsulation Port"

#define NM_VPNC_NATT_MODE_NATT "natt"
#define NM_VPNC_NATT_MODE_NONE "none"
#define NM_VPNC_NATT_MODE_CISCO "cisco-udp"

#define NM_VPNC_PW_TYPE_SAVE   "save"
#define NM_VPNC_PW_TYPE_ASK    "ask"
#define NM_VPNC_PW_TYPE_UNUSED "unused"

typedef struct {
	NMVPNPlugin parent;
} NMVPNCPlugin;

typedef struct {
	NMVPNPluginClass parent;
} NMVPNCPluginClass;

GType nm_vpnc_plugin_get_type (void);

NMVPNCPlugin *nm_vpnc_plugin_new (void);

#endif /* NM_VPNC_PLUGIN_H */
