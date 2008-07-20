/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-pptp-service - PPTP VPN integration with NetworkManager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2008 Red Hat, Inc.
 */

#ifndef NM_PPTP_PLUGIN_H
#define NM_PPTP_PLUGIN_H

#include <glib/gtypes.h>
#include <glib-object.h>
#include <nm-vpn-plugin.h>

#define NM_TYPE_PPTP_PLUGIN            (nm_pptp_plugin_get_type ())
#define NM_PPTP_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_PPTP_PLUGIN, NMPptpPlugin))
#define NM_PPTP_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_PPTP_PLUGIN, NMPptpPluginClass))
#define NM_IS_PPTP_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_PPTP_PLUGIN))
#define NM_IS_PPTP_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_PPTP_PLUGIN))
#define NM_PPTP_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_PPTP_PLUGIN, NMPptpPluginClass))

/* For the pppd plugin <-> VPN plugin service */
#define DBUS_TYPE_G_MAP_OF_VARIANT (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE))

#define NM_DBUS_SERVICE_PPTP_PPP    "org.freedesktop.NetworkManager.pptp-ppp"
#define NM_DBUS_PATH_PPTP_PPP       "/org/freedesktop/NetworkManager/pptp/ppp"
#define NM_DBUS_INTERFACE_PPTP_PPP  "org.freedesktop.NetworkManager.pptp.ppp"


/* For the NM <-> VPN plugin service */
#define NM_DBUS_SERVICE_PPTP    "org.freedesktop.NetworkManager.pptp"
#define NM_DBUS_INTERFACE_PPTP  "org.freedesktop.NetworkManager.pptp"
#define NM_DBUS_PATH_PPTP       "/org/freedesktop/NetworkManager/pptp"

#define NM_PPTP_KEY_GATEWAY           "gateway"
#define NM_PPTP_KEY_USER              "user"
#define NM_PPTP_KEY_PASSWORD          "password"
#define NM_PPTP_KEY_DOMAIN            "domain"
#define NM_PPTP_KEY_REFUSE_EAP        "refuse-eap"
#define NM_PPTP_KEY_REFUSE_PAP        "refuse-pap"
#define NM_PPTP_KEY_REFUSE_CHAP       "refuse-chap"
#define NM_PPTP_KEY_REFUSE_MSCHAP     "refuse-mschap"
#define NM_PPTP_KEY_REFUSE_MSCHAPV2   "refuse-mschapv2"
#define NM_PPTP_KEY_REQUIRE_MPPE      "require-mppe"
#define NM_PPTP_KEY_REQUIRE_MPPE_40   "require-mppe-40"
#define NM_PPTP_KEY_REQUIRE_MPPE_128  "require-mppe-128"
#define NM_PPTP_KEY_MPPE_STATEFUL     "mppe-stateful"
#define NM_PPTP_KEY_NOBSDCOMP         "nobsdcomp"
#define NM_PPTP_KEY_NODEFLATE         "nodeflate"
#define NM_PPTP_KEY_NO_VJ_COMP        "no-vj-comp"
#define NM_PPTP_KEY_LCP_ECHO_FAILURE  "lcp-echo-failure"
#define NM_PPTP_KEY_LCP_ECHO_INTERVAL "lcp-echo-interval"


typedef struct {
	NMVPNPlugin parent;
} NMPptpPlugin;

typedef struct {
	NMVPNPluginClass parent;
} NMPptpPluginClass;

GType nm_pptp_plugin_get_type (void);

NMPptpPlugin *nm_pptp_plugin_new (void);

#endif /* NM_PPTP_PLUGIN_H */
