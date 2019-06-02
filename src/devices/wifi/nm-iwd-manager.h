/* NetworkManager -- Network link manager
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
 * Copyright (C) 2017 Intel Corporation
 */

#ifndef __NETWORKMANAGER_IWD_MANAGER_H__
#define __NETWORKMANAGER_IWD_MANAGER_H__

#include "devices/nm-device.h"
#include "nm-wifi-utils.h"

#define NM_IWD_BUS_TYPE                 G_BUS_TYPE_SYSTEM
#define NM_IWD_SERVICE                  "net.connman.iwd"

#define NM_IWD_AGENT_MANAGER_INTERFACE  "net.connman.iwd.AgentManager"
#define NM_IWD_WIPHY_INTERFACE          "net.connman.iwd.Adapter"
#define NM_IWD_DEVICE_INTERFACE         "net.connman.iwd.Device"
#define NM_IWD_NETWORK_INTERFACE        "net.connman.iwd.Network"
#define NM_IWD_AGENT_INTERFACE          "net.connman.iwd.Agent"
#define NM_IWD_WSC_INTERFACE            \
	"net.connman.iwd.WiFiSimpleConfiguration"
#define NM_IWD_KNOWN_NETWORK_INTERFACE  "net.connman.iwd.KnownNetwork"
#define NM_IWD_SIGNAL_AGENT_INTERFACE   "net.connman.iwd.SignalLevelAgent"
#define NM_IWD_AP_INTERFACE             "net.connman.iwd.AccessPoint"
#define NM_IWD_ADHOC_INTERFACE          "net.connman.iwd.AdHoc"
#define NM_IWD_STATION_INTERFACE        "net.connman.iwd.Station"

#define NM_TYPE_IWD_MANAGER              (nm_iwd_manager_get_type ())
#define NM_IWD_MANAGER(obj)              (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IWD_MANAGER, NMIwdManager))
#define NM_IWD_MANAGER_CLASS(klass)      (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_IWD_MANAGER, NMIwdManagerClass))
#define NM_IS_IWD_MANAGER(obj)           (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_IWD_MANAGER))
#define NM_IS_IWD_MANAGER_CLASS(klass)   (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_IWD_MANAGER))
#define NM_IWD_MANAGER_GET_CLASS(obj)    (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_IWD_MANAGER, NMIwdManagerClass))

typedef struct _NMIwdManager NMIwdManager;
typedef struct _NMIwdManagerClass NMIwdManagerClass;

GType nm_iwd_manager_get_type (void);

NMIwdManager *nm_iwd_manager_get (void);

gboolean nm_iwd_manager_is_known_network (NMIwdManager *self, const char *name,
                                          NMIwdNetworkSecurity security);

GDBusProxy *nm_iwd_manager_get_dbus_interface (NMIwdManager *self, const char *path,
                                               const char *name);

#endif /* __NETWORKMANAGER_IWD_MANAGER_H__ */
