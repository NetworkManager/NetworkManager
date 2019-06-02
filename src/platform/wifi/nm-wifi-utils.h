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
 * Copyright (C) 2005 - 2018 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef __WIFI_UTILS_H__
#define __WIFI_UTILS_H__

#include <net/ethernet.h>

#include "nm-dbus-interface.h"
#include "nm-setting-wireless.h"
#include "platform/nm-netlink.h"

typedef struct NMWifiUtils NMWifiUtils;

#define NM_TYPE_WIFI_UTILS            (nm_wifi_utils_get_type ())
#define NM_WIFI_UTILS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WIFI_UTILS, NMWifiUtils))
#define NM_WIFI_UTILS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_WIFI_UTILS, NMWifiUtilsClass))
#define NM_IS_WIFI_UTILS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_WIFI_UTILS))
#define NM_IS_WIFI_UTILS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_WIFI_UTILS))
#define NM_WIFI_UTILS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_WIFI_UTILS, NMWifiUtilsClass))

GType nm_wifi_utils_get_type (void);

gboolean nm_wifi_utils_is_wifi (int dirfd, const char *ifname);

NMWifiUtils *nm_wifi_utils_new (int ifindex, struct nl_sock *genl, gboolean check_scan);

NMDeviceWifiCapabilities nm_wifi_utils_get_caps (NMWifiUtils *data);

NM80211Mode nm_wifi_utils_get_mode (NMWifiUtils *data);

gboolean nm_wifi_utils_set_mode (NMWifiUtils *data, const NM80211Mode mode);

/* Returns frequency in MHz */
guint32 nm_wifi_utils_get_freq (NMWifiUtils *data);

/* Return the first supported frequency in the zero-terminated list.
 * Frequencies are specified in MHz. */
guint32 nm_wifi_utils_find_freq (NMWifiUtils *data, const guint32 *freqs);

/* out_bssid must be ETH_ALEN bytes */
gboolean nm_wifi_utils_get_bssid (NMWifiUtils *data, guint8 *out_bssid);

/* Returns current bitrate in Kbps */
guint32 nm_wifi_utils_get_rate (NMWifiUtils *data);

/* Returns quality 0 - 100% on success, or -1 on error */
int nm_wifi_utils_get_qual (NMWifiUtils *data);

/* Tells the driver DHCP or SLAAC is running */
gboolean nm_wifi_utils_indicate_addressing_running (NMWifiUtils *data, gboolean running);

gboolean nm_wifi_utils_set_powersave (NMWifiUtils *data, guint32 powersave);

NMSettingWirelessWakeOnWLan nm_wifi_utils_get_wake_on_wlan (NMWifiUtils *data);

gboolean nm_wifi_utils_set_wake_on_wlan (NMWifiUtils *data, NMSettingWirelessWakeOnWLan wowl);

/* OLPC Mesh-only functions */
guint32 nm_wifi_utils_get_mesh_channel (NMWifiUtils *data);

gboolean nm_wifi_utils_set_mesh_channel (NMWifiUtils *data, guint32 channel);

gboolean nm_wifi_utils_set_mesh_ssid (NMWifiUtils *data, const guint8 *ssid, gsize len);

#endif  /* __WIFI_UTILS_H__ */
