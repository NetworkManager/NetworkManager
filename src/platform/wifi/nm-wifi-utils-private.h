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
 * Copyright (C) 2011 - 2018 Red Hat, Inc.
 */

#ifndef __WIFI_UTILS_PRIVATE_H__
#define __WIFI_UTILS_PRIVATE_H__

#include "nm-dbus-interface.h"
#include "nm-wifi-utils.h"

typedef struct {
	GObjectClass parent;

	NM80211Mode (*get_mode) (NMWifiUtils *data);

	gboolean (*set_mode) (NMWifiUtils *data, const NM80211Mode mode);

	/* Set power saving mode on an interface */
	gboolean (*set_powersave) (NMWifiUtils *data, guint32 powersave);

	/* Get WakeOnWLAN configuration on an interface */
	NMSettingWirelessWakeOnWLan (*get_wake_on_wlan) (NMWifiUtils *data);

	/* Set WakeOnWLAN mode on an interface */
	gboolean (*set_wake_on_wlan) (NMWifiUtils *data, NMSettingWirelessWakeOnWLan wowl);

	/* Return current frequency in MHz (really associated BSS frequency) */
	guint32 (*get_freq) (NMWifiUtils *data);

	/* Return first supported frequency in the zero-terminated list */
	guint32 (*find_freq) (NMWifiUtils *data, const guint32 *freqs);

	/* Return current bitrate in Kbps */
	guint32 (*get_rate) (NMWifiUtils *data);

	gboolean (*get_bssid) (NMWifiUtils *data, guint8 *out_bssid);

	/* Return a signal strength percentage 0 - 100% for the current BSSID;
	 * return -1 on errors or if not associated.
	 */
	int (*get_qual) (NMWifiUtils *data);

	/* OLPC Mesh-only functions */

	guint32 (*get_mesh_channel) (NMWifiUtils *data);

	/* channel == 0 means "auto channel" */
	gboolean (*set_mesh_channel) (NMWifiUtils *data, guint32 channel);

	/* ssid == NULL means "auto SSID" */
	gboolean (*set_mesh_ssid) (NMWifiUtils *data, const guint8 *ssid, gsize len);

	gboolean (*indicate_addressing_running) (NMWifiUtils *data, gboolean running);
} NMWifiUtilsClass;

struct NMWifiUtils {
	GObject parent;

	int ifindex;
	NMDeviceWifiCapabilities caps;
};

#endif  /* __WIFI_UTILS_PRIVATE_H__ */
