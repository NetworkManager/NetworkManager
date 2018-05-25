/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright (C) 2005 - 2011 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "wifi-utils.h"

#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include "wifi-utils-private.h"
#include "wifi-utils-nl80211.h"
#if HAVE_WEXT
#include "wifi-utils-wext.h"
#endif
#include "nm-core-utils.h"

#include "platform/nm-platform-utils.h"

gpointer
wifi_data_new (const WifiDataClass *klass, int ifindex)
{
	WifiData *data;

	nm_assert (klass);
	nm_assert (klass->struct_size > sizeof (WifiData));

	data = g_malloc0 (klass->struct_size);
	data->klass = klass;
	data->ifindex = ifindex;
	return data;
}

/*****************************************************************************/

WifiData *
wifi_utils_init (int ifindex, gboolean check_scan)
{
	WifiData *ret;

	g_return_val_if_fail (ifindex > 0, NULL);

	ret = wifi_nl80211_init (ifindex);
	if (ret == NULL) {
#if HAVE_WEXT
		ret = wifi_wext_init (ifindex, check_scan);
#endif
	}
	return ret;
}

int
wifi_utils_get_ifindex (WifiData *data)
{
	g_return_val_if_fail (data != NULL, -1);

	return data->ifindex;
}

NMDeviceWifiCapabilities
wifi_utils_get_caps (WifiData *data)
{
	g_return_val_if_fail (data != NULL, NM_WIFI_DEVICE_CAP_NONE);

	return data->caps;
}

NM80211Mode
wifi_utils_get_mode (WifiData *data)
{
	g_return_val_if_fail (data != NULL, NM_802_11_MODE_UNKNOWN);
	return data->klass->get_mode (data);
}

gboolean
wifi_utils_set_mode (WifiData *data, const NM80211Mode mode)
{
	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (   (mode == NM_802_11_MODE_INFRA)
	                      || (mode == NM_802_11_MODE_AP)
	                      || (mode == NM_802_11_MODE_ADHOC), FALSE);

	/* nl80211 probably doesn't need this */
	return data->klass->set_mode ? data->klass->set_mode (data, mode) : TRUE;
}

gboolean
wifi_utils_set_powersave (WifiData *data, guint32 powersave)
{
	g_return_val_if_fail (data != NULL, FALSE);

	return data->klass->set_powersave ? data->klass->set_powersave (data, powersave) : TRUE;
}

gboolean
wifi_utils_set_wake_on_wlan (WifiData *data, NMSettingWirelessWakeOnWLan wowl)
{
	g_return_val_if_fail (data != NULL, FALSE);

	return data->klass->set_wake_on_wlan ?
	       data->klass->set_wake_on_wlan (data, wowl) : FALSE;
}

guint32
wifi_utils_get_freq (WifiData *data)
{
	g_return_val_if_fail (data != NULL, 0);
	return data->klass->get_freq (data);
}

guint32
wifi_utils_find_freq (WifiData *data, const guint32 *freqs)
{
	g_return_val_if_fail (data != NULL, 0);
	g_return_val_if_fail (freqs != NULL, 0);
	return data->klass->find_freq (data, freqs);
}

gboolean
wifi_utils_get_bssid (WifiData *data, guint8 *out_bssid)
{
	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (out_bssid != NULL, FALSE);

	memset (out_bssid, 0, ETH_ALEN);
	return data->klass->get_bssid (data, out_bssid);
}

guint32
wifi_utils_get_rate (WifiData *data)
{
	g_return_val_if_fail (data != NULL, 0);
	return data->klass->get_rate (data);
}

int
wifi_utils_get_qual (WifiData *data)
{
	g_return_val_if_fail (data != NULL, 0);
	return data->klass->get_qual (data);
}

gboolean
wifi_utils_get_wowlan (WifiData *data)
{
	g_return_val_if_fail (data != NULL, 0);

	if (!data->klass->get_wowlan)
		return FALSE;
	return data->klass->get_wowlan (data);
}

void
wifi_utils_unref (WifiData *data)
{
	g_return_if_fail (data != NULL);

	data->klass->deinit (data);
	g_free (data);
}

gboolean
wifi_utils_is_wifi (int dirfd, const char *ifname)
{
	g_return_val_if_fail (dirfd >= 0, FALSE);

	if (faccessat (dirfd, "phy80211", F_OK, 0) == 0)
		return TRUE;
#if HAVE_WEXT
	if (wifi_wext_is_wifi (ifname))
		return TRUE;
#endif
	return FALSE;
}

/* OLPC Mesh-only functions */

guint32
wifi_utils_get_mesh_channel (WifiData *data)
{
	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (data->klass->get_mesh_channel != NULL, FALSE);
	return data->klass->get_mesh_channel (data);
}

gboolean
wifi_utils_set_mesh_channel (WifiData *data, guint32 channel)
{
	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (channel <= 13, FALSE);
	g_return_val_if_fail (data->klass->set_mesh_channel != NULL, FALSE);
	return data->klass->set_mesh_channel (data, channel);
}

gboolean
wifi_utils_set_mesh_ssid (WifiData *data, const guint8 *ssid, gsize len)
{
	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (data->klass->set_mesh_ssid != NULL, FALSE);
	return data->klass->set_mesh_ssid (data, ssid, len);
}

gboolean
wifi_utils_indicate_addressing_running (WifiData *data, gboolean running)
{
	g_return_val_if_fail (data != NULL, FALSE);
	if (data->klass->indicate_addressing_running)
		return data->klass->indicate_addressing_running (data, running);
	return FALSE;
}

