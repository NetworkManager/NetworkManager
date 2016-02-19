/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2010 Red Hat, Inc.
 */

/*
 * The example shows how to get info about APs visible by Wi-Fi devices using
 * libnm.
 *
 * Compile with:
 *   gcc -Wall `pkg-config --libs --cflags glib-2.0 libnm` get-ap-info-libnm.c -o get-ap-info-libnm
 */

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

#include <NetworkManager.h>

/* Convert flags to string */
static char *
ap_wpa_rsn_flags_to_string (guint32 flags)
{
	char *flags_str[16]; /* Enough space for flags and terminating NULL */
	char *ret_str;
	int i = 0;

	if (flags & NM_802_11_AP_SEC_PAIR_WEP40)
		flags_str[i++] = g_strdup ("pair_wpe40");
	if (flags & NM_802_11_AP_SEC_PAIR_WEP104)
		flags_str[i++] = g_strdup ("pair_wpe104");
	if (flags & NM_802_11_AP_SEC_PAIR_TKIP)
		flags_str[i++] = g_strdup ("pair_tkip");
	if (flags & NM_802_11_AP_SEC_PAIR_CCMP)
		flags_str[i++] = g_strdup ("pair_ccmp");
	if (flags & NM_802_11_AP_SEC_GROUP_WEP40)
		flags_str[i++] = g_strdup ("group_wpe40");
	if (flags & NM_802_11_AP_SEC_GROUP_WEP104)
		flags_str[i++] = g_strdup ("group_wpe104");
	if (flags & NM_802_11_AP_SEC_GROUP_TKIP)
		flags_str[i++] = g_strdup ("group_tkip");
	if (flags & NM_802_11_AP_SEC_GROUP_CCMP)
		flags_str[i++] = g_strdup ("group_ccmp");
	if (flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)
		flags_str[i++] = g_strdup ("psk");
	if (flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
		flags_str[i++] = g_strdup ("802.1X");

	if (i == 0)
		flags_str[i++] = g_strdup ("none");

	flags_str[i] = NULL;

	ret_str = g_strjoinv (" ", flags_str);

	i = 0;
	while (flags_str[i])
		 g_free (flags_str[i++]);

	return ret_str;
}

static void
show_access_point_info (NMAccessPoint *ap)
{
	guint32 flags, wpa_flags, rsn_flags, freq, bitrate;
	guint8 strength;
	GBytes *ssid; 
	const char *hwaddr;
	NM80211Mode mode;
	char *freq_str, *ssid_str, *bitrate_str, *strength_str, *wpa_flags_str, *rsn_flags_str;
	GString *security_str;

	/* Get AP properties */
	flags = nm_access_point_get_flags (ap);
	wpa_flags = nm_access_point_get_wpa_flags (ap);
	rsn_flags = nm_access_point_get_rsn_flags (ap);
	ssid = nm_access_point_get_ssid (ap);
	hwaddr = nm_access_point_get_bssid (ap);
	freq = nm_access_point_get_frequency (ap);
	mode = nm_access_point_get_mode (ap);
	bitrate = nm_access_point_get_max_bitrate (ap);
	strength = nm_access_point_get_strength (ap);

	/* Convert to strings */
	if (ssid)
		ssid_str = nm_utils_ssid_to_utf8 (g_bytes_get_data (ssid, NULL), g_bytes_get_size (ssid));
	else
		ssid_str = g_strdup ("--");
	freq_str = g_strdup_printf ("%u MHz", freq);
	bitrate_str = g_strdup_printf ("%u Mbit/s", bitrate/1000);
	strength_str = g_strdup_printf ("%u", strength);
	wpa_flags_str = ap_wpa_rsn_flags_to_string (wpa_flags);
	rsn_flags_str = ap_wpa_rsn_flags_to_string (rsn_flags);

	security_str = g_string_new (NULL);
	if (   !(flags & NM_802_11_AP_FLAGS_PRIVACY)
	    &&  (wpa_flags != NM_802_11_AP_SEC_NONE)
	    &&  (rsn_flags != NM_802_11_AP_SEC_NONE))
		g_string_append (security_str, "Encrypted: ");

	if (   (flags & NM_802_11_AP_FLAGS_PRIVACY)
	    && (wpa_flags == NM_802_11_AP_SEC_NONE)
	    && (rsn_flags == NM_802_11_AP_SEC_NONE))
		g_string_append (security_str, "WEP ");
	if (wpa_flags != NM_802_11_AP_SEC_NONE)
		g_string_append (security_str, "WPA ");
	if (rsn_flags != NM_802_11_AP_SEC_NONE)
		g_string_append (security_str, "WPA2 ");
	if (   (wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
	    || (rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
		g_string_append (security_str, "Enterprise ");

	if (security_str->len > 0)
		g_string_truncate (security_str, security_str->len-1);  /* Chop off last space */

	printf ("SSID:       %s\n", ssid_str);
	printf ("BSSID:      %s\n", hwaddr);
	printf ("Mode:       %s\n", mode == NM_802_11_MODE_ADHOC ? "Ad-Hoc"
	                          : mode == NM_802_11_MODE_INFRA ? "Infrastructure"
	                          : "Unknown");
	printf ("Freq:       %s\n", freq_str);
	printf ("Bitrate:    %s\n", bitrate_str);
	printf ("Strength:   %s\n", strength_str);
	printf ("Security:   %s\n", security_str->str);
	printf ("WPA flags:  %s\n", wpa_flags_str);
	printf ("RSN flags:  %s\n", rsn_flags_str);
	printf ("D-Bus path: %s\n\n", nm_object_get_path (NM_OBJECT (ap)));

	g_free (ssid_str);
	g_free (freq_str);
	g_free (bitrate_str);
	g_free (strength_str);
	g_free (wpa_flags_str);
	g_free (rsn_flags_str);
	g_string_free (security_str, TRUE);
}

static void
show_wifi_device_info (NMDevice *device)
{
	NMAccessPoint *active_ap = NULL;
	const GPtrArray *aps;
	const char *iface;
	const char *driver;
	guint32 speed;
	GBytes *active_ssid; 
	char *active_ssid_str = NULL;
	int i;

	/* Get active AP */
	if (nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED) {
		if ((active_ap = nm_device_wifi_get_active_access_point (NM_DEVICE_WIFI (device)))) {
			active_ssid = nm_access_point_get_ssid (active_ap);
			if (active_ssid)
				active_ssid_str = nm_utils_ssid_to_utf8 (g_bytes_get_data (active_ssid, NULL),
				                                         g_bytes_get_size (active_ssid));
			else
				active_ssid_str = g_strdup ("--");
		}
	}

        iface = nm_device_get_iface (device);
        driver = nm_device_get_driver (device);
	speed = nm_device_wifi_get_bitrate (NM_DEVICE_WIFI (device));
	speed /= 1000;

	printf ("Device: %s  ----  Driver: %s  ----  Speed: %d Mbit/s  ----  Active AP: %s\n",
	         iface, driver, speed, active_ssid_str ? active_ssid_str : "none");
	printf ("=================================================================================\n");
	g_free (active_ssid_str);

	/* Get all APs of the Wi-Fi device */
	aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (device));

	/* Print AP details */
	for (i = 0; i < aps->len; i++) {
		NMAccessPoint *ap = g_ptr_array_index (aps, i);
		show_access_point_info (ap);
	}
}

int
main (int argc, char *argv[])
{
	NMClient *client;
	const GPtrArray *devices;
	int i;
	GError *error = NULL;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	/* Initialize GType system */
	g_type_init ();
#endif

	/* Get NMClient object */
	client = nm_client_new (NULL, &error);
	if (!client) {
		g_message ("Error: Could not create NMClient: %s.", error->message);
		g_error_free (error);
		return EXIT_FAILURE;
	}

	/* Get all devices managed by NetworkManager */
	devices = nm_client_get_devices (client);

	/* Go through the array and process Wi-Fi devices */
	for (i = 0; i < devices->len; i++) {
		NMDevice *device = g_ptr_array_index (devices, i);
		if (NM_IS_DEVICE_WIFI (device))
			show_wifi_device_info (device);
	}

	g_object_unref (client);

	return EXIT_SUCCESS;
}
