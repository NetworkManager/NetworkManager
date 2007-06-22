/* nm-tool - information tool for NetworkManager
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <iwlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <nm-client.h>
#include <nm-device.h>
#include <nm-device-802-3-ethernet.h>
#include <nm-device-802-11-wireless.h>



static gboolean
get_nm_state (NMClient *client)
{
	NMState state;
	char *state_string;
	gboolean success = TRUE;

	state = nm_client_get_state (client);

	switch (state) {
	case NM_STATE_ASLEEP:
		state_string = "asleep";
		break;

	case NM_STATE_CONNECTING:
		state_string = "connecting";
		break;

	case NM_STATE_CONNECTED:
		state_string = "connected";
		break;

	case NM_STATE_DISCONNECTED:
		state_string = "disconnected";
		break;

	case NM_STATE_UNKNOWN:
	default:
		state_string = "unknown";
		success = FALSE;
		break;
	}

	printf ("State: %s\n\n", state_string);

	return success;
}

static void
print_string (const char *label, const char *data)
{
#define SPACING 18
	int label_len = 0;
	char spaces[50];
	int i;

	g_return_if_fail (label != NULL);
	g_return_if_fail (data != NULL);

	label_len = strlen (label);
	if (label_len > SPACING)
		label_len = SPACING - 1;
	for (i = 0; i < (SPACING - label_len); i++)
		spaces[i] = 0x20;
	spaces[i] = 0x00;

	printf ("  %s:%s%s\n", label, &spaces[0], data);
}


static void
detail_network (gpointer data, gpointer user_data)
{
	NMAccessPoint *ap = NM_ACCESS_POINT (data);
	const char *active_bssid = (const char *) user_data;
	GString *str;
	gboolean active = FALSE;
	guint32 capabilities;
	char *essid;
	char *tmp;

	capabilities = nm_access_point_get_capabilities (ap);

	if (active_bssid) {
		char *current_bssid = nm_access_point_get_hw_address (ap);
		if (current_bssid && !strcmp (current_bssid, active_bssid))
			active = TRUE;

		g_free (current_bssid);
	}

	str = g_string_new (NULL);
	g_string_append_printf (str,
							"%s Mode, Freq %.3f MHz, Rate %d Mb/s, Strength %d",
							(nm_access_point_get_mode (ap) == IW_MODE_INFRA) ? "Infrastructure" : "Ad-Hoc",
							nm_access_point_get_frequency (ap) / 1000000000,
							nm_access_point_get_rate (ap) / 1024,
							nm_access_point_get_strength (ap));

	if (nm_access_point_is_encrypted (ap))
		g_string_append (str, ", Encrypted: ");

	if (capabilities & NM_802_11_CAP_PROTO_WEP)
		g_string_append (str, " WEP");
	if (capabilities & NM_802_11_CAP_PROTO_WPA)
		g_string_append (str, " WPA");
	if (capabilities & NM_802_11_CAP_PROTO_WPA2)
		g_string_append (str, " WPA2");
	if (capabilities & NM_802_11_CAP_KEY_MGMT_802_1X)
		g_string_append (str, " Enterprise");

	/* FIXME: broadcast/hidden */

	essid = nm_access_point_get_essid (ap);
	tmp = g_strdup_printf ("  %s%s", active ? "*" : "", essid);
	g_free (essid);

	print_string (tmp, str->str);

	g_string_free (str, TRUE);
	g_free (tmp);
}

static gchar *
ip4_address_as_string (guint32 ip)
{
	struct in_addr tmp_addr;
	gchar *ip_string;

	tmp_addr.s_addr = ip;
	ip_string = inet_ntoa (tmp_addr);

	return g_strdup (ip_string);
}

static void
detail_device (gpointer data, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (data);
	char *tmp;
	NMDeviceState state;
	int caps;
	int speed;
	GArray *array;

	state = nm_device_get_state (device);

	tmp = nm_device_get_iface (device);
	printf ("- Device: %s ----------------------------------------------------------------\n", tmp);
	g_free (tmp);

	/* General information */
	if (NM_IS_DEVICE_802_3_ETHERNET (device))
		print_string ("Type", "Wired");
	else if (NM_IS_DEVICE_802_11_WIRELESS (device))
		print_string ("Type", "802.11 Wireless");

	tmp = nm_device_get_driver (device);
	if (tmp) {
		print_string ("Driver", tmp);
		g_free (tmp);
	} else
		print_string ("Driver", "(unknown)");

	if (state == NM_DEVICE_STATE_ACTIVATED)
		print_string ("Active", "yes");
	else
		print_string ("Active", "no");

	tmp = NULL;
	if (NM_IS_DEVICE_802_3_ETHERNET (device))
		tmp = nm_device_802_3_ethernet_get_hw_address (NM_DEVICE_802_3_ETHERNET (device));
	else if (NM_IS_DEVICE_802_11_WIRELESS (device))
		tmp = nm_device_802_11_wireless_get_hw_address (NM_DEVICE_802_11_WIRELESS (device));

	if (tmp) {
		print_string ("HW Address", tmp);
		g_free (tmp);
	}

	/* Capabilities */
	caps = nm_device_get_capabilities (device);
	printf ("\n  Capabilities:\n");
	if (caps & NM_DEVICE_CAP_NM_SUPPORTED)
		print_string ("  Supported", "yes");
	else
		print_string ("  Supported", "no");
	if (caps & NM_DEVICE_CAP_CARRIER_DETECT)
		print_string ("  Carrier Detect", "yes");

	speed = 0;
	if (NM_IS_DEVICE_802_3_ETHERNET (device))
		speed = nm_device_802_3_ethernet_get_speed (NM_DEVICE_802_3_ETHERNET (device));
	else if (NM_IS_DEVICE_802_11_WIRELESS (device))
		speed = nm_device_802_11_wireless_get_bitrate (NM_DEVICE_802_11_WIRELESS (device));

	if (speed) {
		char *speed_string;

		speed_string = g_strdup_printf ("%d Mb/s", speed);
		print_string ("  Speed", speed_string);
		g_free (speed_string);
	}

	/* Wireless specific information */
	if ((NM_IS_DEVICE_802_11_WIRELESS (device))) {
		guint32 wireless_caps;
		NMAccessPoint *active_ap = NULL;
		char *active_bssid = NULL;
		GSList *networks;

		printf ("\n  Wireless Settings\n");

		if (caps & NM_DEVICE_CAP_WIRELESS_SCAN)
			print_string ("  Scanning", "yes");

		wireless_caps = nm_device_802_11_wireless_get_capabilities (NM_DEVICE_802_11_WIRELESS (device));

		if (wireless_caps & NM_802_11_CAP_PROTO_WEP)
			print_string ("  WEP Encryption", "yes");
		if (wireless_caps & NM_802_11_CAP_PROTO_WPA)
			print_string ("  WPA Encryption", "yes");
		if (wireless_caps & NM_802_11_CAP_PROTO_WPA2)
			print_string ("  WPA2 Encryption", "yes");

		if (nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED) {
			active_ap = nm_device_802_11_wireless_get_active_network (NM_DEVICE_802_11_WIRELESS (device));
			active_bssid = active_ap ? nm_access_point_get_hw_address (active_ap) : NULL;
		}

		printf ("\n  Wireless Networks%s\n", active_ap ? "(* = Current Network)" : "");

		networks = nm_device_802_11_wireless_get_networks (NM_DEVICE_802_11_WIRELESS (device));
		g_slist_foreach (networks, detail_network, active_bssid);
		g_free (active_bssid);
		g_slist_free (networks);
	} else if (NM_IS_DEVICE_802_3_ETHERNET (device)) {
		printf ("\n  Wired Settings\n");
		/* FIXME */
#if 0
		if (link_active)
			print_string ("  Hardware Link", "yes");
		else
			print_string ("  Hardware Link", "no");
#endif
	}

	/* IP Setup info */
	if (state == NM_DEVICE_STATE_ACTIVATED) {
		NMIP4Config *cfg = nm_device_get_ip4_config (device);

		printf ("\n  IP Settings:\n");

		tmp = ip4_address_as_string (nm_ip4_config_get_address (cfg));
		print_string ("  IP Address", tmp);
		g_free (tmp);

		tmp = ip4_address_as_string (nm_ip4_config_get_netmask (cfg));
		print_string ("  Subnet Mask", tmp);
		g_free (tmp);

		tmp = ip4_address_as_string (nm_ip4_config_get_broadcast (cfg));
		print_string ("  Broadcast", tmp);
		g_free (tmp);

		tmp = ip4_address_as_string (nm_ip4_config_get_gateway (cfg));
		print_string ("  Gateway", tmp);
		g_free (tmp);

		array = nm_ip4_config_get_nameservers (cfg);
		if (array) {
			int i;

			for (i = 0; i < array->len; i++) {
				tmp = ip4_address_as_string (g_array_index (array, guint32, i));
				print_string ("  DNS", tmp);
				g_free (tmp);
			}

			g_array_free (array, TRUE);
		}

		g_object_unref (cfg);
	}

	printf ("\n\n");
}


static void
print_devices (NMClient *client)
{
	GSList *devices;

	devices = nm_client_get_devices (client);
	g_slist_foreach (devices, detail_device, NULL);
	g_slist_free (devices);
}


int
main (int argc, char *argv[])
{
	NMClient *client;

	g_type_init ();

	client = nm_client_new ();
	if (!client) {
		exit (1);
	}

	printf ("\nNetworkManager Tool\n\n");

	if (!get_nm_state (client)) {
		fprintf (stderr, "\n\nNetworkManager appears not to be running (could not get its state).\n");
		exit (1);
	}

	print_devices (client);

	g_object_unref (client);

	return 0;
}
