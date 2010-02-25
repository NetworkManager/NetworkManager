/* nmcli - command-line tool to control NetworkManager
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
 * (C) Copyright 2010 Red Hat, Inc.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>
#include <glib/gi18n.h>
#include <nm-client.h>
#include <nm-device-wifi.h>

#include <nm-client.h>
#include <nm-device.h>
#include <nm-device-ethernet.h>
#include <nm-device-wifi.h>
#include <nm-gsm-device.h>
#include <nm-cdma-device.h>
#include <nm-device-bt.h>
//#include <nm-device-olpc-mesh.h>
#include <nm-utils.h>
#include <nm-setting-ip4-config.h>
#include <nm-vpn-connection.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-pppoe.h>
#include <nm-setting-wireless.h>
#include <nm-setting-gsm.h>
#include <nm-setting-cdma.h>
#include <nm-setting-bluetooth.h>
#include <nm-setting-olpc-mesh.h>

#include "utils.h"
#include "devices.h"


/* static function prototypes */
static void usage (void);
static const char *device_state_to_string (NMDeviceState state);
static NMCResultCode do_devices_status (NmCli *nmc, int argc, char **argv);
static NMCResultCode do_devices_list (NmCli *nmc, int argc, char **argv);
static NMCResultCode do_device_disconnect (NmCli *nmc, int argc, char **argv);
static NMCResultCode do_device_wifi (NmCli *nmc, int argc, char **argv);


extern GMainLoop *loop;   /* glib main loop variable */

static void
usage (void)
{
	fprintf (stderr,
	 	 _("Usage: nmcli dev { COMMAND | help }\n\n"
		 "  COMMAND := { status | list | disconnect | wifi }\n\n"
		 "  status\n"
		 "  list [iface <iface>]\n"
		 "  disconnect iface <iface> [--nowait] [--timeout <timeout>]\n"
		 "  wifi [list [iface <iface>] | apinfo iface <iface> hwaddr <hwaddr>]\n\n"));
}

/* quit main loop */
static void
quit (void)
{
	g_main_loop_quit (loop);  /* quit main loop */
}

static const char *
device_state_to_string (NMDeviceState state)
{
	switch (state) {
	case NM_DEVICE_STATE_UNMANAGED:
		return _("unmanaged");
	case NM_DEVICE_STATE_UNAVAILABLE:
		return _("unavailable");
	case NM_DEVICE_STATE_DISCONNECTED:
		return _("disconnected");
	case NM_DEVICE_STATE_PREPARE:
		return _("connecting (prepare)");
	case NM_DEVICE_STATE_CONFIG:
		return _("connecting (configuring)");
	case NM_DEVICE_STATE_NEED_AUTH:
		return _("connecting (need authentication)");
	case NM_DEVICE_STATE_IP_CONFIG:
		return _("connecting (getting IP configuration)");
	case NM_DEVICE_STATE_ACTIVATED:
		return _("connected");
	case NM_DEVICE_STATE_FAILED:
		return _("connection failed");
	default:
		return _("unknown");
	}
}

/* Return device type - use setting names to match with connection types */
static const char *
get_device_type (NMDevice * device)
{
	if (NM_IS_DEVICE_ETHERNET (device))
		return NM_SETTING_WIRED_SETTING_NAME;
	else if (NM_IS_DEVICE_WIFI (device))
		return NM_SETTING_WIRELESS_SETTING_NAME;
	else if (NM_IS_GSM_DEVICE (device))
		return NM_SETTING_GSM_SETTING_NAME;
	else if (NM_IS_CDMA_DEVICE (device))
		return NM_SETTING_CDMA_SETTING_NAME;
	else if (NM_IS_DEVICE_BT (device))
		return NM_SETTING_BLUETOOTH_SETTING_NAME;
//	else if (NM_IS_DEVICE_OLPC_MESH (device))
//		return NM_SETTING_OLPC_MESH_SETTING_NAME;
	else
		return _("Unknown");
}

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
		flags_str[i++] = g_strdup (_("(none)"));

	flags_str[i] = NULL;

	ret_str = g_strjoinv (" ", flags_str);

	i = 0;
	while (flags_str[i])
		 g_free (flags_str[i++]);

	return ret_str;
}

static void
print_header (const char *label, const char *iface, const char *connection)
{
	GString *string;

	string = g_string_sized_new (79);
	g_string_append_printf (string, "- %s: ", label);
	if (iface)
		g_string_append_printf (string, "%s ", iface);
	if (connection)
		g_string_append_printf (string, " [%s] ", connection);

	while (string->len < 80)
		g_string_append_c (string, '-');

	printf ("%s\n", string->str);

	g_string_free (string, TRUE);
}

static gchar *
ip4_address_as_string (guint32 ip)
{
	struct in_addr tmp_addr;
	char buf[INET_ADDRSTRLEN+1];

	memset (&buf, '\0', sizeof (buf));
	tmp_addr.s_addr = ip;

	if (inet_ntop (AF_INET, &tmp_addr, buf, INET_ADDRSTRLEN)) {
		return g_strdup (buf);
	} else {
		g_warning (_("%s: error converting IP4 address 0x%X"),
		            __func__, ntohl (tmp_addr.s_addr));
		return NULL;
	}
}

static void
detail_access_point (gpointer data, gpointer user_data)
{
	NMAccessPoint *ap = NM_ACCESS_POINT (data);
	const char *active_bssid = (const char *) user_data;
	GString *str;
	gboolean active = FALSE;
	guint32 flags, wpa_flags, rsn_flags;
	const GByteArray * ssid;
	char *tmp;

	flags = nm_access_point_get_flags (ap);
	wpa_flags = nm_access_point_get_wpa_flags (ap);
	rsn_flags = nm_access_point_get_rsn_flags (ap);

	if (active_bssid) {
		const char *current_bssid = nm_access_point_get_hw_address (ap);
		if (current_bssid && !strcmp (current_bssid, active_bssid))
			active = TRUE;
	}

	str = g_string_new (NULL);
	g_string_append_printf (str,
	                        _("%s, %s, Freq %d MHz, Rate %d Mb/s, Strength %d"),
	                        (nm_access_point_get_mode (ap) == NM_802_11_MODE_INFRA) ? ("Infra") : _("Ad-Hoc"),
	                        nm_access_point_get_hw_address (ap),
	                        nm_access_point_get_frequency (ap),
	                        nm_access_point_get_max_bitrate (ap) / 1000,
	                        nm_access_point_get_strength (ap));

	if (   !(flags & NM_802_11_AP_FLAGS_PRIVACY)
	    &&  (wpa_flags != NM_802_11_AP_SEC_NONE)
	    &&  (rsn_flags != NM_802_11_AP_SEC_NONE))
		g_string_append (str, _(", Encrypted: "));

	if (   (flags & NM_802_11_AP_FLAGS_PRIVACY)
	    && (wpa_flags == NM_802_11_AP_SEC_NONE)
	    && (rsn_flags == NM_802_11_AP_SEC_NONE))
		g_string_append (str, _(" WEP"));
	if (wpa_flags != NM_802_11_AP_SEC_NONE)
		g_string_append (str, _(" WPA"));
	if (rsn_flags != NM_802_11_AP_SEC_NONE)
		g_string_append (str, _(" WPA2"));
	if (   (wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
	    || (rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
		g_string_append (str, _(" Enterprise"));

	/* FIXME: broadcast/hidden */

	ssid = nm_access_point_get_ssid (ap);
	tmp = g_strdup_printf ("  %s%s", active ? "*" : "",
	                       ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : _("(none)"));

	print_table_line (0, tmp, 25, str->str, 0, NULL);

	g_string_free (str, TRUE);
	g_free (tmp);
}

struct cb_info {
	NMClient *client;
	const GPtrArray *active;
};

static void
show_device_info (gpointer data, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (data);
//	struct cb_info *info = user_data;
	char *tmp;
	NMDeviceState state;
	const char *dev_type;
	guint32 caps;
	guint32 speed;
	const GArray *array;
	gboolean is_default = FALSE;
	const char *id = NULL;

	state = nm_device_get_state (device);
	print_header (_("Device"), nm_device_get_iface (device), id);

	/* General information */
	dev_type = get_device_type (device);
	print_table_line (0, _("Type"), 25, dev_type, 0, NULL);
	print_table_line (0, _("Driver"), 25, nm_device_get_driver (device) ? nm_device_get_driver (device) : _("(unknown)"), 0, NULL);
	print_table_line (0, _("State"), 25, device_state_to_string (state), 0, NULL);
	if (is_default)
		print_table_line (0, _("Default"), 25, _("yes"), 0, NULL);
	else
		print_table_line (0, _("Default"), 25, _("no"), 0, NULL);

	tmp = NULL;
	if (NM_IS_DEVICE_ETHERNET (device))
		tmp = g_strdup (nm_device_ethernet_get_hw_address (NM_DEVICE_ETHERNET (device)));
	else if (NM_IS_DEVICE_WIFI (device))
		tmp = g_strdup (nm_device_wifi_get_hw_address (NM_DEVICE_WIFI (device)));

	if (tmp) {
		print_table_line (0, _("HW Address"), 25, tmp, 0, NULL);
		g_free (tmp);
	}

	/* Capabilities */
	caps = nm_device_get_capabilities (device);
	printf (_("\n  Capabilities:\n"));
	if (caps & NM_DEVICE_CAP_CARRIER_DETECT)
		print_table_line (2, _("Carrier Detect"), 23, _("yes"), 0, NULL);

	speed = 0;
	if (NM_IS_DEVICE_ETHERNET (device)) {
		/* Speed in Mb/s */
		speed = nm_device_ethernet_get_speed (NM_DEVICE_ETHERNET (device));
	} else if (NM_IS_DEVICE_WIFI (device)) {
		/* Speed in b/s */
		speed = nm_device_wifi_get_bitrate (NM_DEVICE_WIFI (device));
		speed /= 1000;
	}

	if (speed) {
		char *speed_string;

		speed_string = g_strdup_printf (_("%u Mb/s"), speed);
		print_table_line (2, _("Speed"), 23, speed_string, 0, NULL);
		g_free (speed_string);
	}

	/* Wireless specific information */
	if ((NM_IS_DEVICE_WIFI (device))) {
		guint32 wcaps;
		NMAccessPoint *active_ap = NULL;
		const char *active_bssid = NULL;
		const GPtrArray *aps;

		printf (_("\n  Wireless Properties\n"));

		wcaps = nm_device_wifi_get_capabilities (NM_DEVICE_WIFI (device));

		if (wcaps & (NM_WIFI_DEVICE_CAP_CIPHER_WEP40 | NM_WIFI_DEVICE_CAP_CIPHER_WEP104))
			print_table_line (2, _("WEP Encryption"), 23, _("yes"), 0, NULL);
		if (wcaps & NM_WIFI_DEVICE_CAP_WPA)
			print_table_line (2, _("WPA Encryption"), 23, _("yes"), 0, NULL);
		if (wcaps & NM_WIFI_DEVICE_CAP_RSN)
			print_table_line (2, _("WPA2 Encryption"), 23, _("yes"), 0, NULL);
		if (wcaps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP)
			print_table_line (2, _("TKIP cipher"), 23, _("yes"), 0, NULL);
		if (wcaps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP)
			print_table_line (2, _("CCMP cipher"), 23, _("yes"), 0, NULL);

		if (nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED) {
			active_ap = nm_device_wifi_get_active_access_point (NM_DEVICE_WIFI (device));
			active_bssid = active_ap ? nm_access_point_get_hw_address (active_ap) : NULL;
		}

		printf (_("\n  Wireless Access Points %s\n"), active_ap ? _("(* = current AP)") : "");

		aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (device));
		if (aps && aps->len)
			g_ptr_array_foreach ((GPtrArray *) aps, detail_access_point, (gpointer) active_bssid);
	} else if (NM_IS_DEVICE_ETHERNET (device)) {
		printf (_("\n  Wired Properties\n"));

		if (nm_device_ethernet_get_carrier (NM_DEVICE_ETHERNET (device)))
			print_table_line (2, _("Carrier"), 23, _("on"), 0, NULL);
		else
			print_table_line (2, _("Carrier"), 23, _("off"), 0, NULL);
	}

	/* IP Setup info */
	if (state == NM_DEVICE_STATE_ACTIVATED) {
		NMIP4Config *cfg = nm_device_get_ip4_config (device);
		GSList *iter;

		printf (_("\n  IPv4 Settings:\n"));

		for (iter = (GSList *) nm_ip4_config_get_addresses (cfg); iter; iter = g_slist_next (iter)) {
			NMIP4Address *addr = (NMIP4Address *) iter->data;
			guint32 prefix = nm_ip4_address_get_prefix (addr);
			char *tmp2;

			tmp = ip4_address_as_string (nm_ip4_address_get_address (addr));
			print_table_line (2, _("Address"), 23, tmp, 0, NULL);
			g_free (tmp);

			tmp2 = ip4_address_as_string (nm_utils_ip4_prefix_to_netmask (prefix));
			tmp = g_strdup_printf ("%d (%s)", prefix, tmp2);
			g_free (tmp2);
			print_table_line (2, _("Prefix"), 23, tmp, 0, NULL);
			g_free (tmp);

			tmp = ip4_address_as_string (nm_ip4_address_get_gateway (addr));
			print_table_line (2, _("Gateway"), 23, tmp, 0, NULL);
			g_free (tmp);
			printf ("\n");
		}

		array = nm_ip4_config_get_nameservers (cfg);
		if (array) {
			int i;

			for (i = 0; i < array->len; i++) {
				tmp = ip4_address_as_string (g_array_index (array, guint32, i));
				print_table_line (2, _("DNS"), 23, tmp, 0, NULL);
				g_free (tmp);
			}
		}
	}

	printf ("\n\n");
}

static void
show_device_status (NMDevice *device, NmCli *nmc)
{
	const char *iface;
	const char *type;
	const char *state;

	iface = nm_device_get_iface (device);
	type = get_device_type (device);
	state = device_state_to_string (nm_device_get_state (device));

	print_table_line (0, iface, 10, type, 17, state, 0, NULL);
}

static NMCResultCode
do_devices_status (NmCli *nmc, int argc, char **argv)
{
	const GPtrArray *devices;
	int i;

	while (argc > 0) {
		fprintf (stderr, _("Unknown parameter: %s\n"), *argv);
		argc--;
		argv++;
	}

	/* create NMClient */
	if (!nmc->get_client (nmc))
		goto error;

	devices = nm_client_get_devices (nmc->client);

	if (nmc->print_output == NMC_PRINT_PRETTY)
		print_table_header (_("Status of devices"), _("Device"), 10, _("Type"), 17, _("State"), 12, NULL);
	else if (nmc->print_output == NMC_PRINT_NORMAL)
		print_table_line (0, _("Device"), 10, _("Type"), 17, _("State"), 0, NULL);

	for (i = 0; devices && (i < devices->len); i++) {
		NMDevice *device = g_ptr_array_index (devices, i);
		show_device_status (device, nmc);
	}

	return NMC_RESULT_SUCCESS;

error:
	return nmc->return_value;
}

static NMCResultCode
do_devices_list (NmCli *nmc, int argc, char **argv)
{
	const GPtrArray *devices;
	NMDevice *device = NULL;
	const char *iface = NULL;
	gboolean iface_specified = FALSE;
	int i;

	while (argc > 0) {
		if (strcmp (*argv, "iface") == 0) {
			iface_specified = TRUE;

			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: '%s' argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
				goto error;
			}

			iface = *argv;
		} else {
			fprintf (stderr, _("Unknown parameter: %s\n"), *argv);
		}

		argc--;
		argv++;
	}

	/* create NMClient */
	if (!nmc->get_client (nmc))
		goto error;

	devices = nm_client_get_devices (nmc->client);

	if (iface_specified) {
		for (i = 0; devices && (i < devices->len); i++) {
			NMDevice *candidate = g_ptr_array_index (devices, i);
			const char *dev_iface = nm_device_get_iface (candidate);

			if (!strcmp (dev_iface, iface))
				device = candidate;
		}
		if (!device) {
		 	g_string_printf (nmc->return_text, _("Error: Device '%s' not found."), iface);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			goto error;
		}
		show_device_info (device, nmc->client);
	} else {
		if (devices)
			g_ptr_array_foreach ((GPtrArray *) devices, show_device_info, nmc->client);
	}

error:
	return nmc->return_value;
}

static void
device_state_cb (NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;
	NMDeviceState state;

	state = nm_device_get_state (device);

	if (state == NM_DEVICE_STATE_DISCONNECTED) {
		g_string_printf (nmc->return_text, _("Success: Device '%s' successfully disconnected."), nm_device_get_iface (device));
		quit ();
	}
}

static gboolean
timeout_cb (gpointer user_data)
{
	/* Time expired -> exit nmcli */

	NmCli *nmc = (NmCli *) user_data;

	g_string_printf (nmc->return_text, _("Error: Timeout %d sec expired."), nmc->timeout);
	nmc->return_value = NMC_RESULT_ERROR_TIMEOUT_EXPIRED;
	quit ();
	return FALSE;
}

static void
disconnect_device_cb (NMDevice *device, GError *error, gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;
	NMDeviceState state;

	if (error) {
		g_string_printf (nmc->return_text, _("Error: Device '%s' (%s) disconnecting failed: %s"),
		                 nm_device_get_iface (device),
		                 nm_object_get_path (NM_OBJECT (device)),
		                 error->message ? error->message : _("(unknown)"));
		nmc->return_value = NMC_RESULT_ERROR_DEV_DISCONNECT;
		quit ();
	} else {
		state = nm_device_get_state (device);
		printf (_("Device state: %d (%s)\n"), state, device_state_to_string (state));

		if (!nmc->should_wait || state == NM_DEVICE_STATE_DISCONNECTED) {
			/* Don't want to wait or device already disconnected */
			quit ();
		} else {
			g_signal_connect (device, "notify::state", G_CALLBACK (device_state_cb), nmc);
			/* Start timer not to loop forever if "notify::state" signal is not issued */
			g_timeout_add_seconds (nmc->timeout, timeout_cb, nmc);
		}

	}
}

static NMCResultCode
do_device_disconnect (NmCli *nmc, int argc, char **argv)
{
	const GPtrArray *devices;
	NMDevice *device = NULL;
	const char *iface = NULL;
	gboolean iface_specified = FALSE;
	gboolean wait = TRUE;
	int i;

	/* Set default timeout for disconnect operation */
	nmc->timeout = 10;

	while (argc > 0) {
		if (strcmp (*argv, "iface") == 0) {
			iface_specified = TRUE;

			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
				goto error;
			}

			iface = *argv;
		} else if (strcmp (*argv, "--nowait") == 0) {
			wait = FALSE;
		} else if (strcmp (*argv, "--timeout") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
				goto error;
			}

			errno = 0;
			nmc->timeout = strtol (*argv, NULL, 10);
			if (errno || nmc->timeout < 0) {
				g_string_printf (nmc->return_text, _("Error: timeout value '%s' is not valid."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
				goto error;
			}

		} else {
			fprintf (stderr, _("Unknown parameter: %s\n"), *argv);
		}

		argc--;
		argv++;
	}

	if (!iface_specified) {
		g_string_printf (nmc->return_text, _("Error: iface has to be specified."));
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto error;
	}

	/* create NMClient */
	if (!nmc->get_client (nmc))
		goto error;

	devices = nm_client_get_devices (nmc->client);
	for (i = 0; devices && (i < devices->len); i++) {
		NMDevice *candidate = g_ptr_array_index (devices, i);
		const char *dev_iface = nm_device_get_iface (candidate);

		if (!strcmp (dev_iface, iface))
			device = candidate;
	}

	if (!device) {
		g_string_printf (nmc->return_text, _("Error: Device '%s' not found."), iface);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto error;
	}

	nmc->should_wait = wait;
	nm_device_disconnect (device, disconnect_device_cb, nmc);

error:
	return nmc->return_value;
}

static void
show_acces_point_info (NMDevice *device)
{
	NMAccessPoint *active_ap = NULL;
	const char *active_bssid = NULL;
	const GPtrArray *aps;

	if (nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED) {
		active_ap = nm_device_wifi_get_active_access_point (NM_DEVICE_WIFI (device));
		active_bssid = active_ap ? nm_access_point_get_hw_address (active_ap) : NULL;
	}

	aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (device));
	if (aps && aps->len)
		g_ptr_array_foreach ((GPtrArray *) aps, detail_access_point, (gpointer) active_bssid);
}

static NMCResultCode
do_device_wifi_list (NmCli *nmc, int argc, char **argv)
{
	//TODO: cleanup
	const GPtrArray *devices;
	NMDevice *device = NULL;
	const char *iface = NULL;
	gboolean iface_specified = FALSE;
	int i;

	while (argc > 0) {
		if (strcmp (*argv, "iface") == 0) {
			iface_specified = TRUE;

			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
				goto error;
			}

			iface = *argv;
		} else {
			fprintf (stderr, _("Unknown parameter: %s\n"), *argv);
		}

		argc--;
		argv++;
	}

	/* create NMClient */
	if (!nmc->get_client (nmc))
		goto error;

	devices = nm_client_get_devices (nmc->client);

	if (iface_specified) {
		for (i = 0; devices && (i < devices->len); i++) {
			NMDevice *candidate = g_ptr_array_index (devices, i);
			const char *dev_iface = nm_device_get_iface (candidate);

			if (!strcmp (dev_iface, iface))
				device = candidate;
		}

		if (!device) {
		 	g_string_printf (nmc->return_text, _("Error: Device '%s' not found."), iface);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			goto error;
		}

		if ((NM_IS_DEVICE_WIFI (device))) {
			if (nmc->print_output == NMC_PRINT_PRETTY)
				print_table_header (_("WiFi scan list"), NULL);

			show_acces_point_info (device);
		} else {
		 	g_string_printf (nmc->return_text, _("Error: Device '%s' is not a WiFi device."), iface);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			goto error;
		}
	} else {
		if (nmc->print_output == NMC_PRINT_PRETTY)
			print_table_header (_("WiFi scan list"), NULL);

		for (i = 0; devices && (i < devices->len); i++) {
			NMDevice *dev = g_ptr_array_index (devices, i);
			const char *dev_iface = nm_device_get_iface (dev);

			if ((NM_IS_DEVICE_WIFI (dev))) {
				if (nmc->print_output > NMC_PRINT_TERSE)
					print_table_line (0, _("Device:"), 0, dev_iface, 0, NULL);

				show_acces_point_info (dev);
			}
		}
	}

error:
	return nmc->return_value;
}

static NMCResultCode
do_device_wifi_apinfo (NmCli *nmc, int argc, char **argv)
{
	const GPtrArray *devices;
	const GPtrArray *aps;
	NMAccessPoint *ap = NULL;
	const char *iface = NULL;
	const char *hwaddr_user = NULL;
	const char *hwaddr;
	gboolean stop = FALSE;
	guint32 flags, wpa_flags, rsn_flags, freq, bitrate;
	guint8 strength;
	const GByteArray *ssid; 
	NM80211Mode mode;
	char *freq_str, *ssid_str, *bitrate_str, *strength_str, *wpa_flags_str, *rsn_flags_str;
	int i, j;

	while (argc > 0) {
		if (strcmp (*argv, "iface") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
				goto error;
			}
			iface = *argv;
		} else if (strcmp (*argv, "hwaddr") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
				goto error;
			}
			hwaddr_user = *argv;
		} else {
			fprintf (stderr, _("Unknown parameter: %s\n"), *argv);
		}

		argc--;
		argv++;
	}

	if (!hwaddr_user) {
		g_string_printf (nmc->return_text, _("Error: hwaddr has to be specified."));
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto error;
	}

	/* create NMClient */
	if (!nmc->get_client (nmc))
		goto error;

	devices = nm_client_get_devices (nmc->client);

	for (i = 0; !stop && devices && (i < devices->len); i++) {
		NMDevice *device = g_ptr_array_index (devices, i);
		const char *dev_iface = nm_device_get_iface (device);

		if (iface) {
			if (!strcmp (iface, dev_iface))
				stop = TRUE;
			else
				continue;
		}

		aps = NULL;
		if ((NM_IS_DEVICE_WIFI (device)))
			aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (device));
		for (j = 0; aps && (j < aps->len); j++) {
			char *hwaddr_up;
			NMAccessPoint *candidate_ap = g_ptr_array_index (aps, j);
			const char *candidate_hwaddr = nm_access_point_get_hw_address (candidate_ap);

			hwaddr_up = g_ascii_strup (hwaddr_user, -1);
			if (!strcmp (hwaddr_up, candidate_hwaddr))
				ap = candidate_ap;
			g_free (hwaddr_up);
		}
	}

	if (!ap) {
	 	g_string_printf (nmc->return_text, _("Error: Access point with hwaddr '%s' not found."), hwaddr_user);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto error;
	}

	/* get AP properties */
	flags = nm_access_point_get_flags (ap);
	wpa_flags = nm_access_point_get_wpa_flags (ap);
	rsn_flags = nm_access_point_get_rsn_flags (ap);
	ssid = nm_access_point_get_ssid (ap);
	hwaddr = nm_access_point_get_hw_address (ap);
	freq = nm_access_point_get_frequency (ap);
	mode = nm_access_point_get_mode (ap);
	bitrate = nm_access_point_get_max_bitrate (ap);
	strength = nm_access_point_get_strength (ap);

	/* print them */
	ssid_str = g_strdup_printf ("%s", ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : _("(none)"));
	freq_str = g_strdup_printf (_("%u MHz"), freq);
	bitrate_str = g_strdup_printf (_("%u MB/s"), bitrate/1000);
	strength_str = g_strdup_printf ("%u", strength);
	wpa_flags_str = ap_wpa_rsn_flags_to_string (wpa_flags);
	rsn_flags_str = ap_wpa_rsn_flags_to_string (rsn_flags);

	if (nmc->print_output == NMC_PRINT_PRETTY)
		print_table_header (_("AP parameters"), NULL);
	else if (nmc->print_output == NMC_PRINT_NORMAL)
		print_table_line (0, _("AP parameters"), 0, NULL);

	print_table_line (0, _("SSID:"), 25, ssid_str, 0, NULL);
	print_table_line (0, _("BSSID:"), 25, hwaddr, 0, NULL);
	print_table_line (0, _("Frequency:"), 25, freq_str, 0, NULL);
	print_table_line (0, _("Mode:"), 25, mode == NM_802_11_MODE_ADHOC ? _("Ad-hoc") : mode == NM_802_11_MODE_INFRA ? _("Infrastructure") : _("Unknown"), 0, NULL);
	print_table_line (0, _("Maximal bitrate:"), 25, bitrate_str, 0, NULL);
	print_table_line (0, _("Strength:"), 25, strength_str, 0, NULL);
	print_table_line (0, _("Flags:"), 25, flags == NM_802_11_AP_FLAGS_PRIVACY ? _("privacy") : _("(none)"), 0, NULL);
	print_table_line (0, _("WPA flags:"), 25, wpa_flags_str, 0, NULL);
	print_table_line (0, _("RSN flags:"), 25, rsn_flags_str, 0, NULL);

	g_free (ssid_str);
	g_free (freq_str);
	g_free (bitrate_str);
	g_free (strength_str);
	g_free (wpa_flags_str);
	g_free (rsn_flags_str);

error:
	return nmc->return_value;
}

static NMCResultCode
do_device_wifi (NmCli *nmc, int argc, char **argv)
{
	if (argc == 0)
		nmc->return_value = do_device_wifi_list (nmc, argc-1, argv+1);
	else if (argc > 0) {
		if (matches (*argv, "list") == 0) {
			nmc->return_value = do_device_wifi_list (nmc, argc-1, argv+1);
		}
		else if (matches (*argv, "apinfo") == 0) {
			nmc->return_value = do_device_wifi_apinfo (nmc, argc-1, argv+1);
		}
		else {
			g_string_printf (nmc->return_text, _("Error: 'dev wifi' command '%s' is not valid."), *argv);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		}
	}

	return nmc->return_value;
}


NMCResultCode
do_devices (NmCli *nmc, int argc, char **argv)
{
	/* create NMClient */
	if (!nmc->get_client (nmc))
		goto error;

	if (argc == 0)
		nmc->return_value = do_devices_status (nmc, argc-1, argv+1);

	if (argc > 0) {
		if (matches (*argv, "status") == 0) {
			nmc->return_value = do_devices_status (nmc, argc-1, argv+1);
		}
		else if (matches (*argv, "list") == 0) {
			nmc->return_value = do_devices_list (nmc, argc-1, argv+1);
		}
		else if (matches (*argv, "disconnect") == 0) {
			nmc->return_value = do_device_disconnect (nmc, argc-1, argv+1);
		}
		else if (matches (*argv, "wifi") == 0) {
			nmc->return_value = do_device_wifi (nmc, argc-1, argv+1);
		}
		else if (strcmp (*argv, "help") == 0) {
			usage ();
		}
		else {
			g_string_printf (nmc->return_text, _("Error: 'dev' command '%s' is not valid."), *argv);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		}
	}

error:
	return nmc->return_value;
}
