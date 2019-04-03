/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "nm-client.h"
#include "nm-device.h"
#include "nm-device-ethernet.h"
#include "nm-device-wifi.h"
#include "nm-device-generic.h"
#include "nm-utils.h"
#include "nm-active-connection.h"
#include "nm-vpn-connection.h"
#include "nm-setting-ip4-config.h"

static gboolean
test_wireless_enabled (NMClient *client)
{
	gboolean wireless;

	wireless = nm_client_wireless_get_enabled (client);
	g_print ("Wireless enabled? %s\n", wireless ? "yes" : "no");

// nm_client_wireless_set_enabled (client, !wireless);

	wireless = nm_client_wireless_hardware_get_enabled (client);
	g_print ("Wireless HW enabled? %s\n", wireless ? "yes" : "no");

// nm_client_wireless_set_enabled (client, !wireless);

	return TRUE;
}

static gboolean
test_get_state (NMClient *client)
{
	guint state;

	state = nm_client_get_state (client);
	g_print ("Current state: %d\n", state);

	return TRUE;
}

static char *
ip4_address_as_string (guint32 ip)
{
	char buf[INET_ADDRSTRLEN+1];
	guint32 tmp_addr;

	memset (&buf, '\0', sizeof (buf));
	tmp_addr = ip;

	if (inet_ntop (AF_INET, &tmp_addr, buf, INET_ADDRSTRLEN)) {
		return g_strdup (buf);
	} else {
		g_warning ("%s: error converting IP4 address 0x%X",
		           __func__, ntohl (tmp_addr));
		return NULL;
	}
}

static void
dump_ip4_config (NMIP4Config *cfg)
{
	char *tmp;
	const GArray *array;
	const GPtrArray *ptr_array;
	GSList *iter;
	int i;

	for (iter = (GSList *) nm_ip4_config_get_addresses (cfg); iter; iter = g_slist_next (iter)) {
		NMIP4Address *addr = iter->data;
		guint32 u;

		tmp = ip4_address_as_string (nm_ip4_address_get_address (addr));
		g_print ("IP4 address: %s\n", tmp);
		g_free (tmp);

		u = nm_ip4_address_get_prefix (addr);
		tmp = ip4_address_as_string (nm_utils_ip4_prefix_to_netmask (u));
		g_print ("IP4 prefix: %d (%s)\n", u, tmp);
		g_free (tmp);

		tmp = ip4_address_as_string (nm_ip4_address_get_gateway (addr));
		g_print ("IP4 gateway: %s\n\n", tmp);
		g_free (tmp);
	}

	array = nm_ip4_config_get_nameservers (cfg);
	if (array) {
		g_print ("IP4 DNS:\n");
		for (i = 0; i < array->len; i++) {
			tmp = ip4_address_as_string (g_array_index (array, guint32, i));
			g_print ("\t%s\n", tmp);
			g_free (tmp);
		}
	}

	ptr_array = nm_ip4_config_get_domains (cfg);
	if (ptr_array) {
		g_print ("IP4 domains:\n");
		for (i = 0; i < ptr_array->len; i++)
			g_print ("\t%s\n", (const char *) g_ptr_array_index (ptr_array, i));
	}

	array = nm_ip4_config_get_wins_servers (cfg);
	if (array) {
		g_print ("IP4 WINS:\n");
		for (i = 0; i < array->len; i++) {
			tmp = ip4_address_as_string (g_array_index (array, guint32, i));
			g_print ("\t%s\n", tmp);
			g_free (tmp);
		}
	}
}

static void
print_one_dhcp4_option (gpointer key, gpointer data, gpointer user_data)
{
	const char *option = (const char *) key;
	const char *value = (const char *) data;

	g_print ("  %s:   %s\n", option, value);
}

static void
dump_dhcp4_config (NMDHCP4Config *config)
{
	GHashTable *options = NULL;

	if (!config)
		return;

	g_print ("\nDHCP4 Options:\n");
	g_print ("-------------------------------------\n");

	g_object_get (G_OBJECT (config), NM_DHCP4_CONFIG_OPTIONS, &options, NULL);
	g_hash_table_foreach (options, print_one_dhcp4_option, NULL);
}

static void
dump_access_point (NMAccessPoint *ap)
{
	const GByteArray * ssid;
	const char * str;

	ssid = nm_access_point_get_ssid (ap);
	g_print ("\tSsid: %s\n",
	         ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)");

	str = nm_access_point_get_bssid (ap);
	g_print ("\tMAC Address: %s\n", str);

	g_print ("\tFlags: 0x%X\n", nm_access_point_get_flags (ap));
	g_print ("\tWPA Flags: 0x%X\n", nm_access_point_get_wpa_flags (ap));
	g_print ("\tRSN Flags: 0x%X\n", nm_access_point_get_rsn_flags (ap));
	g_print ("\tFrequency: %u\n", nm_access_point_get_frequency (ap));

	g_print ("\tMode: %d\n", nm_access_point_get_mode (ap));
	g_print ("\tRate: %d\n", nm_access_point_get_max_bitrate (ap));
	g_print ("\tStrength: %d\n", nm_access_point_get_strength (ap));
}

static void
dump_wireless (NMDeviceWifi *device)
{
	const char *str;
	const GPtrArray *aps;
	int i;

	g_print ("Mode: %d\n", nm_device_wifi_get_mode (device));
	g_print ("Bitrate: %d\n", nm_device_wifi_get_bitrate (device));

	str = nm_device_wifi_get_hw_address (device);
	g_print ("MAC: %s\n", str);

	g_print ("AccessPoints:\n");
	aps = nm_device_wifi_get_access_points (device);
	for (i = 0; aps && (i < aps->len); i++) {
		dump_access_point (NM_ACCESS_POINT (g_ptr_array_index (aps, i)));
		g_print ("\n");
	}
}

static void
dump_generic (NMDeviceGeneric *device)
{
	g_print ("HW address: %s\n", nm_device_generic_get_hw_address (device));
}

static void
dump_wired (NMDeviceEthernet *device)
{
	const char *str;

	g_print ("Speed: %d\n", nm_device_ethernet_get_speed (device));

	str = nm_device_ethernet_get_hw_address (device);
	g_print ("MAC: %s\n", str);
}

static void
dump_device (NMDevice *device)
{
	const char *str;
	NMDeviceState state;

	str = nm_device_get_iface (device);
	g_print ("Interface: %s\n", str);

	str = nm_device_get_udi (device);
	g_print ("Udi: %s\n", str);

	str = nm_device_get_driver (device);
	g_print ("Driver: %s\n", str);

	str = nm_device_get_vendor (device);
	g_print ("Vendor: %s\n", str);

	str = nm_device_get_product (device);
	g_print ("Product: %s\n", str);

	state = nm_device_get_state (device);
	g_print ("State: %d\n", state);

	if (state == NM_DEVICE_STATE_ACTIVATED)
		dump_ip4_config (nm_device_get_ip4_config (device));

	if (NM_IS_DEVICE_ETHERNET (device))
		dump_wired (NM_DEVICE_ETHERNET (device));
	else if (NM_IS_DEVICE_WIFI (device))
		dump_wireless (NM_DEVICE_WIFI (device));
	else if (NM_IS_DEVICE_GENERIC (device))
		dump_generic (NM_DEVICE_GENERIC (device));

	dump_dhcp4_config (nm_device_get_dhcp4_config (device));
}

static gboolean
test_devices (NMClient *client)
{
	const GPtrArray *devices;
	int i;

	devices = nm_client_get_devices (client);
	g_print ("Got devices:\n");
	if (!devices) {
		g_print ("  NONE\n");
		return TRUE;
	}

	for (i = 0; i < devices->len; i++) {
		NMDevice *device = g_ptr_array_index (devices, i);
		dump_device (device);
		g_print ("\n");
	}

	return TRUE;
}

static void
active_connections_changed (NMClient *client, GParamSpec *pspec, gpointer user_data)
{
	const GPtrArray *connections;
	int i, j;

	g_print ("Active connections changed:\n");
	connections = nm_client_get_active_connections (client);
	for (i = 0; connections && (i < connections->len); i++) {
		NMActiveConnection *connection;
		const GPtrArray *devices;

		connection = g_ptr_array_index (connections, i);
		g_print ("    %s\n", nm_object_get_path (NM_OBJECT (connection)));
		devices = nm_active_connection_get_devices (connection);
		for (j = 0; devices && j < devices->len; j++)
			g_print ("           %s\n", nm_device_get_udi (g_ptr_array_index (devices, j)));
		if (NM_IS_VPN_CONNECTION (connection))
			g_print ("           VPN base connection: %s\n", nm_active_connection_get_specific_object (connection));
	}
}

static void
show_active_connection_device (gpointer data, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (data);

	g_print ("           %s\n", nm_device_get_udi (device));
}

static void
test_get_active_connections (NMClient *client)
{
	const GPtrArray *connections;
	int i;

	g_print ("Active connections:\n");
	connections = nm_client_get_active_connections (client);
	for (i = 0; connections && (i < connections->len); i++) {
		const GPtrArray *devices;

		g_print ("    %s\n", nm_object_get_path (g_ptr_array_index (connections, i)));
		devices = nm_active_connection_get_devices (g_ptr_array_index (connections, i));
		if (devices)
			g_ptr_array_foreach ((GPtrArray *) devices, show_active_connection_device, NULL);
	}
}

static void
device_state_changed (NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
	g_print ("Device state changed: %s %d\n",
	         nm_device_get_iface (device),
	         nm_device_get_state (device));
}

static void
device_added_cb (NMClient *client, NMDevice *device, gpointer user_data)
{
	g_print ("New device added\n");
	dump_device (device);
	g_signal_connect (G_OBJECT (device), "notify::state",
	                  (GCallback) device_state_changed, NULL);
}

static void
device_removed_cb (NMClient *client, NMDevice *device, gpointer user_data)
{
	g_print ("Device removed\n");
	dump_device (device);
}

static void
manager_running (NMClient *client, GParamSpec *pspec, gpointer user_data)
{
	if (nm_client_get_manager_running (client)) {
		g_print ("NM appeared\n");
		test_wireless_enabled (client);
		test_get_state (client);
		test_get_active_connections (client);
		test_devices (client);
	} else
		g_print ("NM disappeared\n");
}

static GMainLoop *loop = NULL;

static void
signal_handler (int signo)
{
	if (signo == SIGINT || signo == SIGTERM) {
		g_message ("Caught signal %d, shutting down...", signo);
		g_main_loop_quit (loop);
	}
}

static void
setup_signals (void)
{
	struct sigaction action;
	sigset_t mask;

	sigemptyset (&mask);
	action.sa_handler = signal_handler;
	action.sa_mask = mask;
	action.sa_flags = 0;
	sigaction (SIGTERM,  &action, NULL);
	sigaction (SIGINT,  &action, NULL);
}

int
main (int argc, char *argv[])
{
	NMClient *client;

	client = nm_client_new ();
	if (!client) {
		exit (1);
	}

	g_signal_connect (client, "notify::" NM_CLIENT_MANAGER_RUNNING,
	                  G_CALLBACK (manager_running), NULL);
	g_signal_connect (client, "notify::" NM_CLIENT_ACTIVE_CONNECTIONS,
	                  G_CALLBACK (active_connections_changed), NULL);
	manager_running (client, NULL, NULL);

	g_signal_connect (client, "device-added",
					  G_CALLBACK (device_added_cb), NULL);
	g_signal_connect (client, "device-removed",
					  G_CALLBACK (device_removed_cb), NULL);

	loop = g_main_loop_new (NULL, FALSE);
	setup_signals ();
	g_main_loop_run (loop);

	g_object_unref (client);

	return 0;
}
