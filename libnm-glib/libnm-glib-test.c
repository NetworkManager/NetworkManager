#include <stdlib.h>
#include "nm-client.h"
#include "nm-device.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"

static gboolean
test_wireless_enabled (NMClient *client)
{
	gboolean wireless;

	wireless = nm_client_wireless_get_enabled (client);
	g_print ("Wireless enabled? %s\n", wireless ? "yes" : "no");

	nm_client_wireless_set_enabled (client, !wireless);

	wireless = nm_client_wireless_get_enabled (client);
	g_print ("Wireless enabled? %s\n", wireless ? "yes" : "no");

	nm_client_wireless_set_enabled (client, !wireless);

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


static void
dump_device (NMDevice *device)
{
	char *str;
	gboolean b;
	guint32 u;
	NMDeviceState state;

	str = nm_device_get_iface (device);
	g_print ("Interface: %s\n", str);
	g_free (str);

	str = nm_device_get_udi (device);
	g_print ("Udi: %s\n", str);
	g_free (str);

	str = nm_device_get_driver (device);
	g_print ("Driver: %s\n", str);
	g_free (str);

	b = nm_device_get_use_dhcp (device);
	g_print ("Use DHCP: %s\n", b ? "yes" : "no");

	u = nm_device_get_ip4_address (device);
	g_print ("IP address: %d\n", u);

	state = nm_device_get_state (device);
	g_print ("State: %d\n", state);

	if (NM_IS_DEVICE_802_3_ETHERNET (device)) {
		int speed = nm_device_802_3_ethernet_get_speed (NM_DEVICE_802_3_ETHERNET (device));
		g_print ("Speed: %d\n", speed);
	} else if (NM_IS_DEVICE_802_11_WIRELESS (device)) {
		GSList *iter;
		GSList *networks = nm_device_802_11_wireless_get_networks (NM_DEVICE_802_11_WIRELESS (device));

		g_print ("Networks:\n");
		for (iter = networks; iter; iter = iter->next) {
			NMAccessPoint *ap = NM_ACCESS_POINT (iter->data);

			str = nm_access_point_get_essid (ap);
			g_print ("\tEssid: %s\n", str);
			g_free (str);
		}
		g_slist_foreach (networks, (GFunc) g_object_unref, NULL);
		g_slist_free (networks);
	}
}

static gboolean
test_devices (NMClient *client)
{
	GSList *list, *iter;

	list = nm_client_get_devices (client);
	g_print ("Got devices:\n");
	for (iter = list; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);
		dump_device (device);
		g_print ("\n");
	}

	g_slist_foreach (list, (GFunc) g_object_unref, NULL);
	g_slist_free (list);

	return TRUE;
}

static void
device_added_cb (NMClient *client, NMDevice *device, gpointer user_data)
{
	g_print ("New device added\n");
	dump_device (device);
}

static void
device_removed_cb (NMClient *client, NMDevice *device, gpointer user_data)
{
	g_print ("Device removed\n");
	dump_device (device);
}


static gboolean
device_deactivate (gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	nm_device_deactivate (device);

	return FALSE;
}

static void
device_state_changed (NMDevice *device, NMDeviceState state, gpointer user_data)
{
	char *str;

	str = nm_device_get_iface (device);
	g_print ("Device state changed: %s %d\n", str, state);
	g_free (str);

	if (state == NM_DEVICE_STATE_ACTIVATED) {
		g_print ("Scheduling device deactivation\n");
		g_timeout_add (5 * 1000,
					   device_deactivate,
					   device);
	}
}

static gboolean
do_stuff (gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	GSList *list, *iter;

	list = nm_client_get_devices (client);
	for (iter = list; iter; iter = iter->next) {
		if (NM_IS_DEVICE_802_3_ETHERNET (iter->data)) {
			NMDevice8023Ethernet *device = NM_DEVICE_802_3_ETHERNET (iter->data);

			g_signal_connect (device, "state-changed",
							  G_CALLBACK (device_state_changed),
							  NULL);
			/* FIXME: This ref is never released */
			g_object_ref (device);

			nm_device_802_3_ethernet_activate (device, TRUE);
			break;
		}
	}

	g_slist_foreach (list, (GFunc) g_object_unref, NULL);
	g_slist_free (list);

	return FALSE;
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

	test_wireless_enabled (client);
	test_get_state (client);
	test_devices (client);

	g_signal_connect (client, "device-added",
					  G_CALLBACK (device_added_cb), NULL);
	g_signal_connect (client, "device-removed",
					  G_CALLBACK (device_removed_cb), NULL);

/* 	g_idle_add (do_stuff, client); */

	g_main_loop_run (g_main_loop_new (NULL, FALSE));

	g_object_unref (client);

	return 0;
}
