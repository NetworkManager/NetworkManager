/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright 2010 - 2014 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>

#include "nm-client.h"
#include "nm-device-wifi.h"
#include "nm-device-ethernet.h"
#include "nm-device-wimax.h"
#include "nm-connection.h"
#include "nm-setting.h"

#include "nm-test-libnm-utils.h"

static GMainLoop *loop = NULL;
static NMTstcServiceInfo *sinfo;

/*****************************************************************************/

static gboolean
loop_quit (gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
	return G_SOURCE_REMOVE;
}

static gboolean
add_device (const char *method, const char *ifname, char **out_path)
{
	GError *error = NULL;
	GVariant *ret;

	ret = g_dbus_proxy_call_sync (sinfo->proxy,
	                              method,
	                              g_variant_new ("(s)", ifname),
	                              G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                              3000,
	                              NULL,
	                              &error);
	g_assert_no_error (error);
	g_assert (ret);
	g_assert_cmpstr (g_variant_get_type_string (ret), ==, "(o)");
	if (out_path)
		g_variant_get (ret, "(o)", out_path);
	g_variant_unref (ret);
	return TRUE;
}

static gboolean
add_wired_device (const char *method, const char *ifname, char **out_path)
{
	const char *empty[] = { NULL };
	GError *error = NULL;
	GVariant *ret;

	ret = g_dbus_proxy_call_sync (sinfo->proxy,
	                              method,
	                              g_variant_new ("(ss^as)", ifname, "/", empty),
	                              G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                              3000,
	                              NULL,
	                              &error);
	g_assert_no_error (error);
	g_assert (ret);
	g_assert_cmpstr (g_variant_get_type_string (ret), ==, "(o)");
	if (out_path)
		g_variant_get (ret, "(o)", out_path);
	g_variant_unref (ret);
	return TRUE;
}

/*****************************************************************************/

typedef struct {
	GMainLoop *loop;
	gboolean signaled;
	gboolean notified;
	guint quit_count;
	guint quit_id;
} DeviceAddedInfo;

static void
device_add_check_quit (DeviceAddedInfo *info)
{
	info->quit_count--;
	if (info->quit_count == 0) {
		g_source_remove (info->quit_id);
		info->quit_id = 0;
		g_main_loop_quit (info->loop);
	}
}

static void
device_added_cb (NMClient *c,
                 NMDevice *device,
                 DeviceAddedInfo *info)
{
	g_assert (device);
	g_assert_cmpstr (nm_device_get_iface (device), ==, "eth0");
	info->signaled = TRUE;
	device_add_check_quit (info);
}

static void
devices_notify_cb (NMClient *c,
                   GParamSpec *pspec,
                   DeviceAddedInfo *info)
{
	const GPtrArray *devices;
	NMDevice *device;

	devices = nm_client_get_devices (c);
	g_assert (devices);
	g_assert_cmpint (devices->len, ==, 1);

	device = g_ptr_array_index (devices, 0);
	g_assert (device);
	g_assert_cmpstr (nm_device_get_iface (device), ==, "eth0");

	info->notified = TRUE;

	device_add_check_quit (info);
}

static void
test_device_added (void)
{
	NMClient *client;
	const GPtrArray *devices;
	NMDevice *device;
	DeviceAddedInfo info = { loop, FALSE, FALSE, 0, 0 };

	sinfo = nmtstc_service_init ();
	if (!nmtstc_service_available (sinfo))
		return;

	client = nmtstc_nm_client_new ();

	devices = nm_client_get_devices (client);
	g_assert (devices == NULL);

	/* Tell the test service to add a new device */
	add_wired_device ("AddWiredDevice", "eth0", NULL);

	g_signal_connect (client,
	                  "device-added",
	                  (GCallback) device_added_cb,
	                  &info);
	info.quit_count++;

	g_signal_connect (client,
	                  "notify::devices",
	                  (GCallback) devices_notify_cb,
	                  &info);
	info.quit_count++;

	/* Wait for libnm-glib to find the device */
	info.quit_id = g_timeout_add_seconds (5, loop_quit, loop);
	g_main_loop_run (loop);

	g_assert (info.signaled);
	g_assert (info.notified);

	g_signal_handlers_disconnect_by_func (client, device_added_cb, &info);
	g_signal_handlers_disconnect_by_func (client, devices_notify_cb, &info);

	devices = nm_client_get_devices (client);
	g_assert (devices);
	g_assert_cmpint (devices->len, ==, 1);

	device = g_ptr_array_index (devices, 0);
	g_assert (device);
	g_assert_cmpstr (nm_device_get_iface (device), ==, "eth0");

	g_object_unref (client);
	g_clear_pointer (&sinfo, nmtstc_service_cleanup);
}

/*****************************************************************************/

static const char *expected_bssid = "66:55:44:33:22:11";

typedef struct {
	GMainLoop *loop;
	gboolean found;
	char *ap_path;
	gboolean signaled;
	gboolean notified;
	guint quit_id;
	guint quit_count;
} WifiApInfo;

static void
wifi_check_quit (WifiApInfo *info)
{
	info->quit_count--;
	if (info->quit_count == 0) {
		g_source_remove (info->quit_id);
		info->quit_id = 0;
		g_main_loop_quit (info->loop);
	}
}

static void
wifi_device_added_cb (NMClient *c,
                      NMDevice *device,
                      WifiApInfo *info)
{
	g_assert_cmpstr (nm_device_get_iface (device), ==, "wlan0");
	info->found = TRUE;
	wifi_check_quit (info);
}

static void
got_ap_path (WifiApInfo *info, const char *path)
{
	if (info->ap_path)
		g_assert_cmpstr (info->ap_path, ==, path);
	else
		info->ap_path = g_strdup (path);
}

static void
wifi_ap_added_cb (NMDeviceWifi *w,
                  NMAccessPoint *ap,
                  WifiApInfo *info)
{
	g_assert (ap);
	g_assert_cmpstr (nm_access_point_get_bssid (ap), ==, expected_bssid);
	got_ap_path (info, nm_object_get_path (NM_OBJECT (ap)));

	info->signaled = TRUE;
	wifi_check_quit (info);
}

static void
wifi_ap_add_notify_cb (NMDeviceWifi *w,
                       GParamSpec *pspec,
                       WifiApInfo *info)
{
	const GPtrArray *aps;
	NMAccessPoint *ap;

	aps = nm_device_wifi_get_access_points (w);
	g_assert (aps);
	g_assert_cmpint (aps->len, ==, 1);

	ap = g_ptr_array_index (aps, 0);
	g_assert (ap);
	g_assert_cmpstr (nm_access_point_get_bssid (ap), ==, "66:55:44:33:22:11");
	got_ap_path (info, nm_object_get_path (NM_OBJECT (ap)));

	info->notified = TRUE;
	wifi_check_quit (info);
}

static void
wifi_ap_removed_cb (NMDeviceWifi *w,
                    NMAccessPoint *ap,
                    WifiApInfo *info)
{
	g_assert (ap);
	g_assert_cmpstr (info->ap_path, ==, nm_object_get_path (NM_OBJECT (ap)));

	info->signaled = TRUE;
	wifi_check_quit (info);
}

static void
wifi_ap_remove_notify_cb (NMDeviceWifi *w,
                          GParamSpec *pspec,
                          WifiApInfo *info)
{
	const GPtrArray *aps;

	aps = nm_device_wifi_get_access_points (w);
	g_assert (aps == NULL);

	info->notified = TRUE;
	wifi_check_quit (info);
}

static void
test_wifi_ap_added_removed (void)
{
	NMClient *client;
	NMDeviceWifi *wifi;
	WifiApInfo info = { loop, FALSE, FALSE, 0, 0 };
	GVariant *ret;
	GError *error = NULL;
	char *expected_path = NULL;

	sinfo = nmtstc_service_init ();
	if (!nmtstc_service_available (sinfo))
		return;

	client = nmtstc_nm_client_new ();

	/*************************************/
	/* Add the wifi device */
	add_device ("AddWifiDevice", "wlan0", NULL);

	g_signal_connect (client,
	                  "device-added",
	                  (GCallback) wifi_device_added_cb,
	                  &info);
	info.quit_count = 1;

	/* Wait for libnm-glib to find the device */
	info.quit_id = g_timeout_add_seconds (5, loop_quit, loop);
	g_main_loop_run (loop);

	g_assert (info.found);
	g_signal_handlers_disconnect_by_func (client, wifi_device_added_cb, &info);

	wifi = (NMDeviceWifi *) nm_client_get_device_by_iface (client, "wlan0");
	g_assert (NM_IS_DEVICE_WIFI (wifi));

	/*************************************/
	/* Add the wifi device */
	info.signaled =  FALSE;
	info.notified = FALSE;
	info.quit_id = 0;

	ret = g_dbus_proxy_call_sync (sinfo->proxy,
	                              "AddWifiAp",
	                              g_variant_new ("(sss)", "wlan0", "test-ap", expected_bssid),
	                              G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                              3000,
	                              NULL,
	                              &error);
	g_assert_no_error (error);
	g_assert (ret);
	g_assert_cmpstr (g_variant_get_type_string (ret), ==, "(o)");
	g_variant_get (ret, "(o)", &expected_path);
	g_variant_unref (ret);

	g_signal_connect (wifi,
	                  "access-point-added",
	                  (GCallback) wifi_ap_added_cb,
	                  &info);
	info.quit_count = 1;

	g_signal_connect (wifi,
	                  "notify::access-points",
	                  (GCallback) wifi_ap_add_notify_cb,
	                  &info);
	info.quit_count++;

	/* Wait for libnm-glib to find the AP */
	info.quit_id = g_timeout_add_seconds (5, loop_quit, loop);
	g_main_loop_run (loop);

	g_assert (info.signaled);
	g_assert (info.notified);
	g_assert (info.ap_path);
	g_assert_cmpstr (info.ap_path, ==, expected_path);
	g_signal_handlers_disconnect_by_func (wifi, wifi_ap_added_cb, &info);
	g_signal_handlers_disconnect_by_func (wifi, wifi_ap_add_notify_cb, &info);

	/*************************************/
	/* Remove the wifi device */
	info.signaled =  FALSE;
	info.notified = FALSE;
	info.quit_id = 0;

	ret = g_dbus_proxy_call_sync (sinfo->proxy,
	                              "RemoveWifiAp",
	                              g_variant_new ("(so)", "wlan0", expected_path),
	                              G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                              3000,
	                              NULL,
	                              &error);
	g_assert_no_error (error);
	g_clear_pointer (&ret, g_variant_unref);

	g_signal_connect (wifi,
	                  "access-point-removed",
	                  (GCallback) wifi_ap_removed_cb,
	                  &info);
	info.quit_count = 1;

	g_signal_connect (wifi,
	                  "notify::access-points",
	                  (GCallback) wifi_ap_remove_notify_cb,
	                  &info);
	info.quit_count++;

	/* Wait for libnm-glib to find the AP */
	info.quit_id = g_timeout_add_seconds (5, loop_quit, loop);
	g_main_loop_run (loop);

	g_assert (info.signaled);
	g_assert (info.notified);
	g_signal_handlers_disconnect_by_func (wifi, wifi_ap_removed_cb, &info);
	g_signal_handlers_disconnect_by_func (wifi, wifi_ap_remove_notify_cb, &info);

	g_free (info.ap_path);
	g_free (expected_path);

	g_object_unref (client);
	g_clear_pointer (&sinfo, nmtstc_service_cleanup);
}

/*****************************************************************************/

static const char *expected_nsp_name = "Clear";

typedef struct {
	GMainLoop *loop;
	gboolean found;
	char *nsp_path;
	gboolean signaled;
	gboolean notified;
	guint quit_id;
	guint quit_count;
} WimaxNspInfo;

static void
wimax_check_quit (WimaxNspInfo *info)
{
	info->quit_count--;
	if (info->quit_count == 0) {
		g_source_remove (info->quit_id);
		info->quit_id = 0;
		g_main_loop_quit (info->loop);
	}
}

static void
wimax_device_added_cb (NMClient *c,
                       NMDevice *device,
                       WimaxNspInfo *info)
{
	g_assert_cmpstr (nm_device_get_iface (device), ==, "wmx0");
	info->found = TRUE;
	wimax_check_quit (info);
}

static void
got_nsp_path (WimaxNspInfo *info, const char *path)
{
	if (info->nsp_path)
		g_assert_cmpstr (info->nsp_path, ==, path);
	else
		info->nsp_path = g_strdup (path);
}

static void
wimax_nsp_added_cb (NMDeviceWimax *w,
                    NMWimaxNsp *nsp,
                    WimaxNspInfo *info)
{
	g_assert (nsp);
	g_assert_cmpstr (nm_wimax_nsp_get_name (nsp), ==, expected_nsp_name);
	got_nsp_path (info, nm_object_get_path (NM_OBJECT (nsp)));

	info->signaled = TRUE;
	wimax_check_quit (info);
}

static void
wimax_nsp_add_notify_cb (NMDeviceWimax *w,
                         GParamSpec *pspec,
                         WimaxNspInfo *info)
{
	const GPtrArray *nsps;
	NMWimaxNsp *nsp;

	nsps = nm_device_wimax_get_nsps (w);
	g_assert (nsps);
	g_assert_cmpint (nsps->len, ==, 1);

	nsp = g_ptr_array_index (nsps, 0);
	g_assert (nsp);
	g_assert_cmpstr (nm_wimax_nsp_get_name (nsp), ==, expected_nsp_name);
	got_nsp_path (info, nm_object_get_path (NM_OBJECT (nsp)));

	info->notified = TRUE;
	wimax_check_quit (info);
}

static void
wimax_nsp_removed_cb (NMDeviceWimax *w,
                      NMWimaxNsp *nsp,
                      WimaxNspInfo *info)
{
	g_assert (nsp);
	g_assert_cmpstr (info->nsp_path, ==, nm_object_get_path (NM_OBJECT (nsp)));

	info->signaled = TRUE;
	wimax_check_quit (info);
}

static void
wimax_nsp_remove_notify_cb (NMDeviceWimax *w,
                            GParamSpec *pspec,
                            WimaxNspInfo *info)
{
	const GPtrArray *nsps;

	nsps = nm_device_wimax_get_nsps (w);
	g_assert (nsps == NULL);

	info->notified = TRUE;
	wimax_check_quit (info);
}

static void
test_wimax_nsp_added_removed (void)
{
	NMClient *client;
	NMDeviceWimax *wimax;
	WimaxNspInfo info = { loop, FALSE, FALSE, 0, 0 };
	GVariant *ret;
	GError *error = NULL;
	char *expected_path = NULL;

	sinfo = nmtstc_service_init ();
	if (!nmtstc_service_available (sinfo))
		return;

	client = nmtstc_nm_client_new ();

	/*************************************/
	/* Add the wimax device */
	add_device ("AddWimaxDevice", "wmx0", NULL);

	g_signal_connect (client,
	                  "device-added",
	                  (GCallback) wimax_device_added_cb,
	                  &info);
	info.quit_count = 1;

	/* Wait for libnm-glib to find the device */
	info.quit_id = g_timeout_add_seconds (5, loop_quit, loop);
	g_main_loop_run (loop);

	g_assert (info.found);
	g_signal_handlers_disconnect_by_func (client, wimax_device_added_cb, &info);

	wimax = (NMDeviceWimax *) nm_client_get_device_by_iface (client, "wmx0");
	g_assert (NM_IS_DEVICE_WIMAX (wimax));

	/*************************************/
	/* Add the wimax NSP */
	info.signaled =  FALSE;
	info.notified = FALSE;
	info.quit_id = 0;

	ret = g_dbus_proxy_call_sync (sinfo->proxy,
	                              "AddWimaxNsp",
	                              g_variant_new ("(ss)", "wmx0", expected_nsp_name),
	                              G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                              3000,
	                              NULL,
	                              &error);
	g_assert_no_error (error);
	g_assert (ret);
	g_assert_cmpstr (g_variant_get_type_string (ret), ==, "(o)");
	g_variant_get (ret, "(o)", &expected_path);
	g_variant_unref (ret);

	g_signal_connect (wimax,
	                  "nsp-added",
	                  (GCallback) wimax_nsp_added_cb,
	                  &info);
	info.quit_count = 1;

	g_signal_connect (wimax,
	                  "notify::nsps",
	                  (GCallback) wimax_nsp_add_notify_cb,
	                  &info);
	info.quit_count++;

	/* Wait for libnm-glib to find the AP */
	info.quit_id = g_timeout_add_seconds (5, loop_quit, loop);
	g_main_loop_run (loop);

	g_assert (info.signaled);
	g_assert (info.notified);
	g_assert (info.nsp_path);
	g_assert_cmpstr (info.nsp_path, ==, expected_path);
	g_signal_handlers_disconnect_by_func (wimax, wimax_nsp_added_cb, &info);
	g_signal_handlers_disconnect_by_func (wimax, wimax_nsp_add_notify_cb, &info);

	/*************************************/
	/* Remove the wimax NSP */
	info.signaled =  FALSE;
	info.notified = FALSE;
	info.quit_id = 0;

	ret = g_dbus_proxy_call_sync (sinfo->proxy,
	                              "RemoveWimaxNsp",
	                              g_variant_new ("(so)", "wmx0", expected_path),
	                              G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                              3000,
	                              NULL,
	                              &error);
	g_assert_no_error (error);
	g_clear_pointer (&ret, g_variant_unref);

	g_signal_connect (wimax,
	                  "nsp-removed",
	                  (GCallback) wimax_nsp_removed_cb,
	                  &info);
	info.quit_count = 1;

	g_signal_connect (wimax,
	                  "notify::nsps",
	                  (GCallback) wimax_nsp_remove_notify_cb,
	                  &info);
	info.quit_count++;

	/* Wait for libnm-glib to find the AP */
	info.quit_id = g_timeout_add_seconds (5, loop_quit, loop);
	g_main_loop_run (loop);

	g_assert (info.signaled);
	g_assert (info.notified);
	g_signal_handlers_disconnect_by_func (wimax, wimax_nsp_removed_cb, &info);
	g_signal_handlers_disconnect_by_func (wimax, wimax_nsp_remove_notify_cb, &info);

	g_free (info.nsp_path);
	g_free (expected_path);

	g_object_unref (client);
	g_clear_pointer (&sinfo, nmtstc_service_cleanup);
}

/*****************************************************************************/

typedef struct {
	GMainLoop *loop;
	gboolean signaled;
	gboolean notified;
	guint quit_count;
	guint quit_id;
} DaInfo;

static void
da_check_quit (DaInfo *info)
{
	g_assert (info->quit_count > 0);
	info->quit_count--;
	if (info->quit_count == 0) {
		g_source_remove (info->quit_id);
		info->quit_id = 0;
		g_main_loop_quit (info->loop);
	}
}

static void
da_device_added_cb (NMClient *c,
                    NMDevice *device,
                    DaInfo *info)
{
	da_check_quit (info);
}

static void
da_device_removed_cb (NMClient *c,
                      NMDevice *device,
                      DaInfo *info)
{
	g_assert_cmpstr (nm_device_get_iface (device), ==, "eth0");
	info->signaled = TRUE;
	da_check_quit (info);
}

static void
da_devices_notify_cb (NMClient *c,
                      GParamSpec *pspec,
                      DaInfo *info)
{
	const GPtrArray *devices;
	NMDevice *device;
	guint i;
	const char *iface;

	devices = nm_client_get_devices (c);
	g_assert (devices);
	g_assert_cmpint (devices->len, ==, 2);

	for (i = 0; i < devices->len; i++) {
		device = g_ptr_array_index (devices, i);
		iface = nm_device_get_iface (device);

		g_assert (!strcmp (iface, "wlan0") || !strcmp (iface, "eth1"));
	}

	info->notified = TRUE;
	da_check_quit (info);
}

static void
test_devices_array (void)
{
	NMClient *client;
	DaInfo info = { loop };
	char *paths[3] = { NULL, NULL, NULL };
	NMDevice *device;
	const GPtrArray *devices;
	GError *error = NULL;
	GVariant *ret;

	sinfo = nmtstc_service_init ();
	if (!nmtstc_service_available (sinfo))
		return;

	client = nmtstc_nm_client_new ();

	/*************************************/
	/* Add some devices */
	add_device ("AddWifiDevice", "wlan0", &paths[0]);
	add_wired_device ("AddWiredDevice", "eth0", &paths[1]);
	add_wired_device ("AddWiredDevice", "eth1", &paths[2]);
	info.quit_count = 3;

	g_signal_connect (client,
	                  "device-added",
	                  (GCallback) da_device_added_cb,
	                  &info);

	/* Wait for libnm-glib to find the device */
	info.quit_id = g_timeout_add_seconds (5, loop_quit, loop);
	g_main_loop_run (loop);

	g_assert_cmpint (info.quit_count, ==, 0);
	g_signal_handlers_disconnect_by_func (client, da_device_added_cb, &info);

	/* Ensure the devices now exist */
	devices = nm_client_get_devices (client);
	g_assert (devices);
	g_assert_cmpint (devices->len, ==, 3);

	device = nm_client_get_device_by_iface (client, "wlan0");
	g_assert (NM_IS_DEVICE_WIFI (device));

	device = nm_client_get_device_by_iface (client, "eth0");
	g_assert (NM_IS_DEVICE_ETHERNET (device));

	device = nm_client_get_device_by_iface (client, "eth1");
	g_assert (NM_IS_DEVICE_ETHERNET (device));

	/********************************/
	/* Now remove the device in the middle */
	ret = g_dbus_proxy_call_sync (sinfo->proxy,
	                              "RemoveDevice",
	                              g_variant_new ("(o)", paths[1]),
	                              G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                              3000,
	                              NULL,
	                              &error);
	g_assert_no_error (error);
	g_assert (ret);
	g_variant_unref (ret);

	g_signal_connect (client,
	                  "device-removed",
	                  (GCallback) da_device_removed_cb,
	                  &info);

	g_signal_connect (client,
	                  "notify::devices",
	                  (GCallback) da_devices_notify_cb,
	                  &info);
	info.quit_count = 2;

	/* Wait for libnm-glib to find the device */
	info.quit_id = g_timeout_add_seconds (5, loop_quit, loop);
	g_main_loop_run (loop);

	g_assert_cmpint (info.quit_count, ==, 0);
	g_signal_handlers_disconnect_by_func (client, da_device_removed_cb, &info);
	g_signal_handlers_disconnect_by_func (client, da_devices_notify_cb, &info);

	/* Ensure only two are left */
	devices = nm_client_get_devices (client);
	g_assert (devices);
	g_assert_cmpint (devices->len, ==, 2);

	device = nm_client_get_device_by_iface (client, "wlan0");
	g_assert (NM_IS_DEVICE_WIFI (device));

	device = nm_client_get_device_by_iface (client, "eth1");
	g_assert (NM_IS_DEVICE_ETHERNET (device));

	g_free (paths[0]);
	g_free (paths[1]);
	g_free (paths[2]);

	g_object_unref (client);
	g_clear_pointer (&sinfo, nmtstc_service_cleanup);
}

static void
manager_running_changed (GObject *client,
                         GParamSpec *pspec,
                         gpointer user_data)
{
	int *running_changed = user_data;

	(*running_changed)++;
	g_main_loop_quit (loop);
}

static void
test_client_manager_running (void)
{
	gs_unref_object NMClient *client1 = NULL;
	gs_unref_object NMClient *client2 = NULL;
	guint quit_id;
	int running_changed = 0;
	GError *error = NULL;

	client1 = nmtstc_nm_client_new ();

	g_assert (!nm_client_get_manager_running (client1));
	g_assert_cmpstr (nm_client_get_version (client1), ==, NULL);

	g_assert (!nm_client_networking_get_enabled (client1));
	/* This will have no effect, but it shouldn't cause any warnings either. */
	nm_client_networking_set_enabled (client1, TRUE);
	g_assert (!nm_client_networking_get_enabled (client1));

	/* OTOH, this should result in an error */
	nm_client_set_logging (client1, "DEFAULT", "INFO", &error);
	g_assert_error (error, NM_CLIENT_ERROR, NM_CLIENT_ERROR_MANAGER_NOT_RUNNING);
	g_clear_error (&error);

	/* Now start the test service. */
	sinfo = nmtstc_service_init ();
	if (!nmtstc_service_available (sinfo))
		return;

	client2 = nmtstc_nm_client_new ();

	/* client2 should know that NM is running, but the previously-created
	 * client1 hasn't gotten the news yet.
	 */
	g_assert (!nm_client_get_manager_running (client1));
	g_assert (nm_client_get_manager_running (client2));

	g_signal_connect (client1, "notify::" NM_CLIENT_MANAGER_RUNNING,
	                  G_CALLBACK (manager_running_changed), &running_changed);
	quit_id = g_timeout_add_seconds (5, loop_quit, loop);
	g_main_loop_run (loop);
	g_assert_cmpint (running_changed, ==, 1);
	g_assert (nm_client_get_manager_running (client1));
	g_source_remove (quit_id);

	/* And kill it */
	g_clear_pointer (&sinfo, nmtstc_service_cleanup);

	g_assert (nm_client_get_manager_running (client1));

	quit_id = g_timeout_add_seconds (5, loop_quit, loop);
	g_main_loop_run (loop);
	g_assert_cmpint (running_changed, ==, 2);
	g_assert (!nm_client_get_manager_running (client1));
	g_source_remove (quit_id);
}

/*****************************************************************************/

static GPtrArray *
_slist_to_array (GPtrArray **connections, GSList *list)
{
	GPtrArray *array;
	const GSList *iter;

	if (!*connections)
		*connections = array = g_ptr_array_new ();
	else {
		array = *connections;
		g_ptr_array_set_size (array, 0);
	}
	for (iter = list; iter; iter = iter->next)
		g_ptr_array_add (array, iter->data);
	g_slist_free (list);
	return array;
}

static gboolean
_test_connection_invalid_find_connections (gpointer element, gpointer needle, gpointer user_data)
{
	NMRemoteConnection *con = NM_REMOTE_CONNECTION (element);
	const char *path = needle;

	g_assert (NM_IS_REMOTE_CONNECTION (con));
	g_assert (path && *path);

	return strcmp (path, nm_connection_get_path ((NMConnection *) con)) == 0;
}

#define ASSERT_IDX(i) \
	g_assert_cmpint (idx[i], >=, 0); \
	g_assert (path##i && *path##i); \
	g_assert (NM_IS_REMOTE_CONNECTION (connections->pdata[idx[i]])); \
	g_assert_cmpstr (nm_connection_get_path (connections->pdata[idx[i]]), ==, path##i);

static void
test_connection_invalid (void)
{
	NMTSTC_SERVICE_INFO_SETUP (my_sinfo)
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	gs_unref_object NMRemoteSettings *settings = NULL;
	gs_unref_ptrarray GPtrArray *connections = NULL;
	gs_free char *path0 = NULL;
	gs_free char *path1 = NULL;
	gs_free char *path2 = NULL;
	gs_free char *uuid2 = NULL;
	gsize n_found;
	gssize idx[3];

	/**************************************************************************
	 * Add two connection before starting libnm. One valid, one invalid.
	 *************************************************************************/

	connection = nmtst_create_minimal_connection ("test-connection-invalid-0", NULL, NM_SETTING_WIRED_SETTING_NAME, &s_con);
	nmtst_connection_normalize (connection);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_UUID, nmtst_uuid_generate (),
	              NULL);
	nmtstc_service_add_connection (my_sinfo,
	                               connection,
	                               TRUE,
	                               &path0);

	nm_connection_remove_setting (connection, NM_TYPE_SETTING_WIRED);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "test-connection-invalid-1",
	              NM_SETTING_CONNECTION_TYPE, "invalid-type-1",
	              NM_SETTING_CONNECTION_UUID, nmtst_uuid_generate (),
	              NULL);
	nmtstc_service_add_connection (my_sinfo,
	                               connection,
	                               FALSE,
	                               &path1);

	nmtst_main_loop_run (loop, 100);

	settings = nmtstc_nm_remote_settings_new ();

	nmtst_main_loop_run (loop, 100);

	_slist_to_array (&connections, nm_remote_settings_list_connections (settings));

	g_assert_cmpint (connections->len, ==, 2);
	n_found = nmtst_find_all_indexes (connections->pdata,
	                                  connections->len,
	                                  (gpointer *) ((const char *[]) { path0, path1 }),
	                                  2,
	                                  _test_connection_invalid_find_connections,
	                                  NULL,
	                                  idx);
	g_assert_cmpint (n_found, ==, 2);
	ASSERT_IDX (0);
	ASSERT_IDX (1);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[0]]);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[1]], 0, 0);

	/**************************************************************************
	 * After having the client up and running, add another invalid connection
	 *************************************************************************/

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "test-connection-invalid-2",
	              NM_SETTING_CONNECTION_TYPE, "invalid-type-2",
	              NM_SETTING_CONNECTION_UUID, (uuid2 = g_strdup (nmtst_uuid_generate ())),
	              NULL);
	nmtstc_service_add_connection (my_sinfo,
	                               connection,
	                               FALSE,
	                               &path2);

	nmtst_main_loop_run (loop, 100);

	_slist_to_array (&connections, nm_remote_settings_list_connections (settings));

	g_assert_cmpint (connections->len, ==, 3);
	n_found = nmtst_find_all_indexes (connections->pdata,
	                                  connections->len,
	                                  (gpointer *) ((const char *[]) { path0, path1, path2 }),
	                                  3,
	                                  _test_connection_invalid_find_connections,
	                                  NULL,
	                                  idx);
	g_assert_cmpint (n_found, ==, 3);
	ASSERT_IDX (0);
	ASSERT_IDX (1);
	ASSERT_IDX (2);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[0]]);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[1]], 0, 0);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[2]], 0, 0);

	/**************************************************************************
	 * Modify the invalid connection. Connection disappears
	 *************************************************************************/

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "test-connection-invalid-2x",
	              NULL);
	nmtstc_service_update_connection (my_sinfo,
	                                  path2,
	                                  connection,
	                                  FALSE);

	nmtst_main_loop_run (loop, 100);

	_slist_to_array (&connections, nm_remote_settings_list_connections (settings));

	g_assert_cmpint (connections->len, ==, 3);
	n_found = nmtst_find_all_indexes (connections->pdata,
	                                  connections->len,
	                                  (gpointer *) ((const char *[]) { path0, path1, path2 }),
	                                  3,
	                                  _test_connection_invalid_find_connections,
	                                  NULL,
	                                  idx);
	g_assert_cmpint (n_found, ==, 3);
	ASSERT_IDX (0);
	ASSERT_IDX (1);
	ASSERT_IDX (2);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[0]]);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[1]], 0, 0);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[2]], 0, 0);

	/**************************************************************************
	 * Modify the invalid connection again. Note that the connection stays
	 * invisible (although it exists, and is valid).
	 *************************************************************************/

	g_clear_object (&connection);
	connection = nmtst_create_minimal_connection ("test-connection-invalid-2", NULL, NM_SETTING_WIRED_SETTING_NAME, &s_con);
	nmtst_connection_normalize (connection);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "test-connection-invalid-2z",
	              NM_SETTING_CONNECTION_TYPE, "802-3-ethernet",
	              NM_SETTING_CONNECTION_UUID, uuid2,
	              NULL);

	nmtstc_service_update_connection (my_sinfo,
	                                  path2,
	                                  connection,
	                                  FALSE);

	nmtst_main_loop_run (loop, 100);

	_slist_to_array (&connections, nm_remote_settings_list_connections (settings));

	g_assert_cmpint (connections->len, ==, 3);
	n_found = nmtst_find_all_indexes (connections->pdata,
	                                  connections->len,
	                                  (gpointer *) ((const char *[]) { path0, path1, path2 }),
	                                  3,
	                                  _test_connection_invalid_find_connections,
	                                  NULL,
	                                  idx);
	g_assert_cmpint (n_found, ==, 3);
	ASSERT_IDX (0);
	ASSERT_IDX (1);
	ASSERT_IDX (2);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[0]]);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[1]], 0, 0);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[2]]);

	/**************************************************************************
	 * Modify the invalid connection and make it valid
	 *************************************************************************/

	g_clear_object (&connection);
	connection = nmtst_create_minimal_connection ("test-connection-invalid-1", NULL, NM_SETTING_WIRED_SETTING_NAME, &s_con);
	nmtst_connection_normalize (connection);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "test-connection-invalid-1x",
	              NM_SETTING_CONNECTION_TYPE, "802-3-ethernet",
	              NM_SETTING_CONNECTION_UUID, nm_connection_get_uuid (connections->pdata[idx[1]]),
	              NULL);

	nmtstc_service_update_connection (my_sinfo,
	                                  path1,
	                                  connection,
	                                  FALSE);

	nmtst_main_loop_run (loop, 100);

	_slist_to_array (&connections, nm_remote_settings_list_connections (settings));

	g_assert_cmpint (connections->len, ==, 3);
	n_found = nmtst_find_all_indexes (connections->pdata,
	                                  connections->len,
	                                  (gpointer *) ((const char *[]) { path0, path1, path2 }),
	                                  3,
	                                  _test_connection_invalid_find_connections,
	                                  NULL,
	                                  idx);
	g_assert_cmpint (n_found, ==, 3);
	ASSERT_IDX (0);
	ASSERT_IDX (1);
	ASSERT_IDX (2);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[0]]);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[1]]);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[2]]);
	g_assert_cmpstr ("test-connection-invalid-1x", ==, nm_connection_get_id (connections->pdata[idx[1]]));

#undef ASSERT_IDX
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	loop = g_main_loop_new (NULL, FALSE);

	g_test_add_func ("/libnm-glib/device-added", test_device_added);
	g_test_add_func ("/libnm-glib/wifi-ap-added-removed", test_wifi_ap_added_removed);
	g_test_add_func ("/libnm-glib/wimax-nsp-added-removed", test_wimax_nsp_added_removed);
	g_test_add_func ("/libnm-glib/devices-array", test_devices_array);
	g_test_add_func ("/libnm-glib/client-manager-running", test_client_manager_running);
	g_test_add_func ("/libnm/connection/invalid", test_connection_invalid);

	return g_test_run ();
}

