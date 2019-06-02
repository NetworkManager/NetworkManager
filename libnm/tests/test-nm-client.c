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

#include <sys/types.h>
#include <signal.h>

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

/*****************************************************************************/

static void
devices_notify_cb (NMClient *c,
                   GParamSpec *pspec,
                   gpointer user_data)
{
	gboolean *notified = user_data;
	const GPtrArray *devices;
	NMDevice *device;

	devices = nm_client_get_devices (c);
	g_assert (devices);
	g_assert_cmpint (devices->len, ==, 1);

	device = g_ptr_array_index (devices, 0);
	g_assert (device);
	g_assert_cmpstr (nm_device_get_iface (device), ==, "eth0");

	*notified = TRUE;
}

static void
test_device_added (void)
{
	NMClient *client;
	const GPtrArray *devices;
	NMDevice *device;
	gboolean notified = FALSE;
	GError *error = NULL;

	sinfo = nmtstc_service_init ();
	if (!nmtstc_service_available (sinfo))
		return;

	client = nm_client_new (NULL, &error);
	g_assert_no_error (error);

	devices = nm_client_get_devices (client);
	g_assert (devices->len == 0);

	g_signal_connect (client,
	                  "notify::devices",
	                  (GCallback) devices_notify_cb,
	                  &notified);

	/* Tell the test service to add a new device */
	nmtstc_service_add_device (sinfo, client, "AddWiredDevice", "eth0");

	/* coverity[loop_condition] */
	while (!notified)
		g_main_context_iteration (NULL, TRUE);

	g_signal_handlers_disconnect_by_func (client, devices_notify_cb, &notified);

	devices = nm_client_get_devices (client);
	g_assert (devices);
	g_assert_cmpint (devices->len, ==, 1);

	device = g_ptr_array_index (devices, 0);
	g_assert (device);
	g_assert_cmpstr (nm_device_get_iface (device), ==, "eth0");

	/* Try deleting the device via the ordinary NM interface, which should fail */
	nm_device_delete (device, NULL, &error);
	g_assert_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_NOT_SOFTWARE);
	g_clear_error (&error);

	g_object_unref (client);
	g_clear_pointer (&sinfo, nmtstc_service_cleanup);
}

/*****************************************************************************/

typedef enum {
	SIGNAL_FIRST  = 0x01,
	SIGNAL_SECOND = 0x02,
	SIGNAL_MASK   = 0x0F,
	NOTIFY_FIRST  = 0x10,
	NOTIFY_SECOND = 0x20,
	NOTIFY_MASK   = 0xF0
} DeviceSignaledAfterInitType;

static void
device_sai_added_cb (NMClient *c,
                     NMDevice *device,
                     gpointer user_data)
{
	guint *result = user_data;

	g_assert (device);
	g_assert_cmpstr (nm_device_get_iface (device), ==, "eth0");

	g_assert ((*result & SIGNAL_MASK) == 0);
	*result |= *result ? SIGNAL_SECOND : SIGNAL_FIRST;
}

static void
devices_sai_notify_cb (NMClient *c,
                       GParamSpec *pspec,
                       gpointer user_data)
{
	guint *result = user_data;
	const GPtrArray *devices;
	NMDevice *device;

	devices = nm_client_get_devices (c);
	g_assert (devices);
	g_assert_cmpint (devices->len, ==, 1);

	device = g_ptr_array_index (devices, 0);
	g_assert (device);
	g_assert_cmpstr (nm_device_get_iface (device), ==, "eth0");

	g_assert ((*result & NOTIFY_MASK) == 0);
	*result |= *result ? NOTIFY_SECOND : NOTIFY_FIRST;
}

static void
test_device_added_signal_after_init (void)
{
	NMClient *client;
	const GPtrArray *devices;
	NMDevice *device;
	guint result = 0;
	GError *error = NULL;

	sinfo = nmtstc_service_init ();
	if (!nmtstc_service_available (sinfo))
		return;

	client = nm_client_new (NULL, &error);
	g_assert_no_error (error);

	devices = nm_client_get_devices (client);
	g_assert (devices->len == 0);

	g_signal_connect (client,
	                  NM_CLIENT_DEVICE_ADDED,
	                  (GCallback) device_sai_added_cb,
	                  &result);

	g_signal_connect (client,
	                  "notify::" NM_CLIENT_DEVICES,
	                  (GCallback) devices_sai_notify_cb,
	                  &result);

	/* Tell the test service to add a new device */
	nmtstc_service_add_device (sinfo, client, "AddWiredDevice", "eth0");

	/* Ensure the 'device-added' signal doesn't show up before
	 * the 'Devices' property change notification */
	/* coverity[loop_condition] */
	while (!(result & SIGNAL_MASK) && !(result & NOTIFY_MASK))
		g_main_context_iteration (NULL, TRUE);

	g_signal_handlers_disconnect_by_func (client, device_sai_added_cb, &result);
	g_signal_handlers_disconnect_by_func (client, devices_sai_notify_cb, &result);

	g_assert ((result & SIGNAL_MASK) == SIGNAL_FIRST);
	g_assert ((result & NOTIFY_MASK) == NOTIFY_SECOND);

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
	g_assert (aps->len == 0);

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

	client = nm_client_new (NULL, &error);
	g_assert_no_error (error);

	/*************************************/
	/* Add the wifi device */
	wifi = (NMDeviceWifi *) nmtstc_service_add_device (sinfo, client, "AddWifiDevice", "wlan0");
	g_assert (NM_IS_DEVICE_WIFI (wifi));

	/*************************************/
	/* Add the wifi AP */
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

	/* Wait for libnm to find the AP */
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

	/* Wait for libnm to find the AP */
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
	g_assert (nsps->len == 0);

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

	client = nm_client_new (NULL, &error);
	g_assert_no_error (error);

	/*************************************/
	/* Add the wimax device */
	wimax = (NMDeviceWimax *) nmtstc_service_add_device (sinfo, client, "AddWimaxDevice", "wmx0");
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

	/* Wait for libnm to find the AP */
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

	/* Wait for libnm to find the AP */
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
	info->quit_count--;
	if (info->quit_count == 0) {
		g_source_remove (info->quit_id);
		info->quit_id = 0;
		g_main_loop_quit (info->loop);
	}
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
new_client_cb (GObject *object,
               GAsyncResult *result,
               gpointer user_data)
{
	NMClient **out_client = user_data;
	GError *error = NULL;

	*out_client = nm_client_new_finish (result, &error);
	g_assert_no_error (error);
	g_assert (*out_client != NULL);

	g_main_loop_quit (loop);
}

static void
test_devices_array (void)
{
	NMClient *client = NULL;
	DaInfo info = { loop };
	NMDevice *wlan0, *eth0, *eth1, *device;
	const GPtrArray *devices;
	GError *error = NULL;
	GVariant *ret;

	sinfo = nmtstc_service_init ();
	if (!nmtstc_service_available (sinfo))
		return;

	/* Make sure that we test the async codepath in at least one test... */
	nm_client_new_async (NULL, new_client_cb, &client);
	g_main_loop_run (loop);
	g_assert (client != NULL);

	/*************************************/
	/* Add some devices */
	wlan0 = nmtstc_service_add_device (sinfo, client,"AddWifiDevice", "wlan0");
	eth0 = nmtstc_service_add_device (sinfo, client, "AddWiredDevice", "eth0");
	eth1 = nmtstc_service_add_device (sinfo, client, "AddWiredDevice", "eth1");

	/* Ensure the devices now exist */
	devices = nm_client_get_devices (client);
	g_assert (devices);
	g_assert_cmpint (devices->len, ==, 3);

	device = nm_client_get_device_by_iface (client, "wlan0");
	g_assert (NM_IS_DEVICE_WIFI (device));
	g_assert (device == wlan0);

	device = nm_client_get_device_by_iface (client, "eth0");
	g_assert (NM_IS_DEVICE_ETHERNET (device));
	g_assert (device == eth0);

	device = nm_client_get_device_by_iface (client, "eth1");
	g_assert (NM_IS_DEVICE_ETHERNET (device));
	g_assert (device == eth1);

	/********************************/
	/* Now remove the device in the middle */
	ret = g_dbus_proxy_call_sync (sinfo->proxy,
	                              "RemoveDevice",
	                              g_variant_new ("(o)", nm_object_get_path (NM_OBJECT (eth0))),
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

	/* Wait for libnm to notice the changes */
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
	g_assert (device == wlan0);

	device = nm_client_get_device_by_iface (client, "eth1");
	g_assert (NM_IS_DEVICE_ETHERNET (device));
	g_assert (device == eth1);

	g_object_unref (client);
	g_clear_pointer (&sinfo, nmtstc_service_cleanup);
}

static void
nm_running_changed (GObject *client,
                    GParamSpec *pspec,
                    gpointer user_data)
{
	int *running_changed = user_data;

	(*running_changed)++;
	g_main_loop_quit (loop);
}

static void
test_client_nm_running (void)
{
	gs_unref_object NMClient *client1 = NULL;
	gs_unref_object NMClient *client2 = NULL;
	guint quit_id;
	int running_changed = 0;
	GError *error = NULL;

	client1 = nm_client_new (NULL, &error);
	g_assert_no_error (error);

	g_assert (!nm_client_get_nm_running (client1));
	g_assert_cmpstr (nm_client_get_version (client1), ==, NULL);

	g_assert (!nm_client_networking_get_enabled (client1));
	/* This will have no effect, but it shouldn't cause any warnings either. */
	nm_client_networking_set_enabled (client1, TRUE, NULL);
	g_assert (!nm_client_networking_get_enabled (client1));

	/* OTOH, this should result in an error */
	nm_client_set_logging (client1, "DEFAULT", "INFO", &error);
	g_assert_error (error, NM_CLIENT_ERROR, NM_CLIENT_ERROR_MANAGER_NOT_RUNNING);
	g_clear_error (&error);

	/* Now start the test service. */
	sinfo = nmtstc_service_init ();
	if (!nmtstc_service_available (sinfo))
		return;

	client2 = nm_client_new (NULL, &error);
	g_assert_no_error (error);

	/* client2 should know that NM is running, but the previously-created
	 * client1 hasn't gotten the news yet.
	 */
	g_assert (!nm_client_get_nm_running (client1));
	g_assert (nm_client_get_nm_running (client2));

	g_signal_connect (client1, "notify::" NM_CLIENT_NM_RUNNING,
	                  G_CALLBACK (nm_running_changed), &running_changed);
	quit_id = g_timeout_add_seconds (5, loop_quit, loop);
	g_main_loop_run (loop);
	g_assert_cmpint (running_changed, ==, 1);
	g_assert (nm_client_get_nm_running (client1));
	g_source_remove (quit_id);

	/* And kill it */
	g_clear_pointer (&sinfo, nmtstc_service_cleanup);

	g_assert (nm_client_get_nm_running (client1));

	quit_id = g_timeout_add_seconds (5, loop_quit, loop);
	g_main_loop_run (loop);
	g_assert_cmpint (running_changed, ==, 2);
	g_assert (!nm_client_get_nm_running (client1));
	g_source_remove (quit_id);
}

typedef struct {
	GMainLoop *loop;
	NMActiveConnection *ac;

	int remaining;
} TestACInfo;

static void
assert_ac_and_device (NMClient *client)
{
	const GPtrArray *devices, *acs, *ac_devices;
	NMDevice *device, *ac_device;
	NMActiveConnection *ac, *device_ac;

	acs = nm_client_get_active_connections (client);
	g_assert (acs != NULL);
	g_assert_cmpint (acs->len, ==, 1);
	devices = nm_client_get_devices (client);
	g_assert (devices != NULL);
	g_assert_cmpint (devices->len, >=, 1);

	ac = acs->pdata[0];
	ac_devices = nm_active_connection_get_devices (ac);
	g_assert (ac_devices != NULL);
	g_assert_cmpint (ac_devices->len, ==, 1);
	ac_device = ac_devices->pdata[0];
	g_assert (ac_device != NULL);

	device = devices->pdata[0];
	if (device != ac_device && devices->len > 1)
		device = devices->pdata[1];
	device_ac = nm_device_get_active_connection (device);
	g_assert (device_ac != NULL);

	g_assert_cmpstr (nm_object_get_path (NM_OBJECT (device)), ==, nm_object_get_path (NM_OBJECT (ac_device)));
	g_assert (device == ac_device);
	g_assert_cmpstr (nm_object_get_path (NM_OBJECT (ac)), ==, nm_object_get_path (NM_OBJECT (device_ac)));
	g_assert (ac == device_ac);
}

static void
add_and_activate_cb (GObject *object,
                     GAsyncResult *result,
                     gpointer user_data)
{
	NMClient *client = NM_CLIENT (object);
	TestACInfo *info = user_data;
	GError *error = NULL;

	info->ac = nm_client_add_and_activate_connection_finish (client, result, &error);
	g_assert_no_error (error);
	g_assert (info->ac != NULL);

	assert_ac_and_device (client);

	info->remaining--;
	if (!info->remaining)
		g_main_loop_quit (info->loop);
}

static void
client_acs_changed_cb (GObject *client,
                       GParamSpec *pspec,
                       gpointer user_data)
{
	TestACInfo *info = user_data;
	const GPtrArray *acs;

	acs = nm_client_get_active_connections (NM_CLIENT (client));
	g_assert (acs != NULL);
	g_assert_cmpint (acs->len, ==, 1);

	info->remaining--;
	if (!info->remaining)
		g_main_loop_quit (info->loop);
}

static void
device_ac_changed_cb (GObject *device,
                      GParamSpec *pspec,
                      gpointer user_data)
{
	TestACInfo *info = user_data;

	g_assert (nm_device_get_active_connection (NM_DEVICE (device)) != NULL);

	info->remaining--;
	if (!info->remaining)
		g_main_loop_quit (info->loop);
}

static void
test_active_connections (void)
{
	NMClient *client;
	NMDevice *device;
	NMConnection *conn;
	TestACInfo info = { loop, NULL, 0 };
	GError *error = NULL;

	sinfo = nmtstc_service_init ();
	if (!nmtstc_service_available (sinfo))
		return;

	client = nm_client_new (NULL, &error);
	g_assert_no_error (error);

	/* Tell the test service to add a new device */
	device = nmtstc_service_add_device (sinfo, client, "AddWiredDevice", "eth0");

	conn = nmtst_create_minimal_connection ("test-ac", NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
	nm_client_add_and_activate_connection_async (client, conn, device, NULL,
	                                             NULL, add_and_activate_cb, &info);
	g_object_unref (conn);

	g_signal_connect (client, "notify::" NM_CLIENT_ACTIVE_CONNECTIONS,
	                  G_CALLBACK (client_acs_changed_cb), &info);
	g_signal_connect (device, "notify::" NM_DEVICE_ACTIVE_CONNECTION,
	                  G_CALLBACK (device_ac_changed_cb), &info);

	/* Two signals plus activate_cb */
	info.remaining = 3;
	g_main_loop_run (loop);
	g_signal_handlers_disconnect_by_func (client, client_acs_changed_cb, &info);
	g_signal_handlers_disconnect_by_func (device, device_ac_changed_cb, &info);

	g_assert (info.ac != NULL);

	g_object_unref (info.ac);
	g_object_unref (client);

	/* Ensure that we can correctly resolve the recursive property link between the
	 * AC and the Device in a newly-created client.
	 */
	client = nm_client_new (NULL, &error);
	g_assert_no_error (error);
	assert_ac_and_device (client);
	g_object_unref (client);

	client = NULL;
	nm_client_new_async (NULL, new_client_cb, &client);
	g_main_loop_run (loop);
	assert_ac_and_device (client);
	g_object_unref (client);

	g_clear_pointer (&sinfo, nmtstc_service_cleanup);
}

static void
client_devices_changed_cb (GObject *client,
                           GParamSpec *pspec,
                           gpointer user_data)
{
	TestACInfo *info = user_data;
	const GPtrArray *devices;
	NMDevice *device;

	devices = nm_client_get_devices (NM_CLIENT (client));
	g_assert (devices != NULL);
	if (devices->len < 2)
		return;
	g_assert_cmpint (devices->len, ==, 2);

	if (NM_IS_DEVICE_VLAN (devices->pdata[0]))
		device = devices->pdata[0];
	else if (NM_IS_DEVICE_VLAN (devices->pdata[1]))
		device = devices->pdata[1];
	else
		g_assert_not_reached ();

	g_assert_cmpstr (nm_device_get_iface (device), ==, "eth0.1");

	if (!nm_device_get_active_connection (device)) {
		info->remaining++;
		g_signal_connect (device, "notify::" NM_DEVICE_ACTIVE_CONNECTION,
		                  G_CALLBACK (device_ac_changed_cb), info);
	}

	info->remaining--;
	if (!info->remaining)
		g_main_loop_quit (info->loop);
}

typedef struct {
	GMainLoop *loop;
	NMRemoteConnection *remote;
} TestConnectionInfo;

static void
add_connection_cb (GObject *object,
                   GAsyncResult *result,
                   gpointer user_data)
{
	TestConnectionInfo *info = user_data;
	GError *error = NULL;

	info->remote = nm_client_add_connection_finish (NM_CLIENT (object), result, &error);
	g_assert_no_error (error);
	g_main_loop_quit (info->loop);
}

static void
activate_cb (GObject *object,
             GAsyncResult *result,
             gpointer user_data)
{
	NMClient *client = NM_CLIENT (object);
	TestACInfo *info = user_data;
	GError *error = NULL;

	info->ac = nm_client_activate_connection_finish (client, result, &error);
	g_assert_no_error (error);
	g_assert (info->ac != NULL);

	assert_ac_and_device (client);

	info->remaining--;
	if (!info->remaining)
		g_main_loop_quit (info->loop);
}

static void
test_activate_virtual (void)
{
	NMClient *client;
	NMConnection *conn;
	NMSettingConnection *s_con;
	NMSettingVlan *s_vlan;
	TestACInfo info = { loop, NULL, 0 };
	TestConnectionInfo conn_info = { loop, NULL };
	GError *error = NULL;

	sinfo = nmtstc_service_init ();
	if (!nmtstc_service_available (sinfo))
		return;

	client = nm_client_new (NULL, &error);
	g_assert_no_error (error);

	nmtstc_service_add_device (sinfo, client, "AddWiredDevice", "eth0");

	conn = nmtst_create_minimal_connection ("test-ac", NULL, NM_SETTING_VLAN_SETTING_NAME, &s_con);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "eth0.1",
	              NULL);
	s_vlan = nm_connection_get_setting_vlan (conn);
	g_object_set (s_vlan,
	              NM_SETTING_VLAN_ID, 1,
	              NM_SETTING_VLAN_PARENT, "eth0",
	              NULL);

	nm_client_add_connection_async (client, conn, TRUE,
	                                NULL, add_connection_cb, &conn_info);
	g_main_loop_run (loop);
	g_object_unref (conn);
	conn = NM_CONNECTION (conn_info.remote);

	nm_client_activate_connection_async (client, conn, NULL, NULL,
	                                     NULL, activate_cb, &info);
	g_object_unref (conn);

	g_signal_connect (client, "notify::" NM_CLIENT_ACTIVE_CONNECTIONS,
	                  G_CALLBACK (client_acs_changed_cb), &info);
	g_signal_connect (client, "notify::" NM_CLIENT_DEVICES,
	                  G_CALLBACK (client_devices_changed_cb), &info);

	/* We're expecting a client::devices change, client::activate callback,
	 * and a device::active-connection change.
	 * The client::devices callback can hook a client::active-connections
	 * change and bump this if the property is not yet loaded.
	 */
	info.remaining = 3;

	g_main_loop_run (loop);
	g_signal_handlers_disconnect_by_func (client, client_acs_changed_cb, &info);
	g_signal_handlers_disconnect_by_func (client, client_devices_changed_cb, &info);

	g_assert (info.ac != NULL);

	g_object_unref (info.ac);
	g_object_unref (client);

	g_clear_pointer (&sinfo, nmtstc_service_cleanup);
}

static void
activate_failed_cb (GObject *object,
                    GAsyncResult *result,
                    gpointer user_data)
{
	NMClient *client = NM_CLIENT (object);
	NMActiveConnection *ac;
	GError *error = NULL;

	ac = nm_client_activate_connection_finish (client, result, &error);
	g_assert (ac == NULL);
	g_assert_error (error, NM_CLIENT_ERROR, NM_CLIENT_ERROR_OBJECT_CREATION_FAILED);
	g_clear_error (&error);

	g_main_loop_quit (loop);
}

static void
test_activate_failed (void)
{
	NMClient *client;
	NMDevice *device;
	NMConnection *conn;
	GError *error = NULL;

	sinfo = nmtstc_service_init ();
	if (!nmtstc_service_available (sinfo))
		return;

	client = nm_client_new (NULL, &error);
	g_assert_no_error (error);

	device = nmtstc_service_add_device (sinfo, client, "AddWiredDevice", "eth0");

	/* Note that test-networkmanager-service.py checks for this exact name */
	conn = nmtst_create_minimal_connection ("object-creation-failed-test", NULL,
	                                        NM_SETTING_WIRED_SETTING_NAME, NULL);

	nm_client_add_and_activate_connection_async (client, conn, device, NULL,
	                                             NULL, activate_failed_cb, NULL);
	g_main_loop_run (loop);

	g_object_unref (conn);
	g_object_unref (client);

	g_clear_pointer (&sinfo, nmtstc_service_cleanup);
}

static void
test_device_connection_compatibility (void)
{
	NMClient *client;
	NMDevice *device1, *device2;
	NMConnection *conn;
	NMSettingWired *s_wired;
	GError *error = NULL;
	const char *subchannels[] = { "0.0.8000", "0.0.8001", "0.0.8002", NULL };
	const char *subchannels_2[] = { "0.0.8000", "0.0.8001", NULL };
	const char *subchannels_x[] = { "0.0.8000", "0.0.8001", "0.0.800X", NULL };
	const char *hw_addr1 = "52:54:00:ab:db:23";
	const char *hw_addr2 = "52:54:00:ab:db:24";

	sinfo = nmtstc_service_init ();
	if (!nmtstc_service_available (sinfo))
		return;

	client = nm_client_new (NULL, &error);
	g_assert_no_error (error);

	/* Create two devices */
	device1 = nmtstc_service_add_wired_device (sinfo, client, "eth0", hw_addr1, subchannels);
	device2 = nmtstc_service_add_wired_device (sinfo, client, "eth1", hw_addr2, NULL);

	g_assert_cmpstr (nm_device_get_hw_address (device1), ==, hw_addr1);
	g_assert_cmpstr (nm_device_get_hw_address (device2), ==, hw_addr2);

	conn = nmtst_create_minimal_connection ("wired-matches", NULL,
	                                        NM_SETTING_WIRED_SETTING_NAME, NULL);
	s_wired = nm_connection_get_setting_wired (conn);
	nm_setting_wired_add_mac_blacklist_item (s_wired, "00:11:22:33:44:55");

	/* device1 and conn are compatible */
	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, hw_addr1,
	              NM_SETTING_WIRED_S390_SUBCHANNELS, subchannels,
	              NULL);
	nm_device_connection_compatible (device1, conn, &error);
	g_assert_no_error (error);

	/* device2 and conn differ in subchannels */
	g_object_set (s_wired, NM_SETTING_WIRED_S390_SUBCHANNELS, subchannels_x, NULL);
	nm_device_connection_compatible (device2, conn, &error);
	g_assert_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION);
	g_clear_error (&error);

	/* device1 and conn differ in subchannels - 2 in connection, 3 in device */
	g_object_set (s_wired, NM_SETTING_WIRED_S390_SUBCHANNELS, subchannels_2, NULL);
	nm_device_connection_compatible (device1, conn, &error);
	g_assert_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION);
	g_clear_error (&error);

	g_object_set (s_wired, NM_SETTING_WIRED_S390_SUBCHANNELS, NULL, NULL);

	/* device2 and conn differ in MAC address */
	g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, "aa:bb:cc:dd:ee:ee", NULL);
	nm_device_connection_compatible (device2, conn, &error);
	g_assert_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION);
	g_clear_error (&error);
	g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, NULL, NULL);

	/* device1 is blacklisted in conn */
	nm_setting_wired_add_mac_blacklist_item (s_wired, hw_addr1);
	nm_device_connection_compatible (device1, conn, &error);
	g_assert_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION);
	g_clear_error (&error);

	g_object_unref (conn);
	g_object_unref (client);

	g_clear_pointer (&sinfo, nmtstc_service_cleanup);
}

/*****************************************************************************/

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
	G_STMT_START { \
		g_assert_cmpint (idx[i], >=, 0); \
		g_assert (path##i && *path##i); \
		g_assert (NM_IS_REMOTE_CONNECTION (connections->pdata[idx[i]])); \
		g_assert_cmpstr (nm_connection_get_path (connections->pdata[idx[i]]), ==, path##i); \
	} G_STMT_END

static void
test_connection_invalid (void)
{
	NMTSTC_SERVICE_INFO_SETUP (my_sinfo)
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	gs_unref_object NMClient *client = NULL;
	const GPtrArray *connections;
	gs_free_error GError *error = NULL;
	gs_free char *path0 = NULL;
	gs_free char *path1 = NULL;
	gs_free char *path2 = NULL;
	gs_free char *path3 = NULL;
	gs_free char *uuid2 = NULL;
	gsize n_found;
	gssize idx[4];
	gs_unref_variant GVariant *variant = NULL;

	/**************************************************************************
	 * Add three connections before starting libnm. One valid, two invalid.
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

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "test-connection-invalid-2",
	              NM_SETTING_CONNECTION_TYPE, "invalid-type-2",
	              NM_SETTING_CONNECTION_UUID, nmtst_uuid_generate (),
	              NULL);
	variant = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);
	NMTST_VARIANT_EDITOR (variant,
	                      NMTST_VARIANT_ADD_SETTING ("invalid-type-2",
	                                                 nmtst_variant_new_vardict ("some-key1", g_variant_new_string ("some-value1"),
	                                                                            "some-key2", g_variant_new_uint32 (4722))));
	g_variant_ref_sink (variant);
	nmtstc_service_add_connection_variant (my_sinfo,
	                                       variant,
	                                       FALSE,
	                                       &path2);

	client = nm_client_new (NULL, &error);
	g_assert_no_error (error);

	connections = nm_client_get_connections (client);
	g_assert (connections);

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
	                               &path3);

	nmtst_main_loop_run (loop, 1000);

	connections = nm_client_get_connections (client);
	g_assert (connections);

	g_assert_cmpint (connections->len, ==, 4);
	n_found = nmtst_find_all_indexes (connections->pdata,
	                                  connections->len,
	                                  (gpointer *) ((const char *[]) { path0, path1, path2, path3 }),
	                                  4,
	                                  _test_connection_invalid_find_connections,
	                                  NULL,
	                                  idx);
	g_assert_cmpint (n_found, ==, 4);
	ASSERT_IDX (0);
	ASSERT_IDX (1);
	ASSERT_IDX (2);
	ASSERT_IDX (3);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[0]]);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[1]], 0, 0);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[2]], 0, 0);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[3]], 0, 0);

	/**************************************************************************
	 * Modify the invalid connection (still invalid)
	 *************************************************************************/

	NMTST_VARIANT_EDITOR (variant,
	                      NMTST_VARIANT_CHANGE_PROPERTY ("invalid-type-2",
	                                                     "some-key2", "u", 4721));
	g_variant_ref_sink (variant);
	nmtstc_service_update_connection_variant (my_sinfo,
	                                          path2,
	                                          variant,
	                                          FALSE);

	nmtst_main_loop_run (loop, 100);

	connections = nm_client_get_connections (client);
	g_assert (connections);

	g_assert_cmpint (connections->len, ==, 4);
	n_found = nmtst_find_all_indexes (connections->pdata,
	                                  connections->len,
	                                  (gpointer *) ((const char *[]) { path0, path1, path2, path3 }),
	                                  4,
	                                  _test_connection_invalid_find_connections,
	                                  NULL,
	                                  idx);
	g_assert_cmpint (n_found, ==, 4);
	ASSERT_IDX (0);
	ASSERT_IDX (1);
	ASSERT_IDX (2);
	ASSERT_IDX (3);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[0]]);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[1]], 0, 0);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[2]], 0, 0);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[3]], 0, 0);

	/**************************************************************************
	 * Modify the invalid connection (becomes valid)
	 *************************************************************************/

	NMTST_VARIANT_EDITOR (variant,
	                      NMTST_VARIANT_DROP_SETTING ("invalid-type-2"));
	NMTST_VARIANT_EDITOR (variant,
	                      NMTST_VARIANT_CHANGE_PROPERTY (NM_SETTING_CONNECTION_SETTING_NAME,
	                                                     NM_SETTING_CONNECTION_TYPE, "s", NM_SETTING_WIRED_SETTING_NAME));
	g_variant_ref_sink (variant);
	nmtstc_service_update_connection_variant (my_sinfo,
	                                          path2,
	                                          variant,
	                                          FALSE);

	nmtst_main_loop_run (loop, 100);

	connections = nm_client_get_connections (client);
	g_assert (connections);

	g_assert_cmpint (connections->len, ==, 4);
	n_found = nmtst_find_all_indexes (connections->pdata,
	                                  connections->len,
	                                  (gpointer *) ((const char *[]) { path0, path1, path2, path3 }),
	                                  4,
	                                  _test_connection_invalid_find_connections,
	                                  NULL,
	                                  idx);
	g_assert_cmpint (n_found, ==, 4);
	ASSERT_IDX (0);
	ASSERT_IDX (1);
	ASSERT_IDX (2);
	ASSERT_IDX (3);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[0]]);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[1]], 0, 0);
	nmtst_assert_connection_verifies_after_normalization (connections->pdata[idx[2]], 0, 0);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[3]], 0, 0);

	/**************************************************************************
	 * Modify the invalid connection (still invalid)
	 *************************************************************************/

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "test-connection-invalid-2x",
	              NULL);
	nmtstc_service_update_connection (my_sinfo,
	                                  path3,
	                                  connection,
	                                  FALSE);

	nmtst_main_loop_run (loop, 100);

	connections = nm_client_get_connections (client);
	g_assert (connections);

	g_assert_cmpint (connections->len, ==, 4);
	n_found = nmtst_find_all_indexes (connections->pdata,
	                                  connections->len,
	                                  (gpointer *) ((const char *[]) { path0, path1, path2, path3 }),
	                                  4,
	                                  _test_connection_invalid_find_connections,
	                                  NULL,
	                                  idx);
	g_assert_cmpint (n_found, ==, 4);
	ASSERT_IDX (0);
	ASSERT_IDX (1);
	ASSERT_IDX (2);
	ASSERT_IDX (3);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[0]]);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[1]], 0, 0);
	nmtst_assert_connection_verifies_after_normalization (connections->pdata[idx[2]], 0, 0);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[3]], 0, 0);
	g_assert_cmpstr ("test-connection-invalid-2x", ==, nm_connection_get_id (connections->pdata[idx[3]]));

	/**************************************************************************
	 * Modify the invalid connection (now becomes valid)
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
	                                  path3,
	                                  connection,
	                                  FALSE);

	nmtst_main_loop_run (loop, 100);

	connections = nm_client_get_connections (client);
	g_assert (connections);

	g_assert_cmpint (connections->len, ==, 4);
	n_found = nmtst_find_all_indexes (connections->pdata,
	                                  connections->len,
	                                  (gpointer *) ((const char *[]) { path0, path1, path2, path3 }),
	                                  4,
	                                  _test_connection_invalid_find_connections,
	                                  NULL,
	                                  idx);
	g_assert_cmpint (n_found, ==, 4);
	ASSERT_IDX (0);
	ASSERT_IDX (1);
	ASSERT_IDX (2);
	ASSERT_IDX (3);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[0]]);
	nmtst_assert_connection_unnormalizable (connections->pdata[idx[1]], 0, 0);
	nmtst_assert_connection_verifies_after_normalization (connections->pdata[idx[2]], 0, 0);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[3]]);
	g_assert_cmpstr ("test-connection-invalid-2z", ==, nm_connection_get_id (connections->pdata[idx[3]]));

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

	connections = nm_client_get_connections (client);
	g_assert (connections);

	g_assert_cmpint (connections->len, ==, 4);
	n_found = nmtst_find_all_indexes (connections->pdata,
	                                  connections->len,
	                                  (gpointer *) ((const char *[]) { path0, path1, path2, path3 }),
	                                  4,
	                                  _test_connection_invalid_find_connections,
	                                  NULL,
	                                  idx);
	g_assert_cmpint (n_found, ==, 4);
	ASSERT_IDX (0);
	ASSERT_IDX (1);
	ASSERT_IDX (2);
	ASSERT_IDX (3);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[0]]);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[1]]);
	nmtst_assert_connection_verifies_after_normalization (connections->pdata[idx[2]], 0, 0);
	nmtst_assert_connection_verifies_without_normalization (connections->pdata[idx[3]]);
	g_assert_cmpstr ("test-connection-invalid-1x", ==, nm_connection_get_id (connections->pdata[idx[1]]));
	g_assert_cmpstr ("test-connection-invalid-2z", ==, nm_connection_get_id (connections->pdata[idx[3]]));

#undef ASSERT_IDX
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	g_setenv ("LIBNM_USE_SESSION_BUS", "1", TRUE);

	nmtst_init (&argc, &argv, TRUE);

	loop = g_main_loop_new (NULL, FALSE);

	g_test_add_func ("/libnm/device-added", test_device_added);
	g_test_add_func ("/libnm/device-added-signal-after-init", test_device_added_signal_after_init);
	g_test_add_func ("/libnm/wifi-ap-added-removed", test_wifi_ap_added_removed);
	g_test_add_func ("/libnm/wimax-nsp-added-removed", test_wimax_nsp_added_removed);
	g_test_add_func ("/libnm/devices-array", test_devices_array);
	g_test_add_func ("/libnm/client-nm-running", test_client_nm_running);
	g_test_add_func ("/libnm/active-connections", test_active_connections);
	g_test_add_func ("/libnm/activate-virtual", test_activate_virtual);
	g_test_add_func ("/libnm/activate-failed", test_activate_failed);
	g_test_add_func ("/libnm/device-connection-compatibility", test_device_connection_compatibility);
	g_test_add_func ("/libnm/connection/invalid", test_connection_invalid);

	return g_test_run ();
}
