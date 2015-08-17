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

#include "config.h"

#include <string.h>

#include "nm-default.h"
#include "NetworkManager.h"
#include "nm-dbus-compat.h"

#include "common.h"

static gboolean
name_exists (GDBusConnection *c, const char *name)
{
	GVariant *reply;
	gboolean exists = FALSE;

	reply = g_dbus_connection_call_sync (c,
	                                     DBUS_SERVICE_DBUS,
	                                     DBUS_PATH_DBUS,
	                                     DBUS_INTERFACE_DBUS,
	                                     "GetNameOwner",
	                                     g_variant_new ("(s)", name),
	                                     NULL,
	                                     G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                                     -1,
	                                     NULL,
	                                     NULL);
	if (reply != NULL) {
		exists = TRUE;
		g_variant_unref (reply);
	}

	return exists;
}

NMTestServiceInfo *
nm_test_service_init (void)
{
	NMTestServiceInfo *info;
	const char *args[2] = { TEST_NM_SERVICE, NULL };
	GError *error = NULL;
	int i;

	info = g_malloc0 (sizeof (*info));

	info->bus = g_bus_get_sync (G_BUS_TYPE_SESSION, NULL,  &error);
	g_assert_no_error (error);

	/* Spawn the test service. info->keepalive_fd will be a pipe to the service's
	 * stdin; if it closes, the service will exit immediately. We use this to
	 * make sure the service exits if the test program crashes.
	 */
	g_spawn_async_with_pipes (NULL, (char **) args, NULL, 0, NULL, NULL,
	                          &info->pid, &info->keepalive_fd, NULL, NULL, &error);
	g_assert_no_error (error);

	/* Wait until the service is registered on the bus */
	for (i = 1000; i > 0; i--) {
		if (name_exists (info->bus, "org.freedesktop.NetworkManager"))
			break;
		g_usleep (G_USEC_PER_SEC / 50);
	}
	g_assert (i > 0);

	/* Grab a proxy to our fake NM service to trigger tests */
	info->proxy = g_dbus_proxy_new_sync (info->bus,
	                                     G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                                     G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS |
	                                     G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
	                                     NULL,
	                                     NM_DBUS_SERVICE,
	                                     NM_DBUS_PATH,
	                                     "org.freedesktop.NetworkManager.LibnmGlibTest",
	                                     NULL, &error);
	g_assert_no_error (error);

	return info;
}

void
nm_test_service_cleanup (NMTestServiceInfo *info)
{
	int i;

	g_object_unref (info->proxy);
	kill (info->pid, SIGTERM);

	/* Wait until the bus notices the service is gone */
	for (i = 100; i > 0; i--) {
		if (!name_exists (info->bus, "org.freedesktop.NetworkManager"))
			break;
		g_usleep (G_USEC_PER_SEC / 50);
	}
	g_assert (i > 0);

	g_object_unref (info->bus);
	close (info->keepalive_fd);

	memset (info, 0, sizeof (*info));
	g_free (info);
}

typedef struct {
	GMainLoop *loop;
	const char *ifname;
	char *path;
	NMDevice *device;
} AddDeviceInfo;

static void
device_added_cb (NMClient *client,
                 NMDevice *device,
                 gpointer user_data)
{
	AddDeviceInfo *info = user_data;

	g_assert (device);
	g_assert_cmpstr (nm_object_get_path (NM_OBJECT (device)), ==, info->path);
	g_assert_cmpstr (nm_device_get_iface (device), ==, info->ifname);

	info->device = device;
	g_main_loop_quit (info->loop);
}

static gboolean
timeout (gpointer user_data)
{
	g_assert_not_reached ();
	return G_SOURCE_REMOVE;
}

NMDevice *
nm_test_service_add_device (NMTestServiceInfo *sinfo, NMClient *client,
                            const char *method, const char *ifname)
{
	AddDeviceInfo info;
	GError *error = NULL;
	GVariant *ret;
	guint timeout_id;

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
	g_variant_get (ret, "(o)", &info.path);
	g_variant_unref (ret);

	/* Wait for libnm to find the device */
	info.ifname = ifname;
	info.loop = g_main_loop_new (NULL, FALSE);
	g_signal_connect (client, "device-added",
	                  G_CALLBACK (device_added_cb), &info);
	timeout_id = g_timeout_add_seconds (5, timeout, NULL);
	g_main_loop_run (info.loop);

	g_source_remove (timeout_id);
	g_signal_handlers_disconnect_by_func (client, device_added_cb, &info);
	g_free (info.path);
	g_main_loop_unref (info.loop);

	return info.device;
}
