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
 * Copyright 2010 - 2015 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <sys/wait.h>

#include "NetworkManager.h"
#include "nm-std-aux/nm-dbus-compat.h"

#include "nm-test-libnm-utils.h"

#define NMTSTC_NM_SERVICE NM_BUILD_SRCDIR"/tools/test-networkmanager-service.py"

/*****************************************************************************/

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

#if (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_GLIB
static DBusGProxy *
_libdbus_create_proxy_test (DBusGConnection *bus)
{
	DBusGProxy *proxy;

	proxy = dbus_g_proxy_new_for_name (bus,
	                                   NM_DBUS_SERVICE,
	                                   NM_DBUS_PATH,
	                                   "org.freedesktop.NetworkManager.LibnmGlibTest");
	g_assert (proxy);

	dbus_g_proxy_set_default_timeout (proxy, G_MAXINT);

	return proxy;
}
#endif

typedef struct {
	GMainLoop *mainloop;
	GDBusConnection *bus;
	int exit_code;
	bool exited:1;
	bool name_found:1;
} ServiceInitWaitData;

static gboolean
_service_init_wait_probe_name (gpointer user_data)
{
	ServiceInitWaitData *data = user_data;

	if (!name_exists (data->bus, "org.freedesktop.NetworkManager"))
		return G_SOURCE_CONTINUE;

	data->name_found = TRUE;
	g_main_loop_quit (data->mainloop);
	return G_SOURCE_REMOVE;
}

static void
_service_init_wait_child_wait (GPid pid,
                               int status,
                               gpointer user_data)
{
	ServiceInitWaitData *data = user_data;

	data->exited = TRUE;
	data->exit_code = status;
	g_main_loop_quit (data->mainloop);
}

NMTstcServiceInfo *
nmtstc_service_available (NMTstcServiceInfo *info)
{
	gs_free char *m = NULL;

	if (info)
		return info;

	/* This happens, when test-networkmanager-service.py exits with 77 status
	 * code. */
	m = g_strdup_printf ("missing dependency for running NetworkManager stub service %s", NMTSTC_NM_SERVICE);
	g_test_skip (m);
	return NULL;
}

NMTstcServiceInfo *
nmtstc_service_init (void)
{
	NMTstcServiceInfo *info;
	const char *args[] = { TEST_NM_PYTHON, NMTSTC_NM_SERVICE, NULL };
	GError *error = NULL;

	info = g_malloc0 (sizeof (*info));

	info->bus = g_bus_get_sync (G_BUS_TYPE_SESSION, NULL,  &error);
	g_assert_no_error (error);

	/* Spawn the test service. info->keepalive_fd will be a pipe to the service's
	 * stdin; if it closes, the service will exit immediately. We use this to
	 * make sure the service exits if the test program crashes.
	 */
	g_spawn_async_with_pipes (NULL, (char **) args, NULL,
	                            G_SPAWN_SEARCH_PATH
	                          | G_SPAWN_DO_NOT_REAP_CHILD,
	                          NULL, NULL,
	                          &info->pid, &info->keepalive_fd, NULL, NULL, &error);
	g_assert_no_error (error);

	{
		nm_auto_unref_gsource GSource *timeout_source = NULL;
		nm_auto_unref_gsource GSource *child_source = NULL;
		GMainContext *context = g_main_context_new ();
		ServiceInitWaitData data = {
			.bus = info->bus,
			.mainloop = g_main_loop_new (context, FALSE),
		};
		gboolean had_timeout;

		timeout_source = g_timeout_source_new (50);
		g_source_set_callback (timeout_source, _service_init_wait_probe_name, &data, NULL);
		g_source_attach (timeout_source, context);

		child_source = g_child_watch_source_new (info->pid);
		g_source_set_callback (child_source, (GSourceFunc)(void (*) (void)) _service_init_wait_child_wait, &data, NULL);
		g_source_attach (child_source, context);

		had_timeout = !nmtst_main_loop_run (data.mainloop, 30000);

		g_source_destroy (timeout_source);
		g_source_destroy (child_source);
		g_main_loop_unref (data.mainloop);
		g_main_context_unref (context);

		if (had_timeout)
			g_error ("test service %s did not start in time", NMTSTC_NM_SERVICE);
		if (!data.name_found) {
			g_assert (data.exited);
			info->pid = NM_PID_T_INVAL;
			nmtstc_service_cleanup (info);

			if (   WIFEXITED (data.exit_code)
			    && WEXITSTATUS (data.exit_code) == 77) {
				/* If the stub service exited with status 77 it means that it decided
				 * that it cannot conduct the tests and the test should be (gracefully)
				 * skip. The likely reason for that, is that libnm is not available
				 * via pygobject. */
				return NULL;
			}
			g_error ("test service %s exited with error code %d", NMTSTC_NM_SERVICE, data.exit_code);
		}
	}

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

#if (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_GLIB
	info->libdbus.bus = dbus_g_bus_get (DBUS_BUS_SESSION, &error);
	g_assert_no_error (error);
	g_assert (info->libdbus.bus);
#endif
	return info;
}

void
nmtstc_service_cleanup (NMTstcServiceInfo *info)
{
	int ret;
	gint64 t;
	int status;

	if (!info)
		return;

	nm_close (nm_steal_fd (&info->keepalive_fd));

	g_clear_object (&info->proxy);

#if (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_GLIB
	g_clear_pointer (&info->libdbus.bus, dbus_g_connection_unref);
#endif

	if (info->pid != NM_PID_T_INVAL) {
		kill (info->pid, SIGTERM);

		t = g_get_monotonic_time ();
again_wait:
		ret = waitpid (info->pid, &status, WNOHANG);
		if (ret == 0) {
			if (t + 2000000 < g_get_monotonic_time ()) {
				kill (info->pid, SIGKILL);
				g_error ("child process %lld did not exit within timeout", (long long) info->pid);
			}
			g_usleep (G_USEC_PER_SEC / 50);
			goto again_wait;
		}
		if (ret == -1 && errno == EINTR)
			goto again_wait;

		g_assert (ret == info->pid);
	}

	g_assert (!name_exists (info->bus, "org.freedesktop.NetworkManager"));

	g_clear_object (&info->bus);

	memset (info, 0, sizeof (*info));
	g_free (info);
}

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_GLIB)
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

static GVariant *
call_add_wired_device (GDBusProxy *proxy, const char *ifname, const char *hwaddr,
                       const char **subchannels, GError **error)
{
	const char *empty[] = { NULL };

	if (!hwaddr)
		hwaddr = "/";
	if (!subchannels)
		subchannels = empty;

	return g_dbus_proxy_call_sync (proxy,
	                               "AddWiredDevice",
	                               g_variant_new ("(ss^as)", ifname, hwaddr, subchannels),
	                               G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                               3000,
	                               NULL,
	                               error);
}

static GVariant *
call_add_device (GDBusProxy *proxy, const char *method, const char *ifname, GError **error)
{
	return g_dbus_proxy_call_sync (proxy,
	                               method,
	                               g_variant_new ("(s)", ifname),
	                               G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                               3000,
	                               NULL,
	                               error);
}

static NMDevice *
add_device_common (NMTstcServiceInfo *sinfo, NMClient *client,
                   const char *method, const char *ifname,
                   const char *hwaddr, const char **subchannels)
{
	AddDeviceInfo info;
	GError *error = NULL;
	GVariant *ret;
	guint timeout_id;

	if (g_strcmp0 (method, "AddWiredDevice") == 0)
		ret = call_add_wired_device (sinfo->proxy, ifname, hwaddr, subchannels, &error);
	else
		ret = call_add_device (sinfo->proxy, method, ifname, &error);

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

NMDevice *
nmtstc_service_add_device (NMTstcServiceInfo *sinfo, NMClient *client,
                           const char *method, const char *ifname)
{
	return add_device_common (sinfo, client, method, ifname, NULL, NULL);
}

NMDevice *
nmtstc_service_add_wired_device (NMTstcServiceInfo *sinfo, NMClient *client,
                                 const char *ifname, const char *hwaddr,
                                 const char **subchannels)
{
	return add_device_common (sinfo, client, "AddWiredDevice", ifname, hwaddr, subchannels);
}
#endif

void
nmtstc_service_add_connection (NMTstcServiceInfo *sinfo,
                               NMConnection *connection,
                               gboolean verify_connection,
                               char **out_path)
{
#if (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_GLIB
	gs_unref_hashtable GHashTable *new_settings = NULL;
	gboolean success;
	gs_free_error GError *error = NULL;
	gs_free char *path = NULL;
	gs_unref_object DBusGProxy *proxy = NULL;

	g_assert (sinfo);
	g_assert (NM_IS_CONNECTION (connection));

	new_settings = nm_connection_to_hash (connection, NM_SETTING_HASH_FLAG_ALL);

	proxy = _libdbus_create_proxy_test (sinfo->libdbus.bus);

	success = dbus_g_proxy_call (proxy,
	                             "AddConnection",
	                             &error,
	                             DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, new_settings,
	                             G_TYPE_BOOLEAN, verify_connection,
	                             G_TYPE_INVALID,
	                             DBUS_TYPE_G_OBJECT_PATH, &path,
	                             G_TYPE_INVALID);
	g_assert_no_error (error);
	g_assert (success);

	g_assert (path && *path);

	if (out_path)
		*out_path = g_strdup (path);
#else
	nmtstc_service_add_connection_variant (sinfo,
	                                       nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL),
	                                       verify_connection,
	                                       out_path);
#endif
}

void
nmtstc_service_add_connection_variant (NMTstcServiceInfo *sinfo,
                                       GVariant *connection,
                                       gboolean verify_connection,
                                       char **out_path)
{
	GVariant *result;
	GError *error = NULL;

	g_assert (sinfo);
	g_assert (G_IS_DBUS_PROXY (sinfo->proxy));
	g_assert (g_variant_is_of_type (connection, G_VARIANT_TYPE ("a{sa{sv}}")));

	result = g_dbus_proxy_call_sync (sinfo->proxy,
	                                 "AddConnection",
	                                 g_variant_new ("(vb)", connection, verify_connection),
	                                 G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                                 3000,
	                                 NULL,
	                                 &error);
	g_assert_no_error (error);
	g_assert (g_variant_is_of_type (result, G_VARIANT_TYPE ("(o)")));
	if (out_path)
		g_variant_get (result, "(o)", out_path);
	g_variant_unref (result);
}

void
nmtstc_service_update_connection (NMTstcServiceInfo *sinfo,
                                  const char *path,
                                  NMConnection *connection,
                                  gboolean verify_connection)
{
	if (!path)
		path = nm_connection_get_path (connection);
	g_assert (path);

#if (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_GLIB
	{
		gs_unref_hashtable GHashTable *new_settings = NULL;
		gboolean success;
		gs_free_error GError *error = NULL;
		gs_unref_object DBusGProxy *proxy = NULL;

		g_assert (sinfo);
		g_assert (NM_IS_CONNECTION (connection));

		new_settings = nm_connection_to_hash (connection, NM_SETTING_HASH_FLAG_ALL);

		proxy = _libdbus_create_proxy_test (sinfo->libdbus.bus);

		success = dbus_g_proxy_call (proxy,
		                             "UpdateConnection",
		                             &error,
		                             DBUS_TYPE_G_OBJECT_PATH, path,
		                             DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, new_settings,
		                             G_TYPE_BOOLEAN, verify_connection,
		                             G_TYPE_INVALID,
		                             G_TYPE_INVALID);
		g_assert_no_error (error);
		g_assert (success);
	}
#else
	nmtstc_service_update_connection_variant (sinfo,
	                                          path,
	                                          nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL),
	                                          verify_connection);
#endif
}

void
nmtstc_service_update_connection_variant (NMTstcServiceInfo *sinfo,
                                          const char *path,
                                          GVariant *connection,
                                          gboolean verify_connection)
{
	GVariant *result;
	GError *error = NULL;

	g_assert (sinfo);
	g_assert (G_IS_DBUS_PROXY (sinfo->proxy));
	g_assert (g_variant_is_of_type (connection, G_VARIANT_TYPE ("a{sa{sv}}")));
	g_assert (path && path[0] == '/');

	result = g_dbus_proxy_call_sync (sinfo->proxy,
	                                 "UpdateConnection",
	                                 g_variant_new ("(ovb)", path, connection, verify_connection),
	                                 G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                                 3000,
	                                 NULL,
	                                 &error);
	g_assert_no_error (error);
	g_assert (g_variant_is_of_type (result, G_VARIANT_TYPE ("()")));
	g_variant_unref (result);
}

/*****************************************************************************/

#if (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_GLIB
NMClient *
nmtstc_nm_client_new (void)
{
	NMClient *client;
	DBusGConnection *bus;
	GError *error = NULL;
	gboolean success;

	bus = dbus_g_bus_get (DBUS_BUS_SESSION, &error);
	g_assert_no_error (error);
	g_assert (bus);

	client = g_object_new (NM_TYPE_CLIENT,
	                       NM_OBJECT_DBUS_CONNECTION, bus,
	                       NM_OBJECT_DBUS_PATH, NM_DBUS_PATH,
	                       NULL);
	g_assert (client != NULL);

	dbus_g_connection_unref (bus);

	success = g_initable_init (G_INITABLE (client), NULL, &error);
	g_assert_no_error (error);
	g_assert (success == TRUE);

	return client;
}

NMRemoteSettings *
nmtstc_nm_remote_settings_new (void)
{
	NMRemoteSettings *settings;
	DBusGConnection *bus;
	GError *error = NULL;

	bus = dbus_g_bus_get (DBUS_BUS_SESSION, &error);
	g_assert_no_error (error);
	g_assert (bus);

	settings = nm_remote_settings_new (bus);
	g_assert (settings);

	dbus_g_connection_unref (bus);

	return settings;
}
#endif

/*****************************************************************************/
