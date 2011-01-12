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
 * Copyright (C) 2010 Red Hat, Inc.
 *
 */

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <glib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>

#include <NetworkManager.h>

#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-utils.h>

#include "nm-remote-settings.h"

static GPid spid = 0;
static NMRemoteSettings *settings = NULL;

/*******************************************************************/

static void
cleanup (void)
{
	if (settings)
		g_object_unref (settings);
	kill (spid, SIGTERM);
}

#define test_assert(condition) \
do { \
	if (!G_LIKELY (condition)) \
		cleanup (); \
	g_assert (condition); \
} while (0)

/*******************************************************************/

typedef struct {
	gboolean done;
	NMRemoteConnection *connection;
} AddInfo;

static void
add_cb (NMRemoteSettings *s,
        NMRemoteConnection *connection,
        GError *error,
        gpointer user_data)
{
	AddInfo *info = user_data;

	if (error)
		g_warning ("Add error: %s", error->message);

	info->done = TRUE;
	info->connection = connection;
}

static void
test_add_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	char *uuid;
	gboolean success;
	time_t start, now;
	AddInfo info = { FALSE, NULL };

	connection = nm_connection_new ();

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	uuid = nm_utils_uuid_generate ();
	g_object_set (G_OBJECT (s_con),
	              NM_SETTING_CONNECTION_ID, "blahblahblah",
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);
	g_free (uuid);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	success = nm_remote_settings_add_connection (settings,
	                                             connection,
	                                             add_cb,
	                                             &info);
	test_assert (success == TRUE);

	start = time (NULL);
	do {
		now = time (NULL);
		g_main_context_iteration (NULL, FALSE);
	} while ((info.done == FALSE) && (now - start < 5));
	test_assert (info.done == TRUE);
	test_assert (info.connection != NULL);

	/* Make sure the connection is the same as what we added */
	test_assert (nm_connection_compare (connection,
	                                    NM_CONNECTION (info.connection),
	                                    NM_SETTING_COMPARE_FLAG_EXACT) == TRUE);
}

/*******************************************************************/

static void
deleted_cb (DBusGProxy *proxy,
            DBusGProxyCall *call,
            gpointer user_data)
{
	GError *error = NULL;
	gboolean success;

	success = dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_INVALID);
	if (!success)
		g_warning ("Failed to delete connection: %s", error->message);
	test_assert (success == TRUE);
	test_assert (error == NULL);
}

static void
removed_cb (NMRemoteConnection *connection, gpointer user_data)
{
	gboolean *done = user_data;

	*done = TRUE;
}

static void
test_remove_connection (DBusGConnection *bus)
{
	NMRemoteConnection *connection;
	time_t start, now;
	GSList *list, *iter;
	DBusGProxy *proxy;
	gboolean done = FALSE;
	char *path;

	/* Find a connection to delete */
	list = nm_remote_settings_list_connections (settings);
	test_assert (g_slist_length (list) > 0);

	connection = NM_REMOTE_CONNECTION (list->data);
	path = g_strdup (nm_connection_get_path (NM_CONNECTION (connection)));
	g_signal_connect (connection, "removed", G_CALLBACK (removed_cb), &done);

	proxy = dbus_g_proxy_new_for_name (bus,
	                                   NM_DBUS_SERVICE,
	                                   path,
	                                   NM_DBUS_IFACE_SETTINGS_CONNECTION);
	test_assert (proxy != NULL);

	/* Bypass the NMRemoteSettings object so we can test it independently */
	dbus_g_proxy_begin_call (proxy, "Delete", deleted_cb, NULL, NULL, G_TYPE_INVALID);

	start = time (NULL);
	do {
		now = time (NULL);
		g_main_context_iteration (NULL, FALSE);
	} while ((done == FALSE) && (now - start < 5));
	test_assert (done == TRUE);

	/* Ensure NMRemoteSettings no longer has the connection */
	list = nm_remote_settings_list_connections (settings);
	for (iter = list; iter; iter = g_slist_next (iter)) {
		NMConnection *candidate = NM_CONNECTION (iter->data);

		test_assert ((gpointer) connection != (gpointer) candidate);
		test_assert (strcmp (path, nm_connection_get_path (candidate)) != 0);
	}

	g_free (path);
	g_object_unref (proxy);
}

/*******************************************************************/

#if GLIB_CHECK_VERSION(2,25,12)
typedef GTestFixtureFunc TCFunc;
#else
typedef void (*TCFunc)(void);
#endif

#define TESTCASE(t, d) g_test_create_case (#t, 0, d, NULL, (TCFunc) t, NULL)

int main (int argc, char **argv)
{
	GTestSuite *suite;
    char *service_argv[3] = { NULL, NULL, NULL };
	int ret;
	GError *error = NULL;
	DBusGConnection *bus;
	int i = 100;

	g_assert (argc == 3);

	g_type_init ();
	
	g_test_init (&argc, &argv, NULL);

	bus = dbus_g_bus_get (DBUS_BUS_SESSION, &error);
	if (!bus) {
		g_warning ("Error connecting to D-Bus: %s", error->message);
		g_assert (error == NULL);
	}

	service_argv[0] = g_strdup_printf ("%s/%s", argv[1], argv[2]);
	if (!g_spawn_async (argv[1], service_argv, NULL, 0, NULL, NULL, &spid, &error)) {
		g_warning ("Error spawning %s: %s", argv[2], error->message);
		g_assert (error == NULL);
	}

	/* Wait until the service is registered on the bus */
	while (i > 0) {
		g_usleep (G_USEC_PER_SEC / 50);
		if (dbus_bus_name_has_owner (dbus_g_connection_get_connection (bus),
		                             "org.freedesktop.NetworkManager",
		                             NULL))
			break;
		i--;
	}
	test_assert (i > 0);

	settings = nm_remote_settings_new (bus);
	test_assert (settings != NULL);

	suite = g_test_get_root ();

	g_test_suite_add (suite, TESTCASE (test_add_connection, NULL));
	g_test_suite_add (suite, TESTCASE (test_remove_connection, bus));

	ret = g_test_run ();

	cleanup ();

	return ret;
}

