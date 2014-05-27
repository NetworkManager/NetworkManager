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
 * Copyright (C) 2010 - 2011 Red Hat, Inc.
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
DBusGConnection *bus = NULL;
NMRemoteConnection *remote = NULL;

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

static void
add_cb (NMRemoteSettings *s,
        NMRemoteConnection *connection,
        GError *error,
        gpointer user_data)
{
	if (error)
		g_warning ("Add error: %s", error->message);

	*((gboolean *) user_data) = TRUE;
	remote = connection;
}

#define TEST_CON_ID "blahblahblah"

static void
test_add_connection (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	char *uuid;
	gboolean success;
	time_t start, now;
	gboolean done = FALSE;

	connection = nm_connection_new ();

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	uuid = nm_utils_uuid_generate ();
	g_object_set (G_OBJECT (s_con),
	              NM_SETTING_CONNECTION_ID, TEST_CON_ID,
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
	                                             &done);
	test_assert (success == TRUE);

	start = time (NULL);
	do {
		now = time (NULL);
		g_main_context_iteration (NULL, FALSE);
	} while ((done == FALSE) && (now - start < 5));
	test_assert (done == TRUE);
	test_assert (remote != NULL);

	/* Make sure the connection is the same as what we added */
	test_assert (nm_connection_compare (connection,
	                                    NM_CONNECTION (remote),
	                                    NM_SETTING_COMPARE_FLAG_EXACT) == TRUE);
}

/*******************************************************************/

static void
set_visible_cb (DBusGProxy *proxy,
                DBusGProxyCall *call,
                gpointer user_data)
{
	GError *error = NULL;
	gboolean success;

	success = dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_INVALID);
	if (!success)
		g_warning ("Failed to change connection visibility: %s", error->message);
	test_assert (success == TRUE);
	test_assert (error == NULL);
}

static void
invis_removed_cb (NMRemoteConnection *connection, gboolean *done)
{
	*done = TRUE;
}

static void
invis_has_settings_cb (NMSetting *setting,
                       const char *key,
                       const GValue *value,
                       GParamFlags flags,
                       gpointer user_data)
{
	*((gboolean *) user_data) = TRUE;
}

static void
test_make_invisible (void)
{
	time_t start, now;
	GSList *list, *iter;
	DBusGProxy *proxy;
	gboolean done = FALSE, has_settings = FALSE;
	char *path;

	test_assert (remote != NULL);

	/* Listen for the remove event when the connection becomes invisible */
	g_signal_connect (remote, "removed", G_CALLBACK (invis_removed_cb), &done);

	path = g_strdup (nm_connection_get_path (NM_CONNECTION (remote)));
	proxy = dbus_g_proxy_new_for_name (bus,
	                                   NM_DBUS_SERVICE,
	                                   path,
	                                   NM_DBUS_IFACE_SETTINGS_CONNECTION);
	test_assert (proxy != NULL);

	/* Bypass the NMRemoteSettings object so we can test it independently */
	dbus_g_proxy_begin_call (proxy, "SetVisible", set_visible_cb, NULL, NULL,
	                         G_TYPE_BOOLEAN, FALSE, G_TYPE_INVALID);

	/* Wait for the connection to be removed */
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

		test_assert ((gpointer) remote != (gpointer) candidate);
		test_assert (strcmp (path, nm_connection_get_path (candidate)) != 0);
	}

	/* And ensure the invisible connection no longer has any settings */
	nm_connection_for_each_setting_value (NM_CONNECTION (remote),
	                                      invis_has_settings_cb,
	                                      &has_settings);
	test_assert (has_settings == FALSE);

	g_free (path);
	g_object_unref (proxy);
}

/*******************************************************************/

static void
vis_new_connection_cb (NMRemoteSettings *foo,
                       NMRemoteConnection *connection,
                       NMRemoteConnection **new)
{
	*new = connection;
}

static void
test_make_visible (void)
{
	time_t start, now;
	GSList *list, *iter;
	DBusGProxy *proxy;
	gboolean found = FALSE;
	char *path;
	NMRemoteConnection *new = NULL;

	test_assert (remote != NULL);

	/* Wait for the new-connection signal when the connection is visible again */
	g_signal_connect (settings, NM_REMOTE_SETTINGS_NEW_CONNECTION,
	                  G_CALLBACK (vis_new_connection_cb), &new);

	path = g_strdup (nm_connection_get_path (NM_CONNECTION (remote)));
	proxy = dbus_g_proxy_new_for_name (bus,
	                                   NM_DBUS_SERVICE,
	                                   path,
	                                   NM_DBUS_IFACE_SETTINGS_CONNECTION);
	test_assert (proxy != NULL);

	/* Bypass the NMRemoteSettings object so we can test it independently */
	dbus_g_proxy_begin_call (proxy, "SetVisible", set_visible_cb, NULL, NULL,
	                         G_TYPE_BOOLEAN, TRUE, G_TYPE_INVALID);


	/* Wait for the settings service to announce the connection again */
	start = time (NULL);
	do {
		now = time (NULL);
		g_main_context_iteration (NULL, FALSE);
	} while ((new == NULL) && (now - start < 5));

	/* Ensure the new connection is the same as the one we made visible again */
	test_assert (new == remote);

	/* Ensure NMRemoteSettings has the connection */
	list = nm_remote_settings_list_connections (settings);
	for (iter = list; iter; iter = g_slist_next (iter)) {
		NMConnection *candidate = NM_CONNECTION (iter->data);

		if ((gpointer) remote == (gpointer) candidate) {
			test_assert (strcmp (path, nm_connection_get_path (candidate)) == 0);
			test_assert (strcmp (TEST_CON_ID, nm_connection_get_id (candidate)) == 0);
			found = TRUE;
			break;
		}
	}
	test_assert (found == TRUE);

	g_free (path);
	g_object_unref (proxy);
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
removed_cb (NMRemoteConnection *connection, gboolean *done)
{
	*done = TRUE;
}

static void
test_remove_connection (void)
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

int
main (int argc, char **argv)
{
    char *service_argv[3] = { NULL, NULL, NULL };
	int ret;
	GError *error = NULL;
	int i = 100;

	g_assert (argc == 3);

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif
	
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

	g_test_add_func ("/remote_settings/add_connection", test_add_connection);
	g_test_add_func ("/remote_settings/make_invisible", test_make_invisible);
	g_test_add_func ("/remote_settings/make_visible", test_make_visible);
	g_test_add_func ("/remote_settings/remove_connection", test_remove_connection);

	ret = g_test_run ();

	cleanup ();

	return ret;
}

