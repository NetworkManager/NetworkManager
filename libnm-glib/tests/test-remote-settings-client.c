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
 * Copyright 2010 - 2011 Red Hat, Inc.
 *
 */

#include "config.h"

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>

#include <NetworkManager.h>

#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-utils.h>

#include "nm-glib.h"
#include "nm-remote-settings.h"
#include "common.h"

#include "nm-test-utils.h"

static NMTestServiceInfo *sinfo;
static NMRemoteSettings *settings = NULL;
DBusGConnection *bus = NULL;
NMRemoteConnection *remote = NULL;

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
	g_object_add_weak_pointer (G_OBJECT (connection), (void **) &remote);
}

#define TEST_CON_ID "blahblahblah"

static void
test_add_connection (void)
{
	gs_unref_object NMConnection *connection = NULL;
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
	g_assert (success == TRUE);

	start = time (NULL);
	do {
		now = time (NULL);
		g_main_context_iteration (NULL, FALSE);
	} while ((done == FALSE) && (now - start < 5));
	g_assert (done == TRUE);
	g_assert (remote != NULL);

	/* Make sure the connection is the same as what we added */
	g_assert (nm_connection_compare (connection,
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
	g_assert_no_error (error);
	g_assert (success == TRUE);
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

	g_assert (remote != NULL);

	/* Listen for the remove event when the connection becomes invisible */
	g_signal_connect (remote, "removed", G_CALLBACK (invis_removed_cb), &done);

	path = g_strdup (nm_connection_get_path (NM_CONNECTION (remote)));
	proxy = dbus_g_proxy_new_for_name (bus,
	                                   NM_DBUS_SERVICE,
	                                   path,
	                                   NM_DBUS_IFACE_SETTINGS_CONNECTION);
	g_assert (proxy != NULL);

	/* Bypass the NMRemoteSettings object so we can test it independently */
	dbus_g_proxy_begin_call (proxy, "SetVisible", set_visible_cb, NULL, NULL,
	                         G_TYPE_BOOLEAN, FALSE, G_TYPE_INVALID);

	/* Wait for the connection to be removed */
	start = time (NULL);
	do {
		now = time (NULL);
		g_main_context_iteration (NULL, FALSE);
	} while ((done == FALSE) && (now - start < 5));
	g_assert (done == TRUE);

	g_assert (remote);
	g_signal_handlers_disconnect_by_func (remote, G_CALLBACK (invis_removed_cb), &done);

	/* Ensure NMRemoteSettings no longer has the connection */
	list = nm_remote_settings_list_connections (settings);
	for (iter = list; iter; iter = g_slist_next (iter)) {
		NMConnection *candidate = NM_CONNECTION (iter->data);

		g_assert ((gpointer) remote != (gpointer) candidate);
		g_assert (strcmp (path, nm_connection_get_path (candidate)) != 0);
	}

	/* And ensure the invisible connection no longer has any settings */
	g_assert (remote);
	nm_connection_for_each_setting_value (NM_CONNECTION (remote),
	                                      invis_has_settings_cb,
	                                      &has_settings);
	g_assert (has_settings == FALSE);

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

	g_assert (remote != NULL);

	/* Wait for the new-connection signal when the connection is visible again */
	g_signal_connect (settings, NM_REMOTE_SETTINGS_NEW_CONNECTION,
	                  G_CALLBACK (vis_new_connection_cb), &new);

	path = g_strdup (nm_connection_get_path (NM_CONNECTION (remote)));
	proxy = dbus_g_proxy_new_for_name (bus,
	                                   NM_DBUS_SERVICE,
	                                   path,
	                                   NM_DBUS_IFACE_SETTINGS_CONNECTION);
	g_assert (proxy != NULL);

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
	g_assert (new);
	g_assert (new == remote);

	g_signal_handlers_disconnect_by_func (settings, G_CALLBACK (vis_new_connection_cb), &new);

	/* Ensure NMRemoteSettings has the connection */
	list = nm_remote_settings_list_connections (settings);
	for (iter = list; iter; iter = g_slist_next (iter)) {
		NMConnection *candidate = NM_CONNECTION (iter->data);

		if ((gpointer) remote == (gpointer) candidate) {
			g_assert_cmpstr (path, ==, nm_connection_get_path (candidate));
			g_assert_cmpstr (TEST_CON_ID, ==, nm_connection_get_id (candidate));
			found = TRUE;
			break;
		}
	}
	g_slist_free (list);
	g_assert (found == TRUE);

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
	g_assert_no_error (error);
	g_assert (success == TRUE);
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
	g_assert_cmpint (g_slist_length (list), >, 0);

	connection = NM_REMOTE_CONNECTION (list->data);
	g_slist_free (list);
	g_assert (connection);
	g_assert (remote == connection);
	path = g_strdup (nm_connection_get_path (NM_CONNECTION (connection)));
	g_signal_connect (connection, "removed", G_CALLBACK (removed_cb), &done);

	proxy = dbus_g_proxy_new_for_name (bus,
	                                   NM_DBUS_SERVICE,
	                                   path,
	                                   NM_DBUS_IFACE_SETTINGS_CONNECTION);
	g_assert (proxy != NULL);

	/* Bypass the NMRemoteSettings object so we can test it independently */
	dbus_g_proxy_begin_call (proxy, "Delete", deleted_cb, NULL, NULL, G_TYPE_INVALID);

	start = time (NULL);
	do {
		now = time (NULL);
		g_main_context_iteration (NULL, FALSE);
	} while ((done == FALSE) && (now - start < 5));
	g_assert (done == TRUE);

	g_assert (!remote);

	/* Ensure NMRemoteSettings no longer has the connection */
	list = nm_remote_settings_list_connections (settings);
	for (iter = list; iter; iter = g_slist_next (iter)) {
		NMConnection *candidate = NM_CONNECTION (iter->data);

		g_assert ((gpointer) connection != (gpointer) candidate);
		g_assert_cmpstr (path, ==, nm_connection_get_path (candidate));
	}
	g_slist_free (list);

	g_free (path);
	g_object_unref (proxy);
}

/*******************************************************************/

static GMainLoop *loop;

static gboolean
loop_quit (gpointer user_data)
{
	g_main_loop_quit (loop);
	return G_SOURCE_REMOVE;
}

static void
settings_service_running_changed (GObject *client,
                                  GParamSpec *pspec,
                                  gpointer user_data)
{
	int *running_changed = user_data;

	(*running_changed)++;
	g_main_loop_quit (loop);
}

static void
test_service_running (void)
{
	NMRemoteSettings *settings2;
	guint quit_id;
	int running_changed = 0;
	gboolean running;

	loop = g_main_loop_new (NULL, FALSE);

	g_object_get (G_OBJECT (settings),
	              NM_REMOTE_SETTINGS_SERVICE_RUNNING, &running,
	              NULL);
	g_assert (running == TRUE);

	/* Now kill the test service. */
	nm_test_service_cleanup (sinfo);

	settings2 = nm_remote_settings_new (bus);

	/* settings2 should know that NM is running, but the previously-created
	 * settings hasn't gotten the news yet.
	 */
	g_object_get (G_OBJECT (settings2),
	              NM_REMOTE_SETTINGS_SERVICE_RUNNING, &running,
	              NULL);
	g_assert (running == FALSE);
	g_object_get (G_OBJECT (settings),
	              NM_REMOTE_SETTINGS_SERVICE_RUNNING, &running,
	              NULL);
	g_assert (running == TRUE);

	g_signal_connect (settings, "notify::" NM_REMOTE_SETTINGS_SERVICE_RUNNING,
	                  G_CALLBACK (settings_service_running_changed), &running_changed);
	quit_id = g_timeout_add_seconds (5, loop_quit, loop);
	g_main_loop_run (loop);
	g_assert_cmpint (running_changed, ==, 1);
	g_source_remove (quit_id);

	g_object_get (G_OBJECT (settings2),
	              NM_REMOTE_SETTINGS_SERVICE_RUNNING, &running,
	              NULL);
	g_assert (running == FALSE);

	/* Now restart it */
	sinfo =  nm_test_service_init ();

	quit_id = g_timeout_add_seconds (5, loop_quit, loop);
	g_main_loop_run (loop);
	g_assert_cmpint (running_changed, ==, 2);
	g_source_remove (quit_id);

	g_object_get (G_OBJECT (settings2),
	              NM_REMOTE_SETTINGS_SERVICE_RUNNING, &running,
	              NULL);
	g_assert (running == TRUE);

	g_object_unref (settings2);
}

/*******************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	int ret;
	GError *error = NULL;

	nmtst_init (&argc, &argv, TRUE);

	bus = dbus_g_bus_get (DBUS_BUS_SESSION, &error);
	g_assert_no_error (error);

	sinfo = nm_test_service_init ();

	settings = nm_remote_settings_new (bus);
	g_assert (settings != NULL);

	/* FIXME: these tests assume that they get run in order, but g_test_run()
	 * does not actually guarantee that!
	 */
	g_test_add_func ("/remote_settings/add_connection", test_add_connection);
	g_test_add_func ("/remote_settings/make_invisible", test_make_invisible);
	g_test_add_func ("/remote_settings/make_visible", test_make_visible);
	g_test_add_func ("/remote_settings/remove_connection", test_remove_connection);
	g_test_add_func ("/remote_settings/service_running", test_service_running);

	ret = g_test_run ();

	nm_test_service_cleanup (sinfo);
	g_object_unref (settings);
	dbus_g_connection_unref (bus);

	return ret;
}

