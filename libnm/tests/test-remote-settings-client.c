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

#include "nm-default.h"

#include <sys/types.h>
#include <signal.h>

#include "nm-test-libnm-utils.h"

static NMTstcServiceInfo *sinfo;
static NMClient *client = NULL;
GDBusConnection *bus = NULL;
NMRemoteConnection *remote = NULL;

/*****************************************************************************/

static void
add_cb (GObject *s,
        GAsyncResult *result,
        gpointer user_data)
{
	gboolean *done = user_data;
	GError *error = NULL;

	remote = nm_client_add_connection_finish (client, result, &error);
	g_assert_no_error (error);

	*done = TRUE;
	g_object_add_weak_pointer (G_OBJECT (remote), (void **) &remote);

	/* nm_client_add_connection_finish() adds a ref to @remote, but we
	 * want the weak pointer to be cleared as soon as @client drops its own ref.
	 * So drop ours.
	 */
	g_object_unref (remote);
}

#define TEST_CON_ID "blahblahblah"

static void
test_add_connection (void)
{
	NMConnection *connection;
	time_t start, now;
	gboolean done = FALSE;

	if (!nmtstc_service_available (sinfo))
		return;

	connection = nmtst_create_minimal_connection (TEST_CON_ID, NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);

	nm_client_add_connection_async (client,
	                                connection,
	                                TRUE,
	                                NULL,
	                                add_cb,
	                                &done);

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
	g_object_unref (connection);
}

/*****************************************************************************/

static void
set_visible_cb (GObject *proxy,
                GAsyncResult *result,
                gpointer user_data)
{
	GError *error = NULL;
	GVariant *ret;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &error);
	g_assert_no_error (error);
	g_variant_unref (ret);
}

static void
visible_changed_cb (GObject *object, GParamSpec *pspec, gboolean *done)
{
	if (!nm_remote_connection_get_visible (NM_REMOTE_CONNECTION (object)))
		*done = TRUE;
}

static void
connection_removed_cb (NMClient *s, NMRemoteConnection *connection, gboolean *done)
{
	if (connection == remote)
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
	const GPtrArray *conns;
	int i;
	GDBusProxy *proxy;
	gboolean visible_changed = FALSE, connection_removed = FALSE;
	gboolean has_settings = FALSE;
	char *path;

	if (!nmtstc_service_available (sinfo))
		return;

	g_assert (remote != NULL);

	/* Listen for the remove event when the connection becomes invisible */
	g_signal_connect (remote, "notify::" NM_REMOTE_CONNECTION_VISIBLE, G_CALLBACK (visible_changed_cb), &visible_changed);
	g_signal_connect (client, "connection-removed", G_CALLBACK (connection_removed_cb), &connection_removed);

	path = g_strdup (nm_connection_get_path (NM_CONNECTION (remote)));
	proxy = g_dbus_proxy_new_sync (bus,
	                               G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                               NULL,
	                               NM_DBUS_SERVICE,
	                               path,
	                               NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                               NULL,
	                               NULL);
	g_assert (proxy != NULL);

	/* Bypass the NMClient object so we can test it independently */
	g_dbus_proxy_call (proxy,
	                   "SetVisible",
	                   g_variant_new ("(b)", FALSE),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   NULL,
	                   set_visible_cb, NULL);

	/* Wait for the connection to be removed */
	start = time (NULL);
	do {
		now = time (NULL);
		g_main_context_iteration (NULL, FALSE);
	} while ((!visible_changed || !connection_removed) && (now - start < 5));
	g_assert (visible_changed == TRUE);
	g_assert (connection_removed == TRUE);

	g_signal_handlers_disconnect_by_func (remote, G_CALLBACK (visible_changed_cb), &visible_changed);
	g_signal_handlers_disconnect_by_func (client, G_CALLBACK (connection_removed_cb), &connection_removed);

	/* Ensure NMClient no longer has the connection */
	conns = nm_client_get_connections (client);
	for (i = 0; i < conns->len; i++) {
		NMConnection *candidate = NM_CONNECTION (conns->pdata[i]);

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

/*****************************************************************************/

static void
vis_new_connection_cb (NMClient *foo,
                       NMRemoteConnection *connection,
                       NMRemoteConnection **new)
{
	*new = connection;
}

static void
test_make_visible (void)
{
	time_t start, now;
	const GPtrArray *conns;
	int i;
	GDBusProxy *proxy;
	gboolean found = FALSE;
	char *path;
	NMRemoteConnection *new = NULL;

	if (!nmtstc_service_available (sinfo))
		return;

	g_assert (remote != NULL);

	/* Wait for the new-connection signal when the connection is visible again */
	g_signal_connect (client, NM_CLIENT_CONNECTION_ADDED,
	                  G_CALLBACK (vis_new_connection_cb), &new);

	path = g_strdup (nm_connection_get_path (NM_CONNECTION (remote)));
	proxy = g_dbus_proxy_new_sync (bus,
	                               G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                               NULL,
	                               NM_DBUS_SERVICE,
	                               path,
	                               NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                               NULL,
	                               NULL);
	g_assert (proxy != NULL);

	/* Bypass the NMClient object so we can test it independently */
	g_dbus_proxy_call (proxy,
	                   "SetVisible",
	                   g_variant_new ("(b)", TRUE),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   NULL,
	                   set_visible_cb, NULL);

	/* Wait for the settings service to announce the connection again */
	start = time (NULL);
	do {
		now = time (NULL);
		g_main_context_iteration (NULL, FALSE);
	} while ((new == NULL) && (now - start < 5));

	/* Ensure the new connection is the same as the one we made visible again */
	g_assert (new);
	g_assert (new == remote);

	g_signal_handlers_disconnect_by_func (client, G_CALLBACK (vis_new_connection_cb), &new);

	/* Ensure NMClient has the connection */
	conns = nm_client_get_connections (client);
	for (i = 0; i < conns->len; i++) {
		NMConnection *candidate = NM_CONNECTION (conns->pdata[i]);

		if ((gpointer) remote == (gpointer) candidate) {
			g_assert_cmpstr (path, ==, nm_connection_get_path (candidate));
			g_assert_cmpstr (TEST_CON_ID, ==, nm_connection_get_id (candidate));
			found = TRUE;
			break;
		}
	}
	g_assert (found == TRUE);

	g_free (path);
	g_object_unref (proxy);
}

/*****************************************************************************/

static void
deleted_cb (GObject *proxy,
            GAsyncResult *result,
            gpointer user_data)
{
	GError *error = NULL;
	GVariant *ret;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &error);
	g_assert_no_error (error);
	g_variant_unref (ret);
}

static void
removed_cb (NMClient *s, NMRemoteConnection *connection, gboolean *done)
{
	if (connection == remote)
		*done = TRUE;
}

static void
test_remove_connection (void)
{
	NMRemoteConnection *connection;
	time_t start, now;
	const GPtrArray *conns;
	int i;
	GDBusProxy *proxy;
	gboolean done = FALSE;
	char *path;

	if (!nmtstc_service_available (sinfo))
		return;

	/* Find a connection to delete */
	conns = nm_client_get_connections (client);
	g_assert_cmpint (conns->len, >, 0);

	connection = NM_REMOTE_CONNECTION (conns->pdata[0]);
	g_assert (connection);
	g_assert (remote == connection);
	path = g_strdup (nm_connection_get_path (NM_CONNECTION (connection)));
	g_signal_connect (client, "connection-removed", G_CALLBACK (removed_cb), &done);

	proxy = g_dbus_proxy_new_sync (bus,
	                               G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                               NULL,
	                               NM_DBUS_SERVICE,
	                               path,
	                               NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                               NULL,
	                               NULL);
	g_assert (proxy != NULL);

	/* Bypass the NMClient object so we can test it independently */
	g_dbus_proxy_call (proxy,
	                   "Delete",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   NULL,
	                   deleted_cb, NULL);

	start = time (NULL);
	do {
		now = time (NULL);
		g_main_context_iteration (NULL, FALSE);
		if (done && !remote)
			break;
	} while (now - start < 5);
	g_assert (done == TRUE);
	g_assert (!remote);

	/* Ensure NMClient no longer has the connection */
	conns = nm_client_get_connections (client);
	for (i = 0; i < conns->len; i++) {
		NMConnection *candidate = NM_CONNECTION (conns->pdata[i]);

		g_assert ((gpointer) connection != (gpointer) candidate);
		g_assert_cmpstr (path, ==, nm_connection_get_path (candidate));
	}

	g_free (path);
	g_object_unref (proxy);
}

/*****************************************************************************/

#define TEST_ADD_REMOVE_ID "add-remove-test-connection"

static void
add_remove_cb (GObject *s,
               GAsyncResult *result,
               gpointer user_data)
{
	NMRemoteConnection *connection;
	gboolean *done = user_data;
	gs_free_error GError *error = NULL;

	connection = nm_client_add_connection_finish (client, result, &error);
	g_assert_error (error, NM_CLIENT_ERROR, NM_CLIENT_ERROR_OBJECT_CREATION_FAILED);
	g_assert (connection == NULL);

	*done = TRUE;
}

static void
test_add_remove_connection (void)
{
	GVariant *ret;
	GError *error = NULL;
	NMConnection *connection;
	time_t start, now;
	gboolean done = FALSE;

	if (!nmtstc_service_available (sinfo))
		return;

	/* This will cause the test server to immediately delete the connection
	 * after creating it.
	 */
	ret = g_dbus_proxy_call_sync (sinfo->proxy,
	                              "AutoRemoveNextConnection",
	                              NULL,
	                              G_DBUS_CALL_FLAGS_NONE, -1,
	                              NULL,
	                              &error);
	g_assert_no_error (error);
	g_variant_unref (ret);

	connection = nmtst_create_minimal_connection (TEST_ADD_REMOVE_ID, NULL, NM_SETTING_WIRED_SETTING_NAME, NULL);
	nm_client_add_connection_async (client,
	                                connection,
	                                TRUE,
	                                NULL,
	                                add_remove_cb,
	                                &done);

	start = time (NULL);
	do {
		now = time (NULL);
		g_main_context_iteration (NULL, FALSE);
	} while ((done == FALSE) && (now - start < 5));
	g_assert (done == TRUE);

	g_object_unref (connection);
}

/*****************************************************************************/

static void
add_bad_cb (GObject *s,
            GAsyncResult *result,
            gpointer user_data)
{
	gboolean *done = user_data;
	gs_free_error GError *error = NULL;

	remote = nm_client_add_connection_finish (client, result, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);

	*done = TRUE;
}

static void
test_add_bad_connection (void)
{
	NMConnection *connection;
	time_t start, now;
	gboolean done = FALSE;

	if (!nmtstc_service_available (sinfo))
		return;

	/* The test daemon doesn't support bond connections */
	connection = nmtst_create_minimal_connection ("bad connection test", NULL, NM_SETTING_BOND_SETTING_NAME, NULL);

	nm_client_add_connection_async (client,
	                                connection,
	                                TRUE,
	                                NULL,
	                                add_bad_cb,
	                                &done);
	g_object_unref (connection);

	start = time (NULL);
	do {
		now = time (NULL);
		g_main_context_iteration (NULL, FALSE);
	} while ((done == FALSE) && (now - start < 5));
	g_assert (done == TRUE);
	g_assert (remote == NULL);
}

/*****************************************************************************/

static void
save_hostname_cb (GObject *s,
                  GAsyncResult *result,
                  gpointer user_data)
{
	gboolean *done = user_data;
	gs_free_error GError *error = NULL;

	nm_client_save_hostname_finish (client, result, &error);
	g_assert_no_error (error);

	*done = TRUE;
}

static void
test_save_hostname (void)
{
	time_t start, now;
	gboolean done = FALSE;
	GError *error = NULL;

	if (!nmtstc_service_available (sinfo))
		return;

	/* test-networkmanager-service.py requires the hostname to contain a '.' */
	nm_client_save_hostname (client, "foo", NULL, &error);
	g_assert_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_HOSTNAME);
	g_clear_error (&error);

	nm_client_save_hostname_async (client, "example.com", NULL, save_hostname_cb, &done);

	start = time (NULL);
	do {
		now = time (NULL);
		g_main_context_iteration (NULL, FALSE);
	} while ((done == FALSE) && (now - start < 5));
	g_assert (done == TRUE);
	g_assert (remote == NULL);
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	int ret;
	GError *error = NULL;

	g_setenv ("LIBNM_USE_SESSION_BUS", "1", TRUE);

	nmtst_init (&argc, &argv, TRUE);

	bus = g_bus_get_sync (G_BUS_TYPE_SESSION, NULL, &error);
	g_assert_no_error (error);

	sinfo = nmtstc_service_init ();

	client = nm_client_new (NULL, &error);
	g_assert_no_error (error);
	g_assert (client != NULL);

	/* FIXME: these tests assume that they get run in order, but g_test_run()
	 * does not actually guarantee that!
	 */
	g_test_add_func ("/client/add_connection", test_add_connection);
	g_test_add_func ("/client/make_invisible", test_make_invisible);
	g_test_add_func ("/client/make_visible", test_make_visible);
	g_test_add_func ("/client/remove_connection", test_remove_connection);
	g_test_add_func ("/client/add_remove_connection", test_add_remove_connection);
	g_test_add_func ("/client/add_bad_connection", test_add_bad_connection);
	g_test_add_func ("/client/save_hostname", test_save_hostname);

	ret = g_test_run ();

	nmtstc_service_cleanup (sinfo);
	g_object_unref (client);
	g_object_unref (bus);

	return ret;
}

