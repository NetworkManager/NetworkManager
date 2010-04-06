/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2005 - 2008 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#include <glib.h>
#include <string.h>
#include <dbus/dbus.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#include "nm-vpn-service.h"
#include "nm-dbus-manager.h"
#include "nm-logging.h"
#include "nm-vpn-manager.h"
#include "nm-glib-compat.h"

G_DEFINE_TYPE (NMVPNService, nm_vpn_service, G_TYPE_OBJECT)

typedef struct {
	NMDBusManager *dbus_mgr;
	char *name;
	char *dbus_service;
	char *program;

	GPid pid;
	GSList *connections;
	guint service_start_timeout;
	guint service_child_watch;
	gulong name_owner_id;
} NMVPNServicePrivate;

#define NM_VPN_SERVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_SERVICE, NMVPNServicePrivate))

#define VPN_CONNECTION_GROUP "VPN Connection"

static GKeyFile *
find_service_file (const char *name)
{
	GDir *dir;
	const char *fn;
	GKeyFile *key_file = NULL;

	dir = g_dir_open (VPN_NAME_FILES_DIR, 0, NULL);
	if (!dir)
		return NULL;

	while ((fn = g_dir_read_name (dir))) {
		char *path;
		gboolean found = FALSE;

		/* only parse filenames that end with .name */
		if (!g_str_has_suffix (fn, ".name"))
			continue;

		key_file = g_key_file_new ();
		path = g_build_filename (VPN_NAME_FILES_DIR, fn, NULL);

		if (g_key_file_load_from_file (key_file, path, G_KEY_FILE_NONE, NULL)) {
			gchar *val;

			val = g_key_file_get_string (key_file, VPN_CONNECTION_GROUP, "service", NULL);
			if (val) {
				if (!strcmp (val, name))
					found = TRUE;
				g_free (val);
			}
		}

		g_free (path);

		if (found)
			break;

		g_key_file_free (key_file);
		key_file = NULL;
	}

	g_dir_close (dir);

	return key_file;
}

NMVPNService *
nm_vpn_service_new (const char *name)
{
	GKeyFile *key_file;
	NMVPNService *service = NULL;
	NMVPNServicePrivate *priv;
	char *dbus_service = NULL;
	char *program = NULL;
	gboolean success = FALSE;

	g_return_val_if_fail (name != NULL, NULL);

	key_file = find_service_file (name);
	if (!key_file)
		return NULL;

	dbus_service = g_key_file_get_string (key_file, VPN_CONNECTION_GROUP, "service", NULL);
	if (!dbus_service)
		goto out;

	program = g_key_file_get_string (key_file, VPN_CONNECTION_GROUP, "program", NULL);
	if (!program)
		goto out;

	service = (NMVPNService *) g_object_new (NM_TYPE_VPN_SERVICE, NULL);
	if (!service)
		goto out;

	priv = NM_VPN_SERVICE_GET_PRIVATE (service);

	priv->name = g_strdup (name);
	priv->dbus_service = dbus_service;
	priv->program = program;

	success = TRUE;

 out:
	g_key_file_free (key_file);

	if (!success) {
		g_free (dbus_service);
		g_free (program);
	}

	return service;
}

const char *
nm_vpn_service_get_name (NMVPNService *service)
{
	g_return_val_if_fail (NM_IS_VPN_SERVICE (service), NULL);

	return NM_VPN_SERVICE_GET_PRIVATE (service)->name;
}

static void
nm_vpn_service_connections_stop (NMVPNService *service,
                                 gboolean fail,
                                 NMVPNConnectionStateReason reason)
{
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (service);
	GSList *iter, *copy;

	/* Copy because stopping the connection may remove it from the list
	 * in the the NMVPNService objects' VPN connection state handler.
	 */
	copy = g_slist_copy (priv->connections);
	for (iter = copy; iter; iter = iter->next) {
		if (fail)
			nm_vpn_connection_fail (NM_VPN_CONNECTION (iter->data), reason);
		else
			nm_vpn_connection_disconnect (NM_VPN_CONNECTION (iter->data), reason);
	}
	g_slist_free (copy);
}

/*
 * nm_vpn_service_child_setup
 *
 * Set the process group ID of the newly forked process
 *
 */
static void
nm_vpn_service_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	/* We are in the child process at this point */
	pid_t pid = getpid ();
	setpgid (pid, pid);
}

static void
vpn_service_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMVPNService *service = NM_VPN_SERVICE (user_data);
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (service);

	if (WIFEXITED (status)) {
		guint err = WEXITSTATUS (status);

		if (err != 0) {
			nm_log_warn (LOGD_VPN, "VPN service '%s' exited with error: %d",
			             nm_vpn_service_get_name (service), WSTOPSIG (status));
		}
	} else if (WIFSTOPPED (status)) {
		nm_log_warn (LOGD_VPN, "VPN service '%s' stopped unexpectedly with signal %d",
		             nm_vpn_service_get_name (service), WSTOPSIG (status));
	} else if (WIFSIGNALED (status)) {
		nm_log_warn (LOGD_VPN, "VPN service '%s' died with signal %d",
		             nm_vpn_service_get_name (service), WTERMSIG (status));
	} else {
		nm_log_warn (LOGD_VPN, "VPN service '%s' died from an unknown cause", 
		             nm_vpn_service_get_name (service));
	}

	priv->pid = 0;
	priv->service_child_watch = 0;

	nm_vpn_service_connections_stop (service, TRUE, NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED);
}

static gboolean
nm_vpn_service_timeout (gpointer data)
{
	NMVPNService *service = NM_VPN_SERVICE (data);

	nm_log_warn (LOGD_VPN, "VPN service '%s' did not start in time, cancelling connections",
	             nm_vpn_service_get_name (service));

	NM_VPN_SERVICE_GET_PRIVATE (service)->service_start_timeout = 0;
	nm_vpn_service_connections_stop (service, TRUE, NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT);

	return FALSE;
}

static gboolean
nm_vpn_service_daemon_exec (NMVPNService *service, GError **error)
{
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (service);
	char *vpn_argv[2];
	gboolean success = FALSE;
	GError *spawn_error = NULL;

	g_return_val_if_fail (NM_IS_VPN_SERVICE (service), FALSE);
	g_return_val_if_fail (error != NULL, FALSE);
	g_return_val_if_fail (*error == NULL, FALSE);

	vpn_argv[0] = priv->program;
	vpn_argv[1] = NULL;

	success = g_spawn_async (NULL, vpn_argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
	                         nm_vpn_service_child_setup, NULL, &priv->pid,
	                         &spawn_error);
	if (success) {
		nm_log_info (LOGD_VPN, "VPN service '%s' started (%s), PID %d", 
		             nm_vpn_service_get_name (service), priv->dbus_service, priv->pid);

		priv->service_child_watch = g_child_watch_add (priv->pid, vpn_service_watch_cb, service);
		priv->service_start_timeout = g_timeout_add_seconds (5, nm_vpn_service_timeout, service);
	} else {
		nm_log_warn (LOGD_VPN, "VPN service '%s': could not launch the VPN service. error: (%d) %s.",
		             nm_vpn_service_get_name (service), spawn_error->code, spawn_error->message);

		g_set_error (error,
		             NM_VPN_MANAGER_ERROR, NM_VPN_MANAGER_ERROR_SERVICE_START_FAILED,
		             "%s", spawn_error ? spawn_error->message : "unknown g_spawn_async() error");

		nm_vpn_service_connections_stop (service, TRUE, NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED);
		if (spawn_error)
			g_error_free (spawn_error);
	}

	return success;
}

static gboolean
destroy_service (gpointer data)
{
	g_object_unref (data);

	return FALSE;
}

static void
connection_vpn_state_changed (NMVPNConnection *connection,
                              NMVPNConnectionState state,
                              NMVPNConnectionStateReason reason,
                              gpointer user_data)
{
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (user_data);

	switch (state) {
	case NM_VPN_CONNECTION_STATE_FAILED:
	case NM_VPN_CONNECTION_STATE_DISCONNECTED:
		/* Remove the connection from our list */
		priv->connections = g_slist_remove (priv->connections, connection);
		g_object_unref (connection);

		if (priv->connections == NULL) {
			/* schedule a timeout (10 seconds) to destroy the service */
			g_timeout_add_seconds (10, destroy_service, user_data);
		}
		break;
	default:
		break;
	}
}

NMVPNConnection *
nm_vpn_service_activate (NMVPNService *service,
                         NMConnection *connection,
                         NMActRequest *act_request,
                         NMDevice *device,
                         GError **error)
{
	NMVPNConnection *vpn;
	NMVPNServicePrivate *priv;

	g_return_val_if_fail (NM_IS_VPN_SERVICE (service), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (act_request), NULL);
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);
	g_return_val_if_fail (error != NULL, NULL);
	g_return_val_if_fail (*error == NULL, NULL);

	priv = NM_VPN_SERVICE_GET_PRIVATE (service);

	vpn = nm_vpn_connection_new (connection, act_request, device);
	g_signal_connect (vpn, "vpn-state-changed",
				   G_CALLBACK (connection_vpn_state_changed),
				   service);

	priv->connections = g_slist_prepend (priv->connections, vpn);

	if (nm_dbus_manager_name_has_owner (priv->dbus_mgr, priv->dbus_service)) {
		// FIXME: fill in error when errors happen
		nm_vpn_connection_activate (vpn);
	} else if (priv->service_start_timeout == 0) {
		nm_log_info (LOGD_VPN, "Starting VPN service '%s'...",
		             nm_vpn_service_get_name (service));
		if (!nm_vpn_service_daemon_exec (service, error))
			vpn = NULL;
	}

	return vpn;
}

GSList *
nm_vpn_service_get_active_connections (NMVPNService *service)
{
	g_return_val_if_fail (NM_IS_VPN_SERVICE (service), NULL);

	return g_slist_copy (NM_VPN_SERVICE_GET_PRIVATE (service)->connections);
}

static void
nm_vpn_service_name_owner_changed (NMDBusManager *mgr,
							const char *name,
							const char *old,
							const char *new,
							gpointer user_data)
{
	NMVPNService *service = NM_VPN_SERVICE (user_data);
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (service);
	gboolean old_owner_good;
	gboolean new_owner_good;

	if (strcmp (name, priv->dbus_service))
		return;

	/* Service changed, no need to wait for the timeout any longer */
	if (priv->service_start_timeout) {
		g_source_remove (priv->service_start_timeout);
		priv->service_start_timeout = 0;
	}

	old_owner_good = (old && (strlen (old) > 0));
	new_owner_good = (new && (strlen (new) > 0));

	if (!old_owner_good && new_owner_good) {
		/* service just appeared */
		GSList *iter;

		nm_log_info (LOGD_VPN, "VPN service '%s' appeared, activating connections",
		             nm_vpn_service_get_name (service));

		for (iter = priv->connections; iter; iter = iter->next)
			nm_vpn_connection_activate (NM_VPN_CONNECTION (iter->data));

	} else if (old_owner_good && !new_owner_good) {
		/* service went away */
		nm_log_info (LOGD_VPN, "VPN service '%s' disappeared, cancelling connections",
		             nm_vpn_service_get_name (service));
		nm_vpn_service_connections_stop (service, TRUE, NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED);
	}
}

/******************************************************************************/

static void
nm_vpn_service_init (NMVPNService *service)
{
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (service);

	priv->dbus_mgr = nm_dbus_manager_get ();
	
	priv->name_owner_id = g_signal_connect (priv->dbus_mgr, "name-owner-changed",
									G_CALLBACK (nm_vpn_service_name_owner_changed),
									service);
}

static gboolean
ensure_killed (gpointer data)
{
	int pid = GPOINTER_TO_INT (data);

	if (kill (pid, 0) == 0)
		kill (pid, SIGKILL);

	/* ensure the child is reaped */
	nm_log_dbg (LOGD_VPN, "waiting for VPN service pid %d to exit", pid);
	waitpid (pid, NULL, 0);
	nm_log_dbg (LOGD_VPN, "VPN service pid %d cleaned up", pid);

	return FALSE;
}

static void
finalize (GObject *object)
{
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (object);

	if (priv->service_start_timeout)
		g_source_remove (priv->service_start_timeout);

	nm_vpn_service_connections_stop (NM_VPN_SERVICE (object),
	                                 FALSE,
	                                 NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED);

	g_signal_handler_disconnect (priv->dbus_mgr, priv->name_owner_id);

	if (priv->service_child_watch)
		g_source_remove (priv->service_child_watch);

	if (priv->pid) {
		if (kill (priv->pid, SIGTERM) == 0)
			g_timeout_add_seconds (2, ensure_killed, GINT_TO_POINTER (priv->pid));
		else {
			kill (priv->pid, SIGKILL);

			/* ensure the child is reaped */
			nm_log_dbg (LOGD_VPN, "waiting for VPN service pid %d to exit", priv->pid);
			waitpid (priv->pid, NULL, 0);
			nm_log_dbg (LOGD_VPN, "VPN service pid %d cleaned up", priv->pid);
		}

		priv->pid = 0;
	}

	g_object_unref (priv->dbus_mgr);

	g_free (priv->name);
	g_free (priv->dbus_service);
	g_free (priv->program);

	G_OBJECT_CLASS (nm_vpn_service_parent_class)->finalize (object);
}

static void
nm_vpn_service_class_init (NMVPNServiceClass *service_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (service_class);

	g_type_class_add_private (service_class, sizeof (NMVPNServicePrivate));

	/* virtual methods */
	object_class->finalize = finalize;
}
