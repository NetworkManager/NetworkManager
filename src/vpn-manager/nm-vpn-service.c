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
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#include <config.h>
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
	gboolean disposed;

	NMDBusManager *dbus_mgr;
	char *name;
	char *dbus_service;
	char *program;
	char *namefile;

	GPid pid;
	GSList *connections;
	guint start_timeout;
	guint quit_timeout;
	guint child_watch;
	gulong name_owner_id;
} NMVPNServicePrivate;

#define NM_VPN_SERVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_SERVICE, NMVPNServicePrivate))

NMVPNService *
nm_vpn_service_new (const char *namefile, GError **error)
{
	NMVPNService *self = NULL;
	GKeyFile *kf;
	char *dbus_service = NULL, *program = NULL, *name = NULL;

	g_return_val_if_fail (namefile != NULL, NULL);
	g_return_val_if_fail (g_path_is_absolute (namefile), NULL);

	kf = g_key_file_new ();
	if (!g_key_file_load_from_file (kf, namefile, G_KEY_FILE_NONE, error)) {
		g_key_file_free (kf);
		return NULL;
	}

	dbus_service = g_key_file_get_string (kf, VPN_CONNECTION_GROUP, "service", NULL);
	if (!dbus_service) {
		g_set_error (error, 0, 0, "VPN service file %s had no 'service' key", namefile);
		goto out;
	}

	program = g_key_file_get_string (kf, VPN_CONNECTION_GROUP, "program", NULL);
	if (!program) {
		g_set_error (error, 0, 0, "VPN service file %s had no 'program' key", namefile);
		goto out;
	}

	name = g_key_file_get_string (kf, VPN_CONNECTION_GROUP, "name", NULL);
	if (!name) {
		g_set_error (error, 0, 0, "VPN service file %s had no 'name' key", namefile);
		goto out;
	}

	self = (NMVPNService *) g_object_new (NM_TYPE_VPN_SERVICE, NULL);
	if (!self) {
		g_set_error (error, 0, 0, "out of memory creating VPN service object");
		goto out;
	}

	NM_VPN_SERVICE_GET_PRIVATE (self)->name = g_strdup (name);
	NM_VPN_SERVICE_GET_PRIVATE (self)->dbus_service = g_strdup (dbus_service);
	NM_VPN_SERVICE_GET_PRIVATE (self)->program = g_strdup (program);
	NM_VPN_SERVICE_GET_PRIVATE (self)->namefile = g_strdup (namefile);

 out:
	g_key_file_free (kf);
	g_free (dbus_service);
	g_free (program);
	g_free (name);
	return self;
}

const char *
nm_vpn_service_get_dbus_service (NMVPNService *service)
{
	g_return_val_if_fail (NM_IS_VPN_SERVICE (service), NULL);

	return NM_VPN_SERVICE_GET_PRIVATE (service)->dbus_service;
}

const char *
nm_vpn_service_get_name_file (NMVPNService *service)
{
	g_return_val_if_fail (NM_IS_VPN_SERVICE (service), NULL);

	return NM_VPN_SERVICE_GET_PRIVATE (service)->namefile;
}

void
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

static void
clear_quit_timeout (NMVPNService *self)
{
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (self);

	if (priv->quit_timeout) {
		g_source_remove (priv->quit_timeout);
		priv->quit_timeout = 0;
	}
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
			             priv->name, WSTOPSIG (status));
		}
	} else if (WIFSTOPPED (status)) {
		nm_log_warn (LOGD_VPN, "VPN service '%s' stopped unexpectedly with signal %d",
		             priv->name, WSTOPSIG (status));
	} else if (WIFSIGNALED (status)) {
		nm_log_warn (LOGD_VPN, "VPN service '%s' died with signal %d",
		             priv->name, WTERMSIG (status));
	} else {
		nm_log_warn (LOGD_VPN, "VPN service '%s' died from an unknown cause", 
		             priv->name);
	}

	priv->pid = 0;
	priv->child_watch = 0;
	clear_quit_timeout (service);

	nm_vpn_service_connections_stop (service, TRUE, NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED);
}

static gboolean
nm_vpn_service_timeout (gpointer data)
{
	NMVPNService *self = NM_VPN_SERVICE (data);
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (self);

	nm_log_warn (LOGD_VPN, "VPN service '%s' start timed out", priv->name);
	priv->start_timeout = 0;
	nm_vpn_service_connections_stop (self, TRUE, NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT);
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
		             priv->name, priv->dbus_service, priv->pid);

		priv->child_watch = g_child_watch_add (priv->pid, vpn_service_watch_cb, service);
		priv->start_timeout = g_timeout_add_seconds (5, nm_vpn_service_timeout, service);
	} else {
		nm_log_warn (LOGD_VPN, "VPN service '%s': could not launch the VPN service. error: (%d) %s.",
		             priv->name,
		             spawn_error ? spawn_error->code : -1,
		             spawn_error && spawn_error->message ? spawn_error->message : "(unknown)");

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

static gboolean
service_quit (gpointer user_data)
{
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (user_data);

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
	priv->quit_timeout = 0;

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
			/* Tell the service to quit in a few seconds */
			if (!priv->quit_timeout)
				priv->quit_timeout = g_timeout_add_seconds (5, service_quit, user_data);
		}
		break;
	default:
		break;
	}
}

NMVPNConnection *
nm_vpn_service_activate (NMVPNService *service,
                         NMConnection *connection,
                         NMDevice *device,
                         gboolean user_requested,
                         gulong user_uid,
                         GError **error)
{
	NMVPNConnection *vpn;
	NMVPNServicePrivate *priv;

	g_return_val_if_fail (NM_IS_VPN_SERVICE (service), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);
	g_return_val_if_fail (error != NULL, NULL);
	g_return_val_if_fail (*error == NULL, NULL);

	priv = NM_VPN_SERVICE_GET_PRIVATE (service);

	clear_quit_timeout (service);

	vpn = nm_vpn_connection_new (connection, device, user_requested, user_uid);
	g_signal_connect (vpn, "vpn-state-changed",
				   G_CALLBACK (connection_vpn_state_changed),
				   service);

	priv->connections = g_slist_prepend (priv->connections, vpn);

	if (nm_dbus_manager_name_has_owner (priv->dbus_mgr, priv->dbus_service)) {
		// FIXME: fill in error when errors happen
		nm_vpn_connection_activate (vpn);
	} else if (priv->start_timeout == 0) {
		nm_log_info (LOGD_VPN, "Starting VPN service '%s'...", priv->name);
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
	GSList *iter;

	if (strcmp (name, priv->dbus_service))
		return;

	/* Service changed, no need to wait for the timeout any longer */
	if (priv->start_timeout) {
		g_source_remove (priv->start_timeout);
		priv->start_timeout = 0;
	}

	old_owner_good = (old && (strlen (old) > 0));
	new_owner_good = (new && (strlen (new) > 0));

	if (!old_owner_good && new_owner_good) {
		/* service just appeared */
		nm_log_info (LOGD_VPN, "VPN service '%s' appeared; activating connections", priv->name);
		clear_quit_timeout (service);

		for (iter = priv->connections; iter; iter = iter->next)
			nm_vpn_connection_activate (NM_VPN_CONNECTION (iter->data));
	} else if (old_owner_good && !new_owner_good) {
		/* service went away */
		nm_log_info (LOGD_VPN, "VPN service '%s' disappeared", priv->name);
		nm_vpn_service_connections_stop (service, TRUE, NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED);
	}
}

/******************************************************************************/

static void
nm_vpn_service_init (NMVPNService *self)
{
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (self);

	priv->dbus_mgr = nm_dbus_manager_get ();
	priv->name_owner_id = g_signal_connect (priv->dbus_mgr,
	                                        NM_DBUS_MANAGER_NAME_OWNER_CHANGED,
	                                        G_CALLBACK (nm_vpn_service_name_owner_changed),
	                                        self);
}

static void
dispose (GObject *object)
{
	NMVPNService *self = NM_VPN_SERVICE (object);
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (self);

	if (priv->disposed)
		goto out;
	priv->disposed = TRUE;

	if (priv->start_timeout)
		g_source_remove (priv->start_timeout);

	nm_vpn_service_connections_stop (NM_VPN_SERVICE (object),
	                                 FALSE,
	                                 NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED);

	g_signal_handler_disconnect (priv->dbus_mgr, priv->name_owner_id);

	if (priv->child_watch)
		g_source_remove (priv->child_watch);

	clear_quit_timeout (self);
	service_quit (self);

	g_object_unref (priv->dbus_mgr);

	g_free (priv->name);
	g_free (priv->dbus_service);
	g_free (priv->program);
	g_free (priv->namefile);

out:
	G_OBJECT_CLASS (nm_vpn_service_parent_class)->dispose (object);
}

static void
nm_vpn_service_class_init (NMVPNServiceClass *service_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (service_class);

	g_type_class_add_private (service_class, sizeof (NMVPNServicePrivate));

	/* virtual methods */
	object_class->dispose = dispose;
}
