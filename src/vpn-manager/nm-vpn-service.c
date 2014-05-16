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
 * Copyright (C) 2005 - 2014 Red Hat, Inc.
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
#include "nm-posix-signals.h"
#include "nm-vpn-manager.h"
#include "nm-glib-compat.h"

G_DEFINE_TYPE (NMVPNService, nm_vpn_service, G_TYPE_OBJECT)

typedef struct {
	char *name;
	char *dbus_service;
	char *program;
	char *namefile;

	NMVPNConnection *active;
	GSList *pending;

	GPid pid;
	guint start_timeout;
	guint child_watch;
	gulong name_owner_id;
} NMVPNServicePrivate;

#define NM_VPN_SERVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_SERVICE, NMVPNServicePrivate))

#define VPN_CONNECTION_GROUP "VPN Connection"

static gboolean start_pending_vpn (NMVPNService *self);

NMVPNService *
nm_vpn_service_new (const char *namefile, GError **error)
{
	NMVPNService *self;
	NMVPNServicePrivate *priv;
	GKeyFile *kf;

	g_return_val_if_fail (namefile != NULL, NULL);
	g_return_val_if_fail (g_path_is_absolute (namefile), NULL);

	kf = g_key_file_new ();
	if (!g_key_file_load_from_file (kf, namefile, G_KEY_FILE_NONE, error)) {
		g_key_file_free (kf);
		return NULL;
	}

	self = (NMVPNService *) g_object_new (NM_TYPE_VPN_SERVICE, NULL);
	priv = NM_VPN_SERVICE_GET_PRIVATE (self);
	priv->namefile = g_strdup (namefile);

	priv->dbus_service = g_key_file_get_string (kf, VPN_CONNECTION_GROUP, "service", error);
	if (!priv->dbus_service)
		goto error;

	priv->program = g_key_file_get_string (kf, VPN_CONNECTION_GROUP, "program", error);
	if (!priv->program)
		goto error;

	priv->name = g_key_file_get_string (kf, VPN_CONNECTION_GROUP, "name", error);
	if (!priv->name)
		goto error;

	g_key_file_free (kf);
	return self;

error:
	g_object_unref (self);
	g_key_file_free (kf);
	return NULL;
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

static void
connection_vpn_state_changed (NMVPNConnection *connection,
                              NMVPNConnectionState new_state,
                              NMVPNConnectionState old_state,
                              NMVPNConnectionStateReason reason,
                              gpointer user_data)
{
	NMVPNService *self = NM_VPN_SERVICE (user_data);
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (self);

	if (new_state == NM_VPN_CONNECTION_STATE_FAILED ||
	    new_state == NM_VPN_CONNECTION_STATE_DISCONNECTED) {
		g_signal_handlers_disconnect_by_func (connection, G_CALLBACK (connection_vpn_state_changed), self);
		if (connection == priv->active) {
			priv->active = NULL;
			start_pending_vpn (self);
		} else
			priv->pending = g_slist_remove (priv->pending, connection);
		g_object_unref (connection);
	}
}

void
nm_vpn_service_connections_stop (NMVPNService *service,
                                 gboolean fail,
                                 NMVPNConnectionStateReason reason)
{
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (service);
	GSList *iter;

	/* Just add priv->active to the beginning of priv->pending,
	 * since we're going to clear priv->pending immediately anyway.
	 */
	if (priv->active) {
		priv->pending = g_slist_prepend (priv->pending, priv->active);
		priv->active = NULL;
	}

	for (iter = priv->pending; iter; iter = iter->next) {
		NMVPNConnection *vpn = NM_VPN_CONNECTION (iter->data);

		g_signal_handlers_disconnect_by_func (vpn, G_CALLBACK (connection_vpn_state_changed), service);
		nm_vpn_connection_stop (vpn, fail, reason);
		g_object_unref (vpn);
	}
	g_clear_pointer (&priv->pending, g_slist_free);
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

	/*
	 * We blocked signals in main(). We need to restore original signal
	 * mask for VPN service here so that it can receive signals.
	 */
	nm_unblock_posix_signals (NULL);
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
start_active_vpn (NMVPNService *self, GError **error)
{
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (self);

	if (!priv->active)
		return TRUE;

	if (nm_dbus_manager_name_has_owner (nm_dbus_manager_get (), priv->dbus_service)) {
		/* Just activate the VPN */
		nm_vpn_connection_activate (priv->active);
		return TRUE;
	} else if (priv->start_timeout == 0) {
		/* VPN service not running, start it */
		nm_log_info (LOGD_VPN, "Starting VPN service '%s'...", priv->name);
		return nm_vpn_service_daemon_exec (self, error);
	}

	/* Already started VPN service, waiting for it to appear on D-Bus */
	return TRUE;
}

static gboolean
start_pending_vpn (NMVPNService *self)
{
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (self);

	g_assert (priv->active == NULL);

	if (!priv->pending)
		return TRUE;

	/* Make next VPN active */
	priv->active = g_slist_nth_data (priv->pending, 0);
	priv->pending = g_slist_remove (priv->pending, priv->active);

	return start_active_vpn (self, NULL);
}

gboolean
nm_vpn_service_activate (NMVPNService *service,
                         NMVPNConnection *vpn,
                         GError **error)
{
	NMVPNServicePrivate *priv;

	g_return_val_if_fail (NM_IS_VPN_SERVICE (service), FALSE);
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), FALSE);
	g_return_val_if_fail (error != NULL, FALSE);
	g_return_val_if_fail (*error == NULL, FALSE);

	priv = NM_VPN_SERVICE_GET_PRIVATE (service);

	g_signal_connect (vpn, NM_VPN_CONNECTION_INTERNAL_STATE_CHANGED,
	                  G_CALLBACK (connection_vpn_state_changed),
	                  service);

	/* Queue up the new VPN connection */
	priv->pending = g_slist_append (priv->pending, g_object_ref (vpn));

	/* Tell the active VPN to deactivate and wait for it to quit before we
	 * start the next VPN.  The just-queued VPN will then be started from
	 * connection_vpn_state_changed().
	 */
	if (priv->active) {
		nm_vpn_connection_deactivate (priv->active, NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED);
		return TRUE;
	}

	/* Otherwise start the next VPN */
	return start_pending_vpn (service);
}

static void
_name_owner_changed (NMDBusManager *mgr,
                     const char *name,
                     const char *old,
                     const char *new,
                     gpointer user_data)
{
	NMVPNService *service = NM_VPN_SERVICE (user_data);
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (service);
	gboolean old_owner_good, new_owner_good, success;

	if (strcmp (name, priv->dbus_service))
		return;

	/* Service changed, no need to wait for the timeout any longer */
	if (priv->start_timeout) {
		g_source_remove (priv->start_timeout);
		priv->start_timeout = 0;
	}

	old_owner_good = (old && old[0]);
	new_owner_good = (new && new[0]);

	if (!old_owner_good && new_owner_good) {
		/* service appeared */
		nm_log_info (LOGD_VPN, "VPN service '%s' appeared; activating connections", priv->name);
		/* Expect success because the VPN service has already appeared */
		success = start_active_vpn (service, NULL);
		g_warn_if_fail (success);
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

	priv->name_owner_id = g_signal_connect (nm_dbus_manager_get (),
	                                        NM_DBUS_MANAGER_NAME_OWNER_CHANGED,
	                                        G_CALLBACK (_name_owner_changed),
	                                        self);
}

static void
dispose (GObject *object)
{
	NMVPNService *self = NM_VPN_SERVICE (object);
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (self);

	if (priv->start_timeout) {
		g_source_remove (priv->start_timeout);
		priv->start_timeout = 0;
	}

	nm_vpn_service_connections_stop (NM_VPN_SERVICE (object),
	                                 FALSE,
	                                 NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED);

	if (priv->name_owner_id) {
		g_signal_handler_disconnect (nm_dbus_manager_get (), priv->name_owner_id);
		priv->name_owner_id = 0;
	}

	if (priv->child_watch) {
		g_source_remove (priv->child_watch);
		priv->child_watch = 0;
	}

	G_OBJECT_CLASS (nm_vpn_service_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMVPNServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (object);

	g_free (priv->name);
	g_free (priv->dbus_service);
	g_free (priv->program);
	g_free (priv->namefile);

	G_OBJECT_CLASS (nm_vpn_service_parent_class)->finalize (object);
}

static void
nm_vpn_service_class_init (NMVPNServiceClass *service_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (service_class);

	g_type_class_add_private (service_class, sizeof (NMVPNServicePrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	object_class->finalize = finalize;
}
