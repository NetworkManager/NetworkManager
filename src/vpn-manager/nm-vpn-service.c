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

#include "config.h"

#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#include "nm-glib.h"
#include "nm-vpn-service.h"
#include "nm-logging.h"
#include "nm-vpn-manager.h"

G_DEFINE_TYPE (NMVpnService, nm_vpn_service, G_TYPE_OBJECT)

typedef struct {
	char *name;
	char *dbus_service;
	char *program;
	char *namefile;

	NMVpnConnection *active;
	GSList *pending;

	guint start_timeout;
	GDBusProxy *proxy;
	gboolean service_running;
} NMVpnServicePrivate;

#define NM_VPN_SERVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_SERVICE, NMVpnServicePrivate))

#define VPN_CONNECTION_GROUP "VPN Connection"

static gboolean start_pending_vpn (NMVpnService *self, GError **error);

static void _name_owner_changed (GObject *object, GParamSpec *pspec, gpointer user_data);

NMVpnService *
nm_vpn_service_new (const char *namefile, GError **error)
{
	NMVpnService *self;
	NMVpnServicePrivate *priv;
	GKeyFile *kf;

	g_return_val_if_fail (namefile != NULL, NULL);
	g_return_val_if_fail (g_path_is_absolute (namefile), NULL);

	kf = g_key_file_new ();
	if (!g_key_file_load_from_file (kf, namefile, G_KEY_FILE_NONE, error)) {
		g_key_file_free (kf);
		return NULL;
	}

	self = (NMVpnService *) g_object_new (NM_TYPE_VPN_SERVICE, NULL);
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

	priv->proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                             G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                                                 G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS |
	                                                 G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
	                                             NULL,
	                                             priv->dbus_service,
	                                             NM_VPN_DBUS_PLUGIN_PATH,
	                                             NM_VPN_DBUS_PLUGIN_INTERFACE,
	                                             NULL, error);
	if (!priv->proxy)
		goto error;

	g_signal_connect (priv->proxy, "notify::g-name-owner",
	                  G_CALLBACK (_name_owner_changed), self);
	_name_owner_changed (G_OBJECT (priv->proxy), NULL, self);

	g_key_file_free (kf);
	return self;

error:
	g_object_unref (self);
	g_key_file_free (kf);
	return NULL;
}

const char *
nm_vpn_service_get_dbus_service (NMVpnService *service)
{
	g_return_val_if_fail (NM_IS_VPN_SERVICE (service), NULL);

	return NM_VPN_SERVICE_GET_PRIVATE (service)->dbus_service;
}

const char *
nm_vpn_service_get_name_file (NMVpnService *service)
{
	g_return_val_if_fail (NM_IS_VPN_SERVICE (service), NULL);

	return NM_VPN_SERVICE_GET_PRIVATE (service)->namefile;
}

static void
connection_vpn_state_changed (NMVpnConnection *connection,
                              NMVpnConnectionState new_state,
                              NMVpnConnectionState old_state,
                              NMVpnConnectionStateReason reason,
                              gpointer user_data)
{
	NMVpnService *self = NM_VPN_SERVICE (user_data);
	NMVpnServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (self);

	if (new_state == NM_VPN_CONNECTION_STATE_FAILED ||
	    new_state == NM_VPN_CONNECTION_STATE_DISCONNECTED) {
		g_signal_handlers_disconnect_by_func (connection, G_CALLBACK (connection_vpn_state_changed), self);
		if (connection == priv->active) {
			priv->active = NULL;
			start_pending_vpn (self, NULL);
		} else
			priv->pending = g_slist_remove (priv->pending, connection);
		g_object_unref (connection);
	}
}

void
nm_vpn_service_stop_connections (NMVpnService *service,
                                 gboolean quitting,
                                 NMVpnConnectionStateReason reason)
{
	NMVpnServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (service);
	GSList *iter;

	/* Just add priv->active to the beginning of priv->pending,
	 * since we're going to clear priv->pending immediately anyway.
	 */
	if (priv->active) {
		priv->pending = g_slist_prepend (priv->pending, priv->active);
		priv->active = NULL;
	}

	for (iter = priv->pending; iter; iter = iter->next) {
		NMVpnConnection *vpn = NM_VPN_CONNECTION (iter->data);

		g_signal_handlers_disconnect_by_func (vpn, G_CALLBACK (connection_vpn_state_changed), service);
		if (quitting) {
			/* Deactivate to allow pre-down before disconnecting */
			nm_vpn_connection_deactivate (vpn, reason, quitting);
		}
		nm_vpn_connection_disconnect (vpn, reason, quitting);
		g_object_unref (vpn);
	}
	g_clear_pointer (&priv->pending, g_slist_free);
}

static gboolean
_daemon_exec_timeout (gpointer data)
{
	NMVpnService *self = NM_VPN_SERVICE (data);
	NMVpnServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (self);

	nm_log_warn (LOGD_VPN, "VPN service '%s' start timed out", priv->name);
	priv->start_timeout = 0;
	nm_vpn_service_stop_connections (self, FALSE, NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT);
	return G_SOURCE_REMOVE;
}

static gboolean
nm_vpn_service_daemon_exec (NMVpnService *service, GError **error)
{
	NMVpnServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (service);
	GPid pid;
	char *vpn_argv[2];
	gboolean success = FALSE;
	GError *spawn_error = NULL;

	g_return_val_if_fail (NM_IS_VPN_SERVICE (service), FALSE);

	vpn_argv[0] = priv->program;
	vpn_argv[1] = NULL;

	success = g_spawn_async (NULL, vpn_argv, NULL, 0, nm_utils_setpgid, NULL, &pid, &spawn_error);
	if (success) {
		nm_log_info (LOGD_VPN, "VPN service '%s' started (%s), PID %ld",
		             priv->name, priv->dbus_service, (long int) pid);
		priv->start_timeout = g_timeout_add_seconds (5, _daemon_exec_timeout, service);
	} else {
		nm_log_warn (LOGD_VPN, "VPN service '%s': could not launch the VPN service. error: (%d) %s.",
		             priv->name,
		             spawn_error ? spawn_error->code : -1,
		             spawn_error && spawn_error->message ? spawn_error->message : "(unknown)");

		g_set_error (error,
		             NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		             "%s", spawn_error ? spawn_error->message : "unknown g_spawn_async() error");

		nm_vpn_service_stop_connections (service, FALSE, NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED);
		if (spawn_error)
			g_error_free (spawn_error);
	}

	return success;
}

static gboolean
start_active_vpn (NMVpnService *self, GError **error)
{
	NMVpnServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (self);

	if (!priv->active)
		return TRUE;

	if (priv->service_running) {
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
start_pending_vpn (NMVpnService *self, GError **error)
{
	NMVpnServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (self);

	g_assert (priv->active == NULL);

	if (!priv->pending)
		return TRUE;

	/* Make next VPN active */
	priv->active = g_slist_nth_data (priv->pending, 0);
	priv->pending = g_slist_remove (priv->pending, priv->active);

	return start_active_vpn (self, error);
}

gboolean
nm_vpn_service_activate (NMVpnService *service,
                         NMVpnConnection *vpn,
                         GError **error)
{
	NMVpnServicePrivate *priv;

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
		nm_vpn_connection_deactivate (priv->active, NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED, FALSE);
		return TRUE;
	}

	/* Otherwise start the next VPN */
	return start_pending_vpn (service, error);
}

static void
_name_owner_changed (GObject *object,
                     GParamSpec *pspec,
                     gpointer user_data)
{
	NMVpnService *service = NM_VPN_SERVICE (user_data);
	NMVpnServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (service);
	gboolean success;
	char *owner;

	owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (object));

	/* Service changed, no need to wait for the timeout any longer */
	if (priv->start_timeout) {
		g_source_remove (priv->start_timeout);
		priv->start_timeout = 0;
	}

	if (owner && !priv->service_running) {
		/* service appeared */
		priv->service_running = TRUE;
		nm_log_info (LOGD_VPN, "VPN service '%s' appeared; activating connections", priv->name);
		/* Expect success because the VPN service has already appeared */
		success = start_active_vpn (service, NULL);
		g_warn_if_fail (success);
	} else if (!owner && priv->service_running) {
		/* service went away */
		priv->service_running = FALSE;
		nm_log_info (LOGD_VPN, "VPN service '%s' disappeared", priv->name);
		nm_vpn_service_stop_connections (service, FALSE, NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED);
	}

	g_free (owner);
}

/******************************************************************************/

static void
nm_vpn_service_init (NMVpnService *self)
{
}

static void
dispose (GObject *object)
{
	NMVpnService *self = NM_VPN_SERVICE (object);
	NMVpnServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (self);

	if (priv->start_timeout) {
		g_source_remove (priv->start_timeout);
		priv->start_timeout = 0;
	}

	/* VPNService owner is required to stop connections before releasing */
	g_assert (priv->active == NULL);
	g_assert (priv->pending == NULL);

	if (priv->proxy) {
		g_signal_handlers_disconnect_by_func (priv->proxy,
		                                      G_CALLBACK (_name_owner_changed),
		                                      self);
		g_clear_object (&priv->proxy);
	}

	G_OBJECT_CLASS (nm_vpn_service_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMVpnServicePrivate *priv = NM_VPN_SERVICE_GET_PRIVATE (object);

	g_free (priv->name);
	g_free (priv->dbus_service);
	g_free (priv->program);
	g_free (priv->namefile);

	G_OBJECT_CLASS (nm_vpn_service_parent_class)->finalize (object);
}

static void
nm_vpn_service_class_init (NMVpnServiceClass *service_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (service_class);

	g_type_class_add_private (service_class, sizeof (NMVpnServicePrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	object_class->finalize = finalize;
}
