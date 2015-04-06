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
 * Copyright (C) 2005 - 2012 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "config.h"

#include <string.h>

#include "nm-glib.h"
#include "nm-vpn-manager.h"
#include "nm-vpn-service.h"
#include "nm-vpn-connection.h"
#include "nm-setting-vpn.h"
#include "nm-dbus-manager.h"
#include "nm-vpn-dbus-interface.h"
#include "nm-enum-types.h"
#include "nm-logging.h"

#define VPN_NAME_FILES_DIR NMCONFDIR "/VPN"

G_DEFINE_TYPE (NMVpnManager, nm_vpn_manager, G_TYPE_OBJECT)

#define NM_VPN_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_MANAGER, NMVpnManagerPrivate))

typedef struct {
	GHashTable *services;
	GFileMonitor *monitor;
	guint monitor_id;
} NMVpnManagerPrivate;


static NMVpnService *
get_service_by_namefile (NMVpnManager *self, const char *namefile)
{
	NMVpnManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer data;

	g_return_val_if_fail (namefile, NULL);
	g_return_val_if_fail (g_path_is_absolute (namefile), NULL);

	g_hash_table_iter_init (&iter, priv->services);
	while (g_hash_table_iter_next (&iter, NULL, &data)) {
		NMVpnService *candidate = NM_VPN_SERVICE (data);
		const char *service_namefile;

		service_namefile = nm_vpn_service_get_name_file (candidate);
		if (!strcmp (namefile, service_namefile))
			return candidate;
	}
	return NULL;
}

gboolean
nm_vpn_manager_activate_connection (NMVpnManager *manager,
                                    NMVpnConnection *vpn,
                                    GError **error)
{
	NMConnection *connection;
	NMSettingVpn *s_vpn;
	NMVpnService *service;
	const char *service_name;
	NMDevice *device;

	g_return_val_if_fail (NM_IS_VPN_MANAGER (manager), FALSE);
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), FALSE);
	g_return_val_if_fail (error != NULL, FALSE);
	g_return_val_if_fail (*error == NULL, FALSE);

	device = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (vpn));
	g_assert (device);
	if (   nm_device_get_state (device) != NM_DEVICE_STATE_ACTIVATED
	    && nm_device_get_state (device) != NM_DEVICE_STATE_SECONDARIES) {
		g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_DEPENDENCY_FAILED,
		                     "The base device for the VPN connection was not active.");
		return FALSE;
	}

	connection = nm_active_connection_get_connection (NM_ACTIVE_CONNECTION (vpn));
	g_assert (connection);
	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	service_name = nm_setting_vpn_get_service_type (s_vpn);
	g_assert (service_name);
	service = g_hash_table_lookup (NM_VPN_MANAGER_GET_PRIVATE (manager)->services, service_name);
	if (!service) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_CONNECTION_NOT_AVAILABLE,
		             "The VPN service '%s' was not installed.",
		             service_name);
		return FALSE;
	}

	return nm_vpn_service_activate (service, vpn, error);
}

gboolean
nm_vpn_manager_deactivate_connection (NMVpnManager *self,
                                      NMVpnConnection *connection,
                                      NMVpnConnectionStateReason reason)
{
	return nm_vpn_connection_deactivate (connection, reason, FALSE);
}

static void
try_add_service (NMVpnManager *self, const char *namefile)
{
	NMVpnManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (self);
	NMVpnService *service = NULL;
	GHashTableIter iter;
	GError *error = NULL;
	const char *service_name;

	g_return_if_fail (g_path_is_absolute (namefile));

	/* Make sure we don't add dupes */
	g_hash_table_iter_init (&iter, priv->services);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &service)) {
		if (g_strcmp0 (namefile, nm_vpn_service_get_name_file (service)) == 0)
			return;
	}

	/* New service */
	service = nm_vpn_service_new (namefile, &error);
	if (service) {
		service_name = nm_vpn_service_get_dbus_service (service);
		g_hash_table_insert (priv->services, (char *) service_name, service);
		nm_log_info (LOGD_VPN, "VPN: loaded %s", service_name);
	} else {
		nm_log_warn (LOGD_VPN, "failed to load VPN service file %s: (%d) %s",
		             namefile,
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}
}

static void
vpn_dir_changed (GFileMonitor *monitor,
                 GFile *file,
                 GFile *other_file,
                 GFileMonitorEvent event_type,
                 gpointer user_data)
{
	NMVpnManager *self = NM_VPN_MANAGER (user_data);
	NMVpnManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (self);
	NMVpnService *service;
	char *path;

	path = g_file_get_path (file);
	if (!g_str_has_suffix (path, ".name")) {
		g_free (path);
		return;
	}

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_DELETED:
		nm_log_dbg (LOGD_VPN, "service file %s deleted", path);

		service = get_service_by_namefile (self, path);
		if (service) {
			const char *service_name = nm_vpn_service_get_dbus_service (service);

			/* Stop active VPN connections and destroy the service */
			nm_vpn_service_stop_connections (service, FALSE,
			                                 NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED);
			nm_log_info (LOGD_VPN, "VPN: unloaded %s", service_name);
			g_hash_table_remove (priv->services, service_name);
		}
		break;
	case G_FILE_MONITOR_EVENT_CREATED:
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		nm_log_dbg (LOGD_VPN, "service file %s created or modified", path);
		try_add_service (self, path);
		break;
	default:
		nm_log_dbg (LOGD_VPN, "service file %s change event %d", path, event_type);
		break;
	}

	g_free (path);
}

/******************************************************************************/

NM_DEFINE_SINGLETON_GETTER (NMVpnManager, nm_vpn_manager_get, NM_TYPE_VPN_MANAGER);

static void
nm_vpn_manager_init (NMVpnManager *self)
{
	NMVpnManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (self);
	GFile *file;
	GDir *dir;
	const char *fn;
	char *path;

	priv->services = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                        NULL, g_object_unref);

	/* Watch the VPN directory for changes */
	file = g_file_new_for_path (VPN_NAME_FILES_DIR "/");
	priv->monitor = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);
	if (priv->monitor) {
		priv->monitor_id = g_signal_connect (priv->monitor, "changed",
		                                     G_CALLBACK (vpn_dir_changed), self);
	}

	/* Load VPN service files */
	dir = g_dir_open (VPN_NAME_FILES_DIR, 0, NULL);
	if (dir) {
		while ((fn = g_dir_read_name (dir))) {
			/* only parse filenames that end with .name */
			if (g_str_has_suffix (fn, ".name")) {
				path = g_build_filename (VPN_NAME_FILES_DIR, fn, NULL);
				try_add_service (self, path);
				g_free (path);
			}
		}
		g_dir_close (dir);
	}
}

static void
stop_all_services (NMVpnManager *self)
{
	NMVpnManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	NMVpnService *service;

	g_hash_table_iter_init (&iter, priv->services);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &service)) {
		nm_vpn_service_stop_connections (service,
		                                 TRUE,
		                                 NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED);
	}
}

static void
dispose (GObject *object)
{
	NMVpnManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (object);

	if (priv->monitor) {
		if (priv->monitor_id)
			g_signal_handler_disconnect (priv->monitor, priv->monitor_id);
		g_file_monitor_cancel (priv->monitor);
		g_clear_object (&priv->monitor);
	}

	if (priv->services) {
		stop_all_services (NM_VPN_MANAGER (object));
		g_hash_table_destroy (priv->services);
		priv->services = NULL;
	}

	G_OBJECT_CLASS (nm_vpn_manager_parent_class)->dispose (object);
}

static void
nm_vpn_manager_class_init (NMVpnManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMVpnManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
}

