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

#include "nm-default.h"
#include "nm-vpn-manager.h"
#include "nm-vpn-service.h"
#include "nm-vpn-connection.h"
#include "nm-setting-vpn.h"
#include "nm-vpn-dbus-interface.h"
#include "nm-core-internal.h"
#include "nm-enum-types.h"

G_DEFINE_TYPE (NMVpnManager, nm_vpn_manager, G_TYPE_OBJECT)

#define NM_VPN_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_MANAGER, NMVpnManagerPrivate))

typedef struct {
	GSList *services;
	GFileMonitor *monitor_etc;
	GFileMonitor *monitor_lib;
	guint monitor_id_etc;
	guint monitor_id_lib;
} NMVpnManagerPrivate;

static NMVpnService *
_plugin_info_get_service (NMVpnPluginInfo *plugin_info)
{
	if (plugin_info)
		return NM_VPN_SERVICE (g_object_get_data (G_OBJECT (plugin_info), "service-instance"));
	return NULL;
}

static void
_plugin_info_set_service (NMVpnPluginInfo *plugin_info, NMVpnService *service)
{
	g_object_set_data_full (G_OBJECT (plugin_info), "service-instance", service,
	                        (GDestroyNotify) g_object_unref);
}

gboolean
nm_vpn_manager_activate_connection (NMVpnManager *manager,
                                    NMVpnConnection *vpn,
                                    GError **error)
{
	NMConnection *connection;
	NMSettingVpn *s_vpn;
	NMVpnService *service;
	NMVpnPluginInfo *plugin_info;
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
	plugin_info = nm_vpn_plugin_info_list_find_by_service (NM_VPN_MANAGER_GET_PRIVATE (manager)->services, service_name);
	service = _plugin_info_get_service (plugin_info);
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
try_add_service (NMVpnManager *self, NMVpnPluginInfo *plugin_info)
{
	NMVpnManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (self);
	NMVpnService *service = NULL;
	GError *error = NULL;

	/* Make sure we don't add dupes.
	 * We don't really allow reload of the same file. What we do allow is however to
	 * delete a file and re-add it. */
	if (nm_vpn_plugin_info_list_find_by_filename (priv->services,
	                                              nm_vpn_plugin_info_get_filename (plugin_info)))
		return;
	if (!nm_vpn_plugin_info_list_add (&priv->services, plugin_info, NULL))
		return;

	/* New service */
	service = nm_vpn_service_new (plugin_info, &error);
	if (service) {
		_plugin_info_set_service (plugin_info, service);
		nm_log_info (LOGD_VPN, "VPN: loaded %s - %s",
		             nm_vpn_plugin_info_get_name (plugin_info),
		             nm_vpn_service_get_dbus_service (service));
	} else {
		nm_log_warn (LOGD_VPN, "failed to load VPN service file %s: %s",
		             nm_vpn_plugin_info_get_filename (plugin_info),
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
	NMVpnPluginInfo *plugin_info;
	NMVpnService *service;
	gs_free char *path = NULL;
	GError *error = NULL;

	path = g_file_get_path (file);
	if (!nm_vpn_plugin_info_validate_filename (path))
		return;

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_DELETED:
		plugin_info = nm_vpn_plugin_info_list_find_by_filename (priv->services, path);
		if (!plugin_info)
			break;

		nm_log_dbg (LOGD_VPN, "vpn: service file %s deleted", path);
		service = _plugin_info_get_service (plugin_info);
		if (service) {
			/* Stop active VPN connections and destroy the service */
			nm_vpn_service_stop_connections (service, FALSE,
			                                 NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED);
			nm_log_info (LOGD_VPN, "VPN: unloaded %s", nm_vpn_service_get_dbus_service (service));

			_plugin_info_set_service (plugin_info, NULL);
		}
		nm_vpn_plugin_info_list_remove (&priv->services, plugin_info);
		break;
	case G_FILE_MONITOR_EVENT_CREATED:
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		plugin_info = nm_vpn_plugin_info_list_find_by_filename (priv->services, path);
		if (plugin_info) {
			/* we don't support reloading an existing plugin. You can only remove the file
			 * and re-add it. By reloading we want to support the use case of installing
			 * a VPN plugin after NM started. No need to burden ourself with a complete
			 * reload. */
			break;
		}

		if (!_nm_vpn_plugin_info_check_file (path, TRUE, TRUE, 0,
		                                     NULL, NULL, &error)) {
			nm_log_dbg (LOGD_VPN, "vpn: ignore changed service file %s (%s)", path, error->message);
			g_clear_error (&error);
			break;
		}
		plugin_info = nm_vpn_plugin_info_new_from_file (path, &error);
		if (!plugin_info) {
			nm_log_dbg (LOGD_VPN, "vpn: ignore changed service file %s due to invalid content (%s)", path, error->message);
			g_clear_error (&error);
			break;
		}

		nm_log_dbg (LOGD_VPN, "vpn: service file %s created or modified", path);
		try_add_service (self, plugin_info);
		g_object_unref (plugin_info);
		break;
	default:
		nm_log_dbg (LOGD_VPN, "vpn: service file %s change event %d", path, event_type);
		break;
	}
}

/******************************************************************************/

NM_DEFINE_SINGLETON_GETTER (NMVpnManager, nm_vpn_manager_get, NM_TYPE_VPN_MANAGER);

static void
nm_vpn_manager_init (NMVpnManager *self)
{
	NMVpnManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (self);
	GFile *file;
	GSList *infos, *info;
	const char *conf_dir_etc = _nm_vpn_plugin_info_get_default_dir_etc ();
	const char *conf_dir_lib = _nm_vpn_plugin_info_get_default_dir_lib ();

	/* Watch the VPN directory for changes */
	file = g_file_new_for_path (conf_dir_lib);
	priv->monitor_lib = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);
	if (priv->monitor_lib) {
		priv->monitor_id_lib = g_signal_connect (priv->monitor_lib, "changed",
		                                         G_CALLBACK (vpn_dir_changed), self);
	}

	file = g_file_new_for_path (conf_dir_etc);
	priv->monitor_etc = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);
	if (priv->monitor_etc) {
		priv->monitor_id_etc = g_signal_connect (priv->monitor_etc, "changed",
		                                         G_CALLBACK (vpn_dir_changed), self);
	}

	/* first read conf_dir_lib. The name files are not really user configuration, but
	 * plugin configuration. Hence we expect ~newer~ plugins to install their files
	 * in /usr/lib/NetworkManager. We want to prefer those files.
	 * In case of no-conflict, the order doesn't matter. */
	infos = _nm_vpn_plugin_info_list_load_dir (conf_dir_lib, TRUE, 0, NULL, NULL);
	for (info = infos; info; info = info->next)
		try_add_service (self, info->data);
	g_slist_free_full (infos, g_object_unref);

	infos = _nm_vpn_plugin_info_list_load_dir (conf_dir_etc, TRUE, 0, NULL, NULL);
	for (info = infos; info; info = info->next)
		try_add_service (self, info->data);
	g_slist_free_full (infos, g_object_unref);
}

static void
dispose (GObject *object)
{
	NMVpnManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (object);

	if (priv->monitor_etc) {
		if (priv->monitor_id_etc)
			g_signal_handler_disconnect (priv->monitor_etc, priv->monitor_id_etc);
		g_file_monitor_cancel (priv->monitor_etc);
		g_clear_object (&priv->monitor_etc);
	}

	if (priv->monitor_lib) {
		if (priv->monitor_id_lib)
			g_signal_handler_disconnect (priv->monitor_lib, priv->monitor_id_lib);
		g_file_monitor_cancel (priv->monitor_lib);
		g_clear_object (&priv->monitor_lib);
	}

	while (priv->services) {
		NMVpnPluginInfo *plugin_info = priv->services->data;
		NMVpnService *service = _plugin_info_get_service (plugin_info);

		if (service) {
			nm_vpn_service_stop_connections (service, TRUE, NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED);
			_plugin_info_set_service (plugin_info, NULL);
		}
		nm_vpn_plugin_info_list_remove (&priv->services, plugin_info);
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

