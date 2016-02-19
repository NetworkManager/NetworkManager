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

#include "nm-default.h"

#include <string.h>

#include "nm-vpn-manager.h"
#include "nm-vpn-plugin-info.h"
#include "nm-vpn-connection.h"
#include "nm-setting-vpn.h"
#include "nm-vpn-dbus-interface.h"
#include "nm-core-internal.h"
#include "nm-enum-types.h"

G_DEFINE_TYPE (NMVpnManager, nm_vpn_manager, G_TYPE_OBJECT)

#define NM_VPN_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_MANAGER, NMVpnManagerPrivate))

typedef struct {
	GSList *plugins;
	GFileMonitor *monitor_etc;
	GFileMonitor *monitor_lib;
	gulong monitor_id_etc;
	gulong monitor_id_lib;

	/* This is only used for services that don't support multiple
	 * connections, to guard access to them. */
	GHashTable *active_services;
} NMVpnManagerPrivate;

/******************************************************************************/

static void
vpn_state_changed (NMVpnConnection *vpn,
                   GParamSpec *pspec,
                   NMVpnManager *manager)
{
	NMVpnManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (manager);
	NMActiveConnectionState state = nm_active_connection_get_state (NM_ACTIVE_CONNECTION (vpn));
	const char *service_name = nm_vpn_connection_get_service (vpn);

	if (state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED) {
		g_hash_table_remove (priv->active_services, service_name);
		g_signal_handlers_disconnect_by_func (vpn, vpn_state_changed, manager);
		g_object_unref (manager);
	}
}

gboolean
nm_vpn_manager_activate_connection (NMVpnManager *manager,
                                    NMVpnConnection *vpn,
                                    GError **error)
{
	NMVpnManagerPrivate *priv;
	NMVpnPluginInfo *plugin_info;
	const char *service_name;
	NMDevice *device;

	g_return_val_if_fail (NM_IS_VPN_MANAGER (manager), FALSE);
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	priv = NM_VPN_MANAGER_GET_PRIVATE (manager);
	device = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (vpn));
	g_assert (device);
	if (   nm_device_get_state (device) != NM_DEVICE_STATE_ACTIVATED
	    && nm_device_get_state (device) != NM_DEVICE_STATE_SECONDARIES) {
		g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_DEPENDENCY_FAILED,
		                     "The base device for the VPN connection was not active.");
		return FALSE;
	}

	service_name = nm_vpn_connection_get_service (vpn);

	plugin_info = nm_vpn_plugin_info_list_find_by_service (priv->plugins, service_name);
	if (!plugin_info) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_CONNECTION_NOT_AVAILABLE,
		             "The VPN service '%s' was not installed.",
		             service_name);
		return FALSE;
	}

	if (   !nm_vpn_plugin_info_supports_multiple (plugin_info)
	    && g_hash_table_contains (priv->active_services, service_name)) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_CONNECTION_NOT_AVAILABLE,
		             "The '%s' plugin only supports a single active connection.",
		             nm_vpn_plugin_info_get_name (plugin_info));
		return FALSE;
	}

	nm_vpn_connection_activate (vpn, plugin_info);

	if (!nm_vpn_plugin_info_supports_multiple (plugin_info)) {
		/* Block activations of the connections of the same service type. */
		g_hash_table_add (priv->active_services, g_strdup (service_name));
		g_signal_connect (vpn, "notify::" NM_ACTIVE_CONNECTION_STATE,
		                  G_CALLBACK (vpn_state_changed),
		                  g_object_ref (manager));
	}

	return TRUE;
}

/******************************************************************************/

static void
try_add_plugin (NMVpnManager *self, NMVpnPluginInfo *plugin_info)
{
	NMVpnManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (self);
	const char *program;

	program = nm_vpn_plugin_info_get_program (plugin_info);
	if (!program || !*program)
		return;

	/* Make sure we don't add dupes.
	 * We don't really allow reload of the same file. What we do allow is however to
	 * delete a file and re-add it. */
	if (nm_vpn_plugin_info_list_find_by_filename (priv->plugins,
	                                              nm_vpn_plugin_info_get_filename (plugin_info)))
		return;
	if (!nm_vpn_plugin_info_list_add (&priv->plugins, plugin_info, NULL))
		return;
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
	gs_free char *path = NULL;
	GError *error = NULL;

	path = g_file_get_path (file);
	if (!nm_vpn_plugin_info_validate_filename (path))
		return;

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_DELETED:
		plugin_info = nm_vpn_plugin_info_list_find_by_filename (priv->plugins, path);
		if (!plugin_info)
			break;

		nm_log_dbg (LOGD_VPN, "vpn: service file %s deleted", path);
		nm_vpn_plugin_info_list_remove (&priv->plugins, plugin_info);
		break;
	case G_FILE_MONITOR_EVENT_CREATED:
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		plugin_info = nm_vpn_plugin_info_list_find_by_filename (priv->plugins, path);
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
		try_add_plugin (self, plugin_info);
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
		try_add_plugin (self, info->data);
	g_slist_free_full (infos, g_object_unref);

	infos = _nm_vpn_plugin_info_list_load_dir (conf_dir_etc, TRUE, 0, NULL, NULL);
	for (info = infos; info; info = info->next)
		try_add_plugin (self, info->data);
	g_slist_free_full (infos, g_object_unref);

	priv->active_services = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
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

	while (priv->plugins)
		nm_vpn_plugin_info_list_remove (&priv->plugins, priv->plugins->data);

	g_hash_table_unref (priv->active_services);

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

