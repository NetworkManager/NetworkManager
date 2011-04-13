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
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include <string.h>
#include <gio/gio.h>

#include "nm-vpn-manager.h"
#include "nm-vpn-service.h"
#include "nm-vpn-connection.h"
#include "nm-setting-vpn.h"
#include "nm-dbus-manager.h"
#include "NetworkManagerVPN.h"
#include "nm-marshal.h"
#include "nm-logging.h"

G_DEFINE_TYPE (NMVPNManager, nm_vpn_manager, G_TYPE_OBJECT)

#define NM_VPN_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_MANAGER, NMVPNManagerPrivate))

typedef struct {
	gboolean disposed;

	GHashTable *services;
	GFileMonitor *monitor;
	guint monitor_id;
} NMVPNManagerPrivate;

enum {
	CONNECTION_ACTIVATED,
	CONNECTION_DEACTIVATED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

GQuark
nm_vpn_manager_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-vpn-manager-error");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_vpn_manager_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* The base device for the VPN connection is not active. */
			ENUM_ENTRY (NM_VPN_MANAGER_ERROR_DEVICE_NOT_ACTIVE, "BaseDeviceNotActive"),
			/* The requested VPN connection was invalid. */
			ENUM_ENTRY (NM_VPN_MANAGER_ERROR_CONNECTION_INVALID, "ConnectionInvalid"),
			/* The VPN service required by this VPN connection did not exist or was invalid. */
			ENUM_ENTRY (NM_VPN_MANAGER_ERROR_SERVICE_INVALID, "ServiceInvalid"),
			/* The VPN service required by this VPN connection could not be started. */
			ENUM_ENTRY (NM_VPN_MANAGER_ERROR_SERVICE_START_FAILED, "ServiceStartFailed"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMVPNManagerError", values);
	}
	return etype;
}


static NMVPNService *
get_service_by_namefile (NMVPNManager *self, const char *namefile)
{
	NMVPNManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer data;

	g_return_val_if_fail (namefile, NULL);
	g_return_val_if_fail (g_path_is_absolute (namefile), NULL);

	g_hash_table_iter_init (&iter, priv->services);
	while (g_hash_table_iter_next (&iter, NULL, &data)) {
		NMVPNService *candidate = NM_VPN_SERVICE (data);
		const char *service_namefile;

		service_namefile = nm_vpn_service_get_name_file (candidate);
		if (!strcmp (namefile, service_namefile))
			return candidate;
	}
	return NULL;
}

static NMVPNConnection *
find_active_vpn_connection_by_connection (NMVPNManager *self, NMConnection *connection)
{
	NMVPNManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer data;
	GSList *active, *aiter;
	NMVPNConnection *found = NULL;

	g_return_val_if_fail (connection, NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	g_hash_table_iter_init (&iter, priv->services);
	while (g_hash_table_iter_next (&iter, NULL, &data) && (found == NULL)) {
		active = nm_vpn_service_get_active_connections (NM_VPN_SERVICE (data));
		for (aiter = active; aiter; aiter = g_slist_next (aiter)) {
			NMVPNConnection *vpn = NM_VPN_CONNECTION (aiter->data);

			if (nm_vpn_connection_get_connection (vpn) == connection) {
				found = vpn;
				break;
			}
		}
		g_slist_free (active);
	}
	return found;
}

static void
connection_vpn_state_changed (NMVPNConnection *connection,
                              NMVPNConnectionState state,
                              NMVPNConnectionStateReason reason,
                              gpointer user_data)
{
	NMVPNManager *manager = NM_VPN_MANAGER (user_data);

	switch (state) {
	case NM_VPN_CONNECTION_STATE_ACTIVATED:
		g_signal_emit (manager, signals[CONNECTION_ACTIVATED], 0, connection);
		break;
	case NM_VPN_CONNECTION_STATE_FAILED:
	case NM_VPN_CONNECTION_STATE_DISCONNECTED:
		g_signal_emit (manager, signals[CONNECTION_DEACTIVATED], 0, connection, state, reason);
		break;
	default:
		break;
	}
}

NMVPNConnection *
nm_vpn_manager_activate_connection (NMVPNManager *manager,
                                    NMConnection *connection,
                                    NMDevice *device,
                                    gboolean user_requested,
                                    gulong user_uid,
                                    GError **error)
{
	NMSettingVPN *vpn_setting;
	NMVPNService *service;
	NMVPNConnection *vpn = NULL;
	const char *service_name;

	g_return_val_if_fail (NM_IS_VPN_MANAGER (manager), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);
	g_return_val_if_fail (error != NULL, NULL);
	g_return_val_if_fail (*error == NULL, NULL);

	if (nm_device_get_state (device) != NM_DEVICE_STATE_ACTIVATED) {
		g_set_error (error,
		             NM_VPN_MANAGER_ERROR, NM_VPN_MANAGER_ERROR_DEVICE_NOT_ACTIVE,
		             "%s", "The base device for the VPN connection was not active.");
		return NULL;
	}

	vpn_setting = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	if (!vpn_setting) {
		g_set_error (error,
		             NM_VPN_MANAGER_ERROR, NM_VPN_MANAGER_ERROR_CONNECTION_INVALID,
		             "%s", "The connection was not a VPN connection.");
		return NULL;
	}

	vpn = find_active_vpn_connection_by_connection (manager, connection);
	if (vpn) {
		nm_vpn_connection_disconnect (vpn, NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED);
		vpn = NULL;
	}

	service_name = nm_setting_vpn_get_service_type (vpn_setting);
	g_assert (service_name);
	service = g_hash_table_lookup (NM_VPN_MANAGER_GET_PRIVATE (manager)->services, service_name);
	if (!service) {
		g_set_error (error,
		             NM_VPN_MANAGER_ERROR, NM_VPN_MANAGER_ERROR_SERVICE_INVALID,
		             "The VPN service '%s' was not installed.",
		             service_name);
		return NULL;
	}

	vpn = nm_vpn_service_activate (service, connection, device, user_requested, user_uid, error);
	if (vpn) {
		g_signal_connect (vpn, "vpn-state-changed",
		                  G_CALLBACK (connection_vpn_state_changed),
		                  manager);
	}

	return vpn;
}

gboolean
nm_vpn_manager_deactivate_connection (NMVPNManager *self,
                                      const char *path,
                                      NMVPNConnectionStateReason reason)
{
	NMVPNManagerPrivate *priv;
	GHashTableIter iter;
	gpointer data;
	GSList *active, *aiter;
	gboolean success = FALSE;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (NM_IS_VPN_MANAGER (self), FALSE);
	g_return_val_if_fail (path != NULL, FALSE);

	priv = NM_VPN_MANAGER_GET_PRIVATE (self);
	g_hash_table_iter_init (&iter, priv->services);
	while (g_hash_table_iter_next (&iter, NULL, &data) && (success == FALSE)) {
		active = nm_vpn_service_get_active_connections (NM_VPN_SERVICE (data));
		for (aiter = active; aiter; aiter = g_slist_next (aiter)) {
			NMVPNConnection *vpn = NM_VPN_CONNECTION (aiter->data);
			const char *vpn_path;

			vpn_path = nm_vpn_connection_get_active_connection_path (vpn);
			if (!strcmp (path, vpn_path)) {
				nm_vpn_connection_disconnect (vpn, reason);
				success = TRUE;
				break;
			}
		}
		g_slist_free (active);
	}

	return success;
}

void
nm_vpn_manager_add_active_connections (NMVPNManager *self,
                                       NMConnection *filter,
                                       GPtrArray *array)
{
	NMVPNManagerPrivate *priv;
	GHashTableIter iter;
	gpointer data;
	GSList *active, *aiter;

	g_return_if_fail (self);
	g_return_if_fail (NM_IS_VPN_MANAGER (self));
	g_return_if_fail (array != NULL);

	priv = NM_VPN_MANAGER_GET_PRIVATE (self);
	g_hash_table_iter_init (&iter, priv->services);
	while (g_hash_table_iter_next (&iter, NULL, &data)) {
		active = nm_vpn_service_get_active_connections (NM_VPN_SERVICE (data));
		for (aiter = active; aiter; aiter = g_slist_next (aiter)) {
			NMVPNConnection *vpn = NM_VPN_CONNECTION (aiter->data);
			const char *path;

			if (!filter || (nm_vpn_connection_get_connection (vpn) == filter)) {
				path = nm_vpn_connection_get_active_connection_path (vpn);
				g_ptr_array_add (array, g_strdup (path));
			}
		}
		g_slist_free (active);
	}
}

GSList *
nm_vpn_manager_get_active_connections (NMVPNManager *self)
{
	NMVPNManagerPrivate *priv;
	GHashTableIter iter;
	gpointer data;
	GSList *list = NULL, *active;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (NM_IS_VPN_MANAGER (self), NULL);

	priv = NM_VPN_MANAGER_GET_PRIVATE (self);
	g_hash_table_iter_init (&iter, priv->services);
	while (g_hash_table_iter_next (&iter, NULL, &data)) {
		active = nm_vpn_service_get_active_connections (NM_VPN_SERVICE (data));
		list = g_slist_concat (list, active);
	}
	return list;
}

NMConnection *
nm_vpn_manager_get_connection_for_active (NMVPNManager *manager,
                                          const char *active_path)
{
	NMVPNManagerPrivate *priv;
	GHashTableIter iter;
	gpointer data;
	GSList *active, *elt;

	g_return_val_if_fail (NM_IS_VPN_MANAGER (manager), NULL);

	priv = NM_VPN_MANAGER_GET_PRIVATE (manager);
	g_hash_table_iter_init (&iter, priv->services);
	while (g_hash_table_iter_next (&iter, NULL, &data)) {
		active = nm_vpn_service_get_active_connections (NM_VPN_SERVICE (data));
		for (elt = active; elt; elt = g_slist_next (elt)) {
			NMVPNConnection *vpn = NM_VPN_CONNECTION (elt->data);
			const char *ac_path;

			ac_path = nm_vpn_connection_get_active_connection_path (vpn);
			if (ac_path && !strcmp (ac_path, active_path))
				return nm_vpn_connection_get_connection (vpn);
		}
	}

	return NULL;
}

static char *
service_name_from_file (const char *path)
{
	GKeyFile *kf = NULL;
	char *service_name = NULL;

	g_return_val_if_fail (g_path_is_absolute (path), NULL);

	if (!g_str_has_suffix (path, ".name"))
		return NULL;

	kf = g_key_file_new ();
	if (g_key_file_load_from_file (kf, path, G_KEY_FILE_NONE, NULL))
		service_name = g_key_file_get_string (kf, VPN_CONNECTION_GROUP, "service", NULL);

	g_key_file_free (kf);
	return service_name;
}

static void
try_add_service (NMVPNManager *self, const char *namefile)
{
	NMVPNManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (self);
	NMVPNService *service = NULL;
	GError *error = NULL;
	const char *service_name;
	char *tmp;

	g_return_if_fail (g_path_is_absolute (namefile));

	/* Make sure we don't add dupes */
	tmp = service_name_from_file (namefile);
	if (tmp)
		service = g_hash_table_lookup (priv->services, tmp);
	g_free (tmp);
	if (service)
		return;

	/* New service, add it */
	service = nm_vpn_service_new (namefile, &error);
	if (!service) {
		nm_log_warn (LOGD_VPN, "failed to load VPN service file %s: (%d) %s",
		             namefile,
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		return;
	}

	service_name = nm_vpn_service_get_dbus_service (service);
	g_hash_table_insert (priv->services, (char *) service_name, service);
	nm_log_info (LOGD_VPN, "VPN: loaded %s", service_name);
}

static void
vpn_dir_changed (GFileMonitor *monitor,
                 GFile *file,
                 GFile *other_file,
                 GFileMonitorEvent event_type,
                 gpointer user_data)
{
	NMVPNManager *self = NM_VPN_MANAGER (user_data);
	NMVPNManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (self);
	NMVPNService *service;
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
			nm_vpn_service_connections_stop (service, TRUE,
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

NMVPNManager *
nm_vpn_manager_get (void)
{
	static NMVPNManager *singleton = NULL;

	if (!singleton)
		singleton = NM_VPN_MANAGER (g_object_new (NM_TYPE_VPN_MANAGER, NULL));
	else
		g_object_ref (singleton);

	g_assert (singleton);
	return singleton;
}

static void
nm_vpn_manager_init (NMVPNManager *self)
{
	NMVPNManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (self);
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
dispose (GObject *object)
{
	NMVPNManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (object);

	if (!priv->disposed) {
		priv->disposed = TRUE;

		if (priv->monitor) {
			if (priv->monitor_id)
				g_signal_handler_disconnect (priv->monitor, priv->monitor_id);
			g_file_monitor_cancel (priv->monitor);
			g_object_unref (priv->monitor);
		}

		g_hash_table_destroy (priv->services);
	}

	G_OBJECT_CLASS (nm_vpn_manager_parent_class)->dispose (object);
}

static void
nm_vpn_manager_class_init (NMVPNManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMVPNManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;

	/* signals */
	signals[CONNECTION_ACTIVATED] =
		g_signal_new ("connection-activated",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    0, NULL, NULL,
				    g_cclosure_marshal_VOID__OBJECT,
				    G_TYPE_NONE, 1, G_TYPE_OBJECT);

	signals[CONNECTION_DEACTIVATED] =
		g_signal_new ("connection-deactivated",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMVPNManagerClass, connection_deactivated),
				    NULL, NULL,
				    _nm_marshal_VOID__OBJECT_UINT_UINT,
				    G_TYPE_NONE, 3,
				    G_TYPE_OBJECT, G_TYPE_UINT, G_TYPE_UINT);

	dbus_g_error_domain_register (NM_VPN_MANAGER_ERROR, NULL, NM_TYPE_VPN_MANAGER_ERROR);
}

