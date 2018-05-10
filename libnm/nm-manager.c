/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-manager.h"

#include <string.h>

#include "nm-utils.h"
#include "nm-checkpoint.h"
#include "nm-common-macros.h"
#include "nm-device-ethernet.h"
#include "nm-device-wifi.h"
#include "nm-core-internal.h"
#include "nm-object-private.h"
#include "nm-active-connection.h"
#include "nm-vpn-connection.h"
#include "nm-dbus-helpers.h"
#include "c-list/src/c-list.h"

#include "introspection/org.freedesktop.NetworkManager.h"

void _nm_device_wifi_set_wireless_enabled (NMDeviceWifi *device, gboolean enabled);

static void nm_manager_initable_iface_init (GInitableIface *iface);
static void nm_manager_async_initable_iface_init (GAsyncInitableIface *iface);
static GInitableIface *nm_manager_parent_initable_iface;
static GAsyncInitableIface *nm_manager_parent_async_initable_iface;

G_DEFINE_TYPE_WITH_CODE (NMManager, nm_manager, NM_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_manager_initable_iface_init);
                         G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, nm_manager_async_initable_iface_init);
                         )

#define NM_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MANAGER, NMManagerPrivate))

typedef struct {
	NMDBusManager *proxy;
	GCancellable *props_cancellable;
	char *version;
	NMState state;
	gboolean startup;
	GPtrArray *devices;
	GPtrArray *all_devices;
	GPtrArray *active_connections;
	GPtrArray *checkpoints;
	GSList *added_checkpoints;
	NMConnectivityState connectivity;
	NMActiveConnection *primary_connection;
	NMActiveConnection *activating_connection;
	NMMetered metered;

	GCancellable *perm_call_cancellable;
	GHashTable *permissions;

	/* Activations waiting for their NMActiveConnection
	 * to appear and then their callback to be called.
	 */
	CList pending_activations;

	gboolean networking_enabled;
	gboolean wireless_enabled;
	gboolean wireless_hw_enabled;

	gboolean wwan_enabled;
	gboolean wwan_hw_enabled;

	gboolean wimax_enabled;
	gboolean wimax_hw_enabled;

	gboolean connectivity_check_available;
	gboolean connectivity_check_enabled;
} NMManagerPrivate;

enum {
	PROP_0,
	PROP_VERSION,
	PROP_STATE,
	PROP_STARTUP,
	PROP_NETWORKING_ENABLED,
	PROP_WIRELESS_ENABLED,
	PROP_WIRELESS_HARDWARE_ENABLED,
	PROP_WWAN_ENABLED,
	PROP_WWAN_HARDWARE_ENABLED,
	PROP_WIMAX_ENABLED,
	PROP_WIMAX_HARDWARE_ENABLED,
	PROP_ACTIVE_CONNECTIONS,
	PROP_CONNECTIVITY,
	PROP_CONNECTIVITY_CHECK_AVAILABLE,
	PROP_CONNECTIVITY_CHECK_ENABLED,
	PROP_PRIMARY_CONNECTION,
	PROP_ACTIVATING_CONNECTION,
	PROP_DEVICES,
	PROP_CHECKPOINTS,
	PROP_METERED,
	PROP_ALL_DEVICES,

	LAST_PROP
};

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,
	ANY_DEVICE_ADDED,
	ANY_DEVICE_REMOVED,
	ACTIVE_CONNECTION_ADDED,
	ACTIVE_CONNECTION_REMOVED,
	CHECKPOINT_ADDED,
	CHECKPOINT_REMOVED,
	PERMISSION_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/*****************************************************************************/

typedef struct {
	NMManager *manager;
	GSimpleAsyncResult *simple;
	char *path;
} CheckpointInfo;

static CheckpointInfo *
find_checkpoint_info (NMManager *manager, const char *path)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	CheckpointInfo *info;
	GSList *iter;

	for (iter = priv->added_checkpoints; iter; iter = g_slist_next (iter)) {
		info = iter->data;
		if (nm_streq0 (path, info->path))
			return info;
	}

	return NULL;
}

static void
checkpoint_info_complete (NMManager *self,
                          CheckpointInfo *info,
                          NMCheckpoint *checkpoint,
                          GError *error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (info);

	if (checkpoint) {
		g_simple_async_result_set_op_res_gpointer (info->simple,
		                                           g_object_ref (checkpoint),
		                                           g_object_unref);
	} else
		g_simple_async_result_set_from_error (info->simple, error);
	g_simple_async_result_complete (info->simple);

	g_object_unref (info->simple);
	priv->added_checkpoints = g_slist_remove (priv->added_checkpoints, info);

	g_free (info->path);
	g_slice_free (CheckpointInfo, info);
}

static void
nm_manager_init (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	c_list_init (&priv->pending_activations);

	priv->state = NM_STATE_UNKNOWN;
	priv->connectivity = NM_CONNECTIVITY_UNKNOWN;

	priv->permissions = g_hash_table_new (nm_direct_hash, NULL);
	priv->devices = g_ptr_array_new ();
	priv->all_devices = g_ptr_array_new ();
	priv->active_connections = g_ptr_array_new ();
}

static void
poke_wireless_devices_with_rf_status (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	int i;

	for (i = 0; i < priv->all_devices->len; i++) {
		NMDevice *device = g_ptr_array_index (priv->all_devices, i);

		if (NM_IS_DEVICE_WIFI (device))
			_nm_device_wifi_set_wireless_enabled (NM_DEVICE_WIFI (device), priv->wireless_enabled);
	}
}

static void
wireless_enabled_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	poke_wireless_devices_with_rf_status (NM_MANAGER (object));
}

static void manager_recheck_permissions (NMDBusManager *proxy, gpointer user_data);

static void
init_dbus (NMObject *object)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_MANAGER_VERSION,                   &priv->version },
		{ NM_MANAGER_STATE,                     &priv->state },
		{ NM_MANAGER_STARTUP,                   &priv->startup },
		{ NM_MANAGER_NETWORKING_ENABLED,        &priv->networking_enabled },
		{ NM_MANAGER_WIRELESS_ENABLED,          &priv->wireless_enabled },
		{ NM_MANAGER_WIRELESS_HARDWARE_ENABLED, &priv->wireless_hw_enabled },
		{ NM_MANAGER_WWAN_ENABLED,              &priv->wwan_enabled },
		{ NM_MANAGER_WWAN_HARDWARE_ENABLED,     &priv->wwan_hw_enabled },
		{ NM_MANAGER_WIMAX_ENABLED,             &priv->wimax_enabled },
		{ NM_MANAGER_WIMAX_HARDWARE_ENABLED,    &priv->wimax_hw_enabled },
		{ NM_MANAGER_ACTIVE_CONNECTIONS,        &priv->active_connections, NULL, NM_TYPE_ACTIVE_CONNECTION, "active-connection" },
		{ NM_MANAGER_CONNECTIVITY,              &priv->connectivity },
		{ NM_MANAGER_CONNECTIVITY_CHECK_AVAILABLE, &priv->connectivity_check_available },
		{ NM_MANAGER_CONNECTIVITY_CHECK_ENABLED, &priv->connectivity_check_enabled },
		{ NM_MANAGER_PRIMARY_CONNECTION,        &priv->primary_connection, NULL, NM_TYPE_ACTIVE_CONNECTION },
		{ NM_MANAGER_ACTIVATING_CONNECTION,     &priv->activating_connection, NULL, NM_TYPE_ACTIVE_CONNECTION },
		{ NM_MANAGER_DEVICES,                   &priv->devices, NULL, NM_TYPE_DEVICE, "device" },
		{ NM_MANAGER_CHECKPOINTS,               &priv->checkpoints, NULL, NM_TYPE_CHECKPOINT, "checkpoint" },
		{ NM_MANAGER_METERED,                   &priv->metered },
		{ NM_MANAGER_ALL_DEVICES,               &priv->all_devices, NULL, NM_TYPE_DEVICE, "any-device" },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_manager_parent_class)->init_dbus (object);

	priv->proxy = NMDBUS_MANAGER (_nm_object_get_proxy (object, NM_DBUS_INTERFACE));
	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE,
	                                property_info);

	/* Permissions */
	g_signal_connect_object (priv->proxy, "check-permissions",
				 G_CALLBACK (manager_recheck_permissions), object, 0);
}

static void
object_creation_failed (NMObject *object, const char *failed_path)
{
	NMManager *self = NM_MANAGER (object);
	CheckpointInfo *info;
	GError *add_error;

	info = find_checkpoint_info (self, failed_path);
	if (info) {
		add_error = g_error_new_literal (NM_CLIENT_ERROR,
		                                 NM_CLIENT_ERROR_OBJECT_CREATION_FAILED,
		                                 _("Checkpoint was removed before it was initialized"));
		checkpoint_info_complete (self, info, NULL, add_error);
		g_error_free (add_error);
	}
}

static NMClientPermission
nm_permission_to_client (const char *nm)
{
	if (!strcmp (nm, NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK))
		return NM_CLIENT_PERMISSION_ENABLE_DISABLE_NETWORK;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_ENABLE_DISABLE_WIFI))
		return NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIFI;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_ENABLE_DISABLE_WWAN))
		return NM_CLIENT_PERMISSION_ENABLE_DISABLE_WWAN;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_ENABLE_DISABLE_WIMAX))
		return NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIMAX;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_SLEEP_WAKE))
		return NM_CLIENT_PERMISSION_SLEEP_WAKE;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_NETWORK_CONTROL))
		return NM_CLIENT_PERMISSION_NETWORK_CONTROL;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED))
		return NM_CLIENT_PERMISSION_WIFI_SHARE_PROTECTED;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_WIFI_SHARE_OPEN))
		return NM_CLIENT_PERMISSION_WIFI_SHARE_OPEN;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM))
		return NM_CLIENT_PERMISSION_SETTINGS_MODIFY_SYSTEM;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN))
		return NM_CLIENT_PERMISSION_SETTINGS_MODIFY_OWN;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_SETTINGS_MODIFY_HOSTNAME))
		return NM_CLIENT_PERMISSION_SETTINGS_MODIFY_HOSTNAME;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_SETTINGS_MODIFY_GLOBAL_DNS))
		return NM_CLIENT_PERMISSION_SETTINGS_MODIFY_GLOBAL_DNS;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_RELOAD))
		return NM_CLIENT_PERMISSION_RELOAD;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_CHECKPOINT_ROLLBACK))
		return NM_CLIENT_PERMISSION_CHECKPOINT_ROLLBACK;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_ENABLE_DISABLE_STATISTICS))
		return NM_CLIENT_PERMISSION_ENABLE_DISABLE_STATISTICS;
	else if (!strcmp (nm, NM_AUTH_PERMISSION_ENABLE_DISABLE_CONNECTIVITY_CHECK))
		return NM_CLIENT_PERMISSION_ENABLE_DISABLE_CONNECTIVITY_CHECK;

	return NM_CLIENT_PERMISSION_NONE;
}

static NMClientPermissionResult
nm_permission_result_to_client (const char *nm)
{
	if (!strcmp (nm, "yes"))
		return NM_CLIENT_PERMISSION_RESULT_YES;
	else if (!strcmp (nm, "no"))
		return NM_CLIENT_PERMISSION_RESULT_NO;
	else if (!strcmp (nm, "auth"))
		return NM_CLIENT_PERMISSION_RESULT_AUTH;
	return NM_CLIENT_PERMISSION_RESULT_UNKNOWN;
}

static void
update_permissions (NMManager *self, GVariant *permissions)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer key, value;
	NMClientPermission perm;
	NMClientPermissionResult perm_result;
	GList *keys, *keys_iter;

	/* get list of old permissions for change notification */
	keys = g_hash_table_get_keys (priv->permissions);
	g_hash_table_remove_all (priv->permissions);

	if (permissions) {
		GVariantIter viter;
		const char *pkey, *pvalue;

		/* Process new permissions */
		g_variant_iter_init (&viter, permissions);
		while (g_variant_iter_next (&viter, "{&s&s}", &pkey, &pvalue)) {
			perm = nm_permission_to_client (pkey);
			perm_result = nm_permission_result_to_client (pvalue);
			if (perm) {
				g_hash_table_insert (priv->permissions,
				                     GUINT_TO_POINTER (perm),
				                     GUINT_TO_POINTER (perm_result));

				/* Remove this permission from the list of previous permissions
				 * we'll be sending NM_CLIENT_PERMISSION_RESULT_UNKNOWN for
				 * in the change signal since it is still a known permission.
				 */
				keys = g_list_remove (keys, GUINT_TO_POINTER (perm));
			}
		}
	}

	/* Signal changes in all updated permissions */
	g_hash_table_iter_init (&iter, priv->permissions);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		g_signal_emit (self, signals[PERMISSION_CHANGED], 0,
		               GPOINTER_TO_UINT (key),
		               GPOINTER_TO_UINT (value));
	}

	/* And signal changes in all permissions that used to be valid but for
	 * some reason weren't received in the last request (if any).
	 */
	for (keys_iter = keys; keys_iter; keys_iter = g_list_next (keys_iter)) {
		g_signal_emit (self, signals[PERMISSION_CHANGED], 0,
		               GPOINTER_TO_UINT (keys_iter->data),
		               NM_CLIENT_PERMISSION_RESULT_UNKNOWN);
	}
	g_list_free (keys);
}

static gboolean
get_permissions_sync (NMManager *self, GError **error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GVariant *permissions;

	if (nmdbus_manager_call_get_permissions_sync (priv->proxy,
	                                              &permissions,
	                                              NULL, error)) {
		update_permissions (self, permissions);
		g_variant_unref (permissions);
		return TRUE;
	} else {
		if (error && *error)
			g_dbus_error_strip_remote_error (*error);
		update_permissions (self, NULL);
		return FALSE;
	}
}

static void
get_permissions_reply (GObject *object,
                       GAsyncResult *result,
                       gpointer user_data)
{
	NMManager *self;
	NMManagerPrivate *priv;
	GVariant *permissions = NULL;
	GError *error = NULL;

	/* WARNING: this may be called after the manager is disposed, so we can't
	 * look at self/priv until after we've determined that that isn't the case.
	 */

	nmdbus_manager_call_get_permissions_finish (NMDBUS_MANAGER (object),
	                                            &permissions,
	                                            result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		/* @self has been disposed. */
		g_error_free (error);
		return;
	}

	self = user_data;
	priv = NM_MANAGER_GET_PRIVATE (self);

	update_permissions (self, permissions);

	g_clear_pointer (&permissions, g_variant_unref);
	g_clear_error (&error);
	g_clear_object (&priv->perm_call_cancellable);
}

static void
manager_recheck_permissions (NMDBusManager *proxy, gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	if (priv->perm_call_cancellable)
		return;

	priv->perm_call_cancellable = g_cancellable_new ();
	nmdbus_manager_call_get_permissions (priv->proxy,
	                                     priv->perm_call_cancellable,
	                                     get_permissions_reply,
	                                     self);
}

const char *
nm_manager_get_version (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	return nm_str_not_empty (NM_MANAGER_GET_PRIVATE (manager)->version);
}

NMState
nm_manager_get_state (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NM_STATE_UNKNOWN);

	return NM_MANAGER_GET_PRIVATE (manager)->state;
}

gboolean
nm_manager_get_startup (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NM_STATE_UNKNOWN);

	return NM_MANAGER_GET_PRIVATE (manager)->startup;
}

gboolean
nm_manager_networking_get_enabled (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	return NM_MANAGER_GET_PRIVATE (manager)->networking_enabled;
}

gboolean
nm_manager_networking_set_enabled (NMManager *manager, gboolean enable, GError **error)
{
	gboolean ret;

	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	ret = nmdbus_manager_call_enable_sync (NM_MANAGER_GET_PRIVATE (manager)->proxy,
	                                       enable,
	                                       NULL, error);
	if (error && *error)
		g_dbus_error_strip_remote_error (*error);
	return ret;
}

gboolean
nm_manager_wireless_get_enabled (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	return NM_MANAGER_GET_PRIVATE (manager)->wireless_enabled;
}

void
nm_manager_wireless_set_enabled (NMManager *manager, gboolean enabled)
{
	g_return_if_fail (NM_IS_MANAGER (manager));

	_nm_object_set_property (NM_OBJECT (manager),
	                         NM_DBUS_INTERFACE,
	                         "WirelessEnabled",
	                         "b", enabled);
}

gboolean
nm_manager_wireless_hardware_get_enabled (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	return NM_MANAGER_GET_PRIVATE (manager)->wireless_hw_enabled;
}

gboolean
nm_manager_wwan_get_enabled (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	return NM_MANAGER_GET_PRIVATE (manager)->wwan_enabled;
}

void
nm_manager_wwan_set_enabled (NMManager *manager, gboolean enabled)
{
	g_return_if_fail (NM_IS_MANAGER (manager));

	_nm_object_set_property (NM_OBJECT (manager),
	                         NM_DBUS_INTERFACE,
	                         "WwanEnabled",
	                         "b", enabled);
}

gboolean
nm_manager_wwan_hardware_get_enabled (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	return NM_MANAGER_GET_PRIVATE (manager)->wwan_hw_enabled;
}

gboolean
nm_manager_wimax_get_enabled (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	return NM_MANAGER_GET_PRIVATE (manager)->wimax_enabled;
}

void
nm_manager_wimax_set_enabled (NMManager *manager, gboolean enabled)
{
	g_return_if_fail (NM_IS_MANAGER (manager));

	_nm_object_set_property (NM_OBJECT (manager),
	                         NM_DBUS_INTERFACE,
	                         "WimaxEnabled",
	                         "b", enabled);
}

gboolean
nm_manager_wimax_hardware_get_enabled (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	return NM_MANAGER_GET_PRIVATE (manager)->wimax_hw_enabled;
}

gboolean
nm_manager_connectivity_check_get_available (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	return NM_MANAGER_GET_PRIVATE (manager)->connectivity_check_available;
}

gboolean
nm_manager_connectivity_check_get_enabled (NMManager *manager)
{
	return NM_MANAGER_GET_PRIVATE (manager)->connectivity_check_enabled;
}

void
nm_manager_connectivity_check_set_enabled (NMManager *manager, gboolean enabled)
{
	g_return_if_fail (NM_IS_MANAGER (manager));

	_nm_object_set_property (NM_OBJECT (manager),
	                         NM_DBUS_INTERFACE,
	                         "ConnectivityCheckEnabled",
	                         "b", enabled);
}

gboolean
nm_manager_get_logging (NMManager *manager, char **level, char **domains, GError **error)
{
	gboolean ret;

	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);
	g_return_val_if_fail (level == NULL || *level == NULL, FALSE);
	g_return_val_if_fail (domains == NULL || *domains == NULL, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!level && !domains)
		return TRUE;

	ret = nmdbus_manager_call_get_logging_sync (NM_MANAGER_GET_PRIVATE (manager)->proxy,
	                                            level, domains,
	                                            NULL, error);
	if (error && *error)
		g_dbus_error_strip_remote_error (*error);
	return ret;
}

gboolean
nm_manager_set_logging (NMManager *manager, const char *level, const char *domains, GError **error)
{
	gboolean ret;

	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!level && !domains)
		return TRUE;

	if (!level)
		level = "";
	if (!domains)
		domains = "";

	ret = nmdbus_manager_call_set_logging_sync (NM_MANAGER_GET_PRIVATE (manager)->proxy,
	                                            level, domains,
	                                            NULL, error);
	if (error && *error)
		g_dbus_error_strip_remote_error (*error);
	return ret;
}

NMClientPermissionResult
nm_manager_get_permission_result (NMManager *manager, NMClientPermission permission)
{
	gpointer result;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NM_CLIENT_PERMISSION_RESULT_UNKNOWN);

	result = g_hash_table_lookup (NM_MANAGER_GET_PRIVATE (manager)->permissions,
	                              GUINT_TO_POINTER (permission));
	return GPOINTER_TO_UINT (result);
}

NMConnectivityState
nm_manager_get_connectivity (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NM_CONNECTIVITY_UNKNOWN);

	return NM_MANAGER_GET_PRIVATE (manager)->connectivity;
}

NMConnectivityState
nm_manager_check_connectivity (NMManager *manager,
                               GCancellable *cancellable,
                               GError **error)
{
	NMManagerPrivate *priv;
	guint32 connectivity;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NM_CONNECTIVITY_UNKNOWN);
	priv = NM_MANAGER_GET_PRIVATE (manager);

	if (nmdbus_manager_call_check_connectivity_sync (priv->proxy,
	                                                 &connectivity,
	                                                 cancellable, error)) {
		if (connectivity != priv->connectivity) {
			priv->connectivity = connectivity;
			g_object_notify (G_OBJECT (manager), NM_MANAGER_CONNECTIVITY);
		}
		return connectivity;
	}
	else {
		if (error && *error)
			g_dbus_error_strip_remote_error (*error);
		return NM_CONNECTIVITY_UNKNOWN;
	}
}

static void
check_connectivity_cb (GObject *object,
                       GAsyncResult *result,
                       gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	guint32 connectivity;
	GError *error = NULL;
	NMManager *manager;
	NMManagerPrivate *priv;

	if (nmdbus_manager_call_check_connectivity_finish (NMDBUS_MANAGER (object),
	                                                   &connectivity,
	                                                   result, &error)) {
		g_simple_async_result_set_op_res_gssize (simple, connectivity);

		manager = NM_MANAGER (g_async_result_get_source_object (G_ASYNC_RESULT (simple)));
		priv = NM_MANAGER_GET_PRIVATE (manager);
		if (connectivity != priv->connectivity) {
			priv->connectivity = connectivity;
			g_object_notify (G_OBJECT (manager), NM_MANAGER_CONNECTIVITY);
		}
	} else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
	}

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

void
nm_manager_check_connectivity_async (NMManager *manager,
                                     GCancellable *cancellable,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data)
{
	NMManagerPrivate *priv;
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_MANAGER (manager));
	priv = NM_MANAGER_GET_PRIVATE (manager);

	simple = g_simple_async_result_new (G_OBJECT (manager), callback, user_data,
	                                    nm_manager_check_connectivity_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);
	nmdbus_manager_call_check_connectivity (priv->proxy,
	                                        cancellable,
	                                        check_connectivity_cb, simple);
}

NMConnectivityState
nm_manager_check_connectivity_finish (NMManager *manager,
                                      GAsyncResult *result,
                                      GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (manager), nm_manager_check_connectivity_async), NM_CONNECTIVITY_UNKNOWN);

	simple = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (simple, error))
		return NM_CONNECTIVITY_UNKNOWN;
	return (NMConnectivityState) g_simple_async_result_get_op_res_gssize (simple);
}

/*****************************************************************************/
/* Devices                                                      */
/*****************************************************************************/

const GPtrArray *
nm_manager_get_devices (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	return NM_MANAGER_GET_PRIVATE (manager)->devices;
}

const GPtrArray *
nm_manager_get_all_devices (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	return NM_MANAGER_GET_PRIVATE (manager)->all_devices;
}

NMDevice *
nm_manager_get_device_by_path (NMManager *manager, const char *object_path)
{
	const GPtrArray *devices;
	guint i;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (object_path, NULL);

	devices = nm_manager_get_devices (manager);
	for (i = 0; i < devices->len; i++) {
		NMDevice *candidate = g_ptr_array_index (devices, i);
		if (!strcmp (nm_object_get_path (NM_OBJECT (candidate)), object_path)) {
			return candidate;
		}
	}
	return NULL;
}

static NMCheckpoint *
get_checkpoint_by_path (NMManager *manager, const char *object_path)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	NMCheckpoint *candidate;
	guint i;

	for (i = 0; i < priv->checkpoints->len; i++) {
		candidate = priv->checkpoints->pdata[i];
		if (nm_streq (nm_object_get_path (NM_OBJECT (candidate)), object_path))
			return candidate;
	}
	return NULL;
}

NMDevice *
nm_manager_get_device_by_iface (NMManager *manager, const char *iface)
{
	const GPtrArray *devices;
	int i;
	NMDevice *device = NULL;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (iface, NULL);

	devices = nm_manager_get_devices (manager);
	for (i = 0; i < devices->len; i++) {
		NMDevice *candidate = g_ptr_array_index (devices, i);
		if (!strcmp (nm_device_get_iface (candidate), iface)) {
			device = candidate;
			break;
		}
	}

	return device;
}

/*****************************************************************************/
/* Active Connections                                           */
/*****************************************************************************/

const GPtrArray *
nm_manager_get_active_connections (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	return NM_MANAGER_GET_PRIVATE (manager)->active_connections;
}

NMActiveConnection *
nm_manager_get_primary_connection (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	return NM_MANAGER_GET_PRIVATE (manager)->primary_connection;
}

NMActiveConnection *
nm_manager_get_activating_connection (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	return NM_MANAGER_GET_PRIVATE (manager)->activating_connection;
}

typedef struct {
	CList lst;
	NMManager *manager;
	GSimpleAsyncResult *simple;
	GCancellable *cancellable;
	gulong cancelled_id;
	char *active_path;
	char *new_connection_path;
} ActivateInfo;

static void
activate_info_complete (ActivateInfo *info,
                        NMActiveConnection *active,
                        GError *error)
{
	if (active)
		g_simple_async_result_set_op_res_gpointer (info->simple, g_object_ref (active), g_object_unref);
	else
		g_simple_async_result_set_from_error (info->simple, error);
	g_simple_async_result_complete (info->simple);

	c_list_unlink_stale (&info->lst);

	g_free (info->active_path);
	g_free (info->new_connection_path);
	g_object_unref (info->simple);
	if (info->cancellable) {
		if (info->cancelled_id)
			g_signal_handler_disconnect (info->cancellable, info->cancelled_id);
		g_object_unref (info->cancellable);
	}
	g_slice_free (ActivateInfo, info);
}

static NMActiveConnection *
find_active_connection_by_path (NMManager *self, const char *ac_path)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	int i;

	for (i = 0; i < priv->active_connections->len; i++) {
		NMActiveConnection *candidate = g_ptr_array_index (priv->active_connections, i);
		const char *candidate_path = nm_object_get_path (NM_OBJECT (candidate));

		if (g_strcmp0 (ac_path, candidate_path) == 0)
			return candidate;
	}

	return NULL;
}

static void
recheck_pending_activations (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	CList *iter, *safe;
	NMActiveConnection *candidate;
	const GPtrArray *devices;
	NMDevice *device;
	GDBusObjectManager *object_manager = NULL;
	GError *error;

	object_manager = _nm_object_get_dbus_object_manager (NM_OBJECT (self));

	/* For each pending activation, look for an active connection that has the
	 * pending activation's object path, where the active connection and its
	 * device have both updated their properties to point to each other, and
	 * call the pending connection's callback.
	 */
	c_list_for_each_safe (iter, safe, &priv->pending_activations) {
		ActivateInfo *info = c_list_entry (iter, ActivateInfo, lst);
		gs_unref_object GDBusObject *dbus_obj = NULL;

		if (!info->active_path)
			continue;

		/* Check that the object manager still knows about the object.
		 * It could be that it vanished before we even learned its name. */
		dbus_obj = g_dbus_object_manager_get_object (object_manager, info->active_path);
		if (!dbus_obj) {
			error = g_error_new_literal (NM_CLIENT_ERROR,
			                             NM_CLIENT_ERROR_OBJECT_CREATION_FAILED,
			                             _("Active connection removed before it was initialized"));
			activate_info_complete (info, NULL, error);
			g_clear_error (&error);
			break;
		}

		candidate = find_active_connection_by_path (self, info->active_path);
		if (!candidate)
			continue;

		/* Check that the AC and device are both ready */
		devices = nm_active_connection_get_devices (candidate);
		if (devices->len == 0)
			continue;

		if (!NM_IS_VPN_CONNECTION (candidate)) {
			device = devices->pdata[0];
			if (nm_device_get_active_connection (device) != candidate)
				continue;
		}

		activate_info_complete (info, candidate, NULL);
		break;
	}
}

static void
activation_cancelled (GCancellable *cancellable,
                      gpointer user_data)
{
	ActivateInfo *info = user_data;
	GError *error = NULL;

	if (!g_cancellable_set_error_if_cancelled (cancellable, &error))
		return;

	activate_info_complete (info, NULL, error);
	g_clear_error (&error);
}

static void
activate_cb (GObject *object,
             GAsyncResult *result,
             gpointer user_data)
{
	ActivateInfo *info = user_data;
	GError *error = NULL;

	if (nmdbus_manager_call_activate_connection_finish (NMDBUS_MANAGER (object),
	                                                    &info->active_path,
	                                                    result, &error)) {
		if (info->cancellable) {
			info->cancelled_id = g_signal_connect (info->cancellable, "cancelled",
			                                       G_CALLBACK (activation_cancelled), info);
		}

		recheck_pending_activations (info->manager);
	} else {
		g_dbus_error_strip_remote_error (error);
		activate_info_complete (info, NULL, error);
		g_clear_error (&error);
	}
}

void
nm_manager_activate_connection_async (NMManager *manager,
                                      NMConnection *connection,
                                      NMDevice *device,
                                      const char *specific_object,
                                      GCancellable *cancellable,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data)
{
	NMManagerPrivate *priv;
	ActivateInfo *info;

	g_return_if_fail (NM_IS_MANAGER (manager));
	if (device)
		g_return_if_fail (NM_IS_DEVICE (device));
	if (connection)
		g_return_if_fail (NM_IS_CONNECTION (connection));

	priv = NM_MANAGER_GET_PRIVATE (manager);

	info = g_slice_new0 (ActivateInfo);
	info->manager = manager;
	info->simple = g_simple_async_result_new (G_OBJECT (manager), callback, user_data,
	                                          nm_manager_activate_connection_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (info->simple, cancellable);
	info->cancellable = cancellable ? g_object_ref (cancellable) : NULL;

	c_list_link_tail (&priv->pending_activations, &info->lst);

	nmdbus_manager_call_activate_connection (priv->proxy,
	                                         connection ? nm_connection_get_path (connection) : "/",
	                                         device ? nm_object_get_path (NM_OBJECT (device)) : "/",
	                                         specific_object ?: "/",
	                                         cancellable,
	                                         activate_cb, info);
}

NMActiveConnection *
nm_manager_activate_connection_finish (NMManager *manager,
                                       GAsyncResult *result,
                                       GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (manager), nm_manager_activate_connection_async), NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	else
		return g_object_ref (g_simple_async_result_get_op_res_gpointer (simple));
}

static void
add_activate_cb (GObject *object,
                 GAsyncResult *result,
                 gpointer user_data)
{
	ActivateInfo *info = user_data;
	GError *error = NULL;

	if (nmdbus_manager_call_add_and_activate_connection_finish (NMDBUS_MANAGER (object),
	                                                            NULL,
	                                                            &info->active_path,
	                                                            result, &error)) {
		if (info->cancellable) {
			info->cancelled_id = g_signal_connect (info->cancellable, "cancelled",
			                                       G_CALLBACK (activation_cancelled), info);
		}

		recheck_pending_activations (info->manager);
	} else {
		g_dbus_error_strip_remote_error (error);
		activate_info_complete (info, NULL, error);
		g_clear_error (&error);
	}
}

void
nm_manager_add_and_activate_connection_async (NMManager *manager,
                                              NMConnection *partial,
                                              NMDevice *device,
                                              const char *specific_object,
                                              GCancellable *cancellable,
                                              GAsyncReadyCallback callback,
                                              gpointer user_data)
{
	NMManagerPrivate *priv;
	GVariant *dict = NULL;
	ActivateInfo *info;

	g_return_if_fail (NM_IS_MANAGER (manager));
	g_return_if_fail (NM_IS_DEVICE (device));
	if (partial)
		g_return_if_fail (NM_IS_CONNECTION (partial));

	priv = NM_MANAGER_GET_PRIVATE (manager);

	info = g_slice_new0 (ActivateInfo);
	info->manager = manager;
	info->simple = g_simple_async_result_new (G_OBJECT (manager), callback, user_data,
	                                          nm_manager_add_and_activate_connection_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (info->simple, cancellable);
	info->cancellable = cancellable ? g_object_ref (cancellable) : NULL;

	c_list_link_tail (&priv->pending_activations, &info->lst);

	if (partial)
		dict = nm_connection_to_dbus (partial, NM_CONNECTION_SERIALIZE_ALL);
	if (!dict)
		dict = g_variant_new_array (G_VARIANT_TYPE ("{sa{sv}}"), NULL, 0);

	nmdbus_manager_call_add_and_activate_connection (priv->proxy,
	                                                 dict,
	                                                 nm_object_get_path (NM_OBJECT (device)),
	                                                 specific_object ?: "/",
	                                                 cancellable,
	                                                 add_activate_cb, info);
}

NMActiveConnection *
nm_manager_add_and_activate_connection_finish (NMManager *manager,
                                               GAsyncResult *result,
                                               GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (manager), nm_manager_add_and_activate_connection_async), NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	else
		return g_object_ref (g_simple_async_result_get_op_res_gpointer (simple));
}

static void
device_ac_changed (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	NMManager *self = user_data;

	recheck_pending_activations (self);
}

static void
device_added (NMManager *self, NMDevice *device)
{
	g_signal_connect_object (device, "notify::" NM_DEVICE_ACTIVE_CONNECTION,
	                         G_CALLBACK (device_ac_changed), self, 0);
}

static void
device_removed (NMManager *self, NMDevice *device)
{
	g_signal_handlers_disconnect_by_func (device, G_CALLBACK (device_ac_changed), self);
}

static void
ac_devices_changed (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	NMManager *self = user_data;

	recheck_pending_activations (self);
}

static void
active_connection_added (NMManager *self, NMActiveConnection *ac)
{
	g_signal_connect_object (ac, "notify::" NM_ACTIVE_CONNECTION_DEVICES,
	                         G_CALLBACK (ac_devices_changed), self, 0);
	recheck_pending_activations (self);
}

static void
active_connection_removed (NMManager *self, NMActiveConnection *ac)
{
	g_signal_handlers_disconnect_by_func (ac, G_CALLBACK (ac_devices_changed), self);
	recheck_pending_activations (self);
}

static void
checkpoint_added (NMManager *manager, NMCheckpoint *checkpoint)
{
	CheckpointInfo *info;

	info = find_checkpoint_info (manager, nm_object_get_path (NM_OBJECT (checkpoint)));
	if (info)
		checkpoint_info_complete (manager, info, checkpoint, NULL);
}

gboolean
nm_manager_deactivate_connection (NMManager *manager,
                                  NMActiveConnection *active,
                                  GCancellable *cancellable,
                                  GError **error)
{
	const char *path;
	gboolean ret;

	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (active), FALSE);

	path = nm_object_get_path (NM_OBJECT (active));
	ret = nmdbus_manager_call_deactivate_connection_sync (NM_MANAGER_GET_PRIVATE (manager)->proxy,
	                                                      path,
	                                                      cancellable, error);
	if (error && *error)
		g_dbus_error_strip_remote_error (*error);
	return ret;
}

static void
deactivated_cb (GObject *object,
                GAsyncResult *result,
                gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	if (nmdbus_manager_call_deactivate_connection_finish (NMDBUS_MANAGER (object),
	                                                      result, &error))
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
	}
	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

void
nm_manager_deactivate_connection_async (NMManager *manager,
                                        NMActiveConnection *active,
                                        GCancellable *cancellable,
                                        GAsyncReadyCallback callback,
                                        gpointer user_data)
{
	const char *path;
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_MANAGER (manager));
	g_return_if_fail (NM_IS_ACTIVE_CONNECTION (active));

	simple = g_simple_async_result_new (G_OBJECT (manager), callback, user_data,
	                                    nm_manager_deactivate_connection_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	path = nm_object_get_path (NM_OBJECT (active));
	nmdbus_manager_call_deactivate_connection (NM_MANAGER_GET_PRIVATE (manager)->proxy,
	                                           path,
	                                           cancellable,
	                                           deactivated_cb, simple);
}

gboolean
nm_manager_deactivate_connection_finish (NMManager *manager,
                                         GAsyncResult *result,
                                         GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (manager), nm_manager_deactivate_connection_async), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
}

/*****************************************************************************/

static void
free_active_connections (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	int i;

	if (!priv->active_connections)
		return;

	/* Break circular refs */
	for (i = 0; i < priv->active_connections->len; i++)
		g_object_run_dispose (G_OBJECT (priv->active_connections->pdata[i]));
	g_ptr_array_unref (priv->active_connections);
	priv->active_connections = NULL;
}

/*****************************************************************************/

static const char **
get_device_paths (const GPtrArray *devices)
{
	const char **array;
	guint i;

	array = g_new (const char *, devices->len + 1);
	for (i = 0; i < devices->len; i++)
		array[i] = nm_object_get_path (NM_OBJECT (devices->pdata[i]));

	array[i] = NULL;

	return array;
}

const GPtrArray *
nm_manager_get_checkpoints (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	return NM_MANAGER_GET_PRIVATE (manager)->checkpoints;
}

static void
checkpoint_created_cb (GObject *object,
                       GAsyncResult *result,
                       gpointer user_data)
{
	CheckpointInfo *info = user_data;
	NMManager *self = info->manager;
	gs_free_error GError *error = NULL;
	NMCheckpoint *checkpoint;

	nmdbus_manager_call_checkpoint_create_finish (NMDBUS_MANAGER (object),
	                                              &info->path, result, &error);
	if (error) {
		g_dbus_error_strip_remote_error (error);
		checkpoint_info_complete (self, info, NULL, error);
		return;
	}

	checkpoint = get_checkpoint_by_path (self, info->path);
	if (!checkpoint) {
		/* this is really problematic. The async request returned, but
		 * we don't yet have a visible (fully initialized) NMCheckpoint instance
		 * to return. Wait longer for it to appear. However, it's ugly. */
		return;
	}

	checkpoint_info_complete (self, info, checkpoint, NULL);
}

void
nm_manager_checkpoint_create (NMManager *manager,
                              const GPtrArray *devices,
                              guint32 rollback_timeout,
                              NMCheckpointCreateFlags flags,
                              GCancellable *cancellable,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	gs_free const char **paths = NULL;
	CheckpointInfo *info;

	g_return_if_fail (NM_IS_MANAGER (manager));

	info = g_slice_new0 (CheckpointInfo);
	info->manager = manager;
	info->simple = g_simple_async_result_new (G_OBJECT (manager), callback, user_data,
	                                          nm_manager_checkpoint_create);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (info->simple, cancellable);
	paths = get_device_paths (devices);
	nmdbus_manager_call_checkpoint_create (NM_MANAGER_GET_PRIVATE (manager)->proxy,
	                                       paths,
	                                       rollback_timeout,
	                                       flags,
	                                       cancellable,
	                                       checkpoint_created_cb,
	                                       info);
	priv->added_checkpoints = g_slist_append (priv->added_checkpoints, info);
}

NMCheckpoint *
nm_manager_checkpoint_create_finish (NMManager *manager,
                                     GAsyncResult *result,
                                     GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	else
		return g_object_ref (g_simple_async_result_get_op_res_gpointer (simple));
}

static void
checkpoint_destroy_cb (GObject *object,
                       GAsyncResult *result,
                       gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	if (nmdbus_manager_call_checkpoint_destroy_finish (NMDBUS_MANAGER (object),
	                                                   result, &error))
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
	}
	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

void
nm_manager_checkpoint_destroy (NMManager *manager,
                               const char *checkpoint_path,
                               GCancellable *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_MANAGER (manager));
	g_return_if_fail (checkpoint_path && checkpoint_path[0] == '/');

	simple = g_simple_async_result_new (G_OBJECT (manager), callback, user_data,
	                                    nm_manager_checkpoint_destroy);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	nmdbus_manager_call_checkpoint_destroy (NM_MANAGER_GET_PRIVATE (manager)->proxy,
	                                        checkpoint_path,
	                                        cancellable,
	                                        checkpoint_destroy_cb, simple);
}

gboolean
nm_manager_checkpoint_destroy_finish (NMManager *manager,
                                      GAsyncResult *result,
                                      GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (manager),
	                                                      nm_manager_checkpoint_destroy),
	                      FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
}

static void
checkpoint_rollback_cb (GObject *object,
                        GAsyncResult *result,
                        gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;
	GVariant *variant = NULL;
	GVariantIter iter;
	GHashTable *hash;
	const char *path;
	guint r;

	if (nmdbus_manager_call_checkpoint_rollback_finish (NMDBUS_MANAGER (object),
	                                                    &variant,
	                                                    result,
	                                                    &error)) {
		hash = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, NULL);
		g_variant_iter_init (&iter, variant);
		while (g_variant_iter_next (&iter, "{&su}", &path, &r))
			g_hash_table_insert (hash, g_strdup (path), GUINT_TO_POINTER (r));
		g_simple_async_result_set_op_res_gpointer (simple, hash, (GDestroyNotify) g_hash_table_unref);
	} else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
	}
	g_simple_async_result_complete (simple);
	g_object_unref (simple);
}

void
nm_manager_checkpoint_rollback (NMManager *manager,
                                const char *checkpoint_path,
                                GCancellable *cancellable,
                                GAsyncReadyCallback callback,
                                gpointer user_data)
{
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_MANAGER (manager));
	g_return_if_fail (checkpoint_path && checkpoint_path[0] == '/');

	simple = g_simple_async_result_new (G_OBJECT (manager), callback, user_data,
	                                    nm_manager_checkpoint_rollback);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	nmdbus_manager_call_checkpoint_rollback (NM_MANAGER_GET_PRIVATE (manager)->proxy,
	                                         checkpoint_path,
	                                         cancellable,
	                                         checkpoint_rollback_cb, simple);
}

GHashTable *
nm_manager_checkpoint_rollback_finish (NMManager *manager,
                                       GAsyncResult *result,
                                       GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (manager),
	                                                      nm_manager_checkpoint_rollback),
	                      NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;
	else
		return g_simple_async_result_get_op_res_gpointer (simple);
}

static void
checkpoint_adjust_rollback_timeout_cb (GObject *object,
                                       GAsyncResult *result,
                                       gpointer user_data)
{
	gs_unref_object GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	if (nmdbus_manager_call_checkpoint_adjust_rollback_timeout_finish (NMDBUS_MANAGER (object),
	                                                                   result,
	                                                                   &error))
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
	}
	g_simple_async_result_complete (simple);
}

void
nm_manager_checkpoint_adjust_rollback_timeout (NMManager *manager,
                                               const char *checkpoint_path,
                                               guint32 add_timeout,
                                               GCancellable *cancellable,
                                               GAsyncReadyCallback callback,
                                               gpointer user_data)
{
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_MANAGER (manager));
	g_return_if_fail (checkpoint_path && checkpoint_path[0] == '/');

	simple = g_simple_async_result_new (G_OBJECT (manager), callback, user_data,
	                                    nm_manager_checkpoint_adjust_rollback_timeout);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	nmdbus_manager_call_checkpoint_adjust_rollback_timeout (NM_MANAGER_GET_PRIVATE (manager)->proxy,
	                                                        checkpoint_path,
	                                                        add_timeout,
	                                                        cancellable,
	                                                        checkpoint_adjust_rollback_timeout_cb,
	                                                        simple);
}

gboolean
nm_manager_checkpoint_adjust_rollback_timeout_finish (NMManager *manager,
                                                      GAsyncResult *result,
                                                      GError **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (manager),
	                                                      nm_manager_checkpoint_adjust_rollback_timeout),
	                      FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	return !g_simple_async_result_propagate_error (simple, error);
}

/*****************************************************************************/

static void
constructed (GObject *object)
{
	G_OBJECT_CLASS (nm_manager_parent_class)->constructed (object);

	g_signal_connect (object, "notify::" NM_MANAGER_WIRELESS_ENABLED,
	                  G_CALLBACK (wireless_enabled_cb), NULL);
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMManager *manager = NM_MANAGER (initable);
	GError *local_error = NULL;

	if (!nm_manager_parent_initable_iface->init (initable, cancellable, error)) {
		/* Never happens. */
		g_return_val_if_reached (FALSE);
	}

	if (!get_permissions_sync (manager, &local_error)) {
		g_warning ("Unable to get permissions: %s\n", local_error->message);
		g_error_free (local_error);
	}

	return TRUE;
}

typedef struct {
	NMManager *manager;
	GCancellable *cancellable;
	GSimpleAsyncResult *result;
} NMManagerInitData;

static void
init_async_complete (NMManagerInitData *init_data)
{
	g_simple_async_result_complete (init_data->result);
	g_object_unref (init_data->result);
	g_clear_object (&init_data->cancellable);
	g_slice_free (NMManagerInitData, init_data);
}

static void
init_async_got_permissions (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMManager *manager = user_data;
	GVariant *permissions;

	if (nmdbus_manager_call_get_permissions_finish (NMDBUS_MANAGER (object),
	                                                &permissions,
	                                                result, NULL)) {
		update_permissions (manager, permissions);
		g_variant_unref (permissions);
	} else
		update_permissions (manager, NULL);

	g_object_unref (manager);
}

static void
init_async_parent_inited (GObject *source, GAsyncResult *result, gpointer user_data)
{
	NMManagerInitData *init_data = user_data;
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (init_data->manager);
	GError *error = NULL;

	if (!nm_manager_parent_async_initable_iface->init_finish (G_ASYNC_INITABLE (source), result, &error)) {
		g_simple_async_result_take_error (init_data->result, error);
		init_async_complete (init_data);
		return;
	}

	nmdbus_manager_call_get_permissions (priv->proxy,
	                                     init_data->cancellable,
	                                     init_async_got_permissions,
	                                     g_object_ref (init_data->manager));

	init_async_complete (init_data);
}

static void
init_async (GAsyncInitable *initable, int io_priority,
            GCancellable *cancellable, GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMManagerInitData *init_data;

	init_data = g_slice_new0 (NMManagerInitData);
	init_data->manager = NM_MANAGER (initable);
	init_data->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	init_data->result = g_simple_async_result_new (G_OBJECT (initable), callback,
	                                               user_data, init_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (init_data->result, cancellable);
	g_simple_async_result_set_op_res_gboolean (init_data->result, TRUE);

	nm_manager_parent_async_initable_iface->init_async (initable, io_priority, cancellable,
	                                                   init_async_parent_inited, init_data);
}

static gboolean
init_finish (GAsyncInitable *initable, GAsyncResult *result, GError **error)
{
	GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return TRUE;
}

static void
dispose (GObject *object)
{
	NMManager *manager = NM_MANAGER (object);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (object);

	nm_clear_g_cancellable (&priv->perm_call_cancellable);

	if (priv->devices) {
		g_ptr_array_unref (priv->devices);
		priv->devices = NULL;
	}
	if (priv->all_devices) {
		g_ptr_array_unref (priv->all_devices);
		priv->all_devices = NULL;
	}

	free_active_connections (manager);
	g_clear_object (&priv->primary_connection);
	g_clear_object (&priv->activating_connection);

	g_clear_object (&priv->proxy);

	/* Each activation should hold a ref on @manager, so if we're being disposed,
	 * there shouldn't be any pending.
	 */
	g_warn_if_fail (c_list_is_empty (&priv->pending_activations));

	g_hash_table_destroy (priv->permissions);
	priv->permissions = NULL;

	G_OBJECT_CLASS (nm_manager_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (object);

	g_free (priv->version);

	G_OBJECT_CLASS (nm_manager_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (object);
	gboolean b;

	switch (prop_id) {
	case PROP_NETWORKING_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->networking_enabled != b) {
			nm_manager_networking_set_enabled (NM_MANAGER (object), b, NULL);
			/* Let the property value flip when we get the change signal from NM */
		}
		break;
	case PROP_WIRELESS_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->wireless_enabled != b) {
			nm_manager_wireless_set_enabled (NM_MANAGER (object), b);
			/* Let the property value flip when we get the change signal from NM */
		}
		break;
	case PROP_WWAN_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->wwan_enabled != b) {
			nm_manager_wwan_set_enabled (NM_MANAGER (object), b);
			/* Let the property value flip when we get the change signal from NM */
		}
		break;
	case PROP_WIMAX_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->wimax_enabled != b) {
			nm_manager_wimax_set_enabled (NM_MANAGER (object), b);
			/* Let the property value flip when we get the change signal from NM */
		}
		break;
	case PROP_CONNECTIVITY_CHECK_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->connectivity_check_enabled != b) {
			nm_manager_connectivity_check_set_enabled (NM_MANAGER (object), b);
			/* Let the property value flip when we get the change signal from NM */
		}
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMManager *self = NM_MANAGER (object);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_VERSION:
		g_value_set_string (value, nm_manager_get_version (self));
		break;
	case PROP_STATE:
		g_value_set_enum (value, nm_manager_get_state (self));
		break;
	case PROP_STARTUP:
		g_value_set_boolean (value, nm_manager_get_startup (self));
		break;
	case PROP_NETWORKING_ENABLED:
		g_value_set_boolean (value, nm_manager_networking_get_enabled (self));
		break;
	case PROP_WIRELESS_ENABLED:
		g_value_set_boolean (value, priv->wireless_enabled);
		break;
	case PROP_WIRELESS_HARDWARE_ENABLED:
		g_value_set_boolean (value, priv->wireless_hw_enabled);
		break;
	case PROP_WWAN_ENABLED:
		g_value_set_boolean (value, priv->wwan_enabled);
		break;
	case PROP_WWAN_HARDWARE_ENABLED:
		g_value_set_boolean (value, priv->wwan_hw_enabled);
		break;
	case PROP_WIMAX_ENABLED:
		g_value_set_boolean (value, priv->wimax_enabled);
		break;
	case PROP_WIMAX_HARDWARE_ENABLED:
		g_value_set_boolean (value, priv->wimax_hw_enabled);
		break;
	case PROP_ACTIVE_CONNECTIONS:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_manager_get_active_connections (self)));
		break;
	case PROP_CONNECTIVITY:
		g_value_set_enum (value, priv->connectivity);
		break;
	case PROP_CONNECTIVITY_CHECK_AVAILABLE:
		g_value_set_boolean (value, priv->connectivity_check_available);
		break;
	case PROP_CONNECTIVITY_CHECK_ENABLED:
		g_value_set_boolean (value, priv->connectivity_check_enabled);
		break;
	case PROP_PRIMARY_CONNECTION:
		g_value_set_object (value, priv->primary_connection);
		break;
	case PROP_ACTIVATING_CONNECTION:
		g_value_set_object (value, priv->activating_connection);
		break;
	case PROP_DEVICES:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_manager_get_devices (self)));
		break;
	case PROP_CHECKPOINTS:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_manager_get_checkpoints (self)));
		break;
	case PROP_METERED:
		g_value_set_uint (value, priv->metered);
		break;
	case PROP_ALL_DEVICES:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_manager_get_all_devices (self)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_manager_class_init (NMManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMManagerPrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	nm_object_class->init_dbus = init_dbus;
	nm_object_class->object_creation_failed = object_creation_failed;

	manager_class->device_added = device_added;
	manager_class->device_removed = device_removed;
	manager_class->active_connection_added = active_connection_added;
	manager_class->active_connection_removed = active_connection_removed;
	manager_class->checkpoint_added = checkpoint_added;

	/* properties */

	g_object_class_install_property
		(object_class, PROP_VERSION,
		 g_param_spec_string (NM_MANAGER_VERSION, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_enum (NM_CLIENT_STATE, "", "",
		                    NM_TYPE_STATE,
		                    NM_STATE_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_STARTUP,
		 g_param_spec_boolean (NM_MANAGER_STARTUP, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_NETWORKING_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_NETWORKING_ENABLED, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_WIRELESS_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WIRELESS_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_WIRELESS_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WIRELESS_HARDWARE_ENABLED, "", "",
		                       TRUE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_WWAN_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WWAN_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_WWAN_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WWAN_HARDWARE_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_WIMAX_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WIMAX_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_WIMAX_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WIMAX_HARDWARE_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_ACTIVE_CONNECTIONS,
		 g_param_spec_boxed (NM_MANAGER_ACTIVE_CONNECTIONS, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_CONNECTIVITY,
		 g_param_spec_enum (NM_CLIENT_CONNECTIVITY, "", "",
		                    NM_TYPE_CONNECTIVITY_STATE,
		                    NM_CONNECTIVITY_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_CONNECTIVITY_CHECK_AVAILABLE,
		 g_param_spec_boolean (NM_MANAGER_CONNECTIVITY_CHECK_AVAILABLE, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_CONNECTIVITY_CHECK_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_CONNECTIVITY_CHECK_ENABLED, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_PRIMARY_CONNECTION,
		 g_param_spec_object (NM_MANAGER_PRIMARY_CONNECTION, "", "",
		                      NM_TYPE_ACTIVE_CONNECTION,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_ACTIVATING_CONNECTION,
		 g_param_spec_object (NM_MANAGER_ACTIVATING_CONNECTION, "", "",
		                      NM_TYPE_ACTIVE_CONNECTION,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_DEVICES,
		 g_param_spec_boxed (NM_MANAGER_DEVICES, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_CHECKPOINTS,
		 g_param_spec_boxed (NM_MANAGER_CHECKPOINTS, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));
	/**
	 * NMManager:metered:
	 *
	 * Whether the connectivity is metered.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_METERED,
		 g_param_spec_uint (NM_MANAGER_METERED, "", "",
		                    0, G_MAXUINT32, NM_METERED_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_ALL_DEVICES,
		 g_param_spec_boxed (NM_MANAGER_ALL_DEVICES, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/* signals */

	signals[DEVICE_ADDED] =
		g_signal_new ("device-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMManagerClass, device_added),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);
	signals[DEVICE_REMOVED] =
		g_signal_new ("device-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMManagerClass, device_removed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);
	signals[ANY_DEVICE_ADDED] =
		g_signal_new ("any-device-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0,
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);
	signals[ANY_DEVICE_REMOVED] =
		g_signal_new ("any-device-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0,
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);
	signals[ACTIVE_CONNECTION_ADDED] =
		g_signal_new ("active-connection-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMManagerClass, active_connection_added),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);
	signals[ACTIVE_CONNECTION_REMOVED] =
		g_signal_new ("active-connection-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMManagerClass, active_connection_removed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);
	signals[CHECKPOINT_ADDED] =
		g_signal_new ("checkpoint-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMManagerClass, checkpoint_added),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);
	signals[CHECKPOINT_REMOVED] =
		g_signal_new ("checkpoint-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMManagerClass, checkpoint_removed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_OBJECT);

	signals[PERMISSION_CHANGED] =
		g_signal_new ("permission-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);
}

static void
nm_manager_initable_iface_init (GInitableIface *iface)
{
	nm_manager_parent_initable_iface = g_type_interface_peek_parent (iface);

	iface->init = init_sync;
}

static void
nm_manager_async_initable_iface_init (GAsyncInitableIface *iface)
{
	nm_manager_parent_async_initable_iface = g_type_interface_peek_parent (iface);

	iface->init_async = init_async;
	iface->init_finish = init_finish;
}
