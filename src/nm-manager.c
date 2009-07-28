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
 * Copyright (C) 2007 - 2009 Novell, Inc.
 * Copyright (C) 2007 - 2009 Red Hat, Inc.
 */

#include <netinet/ether.h>
#include <string.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>

#include "nm-glib-compat.h"
#include "nm-manager.h"
#include "nm-utils.h"
#include "nm-dbus-manager.h"
#include "nm-vpn-manager.h"
#include "nm-modem-manager.h"
#include "nm-device-bt.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-device-ethernet.h"
#include "nm-device-wifi.h"
#include "NetworkManagerSystem.h"
#include "nm-properties-changed-signal.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-connection.h"
#include "nm-setting-wireless.h"
#include "nm-setting-vpn.h"
#include "nm-marshal.h"
#include "nm-dbus-glib-types.h"
#include "nm-udev-manager.h"
#include "nm-hostname-provider.h"
#include "nm-bluez-manager.h"
#include "nm-bluez-common.h"
#include "nm-sysconfig-settings.h"
#include "nm-secrets-provider-interface.h"

#define NM_AUTOIP_DBUS_SERVICE "org.freedesktop.nm_avahi_autoipd"
#define NM_AUTOIP_DBUS_IFACE   "org.freedesktop.nm_avahi_autoipd"

static gboolean impl_manager_get_devices (NMManager *manager, GPtrArray **devices, GError **err);
static void impl_manager_activate_connection (NMManager *manager,
								  const char *service_name,
								  const char *connection_path,
								  const char *device_path,
								  const char *specific_object_path,
								  DBusGMethodInvocation *context);

static gboolean impl_manager_deactivate_connection (NMManager *manager,
                                                    const char *connection_path,
                                                    GError **error);

static gboolean impl_manager_sleep (NMManager *manager, gboolean sleep, GError **err);

/* Legacy 0.6 compatibility interface */

static gboolean impl_manager_legacy_sleep (NMManager *manager, GError **err);
static gboolean impl_manager_legacy_wake  (NMManager *manager, GError **err);
static gboolean impl_manager_legacy_state (NMManager *manager, guint32 *state, GError **err);

#include "nm-manager-glue.h"

static void user_destroy_connections (NMManager *manager);
static void manager_set_wireless_enabled (NMManager *manager, gboolean enabled);

static void connection_added_default_handler (NMManager *manager,
									 NMConnection *connection,
									 NMConnectionScope scope);

static void udev_device_added_cb (NMUdevManager *udev_mgr,
                                  GUdevDevice *device,
                                  NMDeviceCreatorFn creator_fn,
                                  gpointer user_data);

static void udev_device_removed_cb (NMUdevManager *udev_mgr,
                                    GUdevDevice *device,
                                    gpointer user_data);

static void udev_manager_rfkill_changed_cb (NMUdevManager *udev_mgr,
                                            RfKillState state,
                                            gpointer user_data);

static void bluez_manager_bdaddr_added_cb (NMBluezManager *bluez_mgr,
					   const char *bdaddr,
					   const char *name,
					   const char *object_path,
					   guint32 uuids,
					   NMManager *manager);

static void bluez_manager_bdaddr_removed_cb (NMBluezManager *bluez_mgr,
					     const char *bdaddr,
					     const char *object_path,
					     gpointer user_data);

static void bluez_manager_resync_devices (NMManager *self);

static void add_device (NMManager *self, NMDevice *device);

static void hostname_provider_init (NMHostnameProvider *provider_class);

#define SSD_POKE_INTERVAL 120
#define ORIGDEV_TAG "originating-device"

typedef struct {
	DBusGMethodInvocation *context;
	NMConnectionScope scope;
	char *connection_path;
	char *specific_object_path;
	char *device_path;
	guint timeout_id;
} PendingConnectionInfo;

typedef struct {
	char *config_file;

	GSList *devices;
	NMState state;

	NMDBusManager *dbus_mgr;
	NMUdevManager *udev_mgr;
	NMBluezManager *bluez_mgr;

	GHashTable *user_connections;
	DBusGProxy *user_proxy;

	GHashTable *system_connections;
	NMSysconfigSettings *sys_settings;
	char *hostname;

	GSList *secrets_calls;

	PendingConnectionInfo *pending_connection_info;
	gboolean wireless_enabled;
	gboolean wireless_hw_enabled;
	gboolean sleeping;

	NMVPNManager *vpn_manager;
	guint vpn_manager_id;

	NMModemManager *modem_manager;
	guint modem_added_id;
	guint modem_removed_id;

	DBusGProxy *aipd_proxy;

	gboolean disposed;
} NMManagerPrivate;

#define NM_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MANAGER, NMManagerPrivate))

G_DEFINE_TYPE_EXTENDED (NMManager, nm_manager, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_HOSTNAME_PROVIDER,
											   hostname_provider_init))

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,
	STATE_CHANGED,
	STATE_CHANGE,  /* DEPRECATED */
	PROPERTIES_CHANGED,
	CONNECTIONS_ADDED,
	CONNECTION_ADDED,
	CONNECTION_UPDATED,
	CONNECTION_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_STATE,
	PROP_WIRELESS_ENABLED,
	PROP_WIRELESS_HARDWARE_ENABLED,
	PROP_ACTIVE_CONNECTIONS,

	/* Not exported */
	PROP_HOSTNAME,

	LAST_PROP
};

typedef enum
{
	NM_MANAGER_ERROR_UNKNOWN_CONNECTION = 0,
	NM_MANAGER_ERROR_UNKNOWN_DEVICE,
	NM_MANAGER_ERROR_UNMANAGED_DEVICE,
	NM_MANAGER_ERROR_INVALID_SERVICE,
	NM_MANAGER_ERROR_SYSTEM_CONNECTION,
	NM_MANAGER_ERROR_PERMISSION_DENIED,
	NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
	NM_MANAGER_ERROR_ALREADY_ASLEEP_OR_AWAKE,
} NMManagerError;

#define NM_MANAGER_ERROR (nm_manager_error_quark ())
#define NM_TYPE_MANAGER_ERROR (nm_manager_error_get_type ()) 

static GQuark
nm_manager_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-manager-error");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GType
nm_manager_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Connection was not provided by any known settings service. */
			ENUM_ENTRY (NM_MANAGER_ERROR_UNKNOWN_CONNECTION, "UnknownConnection"),
			/* Unknown device. */
			ENUM_ENTRY (NM_MANAGER_ERROR_UNKNOWN_DEVICE, "UnknownDevice"),
			/* Unmanaged device. */
			ENUM_ENTRY (NM_MANAGER_ERROR_UNMANAGED_DEVICE, "UnmanagedDevice"),
			/* Invalid settings service (not a recognized system or user
			 * settings service name)
			 */
			ENUM_ENTRY (NM_MANAGER_ERROR_INVALID_SERVICE, "InvalidService"),
			/* Connection was superceded by a system connection. */
			ENUM_ENTRY (NM_MANAGER_ERROR_SYSTEM_CONNECTION, "SystemConnection"),
			/* User does not have the permission to activate this connection. */
			ENUM_ENTRY (NM_MANAGER_ERROR_PERMISSION_DENIED, "PermissionDenied"),
			/* The connection was not active. */
			ENUM_ENTRY (NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE, "ConnectionNotActive"),
			/* The manager is already in the requested sleep state */
			ENUM_ENTRY (NM_MANAGER_ERROR_ALREADY_ASLEEP_OR_AWAKE, "AlreadyAsleepOrAwake"),
			{ 0, 0, 0 },
		};
		etype = g_enum_register_static ("NMManagerError", values);
	}
	return etype;
}

static void
vpn_manager_connection_deactivated_cb (NMVPNManager *manager,
                                       NMVPNConnection *vpn,
                                       NMVPNConnectionState state,
                                       NMVPNConnectionStateReason reason,
                                       gpointer user_data)
{
	g_object_notify (G_OBJECT (user_data), NM_MANAGER_ACTIVE_CONNECTIONS);
}

static void
modem_added (NMModemManager *modem_manager,
			 NMDevice *modem,
			 gpointer user_data)
{
	NMDeviceType type;
	const char *type_name;

	type = nm_device_get_device_type (NM_DEVICE (modem));
	if (type == NM_DEVICE_TYPE_GSM)
		type_name = "GSM modem";
	else if (type == NM_DEVICE_TYPE_CDMA)
		type_name = "CDMA modem";
	else
		type_name = "Unknown modem";

	add_device (NM_MANAGER (user_data), NM_DEVICE (g_object_ref (modem)));
}

static void
nm_manager_update_state (NMManager *manager)
{
	NMManagerPrivate *priv;
	NMState new_state = NM_STATE_DISCONNECTED;

	g_return_if_fail (NM_IS_MANAGER (manager));

	priv = NM_MANAGER_GET_PRIVATE (manager);

	if (priv->sleeping) {
		new_state = NM_STATE_ASLEEP;
	} else {
		GSList *iter;

		for (iter = priv->devices; iter; iter = iter->next) {
			NMDevice *dev = NM_DEVICE (iter->data);

			if (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED) {
				new_state = NM_STATE_CONNECTED;
				break;
			} else if (nm_device_is_activating (dev)) {
				new_state = NM_STATE_CONNECTING;
			}
		}
	}

	if (priv->state != new_state) {
		priv->state = new_state;
		g_object_notify (G_OBJECT (manager), NM_MANAGER_STATE);

		g_signal_emit (manager, signals[STATE_CHANGED], 0, priv->state);

		/* Emit StateChange too for backwards compatibility */
		g_signal_emit (manager, signals[STATE_CHANGE], 0, priv->state);
	}
}

static void
manager_device_state_changed (NMDevice *device,
                              NMDeviceState new_state,
                              NMDeviceState old_state,
                              NMDeviceStateReason reason,
                              gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);

	switch (new_state) {
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_DISCONNECTED:
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_FAILED:
		g_object_notify (G_OBJECT (manager), NM_MANAGER_ACTIVE_CONNECTIONS);
		break;
	default:
		break;
	}

	nm_manager_update_state (manager);
}

/* Removes a device from a device list; returns the start of the new device list */
static GSList *
remove_one_device (NMManager *manager, GSList *list, NMDevice *device)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	if (nm_device_get_managed (device))
		nm_device_set_managed (device, FALSE, NM_DEVICE_STATE_REASON_REMOVED);

	g_signal_handlers_disconnect_by_func (device, manager_device_state_changed, manager);

	nm_sysconfig_settings_device_removed (priv->sys_settings, device);
	g_signal_emit (manager, signals[DEVICE_REMOVED], 0, device);
	g_object_unref (device);

	return g_slist_remove (list, device);
}

static void
modem_removed (NMModemManager *modem_manager,
			   NMDevice *modem,
			   gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	priv->devices = remove_one_device (self, priv->devices, modem);
}

static void
aipd_handle_event (DBusGProxy *proxy,
                   const char *event,
                   const char *iface,
                   const char *address,
                   gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *iter;
	gboolean handled;

	if (!event || !iface) {
		nm_warning ("Incomplete message received from avahi-autoipd");
		return;
	}

	if (   (strcmp (event, "BIND") != 0)
	    && (strcmp (event, "CONFLICT") != 0)
	    && (strcmp (event, "UNBIND") != 0)
	    && (strcmp (event, "STOP") != 0)) {
		nm_warning ("Unknown event '%s' received from avahi-autoipd", event);
		return;
	}

	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *candidate = NM_DEVICE (iter->data);

		if (!strcmp (nm_device_get_iface (candidate), iface)) {
			nm_device_handle_autoip4_event (candidate, event, address);
			handled = TRUE;
			break;
		}
	}

	if (!handled)
		nm_warning ("Unhandled avahi-autoipd event for '%s'", iface);
}

static const char *
hostname_provider_get_hostname (NMHostnameProvider *provider)
{
	return NM_MANAGER_GET_PRIVATE (provider)->hostname;
}

static void
hostname_provider_init (NMHostnameProvider *provider_class)
{
	provider_class->get_hostname = hostname_provider_get_hostname;
}

NMState
nm_manager_get_state (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NM_STATE_UNKNOWN);

	return NM_MANAGER_GET_PRIVATE (manager)->state;
}

static void
emit_removed (gpointer key, gpointer value, gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	NMConnection *connection = NM_CONNECTION (value);

	g_signal_emit (manager, signals[CONNECTION_REMOVED], 0,
	               connection,
	               nm_connection_get_scope (connection));
}

static void
pending_connection_info_destroy (PendingConnectionInfo *info)
{
	if (!info)
		return;

	if (info->timeout_id)
		g_source_remove (info->timeout_id);

	g_free (info->connection_path);
	g_free (info->specific_object_path);
	g_free (info->device_path);

	g_slice_free (PendingConnectionInfo, info);
}

static GPtrArray *
get_active_connections (NMManager *manager, NMConnection *filter)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	NMVPNManager *vpn_manager;
	GPtrArray *active;
	GSList *iter;

 	active = g_ptr_array_sized_new (3);

	/* Add active device connections */
	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMActRequest *req;
		const char *path;

		req = nm_device_get_act_request (NM_DEVICE (iter->data));
		if (!req)
			continue;

		if (!filter || (nm_act_request_get_connection (req) == filter)) {
			path = nm_act_request_get_active_connection_path (req);
			g_ptr_array_add (active, g_strdup (path));
		}
	}

	/* Add active VPN connections */
	vpn_manager = nm_vpn_manager_get ();
	nm_vpn_manager_add_active_connections (vpn_manager, filter, active);
	g_object_unref (vpn_manager);

	return active;
}

static void
remove_connection (NMManager *manager,
                   NMConnection *connection,
                   GHashTable *hash)
{
	/* Destroys the connection, then associated DBusGProxy due to the
	 * weak reference notify function placed on the connection when it
	 * was created.
	 */
	g_object_ref (connection);
	g_hash_table_remove (hash, nm_connection_get_path (connection));
	g_signal_emit (manager, signals[CONNECTION_REMOVED], 0,
	               connection,
	               nm_connection_get_scope (connection));
	g_object_unref (connection);

	bluez_manager_resync_devices (manager);
}

/*******************************************************************/
/* User settings stuff via D-Bus                                   */
/*******************************************************************/

static void
user_destroy_connections (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	if (priv->user_connections) {
		g_hash_table_foreach (priv->user_connections, emit_removed, manager);
		g_hash_table_remove_all (priv->user_connections);
	}

	if (priv->user_proxy) {
		g_object_unref (priv->user_proxy);
		priv->user_proxy = NULL;
	}
}

typedef struct GetSettingsInfo {
	NMManager *manager;
	NMConnection *connection;
	DBusGProxy *proxy;
	DBusGProxyCall *call;
	GSList **calls;
} GetSettingsInfo;

static void
free_get_settings_info (gpointer data)
{
	GetSettingsInfo *info = (GetSettingsInfo *) data;

	/* If this was the last pending call for a batch of GetSettings calls,
	 * send out the connections-added signal.
	 */
	if (info->calls) {
		*(info->calls) = g_slist_remove (*(info->calls), info->call);
		if (g_slist_length (*(info->calls)) == 0) {
			g_slist_free (*(info->calls));
			g_slice_free (GSList, (gpointer) info->calls);
			g_signal_emit (info->manager, signals[CONNECTIONS_ADDED], 0, NM_CONNECTION_SCOPE_USER);

			/* Update the Bluetooth connections for all the new connections */
			bluez_manager_resync_devices (info->manager);
		}
	}

	if (info->manager) {
		g_object_unref (info->manager);
		info->manager = NULL;
	}
	if (info->connection) {
		g_object_unref (info->connection);
		info->connection = NULL;
	}
	if (info->proxy) {
		g_object_unref (info->proxy);
		info->proxy = NULL;
	}

	g_slice_free (GetSettingsInfo, data);	
}

static void
user_connection_get_settings_cb  (DBusGProxy *proxy,
                                  DBusGProxyCall *call_id,
                                  gpointer user_data)
{
	GetSettingsInfo *info = (GetSettingsInfo *) user_data;
	GError *err = NULL;
	GHashTable *settings = NULL;
	NMConnection *connection;
	NMManager *manager;

	g_return_if_fail (info != NULL);

	if (!dbus_g_proxy_end_call (proxy, call_id, &err,
	                            DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, &settings,
	                            G_TYPE_INVALID)) {
		nm_warning ("Couldn't retrieve connection settings: %s.", err->message);
		g_error_free (err);
		goto out;
	}

	manager = info->manager;
	connection = info->connection;
 	if (connection == NULL) {
		const char *path = dbus_g_proxy_get_path (proxy);
		NMManagerPrivate *priv;
		GError *error = NULL;
		NMConnection *existing = NULL;

		connection = nm_connection_new_from_hash (settings, &error);
		if (connection == NULL) {
			nm_warning ("%s: Invalid connection: '%s' / '%s' invalid: %d",
			            __func__,
			            g_type_name (nm_connection_lookup_setting_type_by_quark (error->domain)),
			            error->message, error->code);
			g_error_free (error);
			goto out;
		}

		nm_connection_set_path (connection, path);
		nm_connection_set_scope (connection, NM_CONNECTION_SCOPE_USER);

		/* Add the new connection to the internal hashes only if the same
		 * connection isn't already there.
		 */
		priv = NM_MANAGER_GET_PRIVATE (manager);

		existing = g_hash_table_lookup (priv->user_connections, path);
		if (!existing || !nm_connection_compare (existing, connection, NM_SETTING_COMPARE_FLAG_EXACT)) {
			g_hash_table_insert (priv->user_connections,
			                     g_strdup (path),
			                     connection);
			existing = NULL;

			/* Attach the D-Bus proxy representing the remote NMConnection
			 * to the local NMConnection object to ensure it stays alive to
			 * continue delivering signals.  It'll be destroyed once the
			 * NMConnection is destroyed.
			 */
			g_object_set_data_full (G_OBJECT (connection),
			                        "proxy",
			                        g_object_ref (info->proxy),
									g_object_unref);
		} else
			g_object_unref (connection);

		/* If the connection-added signal is supposed to be batched, don't
		 * emit the single connection-added here.  Also, don't emit the signal
		 * if the connection wasn't actually added to the system or user hashes.
		 */
		if (!info->calls && !existing) {
			g_signal_emit (manager, signals[CONNECTION_ADDED], 0, connection, NM_CONNECTION_SCOPE_USER);
			/* Update the Bluetooth connections for that single new connection */
			bluez_manager_resync_devices (manager);
		}
	} else {
		// FIXME: merge settings? or just replace?
		nm_warning ("%s (#%d): implement merge settings", __func__, __LINE__);
	}

out:
	if (settings)
		g_hash_table_destroy (settings);

	return;
}

static void
user_connection_removed_cb (DBusGProxy *proxy, gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	NMConnection *connection = NULL;
	const char *path;

	path = dbus_g_proxy_get_path (proxy);
	if (path) {
		connection = g_hash_table_lookup (priv->user_connections, path);
		if (connection)
			remove_connection (manager, connection, priv->user_connections);
	}
}

static void
user_connection_updated_cb (DBusGProxy *proxy,
                            GHashTable *settings,
                            gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	NMConnection *new_connection;
	NMConnection *old_connection = NULL;
	gboolean valid = FALSE;
	GError *error = NULL;
	const char *path;

	path = dbus_g_proxy_get_path (proxy);
	if (path)
		old_connection = g_hash_table_lookup (priv->user_connections, path);

	g_return_if_fail (old_connection != NULL);

	new_connection = nm_connection_new_from_hash (settings, &error);
	if (!new_connection) {
		/* New connection invalid, remove existing connection */
		nm_warning ("%s: Invalid connection: '%s' / '%s' invalid: %d",
		            __func__,
		            g_type_name (nm_connection_lookup_setting_type_by_quark (error->domain)),
		            error->message, error->code);
		g_error_free (error);
		remove_connection (manager, old_connection, priv->user_connections);
		return;
	}
	g_object_unref (new_connection);

	valid = nm_connection_replace_settings (old_connection, settings, NULL);
	if (valid) {
		g_signal_emit (manager, signals[CONNECTION_UPDATED], 0,
		               old_connection,
		               nm_connection_get_scope (old_connection));

		bluez_manager_resync_devices (manager);
	} else {
		remove_connection (manager, old_connection, priv->user_connections);
	}
}

static void
user_internal_new_connection_cb (DBusGProxy *proxy,
                                 const char *path,
                                 NMManager *manager,
                                 GSList **calls)
{
	struct GetSettingsInfo *info;
	DBusGProxy *con_proxy;
	DBusGConnection *g_connection;
	DBusGProxyCall *call;
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	con_proxy = dbus_g_proxy_new_for_name (g_connection,
	                                       dbus_g_proxy_get_bus_name (proxy),
	                                       path,
	                                       NM_DBUS_IFACE_SETTINGS_CONNECTION);
	if (!con_proxy) {
		nm_warning ("Error: could not init user connection proxy");
		return;
	}

	dbus_g_proxy_add_signal (con_proxy, "Updated",
	                         DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (con_proxy, "Updated",
	                             G_CALLBACK (user_connection_updated_cb),
	                             manager,
	                             NULL);

	dbus_g_proxy_add_signal (con_proxy, "Removed", G_TYPE_INVALID, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (con_proxy, "Removed",
	                             G_CALLBACK (user_connection_removed_cb),
	                             manager,
	                             NULL);

	info = g_slice_new0 (GetSettingsInfo);
	info->manager = g_object_ref (manager);
	info->calls = calls;
	call = dbus_g_proxy_begin_call (con_proxy, "GetSettings",
	                                user_connection_get_settings_cb,
	                                info,
	                                free_get_settings_info,
	                                G_TYPE_INVALID);
	info->call = call;
	info->proxy = con_proxy;
	if (info->calls)
		*(info->calls) = g_slist_prepend (*(info->calls), call);
}

static void
user_list_connections_cb  (DBusGProxy *proxy,
                           DBusGProxyCall *call_id,
                           gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	GError *err = NULL;
	GPtrArray *ops;
	GSList **calls = NULL;
	int i;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err,
	                            DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH, &ops,
	                            G_TYPE_INVALID)) {
		nm_warning ("Couldn't retrieve connections: %s.", err->message);
		g_error_free (err);
		goto out;
	}

	/* Keep track of all calls made here; don't want to emit connection-added for
	 * each one, but emit connections-added when they are all done.
	 */
	calls = g_slice_new0 (GSList *);

	for (i = 0; i < ops->len; i++) {
		char *op = g_ptr_array_index (ops, i);

		user_internal_new_connection_cb (proxy, op, manager, calls);
		g_free (op);
	}

	g_ptr_array_free (ops, TRUE);

out:
	return;
}

static void
user_new_connection_cb (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	user_internal_new_connection_cb (proxy, path, NM_MANAGER (user_data), NULL);
}

static void
user_query_connections (NMManager *manager)
{
	NMManagerPrivate *priv;
	DBusGProxyCall *call;
	DBusGConnection *g_connection;

	g_return_if_fail (NM_IS_MANAGER (manager));

	priv = NM_MANAGER_GET_PRIVATE (manager);
	if (!priv->user_proxy) {
		g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
		priv->user_proxy = dbus_g_proxy_new_for_name (g_connection,
		                                              NM_DBUS_SERVICE_USER_SETTINGS,
		                                              NM_DBUS_PATH_SETTINGS,
		                                              NM_DBUS_IFACE_SETTINGS);
		if (!priv->user_proxy) {
			nm_warning ("Error: could not init settings proxy");
			return;
		}

		dbus_g_proxy_add_signal (priv->user_proxy,
		                         "NewConnection",
		                         DBUS_TYPE_G_OBJECT_PATH,
		                         G_TYPE_INVALID);

		dbus_g_proxy_connect_signal (priv->user_proxy, "NewConnection",
		                             G_CALLBACK (user_new_connection_cb),
		                             manager,
		                             NULL);
	}

	/* grab connections */
	call = dbus_g_proxy_begin_call (priv->user_proxy, "ListConnections",
	                                user_list_connections_cb,
	                                manager,
	                                NULL,
	                                G_TYPE_INVALID);
}

/*******************************************************************/
/* System settings stuff via NMSysconfigSettings                   */
/*******************************************************************/

static void
system_connection_updated_cb (NMExportedConnection *exported,
                              gpointer unused,
                              NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	const char *path;
	NMConnection *existing;
	NMConnection *connection;
	GError *error = NULL;

	connection = nm_exported_connection_get_connection (exported);
	path = nm_connection_get_path (connection);

	existing = g_hash_table_lookup (priv->system_connections, path);
	if (!existing)
		return;
	if (existing != connection) {
		g_warning ("%s: existing connection didn't matched updated.", __func__);
		return;
	}

	if (!nm_connection_verify (existing, &error)) {
		/* Updated connection invalid, remove existing connection */
		nm_warning ("%s: Invalid connection: '%s' / '%s' invalid: %d",
		            __func__,
		            g_type_name (nm_connection_lookup_setting_type_by_quark (error->domain)),
		            error->message, error->code);
		g_error_free (error);
		remove_connection (manager, existing, priv->system_connections);
		return;
	}

	g_signal_emit (manager, signals[CONNECTION_UPDATED], 0,
	               existing, NM_CONNECTION_SCOPE_SYSTEM);

	bluez_manager_resync_devices (manager);
}

static void
system_connection_removed_cb (NMExportedConnection *exported,
                              NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	const char *path;
	NMConnection *connection;

	connection = nm_exported_connection_get_connection (exported);
	path = nm_connection_get_path (connection);

	connection = g_hash_table_lookup (priv->system_connections, path);
	if (connection)
		remove_connection (manager, connection, priv->system_connections);
}

static void
system_internal_new_connection (NMManager *manager,
                                NMExportedConnection *exported)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	NMConnection *connection;
	const char *path;

	g_return_if_fail (exported != NULL);

	g_signal_connect (exported, "updated",
	                  G_CALLBACK (system_connection_updated_cb), manager);
	g_signal_connect (exported, "removed",
	                  G_CALLBACK (system_connection_removed_cb), manager);

	connection = nm_exported_connection_get_connection (exported);
	path = nm_connection_get_path (NM_CONNECTION (connection));
	g_hash_table_insert (priv->system_connections, g_strdup (path),
	                     g_object_ref (connection));
}

static void
system_new_connection_cb (NMSysconfigSettings *settings,
                          NMExportedConnection *exported,
                          NMManager *manager)
{
	system_internal_new_connection (manager, exported);
}

static void
system_query_connections (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *system_connections, *iter;

	system_connections = nm_sysconfig_settings_list_connections (priv->sys_settings);
	for (iter = system_connections; iter; iter = g_slist_next (iter))
		system_internal_new_connection (manager, NM_EXPORTED_CONNECTION (iter->data));
	g_slist_free (system_connections);
}

static void
system_unmanaged_devices_changed_cb (NMSysconfigSettings *sys_settings,
                                     GParamSpec *pspec,
                                     gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	const GSList *unmanaged_specs, *iter;

	unmanaged_specs = nm_sysconfig_settings_get_unmanaged_specs (sys_settings);
	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *device = NM_DEVICE (iter->data);
		gboolean managed;

		managed = !nm_device_interface_spec_match_list (NM_DEVICE_INTERFACE (device), unmanaged_specs);
		nm_device_set_managed (device,
		                       managed,
		                       managed ? NM_DEVICE_STATE_REASON_NOW_MANAGED :
		                                   NM_DEVICE_STATE_REASON_NOW_UNMANAGED);
	}
}

static void
system_hostname_changed_cb (NMSysconfigSettings *sys_settings,
                            GParamSpec *pspec,
                            gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	char *hostname;

	hostname = nm_sysconfig_settings_get_hostname (sys_settings);

	if (!hostname && !priv->hostname)
		return;

	if (hostname && priv->hostname && !strcmp (hostname, priv->hostname))
		return;

	g_free (priv->hostname);
	priv->hostname = (hostname && strlen (hostname)) ? g_strdup (hostname) : NULL;
	g_object_notify (G_OBJECT (manager), NM_MANAGER_HOSTNAME);

	g_free (hostname);
}

/*******************************************************************/
/* General NMManager stuff                                         */
/*******************************************************************/

static NMDevice *
nm_manager_get_device_by_udi (NMManager *manager, const char *udi)
{
	GSList *iter;

	for (iter = NM_MANAGER_GET_PRIVATE (manager)->devices; iter; iter = iter->next) {
		if (!strcmp (nm_device_get_udi (NM_DEVICE (iter->data)), udi))
			return NM_DEVICE (iter->data);
	}
	return NULL;
}

static NMDevice *
nm_manager_get_device_by_path (NMManager *manager, const char *path)
{
	GSList *iter;

	for (iter = NM_MANAGER_GET_PRIVATE (manager)->devices; iter; iter = iter->next) {
		if (!strcmp (nm_device_get_path (NM_DEVICE (iter->data)), path))
			return NM_DEVICE (iter->data);
	}
	return NULL;
}

static void
nm_manager_name_owner_changed (NMDBusManager *mgr,
                               const char *name,
                               const char *old,
                               const char *new,
                               gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	gboolean old_owner_good = (old && (strlen (old) > 0));
	gboolean new_owner_good = (new && (strlen (new) > 0));

	if (strcmp (name, NM_DBUS_SERVICE_USER_SETTINGS) == 0) {
		if (!old_owner_good && new_owner_good) {
			/* User Settings service appeared, update stuff */
			user_query_connections (manager);
		} else {
			/* User Settings service disappeared, throw them away (?) */
			user_destroy_connections (manager);
			bluez_manager_resync_devices (manager);
		}
	}
}

static void
manager_set_wireless_enabled (NMManager *manager, gboolean enabled)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *iter;

	if (priv->wireless_enabled == enabled)
		return;

	/* Can't set wireless enabled if it's disabled in hardware */
	if (!priv->wireless_hw_enabled && enabled)
		return;

	priv->wireless_enabled = enabled;

	g_object_notify (G_OBJECT (manager), NM_MANAGER_WIRELESS_ENABLED);

	/* Don't touch devices if asleep/networking disabled */
	if (priv->sleeping)
		return;

	/* enable/disable wireless devices as required */
	for (iter = priv->devices; iter; iter = iter->next) {
		if (NM_IS_DEVICE_WIFI (iter->data))
			nm_device_wifi_set_enabled (NM_DEVICE_WIFI (iter->data), enabled);
	}
}

static void
manager_hidden_ap_found (NMDeviceInterface *device,
                         NMAccessPoint *ap,
                         gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	const struct ether_addr *ap_addr;
	const GByteArray *ap_ssid;
	GSList *iter;
	GSList *connections;
	gboolean done = FALSE;

	ap_ssid = nm_ap_get_ssid (ap);
	if (ap_ssid && ap_ssid->len)
		return;

	ap_addr = nm_ap_get_address (ap);
	g_assert (ap_addr);

	/* Look for this AP's BSSID in the seen-bssids list of a connection,
	 * and if a match is found, copy over the SSID */
	connections = nm_manager_get_connections (manager, NM_CONNECTION_SCOPE_SYSTEM);
	connections = g_slist_concat (connections,  nm_manager_get_connections (manager, NM_CONNECTION_SCOPE_USER));

	for (iter = connections; iter && !done; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingWireless *s_wireless;
		const GByteArray *ssid;
		guint32 num_bssids;
		guint32 i;

		s_wireless = (NMSettingWireless *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS);
		if (!s_wireless)
			goto next;

		num_bssids = nm_setting_wireless_get_num_seen_bssids (s_wireless);
		if (num_bssids < 1)
			goto next;

		ssid = nm_setting_wireless_get_ssid (s_wireless);
		g_assert (ssid);

		for (i = 0; i < num_bssids; i++) {
			const char *seen_bssid = nm_setting_wireless_get_seen_bssid (s_wireless, i);
			struct ether_addr seen_addr;

			if (!ether_aton_r (seen_bssid, &seen_addr))
				continue;

			if (memcmp (ap_addr, &seen_addr, sizeof (struct ether_addr)))
				continue;

			/* Copy the SSID from the connection to the AP */
			nm_ap_set_ssid (ap, ssid);
			done = TRUE;
		}

next:
		g_object_unref (connection);
	}
	g_slist_free (connections);
}

static void
add_device (NMManager *self, NMDevice *device)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	const char *iface, *driver, *type_desc;
	char *path;
	static guint32 devcount = 0;
	const GSList *unmanaged_specs;

	priv->devices = g_slist_append (priv->devices, device);

	g_signal_connect (device, "state-changed",
					  G_CALLBACK (manager_device_state_changed),
					  self);

	/* Attach to the access-point-added signal so that the manager can fill
	 * non-SSID-broadcasting APs with an SSID.
	 */
	if (NM_IS_DEVICE_WIFI (device)) {
		g_signal_connect (device, "hidden-ap-found",
						  G_CALLBACK (manager_hidden_ap_found),
						  self);

		/* Set initial rfkill state */
		nm_device_wifi_set_enabled (NM_DEVICE_WIFI (device), priv->wireless_enabled);
	}

	type_desc = nm_device_get_type_desc (device);
	g_assert (type_desc);
	iface = nm_device_get_iface (device);
	g_assert (iface);
	driver = nm_device_get_driver (device);
	if (!driver)
		driver = "unknown";
	nm_info ("(%s): new %s device (driver: '%s')", iface, type_desc, driver);

	path = g_strdup_printf ("/org/freedesktop/NetworkManager/Devices/%d", devcount++);
	nm_device_set_path (device, path);
	dbus_g_connection_register_g_object (nm_dbus_manager_get_connection (priv->dbus_mgr),
	                                     path,
	                                     G_OBJECT (device));
	nm_info ("(%s): exported as %s", iface, path);
	g_free (path);

	/* Start the device if it's supposed to be managed */
	unmanaged_specs = nm_sysconfig_settings_get_unmanaged_specs (priv->sys_settings);
	if (!priv->sleeping && !nm_device_interface_spec_match_list (NM_DEVICE_INTERFACE (device), unmanaged_specs))
		nm_device_set_managed (device, TRUE, NM_DEVICE_STATE_REASON_NOW_MANAGED);

	nm_sysconfig_settings_device_added (priv->sys_settings, device);
	g_signal_emit (self, signals[DEVICE_ADDED], 0, device);
}

static gboolean
bdaddr_matches_connection (NMSettingBluetooth *s_bt, const char *bdaddr)
{
	const GByteArray *arr;
	gboolean ret = FALSE;

	arr = nm_setting_bluetooth_get_bdaddr (s_bt);

	if (   arr != NULL 
	       && arr->len == ETH_ALEN) {
		char *str;

		str = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
				       arr->data[0],
				       arr->data[1],
				       arr->data[2],
				       arr->data[3],
				       arr->data[4],
				       arr->data[5]);
		ret = g_str_equal (str, bdaddr);
		g_free (str);
	}

	return ret;
}

static NMConnection *
bluez_manager_find_connection (NMManager *manager,
                               const char *bdaddr,
                               guint32 capabilities)
{
	NMConnection *found = NULL;
	GSList *connections, *l;

	connections = nm_manager_get_connections (manager, NM_CONNECTION_SCOPE_SYSTEM);
	connections = g_slist_concat (connections, nm_manager_get_connections (manager, NM_CONNECTION_SCOPE_USER));

	for (l = connections; l != NULL; l = l->next) {
		NMConnection *candidate = NM_CONNECTION (l->data);
		NMSettingConnection *s_con;
		NMSettingBluetooth *s_bt;
		const char *con_type;
		const char *bt_type;

		s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (candidate, NM_TYPE_SETTING_CONNECTION));
		g_assert (s_con);
		con_type = nm_setting_connection_get_connection_type (s_con);
		g_assert (con_type);
		if (!g_str_equal (con_type, NM_SETTING_BLUETOOTH_SETTING_NAME))
			continue;

		s_bt = (NMSettingBluetooth *) nm_connection_get_setting (candidate, NM_TYPE_SETTING_BLUETOOTH);
		if (!s_bt)
			continue;

		if (!bdaddr_matches_connection (s_bt, bdaddr))
			continue;

		bt_type = nm_setting_bluetooth_get_connection_type (s_bt);
		if (   g_str_equal (bt_type, NM_SETTING_BLUETOOTH_TYPE_DUN)
		    && !(capabilities & NM_BT_CAPABILITY_DUN))
		    	continue;
		if (   g_str_equal (bt_type, NM_SETTING_BLUETOOTH_TYPE_PANU)
		    && !(capabilities & NM_BT_CAPABILITY_NAP))
		    	continue;

		found = candidate;
		break;
	}

	g_slist_free (connections);
	return found;
}

static void
bluez_manager_resync_devices (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter, *gone = NULL, *keep = NULL;

	/* Remove devices from the device list that don't have a corresponding connection */
	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *candidate = NM_DEVICE (iter->data);
		guint32 uuids;
		const char *bdaddr;

		if (NM_IS_DEVICE_BT (candidate)) {
			uuids = nm_device_bt_get_capabilities (NM_DEVICE_BT (candidate));
			bdaddr = nm_device_bt_get_hw_address (NM_DEVICE_BT (candidate));

			if (bluez_manager_find_connection (self, bdaddr, uuids))
				keep = g_slist_prepend (keep, candidate);
			else
				gone = g_slist_prepend (gone, candidate);
		} else
			keep = g_slist_prepend (keep, candidate);
	}

	/* Only touch the device list if anything actually changed */
	if (g_slist_length (gone)) {
		g_slist_free (priv->devices);
		priv->devices = keep;

		while (g_slist_length (gone))
			gone = remove_one_device (self, gone, NM_DEVICE (gone->data));
	} else {
		g_slist_free (keep);
		g_slist_free (gone);
	}

	/* Now look for devices without connections */
	nm_bluez_manager_query_devices (priv->bluez_mgr);
}

static void
bluez_manager_bdaddr_added_cb (NMBluezManager *bluez_mgr,
                               const char *bdaddr,
                               const char *name,
                               const char *object_path,
                               guint32 capabilities,
                               NMManager *manager)
{
	NMDevice *device;
	gboolean has_dun = (capabilities & NM_BT_CAPABILITY_DUN);
	gboolean has_nap = (capabilities & NM_BT_CAPABILITY_NAP);

	g_return_if_fail (bdaddr != NULL);
	g_return_if_fail (name != NULL);
	g_return_if_fail (object_path != NULL);
	g_return_if_fail (capabilities != NM_BT_CAPABILITY_NONE);

	/* Make sure the device is not already in the device list */
	if (nm_manager_get_device_by_udi (manager, object_path))
		return;

	if (has_dun == FALSE && has_nap == FALSE)
		return;

	if (!bluez_manager_find_connection (manager, bdaddr, capabilities))
		return;

	device = nm_device_bt_new (object_path, bdaddr, name, capabilities, FALSE);
	if (device) {
		g_message ("%s: BT device %s (%s) added (%s%s%s)",
		           __func__,
		           name,
		           bdaddr,
		           has_dun ? "DUN" : "",
		           has_dun && has_nap ? " " : "",
		           has_nap ? "NAP" : "");

		add_device (manager, device);
	}
}

static void
bluez_manager_bdaddr_removed_cb (NMBluezManager *bluez_mgr,
                                 const char *bdaddr,
                                 const char *object_path,
                                 gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	g_return_if_fail (bdaddr != NULL);
	g_return_if_fail (object_path != NULL);

	g_message ("%s: BT device %s removed", __func__, bdaddr);

	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (!strcmp (nm_device_get_udi (device), object_path)) {
			priv->devices = remove_one_device (self, priv->devices, device);
			break;
		}
	}
}

static NMDevice *
find_device_by_ifindex (NMManager *self, guint32 ifindex)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *device = NM_DEVICE (iter->data);
		gint candidate_idx = 0;

		if (NM_IS_DEVICE_ETHERNET (device))
			candidate_idx = nm_device_ethernet_get_ifindex (NM_DEVICE_ETHERNET (device));
		else if (NM_IS_DEVICE_WIFI (device))
			candidate_idx = nm_device_wifi_get_ifindex (NM_DEVICE_WIFI (device));

		if (candidate_idx == ifindex)
			return device;
	}

	return NULL;
}

static void
udev_device_added_cb (NMUdevManager *udev_mgr,
                      GUdevDevice *udev_device,
                      NMDeviceCreatorFn creator_fn,
                      gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GObject *device;
	guint32 ifindex;

	ifindex = g_udev_device_get_property_as_int (udev_device, "IFINDEX");
	if (find_device_by_ifindex (self, ifindex))
		return;

	device = creator_fn (udev_mgr, udev_device, priv->sleeping);
	if (device)
		add_device (self, NM_DEVICE (device));
}

static void
udev_device_removed_cb (NMUdevManager *manager,
                        GUdevDevice *udev_device,
                        gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMDevice *device;
	guint32 ifindex;

	ifindex = g_udev_device_get_property_as_int (udev_device, "IFINDEX");
	device = find_device_by_ifindex (self, ifindex);
	if (device)
		priv->devices = remove_one_device (self, priv->devices, device);

}

static void
udev_manager_rfkill_changed_cb (NMUdevManager *udev_mgr,
                                RfKillState state,
                                gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	gboolean new_we = TRUE, new_whe = TRUE;

	switch (state) {
	case RFKILL_UNBLOCKED:
		new_we = TRUE;
		new_whe = TRUE;
		break;
	case RFKILL_SOFT_BLOCKED:
		new_we = FALSE;
		new_whe = TRUE;
		break;
	case RFKILL_HARD_BLOCKED:
		new_we = FALSE;
		new_whe = FALSE;
		break;
	default:
		break;
	}	

	nm_info ("Wireless now %s by radio killswitch",
	         (new_we && new_whe) ? "enabled" : "disabled");
	if (new_whe != priv->wireless_hw_enabled) {
		priv->wireless_hw_enabled = new_whe;
		g_object_notify (G_OBJECT (self), NM_MANAGER_WIRELESS_HARDWARE_ENABLED);
	}
	manager_set_wireless_enabled (self, new_we);
}

GSList *
nm_manager_get_devices (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	return NM_MANAGER_GET_PRIVATE (manager)->devices;
}

static gboolean
impl_manager_get_devices (NMManager *manager, GPtrArray **devices, GError **err)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *iter;

	*devices = g_ptr_array_sized_new (g_slist_length (priv->devices));

	for (iter = priv->devices; iter; iter = iter->next)
		g_ptr_array_add (*devices, g_strdup (nm_device_get_path (NM_DEVICE (iter->data))));

	return TRUE;
}

static NMActRequest *
nm_manager_get_act_request_by_path (NMManager *manager,
                                    const char *path,
                                    NMDevice **device)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *iter;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (device != NULL, NULL);
	g_return_val_if_fail (*device == NULL, NULL);

	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMActRequest *req;
		const char *ac_path;

		req = nm_device_get_act_request (NM_DEVICE (iter->data));
		if (!req)
			continue;

		ac_path = nm_act_request_get_active_connection_path (req);
		if (!strcmp (path, ac_path)) {
			*device = NM_DEVICE (iter->data);
			return req;
		}
	}

	return NULL;
}

typedef struct GetSecretsInfo {
	NMManager *manager;
	NMSecretsProviderInterface *provider;

	char *setting_name;
	RequestSecretsCaller caller;
	gboolean request_new;

	/* User connection bits */
	DBusGProxy *proxy;
	DBusGProxyCall *call;

	/* System connection bits */
	guint32 idle_id;
	char *hint1;
	char *hint2;
	char *connection_path;
} GetSecretsInfo;

static void
free_get_secrets_info (gpointer data)
{
	GetSecretsInfo *info = data;
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (info->manager);

	g_object_weak_unref (G_OBJECT (info->provider), (GWeakNotify) free_get_secrets_info, info);

	priv->secrets_calls = g_slist_remove (priv->secrets_calls, info);

	if (info->proxy) {
		if (info->call)
			dbus_g_proxy_cancel_call (info->proxy, info->call);
		g_object_unref (info->proxy);
	}

	if (info->idle_id)
		g_source_remove (info->idle_id);

	g_free (info->hint1);
	g_free (info->hint2);
	g_free (info->setting_name);
	g_free (info->connection_path);
	memset (info, 0, sizeof (GetSecretsInfo));
	g_free (info);
}

static void
provider_cancel_secrets (NMSecretsProviderInterface *provider, gpointer user_data)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (user_data);
	GSList *iter;

	for (iter = priv->secrets_calls; iter; iter = g_slist_next (iter)) {
		GetSecretsInfo *candidate = iter->data;

		if (candidate->provider == provider) {
			free_get_secrets_info (candidate);
			break;
		}
	}
}

static void
user_get_secrets_cb (DBusGProxy *proxy,
                     DBusGProxyCall *call,
                     gpointer user_data)
{
	GetSecretsInfo *info = (GetSecretsInfo *) user_data;
	NMManagerPrivate *priv;
	GHashTable *settings = NULL;
	GError *error = NULL;

	g_return_if_fail (info != NULL);
	g_return_if_fail (info->provider);
	g_return_if_fail (info->setting_name);

	priv = NM_MANAGER_GET_PRIVATE (info->manager);

	if (dbus_g_proxy_end_call (proxy, call, &error,
	                           DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, &settings,
	                           G_TYPE_INVALID)) {
		nm_secrets_provider_interface_get_secrets_result (info->provider,
		                                                  info->setting_name,
		                                                  info->caller,
		                                                  settings,
		                                                  NULL);
		g_hash_table_destroy (settings);
	} else {
		nm_secrets_provider_interface_get_secrets_result (info->provider,
		                                                  info->setting_name,
		                                                  info->caller,
		                                                  NULL,
		                                                  error);
		g_clear_error (&error);
	}

	info->call = NULL;
	free_get_secrets_info (info);
}

static GetSecretsInfo *
user_get_secrets (NMManager *self,
                  NMSecretsProviderInterface *provider,
                  NMConnection *connection,
                  const char *setting_name,
                  gboolean request_new,
                  RequestSecretsCaller caller_id,
                  const char *hint1,
                  const char *hint2)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	DBusGConnection *g_connection;
	GetSecretsInfo *info = NULL;
	GPtrArray *hints = NULL;

	info = g_malloc0 (sizeof (GetSecretsInfo));

	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	info->proxy = dbus_g_proxy_new_for_name (g_connection,
	                                         NM_DBUS_SERVICE_USER_SETTINGS,
	                                         nm_connection_get_path (connection),
	                                         NM_DBUS_IFACE_SETTINGS_CONNECTION_SECRETS);
	if (!info->proxy) {
		nm_warning ("%s: could not create user connection secrets proxy", __func__);
		g_free (info);
		return NULL;
	}

	info->manager = self;
	info->provider = provider;
	info->caller = caller_id;
	info->setting_name = g_strdup (setting_name);

	g_object_weak_ref (G_OBJECT (provider), (GWeakNotify) free_get_secrets_info, info);

	hints = g_ptr_array_sized_new (2);
	if (hint1)
		g_ptr_array_add (hints, (char *) hint1);
	if (hint2)
		g_ptr_array_add (hints, (char *) hint2);

	info->call = dbus_g_proxy_begin_call_with_timeout (info->proxy, "GetSecrets",
	                                                   user_get_secrets_cb,
	                                                   info,
	                                                   NULL,
	                                                   G_MAXINT32,
	                                                   G_TYPE_STRING, setting_name,
	                                                   DBUS_TYPE_G_ARRAY_OF_STRING, hints,
	                                                   G_TYPE_BOOLEAN, request_new,
	                                                   G_TYPE_INVALID);
	g_ptr_array_free (hints, TRUE);
	return info;
}

static gboolean
system_get_secrets_cb (gpointer user_data)
{
	GetSecretsInfo *info = user_data;
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (info->manager);
	GHashTable *settings;
	NMSysconfigConnection *exported;
	GError *error = NULL;
	const char *hints[3] = { NULL, NULL, NULL };

	exported = nm_sysconfig_settings_get_connection_by_path (priv->sys_settings, 
	                                                         info->connection_path);
	if (!exported) {
		g_set_error (&error, 0, 0, "%s", "unknown connection (not exported by "
		             "system settings)");
		nm_secrets_provider_interface_get_secrets_result (info->provider,
		                                                  info->setting_name,
		                                                  info->caller,
		                                                  NULL,
		                                                  error);
		g_clear_error (&error);
		return FALSE;
	}

	hints[0] = info->hint1;
	hints[1] = info->hint2;
	settings = nm_sysconfig_connection_get_secrets (exported,
	                                                info->setting_name,
	                                                hints,
	                                                info->request_new,
	                                                &error);
	nm_secrets_provider_interface_get_secrets_result (info->provider,
	                                                  info->setting_name,
	                                                  info->caller,
	                                                  settings,
	                                                  NULL);
	g_hash_table_destroy (settings);
	return FALSE;
}

static GetSecretsInfo *
system_get_secrets (NMManager *self,
                    NMSecretsProviderInterface *provider,
                    NMConnection *connection,
                    const char *setting_name,
                    gboolean request_new,
                    RequestSecretsCaller caller_id,
                    const char *hint1,
                    const char *hint2)
{
	GetSecretsInfo *info;

	info = g_malloc0 (sizeof (GetSecretsInfo));
	info->manager = self;
	info->provider = provider;
	info->caller = caller_id;
	info->setting_name = g_strdup (setting_name);
	info->hint1 = hint1 ? g_strdup (hint1) : NULL;
	info->hint2 = hint2 ? g_strdup (hint2) : NULL;
	info->connection_path = g_strdup (nm_connection_get_path (connection));
	info->request_new = request_new;

	g_object_weak_ref (G_OBJECT (provider), (GWeakNotify) free_get_secrets_info, info);

	info->idle_id = g_idle_add_full (G_PRIORITY_DEFAULT_IDLE,
	                                 system_get_secrets_cb,
	                                 info,
	                                 free_get_secrets_info);
	return info;
}

static gboolean
provider_get_secrets (NMSecretsProviderInterface *provider,
                      NMConnection *connection,
                      const char *setting_name,
                      gboolean request_new,
                      RequestSecretsCaller caller_id,
                      const char *hint1,
                      const char *hint2,
                      gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GetSecretsInfo *info = NULL;
	NMConnectionScope scope;
	GSList *iter;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (setting_name != NULL, FALSE);

	/* Tear down any pending secrets requests for this secrets provider */
	for (iter = priv->secrets_calls; iter; iter = g_slist_next (iter)) {
		GetSecretsInfo *candidate = iter->data;

		if (provider == candidate->provider) {
			free_get_secrets_info (candidate);
			break;
		}
	}

	/* Build up the new secrets request */
	scope = nm_connection_get_scope (connection);
	if (scope == NM_CONNECTION_SCOPE_SYSTEM) {
		info = system_get_secrets (self, provider, connection, setting_name,
		                           request_new, caller_id, hint1, hint2);
	} else if (scope == NM_CONNECTION_SCOPE_USER) {
		info = user_get_secrets (self, provider, connection, setting_name,
		                         request_new, caller_id, hint1, hint2);
	}

	if (info)
		priv->secrets_calls = g_slist_append (priv->secrets_calls, info);

	return !!info;
}

static const char *
internal_activate_device (NMManager *manager,
                          NMDevice *device,
                          NMConnection *connection,
                          const char *specific_object,
                          gboolean user_requested,
                          GError **error)
{
	NMActRequest *req;
	NMDeviceInterface *dev_iface;
	gboolean success;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	dev_iface = NM_DEVICE_INTERFACE (device);

	/* Ensure the requested connection is compatible with the device */
	if (!nm_device_interface_check_connection_compatible (dev_iface, connection, error))
		return NULL;

	/* Tear down any existing connection */
	if (nm_device_get_act_request (device)) {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_DISCONNECTED,
		                         NM_DEVICE_STATE_REASON_NONE);
	}

	req = nm_act_request_new (connection, specific_object, user_requested, (gpointer) device);
	g_signal_connect (req, "manager-get-secrets", G_CALLBACK (provider_get_secrets), manager);
	g_signal_connect (req, "manager-cancel-secrets", G_CALLBACK (provider_cancel_secrets), manager);
	success = nm_device_interface_activate (dev_iface, req, error);
	g_object_unref (req);

	return success ? nm_act_request_get_active_connection_path (req) : NULL;
}

static gboolean
wait_for_connection_expired (gpointer data)
{
	NMManager *manager = NM_MANAGER (data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	PendingConnectionInfo *info = priv->pending_connection_info;
	GError *error = NULL;

	g_return_val_if_fail (info != NULL, FALSE);

	g_set_error (&error,
	             NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
	             "%s", "Connection was not provided by any settings service");
	nm_warning ("Connection (%d) %s failed to activate (timeout): (%d) %s",
	            info->scope, info->connection_path, error->code, error->message);
	dbus_g_method_return_error (info->context, error);
	g_error_free (error);

	info->timeout_id = 0;
	pending_connection_info_destroy (priv->pending_connection_info);
	priv->pending_connection_info = NULL;

	return FALSE;
}

const char *
nm_manager_activate_connection (NMManager *manager,
                                NMConnection *connection,
                                const char *specific_object,
                                const char *device_path,
                                gboolean user_requested,
                                GError **error)
{
	NMDevice *device = NULL;
	NMSettingConnection *s_con;
	NMVPNConnection *vpn_connection;
	const char *path;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (error != NULL, NULL);
	g_return_val_if_fail (*error == NULL, NULL);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (!strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_VPN_SETTING_NAME)) {
		NMActRequest *req;
		NMVPNManager *vpn_manager;

		/* VPN connection */
		req = nm_manager_get_act_request_by_path (manager, specific_object, &device);
		if (!req) {
			g_set_error (error,
			             NM_MANAGER_ERROR, NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
			             "%s", "Base connection for VPN connection not active.");
			return NULL;
		}

		if (!device) {
			g_set_error (error,
			             NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			             "%s", "Source connection had no active device.");
			return NULL;
		}

		vpn_manager = nm_vpn_manager_get ();
		vpn_connection = nm_vpn_manager_activate_connection (vpn_manager,
		                                                     connection,
		                                                     req,
		                                                     device,
		                                                     error);
		g_signal_connect (vpn_connection, "manager-get-secrets",
		                  G_CALLBACK (provider_get_secrets), manager);
		g_signal_connect (vpn_connection, "manager-cancel-secrets",
		                  G_CALLBACK (provider_cancel_secrets), manager);
		path = nm_vpn_connection_get_active_connection_path (vpn_connection);
		g_object_unref (vpn_manager);
	} else {
		NMDeviceState state;

		/* Device-based connection */
		device = nm_manager_get_device_by_path (manager, device_path);
		if (!device) {
			g_set_error (error,
			             NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			             "%s", "Device not found");
			return NULL;
		}

		state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (device));
		if (state < NM_DEVICE_STATE_DISCONNECTED) {
			g_set_error (error,
			             NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNMANAGED_DEVICE,
			             "%s", "Device not managed by NetworkManager");
			return NULL;
		}

		path = internal_activate_device (manager,
		                                 device,
		                                 connection,
		                                 specific_object,
		                                 user_requested,
		                                 error);
	}

	return path;
}

static void
connection_added_default_handler (NMManager *manager,
						    NMConnection *connection,
						    NMConnectionScope scope)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	PendingConnectionInfo *info = priv->pending_connection_info;
	const char *path;
	GError *error = NULL;

	if (!info)
		return;

	if (scope != info->scope)
		return;

	if (strcmp (info->connection_path, nm_connection_get_path (connection)))
		return;

	/* Will destroy below; can't be valid during the initial activation start */
	priv->pending_connection_info = NULL;

	path = nm_manager_activate_connection (manager,
	                                       connection,
	                                       info->specific_object_path,
	                                       info->device_path,
	                                       TRUE,
	                                       &error);
	if (path) {
		dbus_g_method_return (info->context, path);
		g_object_notify (G_OBJECT (manager), NM_MANAGER_ACTIVE_CONNECTIONS);
	} else {
		dbus_g_method_return_error (info->context, error);
		nm_warning ("Connection (%d) %s failed to activate: (%d) %s",
		            scope, info->connection_path, error->code, error->message);
		g_error_free (error);
	}

	pending_connection_info_destroy (info);
}

static gboolean
is_user_request_authorized (NMManager *manager,
                            DBusGMethodInvocation *context,
                            GError **error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	DBusConnection *connection;
	char *sender = NULL;
	gulong sender_uid = G_MAXULONG;
	DBusError dbus_error;
	char *service_owner = NULL;
	const char *service_name;
	gulong service_uid = G_MAXULONG;
	gboolean success = FALSE;

	/* Ensure the request to activate the user connection came from the
	 * same session as the user settings service.  FIXME: use ConsoleKit
	 * too.
	 */
	if (!priv->user_proxy) {
		g_set_error (error, NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_INVALID_SERVICE,
		             "%s", "No user settings service available");
		goto out;
	}

	sender = dbus_g_method_get_sender (context);
	if (!sender) {
		g_set_error (error, NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_PERMISSION_DENIED,
		             "%s", "Could not determine D-Bus requestor");
		goto out;
	}

	connection = nm_dbus_manager_get_dbus_connection (priv->dbus_mgr);
	if (!connection) {
		g_set_error (error, NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_PERMISSION_DENIED,
		             "%s", "Could not get the D-Bus system bus");
		goto out;
	}

	dbus_error_init (&dbus_error);
	/* FIXME: do this async */
	sender_uid = dbus_bus_get_unix_user (connection, sender, &dbus_error);
	if (dbus_error_is_set (&dbus_error)) {
		dbus_error_free (&dbus_error);
		g_set_error (error, NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_PERMISSION_DENIED,
		             "%s", "Could not determine the Unix user ID of the requestor");
		goto out;
	}

	/* Let root activate anything.
	 * FIXME: use a PolicyKit permission instead
	 */
	if (0 == sender_uid) {
		success = TRUE;
		goto out;
	}

	service_name = dbus_g_proxy_get_bus_name (priv->user_proxy);
	if (!service_name) {
		g_set_error (error, NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_PERMISSION_DENIED,
		             "%s", "Could not determine user settings service name");
		goto out;
	}

	service_owner = nm_dbus_manager_get_name_owner (priv->dbus_mgr, service_name, NULL);
	if (!service_owner) {
		g_set_error (error, NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_PERMISSION_DENIED,
		             "%s", "Could not determine D-Bus owner of the user settings service");
		goto out;
	}

	dbus_error_init (&dbus_error);
	/* FIXME: do this async */
	service_uid = dbus_bus_get_unix_user (connection, service_owner, &dbus_error);
	if (dbus_error_is_set (&dbus_error)) {
		dbus_error_free (&dbus_error);
		g_set_error (error, NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_PERMISSION_DENIED,
		             "%s", "Could not determine the Unix UID of the sender of the request");
		goto out;
	}

	/* And finally, the actual UID check */
	if (sender_uid != service_uid) {
		g_set_error (error, NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_PERMISSION_DENIED,
		             "%s", "Requestor UID does not match the UID of the user settings service");
		goto out;
	}

	success = TRUE;

out:
	g_free (sender);
	g_free (service_owner);
	return success;
}

static void
impl_manager_activate_connection (NMManager *manager,
                                  const char *service_name,
                                  const char *connection_path,
                                  const char *device_path,
                                  const char *specific_object_path,
                                  DBusGMethodInvocation *context)
{
	NMConnectionScope scope = NM_CONNECTION_SCOPE_UNKNOWN;
	NMConnection *connection;
	GError *error = NULL;
	char *real_sop = NULL;
	char *path = NULL;

	if (!strcmp (service_name, NM_DBUS_SERVICE_USER_SETTINGS)) {
		if (!is_user_request_authorized (manager, context, &error))
			goto err;

		scope = NM_CONNECTION_SCOPE_USER;
	} else if (!strcmp (service_name, NM_DBUS_SERVICE_SYSTEM_SETTINGS))
		scope = NM_CONNECTION_SCOPE_SYSTEM;
	else {
		g_set_error (&error,
		             NM_MANAGER_ERROR, NM_MANAGER_ERROR_INVALID_SERVICE,
		             "%s", "Invalid settings service name");
		goto err;
	}

	/* "/" is special-cased to NULL to get through D-Bus */
	if (specific_object_path && strcmp (specific_object_path, "/"))
		real_sop = g_strdup (specific_object_path);

	connection = nm_manager_get_connection_by_object_path (manager, scope, connection_path);
	if (connection) {
		path = (char *) nm_manager_activate_connection (manager,
		                                                connection,
		                                                real_sop,
		                                                device_path,
		                                                TRUE,
		                                                &error);
		if (path) {
			dbus_g_method_return (context, path);
			g_object_notify (G_OBJECT (manager), NM_MANAGER_ACTIVE_CONNECTIONS);
		}
	} else {
		PendingConnectionInfo *info;
		NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

		if (priv->pending_connection_info) {
			pending_connection_info_destroy (priv->pending_connection_info);
			priv->pending_connection_info = NULL;
		}

		/* Don't have the connection quite yet, probably created by
		 * the client on-the-fly.  Defer the activation until we have it
		 */

		info = g_slice_new0 (PendingConnectionInfo);
		info->context = context;
		info->device_path = g_strdup (device_path);
		info->scope = scope;
		info->connection_path = g_strdup (connection_path);
		info->specific_object_path = g_strdup (real_sop);
		info->timeout_id = g_timeout_add_seconds (5, wait_for_connection_expired, manager);

		// FIXME: should probably be per-device, not global to the manager
		NM_MANAGER_GET_PRIVATE (manager)->pending_connection_info = info;
	}

 err:
	if (error) {
		dbus_g_method_return_error (context, error);
		nm_warning ("Connection (%d) %s failed to activate: (%d) %s",
		            scope, connection_path, error->code, error->message);
		g_error_free (error);
	}

	g_free (real_sop);
}

gboolean
nm_manager_deactivate_connection (NMManager *manager,
                                  const char *connection_path,
                                  NMDeviceStateReason reason,
                                  GError **error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	NMVPNManager *vpn_manager;
	GSList *iter;
	gboolean success = FALSE;
	NMVPNConnectionStateReason vpn_reason = NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED;

	/* Check for device connections first */
	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *device = NM_DEVICE (iter->data);
		NMActRequest *req;

		req = nm_device_get_act_request (device);
		if (!req)
			continue;

		if (!strcmp (connection_path, nm_act_request_get_active_connection_path (req))) {
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_DISCONNECTED,
			                         reason);
			success = TRUE;
			goto done;
		}
	}

	/* Check for VPN connections next */
	vpn_manager = nm_vpn_manager_get ();
	if (reason == NM_DEVICE_STATE_REASON_CONNECTION_REMOVED)
		vpn_reason = NM_VPN_CONNECTION_STATE_REASON_CONNECTION_REMOVED;
	if (nm_vpn_manager_deactivate_connection (vpn_manager, connection_path, vpn_reason)) {
		success = TRUE;
	} else {
		g_set_error (error,
		             NM_MANAGER_ERROR, NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
		             "%s", "The connection was not active.");
	}
	g_object_unref (vpn_manager);

done:
	g_object_notify (G_OBJECT (manager), NM_MANAGER_ACTIVE_CONNECTIONS);
	return success;
}

static gboolean
impl_manager_deactivate_connection (NMManager *manager,
                                    const char *connection_path,
                                    GError **error)
{
	return nm_manager_deactivate_connection (manager,
	                                         connection_path,
	                                         NM_DEVICE_STATE_REASON_USER_REQUESTED,
	                                         error);
}

static gboolean
impl_manager_sleep (NMManager *self, gboolean sleep, GError **error)
{
	NMManagerPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_MANAGER (self), FALSE);

	priv = NM_MANAGER_GET_PRIVATE (self);

	if (priv->sleeping == sleep) {
		g_set_error (error,
		             NM_MANAGER_ERROR, NM_MANAGER_ERROR_ALREADY_ASLEEP_OR_AWAKE,
		             "Already %s", sleep ? "asleep" : "awake");		
		return FALSE;
	}

	priv->sleeping = sleep;

	if (sleep) {
		nm_info ("Sleeping...");

		/* Just deactivate and down all devices from the device list,
		 * we'll remove them in 'wake' for speed's sake.
		 */
		for (iter = priv->devices; iter; iter = iter->next)
			nm_device_set_managed (NM_DEVICE (iter->data), FALSE, NM_DEVICE_STATE_REASON_SLEEPING);
	} else {
		const GSList *unmanaged_specs;

		nm_info  ("Waking up...");

		unmanaged_specs = nm_sysconfig_settings_get_unmanaged_specs (priv->sys_settings);

		/* Re-manage managed devices */
		for (iter = priv->devices; iter; iter = iter->next) {
			NMDevice *device = NM_DEVICE (iter->data);

			if (nm_device_interface_spec_match_list (NM_DEVICE_INTERFACE (device), unmanaged_specs))
				nm_device_set_managed (device, FALSE, NM_DEVICE_STATE_REASON_NOW_UNMANAGED);
			else
				nm_device_set_managed (device, TRUE, NM_DEVICE_STATE_REASON_NOW_MANAGED);
		}

		/* Ask for new bluetooth devices */
		bluez_manager_resync_devices (self);
	}

	nm_manager_update_state (self);
	return TRUE;
}

/* Legacy 0.6 compatibility interface */

static gboolean
impl_manager_legacy_sleep (NMManager *manager, GError **error)
{
	return impl_manager_sleep (manager, TRUE, error);
}

static gboolean
impl_manager_legacy_wake  (NMManager *manager, GError **error)
{
	return impl_manager_sleep (manager, FALSE, error);
}

static gboolean
impl_manager_legacy_state (NMManager *manager, guint32 *state, GError **err)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	nm_manager_update_state (manager);
	*state = priv->state;
	return TRUE;
}


/* Connections */

static int
connection_sort (gconstpointer pa, gconstpointer pb)
{
	NMConnection *a = NM_CONNECTION (pa);
	NMSettingConnection *con_a;
	NMConnection *b = NM_CONNECTION (pb);
	NMSettingConnection *con_b;

	con_a = (NMSettingConnection *) nm_connection_get_setting (a, NM_TYPE_SETTING_CONNECTION);
	g_assert (con_a);
	con_b = (NMSettingConnection *) nm_connection_get_setting (b, NM_TYPE_SETTING_CONNECTION);
	g_assert (con_b);

	if (nm_setting_connection_get_autoconnect (con_a) != nm_setting_connection_get_autoconnect (con_b)) {
		if (nm_setting_connection_get_autoconnect (con_a))
			return -1;
		return 1;
	}

	if (nm_setting_connection_get_timestamp (con_a) > nm_setting_connection_get_timestamp (con_b))
		return -1;
	else if (nm_setting_connection_get_timestamp (con_a) == nm_setting_connection_get_timestamp (con_b))
		return 0;
	return 1;
}

static void
connections_to_slist (gpointer key, gpointer value, gpointer user_data)
{
	GSList **list = (GSList **) user_data;

	*list = g_slist_insert_sorted (*list, g_object_ref (value), connection_sort);
}

/* Returns a GSList of referenced NMConnection objects, caller must
 * unref the connections in the list and destroy the list.
 */
GSList *
nm_manager_get_connections (NMManager *manager,
                            NMConnectionScope scope)
{
	NMManagerPrivate *priv;
	GSList *list = NULL;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	priv = NM_MANAGER_GET_PRIVATE (manager);
	if (scope == NM_CONNECTION_SCOPE_USER)
		g_hash_table_foreach (priv->user_connections, connections_to_slist, &list);
	else if (scope == NM_CONNECTION_SCOPE_SYSTEM)
		g_hash_table_foreach (priv->system_connections, connections_to_slist, &list);
	else
		nm_warning ("Unknown NMConnectionScope %d", scope);	
	return list;
}

NMConnection *
nm_manager_get_connection_by_object_path (NMManager *manager,
                                          NMConnectionScope scope,
                                          const char *path)
{
	NMManagerPrivate *priv;
	NMConnection *connection = NULL;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	priv = NM_MANAGER_GET_PRIVATE (manager);
	if (scope == NM_CONNECTION_SCOPE_USER)
		connection = (NMConnection *) g_hash_table_lookup (priv->user_connections, path);
	else if (scope == NM_CONNECTION_SCOPE_SYSTEM)
		connection = (NMConnection *) g_hash_table_lookup (priv->system_connections, path);
	else
		nm_warning ("Unknown NMConnectionScope %d", scope);
	return connection;
}

GPtrArray *
nm_manager_get_active_connections_by_connection (NMManager *manager,
                                                 NMConnection *connection)
{
	return get_active_connections (manager, connection);
}

void
nm_manager_start (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	gboolean we = FALSE;

	switch (nm_udev_manager_get_rfkill_state (priv->udev_mgr)) {
	case RFKILL_UNBLOCKED:
		we = TRUE;
		priv->wireless_hw_enabled = TRUE;
		break;
	case RFKILL_SOFT_BLOCKED:
		we = FALSE;
		priv->wireless_hw_enabled = TRUE;
		break;
	case RFKILL_HARD_BLOCKED:
		we = FALSE;
		priv->wireless_hw_enabled = FALSE;
		break;
	default:
		break;
	}

	nm_info ("Wireless now %s by radio killswitch",
	         (priv->wireless_hw_enabled && we) ? "enabled" : "disabled");
	manager_set_wireless_enabled (self, we);

	system_unmanaged_devices_changed_cb (priv->sys_settings, NULL, self);
	system_hostname_changed_cb (priv->sys_settings, NULL, self);
	system_query_connections (self);

	/* Get user connections if the user settings service is around, otherwise
	 * they will be queried when the user settings service shows up on the
	 * bus in nm_manager_name_owner_changed().
	 */
	if (nm_dbus_manager_name_has_owner (priv->dbus_mgr, NM_DBUS_SERVICE_USER_SETTINGS))
		user_query_connections (self);

	nm_udev_manager_query_devices (priv->udev_mgr);
	bluez_manager_resync_devices (self);
}

NMManager *
nm_manager_get (const char *config_file, const char *plugins, GError **error)
{
	static NMManager *singleton = NULL;
	NMManagerPrivate *priv;

	if (singleton)
		return g_object_ref (singleton);

	singleton = (NMManager *) g_object_new (NM_TYPE_MANAGER, NULL);
	g_assert (singleton);

	priv = NM_MANAGER_GET_PRIVATE (singleton);

	priv->sys_settings = nm_sysconfig_settings_new (config_file, plugins, error);
	if (!priv->sys_settings) {
		g_object_unref (singleton);
		return NULL;
	}

	priv->config_file = g_strdup (config_file);

	g_signal_connect (priv->sys_settings, "notify::" NM_SYSCONFIG_SETTINGS_UNMANAGED_SPECS,
	                  G_CALLBACK (system_unmanaged_devices_changed_cb), singleton);
	g_signal_connect (priv->sys_settings, "notify::" NM_SYSCONFIG_SETTINGS_HOSTNAME,
	                  G_CALLBACK (system_hostname_changed_cb), singleton);
	g_signal_connect (priv->sys_settings, "new-connection",
	                  G_CALLBACK (system_new_connection_cb), singleton);

	dbus_g_connection_register_g_object (nm_dbus_manager_get_connection (priv->dbus_mgr),
	                                     NM_DBUS_PATH,
	                                     G_OBJECT (singleton));

	g_signal_connect (priv->dbus_mgr,
	                  "name-owner-changed",
	                  G_CALLBACK (nm_manager_name_owner_changed),
	                  singleton);

	priv->udev_mgr = nm_udev_manager_new ();
	g_signal_connect (priv->udev_mgr,
	                  "device-added",
	                  G_CALLBACK (udev_device_added_cb),
	                  singleton);
	g_signal_connect (priv->udev_mgr,
	                  "device-removed",
	                  G_CALLBACK (udev_device_removed_cb),
	                  singleton);
	g_signal_connect (priv->udev_mgr,
	                  "rfkill-changed",
	                  G_CALLBACK (udev_manager_rfkill_changed_cb),
	                  singleton);

	priv->bluez_mgr = nm_bluez_manager_get ();

	g_signal_connect (priv->bluez_mgr,
			  "bdaddr-added",
			  G_CALLBACK (bluez_manager_bdaddr_added_cb),
			  singleton);

	g_signal_connect (priv->bluez_mgr,
			  "bdaddr-removed",
			  G_CALLBACK (bluez_manager_bdaddr_removed_cb),
			  singleton);

	return singleton;
}

static void
dispose (GObject *object)
{
	NMManager *manager = NM_MANAGER (object);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_manager_parent_class)->dispose (object);
		return;
	}
	priv->disposed = TRUE;

	pending_connection_info_destroy (priv->pending_connection_info);
	priv->pending_connection_info = NULL;

	while (g_slist_length (priv->secrets_calls)) {
		GetSecretsInfo *info = priv->secrets_calls->data;

		free_get_secrets_info (info);
	}

	while (g_slist_length (priv->devices)) {
		NMDevice *device = NM_DEVICE (priv->devices->data);

		priv->devices = remove_one_device (manager, priv->devices, device);
	}

	user_destroy_connections (manager);
	g_hash_table_destroy (priv->user_connections);
	priv->user_connections = NULL;

	g_hash_table_foreach (priv->system_connections, emit_removed, manager);
	g_hash_table_remove_all (priv->system_connections);
	g_hash_table_destroy (priv->system_connections);
	priv->system_connections = NULL;

	g_free (priv->hostname);
	g_free (priv->config_file);

	if (priv->sys_settings) {
		g_object_unref (priv->sys_settings);
		priv->sys_settings = NULL;
	}

	if (priv->vpn_manager_id) {
		g_source_remove (priv->vpn_manager_id);
		priv->vpn_manager_id = 0;
	}
	g_object_unref (priv->vpn_manager);

	if (priv->modem_added_id) {
		g_source_remove (priv->modem_added_id);
		priv->modem_added_id = 0;
	}
	if (priv->modem_removed_id) {
		g_source_remove (priv->modem_removed_id);
		priv->modem_removed_id = 0;
	}
	g_object_unref (priv->modem_manager);

	g_object_unref (priv->dbus_mgr);
	if (priv->bluez_mgr)
		g_object_unref (priv->bluez_mgr);

	G_OBJECT_CLASS (nm_manager_parent_class)->dispose (object);
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_WIRELESS_ENABLED:
		manager_set_wireless_enabled (NM_MANAGER (object), g_value_get_boolean (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMManager *self = NM_MANAGER (object);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_STATE:
		nm_manager_update_state (self);
		g_value_set_uint (value, priv->state);
		break;
	case PROP_WIRELESS_ENABLED:
		g_value_set_boolean (value, priv->wireless_enabled);
		break;
	case PROP_WIRELESS_HARDWARE_ENABLED:
		g_value_set_boolean (value, priv->wireless_hw_enabled);
		break;
	case PROP_ACTIVE_CONNECTIONS:
		g_value_take_boxed (value, get_active_connections (self, NULL));
		break;
	case PROP_HOSTNAME:
		g_value_set_string (value, priv->hostname);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_manager_init (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	DBusGConnection *g_connection;
	guint id;

	priv->wireless_enabled = TRUE;
	priv->wireless_hw_enabled = TRUE;
	priv->sleeping = FALSE;
	priv->state = NM_STATE_DISCONNECTED;

	priv->dbus_mgr = nm_dbus_manager_get ();

	priv->user_connections = g_hash_table_new_full (g_str_hash,
	                                                g_str_equal,
	                                                g_free,
	                                                g_object_unref);

	priv->system_connections = g_hash_table_new_full (g_str_hash,
	                                                  g_str_equal,
	                                                  g_free,
	                                                  g_object_unref);

	priv->modem_manager = nm_modem_manager_get ();
	priv->modem_added_id = g_signal_connect (priv->modem_manager, "device-added",
	                                         G_CALLBACK (modem_added), manager);
	priv->modem_removed_id = g_signal_connect (priv->modem_manager, "device-removed",
	                                           G_CALLBACK (modem_removed), manager);

	priv->vpn_manager = nm_vpn_manager_get ();
	id = g_signal_connect (G_OBJECT (priv->vpn_manager), "connection-deactivated",
	                       G_CALLBACK (vpn_manager_connection_deactivated_cb), manager);
	priv->vpn_manager_id = id;

	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);

	/* avahi-autoipd stuff */
	priv->aipd_proxy = dbus_g_proxy_new_for_name (g_connection,
	                                              NM_AUTOIP_DBUS_SERVICE,
	                                              "/",
	                                              NM_AUTOIP_DBUS_IFACE);
	if (priv->aipd_proxy) {
		dbus_g_object_register_marshaller (_nm_marshal_VOID__STRING_STRING_STRING,
		                                   G_TYPE_NONE,
		                                   G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
		                                   G_TYPE_INVALID);

		dbus_g_proxy_add_signal (priv->aipd_proxy,
		                         "Event",
		                         G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
		                         G_TYPE_INVALID);

		dbus_g_proxy_connect_signal (priv->aipd_proxy, "Event",
		                             G_CALLBACK (aipd_handle_event),
		                             manager,
		                             NULL);
	} else
		nm_warning ("%s: could not initialize avahi-autoipd D-Bus proxy", __func__);
}

static void
nm_manager_class_init (NMManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMManagerPrivate));

	/* virtual methods */
	manager_class->connection_added = connection_added_default_handler;

	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_uint (NM_MANAGER_STATE,
		                    "State",
		                    "Current state",
		                    0, NM_STATE_DISCONNECTED, 0,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_WIRELESS_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WIRELESS_ENABLED,
		                       "WirelessEnabled",
		                       "Is wireless enabled",
		                       TRUE,
		                       G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_WIRELESS_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WIRELESS_HARDWARE_ENABLED,
		                       "WirelessHardwareEnabled",
		                       "RF kill state",
		                       TRUE,
		                       G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_ACTIVE_CONNECTIONS,
		 g_param_spec_boxed (NM_MANAGER_ACTIVE_CONNECTIONS,
		                     "Active connections",
		                     "Active connections",
		                     DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
		                     G_PARAM_READABLE));

	/* Hostname is not exported over D-Bus */
	g_object_class_install_property
		(object_class, PROP_HOSTNAME,
		 g_param_spec_string (NM_MANAGER_HOSTNAME,
		                      "Hostname",
		                      "Hostname",
		                      NULL,
		                      G_PARAM_READABLE | NM_PROPERTY_PARAM_NO_EXPORT));

	/* signals */
	signals[DEVICE_ADDED] =
		g_signal_new ("device-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMManagerClass, device_added),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE, 1, G_TYPE_OBJECT);

	signals[DEVICE_REMOVED] =
		g_signal_new ("device-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMManagerClass, device_removed),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__OBJECT,
		              G_TYPE_NONE, 1, G_TYPE_OBJECT);

	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMManagerClass, state_changed),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__UINT,
		              G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[PROPERTIES_CHANGED] =
		nm_properties_changed_signal_new (object_class,
		                                  G_STRUCT_OFFSET (NMManagerClass, properties_changed));

	signals[CONNECTIONS_ADDED] =
		g_signal_new ("connections-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMManagerClass, connections_added),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__UINT,
		              G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[CONNECTION_ADDED] =
		g_signal_new ("connection-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMManagerClass, connection_added),
		              NULL, NULL,
		              _nm_marshal_VOID__OBJECT_UINT,
		              G_TYPE_NONE, 2, G_TYPE_OBJECT, G_TYPE_UINT);

	signals[CONNECTION_UPDATED] =
		g_signal_new ("connection-updated",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMManagerClass, connection_updated),
		              NULL, NULL,
		              _nm_marshal_VOID__OBJECT_UINT,
		              G_TYPE_NONE, 2, G_TYPE_OBJECT, G_TYPE_UINT);

	signals[CONNECTION_REMOVED] =
		g_signal_new ("connection-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMManagerClass, connection_removed),
		              NULL, NULL,
		              _nm_marshal_VOID__OBJECT_UINT,
		              G_TYPE_NONE, 2, G_TYPE_OBJECT, G_TYPE_UINT);

	/* StateChange is DEPRECATED */
	signals[STATE_CHANGE] =
		g_signal_new ("state-change",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL,
		              g_cclosure_marshal_VOID__UINT,
		              G_TYPE_NONE, 1, G_TYPE_UINT);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (manager_class),
	                                 &dbus_glib_nm_manager_object_info);

	dbus_g_error_domain_register (NM_MANAGER_ERROR, NULL, NM_TYPE_MANAGER_ERROR);
}

